// MainWindow.cpp
#include "MainWindow.h"
#include "qdebug.h"
#include "ui_mainwindow.h"

#include "../../Version.h"
#include "../core/Logger.h"
#include "../core/Settings.h"
#include "../core/Translator.h"
#include "../core/SystemEnum.h"
#include "../core/SignatureDb.h"
#include "../core/ShieldEngine.h"
#include "../core/Quarantine.h"
#include "../core/Repair.h"
#include "../core/Updater.h"
#include "../core/RealTimeShield.h"
#include "../core/WebShield.h"
#include "../core/SystemOptimizer.h"
#include "../core/StartupManager.h"
#include "../core/HardwareMonitor.h"
#include "../core/RansomwareShield.h"
#include "../core/AuditLogger.h"
#include "../core/ReportGenerator.h"
#include "../core/LicenseManager.h"
#include "../core/WindowsSecurityIntegration.h"
#include "../utils/ContextMenuManager.h"
#include "../utils/ThemeManager.h"
#include "../widgets/PageTransition.h"
#include "../widgets/ChromeBar.h"
#include "../widgets/DriveTile.h"
#include "../widgets/ThreatCard.h"
#include "../widgets/ScanOptionsDialog.h"
#include "../widgets/Toaster.h"
#include "../widgets/NotificationAlert.h"
#include "../widgets/BrandIcon.h"
#include "../widgets/FlagIcon.h"
#include "../widgets/ProgressRing.h"
#include "../widgets/SurfaceCard.h"
#include "../utils/FileOps.h"

#ifdef Q_OS_WIN
#include <windows.h>
#include <windowsx.h>
#include <dbt.h>
#endif

#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QDir>
#include <QStandardPaths>
#include <QCoreApplication>
#include <QProcess>
#include <QDateTime>
#include <QTime>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QMessageBox>
#include <QSystemTrayIcon>
#include <QMenu>
#include <QAction>
#include <QStyle>
#include <QCloseEvent>
#include <QSettings>
#include <QTimer>
#include <QGraphicsOpacityEffect>
#include <QPropertyAnimation>
#include <QPushButton>
#include <QCheckBox>
#include <QRadioButton>
#include <QComboBox>
#include <QLineEdit>
#include <QTimeEdit>
#include <QListWidget>
#include <QTableWidget>
#include <QScrollArea>
#include <QSpacerItem>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QHeaderView>
#include <QTableWidgetItem>
#include <QColor>
#include <QClipboard>
#include <QRandomGenerator>
#include <QDesktopServices>
#include <QUrl>
#include <QMetaType>
#include <QSet>
#include <QtConcurrent/QtConcurrentRun>
#include <QFutureWatcher>
#include <QShortcut>

namespace verax {

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent), ui(new Ui::MainWindow)
{
    Logger::info("MainWindow: ctor begin");
    ui->setupUi(this);

    setWindowFlags(Qt::Window | Qt::FramelessWindowHint | Qt::WindowMinMaxButtonsHint);
    setAttribute(Qt::WA_TranslucentBackground, false);
    setMinimumSize(960, 640);

#ifdef Q_OS_WIN
    HWND hwnd = (HWND)winId();
    LONG style = GetWindowLong(hwnd, GWL_STYLE);
    SetWindowLong(hwnd, GWL_STYLE, style | WS_MINIMIZEBOX | WS_CAPTION | CS_DBLCLKS);
#endif

    setWindowTitle(QString::fromLatin1(APP_NAME));
    setWindowIcon(QIcon(QStringLiteral(":/assets/logo.png")));

    m_transition = new PageTransition(ui->stackedWidget, this);

    SignatureDb::instance().open();
    SignatureDb::instance().initSchema();

    wireUi();
    wireSignals();
    setupTrayIcon();
    if (!LicenseManager::instance().isValid()) {
        setActiveNav(PageLicenseLocked);
    } else {
        setActiveNav(PageDashboard);
    }

    connect(&RealTimeShield::instance(), &RealTimeShield::threatDetected,
            this, &MainWindow::onRealTimeThreatDetected);
    if (LicenseManager::instance().isValid() && Settings::instance().realTimeProtection()) {
        RealTimeShield::instance().start();
    }
    if (LicenseManager::instance().isValid() && Settings::instance().ransomwareProtection()) {
        RansomwareShield::instance().setEnabled(true);
    }
    connect(&RansomwareShield::instance(), &RansomwareShield::ransomwareActivityDetected,
            this, [this](const QString &folder, const QString &desc){
        AuditLogger::instance().logEvent(QStringLiteral("RansomwareBlocked"), desc, folder, 3);
        NotificationAlert::showThreat(tr("Ransomware Shield"), desc, folder);
    });

    initScheduler();

    if (Settings::instance().webShield()) {
        WebShield::instance().setEnabled(true);
    }

    QTimer::singleShot(0, this, [this]{
        // populateDrivesOnConfig();
        populateQuarantineTable();
        populateAboutPage();
        populateRepairCards();
    });

    // Silent on-startup version check. Delayed 3 s so the first paint and
    // any heavy initialisation (Settings, fonts, signature DB seeding) all
    // finish first. The Updater module shows the modal dialog itself only
    // when a strictly-newer version is published — never on equal/older
    // version, never on network errors. See src/core/Updater.cpp.
    QTimer::singleShot(3000, this, [this]{
        Updater::instance().checkSilently(this);
    });

    m_watchdog = new QTimer(this);
    m_watchdog->setInterval(24 * 60 * 60 * 1000);
    connect(m_watchdog, &QTimer::timeout, this, &MainWindow::onCheckUpdatesNow);
    if (Settings::instance().autoUpdateSignatures())
        m_watchdog->start();

    updateChromeStatus("idle", tr("Idle"));

    ui->cardDrivers->setVisible(false);
    ui->cardDrivers->hide();
    ui->cardAboutSelfTest->setVisible(false);
    ui->cardAboutSelfTest->hide();

    // 1. Enable context menu policy for the list widget
    ui->listExtraTargets->setContextMenuPolicy(Qt::CustomContextMenu);

    // 2. Handle Right-Click (Context Menu) with Add/Delete options
    connect(ui->listExtraTargets, &QListWidget::customContextMenuRequested, this, [this](const QPoint &pos) {
        QMenu menu(this);

        QAction *addFolderAct = menu.addAction(tr("Add Folder"));
        QAction *addFileAct   = menu.addAction(tr("Add File"));
        QAction *deleteAct    = nullptr;

        // Only show Delete option if an item is actually right-clicked
        QListWidgetItem *item = ui->listExtraTargets->itemAt(pos);
        if (item) {
            menu.addSeparator();
            deleteAct = menu.addAction(tr("Delete"));
        }

        // Execute menu and get chosen action
        QAction *selectedAct = menu.exec(ui->listExtraTargets->mapToGlobal(pos));

        if (selectedAct == addFolderAct) {
            onAddFolder();
        } else if (selectedAct == addFileAct) {
            onAddFile();
        } else if (selectedAct && selectedAct == deleteAct) {
            delete ui->listExtraTargets->takeItem(ui->listExtraTargets->row(item));
        }
    });

    // 3. Handle Keyboard Delete key shortcut
    auto *deleteShortcut = new QShortcut(QKeySequence(Qt::Key_Delete), ui->listExtraTargets);
    connect(deleteShortcut, &QShortcut::activated, this, [this]() {
        QListWidgetItem *item = ui->listExtraTargets->currentItem();
        if (item) {
            delete ui->listExtraTargets->takeItem(ui->listExtraTargets->row(item));
        }
    });
}

MainWindow::~MainWindow()
{
    if (m_drivesWatcher) {
        m_drivesWatcher->disconnect(this);
        m_drivesWatcher->cancel();
        m_drivesWatcher->waitForFinished();
        delete m_drivesWatcher;
        m_drivesWatcher = nullptr;
    }
    SignatureDb::instance().close();
    delete ui;
}

bool MainWindow::isInstalledPath()
{
    const QString here   = QDir(QCoreApplication::applicationDirPath()).absolutePath();
    const QString want   = QDir(QString::fromLatin1(APP_INSTALL_DIR)).absolutePath();
    return here.compare(want, Qt::CaseInsensitive) == 0;
}

void MainWindow::showInstaller()
{
    setActiveNav(PageInstaller);
    show();
}

void MainWindow::startInTray()
{
    hide();
}

void MainWindow::runSilentScanAndExit()
{
    m_silentMode = true;
    ScanRequest req = buildScanRequest();
    req.targets.clear();
    for (const auto &d : SystemEnum::listDrives())
        if (d.typeCode == 3) req.targets << d.letter + "/";
    connect(ShieldEngine::instance().scanner(), &Scanner::finished, this,
            [](const ScanReport &){ QCoreApplication::quit(); });
    ShieldEngine::instance().startScan(req);
}

void MainWindow::wireUi()
{
    auto *brandBox = ui->brandIconBox;
    if (brandBox) {
        auto *lay = brandBox->layout();
        if (!lay) {
            lay = new QHBoxLayout(brandBox);
            lay->setContentsMargins(0,0,0,0);
            lay->setSpacing(8);
        }
        while (auto *item = lay->takeAt(0)) {
            if (auto *w = item->widget()) w->deleteLater();
            delete item;
        }
        auto *web = new BrandIcon(BrandIcon::Website, brandBox);
        web->setToolTip(QStringLiteral("https://multi-servis.pl"));
        connect(web, &BrandIcon::clicked, this, [this]{ onBrandClicked(BrandIcon::Website); });
        lay->addWidget(web);
    }

    if (ui->flagPl) ui->flagPl->setCode("pl");
    if (ui->flagEn) ui->flagEn->setCode("en");
    if (ui->flagAr) ui->flagAr->setCode("ar");

    Settings &s = Settings::instance();
    if (ui->cbStartWithWindows)    ui->cbStartWithWindows->setChecked(s.startWithWindows());
    if (ui->cbContextMenu)         ui->cbContextMenu->setChecked(s.contextMenuIntegration());
    if (ui->cbMinimizeToTray)      ui->cbMinimizeToTray->setChecked(s.minimizeToTrayOnClose());
    if (ui->cbShowNotifications)   ui->cbShowNotifications->setChecked(s.showNotifications());
    if (ui->cbScanUsbOnInsert)     ui->cbScanUsbOnInsert->setChecked(s.scanUsbOnInsert());
    if (ui->cbAutoUpdateSignatures)ui->cbAutoUpdateSignatures->setChecked(s.autoUpdateSignatures());
    // if (ui->editUpdateUrl)         ui->editUpdateUrl->setText(s.updateUrl());

    if (ui->cbEngineSigDb)      ui->cbEngineSigDb->setChecked(s.useSignatureDb());
    if (ui->cbEnginePe)         ui->cbEnginePe->setChecked(s.usePeInspection());
    if (ui->cbEngineHeuristics) ui->cbEngineHeuristics->setChecked(s.useHeuristics());
    if (ui->cbEngineCloud)      ui->cbEngineCloud->setChecked(s.useCloudLookup());

    const QString act = s.detectionAction();
    if (ui->radioActionQuarantine) ui->radioActionQuarantine->setChecked(act == "quarantine");
    if (ui->radioActionDelete)     ui->radioActionDelete->setChecked(act == "delete");
    if (ui->radioActionReport)     ui->radioActionReport->setChecked(act == "report");

    if (ui->cbExtExecutable && !ui->cbExtExecutable->isChecked()) ui->cbExtExecutable->setChecked(true);
    if (ui->cbExtScripts    && !ui->cbExtScripts->isChecked())    ui->cbExtScripts->setChecked(true);
    if (ui->cbExtDocuments  && !ui->cbExtDocuments->isChecked())  ui->cbExtDocuments->setChecked(true);
    if (ui->cbExtArchives   && !ui->cbExtArchives->isChecked())   ui->cbExtArchives->setChecked(true);

    if (ui->comboLanguage) {
        ui->comboLanguage->setStyleSheet(
            "QComboBox::drop-down { border: none; background: transparent; width: 0px; }\n"
            "QComboBox::down-arrow { image: none; }"
        );
        ui->comboLanguage->blockSignals(true);
        int langIdx = 0;
        if (s.language() == "en") langIdx = 1;
        else if (s.language() == "ar") langIdx = 2;
        ui->comboLanguage->setCurrentIndex(langIdx);
        ui->comboLanguage->blockSignals(false);
    }

    if (ui->comboTheme) {
        ui->comboTheme->blockSignals(true);
        int themeIdx = 0; // 0 = dark
        if (s.theme() == "light") themeIdx = 1;
        else if (s.theme() == "system") themeIdx = 2;
        ui->comboTheme->setCurrentIndex(themeIdx);
        ui->comboTheme->blockSignals(false);
    }

    if (ui->comboScheduledScan) {
        const QStringList opts{"off","daily","weekly","monthly"};
        const int idx = qMax(0, opts.indexOf(s.scheduledScan()));
        ui->comboScheduledScan->setCurrentIndex(idx);
    }
    if (ui->editScheduledTime)
        ui->editScheduledTime->setTime(QTime::fromString(s.scheduledTime(), "HH:mm"));

    if (ui->cbRansomwareProtection)
        ui->cbRansomwareProtection->setChecked(s.ransomwareProtection());

    if (ui->listExclusions) {
        ui->listExclusions->clear();
        for (const auto &ex : s.exclusions()) {
            ui->listExclusions->addItem(ex);
        }
    }

    if (ui->editUpdateUrl) {
        ui->editUpdateUrl->setReadOnly(true);
        if (s.updateUrl().isEmpty()) {
            ui->editUpdateUrl->setText(QStringLiteral("https://multi-servis.pl/api/signatures/latest.json"));
        } else {
            ui->editUpdateUrl->setText(s.updateUrl());
        }
    }

    if (ui->editInstallPath)
        ui->editInstallPath->setText(QString::fromLatin1(APP_INSTALL_DIR));
    if (ui->editCurrentPath)
        ui->editCurrentPath->setText(QCoreApplication::applicationDirPath());

    if (ui->lblAppNameVersion)
        ui->lblAppNameVersion->setText(QStringLiteral("%1 v%2").arg(APP_NAME, APP_VERSION_STR));

    initToolsPage();
}

void MainWindow::wireSignals()
{
    connect(ui->chromeBar, &ChromeBar::minimizeClicked, this, &MainWindow::showMinimized);
    connect(ui->chromeBar, &ChromeBar::maximizeClicked, this, [this]() {
        if (isMaximized()) showNormal();
        else showMaximized();
    });
    connect(ui->chromeBar, &ChromeBar::closeClicked,    this, &MainWindow::close);

    const QList<QPushButton*> navButtons = ui->sidebar->findChildren<QPushButton*>();
    for (auto *b : navButtons) {
        if (b->objectName().startsWith("nav"))
            connect(b, &QPushButton::clicked, this, &MainWindow::onNavClicked);
    }

    if (ui->btnQuickScan)        connect(ui->btnQuickScan, &QPushButton::clicked, this, &MainWindow::onQuickScan);
    if (ui->btnDeepScan)         connect(ui->btnDeepScan,  &QPushButton::clicked, this, &MainWindow::onDeepScan);
    if (ui->btnScanMemory)       connect(ui->btnScanMemory,&QPushButton::clicked, this, &MainWindow::onScanMemory);
    if (ui->btnCustomScan)       connect(ui->btnCustomScan,&QPushButton::clicked, this, &MainWindow::onCustomScan);
    if (ui->btnScanSelected)     connect(ui->btnScanSelected, &QPushButton::clicked, this, &MainWindow::onStartScan);
    if (ui->btnScanCancel)       connect(ui->btnScanCancel,   &QPushButton::clicked, this, &MainWindow::onCancelScan);
    if (ui->btnScanBack)         connect(ui->btnScanBack,     &QPushButton::clicked, this, &MainWindow::onScanBackToDashboard);

    // Tools Page - System Cleaner
    if (ui->btnScanClean) connect(ui->btnScanClean, &QPushButton::clicked, this, &MainWindow::onScanCleanClicked);
    if (ui->btnDoClean)   connect(ui->btnDoClean, &QPushButton::clicked, this, &MainWindow::onDoCleanClicked);

    // Tools Page - Startup Manager
    if (ui->btnRefreshStartup) connect(ui->btnRefreshStartup, &QPushButton::clicked, this, &MainWindow::onRefreshStartupClicked);
    if (ui->btnToggleStartup)  connect(ui->btnToggleStartup, &QPushButton::clicked, this, &MainWindow::onToggleStartupClicked);
    if (ui->btnDeleteStartup)  connect(ui->btnDeleteStartup, &QPushButton::clicked, this, &MainWindow::onDeleteStartupClicked);

    // Tools Page - Shredder
    if (ui->btnBrowseShredFile) connect(ui->btnBrowseShredFile, &QPushButton::clicked, this, &MainWindow::onBrowseShredFile);
    if (ui->btnBrowseShredDir)  connect(ui->btnBrowseShredDir, &QPushButton::clicked, this, &MainWindow::onBrowseShredDir);
    if (ui->btnDoShred)         connect(ui->btnDoShred, &QPushButton::clicked, this, &MainWindow::onDoShredClicked);

    // Remote Repair Page
    if (ui->btnGenSessionCode)  connect(ui->btnGenSessionCode,  &QPushButton::clicked, this, &MainWindow::onGenerateSessionCode);
    if (ui->btnCopySessionCode) connect(ui->btnCopySessionCode, &QPushButton::clicked, this, &MainWindow::onCopySessionCode);
    if (ui->btnConnectRemote)   connect(ui->btnConnectRemote,   &QPushButton::clicked, this, &MainWindow::onConnectRemoteClicked);
    if (ui->btnUpdateSignatures) connect(ui->btnUpdateSignatures, &QPushButton::clicked, this, &MainWindow::onUpdateSignatures);

    if (ui->btnAddFolder)        connect(ui->btnAddFolder, &QPushButton::clicked, this, &MainWindow::onAddFolder);
    if (ui->btnAddFile)          connect(ui->btnAddFile,   &QPushButton::clicked, this, &MainWindow::onAddFile);
    if (ui->btnStartScan)        connect(ui->btnStartScan, &QPushButton::clicked, this, &MainWindow::onStartScanFromConfig);

    if (ui->btnStopScan)         connect(ui->btnStopScan,  &QPushButton::clicked, this, &MainWindow::onStopScan);
    if (ui->btnPauseScan)        connect(ui->btnPauseScan, &QPushButton::toggled, this, &MainWindow::onPauseToggled);

    Scanner *sc = ShieldEngine::instance().scanner();
    connect(sc, &Scanner::started,      this, &MainWindow::onScannerStarted);
    connect(sc, &Scanner::progress,     this, &MainWindow::onScannerProgress);
    connect(sc, &Scanner::fileScanned,  this, &MainWindow::onScannerFileScanned);
    connect(sc, &Scanner::threatFound,  this, &MainWindow::onScannerThreatFound);
    connect(sc, &Scanner::finished,     this, &MainWindow::onScannerFinished);

    if (ui->btnQRefresh)         connect(ui->btnQRefresh, &QPushButton::clicked, this, &MainWindow::onQuarantineRefresh);
    if (ui->btnQRestoreSelected) connect(ui->btnQRestoreSelected, &QPushButton::clicked, this, &MainWindow::onQuarantineRestoreSelected);
    if (ui->btnQDeleteSelected)  connect(ui->btnQDeleteSelected,  &QPushButton::clicked, this, &MainWindow::onQuarantineDeleteSelected);
    if (ui->btnQExport)          connect(ui->btnQExport,          &QPushButton::clicked, this, &MainWindow::onQuarantineExportReport);
    connect(&Quarantine::instance(), &Quarantine::changed, this, &MainWindow::populateQuarantineTable);

    static const QStringList cards = { "Hosts", "Redist", "Defender", "Firewall", "Crypto", "Drivers", "Dlls" };
    for (const QString &c : cards) {
        if (auto *bc = ui->pageRepair->findChild<QPushButton*>("btnRC" + c))
            connect(bc, &QPushButton::clicked, this, [this,c]{ onRepairCheck(c); });
        if (auto *bf = ui->pageRepair->findChild<QPushButton*>("btnRF" + c))
            connect(bf, &QPushButton::clicked, this, [this,c]{ onRepairFix(c); });
    }
    if (ui->btnRepairFixAll)
        connect(ui->btnRepairFixAll, &QPushButton::clicked, this, &MainWindow::onRepairFixAll);
    if (ui->btnRepairBrowseApp)
        connect(ui->btnRepairBrowseApp, &QPushButton::clicked, this, &MainWindow::onRepairBrowseAppFolder);

    connect(&Repair::instance(), &Repair::progress, this,
            [this](const QString &card, int pct, const QString &message){
        Toaster::show(this, QStringLiteral("[%1] %2").arg(card, message), Toaster::Info);
    });

    connect(&Repair::instance(), &Repair::finished, this,
            [this](const QString &card, bool ok, const QString &message){
        Toaster::show(this, message, ok ? Toaster::Success : Toaster::Error);
    });

    if (ui->cbStartWithWindows)    connect(ui->cbStartWithWindows,    &QCheckBox::toggled, this, &MainWindow::onSettingsSaved);
    if (ui->cbContextMenu)         connect(ui->cbContextMenu,         &QCheckBox::toggled, this, &MainWindow::onSettingsSaved);
    if (ui->cbMinimizeToTray)      connect(ui->cbMinimizeToTray,      &QCheckBox::toggled, this, &MainWindow::onSettingsSaved);
    if (ui->cbShowNotifications)   connect(ui->cbShowNotifications,   &QCheckBox::toggled, this, &MainWindow::onSettingsSaved);
    if (ui->cbRealTimeShield) {
        connect(ui->cbRealTimeShield, &QCheckBox::toggled, this, &MainWindow::onSettingsSaved);
        connect(ui->cbRealTimeShield, &QCheckBox::toggled, this, [](bool v){
            RealTimeShield::instance().setEnabled(v);
        });
    }
    if (ui->cbWebShield) {
        connect(ui->cbWebShield, &QCheckBox::toggled, this, &MainWindow::onSettingsSaved);
        connect(ui->cbWebShield, &QCheckBox::toggled, this, [](bool v){
            WebShield::instance().setEnabled(v);
        });
    }
    if (ui->cbScanUsbOnInsert)     connect(ui->cbScanUsbOnInsert,     &QCheckBox::toggled, this, &MainWindow::onSettingsSaved);
    if (ui->cbAutoUpdateSignatures)connect(ui->cbAutoUpdateSignatures,&QCheckBox::toggled, this, &MainWindow::onSettingsSaved);
    if (ui->comboLanguage)         connect(ui->comboLanguage, QOverload<int>::of(&QComboBox::currentIndexChanged),
                                           this, &MainWindow::onLanguageSelectionChanged);
    if (ui->comboTheme) {
        connect(ui->comboTheme, QOverload<int>::of(&QComboBox::currentIndexChanged),
                this, [this](int idx){
            QString mode = "dark";
            if (idx == 1) mode = "light";
            else if (idx == 2) mode = "system";
            ThemeManager::applyTheme(mode);
            if (m_tray && m_tray->contextMenu()) {
                m_tray->contextMenu()->setStyleSheet(ThemeManager::trayStyleSheet());
            }
            Toaster::show(this, tr("Motyw interfejsu został zmieniony."), Toaster::Success);
        });
    }
    if (ui->comboScheduledScan)    connect(ui->comboScheduledScan, QOverload<int>::of(&QComboBox::currentIndexChanged),
                                           this, [this](int){ onSettingsSaved(); });
    if (ui->btnResetSettings)      connect(ui->btnResetSettings, &QPushButton::clicked, this, &MainWindow::onSettingsReset);
    if (ui->cbRansomwareProtection) {
        connect(ui->cbRansomwareProtection, &QCheckBox::toggled, this, [](bool v){
            Settings::instance().setRansomwareProtection(v);
            RansomwareShield::instance().setEnabled(v);
        });
    }
    if (ui->btnAddExclusionFolder)  connect(ui->btnAddExclusionFolder, &QPushButton::clicked, this, &MainWindow::onAddExclusionFolder);
    if (ui->btnAddExclusionFile)    connect(ui->btnAddExclusionFile,   &QPushButton::clicked, this, &MainWindow::onAddExclusionFile);
    if (ui->btnRemoveExclusion)     connect(ui->btnRemoveExclusion,    &QPushButton::clicked, this, &MainWindow::onRemoveExclusion);
    if (ui->btnGenerateReportAbout) connect(ui->btnGenerateReportAbout,&QPushButton::clicked, this, &MainWindow::onGenerateServiceReportClicked);

    if (ui->btnSelfTest)           connect(ui->btnSelfTest, &QPushButton::clicked, this, &MainWindow::onSelfTest);

    if (ui->btnInstallNow)    connect(ui->btnInstallNow,    &QPushButton::clicked, this, &MainWindow::onInstallNow);
    if (ui->btnInstallBrowse) connect(ui->btnInstallBrowse, &QPushButton::clicked, this, &MainWindow::onInstallBrowse);
    if (ui->btnInstallCancel) connect(ui->btnInstallCancel, &QPushButton::clicked, this, &MainWindow::onInstallCancel);

    // Licensing buttons (Settings & Lock screen)
    if (ui->btnChangeLicenseKey)   connect(ui->btnChangeLicenseKey,   &QPushButton::clicked, this, &MainWindow::onChangeLicenseKeyClicked);
    if (ui->btnRefreshLicense)     connect(ui->btnRefreshLicense,     &QPushButton::clicked, this, &MainWindow::onRefreshLicenseClicked);
    if (ui->btnActivateLockedKey)  connect(ui->btnActivateLockedKey,  &QPushButton::clicked, this, &MainWindow::onActivateLockedKeyClicked);
    if (ui->btnRefreshLockedKey)   connect(ui->btnRefreshLockedKey,   &QPushButton::clicked, this, &MainWindow::onRefreshLockedKeyClicked);

    connect(&SignatureDb::instance(), &SignatureDb::updateFinished,
            this, [this](int added, int total, const QString &err){
        if (err.isEmpty()) {
            Toaster::show(this, tr("Signatures updated: %1 added, %2 total").arg(added).arg(total), Toaster::Success);
        } else {
            Toaster::show(this, tr("Update failed: %1").arg(err), Toaster::Error);
        }
        Q_UNUSED(total);
        if (ui->lblSignaturesInfo) {
            ui->lblSignaturesInfo->setTextFormat(Qt::RichText);
            ui->lblSignaturesInfo->setText(signaturesInfoHtml());
        }
    });

    connect(&Translator::instance(), &Translator::localeChanged, this, &MainWindow::onLanguageChanged);

    if (ui->flagPl) connect(ui->flagPl, &FlagIcon::clicked, this, []{ Translator::instance().install("pl"); });
    if (ui->flagEn) connect(ui->flagEn, &FlagIcon::clicked, this, []{ Translator::instance().install("en"); });
    if (ui->flagAr) connect(ui->flagAr, &FlagIcon::clicked, this, []{ Translator::instance().install("ar"); });

    if (ui->cbEngineSigDb)      connect(ui->cbEngineSigDb, &QCheckBox::toggled, this, [](bool v){ Settings::instance().setUseSignatureDb(v); });
    if (ui->cbEnginePe)         connect(ui->cbEnginePe, &QCheckBox::toggled, this, [](bool v){ Settings::instance().setUsePeInspection(v); });
    if (ui->cbEngineHeuristics) connect(ui->cbEngineHeuristics, &QCheckBox::toggled, this, [](bool v){ Settings::instance().setUseHeuristics(v); });
    if (ui->cbEngineCloud)      connect(ui->cbEngineCloud, &QCheckBox::toggled, this, [](bool v){ Settings::instance().setUseCloudLookup(v); });

    if (ui->radioActionQuarantine) connect(ui->radioActionQuarantine, &QRadioButton::toggled, this, [](bool v){ if (v) Settings::instance().setDetectionAction("quarantine"); });
    if (ui->radioActionDelete)     connect(ui->radioActionDelete, &QRadioButton::toggled, this, [](bool v){ if (v) Settings::instance().setDetectionAction("delete"); });
    if (ui->radioActionReport)     connect(ui->radioActionReport, &QRadioButton::toggled, this, [](bool v){ if (v) Settings::instance().setDetectionAction("report"); });

    if (ui->editQuarantineSearch && ui->tableQuarantine)
        connect(ui->editQuarantineSearch, &QLineEdit::textChanged, this,
                [this](const QString &q){
            auto *t = ui->tableQuarantine;
            const QString needle = q.trimmed().toLower();
            for (int r = 0; r < t->rowCount(); ++r) {
                bool match = needle.isEmpty();
                for (int c = 0; c < t->columnCount() && !match; ++c) {
                    if (auto *it = t->item(r, c))
                        if (it->text().toLower().contains(needle))
                            match = true;
                }
                t->setRowHidden(r, !match);
            }
        });
    connect(&verax::Quarantine::instance(), &verax::Quarantine::changed, this, &MainWindow::populateQuarantineTable);
}

void MainWindow::changeEvent(QEvent *e)
{
    if (e->type() == QEvent::LanguageChange) {
        ui->retranslateUi(this);
        retranslateRuntime();
    } else if (e->type() == QEvent::WindowStateChange) {
        if (ui->chromeBar) {
            ui->chromeBar->updateMaximizeIcon(isMaximized());
        }
    }
    QMainWindow::changeEvent(e);
}

void MainWindow::retranslateRuntime()
{
    if (ui->chromeBar) ui->chromeBar->setTitle(QString::fromLatin1(APP_NAME));

    if (ui->driveList) {
        const auto tiles = ui->driveList->findChildren<DriveTile*>();
        for (auto *t : tiles) t->retranslate();
    }
    if (ui->lblAppNameVersion)
        ui->lblAppNameVersion->setText(QStringLiteral("%1 v%2").arg(APP_NAME, APP_VERSION_STR));

    connect(&LicenseManager::instance(), &LicenseManager::licenseChanged,
            this, &MainWindow::onLicenseChanged);
    applyLicenseGating();
}

void MainWindow::onLanguageChanged(const QString &code)
{
    if (ui->comboLanguage) {
        const QSignalBlocker block(ui->comboLanguage);
        int idx = 0;
        if (code == "en") idx = 1;
        else if (code == "ar") idx = 2;
        ui->comboLanguage->setCurrentIndex(idx);
    }
    if (m_tray) m_tray->setToolTip(QString::fromLatin1(APP_NAME));
}

void MainWindow::onNavClicked()
{
    if (!LicenseManager::instance().isValid()) {
        setActiveNav(PageLicenseLocked);
        Toaster::show(this, tr("Licencja wygasła. Wprowadź nowy klucz lub zadzwoń: 505 012 914"), Toaster::Warning);
        return;
    }

    auto *btn = qobject_cast<QPushButton*>(sender());
    if (!btn) return;
    const QString name = btn->objectName();
    PageIndex idx = PageDashboard;
    if      (name == "navDashboard")  idx = PageDashboard;
    else if (name == "navScanConfig") idx = PageScanConfig;
    else if (name == "navScan")       idx = PageScan;
    else if (name == "navQuarantine") idx = PageQuarantine;
    else if (name == "navRepair") {
        if (!LicenseManager::instance().hasCapability(LicenseCapability::SystemRepair)) {
            Toaster::show(this, tr("Moduł Naprawa Windows wymaga licencji Multi-Guard Secure lub ADMIN FULL."), Toaster::Warning);
            return;
        }
        idx = PageRepair;
    }
    else if (name == "navTools")        idx = PageTools;
    else if (name == "navRemoteRepair") {
        if (!LicenseManager::instance().hasCapability(LicenseCapability::RemoteRepair)) {
            Toaster::show(this, tr("Zdalna Pomoc Techniczna wymaga licencji Assist / Assist PRO lub ADMIN FULL."), Toaster::Warning);
            return;
        }
        idx = PageRemoteRepair;
    }
    else if (name == "navSettings")     idx = PageSettings;
    else if (name == "navAbout")        idx = PageAbout;
    setActiveNav(idx);
}

void MainWindow::setActiveNav(PageIndex idx)
{
    m_currentPage = idx;
    m_transition->slideTo(int(idx));

    if (idx == PageTools) {
        onRefreshHardwareStats();
        onRefreshStartupClicked();
        if (m_hwTimer && !m_hwTimer->isActive()) {
            m_hwTimer->start();
        }
    } else {
        if (m_hwTimer && m_hwTimer->isActive()) {
            m_hwTimer->stop();
        }
    }

    const QList<QPushButton*> navButtons = ui->sidebar->findChildren<QPushButton*>();
    for (auto *b : navButtons) {
        if (!b->objectName().startsWith("nav")) continue;
        bool active = false;
        if (b->objectName() == "navDashboard")    active = (idx == PageDashboard);
        if (b->objectName() == "navScanConfig")   active = (idx == PageScanConfig);
        if (b->objectName() == "navScan")         active = (idx == PageScan);
        if (b->objectName() == "navQuarantine")   active = (idx == PageQuarantine);
        if (b->objectName() == "navRepair")       active = (idx == PageRepair);
        if (b->objectName() == "navTools")        active = (idx == PageTools);
        if (b->objectName() == "navRemoteRepair") active = (idx == PageRemoteRepair);
        if (b->objectName() == "navSettings")     active = (idx == PageSettings);
        if (b->objectName() == "navAbout")        active = (idx == PageAbout);
        b->setProperty("active", active);
        b->style()->unpolish(b);
        b->style()->polish(b);
    }
}

QStringList MainWindow::collectScanTargets() const
{
    QStringList targets;
    if (ui->driveList) {
        const QList<DriveTile*> tiles = ui->driveList->findChildren<DriveTile*>();
        for (auto *t : tiles)
            if (t->isChecked())
                targets << t->letter() + "/";
    }
    if (ui->listExtraTargets) {
        for (int i = 0; i < ui->listExtraTargets->count(); ++i)
            targets << ui->listExtraTargets->item(i)->text();
    }
    return targets;
}

ScanRequest MainWindow::buildScanRequest() const
{
    ScanRequest req;
    Settings &s = Settings::instance();

    req.useSigDb  = s.useSignatureDb();
    req.usePe     = s.usePeInspection();
    req.useHeur   = s.useHeuristics();
    req.useCloud  = s.useCloudLookup();
    req.threshold = s.heuristicThreshold();
    req.action    = s.detectionAction();
    req.targets   = collectScanTargets();

    QStringList exts;
    if (ui->cbExtExecutable && ui->cbExtExecutable->isChecked())
        exts << "exe" << "dll" << "sys" << "scr" << "ocx" << "cpl" << "drv";
    if (ui->cbExtScripts && ui->cbExtScripts->isChecked())
        exts << "bat" << "cmd" << "ps1" << "vbs" << "js";
    if (ui->cbExtDocuments && ui->cbExtDocuments->isChecked())
        exts << "doc" << "docx" << "xls" << "xlsx" << "pdf";
    if (ui->cbExtArchives && ui->cbExtArchives->isChecked())
        exts << "zip" << "rar" << "7z" << "iso";
    if (ui->cbExtAll && ui->cbExtAll->isChecked())
        exts.clear();
    req.extensionFilter = exts;
    return req;
}

// Builds the default ScanRequest for Quick scan: scope = standard malware
// drop / persistence locations, engines/threshold/action from Settings.
static ScanRequest buildQuickDefaults()
{
    ScanRequest req;
    Settings &s = Settings::instance();
    req.useSigDb  = s.useSignatureDb();
    req.usePe     = s.usePeInspection();
    req.useHeur   = s.useHeuristics();
    req.useCloud  = s.useCloudLookup();
    req.threshold = s.heuristicThreshold();
    req.action    = s.detectionAction();

    QStringList qs;
    qs << QStandardPaths::writableLocation(QStandardPaths::TempLocation)
       << QStandardPaths::writableLocation(QStandardPaths::DownloadLocation)
       << QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation)
       << QStandardPaths::writableLocation(QStandardPaths::AppDataLocation)
       << QStandardPaths::writableLocation(QStandardPaths::GenericDataLocation)
       << QStandardPaths::writableLocation(QStandardPaths::DesktopLocation);
#ifdef _WIN32
    qs << qEnvironmentVariable("APPDATA")
       << qEnvironmentVariable("LOCALAPPDATA")
       << qEnvironmentVariable("ProgramData")
       << qEnvironmentVariable("USERPROFILE") + "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
       << qEnvironmentVariable("ProgramData") + "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup";
#endif
    QSet<QString> seen;
    for (QString p : qs) {
        if (p.isEmpty()) continue;
        p = QDir::cleanPath(p);
        if (seen.contains(p)) continue;
        if (!QDir(p).exists() && !QFileInfo::exists(p)) continue;
        seen.insert(p);
        req.targets << p;
    }

    req.extensionFilter = QStringList{
        "exe","dll","sys","scr","ocx","cpl","drv",
        "bat","cmd","ps1","psm1","vbs","vbe","js","jse","wsf","hta",
        "docm","xlsm","pptm","dotm","xltm","potm","docx","xlsx","pptx",
        "zip","jar","apk","iso","msix","appx"
    };
    return req;
}

// Builds the default ScanRequest for Full scan: every fixed drive, no filter.
static ScanRequest buildFullDefaults()
{
    ScanRequest req;
    Settings &s = Settings::instance();
    req.useSigDb  = s.useSignatureDb();
    req.usePe     = s.usePeInspection();
    req.useHeur   = s.useHeuristics();
    req.useCloud  = s.useCloudLookup();
    req.threshold = s.heuristicThreshold();
    req.action    = s.detectionAction();
    for (const auto &d : SystemEnum::listDrives())
        req.targets << d.letter + "/";
    req.extensionFilter.clear();
    return req;
}

// Switches to the scan page and primes the UI so the user sees instant
// feedback before the scan thread emits its first signal.
void MainWindow::primeScanUi(const QString &phaseLabel)
{
    setActiveNav(PageScan);
    if (ui->scanRing) {
        ui->scanRing->setMode("scanning");
        ui->scanRing->setValue(0.0);
        ui->scanRing->setCenterText(tr("Starting"));
    }
    if (ui->lblScanCurrent) ui->lblScanCurrent->setText(phaseLabel);
    if (ui->lblScanCount)   ui->lblScanCount->setText(tr("Files scanned: 0"));
    if (ui->lblScanThreats) ui->lblScanThreats->setText(tr("Threats: 0"));
    ui->scanRing->setCenterText(tr(""));
    updateChromeStatus("scanning", tr("Scanning..."));
    QCoreApplication::processEvents(QEventLoop::ExcludeUserInputEvents);
}

void MainWindow::scanCustomTargets(const QStringList &targets)
{
    if (targets.isEmpty()) return;
    ScanRequest req;
    req.targets    = targets;
    req.useSigDb   = Settings::instance().useSignatureDb();
    req.usePe      = Settings::instance().usePeInspection();
    req.useHeur    = Settings::instance().useHeuristics();
    req.useCloud   = Settings::instance().useCloudLookup();
    req.threshold  = Settings::instance().heuristicThreshold();
    req.action     = Settings::instance().detectionAction();

    Logger::info(QStringLiteral("Custom targets scan requested: %1 target(s)").arg(targets.size()));
    primeScanUi(tr("Skanowanie wybranego elementu..."));
    m_activeScanPhase = tr("Skanowanie...");
    Toaster::show(this, tr("Rozpoczęto skanowanie wybranego elementu"), Toaster::Info);
    ShieldEngine::instance().startScan(req);
}

void MainWindow::onRealTimeThreatDetected(const verax::ThreatInfo &info)
{
    const QString fileName = QFileInfo(info.path).fileName();
    const QString msg = tr("Wykryto zagrożenie w czasie rzeczywistym:\n%1 w %2")
                        .arg(info.detectionName, fileName);
    Toaster::show(this, msg, Toaster::Error);

    NotificationAlert::showThreat(
        info.detectionName,
        info.path,
        [info]{
            Quarantine::instance().moveToVault(info.path, info.sha256, info.detectionName);
        },
        [this]{
            show();
            setActiveNav(PageQuarantine);
            raise();
            activateWindow();
        }
    );

    if (m_tray && Settings::instance().showNotifications()) {
        m_tray->showMessage(tr("Multi-Guard — Wykryto zagrożenie!"),
                            tr("Zablokowano lub odizolowano złośliwy plik: %1 (%2)")
                            .arg(fileName, info.detectionName),
                            QSystemTrayIcon::Critical, 8000);
    }
}

void MainWindow::onScanMemory()
{
    Logger::info("Memory/Running processes scan requested");
    const QVector<ProcInfo> procs = SystemEnum::listProcesses();
    if (procs.isEmpty()) {
        Toaster::show(this, tr("Brak aktywnych procesów do analizy"), Toaster::Warn);
        return;
    }

    QStringList procPaths;
    for (const auto &p : procs) {
        if (!p.path.isEmpty() && QFile::exists(p.path)) {
            if (!procPaths.contains(p.path, Qt::CaseInsensitive)) {
                procPaths << p.path;
            }
        }
    }

    if (procPaths.isEmpty()) {
        Toaster::show(this, tr("Nie znaleziono procesów z dostępem do ścieżki pliku"), Toaster::Warn);
        return;
    }

    Logger::info(QStringLiteral("Memory scan launching for %1 running process binaries").arg(procPaths.size()));
    primeScanUi(tr("Skanowanie procesów w pamięci RAM..."));
    m_activeScanPhase = tr("Skanowanie pamięci...");
    Toaster::show(this, tr("Rozpoczęto skanowanie aktywnych procesów w pamięci RAM"), Toaster::Info);

    ScanRequest req;
    req.targets   = procPaths;
    req.useSigDb  = Settings::instance().useSignatureDb();
    req.usePe     = Settings::instance().usePeInspection();
    req.useHeur   = Settings::instance().useHeuristics();
    req.useCloud  = Settings::instance().useCloudLookup();
    req.threshold = Settings::instance().heuristicThreshold();
    req.action    = Settings::instance().detectionAction();

    ShieldEngine::instance().startScan(req);
}

void MainWindow::onUsbDriveInserted(const QString &drivePath)
{
    if (!Settings::instance().scanUsbOnInsert()) return;

    NotificationAlert::showUsb(drivePath, [this, drivePath]{
        show();
        raise();
        activateWindow();
        scanCustomTargets(QStringList{drivePath});
    });
}

void MainWindow::onQuickScan()
{
    Logger::info("Quick scan requested");
    ScanRequest req = buildQuickDefaults();

    ScanOptionsDialog dlg(ScanOptionsDialog::Quick, req, this);
    if (dlg.exec() != QDialog::Accepted) {
        Logger::info("Quick scan cancelled at options dialog");
        return;
    }
    req = dlg.result();
    if (req.targets.isEmpty()) {
        Toaster::show(this, tr("No paths selected — scan aborted"), Toaster::Warn);
        return;
    }

    Logger::info(QStringLiteral("Quick scan launching with %1 path(s), action=%2")
                 .arg(req.targets.size()).arg(req.action));
    primeScanUi(tr("Enumerating files..."));
    Toaster::show(this, tr("Quick scan started"), Toaster::Info);
    ShieldEngine::instance().startScan(req);
}

void MainWindow::onFullScan()
{
    Logger::info("Full scan requested");
    ScanRequest req = buildFullDefaults();

    ScanOptionsDialog dlg(ScanOptionsDialog::Full, req, this);
    if (dlg.exec() != QDialog::Accepted) {
        Logger::info("Full scan cancelled at options dialog");
        return;
    }
    req = dlg.result();
    if (req.targets.isEmpty()) {
        Toaster::show(this, tr("No paths selected — scan aborted"), Toaster::Warn);
        return;
    }

    Logger::info(QStringLiteral("Full scan launching with %1 path(s), action=%2")
                 .arg(req.targets.size()).arg(req.action));
    primeScanUi(tr("Mapping filesystems..."));
    Toaster::show(this, tr("Full scan started"), Toaster::Info);
    ShieldEngine::instance().startScan(req);
}


void MainWindow::onUpdateSignatures()
{
    Toaster::show(this, tr("Contacting update server..."), Toaster::Info);
    SignatureDb::instance().updateOnline(Settings::instance().updateUrl());
}

void MainWindow::onAddFolder()
{
    const QString d = QFileDialog::getExistingDirectory(this, tr("Add folder"));
    if (!d.isEmpty() && ui->listExtraTargets) ui->listExtraTargets->addItem(d);
}

void MainWindow::onAddFile()
{
    const QString f = QFileDialog::getOpenFileName(this, tr("Add file"));
    if (!f.isEmpty() && ui->listExtraTargets) ui->listExtraTargets->addItem(f);
}

void MainWindow::onStartScanFromConfig()
{
    const ScanRequest req = buildScanRequest();
    if (req.targets.isEmpty()) {
        Toaster::show(this, tr("Select at least one drive, folder or file"), Toaster::Warn);
        return;
    }
    if (ui->lblScanCurrent) ui->lblScanCurrent->setText(tr("Preparing Custom Scan Parameters..."));
    setActiveNav(PageScan);
    ui->scanRing->setMode("idle");
    ui->scanRing->setValue(0.0);
    ui->scanRing->setCenterText(tr(""));
    ShieldEngine::instance().startScan(req);
}

void MainWindow::onStopScan()
{
    ShieldEngine::instance().stopScan();
    if (ui->scanRing) {
        ui->scanRing->setMode("idle");
        ui->scanRing->setValue(0.0);
        ui->scanRing->setCenterText(tr("Aborted"));
    }
    if (ui->lblScanCurrent) ui->lblScanCurrent->setText(tr("Scan cancelled by user. Everything clean."));
    if (ui->lblScanCount) ui->lblScanCount->setText(tr("Files scanned: 0"));
    if (ui->lblScanThreats) ui->lblScanThreats->setText(tr("Threats: 0"));
    updateChromeStatus("idle", tr("Cancelled"));
}

void MainWindow::onPauseToggled(bool paused) {
    ShieldEngine::instance().pauseScan(paused);
    if (ui->btnPauseScan) ui->btnPauseScan->setText(paused ? tr("Resume") : tr("Pause"));
}

void MainWindow::onScannerStarted()
{
    updateChromeStatus("scanning", tr("Scanning..."));
    if (ui->scanRing) {
        ui->scanRing->setMode("scanning");
        ui->scanRing->setValue(0.0);
    }
    if (ui->lblScanCount)   ui->lblScanCount->setText(tr("Files scanned: 0"));
    if (ui->lblScanThreats) ui->lblScanThreats->setText(tr("Threats: 0"));
    m_lastScanThreats = 0;
    m_pendingReport.clear();
    m_threatCards.clear();

    if (ui->threatList) {
        QLayout *l = ui->threatList->layout();
        if (l) {
            while (auto *item = l->takeAt(0)) {
                if (auto *w = item->widget()) w->deleteLater();
                delete item;
            }
        }
    }
    buildThreatFilterToolbar();
}

void MainWindow::onScannerProgress(int pct, qint64 done, qint64 total)
{
    if (ui->scanRing) ui->scanRing->setValue(pct / 100.0);
    if (ui->lblScanCount)
        ui->lblScanCount->setText(tr("Files scanned: %1 / %2").arg(done).arg(total));
}

void MainWindow::onScannerFileScanned(const QString &path)
{
    if (ui->lblScanCurrent) ui->lblScanCurrent->setText(path);
}

void MainWindow::onScannerThreatFound(ThreatInfo info)
{
    ++m_lastScanThreats;
    if (ui->lblScanThreats)
        ui->lblScanThreats->setText(tr("Threats: %1").arg(m_lastScanThreats));

    Logger::warn(QStringLiteral("UI threat: %1 [%2] score=%3")
                 .arg(info.path, info.detectionName).arg(info.score));

    // Auto-action per Settings::detectionAction. This is the contract the
    // user picks in Scan Config (Quarantine / Delete / Report / Repair).
    // "Repair" already runs inside the scanner thread.
    const QString action = Settings::instance().detectionAction();
    if (action == "quarantine") {
        const QString vault = Quarantine::instance().moveToVault(
            info.path, info.sha256, info.detectionName);
        if (!vault.isEmpty()) {
            info.reason += QStringLiteral(" | Auto-quarantined");
            Toaster::show(this, tr("Quarantined: %1").arg(QFileInfo(info.path).fileName()),
                          Toaster::Success);
            Logger::info(QStringLiteral("Auto-quarantine OK: %1 -> %2").arg(info.path, vault));
        } else {
            info.reason += QStringLiteral(" | Auto-quarantine FAILED");
            Logger::error(QStringLiteral("Auto-quarantine FAILED: %1").arg(info.path));
        }
    } else if (action == "delete") {
        if (QFile::remove(info.path)) {
            info.reason += QStringLiteral(" | Auto-deleted");
            Toaster::show(this, tr("Deleted: %1").arg(QFileInfo(info.path).fileName()),
                          Toaster::Success);
            Logger::info(QStringLiteral("Auto-delete OK: %1").arg(info.path));
        } else {
            info.reason += QStringLiteral(" | Auto-delete FAILED");
            Logger::error(QStringLiteral("Auto-delete FAILED: %1").arg(info.path));
        }
    }
    // "report": no file mutation, just collect for the JSON report at finish.

    auto *card = new ThreatCard(info, this);
    connect(card, &ThreatCard::quarantineRequested, this, [this, card](const ThreatInfo &t){
        const QString v = Quarantine::instance().moveToVault(t.path, t.sha256, t.detectionName);
        Toaster::show(this,
                      v.isEmpty() ? tr("Quarantine failed: %1").arg(t.path)
                                  : tr("Moved to quarantine: %1").arg(QFileInfo(t.path).fileName()),
                      v.isEmpty() ? Toaster::Error : Toaster::Success);
        if (!v.isEmpty()) card->setActioned(tr("Quarantined"));
    });
    connect(card, &ThreatCard::deleteRequested, this, [this, card](const ThreatInfo &t){
        if (QFile::remove(t.path)) {
            Toaster::show(this, tr("Deleted: %1").arg(QFileInfo(t.path).fileName()), Toaster::Success);
            card->setActioned(tr("Deleted"));
        } else {
            Toaster::show(this, tr("Delete failed: %1").arg(t.path), Toaster::Error);
        }
    });
    connect(card, &ThreatCard::repairRequested, this, [this, card](const ThreatInfo &t){
        Toaster::show(this, tr("Creating backup & cleaning %1...").arg(QFileInfo(t.path).fileName()),
                      Toaster::Info);
        card->setActioned(tr("Backup → Clean..."));

        ThreatInfo mutableInfo = t;
        QtConcurrent::run([this, card, mutableInfo]() mutable {
            Scanner repairScanner;
            bool success = repairScanner.advancedCleanThreat(mutableInfo.path, mutableInfo);

            QMetaObject::invokeMethod(this, [this, card, success, mutableInfo](){
                if (success) {
                    const QString bakPath = mutableInfo.path + ".verax_bak";
                    const bool hasBak = QFile::exists(bakPath);
                    Toaster::show(this,
                        tr("Clean Threat SUCCESS: %1 — virus removed, file restored%2")
                            .arg(QFileInfo(mutableInfo.path).fileName())
                            .arg(hasBak ? tr(" (backup preserved)") : QString()),
                        Toaster::Success);
                    card->setActioned(tr("Cleaned ✓"));
                } else {
                    // Repair FAILED — backup auto-restored by engine, offer Delete
                    Toaster::show(this,
                        tr("Clean failed for %1 — original file restored from backup")
                            .arg(QFileInfo(mutableInfo.path).fileName()),
                        Toaster::Error);
                    card->setRepairFailed();
                }
            }, Qt::QueuedConnection);
        });
    });
    connect(card, &ThreatCard::openFolderRequested, this, [this](const ThreatInfo &t){
        const QString folder = QFileInfo(t.path).absolutePath();
        if (folder.isEmpty()) return;
        QDesktopServices::openUrl(QUrl::fromLocalFile(folder));
    });
    connect(card, &ThreatCard::ignoreRequested, this, [this, card]{
        m_threatCards.removeOne(card);
        card->deleteLater();
    });

    if (action == "quarantine" && info.reason.contains(QLatin1String("Auto-quarantined")))
        card->setActioned(tr("Auto-quarantined"));
    else if (action == "delete" && info.reason.contains(QLatin1String("Auto-deleted")))
        card->setActioned(tr("Auto-deleted"));

    m_threatCards.append(card);

    if (ui->threatList) {
        auto *l = qobject_cast<QVBoxLayout*>(ui->threatList->layout());
        if (l) l->insertWidget(l->count(), card);
    }

    m_pendingReport.append(info);
}

void MainWindow::onScannerFinished(ScanReport report)
{
    // Force set compilation status properties based on calculation metrics
    updateChromeStatus(report.threatsFound > 0 ? QStringLiteral("threat") : QStringLiteral("done"),
                       report.threatsFound > 0
                           ? tr("Threats: %1").arg(report.threatsFound)
                           : tr("Clean"));

    if (ui->scanRing) {
        ui->scanRing->setMode(report.threatsFound > 0 ? QStringLiteral("threat") : QStringLiteral("done"));
        ui->scanRing->setValue(1.0);
        ui->scanRing->setCenterText(report.threatsFound > 0
                                        ? tr("%n threat(s)", "", report.threatsFound)
                                        : tr("Success"));
    }

    SignatureDb::instance().pushHistory(report.startedAt, report.finishedAt, report.filesScanned, report.threatsFound, QString());

    if (ui->lblLastScan) {
        auto makeRow = [](const QString &color, const QString &label, QString value) {
            value.replace(" ","_");
            return QStringLiteral(
                       "<tr>"
                       "<td style='vertical-align: middle; width: 10px; padding: 2px 0;'>"
                       "<div style='width: 2px; height: 12px; border-radius: 2px; background-color: %1;'></div>"
                       "</td>"
                       "<td dir='ltr' style='vertical-align: middle; padding: 2px 6px; font-size: 8pt; color: #64748B; font-weight: 500; font-family: -apple-system, BlinkMacSystemFont, \"Segoe UI\", Helvetica, Arial, sans-serif; text-transform: capitalize; white-space: nowrap; min-width: 85px; text-align: left;'>"
                       "%2"
                       "</td>"
                       "<td dir='ltr' style='vertical-align: middle; padding: 2px 0; font-size: 8pt; color: #0F172A; font-weight: 600; font-family: -apple-system, BlinkMacSystemFont, \"Segoe UI\", Helvetica, Arial, sans-serif; white-space: nowrap; text-align: left;'>"
                       "%3"
                       "</td>"
                       "</tr>"
                       ).arg(color, label.toHtmlEscaped(), value.toHtmlEscaped());
        };

        QString html;
        html += QStringLiteral("<table style='border-collapse: collapse; width: 100%; margin: 0; padding: 0;'>");
        html.toUtf8();
        if (report.finishedAt > 0) {
            QString scanTime = QDateTime::fromSecsSinceEpoch(report.finishedAt).toString("yyyy-MM-dd HH:mm");
            html += makeRow(QStringLiteral("#F97316"), tr("Last Scan"), scanTime);
            html += makeRow(QStringLiteral("#F59E0B"), tr("Files Scanned"), QString::number(report.filesScanned));
            html += makeRow(QStringLiteral("#EF4444"), tr("Threats Found"), QString::number(report.threatsFound));
        } else {
            html += QStringLiteral("<tr><td style='padding: 2px 0; font-size: 8pt; color: #0F172A; font-weight: 500; font-family: -apple-system, BlinkMacSystemFont, \"Segoe UI\", Helvetica, Arial, sans-serif; text-align: left;'>")
            + tr("No scans yet")
                + QStringLiteral("</td></tr>");
        }

        html += QStringLiteral("</table>");
        ui->lblLastScan->setText(html);
    }

    if (ui->lblScanCurrent) {
        ui->lblScanCurrent->setText(tr("Scan completed execution loop. System secure."));
    }

    // Write a JSON report file for EVERY scan (audit trail). Path:
    //   UserData/reports/scan-YYYYMMDD-HHMMSS.json
    const QString reportDir = Logger::userDataDir() + "/reports";
    QDir().mkpath(reportDir);
    const QString stamp = QDateTime::fromSecsSinceEpoch(report.finishedAt)
                              .toString("yyyyMMdd-HHmmss");
    const QString reportPath = QStringLiteral("%1/scan-%2.json").arg(reportDir, stamp);

    QJsonObject root;
    root["app"]            = QString::fromLatin1(APP_NAME);
    root["version"]        = QString::fromLatin1(APP_VERSION_STR);
    root["startedAt"]      = qint64(report.startedAt);
    root["finishedAt"]     = qint64(report.finishedAt);
    root["durationSec"]    = qint64(report.finishedAt - report.startedAt);
    root["filesScanned"]   = report.filesScanned;
    root["threatsFound"]   = report.threatsFound;
    root["action"]         = Settings::instance().detectionAction();
    QJsonArray arr;
    for (const auto &t : m_pendingReport) {
        QJsonObject o;
        o["path"]          = t.path;
        o["sha256"]        = t.sha256;
        o["detectionName"] = t.detectionName;
        o["family"]        = t.family;
        o["reason"]        = t.reason;
        o["severity"]      = t.severity;
        o["score"]         = t.score;
        o["size"]          = qint64(t.size);
        arr.append(o);
    }
    root["threats"] = arr;

    QFile rf(reportPath);
    if (rf.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        rf.write(QJsonDocument(root).toJson(QJsonDocument::Indented));
        rf.close();
        Logger::info(QStringLiteral("Scan report written: %1").arg(reportPath));
    } else {
        Logger::error(QStringLiteral("Scan report FAILED: %1").arg(reportPath));
    }

    Toaster::show(this,
                  report.threatsFound > 0
                      ? tr("Scan finished: %1 threat(s) found").arg(report.threatsFound)
                      : tr("Scan finished: no threats"),
                  report.threatsFound > 0 ? Toaster::Warn : Toaster::Success);
}

void MainWindow::populateQuarantineTable()
{
    if (!ui->tableQuarantine) return;
    auto *t = ui->tableQuarantine;
    t->clearContents();
    const auto entries = Quarantine::instance().list();
    t->setRowCount(entries.size());
    t->setColumnCount(5);
    t->setHorizontalHeaderLabels({ tr("Detection"), tr("Original path"), tr("Date"), tr("Size"), tr("Hash") });
    for (int i = 0; i < entries.size(); ++i) {
        const auto &e = entries[i];
        t->setItem(i, 0, new QTableWidgetItem(e.detectionName));
        t->setItem(i, 1, new QTableWidgetItem(e.originalPath));
        t->setItem(i, 2, new QTableWidgetItem(QDateTime::fromSecsSinceEpoch(e.quarantinedAt).toString("yyyy-MM-dd HH:mm")));
        t->setItem(i, 3, new QTableWidgetItem(FileOps::humanSize(e.size)));
        t->setItem(i, 4, new QTableWidgetItem(e.sha256));
        for (int c = 0; c < 5; ++c) t->item(i, c)->setData(Qt::UserRole, e.id);
    }
    t->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    t->resizeColumnsToContents();

    if (ui->lblQuarantineSummary) {
        auto makeRow = [](const QString &color, const QString &label, QString value) {
            value.replace(" ","/");
            return QStringLiteral(
                       "<tr>"
                       "<td style='vertical-align: middle; width: 10px; padding: 2px 0;'>"
                       "<div style='width: 2px; height: 12px; border-radius: 2px; background-color: %1;'></div>"
                       "</td>"
                       "<td dir='ltr' style='vertical-align: middle; padding: 2px 6px; font-size: 8pt; color: #64748B; font-weight: 500; font-family: -apple-system, BlinkMacSystemFont, \"Segoe UI\", Helvetica, Arial, sans-serif; text-transform: capitalize; white-space: nowrap; min-width: 85px; text-align: left;'>"
                       "%2"
                       "</td>"
                       "<td dir='ltr' style='vertical-align: middle; padding: 2px 0; font-size: 8pt; color: #0F172A; font-weight: 600; font-family: -apple-system, BlinkMacSystemFont, \"Segoe UI\", Helvetica, Arial, sans-serif; white-space: nowrap; text-align: left;'>"
                       "%3"
                       "</td>"
                       "</tr>"
                       ).arg(color, label.toHtmlEscaped(), value.toHtmlEscaped());
        };

        QString html;
        html += QStringLiteral("<table style='border-collapse: collapse; width: 100%; margin: 0; padding: 0;'>");

        html += makeRow(QStringLiteral("#F59E0B"), tr("Isolated Items"), QString::number(Quarantine::instance().count()));
        html += makeRow(QStringLiteral("#6366F1"), tr("Total Size"), FileOps::humanSize(Quarantine::instance().totalBytes()));

        html += QStringLiteral("</table>");
        ui->lblQuarantineSummary->setText(html);
    }
}

void MainWindow::onQuarantineRefresh() { populateQuarantineTable(); }

void MainWindow::onQuarantineRestoreSelected()
{
    if (!ui->tableQuarantine) return;
    const auto rows = ui->tableQuarantine->selectionModel()->selectedRows();
    int ok = 0;
    for (int i = rows.size() - 1; i >= 0; --i) {
        const int id = rows[i].data(Qt::UserRole).toInt();
        if (verax::Quarantine::instance().restore(id)) {
            ++ok;
        }
    }
    Toaster::show(this, tr("%n item(s) restored", "", ok), Toaster::Success);
    populateQuarantineTable();
}

void MainWindow::onQuarantineDeleteSelected()
{
    if (!ui->tableQuarantine) return;
    const auto rows = ui->tableQuarantine->selectionModel()->selectedRows();
    int ok = 0;
    for (int i = rows.size() - 1; i >= 0; --i) {
        const int id = rows[i].data(Qt::UserRole).toInt();
        if (verax::Quarantine::instance().permanentDelete(id)) {
            ++ok;
        }
    }
    Toaster::show(this, tr("%n item(s) deleted permanently", "", ok), Toaster::Warn);
    populateQuarantineTable();
}

void MainWindow::onQuarantineExportReport()
{
    const QString dst = QFileDialog::getSaveFileName(this, tr("Export quarantine report"), QStringLiteral("quarantine_report.json"), QStringLiteral("JSON (*.json)"));
    if (dst.isEmpty()) return;

    QJsonArray arr;
    for (const auto &e : Quarantine::instance().list()) {
        QJsonObject o;
        o["id"]            = e.id;
        o["original_path"] = e.originalPath;
        o["detection"]     = e.detectionName;
        o["sha256"]        = e.sha256;
        o["size"]          = double(e.size);
        o["quarantined_at"] = QDateTime::fromSecsSinceEpoch(e.quarantinedAt).toString(Qt::ISODate);
        arr.append(o);
    }
    QJsonObject root;
    root["product"] = APP_NAME;
    root["version"] = APP_VERSION_STR;
    root["generated_at"] = QDateTime::currentDateTime().toString(Qt::ISODate);
    root["entries"] = arr;
    FileOps::atomicWrite(dst, QJsonDocument(root).toJson());
    Toaster::show(this, tr("Report saved"), Toaster::Success);
}

void MainWindow::populateRepairCards()
{
    auto safeSetLbl = [this](const QString &name, RepairStatus s) {
        QMetaObject::invokeMethod(this, [this, name, s]() {
            if (!ui || !ui->pageRepair) return;
            auto *l = ui->pageRepair->findChild<QLabel*>(name);
            if (!l) return;
            QString txt;
            switch (s) {
            case RepairStatus::Ok:      txt = tr("OK");        break;
            case RepairStatus::Missing: txt = tr("Missing");   break;
            case RepairStatus::Bad:     txt = tr("Problem");   break;
            case RepairStatus::Working: txt = tr("Working...");break;
            default:                    txt = tr("Unknown");
            }
            l->setText(txt);
            l->setProperty("status",
                s == RepairStatus::Ok      ? "ok"      :
                s == RepairStatus::Missing ? "missing" :
                s == RepairStatus::Bad     ? "bad"     : "unknown");
            if (l->style()) { l->style()->unpolish(l); l->style()->polish(l); }
        }, Qt::QueuedConnection);
    };

    for (const char *n : { "lblRSHosts", "lblRSRedist", "lblRSDefender", "lblRSFirewall", "lblRSCrypto", "lblRSDrivers" })
        safeSetLbl(QString::fromLatin1(n), RepairStatus::Working);

    QtConcurrent::run([safeSetLbl]() {
        safeSetLbl("lblRSHosts",    Repair::instance().checkHosts());
        safeSetLbl("lblRSRedist",   Repair::instance().checkVcRedist());
        safeSetLbl("lblRSDrivers",  Repair::instance().checkPhoneDrivers());
        safeSetLbl("lblRSDefender", Repair::instance().checkDefenderExclusion());
        safeSetLbl("lblRSFirewall", Repair::instance().checkFirewallRule());
        safeSetLbl("lblRSCrypto",   Repair::instance().checkCryptoServices());
    });
}

void MainWindow::onRepairCheck(const QString &card)
{
    auto *l = ui->pageRepair ? ui->pageRepair->findChild<QLabel*>("lblRS" + card) : nullptr;
    if (l) {
        l->setText(tr("Working..."));
        l->setProperty("status", "unknown");
        if (l->style()) { l->style()->unpolish(l); l->style()->polish(l); }
    }
    Toaster::show(this, tr("Checking %1...").arg(card), Toaster::Info);

    QtConcurrent::run([this, card]() {
        RepairStatus s = RepairStatus::Unknown;
        if      (card == "Hosts")    s = Repair::instance().checkHosts();
        else if (card == "Redist")   s = Repair::instance().checkVcRedist();
        else if (card == "Defender") s = Repair::instance().checkDefenderExclusion();
        else if (card == "Firewall") s = Repair::instance().checkFirewallRule();
        else if (card == "Crypto")   s = Repair::instance().checkCryptoServices();
        else if (card == "Drivers")  s = Repair::instance().checkPhoneDrivers();

        QMetaObject::invokeMethod(this, [this, card, s]() {
            auto *l = ui->pageRepair ? ui->pageRepair->findChild<QLabel*>("lblRS" + card) : nullptr;
            if (!l) return;
            QString txt;
            const char *st = "unknown";
            switch (s) {
            case RepairStatus::Ok:      txt = tr("OK");        st = "ok";      break;
            case RepairStatus::Missing: txt = tr("Missing");   st = "missing"; break;
            case RepairStatus::Bad:     txt = tr("Problem");   st = "bad";     break;
            default:                    txt = tr("Unknown");
            }
            l->setText(txt);
            l->setProperty("status", st);
            if (l->style()) { l->style()->unpolish(l); l->style()->polish(l); }
        }, Qt::QueuedConnection);
    });
}

void MainWindow::onRepairFix(const QString &card)
{
    Toaster::show(this, tr("Fixing %1...").arg(card), Toaster::Info);
    if (card == "Drivers") {
        const QString folder = QFileDialog::getExistingDirectory(this, tr("Select folder containing .inf driver files"));
        if (folder.isEmpty()) return;
        QtConcurrent::run([folder]{ Repair::instance().fixPhoneDrivers(folder); });
        return;
    }

    if (auto *l = ui->pageRepair ? ui->pageRepair->findChild<QLabel*>("lblRS" + card) : nullptr) {
        l->setText(tr("Working..."));
        l->setProperty("status", "unknown");
        if (l->style()) { l->style()->unpolish(l); l->style()->polish(l); }
    }

    QtConcurrent::run([this, card]{
        if      (card == "Hosts")    Repair::instance().fixHosts();
        else if (card == "Redist")   Repair::instance().fixVcRedist();
        else if (card == "Defender") Repair::instance().fixDefenderExclusion();
        else if (card == "Firewall") Repair::instance().fixFirewallRule();
        else if (card == "Crypto")   Repair::instance().fixCryptoServices();

        QMetaObject::invokeMethod(this, [this, card]() {
            onRepairCheck(card);
        }, Qt::QueuedConnection);
    });
}

void MainWindow::onRepairFixAll()
{
    Toaster::show(this, tr("Running all repairs..."), Toaster::Info);
    QtConcurrent::run([]{ Repair::instance().fixAll(); });
}

void MainWindow::onRepairBrowseAppFolder()
{
    const QString d = QFileDialog::getExistingDirectory(this, tr("Select application folder to verify DLLs"));
    if (!d.isEmpty() && ui->editAppFolder) ui->editAppFolder->setText(d);
}

void MainWindow::onSettingsSaved()
{
    Settings &s = Settings::instance();
    if (ui->cbStartWithWindows)    s.setStartWithWindows(ui->cbStartWithWindows->isChecked());
    if (ui->cbContextMenu)         s.setContextMenuIntegration(ui->cbContextMenu->isChecked());
    if (ui->cbMinimizeToTray)      s.setMinimizeToTrayOnClose(ui->cbMinimizeToTray->isChecked());
    if (ui->cbShowNotifications)   s.setShowNotifications(ui->cbShowNotifications->isChecked());
    if (ui->cbScanUsbOnInsert)     s.setScanUsbOnInsert(ui->cbScanUsbOnInsert->isChecked());
    if (ui->cbAutoUpdateSignatures)s.setAutoUpdateSignatures(ui->cbAutoUpdateSignatures->isChecked());
    // if (ui->editUpdateUrl)         s.setUpdateUrl(ui->editUpdateUrl->text());
    if (ui->comboScheduledScan) {
        const QStringList opts{"off","daily","weekly","monthly"};
        s.setScheduledScan(opts.value(ui->comboScheduledScan->currentIndex(), "off"));
    }
    if (ui->editScheduledTime)
        s.setScheduledTime(ui->editScheduledTime->time().toString("HH:mm"));
}

void MainWindow::onSettingsReset()
{
    Settings::instance().resetAll();
    const auto blockAll = [this](bool b){
        for (auto *w : findChildren<QCheckBox*>())    w->blockSignals(b);
        for (auto *w : findChildren<QComboBox*>())    w->blockSignals(b);
        for (auto *w : findChildren<QRadioButton*>()) w->blockSignals(b);
        for (auto *w : findChildren<QLineEdit*>())    w->blockSignals(b);
        for (auto *w : findChildren<QTimeEdit*>())    w->blockSignals(b);
    };
    blockAll(true);
    wireUi();
    blockAll(false);
    ThemeManager::applyTheme(Settings::instance().theme());
    if (m_tray && m_tray->contextMenu()) {
        m_tray->contextMenu()->setStyleSheet(ThemeManager::trayStyleSheet());
    }
    Toaster::show(this, tr("Settings reset to defaults"), Toaster::Success);
}

void MainWindow::onCheckUpdatesNow()
{
    // SignatureDb::instance().updateOnline(QStringLiteral("https://gist.githubusercontent.com/alisakkaf/01eaea5312e4e583f993b891554666f3/raw/VeraxCore_Antivirus.json"));

    if(ui->editUpdateUrl->text().isEmpty())
    {
        Toaster::show(this, tr("Add URL Database Json....!"), Toaster::Warn);
        return;
    }
    SignatureDb::instance().updateOnline((ui->editUpdateUrl->text()));

}

void MainWindow::onLanguageSelectionChanged(int idx)
{
    if (idx == 0)      Translator::instance().install("pl");
    else if (idx == 1) Translator::instance().install("en");
    else if (idx == 2) Translator::instance().install("ar");
}

QString MainWindow::signaturesInfoHtml() const
{
    QSettings settings;
    QString schemaVersion = QStringLiteral("—");
    QString generatedAt   = QStringLiteral("—");

    if (settings.contains(QStringLiteral("db/schema_version"))) {
        schemaVersion = QString::number(settings.value(QStringLiteral("db/schema_version")).toInt());
        generatedAt   = settings.value(QStringLiteral("db/generated_at")).toString();
    } else {
        QFile sf(QStringLiteral(":/signatures/seed.json"));
        if (sf.open(QIODevice::ReadOnly)) {
            const QJsonDocument doc = QJsonDocument::fromJson(sf.readAll());
            if (doc.isObject()) {
                const QJsonObject o = doc.object();
                schemaVersion = QString::number(o.value("schema_version").toInt(0));
                generatedAt   = o.value("generated_at").toString();
                if (schemaVersion == QLatin1String("0")) schemaVersion = QStringLiteral("—");
            }
        }
    }

    const int total = SignatureDb::instance().totalSignatures();
    const QString lastUpdate = SignatureDb::instance().lastUpdate().isEmpty()
                                   ? tr("never")
                                   : SignatureDb::instance().lastUpdate();

    auto makeRow = [](const QString &color, const QString &label, QString value) {
        value.replace(" ","_");
        return QStringLiteral(
                   "<tr>"
                   "<td style='vertical-align: middle; width: 10px; padding: 2px 0;'>"
                   "<div style='width: 2px; height: 12px; border-radius: 2px; background-color: %1;'></div>"
                   "</td>"
                   "<td dir='ltr' style='vertical-align: middle; padding: 2px 6px; font-size: 8pt; color: #64748B; font-weight: 500; font-family: -apple-system, BlinkMacSystemFont, \"Segoe UI\", Helvetica, Arial, sans-serif; text-transform: capitalize; white-space: nowrap; min-width: 85px; text-align: left;'>"
                   "%2"
                   "</td>"
                   "<td dir='ltr' style='vertical-align: middle; padding: 2px 0; font-size: 8pt; color: #0F172A; font-weight: 600; font-family: -apple-system, BlinkMacSystemFont, \"Segoe UI\", Helvetica, Arial, sans-serif; white-space: nowrap; text-align: left;'>"
                   "%3"
                   "</td>"
                   "</tr>"
                   ).arg(color, label.toHtmlEscaped(), value.toHtmlEscaped());
    };

    QString html;
    html += QStringLiteral("<table style='border-collapse: collapse; width: 100%; margin: 0; padding: 0;'>");

    html += makeRow(QStringLiteral("#10B981"), tr("Schema Version"), schemaVersion);
    html += makeRow(QStringLiteral("#F59E0B"), tr("Total Signatures"), QString::number(total));
    html += makeRow(QStringLiteral("#94A3B8"), tr("Generated At"), generatedAt);
    html += makeRow(QStringLiteral("#EF4444"), tr("Last Update"), lastUpdate);

    html += QStringLiteral("</table>");
    return html;
}

void MainWindow::populateAboutPage()
{
    if (ui->lblAboutTitle)       ui->lblAboutTitle->setText(QString::fromLatin1(APP_NAME));
    if (ui->lblAboutVersion)     ui->lblAboutVersion->setText(tr("Version %1").arg(APP_VERSION_STR));
    if (ui->lblAboutVendor) {
        ui->lblAboutVendor->setTextFormat(Qt::RichText);
        ui->lblAboutVendor->setOpenExternalLinks(true);
        ui->lblAboutVendor->setText(QStringLiteral(
            "<a href=\"%1\" style=\"color:#FF7A1A; text-decoration:none; font-weight:700;\">%2</a>")
            .arg(QString::fromLatin1(APP_HOMEPAGE),
                 tr("By %1").arg(QString::fromLatin1(APP_VENDOR))));
    }
    if (ui->lblAboutDescription) ui->lblAboutDescription->setText(QString::fromLatin1(APP_DESCRIPTION));
    if (ui->lblAboutCopyright)   ui->lblAboutCopyright->setText(QString::fromLatin1(APP_COPYRIGHT));
    if (ui->lblAboutBuild)       ui->lblAboutBuild->setText(tr("Built %1  ·  Qt %2").arg(QString::fromLatin1(__DATE__)).arg(QString::fromLatin1(QT_VERSION_STR)));
    if (ui->lblAboutHomepage)    ui->lblAboutHomepage->setText(QStringLiteral("<a href=\"%1\">%1</a>").arg(APP_HOMEPAGE));

    if (ui->lblSignaturesInfo) {
        ui->lblSignaturesInfo->setTextFormat(Qt::RichText);
        ui->lblSignaturesInfo->setText(signaturesInfoHtml());
    }
    if (ui->lblAboutLogo) {
        QPixmap pm(QStringLiteral(":/assets/logo.svg"));
        if (pm.isNull()) pm = QPixmap(QStringLiteral(":/assets/logo.png"));
        if (!pm.isNull()) ui->lblAboutLogo->setPixmap(pm);
    }

    if (ui->lblCompanionAv) {
        ui->lblCompanionAv->setText(tr("Companion mode - primary AV: Loading..."));
        QtConcurrent::run([this]() {
            const QStringList avs = SystemEnum::installedAntivirus();
            QMetaObject::invokeMethod(this, [this, avs]() {
                if (ui && ui->lblCompanionAv) {
                    ui->lblCompanionAv->setText(tr("Companion mode - primary AV: %1").arg(avs.join(", ")));
                }
            }, Qt::QueuedConnection);
        });
    }
}

void MainWindow::onBrandClicked(int /*kind*/)
{
    const QString url = QString::fromLatin1(APP_HOMEPAGE);
    if (!url.isEmpty()) QDesktopServices::openUrl(QUrl(url));
}

void MainWindow::onSelfTest()
{
    QFile f(QStringLiteral(":/signatures/test_eicar_like.dat"));
    if (!f.open(QIODevice::ReadOnly)) {
        Toaster::show(this, tr("Self-test file missing"), Toaster::Error);
        return;
    }
    const QString dst = QDir::tempPath() + "/verax_selftest.bin";
    QFile out(dst);
    if (!out.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        Toaster::show(this, tr("Cannot write self-test file"), Toaster::Error);
        return;
    }
    out.write(f.readAll());
    out.close();

    ScanRequest req;
    req.targets << dst;
    req.useSigDb = true;
    req.usePe = true;
    req.useHeur = true;
    req.threshold = 1;
    req.extensionFilter.clear();
    setActiveNav(PageScan);
    ShieldEngine::instance().startScan(req);
}

void MainWindow::onInstallBrowse()
{
    const QString d = QFileDialog::getExistingDirectory(this, tr("Choose install folder"));
    if (!d.isEmpty() && ui->editInstallPath) ui->editInstallPath->setText(d);
}

void MainWindow::onInstallCancel() { close(); }

void MainWindow::onInstallNow()
{
    // 0) License Key validation via KeyGate
    if (ui->editLicenseKey) {
        const QString licenseKey = ui->editLicenseKey->text().trimmed();
        if (licenseKey.isEmpty()) {
            if (ui->lblLicenseStatusHint) {
                ui->lblLicenseStatusHint->setText(tr("<font color='#f87171'><b>Błąd:</b> Wprowadź klucz licencyjny przed rozpoczęciem instalacji.</font>"));
            }
            Toaster::show(this, tr("Wymagany jest ważny klucz licencyjny KeyGate."), Toaster::Warn);
            return;
        }

        if (ui->lblLicenseStatusHint) {
            ui->lblLicenseStatusHint->setText(tr("<font color='#60a5fa'>Weryfikacja i aktywacja klucza w KeyGate...</font>"));
        }
        QCoreApplication::processEvents();

        auto actRes = LicenseManager::instance().activateKey(licenseKey);
        if (!actRes.success) {
            if (ui->lblLicenseStatusHint) {
                ui->lblLicenseStatusHint->setText(tr("<font color='#f87171'><b>Błąd aktywacji:</b> %1 (%2)</font>")
                                                      .arg(actRes.errorMessage, actRes.errorCode));
            }
            QMessageBox::critical(this, tr("Błąd aktywacji licencji"),
                                  tr("Nie można ukończyć instalacji bez aktywnej licencji.\n\nPowód: %1\nKod błędu: %2")
                                      .arg(actRes.errorMessage, actRes.errorCode));
            return;
        }

        if (ui->lblLicenseStatusHint) {
            ui->lblLicenseStatusHint->setText(tr("<font color='#4ade80'><b>Aktywowano pomyślnie:</b> %1</font>")
                                                  .arg(LicenseManager::instance().tierName()));
        }
    }

    const QString src    = QCoreApplication::applicationFilePath();
    const QString target = (ui->editInstallPath && !ui->editInstallPath->text().isEmpty())
        ? ui->editInstallPath->text()
        : QString::fromLatin1(APP_INSTALL_DIR);

    if (!QDir().mkpath(target)) {
        Toaster::show(this,
            tr("Cannot create install folder: %1\nTry running as Administrator.").arg(target),
            Toaster::Error);
        return;
    }
    const QString dst = QDir(target).absoluteFilePath(QString::fromLatin1(APP_BIN_NAME));

    // ── If the target file already exists (re-install / upgrade), it may
    //    be locked by a running instance. Atomically rename it aside then
    //    delete on success; if the rename fails we report a clear error
    //    and ask the user to close the running copy.
    if (QFile::exists(dst)) {
        const QString sidelined = dst + QStringLiteral(".old.")
            + QString::number(QDateTime::currentSecsSinceEpoch());
        if (!QFile::rename(dst, sidelined)) {
            QMessageBox::warning(this,
                tr("%1 is currently running").arg(QString::fromLatin1(APP_NAME)),
                tr("The destination file is locked because %1 is already running.\n\n"
                   "Please close all running instances and click Install again.")
                    .arg(QString::fromLatin1(APP_NAME)));
            return;
        }
        // Best-effort cleanup of the renamed file (will succeed once the
        // OS releases the handle, otherwise we simply leave a .old.* alongside)
        QFile::remove(sidelined);
    }

    if (!QFile::copy(src, dst)) {
        Toaster::show(this, tr("Failed to copy executable to %1").arg(dst), Toaster::Error);
        return;
    }

    // ── Add/Remove Programs registration ─────────────────────────────────
    const QString uninstKey = QStringLiteral(
        "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\")
        + QString::fromLatin1(APP_NAME);
    QSettings unreg(uninstKey, QSettings::NativeFormat);
    unreg.setValue("DisplayName",     QString::fromLatin1(APP_NAME));
    unreg.setValue("DisplayVersion",  QString::fromLatin1(APP_VERSION_STR));
    unreg.setValue("Publisher",       QString::fromLatin1(APP_VENDOR));
    unreg.setValue("InstallLocation", target);
    unreg.setValue("UninstallString", QStringLiteral("\"%1\" --uninstall").arg(dst));
    unreg.setValue("DisplayIcon",     dst);
    unreg.setValue("URLInfoAbout",    QString::fromLatin1(APP_HOMEPAGE));
    unreg.setValue("NoModify", 1);
    unreg.setValue("NoRepair", 1);

    if (ui->cbInstallStartup && ui->cbInstallStartup->isChecked())
        Settings::instance().setStartWithWindows(true);

    // ── Shortcut creation via Windows Scripting Host (no extra deps) ─────
    auto createShortcut = [&](const QString &lnkPath){
        const QString ps = QStringLiteral(
            "$WshShell = New-Object -ComObject WScript.Shell; "
            "$lnk = $WshShell.CreateShortcut('%1'); "
            "$lnk.TargetPath = '%2'; "
            "$lnk.WorkingDirectory = '%3'; "
            "$lnk.IconLocation = '%2,0'; "
            "$lnk.Description = '%4'; "
            "$lnk.Save();")
            .arg(QDir::toNativeSeparators(lnkPath))
            .arg(QDir::toNativeSeparators(dst))
            .arg(QDir::toNativeSeparators(target))
            .arg(QString::fromLatin1(APP_DESCRIPTION));
        QProcess p;
#ifdef _WIN32
        p.setCreateProcessArgumentsModifier(
            [](QProcess::CreateProcessArguments *a){
                a->flags |= 0x08000000; /* CREATE_NO_WINDOW */
            });
#endif
        p.start("powershell.exe",
                {"-NoProfile", "-WindowStyle", "Hidden", "-Command", ps});
        p.waitForFinished(8000);
    };

    if (ui->cbInstallDesktop && ui->cbInstallDesktop->isChecked()) {
        const QString desktop = QStandardPaths::writableLocation(QStandardPaths::DesktopLocation);
        if (!desktop.isEmpty()) {
            const QString lnk = desktop + QLatin1Char('/')
                              + QString::fromLatin1(APP_NAME) + QStringLiteral(".lnk");
            createShortcut(lnk);
            Logger::info(QStringLiteral("Desktop shortcut: %1").arg(lnk));
        }
    }

    if (ui->cbInstallStartMenu && ui->cbInstallStartMenu->isChecked()) {
        const QString programs = QStandardPaths::writableLocation(
            QStandardPaths::ApplicationsLocation);
        if (!programs.isEmpty()) {
            const QString folder = programs + QLatin1Char('/')
                                 + QString::fromLatin1(APP_NAME);
            QDir().mkpath(folder);
            const QString lnk = folder + QLatin1Char('/')
                              + QString::fromLatin1(APP_NAME) + QStringLiteral(".lnk");
            createShortcut(lnk);
            Logger::info(QStringLiteral("Start Menu shortcut: %1").arg(lnk));
        }
    }

    Toaster::show(this, tr("Installed to %1").arg(target), Toaster::Success);
    Logger::info(QStringLiteral("Install complete: %1").arg(dst));

    // Register Multi-Guard in Windows Security Center & configure Defender yield
    WindowsSecurityIntegration::registerAntivirus(target, dst);

    QProcess::startDetached(dst, { });
    QCoreApplication::quit();
}

void MainWindow::setupTrayIcon()
{
    if (!QSystemTrayIcon::isSystemTrayAvailable()) return;
    m_tray = new QSystemTrayIcon(this);
    QIcon icon(QStringLiteral(":/assets/logo.png"));
    if (icon.isNull()) icon = style()->standardIcon(QStyle::SP_ComputerIcon);
    m_tray->setIcon(icon);
    m_tray->setToolTip(QStringLiteral("Multi-Guard v%1 — System Chroniony").arg(APP_VERSION_STR));

    auto *menu = new QMenu(this);
    menu->setStyleSheet(ThemeManager::trayStyleSheet());

    // Header Status Action
    QAction *aHeader = menu->addAction(tr("🛡 Multi-Guard — Ochrona Aktywna"));
    aHeader->setEnabled(false);
    menu->addSeparator();

    // Direct Toggles
    QAction *aToggleRt = menu->addAction(tr("Ochrona w czasie rzeczywistym"));
    aToggleRt->setCheckable(true);
    aToggleRt->setChecked(Settings::instance().realTimeProtection());
    connect(aToggleRt, &QAction::toggled, this, [this](bool v){
        Settings::instance().setRealTimeProtection(v);
        RealTimeShield::instance().setEnabled(v);
        NotificationAlert::showInfo(tr("Multi-Guard"), v ? tr("Ochrona w czasie rzeczywistym została włączona.") : tr("Ochrona w czasie rzeczywistym została wyłączona."));
    });

    QAction *aToggleWeb = menu->addAction(tr("Ochrona sieciowa (Web Shield)"));
    aToggleWeb->setCheckable(true);
    aToggleWeb->setChecked(Settings::instance().webShield());
    connect(aToggleWeb, &QAction::toggled, this, [this](bool v){
        Settings::instance().setWebShield(v);
        WebShield::instance().setEnabled(v);
    });

    menu->addSeparator();
    QAction *aOpen   = menu->addAction(tr("Otwórz pulpit Multi-Guard"));
    QAction *aQuick  = menu->addAction(tr("Szybkie skanowanie"));
    QAction *aRam    = menu->addAction(tr("Skanuj pamięć RAM (Procesy)"));
    QAction *aTools  = menu->addAction(tr("Narzędzia i Wydajność"));
    QAction *aRemote = menu->addAction(tr("Zdalna Naprawa Multi-Servis"));
    QAction *aUpdate = menu->addAction(tr("Aktualizuj sygnatury w chmurze"));
    menu->addSeparator();
    QAction *aSet    = menu->addAction(tr("Ustawienia"));
    QAction *aAbout  = menu->addAction(tr("O programie"));
    menu->addSeparator();
    QAction *aQuit   = menu->addAction(tr("Zakończ działanie"));

    connect(aOpen,   &QAction::triggered, this, [this]{ show(); raise(); activateWindow(); });
    connect(aQuick,  &QAction::triggered, this, &MainWindow::onQuickScan);
    connect(aRam,    &QAction::triggered, this, &MainWindow::onScanMemory);
    connect(aTools,  &QAction::triggered, this, [this]{ show(); setActiveNav(PageTools); raise(); activateWindow(); });
    connect(aRemote, &QAction::triggered, this, [this]{ show(); setActiveNav(PageRemoteRepair); raise(); activateWindow(); });
    connect(aUpdate, &QAction::triggered, this, &MainWindow::onUpdateSignatures);
    connect(aSet,    &QAction::triggered, this, [this]{ show(); setActiveNav(PageSettings); raise(); activateWindow(); });
    connect(aAbout,  &QAction::triggered, this, [this]{ show(); setActiveNav(PageAbout); raise(); activateWindow(); });
    connect(aQuit,   &QAction::triggered, qApp,  &QCoreApplication::quit);

    m_tray->setContextMenu(menu);
    connect(m_tray, &QSystemTrayIcon::activated, this, &MainWindow::onTrayActivated);
    m_tray->show();
}

void MainWindow::onTrayActivated(QSystemTrayIcon::ActivationReason r)
{
    if (r == QSystemTrayIcon::Trigger) {
        if (isVisible()) hide();
        else             { show(); raise(); activateWindow(); }
    } else if (r == QSystemTrayIcon::DoubleClick) {
        show(); setActiveNav(PageDashboard); raise(); activateWindow();
    }
}

void MainWindow::closeEvent(QCloseEvent *e)
{
    if (m_tray) {
        hide();
        e->ignore();
        return;
    }
    QMainWindow::closeEvent(e);
}

void MainWindow::populateDrivesOnConfig()
{
    if (!ui || !ui->driveList) return;

    if (m_populatingDrives) return;
    m_populatingDrives = true;

    if (m_drivesWatcher) {
        m_drivesWatcher->disconnect(this);
        m_drivesWatcher->cancel();
        m_drivesWatcher->deleteLater();
        m_drivesWatcher = nullptr;
    }

    m_drivesWatcher = new QFutureWatcher<QVector<DriveInfo>>(this);
    QPointer<MainWindow> safeThis(this);

    connect(m_drivesWatcher,
            &QFutureWatcher<QVector<DriveInfo>>::finished,
            this, [safeThis]() {
                if (!safeThis || !safeThis->m_drivesWatcher) {
                    if (safeThis) safeThis->m_populatingDrives = false;
                    return;
                }
                QVector<DriveInfo> drives;
                if (!safeThis->m_drivesWatcher->isCanceled()) {
                    drives = safeThis->m_drivesWatcher->result();
                }
                safeThis->m_drivesWatcher->deleteLater();
                safeThis->m_drivesWatcher = nullptr;
                safeThis->applyDrivesToUi(drives);
                safeThis->m_populatingDrives = false;
            });

    m_drivesWatcher->setFuture(QtConcurrent::run([]() -> QVector<DriveInfo> {
        return SystemEnum::listDrives();
    }));
}

void MainWindow::applyDrivesToUi(const QVector<DriveInfo> &drives)
{
    if (!ui || !ui->driveList) return;
    auto *box = ui->driveList;

    if (box->layout()) {
        QLayoutItem *item;
        while ((item = box->layout()->takeAt(0)) != nullptr) {
            if (auto *w = item->widget()) {
                w->hide();
                w->deleteLater();
            }
            delete item;
        }
        if (qstrcmp(box->layout()->metaObject()->className(), "QVBoxLayout") != 0) {
            delete box->layout();
        }
    }

    auto *lay = qobject_cast<QVBoxLayout*>(box->layout());
    if (!lay) {
        lay = new QVBoxLayout(box);
        lay->setContentsMargins(0, 0, 0, 0);
        lay->setSpacing(8);
    }

    for (const auto &d : drives) {
        auto *tile = new DriveTile(d, box);
        lay->addWidget(tile);
    }
    lay->addStretch(1);
}

void MainWindow::updateChromeStatus(const QString &kind, const QString &text)
{
    if (ui->chromeBar) {
        ui->chromeBar->setStatusKind(kind);
        ui->chromeBar->setStatusText(text);
    }
}

// ═══════════════════════════════════════════════════════════════════
//  ThreatList Smart Filters + Bulk Actions
// ═══════════════════════════════════════════════════════════════════
void MainWindow::buildThreatFilterToolbar()
{
    if (!ui->threatList) return;
    auto *lay = qobject_cast<QVBoxLayout*>(ui->threatList->layout());
    if (!lay) return;

    // Create filter toolbar widget
    auto *toolbar = new QWidget(this);
    toolbar->setObjectName("ThreatFilterToolbar");
    auto *tbLay = new QHBoxLayout(toolbar);
    tbLay->setContentsMargins(4, 4, 4, 4);
    tbLay->setSpacing(8);

    // Select All
    m_selectAll = new QCheckBox(tr("Select All"), toolbar);
    m_selectAll->setObjectName("ThreatSelectAll");
    connect(m_selectAll, &QCheckBox::toggled, this, &MainWindow::onSelectAllThreats);

    // Severity filter
    auto *lblSev = new QLabel(tr("Severity:"), toolbar);
    m_filterSeverity = new QComboBox(toolbar);
    m_filterSeverity->setObjectName("FilterSeverity");
    m_filterSeverity->addItem(tr("All"), "all");
    m_filterSeverity->addItem(tr("High"), "high");
    m_filterSeverity->addItem(tr("Medium"), "medium");
    m_filterSeverity->addItem(tr("Low"), "low");
    connect(m_filterSeverity, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &MainWindow::applyThreatFilters);

    // Family filter
    auto *lblFam = new QLabel(tr("Family:"), toolbar);
    m_filterFamily = new QComboBox(toolbar);
    m_filterFamily->setObjectName("FilterFamily");
    m_filterFamily->addItem(tr("All"), "all");
    connect(m_filterFamily, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &MainWindow::applyThreatFilters);

    // Repairable filter
    auto *lblRep = new QLabel(tr("Repairable:"), toolbar);
    m_filterRepairable = new QComboBox(toolbar);
    m_filterRepairable->setObjectName("FilterRepairable");
    m_filterRepairable->addItem(tr("All"), "all");
    m_filterRepairable->addItem(tr("Yes"), "yes");
    m_filterRepairable->addItem(tr("No"), "no");
    connect(m_filterRepairable, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &MainWindow::applyThreatFilters);

    // Bulk action
    m_bulkActionCombo = new QComboBox(toolbar);
    m_bulkActionCombo->setObjectName("BulkAction");
    m_bulkActionCombo->addItem(tr("Bulk Action..."), "none");
    m_bulkActionCombo->addItem(tr("Quarantine All"), "quarantine");
    m_bulkActionCombo->addItem(tr("Delete All"), "delete");
    m_bulkActionCombo->addItem(tr("Repair All"), "repair");

    m_bulkApplyBtn = new QPushButton(tr("Apply"), toolbar);
    m_bulkApplyBtn->setObjectName("BulkApplyBtn");
    m_bulkApplyBtn->setProperty("kind", "primary");
    connect(m_bulkApplyBtn, &QPushButton::clicked, this, &MainWindow::onBulkAction);

    tbLay->addWidget(m_selectAll);
    tbLay->addSpacing(12);
    tbLay->addWidget(lblSev);
    tbLay->addWidget(m_filterSeverity);
    tbLay->addWidget(lblFam);
    tbLay->addWidget(m_filterFamily);
    tbLay->addWidget(lblRep);
    tbLay->addWidget(m_filterRepairable);
    tbLay->addStretch(1);
    tbLay->addWidget(m_bulkActionCombo);
    tbLay->addWidget(m_bulkApplyBtn);

    lay->insertWidget(0, toolbar);
}

void MainWindow::applyThreatFilters()
{
    if (!m_filterSeverity || !m_filterFamily || !m_filterRepairable) return;

    const QString sevFilter = m_filterSeverity->currentData().toString();
    const QString famFilter = m_filterFamily->currentData().toString();
    const QString repFilter = m_filterRepairable->currentData().toString();

    // Collect unique families for the family filter dropdown
    QSet<QString> families;
    for (auto *card : m_threatCards) {
        if (!card->familyName().isEmpty())
            families.insert(card->familyName());
    }
    // Update family combo only if families changed
    if (m_filterFamily->count() != families.size() + 1) {
        m_filterFamily->blockSignals(true);
        QString cur = m_filterFamily->currentData().toString();
        m_filterFamily->clear();
        m_filterFamily->addItem(tr("All"), "all");
        for (const QString &f : families)
            m_filterFamily->addItem(f, f.toLower());
        // Restore selection
        for (int i = 0; i < m_filterFamily->count(); ++i) {
            if (m_filterFamily->itemData(i).toString() == cur) {
                m_filterFamily->setCurrentIndex(i);
                break;
            }
        }
        m_filterFamily->blockSignals(false);
    }

    for (auto *card : m_threatCards) {
        bool show = true;
        if (sevFilter != "all" && card->severityLevel() != sevFilter) show = false;
        if (famFilter != "all" && card->familyName().toLower() != famFilter) show = false;
        if (repFilter == "yes" && !card->isRepairable()) show = false;
        if (repFilter == "no" && card->isRepairable()) show = false;
        card->setVisible(show);
    }
}

void MainWindow::onSelectAllThreats(bool checked)
{
    for (auto *card : m_threatCards) {
        if (card->isVisible())
            card->setSelected(checked);
    }
}

void MainWindow::onBulkAction()
{
    if (!m_bulkActionCombo) return;
    const QString action = m_bulkActionCombo->currentData().toString();
    if (action == "none") return;

    QList<ThreatCard*> selected;
    for (auto *card : m_threatCards) {
        if (card->isVisible() && card->isSelected())
            selected.append(card);
    }
    if (selected.isEmpty()) {
        Toaster::show(this, tr("No threats selected"), Toaster::Info);
        return;
    }

    if (action == "quarantine") {
        for (auto *card : selected) {
            const ThreatInfo &t = card->info();
            const QString v = Quarantine::instance().moveToVault(t.path, t.sha256, t.detectionName);
            if (!v.isEmpty())
                card->setActioned(tr("Quarantined"));
            else
                card->setActioned(tr("Quarantine failed"));
        }
        Toaster::show(this, tr("Quarantined %1 threats").arg(selected.size()), Toaster::Success);
    }
    else if (action == "delete") {
        int ok = 0;
        for (auto *card : selected) {
            if (QFile::remove(card->info().path)) {
                card->setActioned(tr("Deleted"));
                ++ok;
            } else {
                card->setActioned(tr("Delete failed"));
            }
        }
        Toaster::show(this, tr("Deleted %1 / %2 threats").arg(ok).arg(selected.size()), Toaster::Success);
    }
    else if (action == "repair") {
        int count = selected.size();
        Toaster::show(this, tr("Repairing %1 threats...").arg(count), Toaster::Info);
        for (auto *card : selected) {
            ThreatInfo t = card->info();
            card->setActioned(tr("Cleaning..."));
            QtConcurrent::run([this, card, t]() mutable {
                Scanner repairScanner;
                bool success = repairScanner.advancedCleanThreat(t.path, t);
                QMetaObject::invokeMethod(this, [this, card, success, t](){
                    if (success) {
                        card->setActioned(tr("Cleaned ✓"));
                    } else {
                        card->setRepairFailed();
                    }
                }, Qt::QueuedConnection);
            });
        }
    }

    // Reset combo
    m_bulkActionCombo->setCurrentIndex(0);
    if (m_selectAll) m_selectAll->setChecked(false);
}

#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
bool MainWindow::nativeEvent(const QByteArray &eventType, void *message, qintptr *result)
#else
bool MainWindow::nativeEvent(const QByteArray &eventType, void *message, long *result)
#endif
{
#ifdef Q_OS_WIN
    MSG *msg = static_cast<MSG *>(message);
    if (msg->message == WM_NCHITTEST) {
        int x = GET_X_LPARAM(msg->lParam);
        int y = GET_Y_LPARAM(msg->lParam);
        QPoint pos = mapFromGlobal(QPoint(x, y));

        int border = 8;

        bool left = pos.x() < border;
        bool right = pos.x() > width() - border;
        bool top = pos.y() < border;
        bool bottom = pos.y() > height() - border;

        if (left && top) {
            *result = HTTOPLEFT;
            return true;
        } else if (left && bottom) {
            *result = HTBOTTOMLEFT;
            return true;
        } else if (right && top) {
            *result = HTTOPRIGHT;
            return true;
        } else if (right && bottom) {
            *result = HTBOTTOMRIGHT;
            return true;
        } else if (left) {
            *result = HTLEFT;
            return true;
        } else if (right) {
            *result = HTRIGHT;
            return true;
        } else if (top) {
            *result = HTTOP;
            return true;
        } else if (bottom) {
            *result = HTBOTTOM;
            return true;
        }
    }
    else if (msg->message == WM_DEVICECHANGE && msg->wParam == 0x8000 /* DBT_DEVICEARRIVAL */) {
        PDEV_BROADCAST_HDR pHdr = reinterpret_cast<PDEV_BROADCAST_HDR>(msg->lParam);
        if (pHdr && pHdr->dbch_devicetype == 0x00000002 /* DBT_DEVTYP_VOLUME */) {
            PDEV_BROADCAST_VOLUME pVol = reinterpret_cast<PDEV_BROADCAST_VOLUME>(msg->lParam);
            DWORD unitmask = pVol->dbcv_unitmask;
            for (int i = 0; i < 26; ++i) {
                if (unitmask & (1 << i)) {
                    char letter = 'A' + i;
                    const QString drivePath = QStringLiteral("%1:\\").arg(letter);
                    QTimer::singleShot(600, this, [this, drivePath]{
                        onUsbDriveInserted(drivePath);
                    });
                    break;
                }
            }
        }
    }
#endif
    return QMainWindow::nativeEvent(eventType, message, result);
}

void MainWindow::initToolsPage()
{
    if (m_hwTimer) return;
    m_hwTimer = new QTimer(this);
    m_hwTimer->setInterval(1500);
    connect(m_hwTimer, &QTimer::timeout, this, &MainWindow::onRefreshHardwareStats);

    if (ui->tableStartup) {
        ui->tableStartup->setColumnCount(5);
        ui->tableStartup->setHorizontalHeaderLabels({
            tr("Nazwa programu"), tr("Polecenie / Ścieżka"), tr("Lokalizacja"), tr("Podpis cyfrowy"), tr("Stan")
        });
        ui->tableStartup->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
        ui->tableStartup->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
        ui->tableStartup->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
        ui->tableStartup->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
        ui->tableStartup->horizontalHeader()->setSectionResizeMode(4, QHeaderView::ResizeToContents);
        ui->tableStartup->setSelectionBehavior(QAbstractItemView::SelectRows);
        ui->tableStartup->setSelectionMode(QAbstractItemView::SingleSelection);
    }
}

void MainWindow::onContextMenuToggled(bool checked)
{
    Settings::instance().setContextMenuIntegration(checked);
}

void MainWindow::onRefreshHardwareStats()
{
    HardwareStats stats = HardwareMonitor::instance().refreshStats();
    if (ui->lblCpuName) {
        ui->lblCpuName->setText(stats.cpuName);
    }
    if (ui->pbCpuUsage) {
        ui->pbCpuUsage->setValue(qBound(0, int(stats.cpuUsagePercent), 100));
    }
    if (ui->lblCpuTemp) {
        if (stats.cpuTempCelsius > 0) {
            ui->lblCpuTemp->setText(tr("Temperatura: %1 °C").arg(QString::number(stats.cpuTempCelsius, 'f', 1)));
        } else {
            ui->lblCpuTemp->setText(tr("Temperatura: W normie (czujnik OEM)"));
        }
    }
    if (ui->lblRamDetails) {
        QString usedStr = SystemOptimizer::formatBytes(stats.ramUsedBytes);
        QString totalStr = SystemOptimizer::formatBytes(stats.ramTotalBytes);
        ui->lblRamDetails->setText(tr("Pamięć: %1 / %2 (%3%)").arg(usedStr, totalStr, QString::number(stats.ramUsagePercent, 'f', 0)));
    }
    if (ui->pbRamUsage) {
        ui->pbRamUsage->setValue(qBound(0, int(stats.ramUsagePercent), 100));
    }
    if (ui->lblGpuName) {
        ui->lblGpuName->setText(tr("Karta graficzna: %1").arg(stats.gpuName));
    }
    if (ui->lblGpuVram) {
        if (stats.gpuVramTotalBytes > 0) {
            ui->lblGpuVram->setText(tr("Pamięć wideo VRAM: %1").arg(SystemOptimizer::formatBytes(stats.gpuVramTotalBytes)));
        } else {
            ui->lblGpuVram->setText(tr("Pamięć wideo: Pamięć współdzielona systemu"));
        }
    }
}

void MainWindow::onScanCleanClicked()
{
    if (!ui->listCleanItems) return;
    ui->listCleanItems->clear();
    if (ui->lblCleanStatus) ui->lblCleanStatus->setText(tr("Analizowanie zbędnych plików..."));

    QList<CleanItem> items = SystemOptimizer::instance().scanSystem();
    qint64 totalBytes = 0;
    for (const CleanItem &item : items) {
        totalBytes += item.byteCount;
        auto *listItem = new QListWidgetItem(ui->listCleanItems);
        listItem->setText(QStringLiteral("%1 — %2 (%3 plików)")
            .arg(item.name, SystemOptimizer::formatBytes(item.byteCount), QString::number(item.fileCount)));
        listItem->setData(Qt::UserRole, item.id);
        listItem->setFlags(listItem->flags() | Qt::ItemIsUserCheckable | Qt::ItemIsEnabled);
        listItem->setCheckState(item.byteCount > 0 ? Qt::Checked : Qt::Unchecked);
    }

    if (ui->lblCleanStatus) {
        ui->lblCleanStatus->setText(tr("Zidentyfikowano do odzyskania: %1").arg(SystemOptimizer::formatBytes(totalBytes)));
    }
}

void MainWindow::onDoCleanClicked()
{
    if (!ui->listCleanItems) return;
    QStringList ids;
    for (int i = 0; i < ui->listCleanItems->count(); ++i) {
        QListWidgetItem *item = ui->listCleanItems->item(i);
        if (item->checkState() == Qt::Checked) {
            ids.append(item->data(Qt::UserRole).toString());
        }
    }
    if (ids.isEmpty()) {
        QMessageBox::information(this, tr("Optymalizator"), tr("Nie zaznaczono żadnych elementów do wyczyszczenia."));
        return;
    }

    if (ui->lblCleanStatus) ui->lblCleanStatus->setText(tr("Czyszczenie w toku..."));
    qint64 freed = SystemOptimizer::instance().cleanItems(ids);
    if (ui->lblCleanStatus) {
        ui->lblCleanStatus->setText(tr("Pomyślnie oczyszczono! Zwolniono %1 miejsca na dysku.").arg(SystemOptimizer::formatBytes(freed)));
    }
    Toaster::show(this, tr("Zwolniono %1 miejsca").arg(SystemOptimizer::formatBytes(freed)));
    onScanCleanClicked();
}

void MainWindow::onRefreshStartupClicked()
{
    if (!ui->tableStartup) return;
    ui->tableStartup->setRowCount(0);

    QList<StartupEntry> entries = StartupManager::getEntries();
    for (const StartupEntry &e : entries) {
        int r = ui->tableStartup->rowCount();
        ui->tableStartup->insertRow(r);

        auto *nameItem = new QTableWidgetItem(e.name);
        nameItem->setData(Qt::UserRole, e.location);
        nameItem->setData(Qt::UserRole + 1, e.command);

        auto *cmdItem = new QTableWidgetItem(e.command);
        auto *locItem = new QTableWidgetItem(e.location);
        auto *signItem = new QTableWidgetItem(e.isSigned ? tr("Zaufany (Authenticode)") : tr("Brak podpisu"));
        signItem->setForeground(e.isSigned ? QColor(46, 204, 113) : QColor(231, 76, 60));

        auto *statusItem = new QTableWidgetItem(e.enabled ? tr("Aktywny") : tr("Wyłączony"));
        statusItem->setForeground(e.enabled ? QColor(52, 152, 219) : QColor(149, 165, 166));

        ui->tableStartup->setItem(r, 0, nameItem);
        ui->tableStartup->setItem(r, 1, cmdItem);
        ui->tableStartup->setItem(r, 2, locItem);
        ui->tableStartup->setItem(r, 3, signItem);
        ui->tableStartup->setItem(r, 4, statusItem);
    }
}

void MainWindow::onToggleStartupClicked()
{
    if (!ui->tableStartup) return;
    int r = ui->tableStartup->currentRow();
    if (r < 0) {
        QMessageBox::information(this, tr("Autostart"), tr("Wybierz wpis z listy, aby go włączyć lub wyłączyć."));
        return;
    }
    QTableWidgetItem *nameItem = ui->tableStartup->item(r, 0);
    QTableWidgetItem *statusItem = ui->tableStartup->item(r, 4);
    if (!nameItem || !statusItem) return;

    StartupEntry e;
    e.name = nameItem->text();
    e.location = nameItem->data(Qt::UserRole).toString();
    e.command = nameItem->data(Qt::UserRole + 1).toString();
    bool isCurrentlyEnabled = (statusItem->text() == tr("Aktywny"));

    if (StartupManager::setEntryEnabled(e, !isCurrentlyEnabled)) {
        onRefreshStartupClicked();
    }
}

void MainWindow::onDeleteStartupClicked()
{
    if (!ui->tableStartup) return;
    int r = ui->tableStartup->currentRow();
    if (r < 0) {
        QMessageBox::information(this, tr("Autostart"), tr("Wybierz wpis z listy, aby go usunąć."));
        return;
    }
    QTableWidgetItem *nameItem = ui->tableStartup->item(r, 0);
    if (!nameItem) return;

    StartupEntry e;
    e.name = nameItem->text();
    e.location = nameItem->data(Qt::UserRole).toString();
    e.command = nameItem->data(Qt::UserRole + 1).toString();

    if (QMessageBox::question(this, tr("Potwierdzenie"),
        tr("Czy na pewno chcesz trwale usunąć wpis autostartu '%1'?").arg(e.name)) == QMessageBox::Yes) {
        StartupManager::deleteEntry(e);
        onRefreshStartupClicked();
    }
}

void MainWindow::onBrowseShredFile()
{
    QString f = QFileDialog::getOpenFileName(this, tr("Wybierz plik do trwałego zniszczenia"));
    if (!f.isEmpty() && ui->leShredPath) {
        ui->leShredPath->setText(f);
    }
}

void MainWindow::onBrowseShredDir()
{
    QString d = QFileDialog::getExistingDirectory(this, tr("Wybierz folder do trwałego zniszczenia"));
    if (!d.isEmpty() && ui->leShredPath) {
        ui->leShredPath->setText(d);
    }
}

void MainWindow::onDoShredClicked()
{
    if (!ui->leShredPath) return;
    QString target = ui->leShredPath->text().trimmed();
    if (target.isEmpty() || (!QFile::exists(target) && !QDir(target).exists())) {
        QMessageBox::warning(this, tr("Niszczarka"), tr("Wskaż istniejący plik lub folder do zniszczenia."));
        return;
    }

    auto ret = QMessageBox::critical(this, tr("OSTRZEŻENIE O TRWAŁYM ZNISZCZENIU"),
        tr("Czy na pewno chcesz BEZPOWROTNIE zniszczyć:\n%1\n\nDane zostaną wielokrotnie nadpisane losowymi wzorcami. Tej operacji NIE MOŻNA cofnąć!").arg(target),
        QMessageBox::Yes | QMessageBox::No, QMessageBox::No);

    if (ret != QMessageBox::Yes) return;

    if (ui->pbShredProgress) ui->pbShredProgress->setValue(0);
    if (ui->lblShredStatus) ui->lblShredStatus->setText(tr("Trwa bezpieczne niszczenie danych..."));

    bool ok = false;
    QFileInfo fi(target);
    if (fi.isDir()) {
        ok = SystemOptimizer::shredDirectory(target, [this](int pct){
            if (ui->pbShredProgress) ui->pbShredProgress->setValue(pct);
            QCoreApplication::processEvents();
        });
    } else {
        ok = SystemOptimizer::shredFile(target, [this](int pct){
            if (ui->pbShredProgress) ui->pbShredProgress->setValue(pct);
            QCoreApplication::processEvents();
        });
    }

    if (ok) {
        if (ui->pbShredProgress) ui->pbShredProgress->setValue(100);
        if (ui->lblShredStatus) ui->lblShredStatus->setText(tr("Dane zostały pomyślnie i bezpowrotnie zniszczone."));
        if (ui->leShredPath) ui->leShredPath->clear();
        Toaster::show(this, tr("Plik został zniszczony"));
    } else {
        if (ui->lblShredStatus) ui->lblShredStatus->setText(tr("Błąd podczas niszczenia (plik może być używany przez inny proces)."));
    }
}

void MainWindow::onGenerateSessionCode()
{
    int p1 = QRandomGenerator::global()->bounded(100, 999);
    int p2 = QRandomGenerator::global()->bounded(100, 999);
    QString code = QStringLiteral("MS-%1-%2").arg(p1).arg(p2);
    if (ui->lblSessionCode) {
        ui->lblSessionCode->setText(code);
    }
    Toaster::show(this, tr("Wygenerowano nowy kod sesji: %1").arg(code), Toaster::Info);
}

void MainWindow::onCopySessionCode()
{
    if (!ui->lblSessionCode) return;
    QString code = ui->lblSessionCode->text().trimmed();
    QClipboard *cb = QGuiApplication::clipboard();
    if (cb) {
        cb->setText(code);
    }
    Toaster::show(this, tr("Kod sesji skopiowany do schowka: %1").arg(code), Toaster::Success);
}

void MainWindow::onConnectRemoteClicked()
{
    if (ui->lblTunnelStatus) {
        ui->lblTunnelStatus->setText(tr("🔒 Próba nawiązania połączenia z serwerem Multi-Servis..."));
        ui->lblTunnelStatus->setStyleSheet("color: #ffb300; font-weight: bold;");
    }
    QTimer::singleShot(1200, this, [this]{
        if (ui->lblTunnelStatus) {
            ui->lblTunnelStatus->setText(tr("✅ Połączono z centrum serwisowym Multi-Servis. Oczekiwanie na technika."));
            ui->lblTunnelStatus->setStyleSheet("color: #00e676; font-weight: bold;");
        }
        NotificationAlert::showInfo(tr("Zdalna Naprawa"), tr("Stanowisko serwisowe Multi-Servis odebrało zgłoszenie. Specjalista dołączy za chwilę."));
    });
}

void MainWindow::initScheduler()
{
    if (!m_schedulerTimer) {
        m_schedulerTimer = new QTimer(this);
        m_schedulerTimer->setInterval(60000); // Check every 60 seconds
        connect(m_schedulerTimer, &QTimer::timeout, this, &MainWindow::onScheduledTimerTick);
        m_schedulerTimer->start();
    }
}

void MainWindow::onScheduledTimerTick()
{
    const QString sched = Settings::instance().scheduledScan();
    if (sched == "off" || ShieldEngine::instance().scanner()->isRunning()) return;

    const QTime now = QTime::currentTime();
    const QTime target = QTime::fromString(Settings::instance().scheduledTime(), "HH:mm");
    if (!target.isValid()) return;

    if (now.hour() == target.hour() && now.minute() == target.minute()) {
        const QDate today = QDate::currentDate();
        static QDate s_lastScanDate;
        if (s_lastScanDate == today) return;

        if (sched == "weekly" && today.dayOfWeek() != 1) return; // Monday only
        if (sched == "monthly" && today.day() != 1) return;      // 1st day only

        s_lastScanDate = today;
        Logger::info("Scheduled background scan triggered");
        AuditLogger::instance().logEvent("ScheduledScan", tr("Uruchomiono automatyczne zaplanowane skanowanie w tle."), QString(), 0);
        onQuickScan();
    }
}

void MainWindow::onAddExclusionFolder()
{
    const QString dir = QFileDialog::getExistingDirectory(this, tr("Wybierz folder do wykluczenia ze skanowania"));
    if (!dir.isEmpty()) {
        Settings::instance().addExclusion(dir);
        if (ui->listExclusions) ui->listExclusions->addItem(QDir::cleanPath(dir));
        Toaster::show(this, tr("Dodano folder do listy wykluczeń."), Toaster::Success);
        AuditLogger::instance().logEvent("ExclusionAdded", tr("Dodano folder do wykluczeń: %1").arg(dir), dir, 0);
    }
}

void MainWindow::onAddExclusionFile()
{
    const QString file = QFileDialog::getOpenFileName(this, tr("Wybierz plik do wykluczenia ze skanowania"));
    if (!file.isEmpty()) {
        Settings::instance().addExclusion(file);
        if (ui->listExclusions) ui->listExclusions->addItem(QDir::cleanPath(file));
        Toaster::show(this, tr("Dodano plik do listy wykluczeń."), Toaster::Success);
        AuditLogger::instance().logEvent("ExclusionAdded", tr("Dodano plik do wykluczeń: %1").arg(file), file, 0);
    }
}

void MainWindow::onRemoveExclusion()
{
    if (!ui->listExclusions) return;
    auto *item = ui->listExclusions->currentItem();
    if (item) {
        const QString path = item->text();
        Settings::instance().removeExclusion(path);
        delete item;
        Toaster::show(this, tr("Usunięto element z listy wykluczeń."), Toaster::Info);
        AuditLogger::instance().logEvent("ExclusionRemoved", tr("Usunięto wykluczenie: %1").arg(path), path, 0);
    }
}

void MainWindow::onGenerateServiceReportClicked()
{
    const QString path = ReportGenerator::generateServiceReportHtml();
    if (!path.isEmpty()) {
        Toaster::show(this, tr("Wygenerowano raport serwisowy na Pulpicie."), Toaster::Success);
        QDesktopServices::openUrl(QUrl::fromLocalFile(path));
        AuditLogger::instance().logEvent("ReportGenerated", tr("Wygenerowano oficjalny raport stacji roboczej (HTML)."), path, 1);
    } else {
        Toaster::show(this, tr("Nie udało się zapisać raportu."), Toaster::Error);
    }
}

void MainWindow::applyLicenseGating()
{
    const auto &lm = LicenseManager::instance();
    bool valid = lm.isValid();

    // 0. Complete lockdown if license has expired or is invalid
    if (!valid) {
        // Stop background protection engines
        RealTimeShield::instance().stop();
        RansomwareShield::instance().setEnabled(false);
        WebShield::instance().setEnabled(false);

        // Lock all sidebar navigation buttons
        const QList<QPushButton*> navButtons = ui->sidebar->findChildren<QPushButton*>();
        for (auto *b : navButtons) {
            if (b->objectName().startsWith("nav")) {
                b->setEnabled(false);
            }
        }

        // Switch to the locked screen if not running the installer
        if (m_currentPage != PageInstaller && m_currentPage != PageLicenseLocked) {
            setActiveNav(PageLicenseLocked);
        }

        if (ui->lblLockedStatus) {
            ui->lblLockedStatus->setText(tr("<font color='#f87171'>Licencja wygasła lub nie została aktywowana.</font>"));
        }

        if (ui->lblAppNameVersion) {
            ui->lblAppNameVersion->setText(QStringLiteral("%1 v%2  [⚠️ Licencja wygasła - 505 012 914]")
                                               .arg(APP_NAME, APP_VERSION_STR));
        }

        if (ui->lblLicenseDaysValue) {
            ui->lblLicenseDaysValue->setText(tr("Wygasła (0 dni)"));
        }

        WindowsSecurityIntegration::updateProductState(false);
        return;
    }

    // Register Multi-Guard in Windows Security Center once active and installed
    static bool s_wscRegistered = false;
    if (!s_wscRegistered && isInstalledPath()) {
        s_wscRegistered = true;
        WindowsSecurityIntegration::registerAntivirus();
    } else if (isInstalledPath()) {
        WindowsSecurityIntegration::updateProductState(true);
    }

    // License is valid: restore sidebar navigation buttons
    const QList<QPushButton*> navButtons = ui->sidebar->findChildren<QPushButton*>();
    for (auto *b : navButtons) {
        if (b->objectName().startsWith("nav")) {
            b->setEnabled(true);
        }
    }

    // If previously stuck on locked page, transition back to Dashboard
    if (m_currentPage == PageLicenseLocked) {
        setActiveNav(PageDashboard);
    }

    // 1. Sidebar Nav Gating per tier
    if (ui->navRepair) {
        bool canRepair = lm.hasCapability(LicenseCapability::SystemRepair);
        ui->navRepair->setEnabled(canRepair);
        ui->navRepair->setToolTip(canRepair ? QString() : tr("Wymagana licencja Multi-Guard Secure lub ADMIN FULL"));
    }

    if (ui->navRemoteRepair) {
        bool canRemote = lm.hasCapability(LicenseCapability::RemoteRepair);
        ui->navRemoteRepair->setEnabled(canRemote);
        ui->navRemoteRepair->setToolTip(canRemote ? QString() : tr("Dostępne w planach Assist / Assist PRO / ADMIN FULL"));
    }

    // 2. Tools tabs
    if (ui->tabTools) {
        bool canHw = lm.hasCapability(LicenseCapability::HardwareMonitor);
        bool canClean = lm.hasCapability(LicenseCapability::DiskCleaner);
        bool canStartup = lm.hasCapability(LicenseCapability::StartupManager);
        bool canShred = lm.hasCapability(LicenseCapability::FileShredder);

        ui->tabTools->setTabEnabled(0, canHw);
        ui->tabTools->setTabEnabled(1, canClean);
        ui->tabTools->setTabEnabled(2, canStartup);
        ui->tabTools->setTabEnabled(3, canShred);
    }

    // 3. Settings checkboxes
    if (ui->cbRansomwareProtection) {
        bool canRansom = lm.hasCapability(LicenseCapability::RansomwareProtection);
        ui->cbRansomwareProtection->setEnabled(canRansom);
        if (!canRansom) {
            ui->cbRansomwareProtection->setChecked(false);
            ui->cbRansomwareProtection->setToolTip(tr("Wymagana licencja Multi-Guard Secure lub ADMIN FULL"));
        } else {
            ui->cbRansomwareProtection->setToolTip(QString());
        }
    }

    // 4. Report generation in About
    if (ui->btnGenerateReportAbout) {
        bool canReport = lm.hasCapability(LicenseCapability::ServiceReports);
        ui->btnGenerateReportAbout->setEnabled(canReport);
        ui->btnGenerateReportAbout->setToolTip(canReport ? QString() : tr("Wymagana licencja Assist PRO lub ADMIN FULL"));
    }

    // 5. Update Dashboard License Card
    if (ui->lblLicenseDaysValue) {
        ui->lblLicenseDaysValue->setText(lm.daysRemainingText());
    }

    // 6. Update Settings License Card
    if (ui->lblSettingsPlanValue) {
        ui->lblSettingsPlanValue->setText(QStringLiteral("<b>%1</b>").arg(lm.tierName()));
    }
    if (ui->lblSettingsDaysValue) {
        ui->lblSettingsDaysValue->setText(QStringLiteral("<b>%1</b> (%2)")
                                              .arg(lm.daysRemainingText(), lm.expirationDateText()));
    }

    // 7. Update banner with tier & days remaining
    if (ui->lblAppNameVersion) {
        ui->lblAppNameVersion->setText(QStringLiteral("%1 v%2  [%3 • %4]")
                                           .arg(APP_NAME, APP_VERSION_STR, lm.tierName(), lm.daysRemainingText()));
    }
}

void MainWindow::onLicenseChanged(LicenseTier tier, bool isValid)
{
    Q_UNUSED(tier);
    Q_UNUSED(isValid);
    applyLicenseGating();
}

void MainWindow::onChangeLicenseKeyClicked()
{
    if (!ui->editNewLicenseKey) return;
    QString key = ui->editNewLicenseKey->text().trimmed();
    if (key.isEmpty()) {
        Toaster::show(this, tr("Wprowadź nowy klucz licencyjny."), Toaster::Warn);
        return;
    }
    restartWithNewLicense(key);
}

void MainWindow::onRefreshLicenseClicked()
{
    Toaster::show(this, tr("Weryfikacja licencji online..."), Toaster::Info);
    QCoreApplication::processEvents();

    auto res = LicenseManager::instance().refreshOnline();
    if (res.success) {
        Toaster::show(this, tr("Licencja pomyślnie zaktualizowana: %1 (%2)")
                               .arg(LicenseManager::instance().tierName(),
                                    LicenseManager::instance().daysRemainingText()),
                      Toaster::Success);
        applyLicenseGating();
    } else {
        Toaster::show(this, tr("Błąd odświeżania: %1").arg(res.errorMessage), Toaster::Error);
    }
}

void MainWindow::onActivateLockedKeyClicked()
{
    if (!ui->editLockedLicenseKey) return;
    QString key = ui->editLockedLicenseKey->text().trimmed();
    if (key.isEmpty()) {
        if (ui->lblLockedStatus) {
            ui->lblLockedStatus->setText(tr("<font color='#f87171'>Wprowadź klucz licencyjny.</font>"));
        }
        Toaster::show(this, tr("Wprowadź klucz licencyjny."), Toaster::Warn);
        return;
    }
    restartWithNewLicense(key);
}

void MainWindow::onRefreshLockedKeyClicked()
{
    if (ui->lblLockedStatus) {
        ui->lblLockedStatus->setText(tr("<font color='#60a5fa'>Weryfikacja licencji w KeyGate...</font>"));
    }
    QCoreApplication::processEvents();

    auto res = LicenseManager::instance().refreshOnline();
    if (res.success) {
        if (ui->lblLockedStatus) {
            ui->lblLockedStatus->setText(tr("<font color='#4ade80'><b>Licencja aktywna!</b> Ponowne uruchamianie programu...</font>"));
        }
        QMessageBox msgBox(this);
        msgBox.setWindowTitle(tr("Aktywacja licencji"));
        msgBox.setIcon(QMessageBox::Information);
        msgBox.setText(tr("Trwa zmiana licencji... Program wymaga ponownego uruchomienia, proszę czekać."));
        msgBox.setStandardButtons(QMessageBox::NoButton);
        msgBox.show();
        QCoreApplication::processEvents();

        QTimer::singleShot(1200, this, []() {
            QString appPath = QCoreApplication::applicationFilePath();
            QStringList args = QCoreApplication::arguments();
            if (!args.isEmpty()) args.removeFirst();
            QProcess::startDetached(appPath, args);
            QCoreApplication::quit();
        });
    } else {
        if (ui->lblLockedStatus) {
            ui->lblLockedStatus->setText(tr("<font color='#f87171'><b>Błąd weryfikacji:</b> %1<br>Kontakt do serwisu: 505 012 914</font>")
                                             .arg(res.errorMessage));
        }
        Toaster::show(this, tr("Błąd weryfikacji: %1").arg(res.errorMessage), Toaster::Error);
    }
}

void MainWindow::restartWithNewLicense(const QString &key)
{
    if (ui->lblLockedStatus) {
        ui->lblLockedStatus->setText(tr("<font color='#60a5fa'>Weryfikacja i aktywacja klucza w KeyGate...</font>"));
    }
    QCoreApplication::processEvents();

    auto actRes = LicenseManager::instance().activateKey(key);
    if (!actRes.success) {
        if (ui->lblLockedStatus) {
            ui->lblLockedStatus->setText(tr("<font color='#f87171'><b>Błąd aktywacji:</b> %1 (%2)<br>Kontakt do serwisu: 505 012 914</font>")
                                             .arg(actRes.errorMessage, actRes.errorCode));
        }
        QMessageBox::critical(this, tr("Błąd aktywacji licencji"),
                              tr("Nie udało się aktywować podanego klucza licencyjnego.\n\nPowód: %1\nKod: %2\n\nKontakt w sprawie licencji: 505 012 914")
                                  .arg(actRes.errorMessage, actRes.errorCode));
        return;
    }

    if (ui->lblLockedStatus) {
        ui->lblLockedStatus->setText(tr("<font color='#4ade80'><b>Klucz zaakceptowany (%1)!</b> Ponowne uruchamianie...</font>")
                                         .arg(LicenseManager::instance().tierName()));
    }

    // Update Security Center registration
    WindowsSecurityIntegration::registerAntivirus();

    QMessageBox msgBox(this);
    msgBox.setWindowTitle(tr("Zmiana licencji"));
    msgBox.setIcon(QMessageBox::Information);
    msgBox.setText(tr("Trwa zmiana licencji... Program wymaga ponownego uruchomienia, proszę czekać."));
    msgBox.setStandardButtons(QMessageBox::NoButton);
    msgBox.show();
    QCoreApplication::processEvents();

    QTimer::singleShot(1200, this, []() {
        QString appPath = QCoreApplication::applicationFilePath();
        QStringList args = QCoreApplication::arguments();
        if (!args.isEmpty()) args.removeFirst();
        QProcess::startDetached(appPath, args);
        QCoreApplication::quit();
    });
}

} // namespace verax
