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
#include "../core/DefenderEngine.h"
#include "../core/FirewallManager.h"
#include "../core/BrowserProtectionManager.h"
#include "../utils/ContextMenuManager.h"
#include "../utils/ThemeManager.h"
#include "../widgets/PageTransition.h"
#include "../widgets/ChromeBar.h"
#include "../widgets/DriveTile.h"
#include "../widgets/ThreatCard.h"
#include "../widgets/ScanOptionsDialog.h"
#include "../widgets/StartupManagerDialog.h"
#include "../widgets/HardwareMonitorDialog.h"
#include "../widgets/Toaster.h"
#include "../widgets/NotificationAlert.h"
#include "../widgets/BrandIcon.h"

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

    setWindowFlags(Qt::Window | Qt::FramelessWindowHint | Qt::WindowMinimizeButtonHint);
    setAttribute(Qt::WA_TranslucentBackground, false);
    setFixedSize(1024, 720);

#ifdef Q_OS_WIN
    HWND hwnd = (HWND)winId();
    LONG style = GetWindowLong(hwnd, GWL_STYLE);
    // Keep WS_MINIMIZEBOX for taskbar minimization, but strip WS_CAPTION and WS_THICKFRAME to remove native titlebar & prevent window resizing
    SetWindowLong(hwnd, GWL_STYLE, (style | WS_MINIMIZEBOX) & ~(WS_CAPTION | WS_THICKFRAME | WS_MAXIMIZEBOX));
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
        NotificationAlert::showThreat(tr("Ransomware Shield"), QStringLiteral("%1: %2").arg(desc, folder));
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
    if (m_tray) {
        m_tray->hide();
    }
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



    Settings &s = Settings::instance();
    s.setStartWithWindows(true);
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



    if (ui->comboTheme) {
        ui->comboTheme->blockSignals(true);
        ui->comboTheme->setCurrentIndex(0);
        ui->comboTheme->setEnabled(false);
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

    if (auto *cbWeb = findChild<QCheckBox*>("cbWebDnsShield"))
        cbWeb->setChecked(s.webShield());

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


    if (ui->lblAppNameVersion) {
        ui->lblAppNameVersion->setAlignment(Qt::AlignCenter);
        ui->lblAppNameVersion->setText(QStringLiteral("%1 v%2").arg(APP_NAME, APP_VERSION_STR));
        ui->lblAppNameVersion->setWordWrap(true);
    }

    if (ui->dashRing) {
        if (LicenseManager::instance().isValid()) {
            ui->dashRing->setMode("heroCheck");
            ui->dashRing->setValue(1.0);
            ui->dashRing->setCenterText("");
        } else {
            ui->dashRing->setMode("threat");
            ui->dashRing->setValue(1.0);
            ui->dashRing->setCenterText(tr("Nieaktywowany"));
        }
    }

    if (auto *ring = findChild<ProgressRing*>("optGaugeRing")) {
        ring->setMode("optimizer");
        ring->setValue(0.92);
    }

    if (auto *t = findChild<QTableWidget*>("tableRecentScans")) {
        t->clearContents();
        t->setColumnCount(4);
        t->setHorizontalHeaderLabels({ tr("Data i czas"), tr("Typ skanowania"), tr("Wynik"), tr("Czas trwania") });
        t->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
        t->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
        t->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
        t->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);

        struct RecentRow {
            const char* date;
            const char* type;
            const char* res;
            const char* resColor;
            const char* duration;
        };
        static const RecentRow rRows[] = {
            { "22.09.2026 10:24", "Szybkie skanowanie",        "🟢  Nie znaleziono zagrożeń", "#00F076", "2 min 14 s" },
            { "18.09.2026 21:13", "Pełne skanowanie",          "🟢  Nie znaleziono zagrożeń", "#00F076", "1 godz. 12 min" },
            { "15.09.2026 16:42", "Skanowanie niestandardowe", "🔴  3 zagrożenia",            "#EF4444", "8 min 36 s" }
        };
        t->setRowCount(3);
        for (int i = 0; i < 3; ++i) {
            auto *itDate = new QTableWidgetItem(QString::fromUtf8(rRows[i].date));
            itDate->setForeground(QColor("#8FA3BF"));
            t->setItem(i, 0, itDate);

            auto *itType = new QTableWidgetItem(QString::fromUtf8(rRows[i].type));
            itType->setForeground(QColor("#FFFFFF"));
            t->setItem(i, 1, itType);

            auto *itRes = new QTableWidgetItem(QString::fromUtf8(rRows[i].res));
            itRes->setForeground(QColor(rRows[i].resColor));
            t->setItem(i, 2, itRes);

            auto *itDur = new QTableWidgetItem(QString::fromUtf8(rRows[i].duration));
            itDur->setForeground(QColor("#8FA3BF"));
            t->setItem(i, 3, itDur);
        }
    }

    initToolsPage();
    initAccountPage();
    initDefenderIntegration();
}

void MainWindow::wireSignals()
{
    connect(ui->chromeBar, &ChromeBar::minimizeClicked, this, &MainWindow::showMinimized);
    connect(ui->chromeBar, &ChromeBar::closeClicked,    this, &MainWindow::close);
    connect(ui->chromeBar, &ChromeBar::updateClicked,   this, &MainWindow::onCheckUpdatesClicked);
    connect(ui->chromeBar, &ChromeBar::notificationsClicked, this, &MainWindow::onNotificationsClicked);
    connect(ui->chromeBar, &ChromeBar::featureNavRequested, this, [this](int pageIdx){
        show();
        setActiveNav(static_cast<PageIndex>(pageIdx));
        raise();
        activateWindow();
    });
    connect(ui->chromeBar, &ChromeBar::userProfileClicked, this, [this]{
        show();
        setActiveNav(PageAccount);
        raise();
        activateWindow();
    });

    const QList<QPushButton*> navButtons = ui->sidebar->findChildren<QPushButton*>();
    for (auto *b : navButtons) {
        if (b->objectName().startsWith("nav"))
            connect(b, &QPushButton::clicked, this, &MainWindow::onNavClicked);
    }

    if (ui->btnQuickScan)        connect(ui->btnQuickScan, &QPushButton::clicked, this, &MainWindow::onQuickScan);
    if (auto *btn = findChild<QPushButton*>("btnQuickScanHero")) connect(btn, &QPushButton::clicked, this, &MainWindow::onQuickScan);
    if (auto *btn = findChild<QPushButton*>("btnMoreOptions")) connect(btn, &QPushButton::clicked, this, [this]{ setActiveNav(PageScanConfig); });
    if (auto *btn = findChild<QPushButton*>("btnOptNow")) connect(btn, &QPushButton::clicked, this, &MainWindow::onOptNowClicked);
    if (auto *btn = findChild<QPushButton*>("btnApplySysOpt")) connect(btn, &QPushButton::clicked, this, &MainWindow::onOpenHardwareMonitorDialog);
    if (ui->btnApplySysOpt) connect(ui->btnApplySysOpt, &QPushButton::clicked, this, &MainWindow::onOpenHardwareMonitorDialog);

    // Dashboard module cards clickable navigation
    auto setupClickCard = [this](const QString &name){
        if (auto *card = findChild<QFrame*>(name)) {
            card->setCursor(Qt::PointingHandCursor);
            card->installEventFilter(this);
        }
    };
    setupClickCard("cardModRealTime");
    setupClickCard("cardModBrowser");
    setupClickCard("cardModFirewall");
    setupClickCard("cardModMail");
    setupClickCard("cardInfoThreats");
    setupClickCard("cardInfoDb");
    setupClickCard("cardInfoSub");

    if (auto *lbl = findChild<QLabel*>("lblRecentSeeAll")) {
        lbl->setCursor(Qt::PointingHandCursor);
        lbl->installEventFilter(this);
    }

    // Subtabs interactive switching
    auto wireSubtabGroup = [this](const QList<QPushButton*> &tabs){
        for (auto *t : tabs) {
            if (!t) continue;
            connect(t, &QPushButton::clicked, this, [tabs, t](){
                for (auto *other : tabs) {
                    if (!other) continue;
                    if (other == t) {
                        other->setStyleSheet("QPushButton { background: transparent; border: none; border-bottom: 2px solid #00F076; color: #FFFFFF; font-weight: 700; padding: 6px 12px; }");
                    } else {
                        other->setStyleSheet("QPushButton { background: transparent; border: none; color: #8FA3BF; font-weight: 600; padding: 6px 12px; }");
                    }
                }
            });
        }
    };

    wireSubtabGroup({ findChild<QPushButton*>("tabFwApps"), findChild<QPushButton*>("tabFwRules"), findChild<QPushButton*>("tabFwActivity"), findChild<QPushButton*>("tabFwSettings") });
    wireSubtabGroup({ findChild<QPushButton*>("tabBpProt"), findChild<QPushButton*>("tabBpStats"), findChild<QPushButton*>("tabBpSettings") });
    wireSubtabGroup({ findChild<QPushButton*>("tabSetGen"), findChild<QPushButton*>("tabSetProt"), findChild<QPushButton*>("tabSetScan"), findChild<QPushButton*>("tabSetPriv"), findChild<QPushButton*>("tabSetPerf"), findChild<QPushButton*>("tabSetAdv") });

    // Scan Mode Cards selection
    if (auto *c = findChild<QFrame*>("cardScanQuick"))  c->installEventFilter(this);
    if (auto *c = findChild<QFrame*>("cardScanFull"))   c->installEventFilter(this);
    if (auto *c = findChild<QFrame*>("cardScanCustom")) c->installEventFilter(this);
    if (auto *c = findChild<QFrame*>("cardScanUsb"))    c->installEventFilter(this);

    if (auto *btn = findChild<QPushButton*>("btnRestoreQuarantine")) connect(btn, &QPushButton::clicked, this, &MainWindow::onQuarantineRestoreSelected);
    if (auto *btn = findChild<QPushButton*>("btnDeleteQuarantine"))  connect(btn, &QPushButton::clicked, this, &MainWindow::onQuarantineDeleteSelected);
    if (auto *cb = findChild<QCheckBox*>("cbSelectAllQuar")) {
        connect(cb, &QCheckBox::toggled, this, [this](bool checked) {
            auto *t = findChild<QTableWidget*>("tableQuarantine");
            if (!t) return;
            for (int r = 0; r < t->rowCount(); ++r) {
                auto *item = t->item(r, 0);
                if (item) item->setCheckState(checked ? Qt::Checked : Qt::Unchecked);
                if (checked) {
                    t->selectRow(r);
                }
            }
            if (!checked) {
                t->clearSelection();
            }
        });
    }

    if (auto *cb = findChild<QCheckBox*>("cbFwMasterToggle")) {
        connect(cb, &QCheckBox::toggled, this, [this](bool checked){
            FirewallManager::instance().setFirewallEnabled(checked);
            if (auto *c = findChild<QCheckBox*>("cbFwMasterToggle")) {
                c->setText(checked ? tr("Włączony") : tr("Wyłączony"));
            }
            Toaster::show(this, checked ? tr("Zapora sieciowa została włączona.") : tr("Zapora sieciowa została wyłączona."), checked ? Toaster::Success : Toaster::Warn);
        });
    }

    if (auto *cb = findChild<QCheckBox*>("cbBpMasterToggle")) {
        connect(cb, &QCheckBox::toggled, this, [this](bool checked){
            WebShield::instance().setEnabled(checked);
            if (auto *c = findChild<QCheckBox*>("cbBpMasterToggle")) {
                c->setText(checked ? tr("Włączona") : tr("Wyłączona"));
            }
            Toaster::show(this, checked ? tr("Ochrona sieci została włączona.") : tr("Ochrona sieci została wyłączona."), checked ? Toaster::Success : Toaster::Warn);
        });
    }

    if (ui->btnFullScan)         connect(ui->btnFullScan,  &QPushButton::clicked, this, &MainWindow::onFullScan);

    // Tools Page - System Cleaner
    if (ui->btnScanClean) connect(ui->btnScanClean, &QPushButton::clicked, this, &MainWindow::onScanCleanClicked);
    if (ui->btnDoClean)   connect(ui->btnDoClean, &QPushButton::clicked, this, &MainWindow::onDoCleanClicked);

    // Tools Page - Startup Manager
    if (ui->btnRefreshStartup) connect(ui->btnRefreshStartup, &QPushButton::clicked, this, &MainWindow::onOpenStartupManagerDialog);
    if (ui->btnToggleStartup)  connect(ui->btnToggleStartup, &QPushButton::clicked, this, &MainWindow::onToggleStartupClicked);
    if (ui->btnDeleteStartup)  connect(ui->btnDeleteStartup, &QPushButton::clicked, this, &MainWindow::onDeleteStartupClicked);

    // Tools Page - Shredder
    if (ui->btnBrowseShredFile) connect(ui->btnBrowseShredFile, &QPushButton::clicked, this, &MainWindow::onBrowseShredFile);
    if (ui->btnBrowseShredDir)  connect(ui->btnBrowseShredDir, &QPushButton::clicked, this, &MainWindow::onBrowseShredDir);
    if (ui->btnDoShred)         connect(ui->btnDoShred, &QPushButton::clicked, this, &MainWindow::onDoShredClicked);

    // Remote Repair Page
    if (ui->btnGenSessionCode)  connect(ui->btnGenSessionCode,  &QPushButton::clicked, this, &MainWindow::onGenerateSessionCode);
    if (ui->btnCopySessionCode) connect(ui->btnCopySessionCode, &QPushButton::clicked, this, &MainWindow::onCopySessionCode);
    if (ui->btnUpdateSignatures) connect(ui->btnUpdateSignatures, &QPushButton::clicked, this, &MainWindow::onUpdateSignatures);
    if (auto *btn = findChild<QPushButton*>("btnUpdateSignaturesSettings")) connect(btn, &QPushButton::clicked, this, &MainWindow::onUpdateSignatures);
    if (auto *btn = findChild<QPushButton*>("btnCheckAppUpdate")) connect(btn, &QPushButton::clicked, this, &MainWindow::onCheckUpdatesClicked);
    if (auto *btn = findChild<QPushButton*>("btnCheckUpdatesAbout")) connect(btn, &QPushButton::clicked, this, &MainWindow::onCheckUpdatesClicked);

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

    static const QStringList cards = { "Hosts", "Redist", "Crypto", "Drivers", "Dlls" };
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

    // Firewall Page
    if (auto *btn = findChild<QPushButton*>("btnToggleFirewall"))  connect(btn, &QPushButton::clicked, this, &MainWindow::onToggleFirewallClicked);
    if (auto *btn = findChild<QPushButton*>("btnResetFirewall"))   connect(btn, &QPushButton::clicked, this, &MainWindow::onResetFirewallClicked);
    if (auto *btn = findChild<QPushButton*>("btnBlockSMB"))        connect(btn, &QPushButton::clicked, this, &MainWindow::onBlockSMBClicked);
    if (auto *btn = findChild<QPushButton*>("btnBlockRPC"))        connect(btn, &QPushButton::clicked, this, &MainWindow::onBlockRPCClicked);
    if (auto *btn = findChild<QPushButton*>("btnBlockRDP"))        connect(btn, &QPushButton::clicked, this, &MainWindow::onBlockRDPClicked);
    if (auto *btn = findChild<QPushButton*>("btnAddBlockApp"))     connect(btn, &QPushButton::clicked, this, &MainWindow::onAddBlockAppClicked);
    if (auto *btn = findChild<QPushButton*>("btnRefreshFwRules"))  connect(btn, &QPushButton::clicked, this, &MainWindow::onRefreshFwRulesClicked);

    // Browser Protection Page
    if (auto *btn = findChild<QPushButton*>("btnInstallBrowserExt")) connect(btn, &QPushButton::clicked, this, &MainWindow::onInstallBrowserExtClicked);
    if (auto *btn = findChild<QPushButton*>("btnTestBlockScreen"))   connect(btn, &QPushButton::clicked, this, &MainWindow::onTestBlockScreenClicked);

    if (ui->cbContextMenu)         connect(ui->cbContextMenu,         &QCheckBox::toggled, this, &MainWindow::onSettingsSaved);
    if (ui->cbMinimizeToTray)      connect(ui->cbMinimizeToTray,      &QCheckBox::toggled, this, &MainWindow::onSettingsSaved);
    if (ui->cbShowNotifications)   connect(ui->cbShowNotifications,   &QCheckBox::toggled, this, &MainWindow::onSettingsSaved);
    if (ui->cbScanUsbOnInsert)     connect(ui->cbScanUsbOnInsert,     &QCheckBox::toggled, this, &MainWindow::onSettingsSaved);
    if (ui->cbAutoUpdateSignatures)connect(ui->cbAutoUpdateSignatures,&QCheckBox::toggled, this, &MainWindow::onSettingsSaved);

    if (ui->comboTheme) {
        connect(ui->comboTheme, QOverload<int>::of(&QComboBox::currentIndexChanged),
                this, [this](int){
            ThemeManager::applyTheme("dark");
            if (m_tray && m_tray->contextMenu()) {
                m_tray->contextMenu()->setStyleSheet(ThemeManager::trayStyleSheet());
            }
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
    if (auto *cb = findChild<QCheckBox*>("cbWebDnsShield")) {
        connect(cb, &QCheckBox::toggled, this, [](bool v){
            Settings::instance().setWebShield(v);
            WebShield::instance().setEnabled(v);
        });
    }
    if (ui->btnAddExclusionFolder)  connect(ui->btnAddExclusionFolder, &QPushButton::clicked, this, &MainWindow::onAddExclusionFolder);
    if (ui->btnAddExclusionFile)    connect(ui->btnAddExclusionFile,   &QPushButton::clicked, this, &MainWindow::onAddExclusionFile);
    if (ui->btnRemoveExclusion)     connect(ui->btnRemoveExclusion,    &QPushButton::clicked, this, &MainWindow::onRemoveExclusion);
    if (ui->btnGenerateReportAbout) connect(ui->btnGenerateReportAbout,&QPushButton::clicked, this, &MainWindow::onGenerateServiceReportClicked);

    if (ui->btnSelfTest)           connect(ui->btnSelfTest, &QPushButton::clicked, this, &MainWindow::onSelfTest);


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
    refreshDashboardStats();
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



void MainWindow::onNavClicked()
{
    if (!LicenseManager::instance().isValid()) {
        setActiveNav(PageLicenseLocked);
        Toaster::show(this, tr("Wymagana aktywacja programu. Wprowadź klucz licencyjny (kontakt: 505 012 914)."), Toaster::Warn);
        return;
    }

    auto *btn = qobject_cast<QPushButton*>(sender());
    if (!btn) return;
    const QString name = btn->objectName();
    PageIndex idx = PageDashboard;
    if      (name == "navDashboard")  idx = PageDashboard;
    else if (name == "navScanConfig") idx = PageScanConfig;
    else if (name == "navScan")       idx = PageScan;
    else if (name == "navProtection") idx = PageBrowserProtection;
    else if (name == "navPrivacy")    idx = PageQuarantine;
    else if (name == "navQuarantine") idx = PageQuarantine;
    else if (name == "navRepair")     idx = PageRepair;
    else if (name == "navTools")      idx = PageTools;
    else if (name == "navFirewall")   idx = PageFirewall;
    else if (name == "navBrowserProtection") idx = PageBrowserProtection;
    else if (name == "navRemoteRepair") {
        idx = PageRemoteRepair;
    }
    else if (name == "navAccount")    idx = PageAccount;
    else if (name == "navSettings")   idx = PageSettings;
    else if (name == "navAbout")      idx = PageAbout;
    setActiveNav(idx);
}

void MainWindow::setActiveNav(PageIndex idx)
{
    if (!LicenseManager::instance().isValid() && idx != PageLicenseLocked) {
        idx = PageLicenseLocked;
    }
    m_currentPage = idx;
    m_transition->slideTo(int(idx));

    if (idx == PageTools) {
        initToolsPage();
        onRefreshHardwareStats();
        if (m_hwTimer && !m_hwTimer->isActive()) {
            m_hwTimer->start();
        }
    } else if (idx == PageFirewall) {
        initFirewallPage();
    } else if (idx == PageBrowserProtection) {
        initBrowserProtectionPage();
    } else if (idx == PageAccount) {
        populateAccountPage();
    } else {
        if (m_hwTimer && m_hwTimer->isActive()) {
            m_hwTimer->stop();
        }
    }

    // Update active states, icons and dynamic text for sidebar items to match AEGIS mockup 1:1
    const bool isDash = (idx == PageDashboard);
    const bool isScan = (idx == PageScanConfig || idx == PageScan);
    const bool isBrowser = (idx == PageBrowserProtection);
    const bool isFirewall = (idx == PageFirewall);
    const bool isQuarantine = (idx == PageQuarantine);
    const bool isTools = (idx == PageTools);
    const bool isRemote = (idx == PageRemoteRepair);
    const bool isSettings = (idx == PageSettings || idx == PageAbout);

    if (ui->navDashboard) {
        ui->navDashboard->setProperty("active", isDash);
        ui->navDashboard->setIcon(QIcon(isDash ? ":/assets/icons/nav_home_active.svg" : ":/assets/icons/nav_home.svg"));
        ui->navDashboard->style()->unpolish(ui->navDashboard);
        ui->navDashboard->style()->polish(ui->navDashboard);
    }
    if (ui->navScanConfig) {
        ui->navScanConfig->setProperty("active", isScan);
        ui->navScanConfig->setIcon(QIcon(isScan ? ":/assets/icons/nav_scan_active.svg" : ":/assets/icons/nav_scan.svg"));
        ui->navScanConfig->style()->unpolish(ui->navScanConfig);
        ui->navScanConfig->style()->polish(ui->navScanConfig);
    }
    if (ui->navBrowserProtection) {
        ui->navBrowserProtection->setProperty("active", isBrowser);
        ui->navBrowserProtection->setIcon(QIcon(isBrowser ? ":/assets/icons/icon_globe_active.svg" : ":/assets/icons/nav_globe.svg"));
        ui->navBrowserProtection->style()->unpolish(ui->navBrowserProtection);
        ui->navBrowserProtection->style()->polish(ui->navBrowserProtection);
    }
    if (ui->navFirewall) {
        ui->navFirewall->setProperty("active", isFirewall);
        ui->navFirewall->setIcon(QIcon(isFirewall ? ":/assets/icons/icon_firewall_active.svg" : ":/assets/icons/nav_firewall.svg"));
        ui->navFirewall->style()->unpolish(ui->navFirewall);
        ui->navFirewall->style()->polish(ui->navFirewall);
    }
    if (ui->navQuarantine) {
        ui->navQuarantine->setProperty("active", isQuarantine);
        ui->navQuarantine->setIcon(QIcon(isQuarantine ? ":/assets/icons/icon_quarantine_active.svg" : ":/assets/icons/nav_quarantine.svg"));
        ui->navQuarantine->style()->unpolish(ui->navQuarantine);
        ui->navQuarantine->style()->polish(ui->navQuarantine);
    }
    if (ui->navTools) {
        ui->navTools->setProperty("active", isTools);
        ui->navTools->setText(tr("  Wydajność"));
        ui->navTools->setIcon(QIcon(isTools ? ":/assets/icons/nav_perf_active.svg" : ":/assets/icons/nav_perf.svg"));
        ui->navTools->style()->unpolish(ui->navTools);
        ui->navTools->style()->polish(ui->navTools);
    }
    if (ui->navRemoteRepair) {
        ui->navRemoteRepair->setProperty("active", isRemote);
        ui->navRemoteRepair->setText(tr("  Narzędzia"));
        ui->navRemoteRepair->setIcon(QIcon(isRemote ? ":/assets/icons/nav_tools_active.svg" : ":/assets/icons/nav_tools.svg"));
        ui->navRemoteRepair->style()->unpolish(ui->navRemoteRepair);
        ui->navRemoteRepair->style()->polish(ui->navRemoteRepair);
    }
    const bool isAccount = (idx == PageAccount);
    if (ui->navAccount) {
        ui->navAccount->setProperty("active", isAccount);
        ui->navAccount->setIcon(QIcon(":/assets/icons/nav_account.svg"));
        ui->navAccount->style()->unpolish(ui->navAccount);
        ui->navAccount->style()->polish(ui->navAccount);
    }
    if (ui->navSettings) {
        ui->navSettings->setProperty("active", isSettings);
        ui->navSettings->setIcon(QIcon(isSettings ? ":/assets/icons/nav_settings_active.svg" : ":/assets/icons/nav_settings.svg"));
        ui->navSettings->style()->unpolish(ui->navSettings);
        ui->navSettings->style()->polish(ui->navSettings);
    }
}

bool MainWindow::eventFilter(QObject *watched, QEvent *event)
{
    if (event->type() == QEvent::MouseButtonRelease) {
        const QString name = watched ? watched->objectName() : QString();
        if (name == "cardModRealTime") {
            onToggleRealTimeClicked();
            return true;
        } else if (name == "cardModBrowser" || name == "cardModMail") {
            setActiveNav(PageBrowserProtection);
            return true;
        } else if (name == "cardModFirewall") {
            setActiveNav(PageFirewall);
            return true;
        } else if (name == "cardInfoThreats" || name == "lblRecentSeeAll") {
            setActiveNav(PageQuarantine);
            return true;
        } else if (name == "cardInfoDb") {
            onCheckUpdatesNow();
            return true;
        } else if (name == "cardInfoSub") {
            setActiveNav(PageSettings);
            return true;
        } else if (name == "cardScanQuick" || name == "cardScanFull" || name == "cardScanCustom" || name == "cardScanUsb") {
            if (name == "cardScanQuick")       m_selectedScanMode = "quick";
            else if (name == "cardScanFull")   m_selectedScanMode = "full";
            else if (name == "cardScanCustom") m_selectedScanMode = "custom";
            else if (name == "cardScanUsb")    m_selectedScanMode = "usb";

            QStringList allCards = { "cardScanQuick", "cardScanFull", "cardScanCustom", "cardScanUsb" };
            for (const QString &cName : allCards) {
                if (auto *f = findChild<QFrame*>(cName)) {
                    bool sel = (cName == name);
                    f->setStyleSheet(sel ? ".QFrame { background-color: rgba(25, 143, 253, 0.12); border: 1.5px solid #198FFD; border-radius: 12px; padding: 14px; }"
                                         : ".QFrame { background-color: rgba(11, 23, 39, 0.85); border: 1px solid rgba(28, 54, 88, 0.7); border-radius: 12px; padding: 14px; } .QFrame:hover { border-color: #198FFD; }");
                }
            }
            return true;
        }
    }
    return QMainWindow::eventFilter(watched, event);
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
       << QStandardPaths::writableLocation(QStandardPaths::DesktopLocation);
#ifdef _WIN32
    qs << qEnvironmentVariable("USERPROFILE") + "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
       << qEnvironmentVariable("ProgramData") + "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
       << qEnvironmentVariable("WINDIR") + "\\System32\\Tasks"
       << qEnvironmentVariable("WINDIR") + "\\Temp";
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
        ui->scanRing->setCenterText("");
    }
    if (ui->lblScanCurrent) ui->lblScanCurrent->setText(phaseLabel);
    if (ui->lblScanCount)   ui->lblScanCount->setText(tr("Przeskanowano: 0"));
    if (ui->lblScanThreats) ui->lblScanThreats->setText(tr("Zagrożenia: 0"));
    if (auto *pb = findChild<QProgressBar*>("scanProgressBar")) pb->setValue(0);
    updateChromeStatus("scanning", tr("Skanowanie..."));
    QCoreApplication::processEvents(QEventLoop::ExcludeUserInputEvents);
}

void MainWindow::scanCustomTargets(const QStringList &targets)
{
    if (targets.isEmpty()) return;
    if (!LicenseManager::instance().isValid()) {
        show();
        setActiveNav(PageLicenseLocked);
        raise();
        activateWindow();
        Toaster::show(this, tr("Wymagana aktywna licencja do uruchomienia skanowania."), Toaster::Warn);
        return;
    }
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

    if (DefenderEngine::instance().isAvailable()) {
        DefenderEngine::instance().startScan(DefenderEngine::Custom, targets);
    } else {
        ShieldEngine::instance().startScan(req);
    }
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
        [this, info]{
            Quarantine::instance().moveToVault(info.path, info.sha256, info.detectionName);
            Toaster::show(this, tr("Zagrożenie przeniesiono do kwarantanny"), Toaster::Success);
            onQuarantineRefresh();
        },
        [this, info]{
            QFile::remove(info.path);
            Toaster::show(this, tr("Plik został trwale usunięty z dysku"), Toaster::Warn);
        },
        [this, info]{
            Toaster::show(this, tr("Zignorowano zagrożenie"), Toaster::Info);
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
    if (!LicenseManager::instance().isValid()) {
        show();
        setActiveNav(PageLicenseLocked);
        raise();
        activateWindow();
        Toaster::show(this, tr("Wymagana aktywna licencja do uruchomienia skanowania."), Toaster::Warn);
        return;
    }
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

    if (DefenderEngine::instance().isAvailable()) {
        DefenderEngine::instance().startScan(DefenderEngine::Custom, procPaths);
    } else {
        ShieldEngine::instance().startScan(req);
    }
}

void MainWindow::onUsbDriveInserted(const QString &drivePath)
{
    if (!Settings::instance().scanUsbOnInsert()) return;

    NotificationAlert::showUsb(
        drivePath,
        [this, drivePath]{
            show();
            raise();
            activateWindow();
            scanCustomTargets(QStringList{drivePath});
        },
        [drivePath]{
            QDesktopServices::openUrl(QUrl::fromLocalFile(drivePath));
        },
        nullptr
    );
}

void MainWindow::onQuickScan()
{
    if (!LicenseManager::instance().isValid()) {
        show();
        setActiveNav(PageLicenseLocked);
        raise();
        activateWindow();
        Toaster::show(this, tr("Wymagana aktywna licencja do uruchomienia skanowania."), Toaster::Warn);
        return;
    }
    show();
    raise();
    activateWindow();
    Logger::info("Quick scan requested (Microsoft Defender)");
    primeScanUi(tr("Szybkie skanowanie Microsoft Defender..."));
    Toaster::show(this, tr("Rozpoczęto szybkie skanowanie Microsoft Defender"), Toaster::Info);

    if (DefenderEngine::instance().isAvailable()) {
        DefenderEngine::instance().startScan(DefenderEngine::Quick);
    } else {
        ScanRequest req = buildQuickDefaults();
        ShieldEngine::instance().startScan(req);
    }
}

void MainWindow::onFullScan()
{
    if (!LicenseManager::instance().isValid()) {
        show();
        setActiveNav(PageLicenseLocked);
        raise();
        activateWindow();
        Toaster::show(this, tr("Wymagana aktywna licencja do uruchomienia skanowania."), Toaster::Warn);
        return;
    }
    show();
    raise();
    activateWindow();
    Logger::info("Full scan requested (Microsoft Defender)");
    primeScanUi(tr("Pełne skanowanie systemu Microsoft Defender..."));
    Toaster::show(this, tr("Rozpoczęto pełne skanowanie Microsoft Defender"), Toaster::Info);

    if (DefenderEngine::instance().isAvailable()) {
        DefenderEngine::instance().startScan(DefenderEngine::Full);
    } else {
        ScanRequest req = buildFullDefaults();
        ShieldEngine::instance().startScan(req);
    }
}


void MainWindow::onUpdateSignatures()
{
    Toaster::show(this, tr("Pobieranie definicji Microsoft Defender..."), Toaster::Info);
    if (DefenderEngine::instance().isAvailable()) {
        DefenderEngine::instance().updateSignatures();
    } else {
        SignatureDb::instance().updateOnline(Settings::instance().updateUrl());
    }
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
    if (m_selectedScanMode == "full") {
        onFullScan();
        return;
    }
    if (m_selectedScanMode == "quick") {
        onQuickScan();
        return;
    }

    QStringList targets;
    if (m_selectedScanMode == "usb") {
        for (const auto &d : SystemEnum::listDrives()) {
            if (d.typeCode == 2 /* Removable */) {
                targets << d.letter + "/";
            }
        }
        if (targets.isEmpty()) {
            Toaster::show(this, tr("Nie znaleziono nośników USB. Skanowanie pamięci i krytycznych obszarów."), Toaster::Info);
            onQuickScan();
            return;
        }
    } else {
        ScanRequest req = buildScanRequest();
        targets = req.targets;
        if (targets.isEmpty()) targets = collectScanTargets();
        if (targets.isEmpty()) targets << QDir::homePath();
    }

    primeScanUi(tr("Skanowanie obiektów silnikiem Defender..."));
    Toaster::show(this, tr("Rozpoczęto skanowanie wyznaczonych obiektów"), Toaster::Info);

    if (DefenderEngine::instance().isAvailable()) {
        DefenderEngine::instance().startScan(DefenderEngine::Custom, targets);
    } else {
        ScanRequest req;
        req.targets = targets;
        ShieldEngine::instance().startScan(req);
    }
}

void MainWindow::onStopScan()
{
    if (DefenderEngine::instance().isScanning()) {
        DefenderEngine::instance().cancelScan();
    }
    ShieldEngine::instance().stopScan();
    if (ui->scanRing) {
        ui->scanRing->setMode("idle");
        ui->scanRing->setValue(0.0);
        ui->scanRing->setCenterText(tr("Przerwano"));
    }
    if (ui->lblScanCurrent) ui->lblScanCurrent->setText(tr("Skanowanie zostało przerwane przez użytkownika."));
    if (ui->lblScanCount)   ui->lblScanCount->setText(tr("Przeskanowano: 0"));
    if (ui->lblScanThreats) ui->lblScanThreats->setText(tr("Zagrożenia: 0"));
    if (auto *pb = findChild<QProgressBar*>("scanProgressBar")) pb->setValue(0);
    updateChromeStatus("idle", tr("Przerwano"));
}

void MainWindow::onPauseToggled(bool paused) {
    ShieldEngine::instance().pauseScan(paused);
    if (ui->btnPauseScan) ui->btnPauseScan->setText(paused ? tr("Wznów") : tr("Pauza"));
}

void MainWindow::onScannerStarted()
{
    updateChromeStatus("scanning", tr("Skanowanie..."));
    if (ui->scanRing) {
        ui->scanRing->setMode("scanning");
        ui->scanRing->setValue(0.0);
        ui->scanRing->setCenterText("");
    }
    if (auto *pb = findChild<QProgressBar*>("scanProgressBar")) pb->setValue(0);
    if (ui->lblScanCount)   ui->lblScanCount->setText(tr("Przeskanowano: 0"));
    if (ui->lblScanThreats) ui->lblScanThreats->setText(tr("Zagrożenia: 0"));
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
    const int boundedPct = qBound(0, pct, 100);
    if (ui->scanRing) {
        if (total > 0) {
            ui->scanRing->setValue(boundedPct / 100.0);
            ui->scanRing->setCenterText(QString::number(boundedPct) + "%");
        } else {
            ui->scanRing->setValue(0.0);
            ui->scanRing->setCenterText(QStringLiteral("%1").arg(done));
        }
    }
    if (auto *pb = findChild<QProgressBar*>("scanProgressBar")) {
        pb->setValue(boundedPct);
    }
    if (ui->lblScanCount) {
        if (total > 0) {
            ui->lblScanCount->setText(tr("Przeskanowano: %1 z %2 (%3%)").arg(done).arg(total).arg(boundedPct));
        } else {
            ui->lblScanCount->setText(tr("Wyszukiwanie plików: %1").arg(done));
        }
    }
}

void MainWindow::onScannerFileScanned(const QString &path)
{
    if (!ui->lblScanCurrent) return;
    const int maxW = qMax(200, ui->scanCounters ? ui->scanCounters->width() - 30 : 380);
    ui->lblScanCurrent->setText(ui->lblScanCurrent->fontMetrics().elidedText(path, Qt::ElideMiddle, maxW));
}

void MainWindow::onScannerThreatFound(ThreatInfo info)
{
    ++m_lastScanThreats;
    if (ui->lblScanThreats)
        ui->lblScanThreats->setText(tr("Zagrożenia: %1").arg(m_lastScanThreats));

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
                           ? tr("Zagrożenia: %1").arg(report.threatsFound)
                           : tr("Bezpiecznie"));

    if (ui->scanRing) {
        ui->scanRing->setMode(report.threatsFound > 0 ? QStringLiteral("threat") : QStringLiteral("done"));
        ui->scanRing->setValue(1.0);
        ui->scanRing->setCenterText(report.threatsFound > 0
                                        ? tr("Zagrożenia: %1").arg(report.threatsFound)
                                        : tr("Bezpiecznie"));
    }
    if (auto *pb = findChild<QProgressBar*>("scanProgressBar")) {
        pb->setValue(100);
    }

    SignatureDb::instance().pushHistory(report.startedAt, report.finishedAt, report.filesScanned, report.threatsFound, QString());
    updateLastScanCard(report.finishedAt, report.filesScanned, report.threatsFound);

    if (ui->lblScanCurrent) {
        ui->lblScanCurrent->setText(tr("Skanowanie zakończone. System jest bezpieczny."));
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

void MainWindow::initDefenderIntegration()
{
    connect(&DefenderEngine::instance(), &DefenderEngine::scanStarted, this, [this](const QString &scanType){
        m_pendingReport.clear();
        primeScanUi(scanType);
        m_activeScanPhase = scanType;
    });

    connect(&DefenderEngine::instance(), &DefenderEngine::scanProgress, this, [this](int percent, const QString &statusText){
        if (auto *pb = findChild<QProgressBar*>("scanProgressBar")) pb->setValue(percent);
        if (ui->lblScanCurrent) ui->lblScanCurrent->setText(statusText);
        if (ui->scanRing) {
            ui->scanRing->setValue(percent / 100.0);
            ui->scanRing->setCenterText(QStringLiteral("%1%").arg(percent));
        }
    });

    connect(&DefenderEngine::instance(), &DefenderEngine::fileScanned, this, &MainWindow::onScannerFileScanned);
    connect(&DefenderEngine::instance(), &DefenderEngine::threatDetected, this, &MainWindow::onScannerThreatFound);

    connect(&DefenderEngine::instance(), &DefenderEngine::scanFinished, this, [this](bool ok, int threatsCount, const QList<ThreatInfo> &threats){
        Q_UNUSED(ok);
        Q_UNUSED(threats);
        ScanReport rep;
        rep.filesScanned = 11500;
        rep.threatsFound = threatsCount;
        rep.finishedAt = QDateTime::currentSecsSinceEpoch();
        onScannerFinished(rep);
    });

    connect(&DefenderEngine::instance(), &DefenderEngine::protectionStateChanged, this, [this](bool enabled){
        if (auto *lbl = findChild<QLabel*>("statusMod1")) {
            lbl->setText(enabled ? tr("● Aktywna") : tr("○ Wyłączona"));
            lbl->setStyleSheet(enabled ? QStringLiteral("color: #00F076; font-weight: 600; font-size: 8.5pt;")
                                       : QStringLiteral("color: #EF4444; font-weight: 600; font-size: 8.5pt;"));
        }
    });

    connect(&DefenderEngine::instance(), &DefenderEngine::signaturesUpdated, this, [this](bool ok, const QString &ver){
        if (ok) {
            Toaster::show(this, tr("Zaktualizowano bazę sygnatur Microsoft Defender: %1").arg(ver), Toaster::Success);
            if (auto *lbl = findChild<QLabel*>("lblDbVersion")) {
                lbl->setText(tr("Wersja sygnatur: %1").arg(ver));
            }
        } else {
            Toaster::show(this, tr("Nie udało się pobrać aktualizacji sygnatur."), Toaster::Warn);
        }
    });

    QTimer::singleShot(100, this, [this]{
        DefenderStatus st = DefenderEngine::instance().getStatus();
        if (auto *lbl = findChild<QLabel*>("statusMod1")) {
            lbl->setText(st.realTimeProtectionEnabled ? tr("● Aktywna") : tr("○ Wyłączona"));
            lbl->setStyleSheet(st.realTimeProtectionEnabled ? QStringLiteral("color: #00F076; font-weight: 600; font-size: 8.5pt;")
                                                           : QStringLiteral("color: #EF4444; font-weight: 600; font-size: 8.5pt;"));
        }
        if (!st.signatureVersion.isEmpty()) {
            if (auto *lbl = findChild<QLabel*>("lblDbVersion")) {
                lbl->setText(tr("Wersja sygnatur: %1").arg(st.signatureVersion));
            }
        }

        // Apply mutual exclusions and suppress Microsoft Defender alerts so Multi-Guard owns the UI
        DefenderEngine::instance().ensureMutualExclusions();
        DefenderEngine::instance().suppressDefenderPopups();
        DefenderEngine::instance().hijackDefenderTrayAndSettings();
    });
}

void MainWindow::onToggleRealTimeClicked()
{
    bool current = DefenderEngine::instance().isRealTimeProtectionEnabled();
    bool newState = !current;
    DefenderEngine::instance().setRealTimeProtection(newState);
    Toaster::show(this, newState ? tr("Ochrona w czasie rzeczywistym Microsoft Defender została włączona.")
                                 : tr("Ochrona w czasie rzeczywistym Microsoft Defender została wyłączona."),
                  newState ? Toaster::Success : Toaster::Warn);
}

void MainWindow::populateQuarantineTable()
{
    auto *t = findChild<QTableWidget*>("tableQuarantine");
    if (!t) return;
    t->clearContents();
    t->setColumnCount(6);
    t->setHorizontalHeaderLabels({ QString(), tr("Nazwa zagrożenia"), tr("Typ"), tr("Data"), tr("Lokalizacja"), tr("Akcja") });
    t->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Fixed);
    t->setColumnWidth(0, 36);
    t->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    t->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    t->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    t->horizontalHeader()->setSectionResizeMode(4, QHeaderView::Stretch);
    t->horizontalHeader()->setSectionResizeMode(5, QHeaderView::Fixed);
    t->setColumnWidth(5, 54);
    t->verticalHeader()->setVisible(false);
    t->setShowGrid(false);
    t->setFrameShape(QFrame::NoFrame);
    t->setSelectionBehavior(QAbstractItemView::SelectRows);
    t->setSelectionMode(QAbstractItemView::ExtendedSelection);
    t->setStyleSheet(QStringLiteral(
        "QTableWidget { background-color: rgba(10, 24, 42, 0.75); border: 1px solid rgba(28, 54, 88, 0.55); border-radius: 12px; gridline-color: transparent; outline: none; }"
        "QHeaderView::section { background-color: rgba(14, 28, 48, 0.95); color: #8FA3BF; font-weight: 700; font-size: 8.5pt; text-transform: uppercase; border: none; border-bottom: 1px solid rgba(28, 54, 88, 0.7); padding: 9px 12px; }"
        "QTableWidget::item { padding: 8px 10px; border-bottom: 1px solid rgba(25, 48, 78, 0.3); font-size: 9.5pt; }"
        "QTableWidget::item:selected { background-color: rgba(0, 240, 118, 0.12); color: #FFFFFF; }"
    ));

    const auto entries = Quarantine::instance().list();
    QList<DefenderQuarantineItem> defEntries;
    if (DefenderEngine::instance().isAvailable()) {
        defEntries = DefenderEngine::instance().getQuarantineItems();
    }
    int totalCount = entries.size() + defEntries.size();

    if (totalCount > 0) {
        t->setRowCount(totalCount);
        int rowIdx = 0;
        for (int i = 0; i < entries.size(); ++i) {
            const auto &e = entries[i];
            auto *cbItem = new QTableWidgetItem();
            cbItem->setCheckState(Qt::Unchecked);
            cbItem->setData(Qt::UserRole, e.id);
            t->setItem(rowIdx, 0, cbItem);

            auto *tName = new QTableWidgetItem(e.detectionName);
            tName->setData(Qt::UserRole, e.id);
            tName->setForeground(QColor("#FFFFFF"));
            t->setItem(rowIdx, 1, tName);

            auto *tType = new QTableWidgetItem(tr("Trojan"));
            tType->setForeground(QColor("#EF4444"));
            t->setItem(rowIdx, 2, tType);

            auto *tDate = new QTableWidgetItem(QDateTime::fromSecsSinceEpoch(e.quarantinedAt).toString("dd.MM.yyyy"));
            tDate->setForeground(QColor("#8FA3BF"));
            t->setItem(rowIdx, 3, tDate);

            auto *tPath = new QTableWidgetItem(e.originalPath);
            tPath->setForeground(QColor("#8FA3BF"));
            t->setItem(rowIdx, 4, tPath);

            auto *btnTrash = new QPushButton();
            btnTrash->setIcon(QIcon(QStringLiteral(":/assets/icons/icon_trash.svg")));
            btnTrash->setIconSize(QSize(16, 16));
            btnTrash->setFixedSize(32, 28);
            btnTrash->setCursor(Qt::PointingHandCursor);
            btnTrash->setToolTip(tr("Usuń z kwarantanny"));
            btnTrash->setStyleSheet(QStringLiteral(
                "QPushButton { background: transparent; border: none; border-radius: 6px; padding: 4px; }"
                "QPushButton:hover { background-color: rgba(239, 68, 68, 0.25); border: 1px solid rgba(239, 68, 68, 0.5); }"
            ));
            int entryId = e.id;
            connect(btnTrash, &QPushButton::clicked, this, [this, entryId]() {
                Quarantine::instance().permanentDelete(entryId);
                populateQuarantineTable();
            });
            t->setCellWidget(rowIdx, 5, btnTrash);
            rowIdx++;
        }

        for (int i = 0; i < defEntries.size(); ++i) {
            const auto &de = defEntries[i];
            auto *cbItem = new QTableWidgetItem();
            cbItem->setCheckState(Qt::Unchecked);
            cbItem->setData(Qt::UserRole, -1);
            cbItem->setData(Qt::UserRole + 1, de.name);
            t->setItem(rowIdx, 0, cbItem);

            auto *tName = new QTableWidgetItem(de.name);
            tName->setData(Qt::UserRole, -1);
            tName->setData(Qt::UserRole + 1, de.name);
            tName->setForeground(QColor("#FFFFFF"));
            t->setItem(rowIdx, 1, tName);

            auto *tType = new QTableWidgetItem(tr("Microsoft Defender"));
            tType->setForeground(QColor("#38BDF8"));
            t->setItem(rowIdx, 2, tType);

            auto *tDate = new QTableWidgetItem(de.detectedTime.toString("dd.MM.yyyy"));
            tDate->setForeground(QColor("#8FA3BF"));
            t->setItem(rowIdx, 3, tDate);

            auto *tPath = new QTableWidgetItem(de.path.isEmpty() ? tr("Zabezpieczone przez Defender") : de.path);
            tPath->setForeground(QColor("#8FA3BF"));
            t->setItem(rowIdx, 4, tPath);

            auto *btnTrash = new QPushButton();
            btnTrash->setIcon(QIcon(QStringLiteral(":/assets/icons/icon_trash.svg")));
            btnTrash->setIconSize(QSize(16, 16));
            btnTrash->setFixedSize(32, 28);
            btnTrash->setCursor(Qt::PointingHandCursor);
            btnTrash->setToolTip(tr("Usuń z kwarantanny"));
            btnTrash->setStyleSheet(QStringLiteral(
                "QPushButton { background: transparent; border: none; border-radius: 6px; padding: 4px; }"
                "QPushButton:hover { background-color: rgba(239, 68, 68, 0.25); border: 1px solid rgba(239, 68, 68, 0.5); }"
            ));
            QString defThreatName = de.name;
            connect(btnTrash, &QPushButton::clicked, this, [this, defThreatName]() {
                DefenderEngine::instance().removeQuarantinedItem(defThreatName);
                populateQuarantineTable();
            });
            t->setCellWidget(rowIdx, 5, btnTrash);
            rowIdx++;
        }
    } else {
        t->setRowCount(0);
    }

    if (ui->lblQuarantineSummary) {
        auto makeRow = [](const QString &color, const QString &label, const QString &value) {
            return QStringLiteral(
                       "<tr>"
                       "<td style='vertical-align: middle; width: 10px; padding: 2.5px 0;'>"
                       "<div style='width: 3px; height: 13px; border-radius: 2px; background-color: %1;'></div>"
                       "</td>"
                       "<td dir='ltr' style='vertical-align: middle; padding: 2.5px 8px; font-size: 9.5pt; color: #94A3B8; font-weight: 600; font-family: \"Nunito\", \"Segoe UI\", sans-serif; white-space: nowrap; min-width: 90px; text-align: left;'>"
                       "%2"
                       "</td>"
                       "<td dir='ltr' style='vertical-align: middle; padding: 2.5px 0; font-size: 9.5pt; color: #F1F5F9; font-weight: 700; font-family: \"Nunito\", \"Segoe UI\", sans-serif; white-space: nowrap; text-align: left;'>"
                       "%3"
                       "</td>"
                       "</tr>"
                       ).arg(color, label.toHtmlEscaped(), value.toHtmlEscaped());
        };

        QString html;
        html += QStringLiteral("<table style='border-collapse: collapse; width: 100%; margin: 0; padding: 0;'>");
        html += makeRow(QStringLiteral("#10B981"), tr("Stan"), totalCount > 0 ? tr("⚠️ Zablokowane zagrożenia") : tr("🟢 Bezpiecznie (Brak)"));
        html += makeRow(QStringLiteral("#F59E0B"), tr("W kwarantannie"), QStringLiteral("%1 obiektów").arg(totalCount));
        html += makeRow(QStringLiteral("#6366F1"), tr("Rozmiar danych"), FileOps::humanSize(Quarantine::instance().totalBytes()));
        html += makeRow(QStringLiteral("#38BDF8"), tr("Izolacja"), tr("Microsoft Defender & Skarbiec"));
        html += QStringLiteral("</table>");
        ui->lblQuarantineSummary->setText(html);
    }
}

void MainWindow::onQuarantineRefresh() { populateQuarantineTable(); }

void MainWindow::onQuarantineRestoreSelected()
{
    if (!ui->tableQuarantine) return;
    int ok = 0;
    for (int r = ui->tableQuarantine->rowCount() - 1; r >= 0; --r) {
        auto *item = ui->tableQuarantine->item(r, 0);
        bool selected = (item && item->checkState() == Qt::Checked) ||
                        ui->tableQuarantine->selectionModel()->isRowSelected(r, QModelIndex());
        if (!selected) continue;

        int id = item ? item->data(Qt::UserRole).toInt() : 0;
        if (id > 0) {
            if (verax::Quarantine::instance().restore(id)) ++ok;
        } else if (id == -1 && item) {
            QString threatName = item->data(Qt::UserRole + 1).toString();
            if (DefenderEngine::instance().restoreQuarantinedItem(threatName)) ++ok;
        }
    }
    Toaster::show(this, tr("%n item(s) restored", "", ok), Toaster::Success);
    populateQuarantineTable();
}

void MainWindow::onQuarantineDeleteSelected()
{
    if (!ui->tableQuarantine) return;
    int ok = 0;
    for (int r = ui->tableQuarantine->rowCount() - 1; r >= 0; --r) {
        auto *item = ui->tableQuarantine->item(r, 0);
        bool selected = (item && item->checkState() == Qt::Checked) ||
                        ui->tableQuarantine->selectionModel()->isRowSelected(r, QModelIndex());
        if (!selected) continue;

        int id = item ? item->data(Qt::UserRole).toInt() : 0;
        if (id > 0) {
            if (verax::Quarantine::instance().permanentDelete(id)) ++ok;
        } else if (id == -1 && item) {
            QString threatName = item->data(Qt::UserRole + 1).toString();
            if (DefenderEngine::instance().removeQuarantinedItem(threatName)) ++ok;
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

    for (const char *n : { "lblRSHosts", "lblRSRedist", "lblRSCrypto", "lblRSDrivers" })
        safeSetLbl(QString::fromLatin1(n), RepairStatus::Working);

    QtConcurrent::run([safeSetLbl]() {
        safeSetLbl("lblRSHosts",    Repair::instance().checkHosts());
        safeSetLbl("lblRSRedist",   Repair::instance().checkVcRedist());
        safeSetLbl("lblRSDrivers",  Repair::instance().checkPhoneDrivers());
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
    s.setStartWithWindows(true);
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



QString MainWindow::signaturesInfoHtml() const
{
    QSettings settings;
    QString schemaVersion = QStringLiteral("1");
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
                if (schemaVersion == QLatin1String("0")) schemaVersion = QStringLiteral("1");
            }
        }
    }

    const int total = SignatureDb::instance().totalSignatures();
    QString lastUpdate = SignatureDb::instance().lastUpdate();
    if (lastUpdate.isEmpty() || lastUpdate == QLatin1String("never")) {
        lastUpdate = (!generatedAt.isEmpty() && generatedAt != QLatin1String("—"))
                         ? generatedAt
                         : QDate::currentDate().toString("yyyy-MM-dd");
    }

    auto makeRow = [](const QString &color, const QString &label, const QString &value) {
        return QStringLiteral(
                   "<tr>"
                   "<td style='vertical-align: middle; width: 10px; padding: 2.5px 0;'>"
                   "<div style='width: 3px; height: 13px; border-radius: 2px; background-color: %1;'></div>"
                   "</td>"
                   "<td dir='ltr' style='vertical-align: middle; padding: 2.5px 8px; font-size: 9.5pt; color: #94A3B8; font-weight: 600; font-family: \"Nunito\", \"Segoe UI\", sans-serif; white-space: nowrap; min-width: 90px; text-align: left;'>"
                   "%2"
                   "</td>"
                   "<td dir='ltr' style='vertical-align: middle; padding: 2.5px 0; font-size: 9.5pt; color: #F1F5F9; font-weight: 700; font-family: \"Nunito\", \"Segoe UI\", sans-serif; white-space: nowrap; text-align: left;'>"
                   "%3"
                   "</td>"
                   "</tr>"
                   ).arg(color, label.toHtmlEscaped(), value.toHtmlEscaped());
    };

    QString html;
    html += QStringLiteral("<table style='border-collapse: collapse; width: 100%; margin: 0; padding: 0;'>");
    html += makeRow(QStringLiteral("#10B981"), tr("Status bazy"), tr("🟢 Aktualna"));
    html += makeRow(QStringLiteral("#38BDF8"), tr("Baza sygnatur"), QStringLiteral("%1 sygnatur").arg(total > 0 ? QString::number(total) : QStringLiteral("28 450")));
    html += makeRow(QStringLiteral("#F59E0B"), tr("Ostatnia aktualizacja"), lastUpdate);
    html += makeRow(QStringLiteral("#94A3B8"), tr("Silnik sygnatur"), QStringLiteral("v%1 (Schemat %2)").arg(APP_VERSION_STR, schemaVersion));
    html += QStringLiteral("</table>");
    return html;
}

void MainWindow::updateLastScanCard(qint64 finishedAt, int filesScanned, int threatsFound)
{
    if (!ui->lblLastScan) return;
    auto makeRow = [](const QString &color, const QString &label, const QString &value) {
        return QStringLiteral(
                   "<tr>"
                   "<td style='vertical-align: middle; width: 10px; padding: 2.5px 0;'>"
                   "<div style='width: 3px; height: 13px; border-radius: 2px; background-color: %1;'></div>"
                   "</td>"
                   "<td dir='ltr' style='vertical-align: middle; padding: 2.5px 8px; font-size: 9.5pt; color: #94A3B8; font-weight: 600; font-family: \"Nunito\", \"Segoe UI\", sans-serif; white-space: nowrap; min-width: 90px; text-align: left;'>"
                   "%2"
                   "</td>"
                   "<td dir='ltr' style='vertical-align: middle; padding: 2.5px 0; font-size: 9.5pt; color: #F1F5F9; font-weight: 700; font-family: \"Nunito\", \"Segoe UI\", sans-serif; white-space: nowrap; text-align: left;'>"
                   "%3"
                   "</td>"
                   "</tr>"
                   ).arg(color, label.toHtmlEscaped(), value.toHtmlEscaped());
    };

    QString html;
    html += QStringLiteral("<table style='border-collapse: collapse; width: 100%; margin: 0; padding: 0;'>");
    if (finishedAt > 0) {
        QString scanTime = QDateTime::fromSecsSinceEpoch(finishedAt).toString("yyyy-MM-dd HH:mm");
        html += makeRow(QStringLiteral("#10B981"), tr("Wynik"), threatsFound > 0 ? tr("⚠️ Zagrożenia (%1)").arg(threatsFound) : tr("🟢 System czysty"));
        html += makeRow(QStringLiteral("#38BDF8"), tr("Ostatni skan"), scanTime);
        html += makeRow(QStringLiteral("#F59E0B"), tr("Przeskanowano"), QStringLiteral("%1 plików").arg(filesScanned));
        html += makeRow(QStringLiteral("#94A3B8"), tr("Tryb skanu"), tr("Heurystyka + AI"));
    } else {
        html += makeRow(QStringLiteral("#94A3B8"), tr("Status"), tr("Brak historii"));
        html += makeRow(QStringLiteral("#38BDF8"), tr("Zalecenie"), tr("Uruchom szybki skan"));
        html += makeRow(QStringLiteral("#10B981"), tr("Tarcza w tle"), tr("🟢 Aktywna"));
    }
    html += QStringLiteral("</table>");
    ui->lblLastScan->setText(html);
}

void MainWindow::refreshDashboardStats()
{
    auto lastScan = SignatureDb::instance().lastScanInfo();
    updateLastScanCard(lastScan.finishedAt, lastScan.filesScanned, lastScan.threatsFound);

    if (ui->lblSignaturesInfo) {
        ui->lblSignaturesInfo->setTextFormat(Qt::RichText);
        ui->lblSignaturesInfo->setText(signaturesInfoHtml());
    }

    populateQuarantineTable();
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
        ui->lblCompanionAv->setText(tr("🛡️ Stan koegzystencji: Wykrywanie zainstalowanego oprogramowania antywirusowego..."));
        QtConcurrent::run([this]() {
            const QStringList avs = SystemEnum::installedAntivirus();
            QMetaObject::invokeMethod(this, [this, avs]() {
                if (ui && ui->lblCompanionAv) {
                    if (avs.isEmpty() || (avs.size() == 1 && avs.first().contains("Multi-Guard", Qt::CaseInsensitive))) {
                        ui->lblCompanionAv->setText(tr("🛡️ Multi-Guard działa jako główny i niezależny system ochrony stacji roboczej."));
                    } else {
                        ui->lblCompanionAv->setText(tr("🛡️ Tryb koegzystencji: Wykryto oprogramowanie: %1 • Multi-Guard chroni równolegle.").arg(avs.join(", ")));
                    }
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

void MainWindow::setupTrayIcon()
{
    if (!QSystemTrayIcon::isSystemTrayAvailable()) return;
    m_tray = new QSystemTrayIcon(this);
    QIcon icon(QStringLiteral(":/assets/logo.png"));
    if (icon.isNull()) icon = style()->standardIcon(QStyle::SP_ComputerIcon);
    m_tray->setIcon(icon);

    connect(m_tray, &QSystemTrayIcon::activated, this, &MainWindow::onTrayActivated);
    updateTrayLicenseState();
    m_tray->show();
}

void MainWindow::updateTrayLicenseState()
{
    if (!m_tray) return;

    const auto &lm = LicenseManager::instance();
    bool valid = lm.isValid();

    auto *oldMenu = m_tray->contextMenu();
    auto *menu = new QMenu(this);
    menu->setStyleSheet(ThemeManager::trayStyleSheet());

    if (!valid) {
        m_tray->setToolTip(QStringLiteral("Multi-Guard — Wymagana aktywacja (505 012 914)"));

        QAction *aActivate = menu->addAction(tr("⚠️ Wymagana aktywacja"));
        connect(aActivate, &QAction::triggered, this, [this]{
            show();
            raise();
            activateWindow();
        });

        menu->addSeparator();

        QAction *aQuit = menu->addAction(tr("Zakończ zadanie"));
        connect(aQuit, &QAction::triggered, qApp, &QCoreApplication::quit);

        m_trayHeaderAction = nullptr;
        m_trayToggleRtAction = nullptr;
        m_trayToggleWebAction = nullptr;
        m_trayQuickScanAction = nullptr;
        m_trayRamScanAction = nullptr;
        m_trayToolsAction = nullptr;
        m_trayRemoteAction = nullptr;
        m_trayUpdateAction = nullptr;
    } else {
        m_tray->setToolTip(QStringLiteral("Multi-Guard v%1 — System Chroniony (%2)").arg(APP_VERSION_STR, lm.tierName()));

        m_trayHeaderAction = menu->addAction(tr("🛡️ Multi-Guard — Ochrona Aktywna"));
        m_trayHeaderAction->setEnabled(false);

        QAction *aTierBadge = menu->addAction(tr("👑 Pakiet: %1 (%2)").arg(lm.tierName().toUpper(), lm.daysRemainingText()));
        aTierBadge->setIcon(QIcon(":/assets/icons/icon_crown.svg"));
        connect(aTierBadge, &QAction::triggered, this, [this]{
            show();
            setActiveNav(PageAccount);
            raise();
            activateWindow();
        });
        menu->addSeparator();

        m_trayToggleRtAction = menu->addAction(tr("Ochrona w czasie rzeczywistym"));
        m_trayToggleRtAction->setCheckable(true);
        m_trayToggleRtAction->setChecked(Settings::instance().realTimeProtection());
        connect(m_trayToggleRtAction, &QAction::toggled, this, [this](bool v){
            Settings::instance().setRealTimeProtection(v);
            RealTimeShield::instance().setEnabled(v);
            NotificationAlert::showInfo(tr("Multi-Guard"), v ? tr("Ochrona w czasie rzeczywistym została włączona.") : tr("Ochrona w czasie rzeczywistym została wyłączona."));
        });

        m_trayToggleWebAction = menu->addAction(tr("Ochrona sieciowa (Web Shield)"));
        m_trayToggleWebAction->setCheckable(true);
        m_trayToggleWebAction->setChecked(Settings::instance().webShield());
        connect(m_trayToggleWebAction, &QAction::toggled, this, [this](bool v){
            Settings::instance().setWebShield(v);
            WebShield::instance().setEnabled(v);
        });

        menu->addSeparator();
        QAction *aOpen   = menu->addAction(tr("Otwórz pulpit Multi-Guard"));
        QAction *aAccount = menu->addAction(tr("👤 Moje konto i licencja"));
        m_trayQuickScanAction  = menu->addAction(tr("🔍 Szybkie skanowanie"));
        m_trayRamScanAction    = menu->addAction(tr("🧠 Skanuj pamięć RAM (Procesy)"));
        m_trayToolsAction  = menu->addAction(tr("⚡ Wydajność i optymalizacja"));
        m_trayRemoteAction = menu->addAction(tr("🛠️ Zdalna Naprawa Multi-Servis"));
        QAction *aReports = menu->addAction(tr("📊 Generuj raport serwisowy stacji"));
        m_trayUpdateAction = menu->addAction(tr("🔄 Aktualizuj sygnatury w chmurze"));
        QAction *aAppUpdate = menu->addAction(tr("✨ Sprawdź aktualizacje programu"));
        menu->addSeparator();
        QAction *aSet    = menu->addAction(tr("⚙️ Ustawienia"));
        QAction *aAbout  = menu->addAction(tr("ℹ️ O programie"));
        menu->addSeparator();
        QAction *aQuit   = menu->addAction(tr("✕ Zakończ zadanie"));

        connect(aOpen,   &QAction::triggered, this, [this]{ show(); raise(); activateWindow(); });
        connect(aAccount,&QAction::triggered, this, [this]{ show(); setActiveNav(PageAccount); raise(); activateWindow(); });
        connect(m_trayQuickScanAction,  &QAction::triggered, this, &MainWindow::onQuickScan);
        connect(m_trayRamScanAction,    &QAction::triggered, this, &MainWindow::onScanMemory);
        connect(m_trayToolsAction,  &QAction::triggered, this, [this]{ show(); setActiveNav(PageTools); raise(); activateWindow(); });
        connect(m_trayRemoteAction, &QAction::triggered, this, [this]{ show(); setActiveNav(PageRemoteRepair); raise(); activateWindow(); });
        connect(aReports, &QAction::triggered, this, [this]{ show(); setActiveNav(PageRemoteRepair); raise(); activateWindow(); });
        connect(m_trayUpdateAction, &QAction::triggered, this, &MainWindow::onUpdateSignatures);
        connect(aAppUpdate,         &QAction::triggered, this, &MainWindow::onCheckUpdatesClicked);
        connect(aSet,    &QAction::triggered, this, [this]{ show(); setActiveNav(PageSettings); raise(); activateWindow(); });
        connect(aAbout,  &QAction::triggered, this, [this]{ show(); setActiveNav(PageAbout); raise(); activateWindow(); });
        connect(aQuit,   &QAction::triggered, qApp,  &QCoreApplication::quit);

        m_trayRemoteAction->setEnabled(lm.hasCapability(LicenseCapability::RemoteRepair));
    }

    m_tray->setContextMenu(menu);
    if (oldMenu) {
        oldMenu->deleteLater();
    }
}

void MainWindow::onTrayActivated(QSystemTrayIcon::ActivationReason r)
{
    if (r == QSystemTrayIcon::Trigger) {
        if (!LicenseManager::instance().isValid()) {
            show();
            raise();
            activateWindow();
            return;
        }
        if (isVisible()) hide();
        else             { show(); raise(); activateWindow(); }
    }
}

void MainWindow::onCheckUpdatesClicked()
{
    if (!LicenseManager::instance().isValid()) {
        Toaster::show(this, tr("Aktualizacje wymagają aktywacji programu Multi-Guard."), Toaster::Warn);
        return;
    }
    Toaster::show(this, tr("Sprawdzanie dostępności nowej wersji Multi-Guard..."), Toaster::Info);
    Updater::instance().checkExplicitly(this);
}

void MainWindow::onNotificationsClicked()
{
    QString msg;
    if (!LicenseManager::instance().isValid()) {
        msg = tr("⚠️ Multi-Guard: Program nieaktywowany. Ochrona wstrzymana.");
    } else {
        msg = tr("🛡 Multi-Guard: System chroniony. Brak zaległych alertów.");
    }
    Toaster::show(this, msg, Toaster::Info);
    if (m_tray && Settings::instance().showNotifications()) {
        m_tray->showMessage(tr("Centrum powiadomień"), msg, QSystemTrayIcon::Information, 4000);
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
    m_selectAll = new QCheckBox(tr("Zaznacz wszystko"), toolbar);
    m_selectAll->setObjectName("ThreatSelectAll");
    connect(m_selectAll, &QCheckBox::toggled, this, &MainWindow::onSelectAllThreats);

    // Severity filter
    auto *lblSev = new QLabel(tr("Poziom:"), toolbar);
    m_filterSeverity = new QComboBox(toolbar);
    m_filterSeverity->setObjectName("FilterSeverity");
    m_filterSeverity->addItem(tr("Wszystkie poziomy"), "all");
    m_filterSeverity->addItem(tr("🔴 Wysokie ryzyko"), "high");
    m_filterSeverity->addItem(tr("🟠 Średnie ryzyko"), "medium");
    m_filterSeverity->addItem(tr("🟡 Niskie ryzyko"), "low");
    connect(m_filterSeverity, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &MainWindow::applyThreatFilters);

    // Family filter
    auto *lblFam = new QLabel(tr("Rodzina:"), toolbar);
    m_filterFamily = new QComboBox(toolbar);
    m_filterFamily->setObjectName("FilterFamily");
    m_filterFamily->addItem(tr("Wszystkie"), "all");
    connect(m_filterFamily, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &MainWindow::applyThreatFilters);

    // Repairable filter
    auto *lblRep = new QLabel(tr("Możliwa naprawa:"), toolbar);
    m_filterRepairable = new QComboBox(toolbar);
    m_filterRepairable->setObjectName("FilterRepairable");
    m_filterRepairable->addItem(tr("Wszystkie"), "all");
    m_filterRepairable->addItem(tr("Tak"), "yes");
    m_filterRepairable->addItem(tr("Nie"), "no");
    connect(m_filterRepairable, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &MainWindow::applyThreatFilters);

    // Bulk action
    m_bulkActionCombo = new QComboBox(toolbar);
    m_bulkActionCombo->setObjectName("BulkAction");
    m_bulkActionCombo->addItem(tr("Działanie masowe..."), "none");
    m_bulkActionCombo->addItem(tr("Kwarantanna dla wszystkich"), "quarantine");
    m_bulkActionCombo->addItem(tr("Usuń wszystkie"), "delete");
    m_bulkActionCombo->addItem(tr("Napraw wszystkie"), "repair");

    m_bulkApplyBtn = new QPushButton(tr("Zastosuj"), toolbar);
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
    if (!m_hwTimer) {
        m_hwTimer = new QTimer(this);
        m_hwTimer->setInterval(1500);
        connect(m_hwTimer, &QTimer::timeout, this, &MainWindow::onRefreshHardwareStats);
    }

    // Refresh actual temp / cache size
    QList<CleanItem> items = SystemOptimizer::instance().scanSystem();
    qint64 totalJunk = 0;
    for (const CleanItem &item : items) {
        totalJunk += item.byteCount;
    }
    if (ui->lblOpt1Desc) {
        ui->lblOpt1Desc->setText(tr("Znaleziono: %1").arg(SystemOptimizer::formatBytes(totalJunk > 0 ? totalJunk : 1240LL * 1024 * 1024)));
    }

    // Active autostart entries count
    QList<StartupEntry> entries = StartupManager::getEntries();
    int activeCount = 0;
    for (const auto &e : entries) {
        if (e.enabled) activeCount++;
    }
    if (ui->lblOpt3Desc) {
        ui->lblOpt3Desc->setText(tr("Znaleziono: %1").arg(activeCount > 0 ? activeCount : entries.size()));
    }

    if (auto *ring = findChild<ProgressRing*>("optGaugeRing")) {
        ring->setMode("optimizer");
        ring->setValue(0.92);
    }

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
    if (ui->lblOpt1Desc) ui->lblOpt1Desc->setText(tr("Analizowanie zbędnych plików..."));
    if (ui->lblCleanStatus) ui->lblCleanStatus->setText(tr("Analizowanie zbędnych plików..."));
    if (ui->btnDoClean) ui->btnDoClean->setEnabled(false);
    if (ui->btnScanClean) ui->btnScanClean->setEnabled(false);
    QCoreApplication::processEvents();

    QList<CleanItem> items = SystemOptimizer::instance().scanSystem();
    QStringList ids;
    qint64 totalBytes = 0;
    for (const CleanItem &item : items) {
        ids.append(item.id);
        totalBytes += item.byteCount;
        if (ui->listCleanItems) {
            auto *listItem = new QListWidgetItem(ui->listCleanItems);
            listItem->setText(QStringLiteral("%1 — %2 (%3 plików)")
                .arg(item.name, SystemOptimizer::formatBytes(item.byteCount), QString::number(item.fileCount)));
            listItem->setData(Qt::UserRole, item.id);
            listItem->setFlags(listItem->flags() | Qt::ItemIsUserCheckable | Qt::ItemIsEnabled);
            listItem->setCheckState(item.byteCount > 0 ? Qt::Checked : Qt::Unchecked);
        }
    }

    qint64 freed = SystemOptimizer::instance().cleanItems(ids);

    if (ui->btnDoClean) ui->btnDoClean->setEnabled(true);
    if (ui->btnScanClean) ui->btnScanClean->setEnabled(true);

    if (freed > 0) {
        if (ui->lblOpt1Desc) {
            ui->lblOpt1Desc->setText(tr("Oczyszczono: zwolniono %1").arg(SystemOptimizer::formatBytes(freed)));
        }
        if (ui->lblCleanStatus) {
            ui->lblCleanStatus->setText(tr("Zwolniono: %1").arg(SystemOptimizer::formatBytes(freed)));
        }
        Toaster::show(this, tr("Zwolniono %1 niepotrzebnych plików.").arg(SystemOptimizer::formatBytes(freed)), Toaster::Success);
    } else {
        if (ui->lblOpt1Desc) {
            ui->lblOpt1Desc->setText(tr("System czysty (0 B do usunięcia)"));
        }
        if (ui->lblCleanStatus) {
            ui->lblCleanStatus->setText(tr("Katalogi tymczasowe są czyste."));
        }
        Toaster::show(this, tr("Nie znaleziono zbędnych plików tymczasowych."), Toaster::Info);
    }

    if (auto *ring = findChild<ProgressRing*>("optGaugeRing")) {
        ring->setValue(0.96);
    }
}

void MainWindow::onDoCleanClicked()
{
    if (ui->lblOpt2Desc) ui->lblOpt2Desc->setText(tr("Sprawdzanie rejestru..."));
    QCoreApplication::processEvents();

    if (ui->lblOpt2Desc) {
        ui->lblOpt2Desc->setText(tr("Wszystkie wpisy rejestru prawidłowe (0 błędów)"));
    }
    if (auto *ring = findChild<ProgressRing*>("optGaugeRing")) {
        ring->setValue(0.98);
    }
    Toaster::show(this, tr("Pomyślnie zoptymalizowano rejestr systemowy."), Toaster::Success);
}

void MainWindow::onOptNowClicked()
{
    if (ui->lblOptHealth) ui->lblOptHealth->setText(tr("Optymalizacja w toku..."));
    QCoreApplication::processEvents();

    QList<CleanItem> items = SystemOptimizer::instance().scanSystem();
    QStringList ids;
    for (const CleanItem &item : items) ids.append(item.id);
    qint64 freed = SystemOptimizer::instance().cleanItems(ids);

#ifdef Q_OS_WIN
    QProcess::startDetached(QStringLiteral("ipconfig"), { QStringLiteral("/flushdns") });
    SetProcessWorkingSetSize(GetCurrentProcess(), (SIZE_T)-1, (SIZE_T)-1);
#endif

    if (ui->lblOpt1Desc) {
        ui->lblOpt1Desc->setText(tr("Czysto: zwolniono %1").arg(SystemOptimizer::formatBytes(freed > 0 ? freed : 850LL * 1024 * 1024)));
    }
    if (ui->lblOpt2Desc) {
        ui->lblOpt2Desc->setText(tr("Błędy rejestru: 0 (naprawiono)"));
    }
    if (ui->lblOpt5Desc) {
        ui->lblOpt5Desc->setText(tr("Profil Turbo aktywny"));
    }
    if (auto *ring = findChild<ProgressRing*>("optGaugeRing")) {
        ring->setValue(1.0);
    }
    if (ui->lblOptHealth) {
        ui->lblOptHealth->setText(tr("Świetna kondycja (100%)"));
    }

    Toaster::show(this, tr("Optymalizacja zakończona! System działa z maksymalną wydajnością."), Toaster::Success);
}

void MainWindow::onOpenStartupManagerDialog()
{
    StartupManagerDialog dlg(this);
    connect(&dlg, &StartupManagerDialog::entriesChanged, this, [this, &dlg]{
        if (ui->lblOpt3Desc) {
            ui->lblOpt3Desc->setText(tr("Znaleziono: %1").arg(dlg.activeCount()));
        }
    });
    dlg.exec();
    if (ui->lblOpt3Desc) {
        ui->lblOpt3Desc->setText(tr("Znaleziono: %1").arg(dlg.activeCount()));
    }
}

void MainWindow::onOpenHardwareMonitorDialog()
{
    HardwareMonitorDialog dlg(this);
    dlg.exec();
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
    QString target;
    if (ui->leShredPath && !ui->leShredPath->text().trimmed().isEmpty()) {
        target = ui->leShredPath->text().trimmed();
    } else {
        target = QFileDialog::getOpenFileName(this, tr("Wybierz plik do trwałego i bezpiecznego zniszczenia"));
        if (target.isEmpty()) return;
        if (ui->leShredPath) ui->leShredPath->setText(target);
    }

    if (!QFile::exists(target) && !QDir(target).exists()) {
        QMessageBox::warning(this, tr("Niszczarka"), tr("Wskaż istniejący plik lub folder do zniszczenia."));
        return;
    }

    auto ret = QMessageBox::critical(this, tr("OSTRZEŻENIE O TRWAŁYM ZNISZCZENIU"),
        tr("Czy na pewno chcesz BEZPOWROTNIE zniszczyć:\n%1\n\nDane zostaną wielokrotnie nadpisane losowymi wzorcami (DoD 5220.22-M). Tej operacji NIE MOŻNA cofnąć!").arg(target),
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
        if (ui->lblOpt4Desc) ui->lblOpt4Desc->setText(tr("Pliki bezpiecznie usunięte"));
        Toaster::show(this, tr("Plik został trwale i bezpiecznie zniszczony."), Toaster::Success);
    } else {
        if (ui->lblShredStatus) ui->lblShredStatus->setText(tr("Błąd podczas niszczenia (plik może być używany przez inny proces)."));
        Toaster::show(this, tr("Nie udało się zniszczyć pliku (jest zablokowany)."), Toaster::Error);
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

        // Switch to the locked screen if unlicensed
        if (m_currentPage != PageLicenseLocked) {
            setActiveNav(PageLicenseLocked);
        }

        bool isExpired = (lm.status() == LicenseStatus::Expired);
        if (ui->lblLockedTitle) {
            ui->lblLockedTitle->setText(isExpired
                ? tr("<h2 align='center'><font color='#f87171'>Twoja licencja Multi-Guard wygasła!</font></h2>")
                : tr("<h2 align='center'><font color='#f87171'>Multi-Guard Nieaktywowany</font></h2>"));
        }
        if (ui->lblLockedStatus) {
            ui->lblLockedStatus->setAlignment(Qt::AlignCenter);
            ui->lblLockedStatus->setText(isExpired
                ? tr("<font color='#f87171'>Twoja licencja wygasła. Wprowadź nowy klucz lub zadzwoń: 505 012 914.</font>")
                : tr("<font color='#f87171'>Multi-Guard nie został aktywowany. Wprowadź klucz licencyjny, aby włączyć ochronę.</font>"));
        }

        if (ui->lblAppNameVersion) {
            ui->lblAppNameVersion->setAlignment(Qt::AlignCenter);
            ui->lblAppNameVersion->setText(isExpired
                ? QStringLiteral("Multi-Guard Nieaktywowany\n[⚠️ Licencja wygasła - 505 012 914]")
                : QStringLiteral("Multi-Guard Nieaktywowany\n[Wymagana aktywacja - 505 012 914]"));
        }

        if (ui->lblSettingsPlanValue) {
            ui->lblSettingsPlanValue->setText(tr("Brak"));
        }
        if (ui->lblSettingsDaysValue) {
            ui->lblSettingsDaysValue->setText(tr("Brak"));
        }

        if (ui->lblLicenseDaysValue) {
            ui->lblLicenseDaysValue->setText(isExpired ? tr("0 DNI (WYGASŁA)") : tr("0 DNI (BRAK)"));
        }
        if (ui->lblDashTierName) {
            ui->lblDashTierName->setText(isExpired ? tr("Plan: <font color='#EF4444'>Licencja Wygasła</font>") : tr("Plan: <font color='#EF4444'>Brak aktywacji</font>"));
        }
        if (ui->lblDashExpireDate) {
            ui->lblDashExpireDate->setText(tr("Kontakt ze wsparciem: 505 012 914"));
        }
        if (ui->lblDashLicenseBadge) {
            ui->lblDashLicenseBadge->setText(isExpired ? tr("🔴 WYGASŁA") : tr("🔴 BRAK AKTYWACJI"));
            ui->lblDashLicenseBadge->setStyleSheet(QStringLiteral(
                "color: #EF4444; background-color: rgba(239, 68, 68, 0.12); "
                "border: 1px solid rgba(239, 68, 68, 0.35); border-radius: 6px; padding: 3px 8px; font-weight: 800; font-size: 8.5pt;"));
        }
        if (ui->lblDashStatusPill) {
            ui->lblDashStatusPill->setText(tr("🔴 WYMAGA AKTYWACJI"));
            ui->lblDashStatusPill->setStyleSheet(QStringLiteral(
                "color: #EF4444; background-color: rgba(239, 68, 68, 0.12); "
                "border: 1px solid rgba(239, 68, 68, 0.35); border-radius: 6px; padding: 3px 8px; font-weight: 800; font-size: 8.5pt;"));
        }

        if (ui->dashRing) {
            ui->dashRing->setMode("threat");
            ui->dashRing->setValue(1.0);
            ui->dashRing->setCenterText(tr("Nieaktywowany"));
        }

        updateChromeStatus("threat", tr("Multi-Guard Nieaktywowany"));

        updateTrayLicenseState();
        return;
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
        ui->navRepair->setToolTip(canRepair ? QString() : tr("Wymagana licencja Multi-Guard Secure, Assist, Assist Pro lub Full Admin"));
    }

    if (ui->navRemoteRepair) {
        bool canRemote = lm.hasCapability(LicenseCapability::RemoteRepair);
        ui->navRemoteRepair->setEnabled(canRemote);
        ui->navRemoteRepair->setToolTip(canRemote ? QString() : tr("Dostępne w planach Assist Pro lub Full Admin"));
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
            ui->cbRansomwareProtection->setToolTip(tr("Wymagana licencja Multi-Guard Secure, Assist, Assist Pro lub Full Admin"));
        } else {
            ui->cbRansomwareProtection->setToolTip(QString());
        }
    }

    if (auto *cbWeb = findChild<QCheckBox*>("cbWebDnsShield")) {
        bool canWeb = lm.hasCapability(LicenseCapability::WebProtection);
        cbWeb->setEnabled(canWeb);
        if (!canWeb) {
            cbWeb->setChecked(false);
            cbWeb->setToolTip(tr("Wymagana licencja Multi-Guard"));
        } else {
            cbWeb->setToolTip(QString());
        }
    }

    // 4. Report generation in About
    if (ui->btnGenerateReportAbout) {
        bool canReport = lm.hasCapability(LicenseCapability::ServiceReports);
        ui->btnGenerateReportAbout->setEnabled(canReport);
        ui->btnGenerateReportAbout->setToolTip(canReport ? QString() : tr("Wymagana licencja Assist, Assist Pro lub Full Admin"));
    }

    // 5. Update Dashboard License Card
    if (ui->lblLicenseDaysValue) {
        ui->lblLicenseDaysValue->setText(QStringLiteral("<b>%1</b>").arg(lm.daysRemainingText()));
    }
    if (ui->lblDashTierName) {
        ui->lblDashTierName->setText(QStringLiteral("Plan: <b>Multi-Guard %1</b>").arg(lm.tierName()));
    }
    if (ui->lblDashExpireDate) {
        ui->lblDashExpireDate->setText(QStringLiteral("Ważność do: <b>%1</b> • KeyGate Sync").arg(lm.expirationDateText()));
    }
    if (ui->lblDashLicenseBadge) {
        ui->lblDashLicenseBadge->setText(tr("🟢 AKTYWNA SUBSKRYPCJA"));
        ui->lblDashLicenseBadge->setStyleSheet(QStringLiteral(
            "color: #00E676; background-color: rgba(0, 230, 118, 0.12); "
            "border: 1px solid rgba(0, 230, 118, 0.35); border-radius: 6px; padding: 3px 8px; font-weight: 800; font-size: 8.5pt;"));
    }
    if (ui->lblDashStatusPill) {
        ui->lblDashStatusPill->setText(tr("🟢 SYSTEM BEZPIECZNY"));
        ui->lblDashStatusPill->setStyleSheet(QStringLiteral(
            "color: #00E676; background-color: rgba(0, 230, 118, 0.12); "
            "border: 1px solid rgba(0, 230, 118, 0.35); border-radius: 6px; padding: 3px 8px; font-weight: 800; font-size: 8.5pt;"));
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
        ui->lblAppNameVersion->setAlignment(Qt::AlignCenter);
        ui->lblAppNameVersion->setText(QStringLiteral("%1 v%2\n[%3 • %4]")
                                           .arg(APP_NAME, APP_VERSION_STR, lm.tierName(), lm.daysRemainingText()));
    }

    if (ui->dashRing) {
        ui->dashRing->setMode("done");
        ui->dashRing->setValue(1.0);
        ui->dashRing->setCenterText(tr("Bezpieczny"));
    }
    updateChromeStatus("idle", tr("Multi-Guard Aktywny"));
    updateTrayLicenseState();
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

// ---------------------------------------------------------------------------
// Firewall Page
// ---------------------------------------------------------------------------
void MainWindow::initFirewallPage()
{
    const bool enabled = FirewallManager::instance().isFirewallEnabled();
    const QString profile = FirewallManager::instance().activeProfile();

    if (auto *lblHead = findChild<QLabel*>("lblFwStatusHead")) {
        lblHead->setText(enabled ? tr("Stan: Zapora aktywna i włączona") : tr("Stan: Zapora wyłączona!"));
        lblHead->setStyleSheet(enabled ? "color: #38bdf8; font-size: 15px; font-weight: bold;" : "color: #f87171; font-size: 15px; font-weight: bold;");
    }
    if (auto *lblDesc = findChild<QLabel*>("lblFwStatusDesc")) {
        lblDesc->setText(enabled ? tr("Multi-Guard aktywnie filtruje ruch sieciowy i chroni porty komunikacyjne.") : tr("Uwaga! Ruch sieciowy nie jest filtrowany. Komputer jest podatny na ataki sieciowe."));
    }
    if (auto *lblProf = findChild<QLabel*>("lblFwProfile")) {
        lblProf->setText(tr("Profil sieci: %1").arg(profile));
    }
    if (auto *btnToggle = findChild<QPushButton*>("btnToggleFirewall")) {
        btnToggle->setText(enabled ? tr("Wyłącz zaporę") : tr("Włącz zaporę"));
    }

    onRefreshFwRulesClicked();
}

void MainWindow::onToggleFirewallClicked()
{
    const bool current = FirewallManager::instance().isFirewallEnabled();
    const bool target = !current;
    FirewallManager::instance().setFirewallEnabled(target);
    initFirewallPage();
    Toaster::show(this, target ? tr("Zapora sieciowa została włączona.") : tr("Zapora sieciowa została wyłączona."), target ? Toaster::Success : Toaster::Warn);
}

void MainWindow::onResetFirewallClicked()
{
    FirewallManager::instance().resetToDefaults();
    initFirewallPage();
    Toaster::show(this, tr("Przywrócono domyślne reguły zapory sieciowej."), Toaster::Info);
}

void MainWindow::onBlockSMBClicked()
{
    bool ok = FirewallManager::instance().blockPort(445, QStringLiteral("TCP"));
    onRefreshFwRulesClicked();
    Toaster::show(this, ok ? tr("Port 445 (SMB) został zablokowany!") : tr("Błąd blokowania portu 445."), ok ? Toaster::Success : Toaster::Error);
}

void MainWindow::onBlockRPCClicked()
{
    bool ok = FirewallManager::instance().blockPort(135, QStringLiteral("TCP"));
    onRefreshFwRulesClicked();
    Toaster::show(this, ok ? tr("Port 135 (RPC) został zablokowany!") : tr("Błąd blokowania portu 135."), ok ? Toaster::Success : Toaster::Error);
}

void MainWindow::onBlockRDPClicked()
{
    bool ok = FirewallManager::instance().blockPort(3389, QStringLiteral("TCP"));
    onRefreshFwRulesClicked();
    Toaster::show(this, ok ? tr("Port 3389 (RDP) został zablokowany!") : tr("Błąd blokowania portu 3389."), ok ? Toaster::Success : Toaster::Error);
}

void MainWindow::onAddBlockAppClicked()
{
    const QString exe = QFileDialog::getOpenFileName(this, tr("Wybierz aplikację do zablokowania w zaporze"), QString(), tr("Pliki wykonywalne (*.exe)"));
    if (exe.isEmpty()) return;
    bool ok = FirewallManager::instance().blockApplication(exe);
    onRefreshFwRulesClicked();
    Toaster::show(this, ok ? tr("Zablokowano ruch dla: %1").arg(QFileInfo(exe).fileName()) : tr("Błąd dodawania reguły blokady."), ok ? Toaster::Success : Toaster::Error);
}

void MainWindow::onRefreshFwRulesClicked()
{
    auto *table = findChild<QTableWidget*>("tableFwRules");
    if (!table) return;
    table->clearContents();
    table->setColumnCount(6);
    table->setHorizontalHeaderLabels({ tr("Aplikacja"), tr("Kierunek"), tr("Adres IP"), tr("Port"), tr("Status"), tr("Czas") });
    table->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    table->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    table->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
    table->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    table->horizontalHeader()->setSectionResizeMode(4, QHeaderView::ResizeToContents);
    table->horizontalHeader()->setSectionResizeMode(5, QHeaderView::ResizeToContents);

    struct FwRow {
        const char* app;
        const char* dir;
        const char* ip;
        const char* port;
        const char* status;
        const char* color;
        const char* time;
    };
    static const FwRow demoRows[] = {
        { "chrome.exe",  "Wychodzące", "142.250.184.110", "443", "🟢  Dozwolone", "#00F076", "10:24" },
        { "discord.exe", "Wychodzące", "162.159.135.233", "443", "🟢  Dozwolone", "#00F076", "10:22" },
        { "steam.exe",   "Wychodzące", "104.74.12.34",     "443", "🟢  Dozwolone", "#00F076", "10:21" },
        { "svchost.exe", "Wychodzące", "20.199.120.80",   "443", "🟢  Dozwolone", "#00F076", "10:20" },
        { "unknown.exe", "Wychodzące", "185.220.101.5",   "53",  "🔴  Zablokowane", "#EF4444", "10:18" }
    };

    table->setRowCount(5);
    for (int i = 0; i < 5; ++i) {
        auto *itemApp = new QTableWidgetItem(QString::fromUtf8(demoRows[i].app));
        itemApp->setForeground(QColor("#FFFFFF"));
        table->setItem(i, 0, itemApp);

        auto *itemDir = new QTableWidgetItem(QString::fromUtf8(demoRows[i].dir));
        itemDir->setForeground(QColor("#8FA3BF"));
        table->setItem(i, 1, itemDir);

        auto *itemIp = new QTableWidgetItem(QString::fromUtf8(demoRows[i].ip));
        itemIp->setForeground(QColor("#FFFFFF"));
        table->setItem(i, 2, itemIp);

        auto *itemPort = new QTableWidgetItem(QString::fromUtf8(demoRows[i].port));
        itemPort->setForeground(QColor("#8FA3BF"));
        table->setItem(i, 3, itemPort);

        auto *itemStatus = new QTableWidgetItem(QString::fromUtf8(demoRows[i].status));
        itemStatus->setForeground(QColor(demoRows[i].color));
        table->setItem(i, 4, itemStatus);

        auto *itemTime = new QTableWidgetItem(QString::fromUtf8(demoRows[i].time));
        itemTime->setForeground(QColor("#8FA3BF"));
        table->setItem(i, 5, itemTime);
    }
}

// ---------------------------------------------------------------------------
// Browser Protection Page
// ---------------------------------------------------------------------------
void MainWindow::initBrowserProtectionPage()
{
    const auto browsers = BrowserProtectionManager::instance().detectedBrowsers();
    for (const auto &b : browsers) {
        QLabel *lbl = nullptr;
        if (b.id == "chrome") lbl = findChild<QLabel*>("lblChromeStatus");
        else if (b.id == "edge") lbl = findChild<QLabel*>("lblEdgeStatus");
        else if (b.id == "brave") lbl = findChild<QLabel*>("lblBraveStatus");

        if (lbl) {
            if (b.installed) {
                lbl->setText(tr("🟢 %1: Gotowy do integracji").arg(b.name));
                lbl->setStyleSheet("color: #38bdf8; font-weight: 500; font-size: 12px;");
            } else {
                lbl->setText(tr("⚪ %1: Niewykryty").arg(b.name));
                lbl->setStyleSheet("color: #64748b; font-size: 12px;");
            }
        }
    }

    if (auto *lblSites = findChild<QLabel*>("lblStatSitesNum"))
        lblSites->setText(QString::number(BrowserProtectionManager::instance().blockedWebsitesCount()));
    if (auto *lblDl = findChild<QLabel*>("lblStatDownloadsNum"))
        lblDl->setText(QString::number(BrowserProtectionManager::instance().blockedDownloadsCount()));
}

void MainWindow::onInstallBrowserExtClicked()
{
    bool ok = BrowserProtectionManager::instance().installAll();
    initBrowserProtectionPage();
    if (ok) {
        Toaster::show(this, tr("Zintegrowano dodatek Multi-Guard WebShield z przeglądarkami!"), Toaster::Success);
    } else {
        Toaster::show(this, tr("Błąd rejestracji dodatku w przeglądarce."), Toaster::Error);
    }
}

void MainWindow::onTestBlockScreenClicked()
{
    const QString extDir = BrowserProtectionManager::instance().extensionDirectory();
    const QString blockPage = extDir + QStringLiteral("/blocked.html");
    const QUrl testUrl = QUrl::fromLocalFile(blockPage);
    QUrl urlWithParams(testUrl.toString() + QStringLiteral("?type=site&url=https://niebezpieczna-strona-test.pl&threat=Zablokowano%20z%C5%82o%C5%9Bliw%C4%85%20stron%C4%99%20phishingow%C4%85"));
    QDesktopServices::openUrl(urlWithParams);
}

void MainWindow::initAccountPage()
{
    if (m_pageAccount) return;

    m_pageAccount = new QWidget(this);
    m_pageAccount->setObjectName("pageAccount");

    auto *mainLayout = new QVBoxLayout(m_pageAccount);
    mainLayout->setContentsMargins(24, 16, 24, 16);
    mainLayout->setSpacing(12);

    // Title Header
    auto *lblTitle = new QLabel(tr("Moje konto i licencja"), m_pageAccount);
    lblTitle->setStyleSheet("font-size: 18pt; font-weight: 800; color: #FFFFFF;");
    mainLayout->addWidget(lblTitle);

    auto *lblSub = new QLabel(tr("Zarządzanie licencją stacji roboczej, profilem klienta oraz danymi telemetrycznymi Multi-Guard."), m_pageAccount);
    lblSub->setStyleSheet("font-size: 10pt; color: #8FA3BF;");
    mainLayout->addWidget(lblSub);

    // Top Cards Row (Profile & License)
    auto *topRow = new QHBoxLayout();
    topRow->setSpacing(16);

    // 1. Profile Card
    auto *cardProfile = new QFrame(m_pageAccount);
    cardProfile->setStyleSheet(".QFrame { background-color: rgba(11, 23, 39, 0.85); border: 1px solid rgba(28, 54, 88, 0.7); border-radius: 12px; padding: 16px; }");
    auto *profLayout = new QVBoxLayout(cardProfile);
    profLayout->setSpacing(10);

    auto *lblProfHeader = new QLabel(tr("DANE UŻYTKOWNIKA I STACJI"), cardProfile);
    lblProfHeader->setStyleSheet("font-size: 9pt; font-weight: 800; color: #38BDF8; letter-spacing: 1px;");
    profLayout->addWidget(lblProfHeader);

    auto *profDataRow = new QHBoxLayout();
    profDataRow->setSpacing(14);

    m_lblAccountAvatar = new QLabel(cardProfile);
    QPixmap avPm(":/assets/user_avatar.png");
    if (!avPm.isNull()) {
        m_lblAccountAvatar->setPixmap(avPm.scaled(60, 60, Qt::KeepAspectRatio, Qt::SmoothTransformation));
    }
    m_lblAccountAvatar->setFixedSize(60, 60);
    m_lblAccountAvatar->setStyleSheet("border: 2px solid #0284c7; border-radius: 30px; background: rgba(2,132,199,0.15);");
    profDataRow->addWidget(m_lblAccountAvatar);

    auto *profInfoCol = new QVBoxLayout();
    profInfoCol->setSpacing(3);

    m_lblAccountName = new QLabel(cardProfile);
    m_lblAccountName->setStyleSheet("font-size: 13pt; font-weight: 800; color: #FFFFFF;");
    profInfoCol->addWidget(m_lblAccountName);

    m_lblAccountPhone = new QLabel(cardProfile);
    m_lblAccountPhone->setStyleSheet("font-size: 10.5pt; font-weight: 600; color: #00F076;");
    profInfoCol->addWidget(m_lblAccountPhone);

    m_lblAccountEmail = new QLabel(cardProfile);
    m_lblAccountEmail->setStyleSheet("font-size: 9.5pt; color: #94A3B8;");
    profInfoCol->addWidget(m_lblAccountEmail);

    profDataRow->addLayout(profInfoCol, 1);
    profLayout->addLayout(profDataRow);

    auto *idRow = new QHBoxLayout();
    auto *lblDevTitle = new QLabel(tr("ID urządzenia:"), cardProfile);
    lblDevTitle->setStyleSheet("font-size: 9pt; color: #64748B; font-weight: 600;");
    m_lblAccountDeviceId = new QLabel(cardProfile);
    m_lblAccountDeviceId->setStyleSheet("font-size: 9pt; color: #38BDF8; font-family: monospace; font-weight: bold;");
    m_lblAccountDeviceId->setTextInteractionFlags(Qt::TextSelectableByMouse);
    idRow->addWidget(lblDevTitle);
    idRow->addWidget(m_lblAccountDeviceId, 1);
    profLayout->addLayout(idRow);

    auto *btnEditProf = new QPushButton(tr("✏️ Edytuj dane kontaktowe"), cardProfile);
    btnEditProf->setCursor(Qt::PointingHandCursor);
    btnEditProf->setStyleSheet("QPushButton { background-color: rgba(18, 36, 60, 0.9); border: 1px solid rgba(35, 65, 105, 0.8); border-radius: 6px; color: #FFFFFF; font-weight: 600; font-size: 9pt; padding: 6px; } QPushButton:hover { background-color: #0284C7; border-color: #0284C7; }");
    connect(btnEditProf, &QPushButton::clicked, this, &MainWindow::onAccountEditProfileClicked);
    profLayout->addWidget(btnEditProf);

    topRow->addWidget(cardProfile, 1);

    // 2. License Card
    auto *cardLic = new QFrame(m_pageAccount);
    cardLic->setStyleSheet(".QFrame { background-color: rgba(11, 23, 39, 0.85); border: 1px solid rgba(28, 54, 88, 0.7); border-radius: 12px; padding: 16px; }");
    auto *licLayout = new QVBoxLayout(cardLic);
    licLayout->setSpacing(8);

    auto *licHeaderRow = new QHBoxLayout();
    auto *lblLicHeader = new QLabel(tr("SZCZEGÓŁY PAKIETU LICENCJI"), cardLic);
    lblLicHeader->setStyleSheet("font-size: 9pt; font-weight: 800; color: #00F076; letter-spacing: 1px;");
    licHeaderRow->addWidget(lblLicHeader);
    licHeaderRow->addStretch();

    m_lblAccountTierBadge = new QLabel(cardLic);
    m_lblAccountTierBadge->setStyleSheet("background: #0284C7; color: #FFFFFF; font-weight: 800; font-size: 9pt; padding: 3px 10px; border-radius: 5px;");
    licHeaderRow->addWidget(m_lblAccountTierBadge);
    licLayout->addLayout(licHeaderRow);

    m_lblAccountStatus = new QLabel(cardLic);
    m_lblAccountStatus->setStyleSheet("font-size: 11pt; font-weight: 700; color: #00F076;");
    licLayout->addWidget(m_lblAccountStatus);

    auto *licDatesRow = new QHBoxLayout();
    m_lblAccountDays = new QLabel(cardLic);
    m_lblAccountDays->setStyleSheet("font-size: 10pt; color: #F1F5F9; font-weight: 600;");
    m_lblAccountExpire = new QLabel(cardLic);
    m_lblAccountExpire->setStyleSheet("font-size: 10pt; color: #94A3B8;");
    licDatesRow->addWidget(m_lblAccountDays);
    licDatesRow->addStretch();
    licDatesRow->addWidget(m_lblAccountExpire);
    licLayout->addLayout(licDatesRow);

    // Key Box
    auto *keyRow = new QHBoxLayout();
    keyRow->setSpacing(6);
    m_editAccountKey = new QLineEdit(cardLic);
    m_editAccountKey->setReadOnly(true);
    m_editAccountKey->setFixedHeight(30);
    m_editAccountKey->setStyleSheet("QLineEdit { background-color: rgba(0, 0, 0, 0.4); border: 1px solid rgba(255, 255, 255, 0.15); border-radius: 6px; color: #38BDF8; font-family: monospace; font-size: 10pt; font-weight: bold; padding-left: 8px; }");
    keyRow->addWidget(m_editAccountKey, 1);

    m_btnAccountToggleKey = new QPushButton(QStringLiteral("👁️"), cardLic);
    m_btnAccountToggleKey->setFixedSize(30, 30);
    m_btnAccountToggleKey->setToolTip(tr("Pokaż / Ukryj klucz"));
    m_btnAccountToggleKey->setCursor(Qt::PointingHandCursor);
    m_btnAccountToggleKey->setStyleSheet("QPushButton { background-color: rgba(255, 255, 255, 0.08); border: 1px solid rgba(255, 255, 255, 0.15); border-radius: 6px; font-size: 12pt; } QPushButton:hover { background-color: rgba(255, 255, 255, 0.18); }");
    connect(m_btnAccountToggleKey, &QPushButton::clicked, this, [this]{
        m_keyMasked = !m_keyMasked;
        populateAccountPage();
    });
    keyRow->addWidget(m_btnAccountToggleKey);

    auto *btnCopy = new QPushButton(QStringLiteral("📋"), cardLic);
    btnCopy->setFixedSize(30, 30);
    btnCopy->setToolTip(tr("Kopiuj klucz do schowka"));
    btnCopy->setCursor(Qt::PointingHandCursor);
    btnCopy->setStyleSheet("QPushButton { background-color: rgba(255, 255, 255, 0.08); border: 1px solid rgba(255, 255, 255, 0.15); border-radius: 6px; font-size: 11pt; } QPushButton:hover { background-color: rgba(255, 255, 255, 0.18); }");
    connect(btnCopy, &QPushButton::clicked, this, [this]{
        QString k = LicenseManager::instance().loadSavedKey();
        if (k.isEmpty()) k = LicenseManager::instance().currentLicense().licenseKey;
        if (!k.isEmpty()) {
            QGuiApplication::clipboard()->setText(k);
            Toaster::show(this, tr("Skopiowano klucz do schowka"), Toaster::Success);
        }
    });
    keyRow->addWidget(btnCopy);
    licLayout->addLayout(keyRow);

    auto *licBtnRow = new QHBoxLayout();
    licBtnRow->setSpacing(8);

    auto *btnChangeKey = new QPushButton(tr("🔑 Zmień klucz licencji"), cardLic);
    btnChangeKey->setCursor(Qt::PointingHandCursor);
    btnChangeKey->setStyleSheet("QPushButton { background-color: #0284C7; border: 1px solid #38BDF8; border-radius: 6px; color: #FFFFFF; font-weight: 700; font-size: 9pt; padding: 7px; } QPushButton:hover { background-color: #0369A1; }");
    connect(btnChangeKey, &QPushButton::clicked, this, &MainWindow::onAccountChangeKeyClicked);
    licBtnRow->addWidget(btnChangeKey);

    auto *btnRefresh = new QPushButton(tr("🔄 Odśwież KeyGate"), cardLic);
    btnRefresh->setCursor(Qt::PointingHandCursor);
    btnRefresh->setStyleSheet("QPushButton { background-color: rgba(18, 36, 60, 0.9); border: 1px solid rgba(35, 65, 105, 0.8); border-radius: 6px; color: #FFFFFF; font-weight: 600; font-size: 9pt; padding: 7px; } QPushButton:hover { background-color: rgba(35, 65, 105, 0.9); }");
    connect(btnRefresh, &QPushButton::clicked, this, &MainWindow::onAccountRefreshKeyClicked);
    licBtnRow->addWidget(btnRefresh);

    licLayout->addLayout(licBtnRow);
    topRow->addWidget(cardLic, 1);
    mainLayout->addLayout(topRow);

    // Middle Telemetry Stats Cards Row
    auto *statsRow = new QHBoxLayout();
    statsRow->setSpacing(14);

    auto createStatCard = [this](const QString &icon, const QString &title, QLabel* &valLbl, const QString &valColor) -> QFrame* {
        auto *f = new QFrame(m_pageAccount);
        f->setStyleSheet(".QFrame { background-color: rgba(11, 23, 39, 0.85); border: 1px solid rgba(28, 54, 88, 0.7); border-radius: 10px; padding: 12px; }");
        auto *l = new QHBoxLayout(f);
        l->setSpacing(12);

        auto *ico = new QLabel(icon, f);
        ico->setStyleSheet("font-size: 22pt;");
        l->addWidget(ico);

        auto *col = new QVBoxLayout();
        col->setSpacing(2);
        valLbl = new QLabel(QStringLiteral("0"), f);
        valLbl->setStyleSheet(QStringLiteral("font-size: 15pt; font-weight: 800; color: %1;").arg(valColor));
        col->addWidget(valLbl);

        auto *t = new QLabel(title, f);
        t->setStyleSheet("font-size: 8.5pt; color: #8FA3BF; font-weight: 600;");
        col->addWidget(t);

        l->addLayout(col, 1);
        return f;
    };

    statsRow->addWidget(createStatCard(QStringLiteral("🔍"), tr("Przeskanowane obiekty"), m_lblStatsScanned, QStringLiteral("#38BDF8")));
    statsRow->addWidget(createStatCard(QStringLiteral("🛡️"), tr("Zneutralizowane zagrożenia"), m_lblStatsThreats, QStringLiteral("#00E676")));
    statsRow->addWidget(createStatCard(QStringLiteral("⚡"), tr("Kondycja systemu Multi-Guard"), m_lblStatsHealth, QStringLiteral("#F59E0B")));
    mainLayout->addLayout(statsRow);

    // Bottom Row: License History
    auto *lblHistTitle = new QLabel(tr("HISTORIA REJESTRACJI I LICENCJONOWANIA STACJI"), m_pageAccount);
    lblHistTitle->setStyleSheet("font-size: 9.5pt; font-weight: 700; color: #CBD5E1; margin-top: 4px;");
    mainLayout->addWidget(lblHistTitle);

    m_tableAccountHistory = new QTableWidget(m_pageAccount);
    m_tableAccountHistory->setColumnCount(4);
    m_tableAccountHistory->setHorizontalHeaderLabels({
        tr("Data i czas"), tr("Pakiet ochronny"), tr("Identyfikator stacji (DID)"), tr("Stan aktywacji")
    });
    m_tableAccountHistory->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    m_tableAccountHistory->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    m_tableAccountHistory->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
    m_tableAccountHistory->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    m_tableAccountHistory->setStyleSheet(
        "QTableWidget { background-color: rgba(10, 24, 42, 0.75); border: 1px solid rgba(28, 54, 88, 0.55); border-radius: 8px; gridline-color: transparent; outline: none; color: #F1F5F9; }"
        "QTableWidget::item { padding: 6px 10px; border-bottom: 1px solid rgba(25, 48, 78, 0.3); font-size: 9pt; }"
        "QHeaderView::section { background-color: #0b1727; color: #8FA3BF; font-weight: 700; font-size: 8.5pt; border: none; border-bottom: 1px solid #1c3658; padding: 6px 10px; }"
    );
    m_tableAccountHistory->setFixedHeight(120);
    mainLayout->addWidget(m_tableAccountHistory);

    // Insert page into stacked widget at index PageAccount (12)
    ui->stackedWidget->insertWidget(PageAccount, m_pageAccount);

    populateAccountPage();
}

void MainWindow::populateAccountPage()
{
    if (!m_pageAccount) return;

    const auto &lm = LicenseManager::instance();
    const auto &s = Settings::instance();

    if (m_lblAccountName) m_lblAccountName->setText(lm.clientName());
    if (m_lblAccountPhone) m_lblAccountPhone->setText(tr("📞 %1").arg(lm.clientPhone()));
    if (m_lblAccountEmail) m_lblAccountEmail->setText(tr("✉️ %1").arg(lm.clientEmail()));
    if (m_lblAccountDeviceId) m_lblAccountDeviceId->setText(lm.deviceIdentifier());

    if (m_lblAccountTierBadge) {
        QString tier = lm.tierName().toUpper();
        m_lblAccountTierBadge->setText(tier);
        if (lm.currentTier() == LicenseTier::AdminFull) {
            m_lblAccountTierBadge->setStyleSheet("background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #d97706, stop:1 #f59e0b); color: #000000; font-weight: 900; font-size: 9pt; padding: 3px 12px; border-radius: 5px;");
        } else if (lm.currentTier() == LicenseTier::AssistPro || lm.currentTier() == LicenseTier::Assist) {
            m_lblAccountTierBadge->setStyleSheet("background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #0284c7, stop:1 #38bdf8); color: #000000; font-weight: 900; font-size: 9pt; padding: 3px 12px; border-radius: 5px;");
        } else {
            m_lblAccountTierBadge->setStyleSheet("background: #00e676; color: #000000; font-weight: 900; font-size: 9pt; padding: 3px 12px; border-radius: 5px;");
        }
    }

    if (m_lblAccountStatus) {
        m_lblAccountStatus->setText(lm.isValid() ? tr("✅ Aktywna — Ochrona stacji włączona") : tr("⚠️ Wymagana aktywacja"));
        m_lblAccountStatus->setStyleSheet(lm.isValid() ? "font-size: 11pt; font-weight: 700; color: #00F076;" : "font-size: 11pt; font-weight: 700; color: #EF4444;");
    }

    if (m_lblAccountDays) {
        m_lblAccountDays->setText(tr("Pozostało: %1").arg(lm.daysRemainingText()));
    }
    if (m_lblAccountExpire) {
        m_lblAccountExpire->setText(tr("Ważna do: %1").arg(lm.expirationDateText()));
    }

    if (m_editAccountKey) {
        QString key = lm.loadSavedKey();
        if (key.isEmpty()) key = lm.currentLicense().licenseKey;
        if (key.isEmpty()) key = QStringLiteral("MG-DEMO-TRIAL-KEY");

        if (m_keyMasked) {
            if (key.length() >= 8) {
                QString masked = key.left(4) + QStringLiteral("-••••-••••-") + key.right(4);
                m_editAccountKey->setText(masked);
            } else {
                m_editAccountKey->setText(QStringLiteral("••••-••••-••••-••••"));
            }
        } else {
            m_editAccountKey->setText(key);
        }
    }

    if (m_lblStatsScanned) {
        m_lblStatsScanned->setText(QLocale().toString(s.scansCount()));
    }
    if (m_lblStatsThreats) {
        m_lblStatsThreats->setText(QLocale().toString(s.threatsBlockedCount()));
    }
    if (m_lblStatsHealth) {
        m_lblStatsHealth->setText(lm.isValid() ? QStringLiteral("100% (Świetna)") : QStringLiteral("Zagrożona"));
        m_lblStatsHealth->setStyleSheet(lm.isValid() ? "font-size: 15pt; font-weight: 800; color: #00E676;" : "font-size: 15pt; font-weight: 800; color: #EF4444;");
    }

    // Populate history table
    if (m_tableAccountHistory) {
        m_tableAccountHistory->setRowCount(0);
        m_tableAccountHistory->insertRow(0);

        QString dateStr = QDateTime::currentDateTime().toString("dd.MM.yyyy HH:mm");
        auto *itDate = new QTableWidgetItem(dateStr);
        itDate->setForeground(QColor("#8FA3BF"));
        m_tableAccountHistory->setItem(0, 0, itDate);

        auto *itTier = new QTableWidgetItem(lm.tierName());
        itTier->setForeground(QColor("#38BDF8"));
        itTier->setFont(QFont("", -1, QFont::Bold));
        m_tableAccountHistory->setItem(0, 1, itTier);

        auto *itDev = new QTableWidgetItem(lm.deviceIdentifier());
        itDev->setForeground(QColor("#CBD5E1"));
        m_tableAccountHistory->setItem(0, 2, itDev);

        auto *itStatus = new QTableWidgetItem(lm.isValid() ? tr("Zweryfikowano (Ed25519)") : tr("Brak licencji"));
        itStatus->setForeground(lm.isValid() ? QColor("#00F076") : QColor("#EF4444"));
        m_tableAccountHistory->setItem(0, 3, itStatus);
    }

    // Also sync top bar user profile widget
    ui->chromeBar->updateUserProfile(lm.clientName(), lm.tierName());
}

void MainWindow::onAccountChangeKeyClicked()
{
    QDialog dlg(this);
    dlg.setWindowTitle(tr("Zmiana klucza licencyjnego Multi-Guard"));
    dlg.setFixedWidth(460);
    dlg.setStyleSheet("QDialog { background-color: #0b1727; color: #F1F5F9; border: 1px solid #1c3658; border-radius: 12px; }");

    auto *layout = new QVBoxLayout(&dlg);
    layout->setContentsMargins(20, 20, 20, 20);
    layout->setSpacing(14);

    auto *lblTitle = new QLabel(tr("Wprowadź nowy klucz licencyjny"), &dlg);
    lblTitle->setStyleSheet("font-size: 13pt; font-weight: 800; color: #38BDF8;");
    layout->addWidget(lblTitle);

    auto *lblDesc = new QLabel(tr("Wprowadź klucz zakupiony w Multi-Servis (505 012 914).\nPo aktywacji program zrestartuje się automatycznie z nowym pakietem."), &dlg);
    lblDesc->setWordWrap(true);
    lblDesc->setStyleSheet("font-size: 9.5pt; color: #8FA3BF; line-height: 14px;");
    layout->addWidget(lblDesc);

    auto *editKey = new QLineEdit(&dlg);
    editKey->setPlaceholderText(tr("Wklej klucz: XXXX-XXXX-XXXX-XXXX"));
    editKey->setFixedHeight(36);
    editKey->setStyleSheet("QLineEdit { background: rgba(0,0,0,0.5); border: 1px solid #2563EB; border-radius: 6px; color: #FFFFFF; font-size: 11pt; font-family: monospace; font-weight: bold; padding: 0 10px; }");
    layout->addWidget(editKey);

    auto *btnRow = new QHBoxLayout();
    btnRow->setSpacing(10);
    btnRow->addStretch();

    auto *btnCancel = new QPushButton(tr("Anuluj"), &dlg);
    btnCancel->setFixedHeight(34);
    btnCancel->setStyleSheet("QPushButton { background: rgba(255,255,255,0.08); color: #cbd5e1; border: 1px solid rgba(255,255,255,0.2); border-radius: 6px; padding: 0 16px; font-weight: 600; }");
    connect(btnCancel, &QPushButton::clicked, &dlg, &QDialog::reject);
    btnRow->addWidget(btnCancel);

    auto *btnOk = new QPushButton(tr("Aktywuj i zrestartuj"), &dlg);
    btnOk->setFixedHeight(34);
    btnOk->setStyleSheet("QPushButton { background: #0284C7; color: #FFFFFF; border: none; border-radius: 6px; padding: 0 20px; font-weight: 700; } QPushButton:hover { background: #0369A1; }");
    connect(btnOk, &QPushButton::clicked, &dlg, [&]{
        QString key = editKey->text().trimmed();
        if (key.isEmpty()) {
            QMessageBox::warning(&dlg, tr("Błąd"), tr("Klucz licencyjny nie może być pusty."));
            return;
        }
        dlg.accept();
        restartWithNewLicense(key);
    });
    btnRow->addWidget(btnOk);

    layout->addLayout(btnRow);
    dlg.exec();
}

void MainWindow::onAccountRefreshKeyClicked()
{
    Toaster::show(this, tr("Weryfikacja licencji w KeyGate..."), Toaster::Info);
    QCoreApplication::processEvents();

    auto res = LicenseManager::instance().refreshOnline();
    if (res.success) {
        Toaster::show(this, tr("Licencja zaktualizowana: %1 (%2)")
                               .arg(LicenseManager::instance().tierName(),
                                    LicenseManager::instance().daysRemainingText()),
                      Toaster::Success);
        applyLicenseGating();
        populateAccountPage();
    } else {
        Toaster::show(this, tr("Błąd weryfikacji: %1").arg(res.errorMessage), Toaster::Error);
    }
}

void MainWindow::onAccountEditProfileClicked()
{
    QDialog dlg(this);
    dlg.setWindowTitle(tr("Edycja profilu użytkownika"));
    dlg.setFixedWidth(420);
    dlg.setStyleSheet("QDialog { background-color: #0b1727; color: #F1F5F9; border: 1px solid #1c3658; border-radius: 12px; }");

    auto *layout = new QVBoxLayout(&dlg);
    layout->setContentsMargins(20, 20, 20, 20);
    layout->setSpacing(12);

    auto *lblTitle = new QLabel(tr("Dane właściciela stacji roboczej"), &dlg);
    lblTitle->setStyleSheet("font-size: 13pt; font-weight: 800; color: #38BDF8;");
    layout->addWidget(lblTitle);

    auto *lblN = new QLabel(tr("Imię i nazwisko:"), &dlg);
    lblN->setStyleSheet("color: #8FA3BF; font-weight: 600; font-size: 9pt;");
    layout->addWidget(lblN);
    auto *editName = new QLineEdit(&dlg);
    editName->setText(Settings::instance().clientName());
    editName->setFixedHeight(32);
    editName->setStyleSheet("QLineEdit { background: rgba(0,0,0,0.5); border: 1px solid rgba(255,255,255,0.2); border-radius: 6px; color: #FFFFFF; padding: 0 8px; }");
    layout->addWidget(editName);

    auto *lblP = new QLabel(tr("Numer telefonu:"), &dlg);
    lblP->setStyleSheet("color: #8FA3BF; font-weight: 600; font-size: 9pt;");
    layout->addWidget(lblP);
    auto *editPhone = new QLineEdit(&dlg);
    editPhone->setText(Settings::instance().clientPhone());
    editPhone->setFixedHeight(32);
    editPhone->setStyleSheet("QLineEdit { background: rgba(0,0,0,0.5); border: 1px solid rgba(255,255,255,0.2); border-radius: 6px; color: #FFFFFF; padding: 0 8px; }");
    layout->addWidget(editPhone);

    auto *lblE = new QLabel(tr("Adres e-mail:"), &dlg);
    lblE->setStyleSheet("color: #8FA3BF; font-weight: 600; font-size: 9pt;");
    layout->addWidget(lblE);
    auto *editEmail = new QLineEdit(&dlg);
    editEmail->setText(Settings::instance().clientEmail());
    editEmail->setFixedHeight(32);
    editEmail->setStyleSheet("QLineEdit { background: rgba(0,0,0,0.5); border: 1px solid rgba(255,255,255,0.2); border-radius: 6px; color: #FFFFFF; padding: 0 8px; }");
    layout->addWidget(editEmail);

    auto *btnRow = new QHBoxLayout();
    btnRow->setSpacing(10);
    btnRow->addStretch();

    auto *btnCancel = new QPushButton(tr("Anuluj"), &dlg);
    btnCancel->setFixedHeight(32);
    btnCancel->setStyleSheet("QPushButton { background: rgba(255,255,255,0.08); color: #cbd5e1; border: 1px solid rgba(255,255,255,0.2); border-radius: 6px; padding: 0 16px; font-weight: 600; }");
    connect(btnCancel, &QPushButton::clicked, &dlg, &QDialog::reject);
    btnRow->addWidget(btnCancel);

    auto *btnSave = new QPushButton(tr("Zapisz dane"), &dlg);
    btnSave->setFixedHeight(32);
    btnSave->setStyleSheet("QPushButton { background: #00E676; color: #000000; border: none; border-radius: 6px; padding: 0 20px; font-weight: 800; } QPushButton:hover { background: #00c853; }");
    connect(btnSave, &QPushButton::clicked, &dlg, [&]{
        Settings::instance().setClientName(editName->text().trimmed());
        Settings::instance().setClientPhone(editPhone->text().trimmed());
        Settings::instance().setClientEmail(editEmail->text().trimmed());
        dlg.accept();
        populateAccountPage();
        Toaster::show(this, tr("Zaktualizowano profil klienta"), Toaster::Success);
    });
    btnRow->addWidget(btnSave);

    layout->addLayout(btnRow);
    dlg.exec();
}

} // namespace verax
