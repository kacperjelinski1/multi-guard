// MainWindow.h - frameless window + sidebar + QStackedWidget pages
// All pages live in the single mainwindow.ui. This class owns the logic.
// By Ali Sakkaf - https://alisakkaf.com
#pragma once

#include <QMainWindow>
#include <QPointer>
#include <QSystemTrayIcon>
#include <QVector>
#include "../core/Scanner.h"
#include "../core/SystemEnum.h"
#include "../core/LicenseManager.h"

class QMenu;
class QAction;
class QTimer;
class QComboBox;
class QCheckBox;
class QPushButton;
template <class T> class QFutureWatcher;

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

namespace verax {

class PageTransition;
class ThreatCard;

class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    enum PageIndex {
        PageDashboard = 0,
        PageScanConfig,
        PageScan,
        PageQuarantine,
        PageRepair,
        PageTools,
        PageFirewall,
        PageBrowserProtection,
        PageRemoteRepair,
        PageSettings,
        PageAbout,
        PageLicenseLocked,
        PageAccount
    };
    Q_ENUM(PageIndex)

    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow() override;

    static bool isInstalledPath() { return true; }
    void showInstaller() { show(); }
    void startInTray();
    void runSilentScanAndExit();
    void scanCustomTargets(const QStringList &targets);
    QSystemTrayIcon* trayIcon() const { return m_tray; }

public slots:
    void onRealTimeThreatDetected(const verax::ThreatInfo &info);

protected:
    void changeEvent(QEvent *e) override;
    void closeEvent(QCloseEvent *e) override;
protected:
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
    bool nativeEvent(const QByteArray &eventType, void *message, qintptr *result) override;
#else
    bool nativeEvent(const QByteArray &eventType, void *message, long *result) override;
#endif
private slots:
    void onNavClicked();

    // Dashboard
    void onQuickScan();
    void onFullScan();
    void onScanMemory();
    void onUpdateSignatures();
    void onUsbDriveInserted(const QString &drivePath);

    // Scan config
    void onAddFolder();
    void onAddFile();
    void onStartScanFromConfig();

    // Scan page
    void onStopScan();
    void onPauseToggled(bool paused);

    // Scanner signals
    void onScannerStarted();
    void onScannerProgress(int pct, qint64 done, qint64 total);
    void onScannerFileScanned(const QString &path);
    void onScannerThreatFound(verax::ThreatInfo info);
    void onScannerFinished(verax::ScanReport report);

    // Quarantine
    void onQuarantineRefresh();
    void onQuarantineRestoreSelected();
    void onQuarantineDeleteSelected();
    void onQuarantineExportReport();

    // Repair
    void onRepairCheck(const QString &card);
    void onRepairFix(const QString &card);
    void onRepairFixAll();
    void onRepairBrowseAppFolder();

    // Settings
    void onSettingsSaved();
    void onSettingsReset();
    void onCheckUpdatesNow();

    // About
    void onSelfTest();
    void onBrandClicked(int kind);   // BrandIcon::Kind

    // Tray
    void onTrayActivated(QSystemTrayIcon::ActivationReason r);

    // ThreatList smart filters + bulk actions
    void applyThreatFilters();
    void onBulkAction();
    void onSelectAllThreats(bool checked);

private:
    void wireUi();
    void wireSignals();
    void retranslateRuntime();
    void populateDrivesOnConfig();
    void applyDrivesToUi(const QVector<DriveInfo> &drives);
    void populateQuarantineTable();
    void populateRepairCards();
    void populateAboutPage();
    void setActiveNav(PageIndex idx);
    void setupTrayIcon();
    void updateTrayLicenseState();
    void buildThreatFilterToolbar();
    QString signaturesInfoHtml() const;
    void updateLastScanCard(qint64 finishedAt, int filesScanned, int threatsFound);
    void refreshDashboardStats();
    void updateChromeStatus(const QString &kind, const QString &text);
    void primeScanUi(const QString &phaseLabel);
    QStringList collectScanTargets() const;
    ScanRequest buildScanRequest() const;

    void onCheckUpdatesClicked();
    void onNotificationsClicked();

    void initToolsPage();
    void onRefreshHardwareStats();
    void onScanCleanClicked();
    void onDoCleanClicked();
    void onOptNowClicked();
    void onOpenStartupManagerDialog();
    void onOpenHardwareMonitorDialog();
    void onRefreshStartupClicked();
    void onToggleStartupClicked();
    void onDeleteStartupClicked();
    void onBrowseShredFile();
    void onBrowseShredDir();
    void onDoShredClicked();
    void onContextMenuToggled(bool checked);
    void onGenerateSessionCode();
    void onCopySessionCode();
    void onConnectRemoteClicked();

    // Whitelist, Scheduler & Reports
    void initScheduler();
    void onScheduledTimerTick();
    void onAddExclusionFolder();
    void onAddExclusionFile();
    void onRemoveExclusion();
    void onGenerateServiceReportClicked();

    // Firewall & Browser Protection
    void initFirewallPage();
    void onToggleFirewallClicked();
    void onResetFirewallClicked();
    void onBlockSMBClicked();
    void onBlockRPCClicked();
    void onBlockRDPClicked();
    void onAddBlockAppClicked();
    void onRefreshFwRulesClicked();

    void initBrowserProtectionPage();
    void onInstallBrowserExtClicked();
    void onTestBlockScreenClicked();

    // Licensing
    void applyLicenseGating();
    void onLicenseChanged(verax::LicenseTier tier, bool isValid);
    void onChangeLicenseKeyClicked();
    void onRefreshLicenseClicked();
    void onActivateLockedKeyClicked();
    void onRefreshLockedKeyClicked();
    void restartWithNewLicense(const QString &key);

protected:
    bool eventFilter(QObject *watched, QEvent *event) override;

private:
    Ui::MainWindow *ui = nullptr;
    PageTransition *m_transition = nullptr;
    QSystemTrayIcon *m_tray = nullptr;
    QAction *m_trayHeaderAction = nullptr;
    QAction *m_trayToggleRtAction = nullptr;
    QAction *m_trayToggleWebAction = nullptr;
    QAction *m_trayQuickScanAction = nullptr;
    QAction *m_trayRamScanAction = nullptr;
    QAction *m_trayToolsAction = nullptr;
    QAction *m_trayRemoteAction = nullptr;
    QAction *m_trayUpdateAction = nullptr;
    QTimer *m_watchdog = nullptr;
    QTimer *m_hwTimer = nullptr;
    QTimer *m_schedulerTimer = nullptr;
    QFutureWatcher<QVector<DriveInfo>> *m_drivesWatcher = nullptr;

    int  m_currentPage = PageDashboard;
    bool m_silentMode  = false;
    bool m_populatingDrives = false;
    qint64 m_lastScanThreats = 0;
    QVector<ThreatInfo> m_pendingReport;

    // ThreatList smart UI
    QList<ThreatCard*> m_threatCards;
    QComboBox   *m_filterSeverity = nullptr;
    QComboBox   *m_filterFamily   = nullptr;
    QComboBox   *m_filterRepairable = nullptr;
    QCheckBox   *m_selectAll      = nullptr;
    QComboBox   *m_bulkActionCombo = nullptr;
    QPushButton *m_bulkApplyBtn   = nullptr;

    void initAccountPage();
    void populateAccountPage();
    void onAccountChangeKeyClicked();
    void onAccountRefreshKeyClicked();
    void onAccountEditProfileClicked();

    QWidget *m_pageAccount = nullptr;
    QLabel  *m_lblAccountAvatar = nullptr;
    QLabel  *m_lblAccountName = nullptr;
    QLabel  *m_lblAccountPhone = nullptr;
    QLabel  *m_lblAccountEmail = nullptr;
    QLabel  *m_lblAccountDeviceId = nullptr;
    QLabel  *m_lblAccountTierBadge = nullptr;
    QLabel  *m_lblAccountStatus = nullptr;
    QLabel  *m_lblAccountDays = nullptr;
    QLabel  *m_lblAccountExpire = nullptr;
    QLineEdit *m_editAccountKey = nullptr;
    QPushButton *m_btnAccountToggleKey = nullptr;
    QLabel  *m_lblStatsScanned = nullptr;
    QLabel  *m_lblStatsThreats = nullptr;
    QLabel  *m_lblStatsHealth = nullptr;
    QTableWidget *m_tableAccountHistory = nullptr;
    bool     m_keyMasked = true;

    QString      m_activeScanPhase;
    QString      m_selectedScanMode = QStringLiteral("quick");
};

} // namespace verax
