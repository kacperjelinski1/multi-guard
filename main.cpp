#include "src/core/SignatureDb.h"
// ═══════════════════════════════════════════════════════════════════════
//  Verax - main entry point
//  By Ali Sakkaf  -  https://alisakkaf.com
// ═══════════════════════════════════════════════════════════════════════
#include "harden.h"
#include "Version.h"

#include "src/core/Settings.h"
#include "src/core/Translator.h"
#include "src/core/Logger.h"
#include "src/core/LicenseManager.h"
#include "src/ui/MainWindow.h"
#include "src/utils/ThemeManager.h"

#include <QApplication>
#include <QCommandLineParser>
#include <QCommandLineOption>
#include <QFile>
#include <QFontDatabase>
#include <QDir>
#include <QFileInfo>
#include <QRegularExpression>
#include <QLocalServer>
#include <QLocalSocket>

#ifdef Q_OS_WIN
#include <windows.h>
#include <tlhelp32.h>

// Sweep the Windows notification tray to eliminate ghost tray icons from terminated processes
static void refreshSystemTray()
{
    auto sweepToolbar = [](HWND hWnd) {
        if (!hWnd) return;
        RECT rc;
        if (GetClientRect(hWnd, &rc)) {
            for (int x = 1; x < rc.right; x += 8) {
                for (int y = 1; y < rc.bottom; y += 8) {
                    SendMessageA(hWnd, WM_MOUSEMOVE, 0, MAKELPARAM(x, y));
                }
            }
        }
    };

    // 1) Main taskbar tray
    HWND hShell = FindWindowA("Shell_TrayWnd", NULL);
    if (hShell) {
        HWND hNotify = FindWindowExA(hShell, NULL, "TrayNotifyWnd", NULL);
        if (hNotify) {
            HWND hSysPager = FindWindowExA(hNotify, NULL, "SysPager", NULL);
            HWND hTb = FindWindowExA(hSysPager ? hSysPager : hNotify, NULL, "ToolbarWindow32", NULL);
            sweepToolbar(hTb);
        }
    }

    // 2) Overflow notification area (the chevron ^ popup)
    HWND hOverflow = FindWindowA("NotifyIconOverflowWindow", NULL);
    if (hOverflow) {
        HWND hTbOverflow = FindWindowExA(hOverflow, NULL, "ToolbarWindow32", NULL);
        sweepToolbar(hTbOverflow);
    }
}

// Kill any other running Multi-Guard / VeraxCore instances immediately
static void terminateOtherInstances()
{
    DWORD myPid = GetCurrentProcessId();
    QString myExeName = QFileInfo(QCoreApplication::applicationFilePath()).fileName();
    bool killedAny = false;

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32W);
        if (Process32FirstW(hSnap, &pe32)) {
            do {
                if (pe32.th32ProcessID != myPid && pe32.th32ProcessID > 4) {
                    QString exeName = QString::fromWCharArray(pe32.szExeFile);
                    if (exeName.compare(myExeName, Qt::CaseInsensitive) == 0 ||
                        exeName.compare(QString::fromLatin1(APP_BIN_NAME), Qt::CaseInsensitive) == 0 ||
                        exeName.compare(QStringLiteral("Multi-Guard.exe"), Qt::CaseInsensitive) == 0 ||
                        exeName.compare(QStringLiteral("VeraxCore.exe"), Qt::CaseInsensitive) == 0) {
                        HANDLE hProc = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, pe32.th32ProcessID);
                        if (hProc) {
                            TerminateProcess(hProc, 0);
                            WaitForSingleObject(hProc, 500);
                            CloseHandle(hProc);
                            killedAny = true;
                        }
                    }
                }
            } while (Process32NextW(hSnap, &pe32));
        }
        CloseHandle(hSnap);
    }

    if (killedAny) {
        Sleep(150);
        refreshSystemTray();
    }
}
#endif

int main(int argc, char *argv[])
{
    // 1) HARDEN FIRST - before any other init. Kills DLL planting.
    shield::harden();

    // 2) High DPI Scaling & Subpixel Font Rendering
    QCoreApplication::setAttribute(Qt::AA_EnableHighDpiScaling);
    QCoreApplication::setAttribute(Qt::AA_UseHighDpiPixmaps);
    qputenv("QT_AUTO_SCREEN_SCALE_FACTOR", "1");

    QApplication a(argc, argv);

    // Modern smooth, rounded and legible typography (Nunito / Segoe UI Variable)
    QString primaryFamily;
    int fontId = QFontDatabase::addApplicationFont(QStringLiteral(":/fonts/Nunito.ttf"));
    if (fontId != -1) {
        const QStringList loadedFamilies = QFontDatabase::applicationFontFamilies(fontId);
        if (!loadedFamilies.isEmpty()) {
            primaryFamily = loadedFamilies.first();
        }
    }

    QFont appFont;
    QStringList preferredFamilies;
    if (!primaryFamily.isEmpty()) {
        preferredFamilies << primaryFamily;
    }
    preferredFamilies << QStringLiteral("Nunito")
                      << QStringLiteral("Segoe UI Variable Text")
                      << QStringLiteral("Segoe UI Variable Display")
                      << QStringLiteral("Segoe UI")
                      << QStringLiteral("Aptos")
                      << QStringLiteral("Inter")
                      << QStringLiteral("sans-serif");
    appFont.setFamilies(preferredFamilies);
    appFont.setPointSize(10);
    appFont.setWeight(QFont::Medium);
    appFont.setStyleStrategy(QFont::PreferAntialias);
    a.setFont(appFont);

    qRegisterMetaType<verax::DriveInfo>("verax::DriveInfo");
    qRegisterMetaType<QVector<verax::DriveInfo>>("QVector<verax::DriveInfo>");
    qRegisterMetaType<verax::ProcInfo>("verax::ProcInfo");
    qRegisterMetaType<QVector<verax::ProcInfo>>("QVector<verax::ProcInfo>");
    qRegisterMetaType<verax::ThreatInfo>("verax::ThreatInfo");
    qRegisterMetaType<verax::ScanReport>("verax::ScanReport");
    qRegisterMetaType<verax::ScanRequest>("verax::ScanRequest");
    qRegisterMetaType<verax::DriveInfo>("DriveInfo");
    qRegisterMetaType<QVector<verax::DriveInfo>>("QVector<DriveInfo>");
    qRegisterMetaType<verax::ProcInfo>("ProcInfo");
    qRegisterMetaType<QVector<verax::ProcInfo>>("QVector<ProcInfo>");
    qRegisterMetaType<verax::ThreatInfo>("ThreatInfo");
    qRegisterMetaType<verax::ScanReport>("ScanReport");
    qRegisterMetaType<verax::ScanRequest>("ScanRequest");


    QApplication::setOrganizationName(APP_VENDOR);
    QApplication::setOrganizationDomain("multi-servis.pl");
    QApplication::setApplicationName(APP_NAME);
    QApplication::setApplicationVersion(APP_VERSION_STR);
    QApplication::setQuitOnLastWindowClosed(false); // tray-aware

    // 3) Logger first so all subsequent failures are recorded
    verax::Logger::init();
    verax::Logger::info(QStringLiteral("=== %1 v%2 starting ===")
                        .arg(APP_NAME).arg(APP_VERSION_STR));
    if (!primaryFamily.isEmpty()) {
        verax::Logger::info(QStringLiteral("Primary smooth rounded font active: %1").arg(primaryFamily));
    }

    // 5) Settings + Translator (must come before any UI)
    verax::Settings::instance().load();
    verax::Translator::instance().install(
        verax::Settings::instance().language());

    // Initialize the signature and quarantine schema on every application start.
    if (!verax::SignatureDb::instance().initSchema())
        verax::Logger::error(QStringLiteral("Signature database initialization failed"));

    // 5.5) License Manager (loads saved KeyGate token & verifies offline)
    verax::LicenseManager::instance().init();

    // 6) Theme Manager (Dark / Light / System)
    verax::ThemeManager::applyTheme();

    // 7) CLI parser - silent scan, tray-only mode
    QCommandLineParser parser;
    parser.setApplicationDescription(QString::fromLatin1(APP_DESCRIPTION));
    parser.addHelpOption();
    parser.addVersionOption();
    QCommandLineOption optScan(QStringList{"s","scan"},
        QObject::tr("Run silent scan and exit"));
    QCommandLineOption optTray(QStringList{"t","tray"},
        QObject::tr("Start minimized to system tray"));
    parser.addOption(optScan);
    parser.addOption(optTray);
    parser.process(a);

#ifdef Q_OS_WIN
    // 7.5) Single Instance check via IPC:
    // If Multi-Guard is already running, pass arguments (or activate window) and exit immediately.
    const QString ipcName = QStringLiteral("MultiGuard_SingleInstance_IPC");
    const QStringList initialArgs = parser.positionalArguments();
    {
        QLocalSocket socket;
        socket.connectToServer(ipcName);
        if (socket.waitForConnected(300)) {
            if (!initialArgs.isEmpty()) {
                socket.write("SCAN:" + initialArgs.join(QStringLiteral("|||")).toUtf8() + "\n");
            } else {
                socket.write("SHOW\n");
            }
            socket.flush();
            socket.waitForBytesWritten(500);
            socket.waitForDisconnected(500);
            return 0; // Seamless handoff to running instance, exit immediately!
        }
    }

    // If no running instance responded, terminate any orphaned ghost processes and refresh tray
    terminateOtherInstances();
    refreshSystemTray();
#endif

    // 8) Build main window
    verax::Logger::info("main: about to construct MainWindow");
    verax::MainWindow w;

#ifdef Q_OS_WIN
    // Listen for future launches so they can request scans or window activation
    QLocalServer::removeServer(ipcName);
    QLocalServer *ipcServer = new QLocalServer(&a);
    if (ipcServer->listen(ipcName)) {
        QObject::connect(ipcServer, &QLocalServer::newConnection, [ipcServer, &w]() {
            QLocalSocket *client = ipcServer->nextPendingConnection();
            if (!client) return;
            QObject::connect(client, &QLocalSocket::readyRead, [client, &w]() {
                QByteArray raw = client->readAll().trimmed();
                if (raw.startsWith("SCAN:")) {
                    QString payload = QString::fromUtf8(raw.mid(5));
                    QStringList targets = payload.split(QStringLiteral("|||"), Qt::SkipEmptyParts);
                    w.showNormal();
                    w.raise();
                    w.activateWindow();
                    HWND hWnd = (HWND)w.winId();
                    if (hWnd) {
                        ShowWindow(hWnd, SW_RESTORE);
                        SetForegroundWindow(hWnd);
                    }
                    if (!targets.isEmpty()) {
                        w.scanCustomTargets(targets);
                    }
                } else if (raw == "SHOW") {
                    w.showNormal();
                    w.raise();
                    w.activateWindow();
                    HWND hWnd = (HWND)w.winId();
                    if (hWnd) {
                        ShowWindow(hWnd, SW_RESTORE);
                        SetForegroundWindow(hWnd);
                    }
                } else if (raw.contains("QUIT")) {
                    if (w.trayIcon()) {
                        w.trayIcon()->hide();
                    }
                    qApp->quit();
                }
            });
        });
    }
#endif

    const QStringList positionalArgs = parser.positionalArguments();
    if (!positionalArgs.isEmpty()) {
        w.show();
        w.scanCustomTargets(positionalArgs);
    }
    else if (parser.isSet(optScan))      w.runSilentScanAndExit();
    else if (parser.isSet(optTray))      w.startInTray();
    else                                 w.show();

#ifdef Q_OS_WIN
    if (!parser.isSet(optScan) && !parser.isSet(optTray)) {
        w.raise();
        w.activateWindow();
        HWND hWnd = (HWND)w.winId();
        if (hWnd) {
            ShowWindow(hWnd, SW_RESTORE);
            SetForegroundWindow(hWnd);
        }
    }
#endif
    verax::Logger::info("main: window shown, entering exec()");

    return a.exec();
}
