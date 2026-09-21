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
#include <QMessageBox>
#include <QPushButton>
#include <QRegularExpression>

#ifdef Q_OS_WIN
#include <windows.h>
#include <tlhelp32.h>
#endif

int main(int argc, char *argv[])
{
    // 1) HARDEN FIRST - before any other init. Kills DLL planting.
    shield::harden();

    // Disable High DPI Scaling globally
    qputenv("QT_ENABLE_HIGHDPI_SCALING", "0");
    qputenv("QT_AUTO_SCREEN_SCALE_FACTOR", "0");

    // Force Windows to treat the application as DPI Unaware
    qputenv("QT_QPA_PLATFORM", "windows:dpiawareness=0");

    QApplication a(argc, argv);

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

    // 4) Load fonts (best-effort - falls back to system fonts)
    const QStringList fontPaths = {
        QStringLiteral(":/fonts/Inter-Regular.ttf"),
        QStringLiteral(":/fonts/Inter-SemiBold.ttf"),
        QStringLiteral(":/fonts/Inter-Bold.ttf"),
        QStringLiteral(":/fonts/NotoNaskhArabic-Bold.ttf"),
    };
    for (const QString &p : fontPaths) {
        if (QFile::exists(p))
            QFontDatabase::addApplicationFont(p);
    }

    // 5) Settings + Translator (must come before any UI)
    verax::Settings::instance().load();
    verax::Translator::instance().install(
        verax::Settings::instance().language());

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
    // 7.5) Single Instance check
    HANDLE hMutex = CreateMutexA(NULL, FALSE, "MultiGuard_SingleInstance_Mutex");
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        // Bring existing window to front
        HWND hWnd = FindWindowA(NULL, APP_NAME);
        if (hWnd) {
            ShowWindow(hWnd, SW_RESTORE);
            SetForegroundWindow(hWnd);
        }

        // Show elegant dialog
        QMessageBox msgBox;
        msgBox.setIconPixmap(QPixmap(":/assets/logo.png").scaled(64, 64, Qt::KeepAspectRatio, Qt::SmoothTransformation));
        msgBox.setWindowTitle(QString::fromLatin1(APP_NAME));
        
        bool isAr = (verax::Settings::instance().language() == "ar");
        if (isAr) {
            msgBox.setLayoutDirection(Qt::RightToLeft);
            msgBox.setText(QString::fromUtf8("البرنامج قيد التشغيل بالفعل.\nهل تريد إغلاق النسخة الحالية وإعادة فتح البرنامج؟"));
            msgBox.setStandardButtons(QMessageBox::Yes | QMessageBox::No);
            msgBox.setButtonText(QMessageBox::Yes, QString::fromUtf8("نعم، أعد الفتح"));
            msgBox.setButtonText(QMessageBox::No, QString::fromUtf8("لا، تراجع"));
        } else {
            msgBox.setText(QObject::tr("The program is already running.\nDo you want to close the existing instance and reopen it?"));
            msgBox.setStandardButtons(QMessageBox::Yes | QMessageBox::No);
            msgBox.setButtonText(QMessageBox::Yes, QObject::tr("Yes"));
            msgBox.setButtonText(QMessageBox::No, QObject::tr("No"));
        }
        msgBox.setDefaultButton(QMessageBox::No);

        if (msgBox.exec() == QMessageBox::Yes) {
            // Kill existing instances
            DWORD myPid = GetCurrentProcessId();
            HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (hSnap != INVALID_HANDLE_VALUE) {
                PROCESSENTRY32W pe32;
                pe32.dwSize = sizeof(PROCESSENTRY32W);
                if (Process32FirstW(hSnap, &pe32)) {
                    do {
                        if (pe32.th32ProcessID != myPid) {
                            QString exeName = QString::fromWCharArray(pe32.szExeFile);
                            if (exeName.compare(QString::fromLatin1(APP_BIN_NAME), Qt::CaseInsensitive) == 0) {
                                HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pe32.th32ProcessID);
                                if (hProc) {
                                    TerminateProcess(hProc, 0);
                                    CloseHandle(hProc);
                                }
                            }
                        }
                    } while (Process32NextW(hSnap, &pe32));
                }
                CloseHandle(hSnap);
            }
            Sleep(1000); // Give OS time to fully terminate and release mutexes
        } else {
            return 0; // Exit cleanly
        }
    }
#endif

    // 8) Build main window
    verax::Logger::info("main: about to construct MainWindow");
    verax::MainWindow w;
    verax::Logger::info("main: MainWindow constructed");
    const bool installed = verax::MainWindow::isInstalledPath();
    verax::Logger::info(QStringLiteral("main: installed=%1").arg(installed ? "yes" : "no"));

    const QStringList positionalArgs = parser.positionalArguments();
    if (!positionalArgs.isEmpty()) {
        w.show();
        w.scanCustomTargets(positionalArgs);
    }
    else if (parser.isSet(optScan))      w.runSilentScanAndExit();
    else if (parser.isSet(optTray))      w.startInTray();
    else if (!installed)                 w.showInstaller();
    else                                 w.show();
    verax::Logger::info("main: window shown, entering exec()");

    return a.exec();
}
