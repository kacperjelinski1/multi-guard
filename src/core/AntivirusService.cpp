// AntivirusService.cpp
// Core Windows Service implementation and IPC server for Multi-Guard
#include "AntivirusService.h"
#include "RealTimeShield.h"
#include "RansomwareShield.h"
#include "SignatureDb.h"
#include "LicenseManager.h"
#include "WindowsSecurityCenterProvider.h"
#include "Settings.h"
#include "Logger.h"
#include "AuditLogger.h"
#include "../../Version.h"

#include <QCoreApplication>
#include <QLocalServer>
#include <QLocalSocket>
#include <QJsonDocument>
#include <QDateTime>
#include <QDir>
#include <QFileInfo>

#ifdef _WIN32
#include <windows.h>
#endif

namespace verax {

const QString AntivirusService::SERVICE_NAME         = QStringLiteral("MultiGuardAV");
const QString AntivirusService::SERVICE_DISPLAY_NAME = QStringLiteral("Multi-Guard Antivirus Service");
const QString AntivirusService::IPC_PIPE_NAME        = QStringLiteral("MultiGuard_Service_IPC");

#ifdef _WIN32
static SERVICE_STATUS        s_serviceStatus;
static SERVICE_STATUS_HANDLE s_serviceStatusHandle = NULL;

static void reportServiceStatus(DWORD currentState, DWORD win32ExitCode, DWORD waitHint)
{
    static DWORD s_checkPoint = 1;
    s_serviceStatus.dwCurrentState  = currentState;
    s_serviceStatus.dwWin32ExitCode = win32ExitCode;
    s_serviceStatus.dwWaitHint      = waitHint;

    if (currentState == SERVICE_START_PENDING) {
        s_serviceStatus.dwControlsAccepted = 0;
    } else {
        s_serviceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    }

    if (currentState == SERVICE_RUNNING || currentState == SERVICE_STOPPED) {
        s_serviceStatus.dwCheckPoint = 0;
    } else {
        s_serviceStatus.dwCheckPoint = s_checkPoint++;
    }

    SetServiceStatus(s_serviceStatusHandle, &s_serviceStatus);
}

static DWORD WINAPI winServiceCtrlHandler(DWORD ctrl, DWORD eventType, LPVOID eventData, LPVOID context)
{
    Q_UNUSED(eventType);
    Q_UNUSED(eventData);
    Q_UNUSED(context);

    switch (ctrl) {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        Logger::info("AntivirusService: Received SERVICE_CONTROL_STOP/SHUTDOWN from Windows SCM.");
        reportServiceStatus(SERVICE_STOP_PENDING, NO_ERROR, 5000);
        QCoreApplication::quit();
        return NO_ERROR;
    default:
        break;
    }
    return ERROR_CALL_NOT_IMPLEMENTED;
}

static void WINAPI winServiceMain(DWORD argc, LPWSTR *argv)
{
    Q_UNUSED(argc);
    Q_UNUSED(argv);

    s_serviceStatusHandle = RegisterServiceCtrlHandlerExW(
        (LPCWSTR)AntivirusService::SERVICE_NAME.utf16(),
        winServiceCtrlHandler,
        NULL
    );

    if (!s_serviceStatusHandle) {
        return;
    }

    s_serviceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    s_serviceStatus.dwServiceSpecificExitCode = 0;

    reportServiceStatus(SERVICE_START_PENDING, NO_ERROR, 5000);

    // Bootstrap engine inside service event loop
    bool started = AntivirusService::instance().startEngine();
    if (!started) {
        reportServiceStatus(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR, 0);
        return;
    }

    reportServiceStatus(SERVICE_RUNNING, NO_ERROR, 0);
    Logger::info("AntivirusService: Service running in background session.");
}
#endif

AntivirusService& AntivirusService::instance()
{
    static AntivirusService s_instance;
    return s_instance;
}

AntivirusService::AntivirusService(QObject *parent)
    : QObject(parent)
{
}

AntivirusService::~AntivirusService()
{
    stopEngine();
}

int AntivirusService::runService(int argc, char *argv[])
{
#ifndef _WIN32
    QCoreApplication app(argc, argv);
    Logger::info("AntivirusService: Running in headless daemon mode.");
    AntivirusService::instance().startEngine();
    return app.exec();
#else
    // Check if running interactively from console with --service-headless
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--service-headless") == 0) {
            QCoreApplication app(argc, argv);
            Logger::info("AntivirusService: Running in console headless mode.");
            AntivirusService::instance().startEngine();
            return app.exec();
        }
    }

    // Windows SCM dispatch
    const SERVICE_TABLE_ENTRYW serviceTable[] = {
        { (LPWSTR)SERVICE_NAME.utf16(), (LPSERVICE_MAIN_FUNCTIONW)winServiceMain },
        { NULL, NULL }
    };

    if (!StartServiceCtrlDispatcherW(serviceTable)) {
        DWORD err = GetLastError();
        // If ERROR_FAILED_SERVICE_CONTROLLER_CONNECT, started manually from cmd line
        if (err == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
            QCoreApplication app(argc, argv);
            Logger::info("AntivirusService: Started outside SCM, running as background process.");
            AntivirusService::instance().startEngine();
            return app.exec();
        }
        return 1;
    }
    return 0;
#endif
}

bool AntivirusService::installService(const QString &exePath)
{
#ifndef _WIN32
    Q_UNUSED(exePath);
    return false;
#else
    const QString targetExe = !exePath.isEmpty()
        ? QDir::toNativeSeparators(exePath)
        : QDir::toNativeSeparators(QCoreApplication::applicationFilePath());

    const QString binPath = QStringLiteral("\"%1\" --service").arg(targetExe);

    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSCM) {
        Logger::error("AntivirusService: Nie udało się otworzyć SCM (wymagane uprawnienia administratora).");
        return false;
    }

    SC_HANDLE hService = CreateServiceW(
        hSCM,
        (LPCWSTR)SERVICE_NAME.utf16(),
        (LPCWSTR)SERVICE_DISPLAY_NAME.utf16(),
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START,
        SERVICE_ERROR_NORMAL,
        (LPCWSTR)binPath.utf16(),
        NULL,
        NULL,
        NULL,
        NULL, // LocalSystem account
        NULL
    );

    if (!hService) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_EXISTS) {
            Logger::info("AntivirusService: Usługa już istnieje w systemie SCM.");
            CloseServiceHandle(hSCM);
            return true;
        }
        Logger::error(QStringLiteral("AntivirusService: Błąd tworzenia usługi SCM: 0x%1").arg(err, 8, 16, QLatin1Char('0')));
        CloseServiceHandle(hSCM);
        return false;
    }

    // Set service description
    SERVICE_DESCRIPTIONW sd;
    const QString desc = QStringLiteral("Zapewnia stałą ochronę antywirusową w czasie rzeczywistym i bezpieczną synchronizację z systemem operacyjnym.");
    sd.lpDescription = (LPWSTR)desc.utf16();
    ChangeServiceConfig2W(hService, SERVICE_CONFIG_DESCRIPTION, &sd);

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);

    Logger::info("AntivirusService: Pomyślnie zarejestrowano usługę Multi-Guard w Windows SCM.");
    return true;
#endif
}

bool AntivirusService::uninstallService()
{
#ifndef _WIN32
    return false;
#else
    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSCM) return false;

    SC_HANDLE hService = OpenServiceW(hSCM, (LPCWSTR)SERVICE_NAME.utf16(), SERVICE_STOP | DELETE);
    if (!hService) {
        CloseServiceHandle(hSCM);
        return true;
    }

    SERVICE_STATUS status;
    ControlService(hService, SERVICE_CONTROL_STOP, &status);

    bool ok = DeleteService(hService);
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);

    Logger::info(QStringLiteral("AntivirusService: Usunięcie usługi z SCM (sukces=%1)").arg(ok ? "TAK" : "NIE"));
    return ok;
#endif
}

bool AntivirusService::startService()
{
#ifndef _WIN32
    return false;
#else
    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCM) return false;

    SC_HANDLE hService = OpenServiceW(hSCM, (LPCWSTR)SERVICE_NAME.utf16(), SERVICE_START);
    if (!hService) {
        CloseServiceHandle(hSCM);
        return false;
    }

    bool ok = StartServiceW(hService, 0, NULL);
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    return ok;
#endif
}

bool AntivirusService::stopService()
{
#ifndef _WIN32
    return false;
#else
    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCM) return false;

    SC_HANDLE hService = OpenServiceW(hSCM, (LPCWSTR)SERVICE_NAME.utf16(), SERVICE_STOP);
    if (!hService) {
        CloseServiceHandle(hSCM);
        return false;
    }

    SERVICE_STATUS status;
    bool ok = ControlService(hService, SERVICE_CONTROL_STOP, &status);
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    return ok;
#endif
}

bool AntivirusService::isServiceInstalled()
{
#ifndef _WIN32
    return false;
#else
    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCM) return false;

    SC_HANDLE hService = OpenServiceW(hSCM, (LPCWSTR)SERVICE_NAME.utf16(), SERVICE_QUERY_STATUS);
    bool installed = (hService != NULL);
    if (hService) CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    return installed;
#endif
}

bool AntivirusService::isServiceRunning()
{
#ifndef _WIN32
    return false;
#else
    // Quick verification via IPC pipe ping
    QString res = sendIpcCommand(QStringLiteral("PING"), 500);
    if (res == QStringLiteral("PONG")) {
        return true;
    }

    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCM) return false;

    SC_HANDLE hService = OpenServiceW(hSCM, (LPCWSTR)SERVICE_NAME.utf16(), SERVICE_QUERY_STATUS);
    if (!hService) {
        CloseServiceHandle(hSCM);
        return false;
    }

    SERVICE_STATUS_PROCESS ssp;
    DWORD bytesNeeded = 0;
    bool running = false;
    if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &bytesNeeded)) {
        running = (ssp.dwCurrentState == SERVICE_RUNNING);
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    return running;
#endif
}

bool AntivirusService::startEngine()
{
    if (m_engineRunning) return true;

    Logger::info("AntivirusService: Inicjalizacja podsystemów silnika Multi-Guard...");

    // 1. Otwarcie bazy sygnatur
    SignatureDb::instance().open();

    // 2. Inicjalizacja licencji
    LicenseManager::instance().initialize();

    // 3. Połączenie sygnałów aktualizacji sygnatur i RTP z dostawcą WSC
    connect(&RealTimeShield::instance(), &RealTimeShield::statusChanged,
            &WindowsSecurityCenterProvider::instance(), &WindowsSecurityCenterProvider::onRtpStatusChanged);
    connect(&SignatureDb::instance(), &SignatureDb::updateFinished,
            &WindowsSecurityCenterProvider::instance(), &WindowsSecurityCenterProvider::onSignaturesUpdated);

    // 4. Uruchomienie tarczy w czasie rzeczywistym
    if (LicenseManager::instance().isValid() && Settings::instance().realTimeProtection()) {
        RealTimeShield::instance().start();
    }

    // 5. Uruchomienie tarczy Ransomware (Canary Guard)
    if (LicenseManager::instance().isValid() && Settings::instance().ransomwareProtection()) {
        RansomwareShield::instance().setEnabled(true);
    }

    // 6. Inicjalizacja raportowania do Windows Security Center
    WindowsSecurityCenterProvider::instance().refreshStatus();

    // 7. Utworzenie serwera IPC dla interfejsu użytkownika
    setupIpcServer();

    m_engineRunning = true;
    Logger::info("AntivirusService: Usługa antywirusowa działa i nasłuchuje na kanale IPC.");
    return true;
}

void AntivirusService::stopEngine()
{
    if (!m_engineRunning) return;

    Logger::info("AntivirusService: Zatrzymywanie silnika antywirusowego...");

    RealTimeShield::instance().stop();
    RansomwareShield::instance().setEnabled(false);
    WindowsSecurityCenterProvider::instance().notifyShutdown();

    if (m_ipcServer) {
        m_ipcServer->close();
        delete m_ipcServer;
        m_ipcServer = nullptr;
    }

    m_engineRunning = false;
    Logger::info("AntivirusService: Silnik zatrzymany.");
}

void AntivirusService::setupIpcServer()
{
    if (m_ipcServer) {
        m_ipcServer->close();
        delete m_ipcServer;
    }

    m_ipcServer = new QLocalServer(this);
    QLocalServer::removeServer(IPC_PIPE_NAME);

    connect(m_ipcServer, &QLocalServer::newConnection,
            this, &AntivirusService::onNewIpcConnection);

    if (!m_ipcServer->listen(IPC_PIPE_NAME)) {
        Logger::warn(QStringLiteral("AntivirusService: Nie udało się uruchomić serwera IPC na pipe: %1. Błąd: %2")
                     .arg(IPC_PIPE_NAME, m_ipcServer->errorString()));
    } else {
        Logger::info(QStringLiteral("AntivirusService: Serwer IPC aktywny: %1").arg(IPC_PIPE_NAME));
    }
}

void AntivirusService::onNewIpcConnection()
{
    while (m_ipcServer && m_ipcServer->hasPendingConnections()) {
        QLocalSocket *sock = m_ipcServer->nextPendingConnection();
        connect(sock, &QLocalSocket::readyRead, this, &AntivirusService::onIpcReadyRead);
        connect(sock, &QLocalSocket::disconnected, this, &AntivirusService::onIpcDisconnected);
    }
}

void AntivirusService::onIpcReadyRead()
{
    auto *sock = qobject_cast<QLocalSocket*>(sender());
    if (!sock) return;

    while (sock->canReadLine()) {
        QString line = QString::fromUtf8(sock->readLine()).trimmed();
        if (!line.isEmpty()) {
            processIpcMessage(sock, line);
        }
    }
}

void AntivirusService::onIpcDisconnected()
{
    auto *sock = qobject_cast<QLocalSocket*>(sender());
    if (sock) {
        sock->deleteLater();
    }
}

void AntivirusService::processIpcMessage(QLocalSocket *socket, const QString &msg)
{
    if (!socket) return;

    if (msg == QStringLiteral("PING")) {
        socket->write("PONG\n");
        socket->flush();
        return;
    }

    if (msg == QStringLiteral("GET_STATUS")) {
        QJsonObject st = getStatusJson();
        QByteArray data = QJsonDocument(st).toJson(QJsonDocument::Compact) + "\n";
        socket->write(data);
        socket->flush();
        return;
    }

    if (msg == QStringLiteral("START_RTP")) {
        RealTimeShield::instance().start();
        socket->write("OK\n");
        socket->flush();
        return;
    }

    if (msg == QStringLiteral("STOP_RTP")) {
        RealTimeShield::instance().stop();
        socket->write("OK\n");
        socket->flush();
        return;
    }

    if (msg == QStringLiteral("TRIGGER_UPDATE")) {
        SignatureDb::instance().updateOnline(QStringLiteral("https://raw.githubusercontent.com/kacperjelinski1/multi-guard/main/signatures/update.json"));
        socket->write("OK\n");
        socket->flush();
        return;
    }

    socket->write("UNKNOWN_COMMAND\n");
    socket->flush();
}

QJsonObject AntivirusService::getStatusJson() const
{
    QJsonObject obj;
    obj[QStringLiteral("engine_running")]     = m_engineRunning;
    obj[QStringLiteral("rtp_running")]        = RealTimeShield::instance().isRunning();
    obj[QStringLiteral("rtp_enabled")]        = RealTimeShield::instance().isEnabled();
    obj[QStringLiteral("signatures_status")]  = SignatureDb::instance().statusString();
    obj[QStringLiteral("signatures_count")]   = SignatureDb::instance().totalSignatures();
    obj[QStringLiteral("signatures_date")]    = SignatureDb::instance().lastUpdate();
    obj[QStringLiteral("license_valid")]      = LicenseManager::instance().isValid();
    obj[QStringLiteral("license_tier")]       = LicenseManager::instance().tierName();
    obj[QStringLiteral("ransomware_enabled")] = RansomwareShield::instance().isEnabled();
    return obj;
}

QString AntivirusService::sendIpcCommand(const QString &cmd, int timeoutMs)
{
    QLocalSocket sock;
    sock.connectToServer(IPC_PIPE_NAME);
    if (!sock.waitForConnected(timeoutMs)) {
        return QString();
    }

    QByteArray sendData = cmd.toUtf8() + "\n";
    sock.write(sendData);
    sock.flush();

    if (!sock.waitForReadyRead(timeoutMs)) {
        return QString();
    }

    return QString::fromUtf8(sock.readLine()).trimmed();
}

} // namespace verax
