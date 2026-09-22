#pragma once

#include <QObject>
#include <QString>
#include <QJsonObject>
#include <memory>

class QLocalServer;
class QLocalSocket;

namespace verax {

/**
 * @brief AntivirusService
 * 
 * Niezależna usługa systemowa Multi-Guard (Windows Service).
 * Działa w tle (Session 0) niezależnie od zalogowanego użytkownika i bez otwartego GUI.
 * Odpowiada za:
 *  - Real-Time Shield (ochrona w czasie rzeczywistym),
 *  - Ransomware Shield (canary files),
 *  - Silnik skanujący (Scanner Engine),
 *  - Bazę sygnatur i automatyczne aktualizacje w tle,
 *  - Obsługę kwarantanny,
 *  - Warstwę integracji z Windows Security Center (WindowsSecurityCenterProvider),
 *  - Komunikację IPC z interfejsem użytkownika (Multi-Guard UI).
 */
class AntivirusService : public QObject {
    Q_OBJECT
public:
    static const QString SERVICE_NAME;
    static const QString SERVICE_DISPLAY_NAME;
    static const QString IPC_PIPE_NAME;

    static AntivirusService& instance();

    // Uruchomienie jako usługa Windows (SERVICE_TABLE_ENTRY) lub daemon headless
    static int runService(int argc, char *argv[]);

    // Zarządzanie usługą w systemie Windows (SCM)
    static bool installService(const QString &exePath = QString());
    static bool uninstallService();
    static bool startService();
    static bool stopService();
    static bool isServiceInstalled();
    static bool isServiceRunning();

    // Bezpośrednie uruchomienie logiki silnika usługi (headless event loop)
    bool startEngine();
    void stopEngine();

    // Sprawdzenie stanu usługi
    bool isEngineRunning() const { return m_engineRunning; }
    QJsonObject getStatusJson() const;

    // Klient IPC: wysłanie polecenia z GUI do usługi
    static QString sendIpcCommand(const QString &cmd, int timeoutMs = 3000);

private slots:
    void onNewIpcConnection();
    void onIpcReadyRead();
    void onIpcDisconnected();

private:
    explicit AntivirusService(QObject *parent = nullptr);
    ~AntivirusService() override;

    void setupIpcServer();
    void processIpcMessage(QLocalSocket *socket, const QString &msg);

    QLocalServer *m_ipcServer = nullptr;
    bool m_engineRunning = false;
};

} // namespace verax
