#pragma once

#include <QObject>
#include <QString>
#include <QPointer>

class QNetworkAccessManager;
class QWidget;

namespace verax {

struct UpdateInfo {
    QString  latestVersion;     // e.g. "1.1.6.0"
    QString  changelog;         // release notes text
    QString  downloadUrl;       // direct installer .exe download URL
    QString  releasePageUrl;    // release webpage URL for browser fallback
    bool     valid = false;     // true only if the payload parsed cleanly
    bool     newer = false;     // true if latestVersion > APP_VERSION_STR
};

class Updater : public QObject {
    Q_OBJECT
public:
    static Updater& instance();

    // Silent background check on app startup (only alerts if newer version exists)
    void checkSilently(QWidget *uiOwner);

    // User-triggered check (e.g. from top bar button, Settings, or About)
    // Always provides visual feedback (toast/dialog) whether an update exists or not
    void checkExplicitly(QWidget *uiOwner);

    // Compare two dotted version strings ("1.1.5.0", "1.1.6.0")
    static int compareVersions(const QString &a, const QString &b);

    // Parse version.txt payload
    static UpdateInfo parseBody(const QString &body);

signals:
    void updateAvailable(const UpdateInfo &info);
    void noUpdate();
    void checkFailed(const QString &error);

private:
    explicit Updater(QObject *parent = nullptr);
    void runCheck();
    void showUpdateDialog(QWidget *parent, const UpdateInfo &info);

    QNetworkAccessManager *m_nam = nullptr;
    QPointer<QWidget>      m_owner;
    bool                   m_inFlight = false;
    bool                   m_explicit = false;
};

} // namespace verax
