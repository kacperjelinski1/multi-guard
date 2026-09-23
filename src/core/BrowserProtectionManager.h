#pragma once

#include <QObject>
#include <QString>
#include <QStringList>
#include <QMap>

namespace verax {

struct BrowserInfo {
    QString id;          // "chrome", "edge", "brave", "firefox"
    QString name;        // "Google Chrome", "Microsoft Edge", etc.
    bool    installed = false;
    bool    extensionActive = false;
    QString path;
};

class BrowserProtectionManager : public QObject {
    Q_OBJECT
public:
    static BrowserProtectionManager& instance();

    QList<BrowserInfo> detectedBrowsers();
    bool installExtension(const QString &browserId);
    bool installAll();

    QString extensionDirectory() const;

    int blockedWebsitesCount() const { return m_blockedWebsites; }
    int blockedDownloadsCount() const { return m_blockedDownloads; }
    void incrementBlockedWebsites() { ++m_blockedWebsites; }
    void incrementBlockedDownloads() { ++m_blockedDownloads; }

signals:
    void installationFinished(const QString &browserName, bool success, const QString &message);
    void protectionStatusChanged();

private:
    explicit BrowserProtectionManager(QObject *parent = nullptr);
    int m_blockedWebsites = 0;
    int m_blockedDownloads = 0;
};

} // namespace verax
