// Settings.h - QSettings facade + startup-with-Windows + schedule
// By Ali Sakkaf - https://alisakkaf.com
#pragma once
#include <QObject>
#include <QString>
#include <QStandardPaths>
namespace verax {

class Settings : public QObject {
    Q_OBJECT
public:
    static Settings& instance();

    void load();
    void save();

    // General
    QString language() const                 { return m_language; }
    void    setLanguage(const QString &code);

    QString theme() const                    { return m_theme; }
    void    setTheme(const QString &theme);

    bool    startWithWindows() const         { return m_startWithWindows; }
    void    setStartWithWindows(bool v);

    bool    contextMenuIntegration() const   { return m_contextMenu; }
    void    setContextMenuIntegration(bool v);

    bool    realTimeProtection() const       { return m_realTimeProtection; }
    void    setRealTimeProtection(bool v);

    bool    ransomwareProtection() const     { return m_ransomwareProtection; }
    void    setRansomwareProtection(bool v);

    bool    webShield() const                { return m_webShield; }
    void    setWebShield(bool v);

    QStringList exclusions() const           { return m_exclusions; }
    void    addExclusion(const QString &path);
    void    removeExclusion(const QString &path);
    bool    isExcluded(const QString &path) const;

    bool    minimizeToTrayOnClose() const    { return m_trayOnClose; }
    void    setMinimizeToTrayOnClose(bool v) { m_trayOnClose = v; save(); }

    bool    showNotifications() const        { return m_showNotifications; }
    void    setShowNotifications(bool v)     { m_showNotifications = v; save(); }

    // Scanning
    bool    scanUsbOnInsert() const          { return m_scanUsbOnInsert; }
    void    setScanUsbOnInsert(bool v)       { m_scanUsbOnInsert = v; save(); }

    QString scheduledScan() const            { return m_scheduledScan; }
    void    setScheduledScan(const QString &v) { m_scheduledScan = v; save(); }

    QString scheduledTime() const            { return m_scheduledTime; }
    void    setScheduledTime(const QString &v) { m_scheduledTime = v; save(); }

    // Updates
    bool    autoUpdateSignatures() const     { return m_autoUpdate; }
    void    setAutoUpdateSignatures(bool v)  { m_autoUpdate = v; save(); }

    QString updateUrl() const                { return m_updateUrl; }
    void    setUpdateUrl(const QString &v)   { m_updateUrl = v; save(); }

    // Scan engine toggles
    bool    useSignatureDb() const           { return m_useSigDb; }
    void    setUseSignatureDb(bool v)        { m_useSigDb = v; save(); }
    bool    usePeInspection() const          { return m_usePe; }
    void    setUsePeInspection(bool v)       { m_usePe = v; save(); }
    bool    useHeuristics() const            { return m_useHeur; }
    void    setUseHeuristics(bool v)         { m_useHeur = v; save(); }
    bool    useCloudLookup() const           { return m_useCloud; }
    void    setUseCloudLookup(bool v)        { m_useCloud = v; save(); }

    // Threshold
    int     heuristicThreshold() const       { return m_heurThreshold; }
    void    setHeuristicThreshold(int v)     { m_heurThreshold = v; save(); }

    QString detectionAction() const          { return m_detectionAction; } // quarantine|delete|report
    void    setDetectionAction(const QString &v) { m_detectionAction = v; save(); }

    // Reset
    void    resetAll();

signals:
    void languageChanged(const QString &code);

private:
    explicit Settings(QObject *parent = nullptr);
    void applyStartupRegistry();
    void applyContextMenuRegistry();

    QString m_language          = QStringLiteral("pl");
    QString m_theme             = QStringLiteral("dark");
    bool    m_startWithWindows  = false;
    bool    m_contextMenu       = false;
    bool        m_realTimeProtection= true;
    bool        m_ransomwareProtection = true;
    bool        m_webShield         = false;
    bool        m_trayOnClose       = true;
    bool        m_showNotifications = true;
    QStringList m_exclusions;

    bool    m_scanUsbOnInsert   = true;
    QString m_scheduledScan     = QStringLiteral("off");
    QString m_scheduledTime     = QStringLiteral("03:00");

    bool    m_autoUpdate        = true;
    QString m_updateUrl;

    bool    m_useSigDb          = true;
    bool    m_usePe             = true;
    bool    m_useHeur           = true;
    bool    m_useCloud          = false;

    int     m_heurThreshold     = 60;
    QString m_detectionAction   = QStringLiteral("report");
};

} // namespace verax
