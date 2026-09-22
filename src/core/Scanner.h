#pragma once

#include <QObject>
#include <QStringList>
#include <QAtomicInt>
#include <QHash>
#include <QMutex>
#include "SignatureDb.h"

namespace verax {

struct ScanRequest {
    bool useSigDb = true;
    bool usePe = true;
    bool useHeur = true;
    bool useCloud = false;
    int threshold = 50;
    QString action = "report"; // "quarantine", "delete", "report", "repair"
    QStringList targets;
    QStringList extensionFilter;
    qint64 maxFileBytes = 100LL * 1024 * 1024;
};

struct ThreatInfo {
    QString path;
    QString sha256;
    QString detectionName;
    QString family;
    QString reason;
    int severity = 0;
    int score = 0;
    qint64 size = 0;
    bool repairable = false;
    QString repairMethod;
    QString entryPointPatch;
};

struct ScanReport {
    qint64 startedAt = 0;
    qint64 finishedAt = 0;
    int filesScanned = 0;
    int threatsFound = 0;
};

class Scanner : public QObject {
    Q_OBJECT
public:
    explicit Scanner(QObject *parent = nullptr);
    ~Scanner();

    void request(const ScanRequest &req);
    void requestStop();
    void requestPause(bool p);

    bool isRunning() const { return m_running.loadAcquire() != 0; }

    // === Advanced Clean Threat / Repair (public for UI direct call) ===
    bool advancedCleanThreat(const QString &path, ThreatInfo &info);
    int  inspectFile(const QString &path, const ScanRequest &req, ThreatInfo &info);
    static bool verifyAuthenticode(const QString &path);
    static int  scanWithWindowsDefender(const QString &path, ThreatInfo &info);
    static bool scanBufferWithAmsi(const uchar *data, qint64 size, const QString &contentName, ThreatInfo &info);

signals:
    void started();
    void progress(int pct, qint64 done, qint64 total);
    void fileScanned(const QString &path);
    void threatFound(ThreatInfo info);
    void finished(ScanReport report);
    void error(const QString &msg);

private:
    void runOn(const ScanRequest &req);
    void enumerate(const QString &target, QStringList &out, const QStringList &exts);
    int peHeuristics(const QString &path, ThreatInfo &info);
    int scriptHeuristics(const QString &path, ThreatInfo &info);
    int documentHeuristics(const QString &path, ThreatInfo &info);
    int archiveHeuristics(const QString &path, ThreatInfo &info);
    bool disinfectPE(const QString &path);
    bool cloudLookup(const QString &hash, ThreatInfo &info);

    // === Advanced PE Analysis ===
    int  detectFloxifFamily(const uchar *base, qint64 mapSize, quint32 epRva,
                            const void *secHdr, int numSections, ThreatInfo &info);
    int  detectMikcerFamily(const uchar *base, qint64 mapSize, quint32 epRva,
                            const void *secHdr, int numSections, ThreatInfo &info);
    int  detectSalityFamily(const uchar *base, qint64 mapSize, quint32 epRva,
                            const void *secHdr, int numSections, ThreatInfo &info);
    int  detectVirutFamily(const uchar *base, qint64 mapSize, quint32 epRva,
                           const void *secHdr, int numSections, ThreatInfo &info);
    int  detectRamnitFamily(const uchar *base, qint64 mapSize, quint32 epRva,
                            const void *secHdr, int numSections, ThreatInfo &info);
    int  detectNeshtaFamily(const uchar *base, qint64 mapSize, quint32 epRva,
                            const void *secHdr, int numSections, ThreatInfo &info);
    int  detectExpiroFamily(const uchar *base, qint64 mapSize, quint32 epRva,
                            const void *secHdr, int numSections, ThreatInfo &info);
    int  detectEntryPointAnomaly(const uchar *base, qint64 mapSize, quint32 epRva,
                                 const void *secHdr, int numSections, bool is64, ThreatInfo &info);
    int  detectCodeCaveInjection(const uchar *base, qint64 mapSize,
                                  const void *secHdr, int numSections, ThreatInfo &info);
    int  detectOverlayPayload(qint64 fileSize, qint64 maxSectionEnd,
                               quint32 sizeOfImage, ThreatInfo &info);
    int  detectByteSignatures(const uchar *base, qint64 mapSize, quint32 epRva, const void *secHdrV, int numSections, ThreatInfo &info);
    int  detectIATHooks(const uchar *base, qint64 mapSize, quint32 numDirs,
                        const void *dataDirs, const void *secHdr, int numSections, ThreatInfo &info);

    // === Advanced Repair internals ===
    bool killProcessesUsingFile(const QString &path);
    bool setFullPermissions(const QString &path);
    bool repairEntryPoint(uchar *base, qint64 fileSize, bool is64,
                          const QString &epPatchHex, quint32 epRva, const void *secHdr, int numSections);
    bool truncateOverlay(const QString &path, qint64 legitEnd);
    bool recalcPeChecksum(uchar *base, qint64 fileSize, bool is64);
    bool backupBeforeRepair(const QString &path);
    bool detectOriginalPrologue(const uchar *base, qint64 mapSize, quint32 epRva,
                                const void *secHdr, int numSections, bool is64, QByteArray &outPrologue);

    QAtomicInt m_stop{0};
    QAtomicInt m_pause{0};
    QAtomicInt m_running{0};
    int        m_cloudCallsThisScan = 0; // capped per-scan to avoid stalls
    bool       m_cloudErrorWarned   = false; // log only the first network error
    QList<ByteSig> m_byteSignatures; // loaded once per scan

    static QMutex                     s_cloudMutex;
    static QHash<QString, ThreatInfo> s_cloudCache;
};

} // namespace verax
