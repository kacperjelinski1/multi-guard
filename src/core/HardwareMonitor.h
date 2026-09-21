#pragma once

#include <QString>
#include <QObject>

#ifdef Q_OS_WIN
#include <windows.h>
#endif

namespace verax {

struct HardwareStats {
    double cpuUsagePercent = 0.0;
    QString cpuName;
    int cpuCores = 0;
    double cpuTempCelsius = 0.0; // -1 if not available

    qint64 ramUsedBytes = 0;
    qint64 ramTotalBytes = 0;
    double ramUsagePercent = 0.0;

    QString gpuName;
    qint64 gpuVramTotalBytes = 0;
    double gpuTempCelsius = 0.0; // -1 if not available
};

class HardwareMonitor : public QObject {
    Q_OBJECT
public:
    static HardwareMonitor& instance();

    HardwareStats refreshStats();
    HardwareStats lastStats() const { return m_lastStats; }

private:
    HardwareMonitor();

    HardwareStats m_lastStats;

#ifdef Q_OS_WIN
    FILETIME m_prevIdleTime;
    FILETIME m_prevKernelTime;
    FILETIME m_prevUserTime;
    bool m_firstRun = true;

    static quint64 fileTimeToUInt64(const FILETIME &ft);
    double queryCpuTemperature();
#endif
};

} // namespace verax
