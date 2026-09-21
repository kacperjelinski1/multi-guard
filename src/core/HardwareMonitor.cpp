#include "HardwareMonitor.h"
#include "Logger.h"

#include <QThread>
#include <QSettings>

#ifdef Q_OS_WIN
#include <wbemidl.h>
#endif

namespace verax {

HardwareMonitor& HardwareMonitor::instance()
{
    static HardwareMonitor s_inst;
    return s_inst;
}

HardwareMonitor::HardwareMonitor()
{
#ifdef Q_OS_WIN
    ZeroMemory(&m_prevIdleTime, sizeof(FILETIME));
    ZeroMemory(&m_prevKernelTime, sizeof(FILETIME));
    ZeroMemory(&m_prevUserTime, sizeof(FILETIME));
#endif
    refreshStats();
}

#ifdef Q_OS_WIN
quint64 HardwareMonitor::fileTimeToUInt64(const FILETIME &ft)
{
    ULARGE_INTEGER uli;
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;
    return uli.QuadPart;
}

double HardwareMonitor::queryCpuTemperature()
{
    // Try reading MSAcpi_ThermalZoneTemperature via WMI
    double tempC = -1.0;
    IWbemLocator *pLoc = nullptr;
    IWbemServices *pSvc = nullptr;

    HRESULT hr = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER,
                                  IID_IWbemLocator, (LPVOID*)&pLoc);
    if (SUCCEEDED(hr) && pLoc) {
        BSTR bstrNamespace = SysAllocString(L"ROOT\\WMI");
        hr = pLoc->ConnectServer(bstrNamespace, nullptr, nullptr, 0, 0, 0, 0, &pSvc);
        SysFreeString(bstrNamespace);

        if (SUCCEEDED(hr) && pSvc) {
            CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
                              RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
                              nullptr, EOAC_NONE);

            BSTR bstrQuery = SysAllocString(L"SELECT CurrentTemperature FROM MSAcpi_ThermalZoneTemperature");
            BSTR bstrWQL = SysAllocString(L"WQL");
            IEnumWbemClassObject *pEnum = nullptr;

            hr = pSvc->ExecQuery(bstrWQL, bstrQuery,
                                 WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                                 nullptr, &pEnum);
            SysFreeString(bstrQuery);
            SysFreeString(bstrWQL);

            if (SUCCEEDED(hr) && pEnum) {
                IWbemClassObject *pclsObj = nullptr;
                ULONG uReturn = 0;
                if (pEnum->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn) == S_OK && uReturn > 0) {
                    VARIANT vtProp;
                    VariantInit(&vtProp);
                    if (SUCCEEDED(pclsObj->Get(L"CurrentTemperature", 0, &vtProp, 0, 0))) {
                        // Value is in tenths of Kelvin
                        double kelvinTenths = vtProp.lVal;
                        tempC = (kelvinTenths / 10.0) - 273.15;
                        VariantClear(&vtProp);
                    }
                    pclsObj->Release();
                }
                pEnum->Release();
            }
            pSvc->Release();
        }
        pLoc->Release();
    }
    return tempC;
}
#endif

HardwareStats HardwareMonitor::refreshStats()
{
    HardwareStats stats;
    stats.cpuCores = QThread::idealThreadCount();

#ifdef Q_OS_WIN
    // 1. CPU Usage
    FILETIME idleTime, kernelTime, userTime;
    if (GetSystemTimes(&idleTime, &kernelTime, &userTime)) {
        if (!m_firstRun) {
            quint64 idle = fileTimeToUInt64(idleTime) - fileTimeToUInt64(m_prevIdleTime);
            quint64 kernel = fileTimeToUInt64(kernelTime) - fileTimeToUInt64(m_prevKernelTime);
            quint64 user = fileTimeToUInt64(userTime) - fileTimeToUInt64(m_prevUserTime);
            quint64 sysTotal = kernel + user;

            if (sysTotal > 0) {
                stats.cpuUsagePercent = (1.0 - (double(idle) / double(sysTotal))) * 100.0;
                if (stats.cpuUsagePercent < 0.0) stats.cpuUsagePercent = 0.0;
                if (stats.cpuUsagePercent > 100.0) stats.cpuUsagePercent = 100.0;
            }
        }
        m_prevIdleTime = idleTime;
        m_prevKernelTime = kernelTime;
        m_prevUserTime = userTime;
        m_firstRun = false;
    }

    // 2. CPU Name
    QSettings regCpu("HKEY_LOCAL_MACHINE\\HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", QSettings::NativeFormat);
    stats.cpuName = regCpu.value("ProcessorNameString").toString().trimmed();
    if (stats.cpuName.isEmpty()) {
        stats.cpuName = QStringLiteral("Intel/AMD Processor (%1 Threads)").arg(stats.cpuCores);
    }

    // 3. CPU Temperature
    stats.cpuTempCelsius = queryCpuTemperature();

    // 4. RAM Usage
    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(MEMORYSTATUSEX);
    if (GlobalMemoryStatusEx(&memInfo)) {
        stats.ramTotalBytes = memInfo.ullTotalPhys;
        stats.ramUsedBytes = memInfo.ullTotalPhys - memInfo.ullAvailPhys;
        stats.ramUsagePercent = memInfo.dwMemoryLoad;
    }

    // 5. GPU Name and VRAM
    QSettings regGpu("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000", QSettings::NativeFormat);
    stats.gpuName = regGpu.value("DriverDesc").toString().trimmed();
    if (stats.gpuName.isEmpty()) {
        stats.gpuName = QStringLiteral("Karta graficzna GPU");
    }
    stats.gpuVramTotalBytes = regGpu.value("HardwareInformation.qwMemorySize").toLongLong();
    stats.gpuTempCelsius = -1.0; // Handled by OEM driver tools
#else
    // Fallback for non-Windows platforms (development/preview)
    stats.cpuName = QStringLiteral("Procesor (%1 rdzeni)").arg(stats.cpuCores);
    stats.cpuUsagePercent = 12.5;
    stats.ramTotalBytes = 16ULL * 1024 * 1024 * 1024;
    stats.ramUsedBytes = 6ULL * 1024 * 1024 * 1024;
    stats.ramUsagePercent = 37.5;
    stats.gpuName = QStringLiteral("Zintegrowany układ graficzny");
    stats.gpuVramTotalBytes = 4ULL * 1024 * 1024 * 1024;
#endif

    m_lastStats = stats;
    return stats;
}

} // namespace verax
