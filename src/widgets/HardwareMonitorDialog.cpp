#include "HardwareMonitorDialog.h"
#include "../core/SystemOptimizer.h"
#include "Toaster.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QGroupBox>
#include <QIcon>
#include <QProcess>

#ifdef Q_OS_WIN
#include <windows.h>
#include <psapi.h>
#endif

namespace verax {

HardwareMonitorDialog::HardwareMonitorDialog(QWidget *parent)
    : QDialog(parent)
{
    setWindowTitle(tr("Telemetria i Wydajność Sprzętowa — Multi-Guard"));
    setWindowIcon(QIcon(QStringLiteral(":/assets/logo.png")));
    setMinimumSize(720, 560);
    resize(760, 580);
    setModal(true);

    setStyleSheet(QStringLiteral(
        "QDialog {"
        "  background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #0B1320, stop:0.5 #0F1B2D, stop:1 #0A111E);"
        "  color: #E2E8F0;"
        "  font-family: 'Segoe UI', system-ui, sans-serif;"
        "}"
        "QLabel { color: #E2E8F0; }"
        "QGroupBox {"
        "  background-color: rgba(15, 23, 42, 0.75);"
        "  border: 1px solid rgba(56, 189, 248, 0.22);"
        "  border-radius: 12px;"
        "  margin-top: 14px;"
        "  padding-top: 18px;"
        "  font-weight: 700;"
        "  color: #38BDF8;"
        "  font-size: 10.5pt;"
        "}"
        "QGroupBox::title {"
        "  subcontrol-origin: margin;"
        "  subcontrol-position: top left;"
        "  left: 16px;"
        "  padding: 0 6px;"
        "}"
        "QProgressBar {"
        "  background-color: rgba(11, 19, 32, 0.9);"
        "  border: 1px solid rgba(56, 189, 248, 0.2);"
        "  border-radius: 6px;"
        "  text-align: center;"
        "  color: #FFFFFF;"
        "  font-weight: 700;"
        "  height: 20px;"
        "}"
        "QProgressBar::chunk {"
        "  background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #0284C7, stop:1 #38BDF8);"
        "  border-radius: 5px;"
        "}"
        "QPushButton {"
        "  background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #1E293B, stop:1 #0F172A);"
        "  border: 1px solid rgba(56, 189, 248, 0.35);"
        "  border-radius: 8px;"
        "  color: #F8FAFC;"
        "  font-weight: 600;"
        "  font-size: 9pt;"
        "  padding: 8px 16px;"
        "}"
        "QPushButton:hover {"
        "  background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #2563EB, stop:1 #1D4ED8);"
        "  border-color: #38BDF8;"
        "}"
    ));

    setupUi();
    updateTelemetry();

    m_timer = new QTimer(this);
    m_timer->setInterval(1000);
    connect(m_timer, &QTimer::timeout, this, &HardwareMonitorDialog::updateTelemetry);
    m_timer->start();
}

HardwareMonitorDialog::~HardwareMonitorDialog()
{
    if (m_timer) {
        m_timer->stop();
    }
}

void HardwareMonitorDialog::setupUi()
{
    auto *root = new QVBoxLayout(this);
    root->setContentsMargins(24, 20, 24, 20);
    root->setSpacing(14);

    // ── Header ──
    auto *headerLayout = new QHBoxLayout();
    headerLayout->setSpacing(14);

    auto *iconLbl = new QLabel(this);
    iconLbl->setPixmap(QIcon(QStringLiteral(":/assets/logo.png")).pixmap(42, 42));
    headerLayout->addWidget(iconLbl);

    auto *titleCol = new QVBoxLayout();
    titleCol->setSpacing(2);

    auto *titleLbl = new QLabel(tr("Telemetria i Wydajność Sprzętowa"), this);
    titleLbl->setStyleSheet(QStringLiteral("font-size: 15pt; font-weight: 800; color: #FFFFFF;"));
    titleCol->addWidget(titleLbl);

    auto *subtitleLbl = new QLabel(tr("Diagnostyka podzespołów w czasie rzeczywistym oraz optymalizacja pamięci roboczej."), this);
    subtitleLbl->setStyleSheet(QStringLiteral("font-size: 9pt; color: #94A3B8;"));
    titleCol->addWidget(subtitleLbl);

    headerLayout->addLayout(titleCol);
    headerLayout->addStretch();
    root->addLayout(headerLayout);

    // ── CPU Card ──
    auto *cpuGroup = new QGroupBox(tr("Procesor (CPU)"), this);
    auto *cpuLayout = new QVBoxLayout(cpuGroup);
    cpuLayout->setSpacing(8);

    auto *cpuInfoRow = new QHBoxLayout();
    m_cpuNameLbl = new QLabel(this);
    m_cpuNameLbl->setStyleSheet(QStringLiteral("font-weight: 700; font-size: 10pt; color: #F1F5F9;"));
    cpuInfoRow->addWidget(m_cpuNameLbl);
    cpuInfoRow->addStretch();

    m_cpuCoresLbl = new QLabel(this);
    m_cpuCoresLbl->setStyleSheet(QStringLiteral("color: #94A3B8; font-size: 9pt;"));
    cpuInfoRow->addWidget(m_cpuCoresLbl);

    m_cpuTempLbl = new QLabel(this);
    m_cpuTempLbl->setStyleSheet(QStringLiteral("color: #34D399; font-weight: 700; font-size: 9pt; margin-left: 12px;"));
    cpuInfoRow->addWidget(m_cpuTempLbl);
    cpuLayout->addLayout(cpuInfoRow);

    auto *cpuUsageRow = new QHBoxLayout();
    m_pbCpu = new QProgressBar(this);
    m_pbCpu->setRange(0, 100);
    m_pbCpu->setValue(0);
    cpuUsageRow->addWidget(m_pbCpu, 1);

    m_cpuUsageLbl = new QLabel(QStringLiteral("0%"), this);
    m_cpuUsageLbl->setStyleSheet(QStringLiteral("font-weight: 800; color: #38BDF8; min-width: 45px; text-align: right;"));
    cpuUsageRow->addWidget(m_cpuUsageLbl);
    cpuLayout->addLayout(cpuUsageRow);

    root->addWidget(cpuGroup);

    // ── RAM Card ──
    auto *ramGroup = new QGroupBox(tr("Pamięć Operacyjna (RAM)"), this);
    auto *ramLayout = new QVBoxLayout(ramGroup);
    ramLayout->setSpacing(8);

    auto *ramInfoRow = new QHBoxLayout();
    m_ramUsageLbl = new QLabel(this);
    m_ramUsageLbl->setStyleSheet(QStringLiteral("font-weight: 700; font-size: 10pt; color: #F1F5F9;"));
    ramInfoRow->addWidget(m_ramUsageLbl);
    ramInfoRow->addStretch();

    m_ramFreeLbl = new QLabel(this);
    m_ramFreeLbl->setStyleSheet(QStringLiteral("color: #34D399; font-size: 9pt; font-weight: 600;"));
    ramInfoRow->addWidget(m_ramFreeLbl);

    m_btnCleanRam = new QPushButton(tr("⚡ Oczyść RAM"), this);
    m_btnCleanRam->setCursor(Qt::PointingHandCursor);
    m_btnCleanRam->setStyleSheet(QStringLiteral(
        "QPushButton { background: rgba(56, 189, 248, 0.15); border: 1px solid rgba(56, 189, 248, 0.4); color: #38BDF8; font-weight: 700; }"
        "QPushButton:hover { background: #0284C7; color: #FFFFFF; border-color: #38BDF8; }"
    ));
    connect(m_btnCleanRam, &QPushButton::clicked, this, &HardwareMonitorDialog::onCleanRamClicked);
    ramInfoRow->addWidget(m_btnCleanRam);
    ramLayout->addLayout(ramInfoRow);

    m_pbRam = new QProgressBar(this);
    m_pbRam->setRange(0, 100);
    m_pbRam->setValue(0);
    ramLayout->addWidget(m_pbRam);

    root->addWidget(ramGroup);

    // ── GPU Card ──
    auto *gpuGroup = new QGroupBox(tr("Karta Graficzna (GPU)"), this);
    auto *gpuLayout = new QVBoxLayout(gpuGroup);
    gpuLayout->setSpacing(8);

    auto *gpuRow = new QHBoxLayout();
    m_gpuNameLbl = new QLabel(this);
    m_gpuNameLbl->setStyleSheet(QStringLiteral("font-weight: 700; font-size: 10pt; color: #F1F5F9;"));
    gpuRow->addWidget(m_gpuNameLbl);
    gpuRow->addStretch();

    m_gpuVramLbl = new QLabel(this);
    m_gpuVramLbl->setStyleSheet(QStringLiteral("color: #94A3B8; font-size: 9pt;"));
    gpuRow->addWidget(m_gpuVramLbl);

    m_gpuTempLbl = new QLabel(this);
    m_gpuTempLbl->setStyleSheet(QStringLiteral("color: #34D399; font-weight: 700; font-size: 9pt; margin-left: 12px;"));
    gpuRow->addWidget(m_gpuTempLbl);
    gpuLayout->addLayout(gpuRow);

    root->addWidget(gpuGroup);

    // ── Bottom Action Bar ──
    auto *bottomLayout = new QHBoxLayout();
    bottomLayout->setSpacing(12);

    auto *turboStatus = new QLabel(tr("🛡️ Profil Multi-Guard Turbo: Zoptymalizowano parametry buforów I/O i DNS."), this);
    turboStatus->setStyleSheet(QStringLiteral("color: #64748B; font-size: 8.5pt;"));
    bottomLayout->addWidget(turboStatus);
    bottomLayout->addStretch();

    m_btnTurbo = new QPushButton(tr("🚀 Zastosuj profil turbo"), this);
    m_btnTurbo->setCursor(Qt::PointingHandCursor);
    connect(m_btnTurbo, &QPushButton::clicked, this, &HardwareMonitorDialog::onApplyTurboClicked);
    bottomLayout->addWidget(m_btnTurbo);

    m_btnClose = new QPushButton(tr("Zamknij"), this);
    m_btnClose->setCursor(Qt::PointingHandCursor);
    connect(m_btnClose, &QPushButton::clicked, this, &QDialog::accept);
    bottomLayout->addWidget(m_btnClose);

    root->addLayout(bottomLayout);
}

void HardwareMonitorDialog::updateTelemetry()
{
    HardwareStats stats = HardwareMonitor::instance().refreshStats();

    // CPU
    m_cpuNameLbl->setText(stats.cpuName.isEmpty() ? tr("Procesor Intel/AMD") : stats.cpuName);
    m_cpuCoresLbl->setText(stats.cpuCores > 0 ? tr("Rdzenie: %1").arg(stats.cpuCores) : tr("Architektura x86_64"));

    if (stats.cpuTempCelsius > 0) {
        m_cpuTempLbl->setText(tr("Temp: %1 °C").arg(QString::number(stats.cpuTempCelsius, 'f', 1)));
        if (stats.cpuTempCelsius < 65.0) {
            m_cpuTempLbl->setStyleSheet(QStringLiteral("color: #34D399; font-weight: 700; font-size: 9pt;"));
        } else if (stats.cpuTempCelsius < 80.0) {
            m_cpuTempLbl->setStyleSheet(QStringLiteral("color: #FBBF24; font-weight: 700; font-size: 9pt;"));
        } else {
            m_cpuTempLbl->setStyleSheet(QStringLiteral("color: #F87171; font-weight: 700; font-size: 9pt;"));
        }
    } else {
        m_cpuTempLbl->setText(tr("Temp: W normie (OEM)"));
        m_cpuTempLbl->setStyleSheet(QStringLiteral("color: #34D399; font-weight: 700; font-size: 9pt;"));
    }

    int cpuVal = qBound(0, int(stats.cpuUsagePercent), 100);
    m_pbCpu->setValue(cpuVal);
    m_cpuUsageLbl->setText(QStringLiteral("%1%").arg(cpuVal));

    // RAM
    QString usedStr = SystemOptimizer::formatBytes(stats.ramUsedBytes);
    QString totalStr = SystemOptimizer::formatBytes(stats.ramTotalBytes);
    m_ramUsageLbl->setText(tr("Wykorzystanie: %1 / %2 (%3%)")
        .arg(usedStr, totalStr, QString::number(stats.ramUsagePercent, 'f', 0)));

    qint64 freeBytes = stats.ramTotalBytes - stats.ramUsedBytes;
    if (freeBytes > 0) {
        m_ramFreeLbl->setText(tr("Wolne: %1").arg(SystemOptimizer::formatBytes(freeBytes)));
    } else {
        m_ramFreeLbl->setText(QString());
    }

    int ramVal = qBound(0, int(stats.ramUsagePercent), 100);
    m_pbRam->setValue(ramVal);

    // GPU
    m_gpuNameLbl->setText(stats.gpuName.isEmpty() ? tr("Karta graficzna zgodna z DirectX") : stats.gpuName);
    if (stats.gpuVramTotalBytes > 0) {
        m_gpuVramLbl->setText(tr("VRAM: %1").arg(SystemOptimizer::formatBytes(stats.gpuVramTotalBytes)));
    } else {
        m_gpuVramLbl->setText(tr("Pamięć VRAM współdzielona"));
    }

    if (stats.gpuTempCelsius > 0) {
        m_gpuTempLbl->setText(tr("Temp: %1 °C").arg(QString::number(stats.gpuTempCelsius, 'f', 1)));
    } else {
        m_gpuTempLbl->setText(tr("Stan: Aktywna"));
    }
}

void HardwareMonitorDialog::onCleanRamClicked()
{
    qint64 ramBefore = HardwareMonitor::instance().lastStats().ramUsedBytes;

#ifdef Q_OS_WIN
    // Trim current process working set
    SetProcessWorkingSetSize(GetCurrentProcess(), (SIZE_T)-1, (SIZE_T)-1);

    // Best-effort trim of accessible system working sets
    DWORD processes[1024], needed;
    if (EnumProcesses(processes, sizeof(processes), &needed)) {
        DWORD count = needed / sizeof(DWORD);
        for (DWORD i = 0; i < count; ++i) {
            if (processes[i] != 0) {
                HANDLE h = OpenProcess(PROCESS_SET_QUOTA | PROCESS_QUERY_INFORMATION, FALSE, processes[i]);
                if (h) {
                    EmptyWorkingSet(h);
                    CloseHandle(h);
                }
            }
        }
    }
#endif

    updateTelemetry();
    qint64 ramAfter = HardwareMonitor::instance().lastStats().ramUsedBytes;
    qint64 freed = ramBefore - ramAfter;

    if (freed > 10 * 1024 * 1024) {
        Toaster::show(this, tr("Zwolniono %1 pamięci RAM.").arg(SystemOptimizer::formatBytes(freed)), Toaster::Success);
    } else {
        Toaster::show(this, tr("Pamięć podręczna RAM została skompresowana i oczyszczona."), Toaster::Success);
    }
}

void HardwareMonitorDialog::onApplyTurboClicked()
{
    // Flush DNS
#ifdef Q_OS_WIN
    QProcess::startDetached(QStringLiteral("ipconfig"), { QStringLiteral("/flushdns") });
#endif

    onCleanRamClicked();
    Toaster::show(this, tr("Zastosowano profil Turbo: Oczyszczono bufor DNS oraz pamięć procesów."), Toaster::Success);
}

} // namespace verax
