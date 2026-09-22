#pragma once

#include <QDialog>
#include <QLabel>
#include <QProgressBar>
#include <QPushButton>
#include <QTimer>
#include "../core/HardwareMonitor.h"

namespace verax {

class HardwareMonitorDialog : public QDialog {
    Q_OBJECT
public:
    explicit HardwareMonitorDialog(QWidget *parent = nullptr);
    ~HardwareMonitorDialog() override;

private slots:
    void updateTelemetry();
    void onCleanRamClicked();
    void onApplyTurboClicked();

private:
    void setupUi();

    QTimer       *m_timer      = nullptr;

    // CPU
    QLabel       *m_cpuNameLbl = nullptr;
    QLabel       *m_cpuCoresLbl= nullptr;
    QLabel       *m_cpuTempLbl = nullptr;
    QLabel       *m_cpuUsageLbl= nullptr;
    QProgressBar *m_pbCpu      = nullptr;

    // RAM
    QLabel       *m_ramUsageLbl= nullptr;
    QLabel       *m_ramFreeLbl = nullptr;
    QProgressBar *m_pbRam      = nullptr;
    QPushButton  *m_btnCleanRam= nullptr;

    // GPU
    QLabel       *m_gpuNameLbl = nullptr;
    QLabel       *m_gpuVramLbl = nullptr;
    QLabel       *m_gpuTempLbl = nullptr;

    // System
    QPushButton  *m_btnTurbo   = nullptr;
    QPushButton  *m_btnClose   = nullptr;
};

} // namespace verax
