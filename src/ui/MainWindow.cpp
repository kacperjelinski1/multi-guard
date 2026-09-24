#include "MainWindow.h"
#include "ui_mainwindow.h"
#include "../widgets/PageTransition.h"
#include "../widgets/ChromeBar.h"
#include <QTimer>

#ifdef Q_OS_WIN
#include <windows.h>
#endif

namespace verax {

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent), ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    setWindowFlags(Qt::Window | Qt::FramelessWindowHint | Qt::WindowMinimizeButtonHint);
    setAttribute(Qt::WA_TranslucentBackground, false);
    setFixedSize(1024, 720);

#ifdef Q_OS_WIN
    HWND hwnd = (HWND)winId();
    LONG style = GetWindowLong(hwnd, GWL_STYLE);
    SetWindowLong(hwnd, GWL_STYLE, (style | WS_MINIMIZEBOX) & ~(WS_CAPTION | WS_THICKFRAME | WS_MAXIMIZEBOX));
#endif

    m_transition = new PageTransition(ui->stackedWidget, this);

    // Wire up navigation
    connect(ui->navDashboard, &QPushButton::clicked, this, [this]{ setActiveNav(0); });
    connect(ui->navScanConfig, &QPushButton::clicked, this, [this]{ setActiveNav(1); });
    connect(ui->navBrowserProtection, &QPushButton::clicked, this, [this]{ setActiveNav(2); });
    connect(ui->navFirewall, &QPushButton::clicked, this, [this]{ setActiveNav(3); });
    connect(ui->navQuarantine, &QPushButton::clicked, this, [this]{ setActiveNav(4); });
    connect(ui->navTools, &QPushButton::clicked, this, [this]{ setActiveNav(5); });
    connect(ui->navRemoteRepair, &QPushButton::clicked, this, [this]{ setActiveNav(6); });
    connect(ui->navAccount, &QPushButton::clicked, this, [this]{ setActiveNav(7); });
    connect(ui->navSettings, &QPushButton::clicked, this, [this]{ setActiveNav(8); });
    
    // Go to dashboard by default
    setActiveNav(0);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::setActiveNav(int index)
{
    if (m_transition) {
        m_transition->setPage(index);
    } else {
        ui->stackedWidget->setCurrentIndex(index);
    }
}

} // namespace verax
