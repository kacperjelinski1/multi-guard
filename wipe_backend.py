import os
import shutil

# 1. Update Verax.pro
pro_file = 'Verax.pro'
with open(pro_file, 'r') as f:
    lines = f.readlines()

new_lines = []
skip_mode = False
for line in lines:
    if 'src/core/' in line:
        if 'Settings' in line or 'Logger' in line or 'Translator' in line:
            new_lines.append(line)
        else:
            # Skip this line
            continue
    else:
        new_lines.append(line)

with open(pro_file, 'w') as f:
    f.writelines(new_lines)

# 2. Delete core files
core_dir = 'src/core'
for item in os.listdir(core_dir):
    if not (item.startswith('Settings') or item.startswith('Logger') or item.startswith('Translator')):
        os.remove(os.path.join(core_dir, item))

# 3. Rewrite MainWindow.h
h_content = """#pragma once

#include <QMainWindow>
#include <QSystemTrayIcon>

namespace Ui {
class MainWindow;
}

namespace verax {

class PageTransition;

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private:
    Ui::MainWindow *ui;
    PageTransition *m_transition = nullptr;

    void setActiveNav(int index);
};

} // namespace verax
"""
with open('src/ui/MainWindow.h', 'w') as f:
    f.write(h_content)

# 4. Rewrite MainWindow.cpp
cpp_content = """#include "MainWindow.h"
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
"""
with open('src/ui/MainWindow.cpp', 'w') as f:
    f.write(cpp_content)

# 5. Rewrite main.cpp
main_content = """#include <QApplication>
#include <QFontDatabase>
#include "src/ui/MainWindow.h"
#include "src/core/Logger.h"
#include "src/core/Settings.h"
#include "src/core/Translator.h"
#include "src/utils/ThemeManager.h"
#include "harden.h"

int main(int argc, char *argv[])
{
    shield::harden();
    QCoreApplication::setAttribute(Qt::AA_EnableHighDpiScaling);
    QCoreApplication::setAttribute(Qt::AA_UseHighDpiPixmaps);

    QApplication a(argc, argv);

    verax::Logger::init();
    verax::Settings::instance().load();
    verax::Translator::instance().install(verax::Settings::instance().language());
    verax::ThemeManager::applyTheme();

    verax::MainWindow w;
    w.show();

    return a.exec();
}
"""
with open('main.cpp', 'w') as f:
    f.write(main_content)

print("Done wiping backend!")
