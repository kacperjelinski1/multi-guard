#pragma once

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
