// ChromeBar.h - frameless drag bar with title + min/max/close
// By Ali Sakkaf - https://alisakkaf.com
#pragma once
#include <QWidget>
class QLabel;
class QPushButton;
class QHBoxLayout;

namespace verax {

class ChromeBar : public QWidget {
    Q_OBJECT
public:
    explicit ChromeBar(QWidget *parent = nullptr);
    void setTitle(const QString &t);
    void setStatusText(const QString &s);
    void setStatusKind(const QString &kind); // idle|scanning|threat
    void updateMaximizeIcon(bool isMaximized);

signals:
    void minimizeClicked();
    void maximizeClicked();
    void closeClicked();
    void updateClicked();
    void notificationsClicked();

protected:
    void mousePressEvent(QMouseEvent *e) override;
    void mouseMoveEvent (QMouseEvent *e) override;
    void mouseReleaseEvent(QMouseEvent *e) override;
    void mouseDoubleClickEvent(QMouseEvent *e) override;

private:
    QLabel       *m_logo             = nullptr;
    QLabel       *m_title            = nullptr;
    QLabel       *m_status           = nullptr;
    QPushButton  *m_btnUpdate        = nullptr;
    QPushButton  *m_btnNotifications = nullptr;
    QPushButton  *m_btnMin           = nullptr;
    QPushButton  *m_btnClose         = nullptr;

    QPoint        m_dragOrigin;
    bool          m_dragging = false;
};

} // namespace verax
