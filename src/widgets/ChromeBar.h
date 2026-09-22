// ChromeBar.h - frameless drag bar with title + min/max/close
// By Ali Sakkaf - https://alisakkaf.com
#pragma once
#include <QWidget>
class QLabel;
class QPushButton;
class QLineEdit;
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
    void updateUserProfile(const QString &name, const QString &tier);

signals:
    void minimizeClicked();
    void maximizeClicked();
    void closeClicked();
    void updateClicked();
    void notificationsClicked();
    void featureNavRequested(int pageIndex);
    void userProfileClicked();

protected:
    void mousePressEvent(QMouseEvent *e) override;
    void mouseMoveEvent (QMouseEvent *e) override;
    void mouseReleaseEvent(QMouseEvent *e) override;
    void mouseDoubleClickEvent(QMouseEvent *e) override;
    bool eventFilter(QObject *watched, QEvent *event) override;

private:
    void setupSearchCompleter();

    QLabel       *m_logo             = nullptr;
    QLabel       *m_title            = nullptr;
    QLabel       *m_status           = nullptr;
    QLineEdit    *m_searchEdit       = nullptr;
    QPushButton  *m_btnUpdate        = nullptr;
    QPushButton  *m_btnNotifications = nullptr;
    QWidget      *m_userWidget       = nullptr;
    QLabel       *m_userNameLabel    = nullptr;
    QLabel       *m_userTierLabel    = nullptr;
    QPushButton  *m_btnMin           = nullptr;
    QPushButton  *m_btnMax           = nullptr;
    QPushButton  *m_btnClose         = nullptr;

    QPoint        m_dragOrigin;
    bool          m_dragging = false;
};

} // namespace verax
