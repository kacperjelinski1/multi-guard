#pragma once

#include <QWidget>
#include <QString>
#include <functional>

class QLabel;
class QPushButton;
class QTimer;
class QPropertyAnimation;

namespace verax {

class NotificationAlert : public QWidget {
    Q_OBJECT
public:
    enum AlertType {
        Threat,
        UsbDevice,
        Information
    };

    static void showThreat(const QString &threatName, const QString &filePath,
                           std::function<void()> onQuarantine = nullptr,
                           std::function<void()> onDeletePermanent = nullptr,
                           std::function<void()> onIgnore = nullptr);

    static void showUsb(const QString &drivePath,
                        std::function<void()> onScan = nullptr,
                        std::function<void()> onOpenSafely = nullptr,
                        std::function<void()> onIgnore = nullptr);

    static void showInfo(const QString &title, const QString &message);

protected:
    void enterEvent(QEvent *e) override;
    void leaveEvent(QEvent *e) override;

private:
    NotificationAlert(AlertType type, const QString &title, const QString &subtitle,
                      const QString &details,
                      const QString &actionText, std::function<void()> actionCb,
                      const QString &secondaryText = QString(), std::function<void()> secondaryCb = nullptr,
                      const QString &tertiaryText = QString(), std::function<void()> tertiaryCb = nullptr);

    void setupUi(AlertType type, const QString &title, const QString &subtitle,
                 const QString &details,
                 const QString &actionText, std::function<void()> actionCb,
                 const QString &secondaryText, std::function<void()> secondaryCb,
                 const QString &tertiaryText, std::function<void()> tertiaryCb);

    void repositionAndAnimate();

    QTimer *m_autoCloseTimer = nullptr;
    QPropertyAnimation *m_anim = nullptr;
    AlertType m_type = Information;
};

} // namespace verax
