#include "NotificationAlert.h"
#include "../utils/ThemeManager.h"

#include <QApplication>
#include <QScreen>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QTimer>
#include <QPropertyAnimation>
#include <QGraphicsOpacityEffect>
#include <QIcon>
#include <QPixmap>
#include <QFont>

namespace verax {

NotificationAlert::NotificationAlert(AlertType type, const QString &title, const QString &subtitle,
                                     const QString &details,
                                     const QString &actionText, std::function<void()> actionCb,
                                     const QString &secondaryText, std::function<void()> secondaryCb)
    : QWidget(nullptr, Qt::FramelessWindowHint | Qt::WindowStaysOnTopHint | Qt::Tool | Qt::NoDropShadowWindowHint)
{
    setAttribute(Qt::WA_TranslucentBackground);
    setAttribute(Qt::WA_DeleteOnClose);
    setupUi(type, title, subtitle, details, actionText, actionCb, secondaryText, secondaryCb);
}

void NotificationAlert::setupUi(AlertType type, const QString &title, const QString &subtitle,
                                 const QString &details,
                                 const QString &actionText, std::function<void()> actionCb,
                                 const QString &secondaryText, std::function<void()> secondaryCb)
{
    m_type = type;
    const bool isUsb = (type == UsbDevice);
    setFixedWidth(isUsb ? 520 : 440);

    QString accentColor = "#00e676";
    QString headerIcon = "🛡";
    if (type == Threat) {
        accentColor = "#ff4d4f";
        headerIcon = "⚠️";
    } else if (type == UsbDevice) {
        accentColor = "#2563eb";
        headerIcon = "🔌";
    }

    bool isDark = ThemeManager::isDark();

    auto *rootCard = new QWidget(this);
    rootCard->setObjectName("alertCard");
    rootCard->setStyleSheet(ThemeManager::alertStyleSheet(accentColor));

    auto *mainLayout = new QVBoxLayout(rootCard);
    mainLayout->setContentsMargins(isUsb ? 20 : 16, isUsb ? 18 : 14, isUsb ? 20 : 16, isUsb ? 18 : 14);
    mainLayout->setSpacing(isUsb ? 12 : 8);

    // Top Header Row
    auto *topRow = new QHBoxLayout();
    topRow->setSpacing(10);

    auto *lblIcon = new QLabel(headerIcon, rootCard);
    QFont iconFont = lblIcon->font();
    iconFont.setPointSize(isUsb ? 24 : 16);
    lblIcon->setFont(iconFont);

    auto *lblTitle = new QLabel(title, rootCard);
    QFont titleFont = lblTitle->font();
    titleFont.setBold(true);
    titleFont.setPointSize(isUsb ? 13 : 11);
    lblTitle->setFont(titleFont);
    lblTitle->setStyleSheet(QString("color: %1; font-weight: bold;").arg(accentColor));

    auto *btnDismiss = new QPushButton("✕", rootCard);
    btnDismiss->setFixedSize(26, 26);
    btnDismiss->setCursor(Qt::PointingHandCursor);
    btnDismiss->setStyleSheet(isDark
        ? "QPushButton { background: transparent; color: #8c93a0; border: none; font-size: 14px; font-weight: bold; }"
          "QPushButton:hover { color: #ffffff; background: rgba(255, 255, 255, 0.12); border-radius: 13px; }"
        : "QPushButton { background: transparent; color: #64748b; border: none; font-size: 14px; font-weight: bold; }"
          "QPushButton:hover { color: #0f172a; background: rgba(0, 0, 0, 0.08); border-radius: 13px; }");
    connect(btnDismiss, &QPushButton::clicked, this, &QWidget::close);

    topRow->addWidget(lblIcon);
    topRow->addWidget(lblTitle, 1);
    topRow->addWidget(btnDismiss);
    mainLayout->addLayout(topRow);

    // Subtitle
    auto *lblSub = new QLabel(subtitle, rootCard);
    lblSub->setWordWrap(true);
    lblSub->setStyleSheet(isDark
        ? (isUsb ? "color: #f1f5f9; font-size: 13px; font-weight: 600;" : "color: #e0e4ec; font-size: 12px; font-weight: 500;")
        : (isUsb ? "color: #0f172a; font-size: 13px; font-weight: 600;" : "color: #334155; font-size: 12px; font-weight: 500;"));
    mainLayout->addWidget(lblSub);

    // Details if any (e.g. file path)
    if (!details.isEmpty()) {
        auto *lblDet = new QLabel(details, rootCard);
        lblDet->setWordWrap(true);
        lblDet->setStyleSheet(isDark
            ? (isUsb ? "color: #94a3b8; font-size: 12px; font-family: monospace; background: rgba(0,0,0,0.4); padding: 8px 10px; border-radius: 6px;"
                     : "color: #94a3b8; font-size: 11px; font-family: monospace; background: rgba(0,0,0,0.3); padding: 4px 6px; border-radius: 4px;")
            : (isUsb ? "color: #334155; font-size: 12px; font-family: monospace; background: rgba(0,0,0,0.08); padding: 8px 10px; border-radius: 6px;"
                     : "color: #475569; font-size: 11px; font-family: monospace; background: rgba(0,0,0,0.06); padding: 4px 6px; border-radius: 4px;"));
        mainLayout->addWidget(lblDet);
    }

    // Action Buttons
    if (!actionText.isEmpty() || !secondaryText.isEmpty()) {
        auto *btnRow = new QHBoxLayout();
        btnRow->setSpacing(isUsb ? 10 : 8);
        btnRow->addStretch();

        if (!secondaryText.isEmpty()) {
            auto *btnSec = new QPushButton(secondaryText, rootCard);
            btnSec->setCursor(Qt::PointingHandCursor);
            btnSec->setStyleSheet(isDark
                ? (isUsb ? "QPushButton { background: rgba(255,255,255,0.08); color: #d0d5dd; border: 1px solid rgba(255,255,255,0.2); border-radius: 6px; padding: 7px 18px; font-size: 12px; font-weight: 600; }"
                           "QPushButton:hover { background: rgba(255,255,255,0.18); color: #ffffff; }"
                         : "QPushButton { background: rgba(255,255,255,0.08); color: #d0d5dd; border: 1px solid rgba(255,255,255,0.15); border-radius: 5px; padding: 5px 12px; font-size: 11px; font-weight: 500; }"
                           "QPushButton:hover { background: rgba(255,255,255,0.15); color: #ffffff; }")
                : (isUsb ? "QPushButton { background: #f1f5f9; color: #334155; border: 1px solid #cbd5e1; border-radius: 6px; padding: 7px 18px; font-size: 12px; font-weight: 600; }"
                           "QPushButton:hover { background: #e2e8f0; color: #0f172a; }"
                         : "QPushButton { background: #f1f5f9; color: #334155; border: 1px solid #cbd5e1; border-radius: 5px; padding: 5px 12px; font-size: 11px; font-weight: 500; }"
                           "QPushButton:hover { background: #e2e8f0; color: #0f172a; }"));
            connect(btnSec, &QPushButton::clicked, this, [this, secondaryCb]{
                if (secondaryCb) secondaryCb();
                close();
            });
            btnRow->addWidget(btnSec);
        }

        if (!actionText.isEmpty()) {
            auto *btnAct = new QPushButton(actionText, rootCard);
            btnAct->setCursor(Qt::PointingHandCursor);
            btnAct->setStyleSheet(isUsb
                ? QString(
                    "QPushButton { background: %1; color: #ffffff; border: none; border-radius: 6px; padding: 7px 22px; font-size: 12px; font-weight: bold; }"
                    "QPushButton:hover { background: #1d4ed8; }"
                  ).arg(accentColor)
                : QString(
                    "QPushButton { background: %1; color: #ffffff; border: none; border-radius: 5px; padding: 5px 14px; font-size: 11px; font-weight: bold; }"
                    "QPushButton:hover { background: %2; }"
                  ).arg(accentColor).arg(accentColor));
            connect(btnAct, &QPushButton::clicked, this, [this, actionCb]{
                if (actionCb) actionCb();
                close();
            });
            btnRow->addWidget(btnAct);
        }

        mainLayout->addLayout(btnRow);
    }

    auto *rootLayout = new QVBoxLayout(this);
    rootLayout->setContentsMargins(0, 0, 0, 0);
    rootLayout->addWidget(rootCard);

    adjustSize();

    // Auto close timer only for non-USB notifications (USB notification stays permanently until user acts)
    if (!isUsb) {
        m_autoCloseTimer = new QTimer(this);
        m_autoCloseTimer->setSingleShot(true);
        m_autoCloseTimer->setInterval(8000);
        connect(m_autoCloseTimer, &QTimer::timeout, this, &QWidget::close);
        m_autoCloseTimer->start();
    }

    repositionAndAnimate();
}

void NotificationAlert::repositionAndAnimate()
{
    QScreen *screen = QGuiApplication::primaryScreen();
    if (!screen) return;

    QRect avail = screen->availableGeometry();
    int targetX = avail.right() - width() - 24;
    int targetY = avail.bottom() - height() - 24;

    move(targetX, targetY + 30);
    show();

    m_anim = new QPropertyAnimation(this, "pos", this);
    m_anim->setDuration(280);
    m_anim->setStartValue(QPoint(targetX, targetY + 30));
    m_anim->setEndValue(QPoint(targetX, targetY));
    m_anim->setEasingCurve(QEasingCurve::OutCubic);
    m_anim->start(QAbstractAnimation::DeleteWhenStopped);
}

void NotificationAlert::enterEvent(QEvent *e)
{
    if (m_autoCloseTimer && m_autoCloseTimer->isActive()) {
        m_autoCloseTimer->stop();
    }
    QWidget::enterEvent(e);
}

void NotificationAlert::leaveEvent(QEvent *e)
{
    if (m_autoCloseTimer && m_type != UsbDevice) {
        m_autoCloseTimer->start(4000);
    }
    QWidget::leaveEvent(e);
}

void NotificationAlert::showThreat(const QString &threatName, const QString &filePath,
                                   std::function<void()> onQuarantine,
                                   std::function<void()> onShowDetails)
{
    auto *alert = new NotificationAlert(
        Threat,
        tr("ZAGROŻENIE WYKRYTE!"),
        tr("Zablokowano złośliwy plik: %1").arg(threatName),
        filePath,
        tr("Kwarantanna"), onQuarantine,
        tr("Pokaż szczegóły"), onShowDetails
    );
    Q_UNUSED(alert);
}

void NotificationAlert::showUsb(const QString &drivePath, std::function<void()> onScan)
{
    auto *alert = new NotificationAlert(
        UsbDevice,
        tr("Wykryto nośnik USB"),
        tr("Podłączono napęd zewnętrzny: %1").arg(drivePath),
        tr("Zalecane natychmiastowe przeskanowanie woluminu pod kątem infekcji."),
        tr("Skanuj napęd"), onScan,
        tr("Pomiń"), nullptr
    );
    Q_UNUSED(alert);
}

void NotificationAlert::showInfo(const QString &title, const QString &message)
{
    auto *alert = new NotificationAlert(
        Information,
        title,
        message,
        QString(),
        tr("OK"), nullptr
    );
    Q_UNUSED(alert);
}

} // namespace verax
