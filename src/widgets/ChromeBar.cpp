// ChromeBar.cpp - title bar for frameless window matching AEGIS design
#include "ChromeBar.h"
#include "../../Version.h"

#include <QLabel>
#include <QPushButton>
#include <QLineEdit>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QMouseEvent>
#include <QFontMetrics>
#include <QPixmap>
#include <QIcon>
#include <QStyle>
#include "../core/Settings.h"

namespace verax {

ChromeBar::ChromeBar(QWidget *parent) : QWidget(parent)
{
    setObjectName("ChromeBar");
    setAttribute(Qt::WA_StyledBackground, true);

    auto *layout = new QHBoxLayout(this);
    layout->setContentsMargins(16, 8, 16, 8);
    layout->setSpacing(12);

    // Left spacer or brand indicator if standalone
    layout->addSpacing(8);

    // Center Search Bar Pill
    layout->addStretch(1);
    m_searchEdit = new QLineEdit(this);
    m_searchEdit->setObjectName("topSearchBar");
    m_searchEdit->setPlaceholderText(tr("🔍 Szukaj funkcji, ustawień..."));
    m_searchEdit->setMinimumWidth(160);
    m_searchEdit->setMaximumWidth(360);
    m_searchEdit->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    m_searchEdit->setFixedHeight(32);
    m_searchEdit->setClearButtonEnabled(true);
    layout->addWidget(m_searchEdit);
    layout->addStretch(1);

    // Notification Bell Button
    m_btnNotifications = new QPushButton(this);
    m_btnNotifications->setObjectName("btnTopBell");
    m_btnNotifications->setIcon(QIcon(":/assets/icons/icon_bell.svg"));
    m_btnNotifications->setIconSize(QSize(20, 20));
    m_btnNotifications->setToolTip(tr("Powiadomienia"));
    m_btnNotifications->setFixedSize(36, 32);
    m_btnNotifications->setCursor(Qt::PointingHandCursor);
    m_btnNotifications->setFocusPolicy(Qt::NoFocus);
    layout->addWidget(m_btnNotifications);

    // User Profile Widget (Kacper | Premium)
    m_userWidget = new QWidget(this);
    m_userWidget->setObjectName("userProfileWidget");
    auto *userLayout = new QHBoxLayout(m_userWidget);
    userLayout->setContentsMargins(4, 0, 8, 0);
    userLayout->setSpacing(8);

    auto *lblAvatar = new QLabel(m_userWidget);
    lblAvatar->setObjectName("lblUserAvatar");
    QPixmap avPm(":/assets/user_avatar.png");
    if (!avPm.isNull()) {
        lblAvatar->setPixmap(avPm.scaled(28, 28, Qt::KeepAspectRatio, Qt::SmoothTransformation));
    }
    lblAvatar->setFixedSize(28, 28);
    userLayout->addWidget(lblAvatar);

    auto *textLayout = new QVBoxLayout();
    textLayout->setContentsMargins(0, 0, 0, 0);
    textLayout->setSpacing(0);

    auto *lblName = new QLabel(QStringLiteral("Kacper"), m_userWidget);
    lblName->setObjectName("lblUserName");
    lblName->setStyleSheet("font-weight: 700; font-size: 11px; color: #FFFFFF; line-height: 12px;");
    textLayout->addWidget(lblName);

    auto *lblTier = new QLabel(QStringLiteral("Premium"), m_userWidget);
    lblTier->setObjectName("lblUserTier");
    lblTier->setStyleSheet("font-size: 9px; color: #38BDF8; font-weight: 600; line-height: 10px;");
    textLayout->addWidget(lblTier);

    userLayout->addLayout(textLayout);
    layout->addWidget(m_userWidget);

    layout->addSpacing(6);

    // Window controls: Minimize, Maximize, Close
    m_btnMin = new QPushButton(QStringLiteral("—"), this);
    m_btnMin->setObjectName("btnMinimize");
    m_btnMin->setFixedSize(30, 28);
    m_btnMin->setCursor(Qt::PointingHandCursor);
    m_btnMin->setFocusPolicy(Qt::NoFocus);

    m_btnMax = new QPushButton(QStringLiteral("□"), this);
    m_btnMax->setObjectName("btnMaximize");
    m_btnMax->setFixedSize(30, 28);
    m_btnMax->setCursor(Qt::PointingHandCursor);
    m_btnMax->setFocusPolicy(Qt::NoFocus);

    m_btnClose = new QPushButton(QStringLiteral("✕"), this);
    m_btnClose->setObjectName("btnClose");
    m_btnClose->setFixedSize(30, 28);
    m_btnClose->setCursor(Qt::PointingHandCursor);
    m_btnClose->setFocusPolicy(Qt::NoFocus);

    m_btnMax->setVisible(false);
    layout->addWidget(m_btnMin);
    layout->addWidget(m_btnClose);

    setFixedHeight(48);

    connect(m_btnNotifications, &QPushButton::clicked, this, &ChromeBar::notificationsClicked);
    connect(m_btnMin,           &QPushButton::clicked, this, &ChromeBar::minimizeClicked);
    connect(m_btnMax,           &QPushButton::clicked, this, &ChromeBar::maximizeClicked);
    connect(m_btnClose,         &QPushButton::clicked, this, &ChromeBar::closeClicked);
}

void ChromeBar::setTitle(const QString &) {}
void ChromeBar::setStatusText(const QString &) {}
void ChromeBar::setStatusKind(const QString &) {}

void ChromeBar::updateMaximizeIcon(bool isMaximized)
{
    if (m_btnMax) {
        m_btnMax->setText(isMaximized ? QStringLiteral("❐") : QStringLiteral("□"));
    }
}

void ChromeBar::mousePressEvent(QMouseEvent *e)
{
    if (e->button() == Qt::LeftButton) {
        m_dragging = true;
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
        m_dragOrigin = e->globalPosition().toPoint() - window()->pos();
#else
        m_dragOrigin = e->globalPos() - window()->pos();
#endif
        e->accept();
    }
}

void ChromeBar::mouseMoveEvent(QMouseEvent *e)
{
    if (m_dragging && (e->buttons() & Qt::LeftButton)) {
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
        window()->move(e->globalPosition().toPoint() - m_dragOrigin);
#else
        window()->move(e->globalPos() - m_dragOrigin);
#endif
        e->accept();
    }
}

void ChromeBar::mouseReleaseEvent(QMouseEvent *e)
{
    m_dragging = false;
    e->accept();
}

void ChromeBar::mouseDoubleClickEvent(QMouseEvent *e)
{
    // Fixed window size - maximize disabled
    e->accept();
}

} // namespace verax
