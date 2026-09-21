// ChromeBar.cpp - title bar for frameless window. Built in code so the
// chrome can be promoted in .ui without per-page duplication.
// By Ali Sakkaf - https://alisakkaf.com
#include "ChromeBar.h"
#include "../../Version.h"

#include <QLabel>
#include <QPushButton>
#include <QHBoxLayout>
#include <QMouseEvent>
#include <QFontMetrics>
#include <QPixmap>
#include <QStyle>
#include "../core/Settings.h"

namespace verax {

ChromeBar::ChromeBar(QWidget *parent) : QWidget(parent)
{
    setObjectName("ChromeBar");
    setAttribute(Qt::WA_StyledBackground, true);

    auto *layout = new QHBoxLayout(this);
    const int pad = fontMetrics().averageCharWidth();
    layout->setContentsMargins(pad * 2, 0, pad, 0);
    layout->setSpacing(pad);

    m_logo = new QLabel(this);
    m_logo->setObjectName("ChromeBarLogo");
    QPixmap pm(":/assets/logo.png");
    if (!pm.isNull()) {
        const int side = fontMetrics().height() * 2;
        m_logo->setPixmap(pm.scaled(side, side, Qt::KeepAspectRatio,
                                    Qt::SmoothTransformation));
    } else {
        m_logo->setText("M");
        m_logo->setObjectName("ChromeBarLogoText");
    }

    m_title = new QLabel(QString::fromLatin1(APP_NAME), this);
    m_title->setObjectName("ChromeBarTitle");

    m_status = new QLabel(tr("Idle"), this);
    m_status->setObjectName("ChromeBarStatus");
    m_status->setProperty("kind", "idle");
    m_status->setAlignment(Qt::AlignCenter);

    // Fix Qt synthetic bold shaping bug for Arabic
    if (verax::Settings::instance().language() == "ar") {
        m_title->setStyleSheet("font-weight: normal;");
        m_status->setStyleSheet("font-weight: normal;");
    }

    m_btnMin = new QPushButton("\u2014", this);   // em-dash for minimize
    m_btnMin->setObjectName("ChromeBarMinimize");
    m_btnMin->setFlat(true);
    m_btnMin->setCursor(Qt::PointingHandCursor);
    m_btnMin->setFocusPolicy(Qt::NoFocus);

    m_btnMax = new QPushButton("\u25A1", this);   // square for maximize
    m_btnMax->setObjectName("ChromeBarMaximize");
    m_btnMax->setFlat(true);
    m_btnMax->setCursor(Qt::PointingHandCursor);
    m_btnMax->setFocusPolicy(Qt::NoFocus);

    m_btnClose = new QPushButton("\u2715", this); // multiplication X
    m_btnClose->setObjectName("ChromeBarClose");
    m_btnClose->setFlat(true);
    m_btnClose->setCursor(Qt::PointingHandCursor);
    m_btnClose->setFocusPolicy(Qt::NoFocus);

    const int btnSide = fontMetrics().height() + fontMetrics().height() / 2;
    m_btnMin->setFixedSize(btnSide * 2, btnSide);
    m_btnMax->setFixedSize(btnSide * 2, btnSide);
    m_btnClose->setFixedSize(btnSide * 2, btnSide);

    layout->addWidget(m_logo);
    layout->addWidget(m_title);
    layout->addStretch(1);
    layout->addWidget(m_status);
    layout->addStretch(1);
    layout->addWidget(m_btnMin);
    layout->addWidget(m_btnMax);
    layout->addWidget(m_btnClose);

    const int h = fontMetrics().height() * 24 / 10;
    setFixedHeight(h);

    connect(m_btnMin,   &QPushButton::clicked, this, &ChromeBar::minimizeClicked);
    connect(m_btnMax,   &QPushButton::clicked, this, &ChromeBar::maximizeClicked);
    connect(m_btnClose, &QPushButton::clicked, this, &ChromeBar::closeClicked);
}

void ChromeBar::setTitle(const QString &t)      { m_title->setText(t); }
void ChromeBar::setStatusText(const QString &s) { m_status->setText(s); }
void ChromeBar::setStatusKind(const QString &k) {
    m_status->setProperty("kind", k);
    m_status->style()->unpolish(m_status);
    m_status->style()->polish(m_status);
}

void ChromeBar::updateMaximizeIcon(bool isMaximized) {
    if (isMaximized) {
        m_btnMax->setText("\u25EB"); // restore
    } else {
        m_btnMax->setText("\u25A1"); // maximize
    }
}

void ChromeBar::mousePressEvent(QMouseEvent *e)
{
    if (e->button() != Qt::LeftButton) { QWidget::mousePressEvent(e); return; }
    if (m_btnMin->geometry().contains(e->pos())) return;
    if (m_btnMax->geometry().contains(e->pos())) return;
    if (m_btnClose->geometry().contains(e->pos())) return;
    m_dragging = true;
    m_dragOrigin = e->globalPos() - window()->frameGeometry().topLeft();
    e->accept();
}
void ChromeBar::mouseMoveEvent(QMouseEvent *e)
{
    if (m_dragging && (e->buttons() & Qt::LeftButton)) {
        if (window()->isMaximized()) {
            // Un-maximize naturally if dragging while maximized
            // Need to adjust drag origin relative to cursor so it doesn't jump weirdly
            QPoint globalCursorPos = e->globalPos();
            int widthBefore = window()->width();
            window()->showNormal();
            int widthAfter = window()->width();
            
            // Adjust dragOrigin X proportionally
            double ratio = static_cast<double>(m_dragOrigin.x()) / static_cast<double>(widthBefore);
            m_dragOrigin.setX(static_cast<int>(widthAfter * ratio));
            
            window()->move(globalCursorPos - m_dragOrigin);
        } else {
            window()->move(e->globalPos() - m_dragOrigin);
        }
        e->accept();
    } else {
        QWidget::mouseMoveEvent(e);
    }
}
void ChromeBar::mouseReleaseEvent(QMouseEvent *e)
{
    m_dragging = false;
    QWidget::mouseReleaseEvent(e);
}
void ChromeBar::mouseDoubleClickEvent(QMouseEvent *e)
{
    if (e->button() == Qt::LeftButton) {
        emit maximizeClicked();
        e->accept();
    } else {
        QWidget::mouseDoubleClickEvent(e);
    }
}

} // namespace verax
