// SurfaceCard.cpp - styling driven by QSS via objectName/property
// By Ali Sakkaf - https://alisakkaf.com
#include "SurfaceCard.h"
#include <QGraphicsDropShadowEffect>
#include <QEvent>
#include <QStyle>
#include <QVariant>

#include "src/core/Settings.h"

namespace verax {

SurfaceCard::SurfaceCard(QWidget *parent) : QFrame(parent)
{
    setObjectName("SurfaceCard");
    setProperty("class", "SurfaceCard");
    setFrameShape(QFrame::NoFrame);
    setAttribute(Qt::WA_StyledBackground, true);
}

void SurfaceCard::setInteractive(bool v)
{
    m_interactive = v;
    setProperty("interactive", v);
    style()->unpolish(this);
    style()->polish(this);
}

void SurfaceCard::enterEvent(QEvent *e)
{
    QFrame::enterEvent(e);
}

void SurfaceCard::leaveEvent(QEvent *e)
{
    QFrame::leaveEvent(e);
}

} // namespace verax
