// FlagIcon.cpp - simplified UK / Saudi flag representations
// By Ali Sakkaf - https://alisakkaf.com
#include "FlagIcon.h"
#include <QPainter>
#include <QPainterPath>
#include <QMouseEvent>

namespace verax {

FlagIcon::FlagIcon(QWidget *parent) : QWidget(parent)
{
    setObjectName("FlagIcon");
    setMinimumSize(24, 16);
    setCursor(Qt::PointingHandCursor);
    setAttribute(Qt::WA_Hover, true);
}

void FlagIcon::setCode(const QString &code) {
    m_code = code.toLower();
    update();
}

void FlagIcon::mouseReleaseEvent(QMouseEvent *e)
{
    if (e->button() == Qt::LeftButton && rect().contains(e->pos()))
        emit clicked();
    QWidget::mouseReleaseEvent(e);
}

void FlagIcon::enterEvent(QEvent *e) { m_hover = true;  update(); QWidget::enterEvent(e); }
void FlagIcon::leaveEvent(QEvent *e) { m_hover = false; update(); QWidget::leaveEvent(e); }

void FlagIcon::paintEn(QPainter &p, const QRectF &r)
{
    // Simplified Union Jack (blue + red + white)
    p.fillRect(r, QColor("#012169"));
    QPen wpen(QColor("#FFFFFF"));
    wpen.setWidthF(r.height() / 6.0);
    QPen rpen(QColor("#C8102E"));
    rpen.setWidthF(r.height() / 10.0);

    p.setPen(wpen);
    p.drawLine(r.topLeft(),  r.bottomRight());
    p.drawLine(r.topRight(), r.bottomLeft());
    p.drawLine(QPointF(r.center().x(), r.top()),    QPointF(r.center().x(), r.bottom()));
    p.drawLine(QPointF(r.left(), r.center().y()),   QPointF(r.right(), r.center().y()));

    p.setPen(rpen);
    p.drawLine(QPointF(r.center().x(), r.top()),    QPointF(r.center().x(), r.bottom()));
    p.drawLine(QPointF(r.left(), r.center().y()),   QPointF(r.right(), r.center().y()));
}

void FlagIcon::paintAr(QPainter &p, const QRectF &r)
{
    // Simplified Saudi Arabia (green + white bar)
    p.fillRect(r, QColor("#006C35"));
    QFont f = p.font();
    f.setPointSizeF(r.height() * 0.42);
    p.setFont(f);
    p.setPen(QColor("#FFFFFF"));
    p.drawText(r, Qt::AlignCenter, QStringLiteral("\u0627\u0644\u0639\u0631\u0628\u064A\u0629"));
}

void FlagIcon::paintPl(QPainter &p, const QRectF &r)
{
    // Poland flag: top half white, bottom half red
    QRectF top(r.left(), r.top(), r.width(), r.height() / 2.0);
    QRectF btm(r.left(), r.top() + r.height() / 2.0, r.width(), r.height() / 2.0);
    p.fillRect(top, QColor("#FFFFFF"));
    p.fillRect(btm, QColor("#DC143C"));
}

void FlagIcon::paintEvent(QPaintEvent *)
{
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing);

    QRectF r = rect().adjusted(1, 1, -1, -1);
    QPainterPath clip; clip.addRoundedRect(r, 3, 3);
    p.setClipPath(clip);

    if (m_code == "ar")      paintAr(p, r);
    else if (m_code == "pl") paintPl(p, r);
    else                     paintEn(p, r);

    p.setClipping(false);
    p.setPen(m_hover ? QColor("#2563EB") : QColor("#CBD5E1"));
    p.drawRoundedRect(r, 3, 3);
}

} // namespace verax
