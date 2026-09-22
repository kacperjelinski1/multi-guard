#include "ProgressRing.h"
#include <QPainter>
#include <QPainterPath>
#include <QConicalGradient>
#include <QRadialGradient>
#include <QPropertyAnimation>
#include <QSvgRenderer>
#include "../core/Settings.h"

namespace verax {

ProgressRing::ProgressRing(QWidget *parent) : QWidget(parent)
{
    setObjectName("ProgressRing");
    setMinimumSize(160, 160);
}

QSize ProgressRing::sizeHint() const { return QSize(220, 220); }

void ProgressRing::setValue(qreal v)
{
    v = qBound(0.0, v, 1.0);
    m_value = v;
    m_displayed = v;
    update();
}

void ProgressRing::setCenterText(const QString &t) { m_centerText = t; update(); }
void ProgressRing::setMode(const QString &m)        { m_mode = m; update(); }

void ProgressRing::paintEvent(QPaintEvent *)
{
    const int side = qMin(width(), height());
    const QRectF box(QRectF(0, 0, side, side).adjusted(16, 16, -16, -16)
                         .translated((width()-side)/2.0, (height()-side)/2.0));

    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing);

    // Multi-layer outer glowing aura
    QRadialGradient glow(box.center(), side * 0.5);
    if (m_mode == "done" || m_mode == "heroCheck") {
        glow.setColorAt(0.0, QColor(0, 240, 118, 50));
        glow.setColorAt(0.55, QColor(0, 240, 118, 15));
        glow.setColorAt(1.0, QColor(0, 0, 0, 0));
    } else if (m_mode == "scanning") {
        glow.setColorAt(0.0, QColor(0, 196, 255, 45));
        glow.setColorAt(0.55, QColor(0, 240, 118, 20));
        glow.setColorAt(1.0, QColor(0, 0, 0, 0));
    } else if (m_mode == "threat") {
        glow.setColorAt(0.0, QColor(239, 68, 68, 45));
        glow.setColorAt(0.65, QColor(239, 68, 68, 10));
        glow.setColorAt(1.0, QColor(0, 0, 0, 0));
    } else {
        glow.setColorAt(0.0, QColor(0, 240, 118, 30));
        glow.setColorAt(1.0, QColor(0, 0, 0, 0));
    }
    p.setPen(Qt::NoPen);
    p.setBrush(glow);
    p.drawEllipse(box.adjusted(-8, -8, 8, 8));

    // Background track ring
    QPen bg(QColor(15, 30, 50, 220));
    const qreal strokeW = side * 0.085;
    bg.setWidthF(strokeW);
    bg.setCapStyle(Qt::RoundCap);
    p.setPen(bg);
    p.setBrush(Qt::NoBrush);
    p.drawEllipse(box);

    // Active arc / full ring
    if (m_mode == "done" || m_mode == "heroCheck") {
        // Solid neon green outer ring
        QPen pen(QColor("#00F076"));
        pen.setWidthF(strokeW * 0.9);
        pen.setCapStyle(Qt::RoundCap);
        p.setPen(pen);
        p.drawEllipse(box);

        // Big checkmark in center
        p.setPen(Qt::NoPen);
        QPen checkPen(QColor("#00F076"));
        checkPen.setWidthF(side * 0.085);
        checkPen.setCapStyle(Qt::RoundCap);
        checkPen.setJoinStyle(Qt::RoundJoin);
        p.setPen(checkPen);

        QPainterPath checkPath;
        const qreal cx = box.center().x();
        const qreal cy = box.center().y();
        const qreal s = side * 0.22;
        checkPath.moveTo(cx - s * 0.9, cy - s * 0.05);
        checkPath.lineTo(cx - s * 0.2, cy + s * 0.65);
        checkPath.lineTo(cx + s * 1.0, cy - s * 0.65);
        p.drawPath(checkPath);
        return;
    }

    if (m_mode == "optimizer") {
        // Circular health ring (e.g. 92/100)
        QPen pen(QColor("#00F076"));
        pen.setWidthF(strokeW);
        pen.setCapStyle(Qt::RoundCap);
        p.setPen(pen);
        const int span = int(m_displayed * 360.0 * 16.0);
        p.drawArc(box, 90 * 16, -span);

        // Center text: 92 / 100
        QFont fMain = font();
        fMain.setPointSizeF(side * 0.16);
        fMain.setBold(true);
        p.setFont(fMain);
        p.setPen(QColor("#FFFFFF"));

        QRectF textRect(box.left(), box.center().y() - side * 0.18, box.width(), side * 0.24);
        const QString numText = QString::number(int(m_displayed * 100));
        p.drawText(textRect, Qt::AlignCenter, numText);

        QFont fSub = font();
        fSub.setPointSizeF(side * 0.075);
        fSub.setBold(false);
        p.setFont(fSub);
        p.setPen(QColor("#94A3B8"));
        QRectF subRect(box.left(), box.center().y() + side * 0.04, box.width(), side * 0.16);
        p.drawText(subRect, Qt::AlignCenter, "/ 100");
        return;
    }

    // Standard scanning progress ring with Conical gradient (cyan to neon green)
    const int span = int(m_displayed * 360.0 * 16.0);
    if (span > 0) {
        QConicalGradient conic(box.center(), 90);
        if (m_mode == "threat") {
            conic.setColorAt(0.0, QColor("#EF4444"));
            conic.setColorAt(1.0, QColor("#DC2626"));
        } else {
            conic.setColorAt(0.0, QColor("#00C4FF"));   // Cyan
            conic.setColorAt(0.7, QColor("#00F076"));   // Neon Green
            conic.setColorAt(1.0, QColor("#00C4FF"));
        }
        QBrush brush(conic);
        QPen pen(brush, strokeW, Qt::SolidLine, Qt::RoundCap);
        p.setPen(pen);
        p.drawArc(box, 90 * 16, -span);
    }

    // Center Percentage Text (e.g. 68%)
    const QString text = m_centerText.isEmpty()
                             ? QString::number(int(m_displayed * 100)) + "%" : m_centerText;

    QFont f = font();
    f.setPointSizeF(side * 0.16);
    f.setBold(true);
    p.setFont(f);
    p.setPen(QColor("#FFFFFF"));
    p.drawText(box, Qt::AlignCenter, text);
}

} // namespace verax
