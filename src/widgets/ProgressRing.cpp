#include "ProgressRing.h"
#include <QPainter>
#include <QPainterPath>
#include <QConicalGradient>
#include <QRadialGradient>
#include <QPropertyAnimation>
#include <QSvgRenderer>
#include <QTimer>
#include <QVector>
#include <cmath>
#include "../core/Settings.h"

namespace verax {

ProgressRing::ProgressRing(QWidget *parent) : QWidget(parent)
{
    setObjectName("ProgressRing");
    setMinimumSize(160, 160);

    m_animTimer = new QTimer(this);
    connect(m_animTimer, &QTimer::timeout, this, [this]() {
        if (!isVisible()) return;
        m_dashAngle = std::fmod(m_dashAngle + 0.8, 360.0);
        update();
    });
    m_animTimer->start(35);
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
    QRadialGradient glow(box.center(), side * 0.55);
    if (m_mode == "done" || m_mode == "heroCheck") {
        glow.setColorAt(0.0, QColor(0, 240, 118, 75));
        glow.setColorAt(0.5, QColor(0, 240, 118, 25));
        glow.setColorAt(1.0, QColor(0, 0, 0, 0));
    } else if (m_mode == "scanning") {
        glow.setColorAt(0.0, QColor(0, 196, 255, 55));
        glow.setColorAt(0.55, QColor(0, 240, 118, 20));
        glow.setColorAt(1.0, QColor(0, 0, 0, 0));
    } else if (m_mode == "threat") {
        glow.setColorAt(0.0, QColor(239, 68, 68, 55));
        glow.setColorAt(0.65, QColor(239, 68, 68, 12));
        glow.setColorAt(1.0, QColor(0, 0, 0, 0));
    } else {
        glow.setColorAt(0.0, QColor(0, 240, 118, 35));
        glow.setColorAt(1.0, QColor(0, 0, 0, 0));
    }
    p.setPen(Qt::NoPen);
    p.setBrush(glow);
    p.drawEllipse(box.adjusted(-10, -10, 10, 10));

    // Active arc / full ring
    if (m_mode == "done" || m_mode == "heroCheck") {
        // Outer rotating dashed cyber ring
        QPen dashPen(QColor(0, 240, 118, 185));
        dashPen.setWidthF(2.0);
        QVector<qreal> dashes;
        dashes << 4.0 << 6.0;
        dashPen.setDashPattern(dashes);
        p.setPen(dashPen);
        p.setBrush(Qt::NoBrush);

        p.save();
        p.translate(box.center());
        p.rotate(m_dashAngle);
        const qreal r = box.width() / 2.0 + 6.0;
        p.drawEllipse(QRectF(-r, -r, r * 2.0, r * 2.0));
        p.restore();

        // Inner glowing translucent disk
        QRadialGradient innerDisk(box.center(), box.width() / 2.0);
        innerDisk.setColorAt(0.0, QColor(0, 240, 118, 60));
        innerDisk.setColorAt(0.7, QColor(0, 240, 118, 18));
        innerDisk.setColorAt(1.0, QColor(4, 16, 30, 230));
        p.setPen(Qt::NoPen);
        p.setBrush(innerDisk);
        p.drawEllipse(box);

        // Solid neon green ring
        QPen ringPen(QColor("#00F076"));
        ringPen.setWidthF(4.0);
        ringPen.setCapStyle(Qt::RoundCap);
        p.setPen(ringPen);
        p.setBrush(Qt::NoBrush);
        p.drawEllipse(box);

        // Bright checkmark in center
        QPen checkPen(QColor("#00F076"));
        checkPen.setWidthF(side * 0.088);
        checkPen.setCapStyle(Qt::RoundCap);
        checkPen.setJoinStyle(Qt::RoundJoin);
        p.setPen(checkPen);

        QPainterPath checkPath;
        const qreal cx = box.center().x();
        const qreal cy = box.center().y();
        const qreal s = side * 0.22;
        checkPath.moveTo(cx - s * 0.88, cy - s * 0.04);
        checkPath.lineTo(cx - s * 0.2, cy + s * 0.65);
        checkPath.lineTo(cx + s * 0.96, cy - s * 0.65);
        p.drawPath(checkPath);
        return;
    }

    // Background track ring
    QPen bg(QColor(15, 30, 50, 220));
    const qreal strokeW = side * 0.085;
    bg.setWidthF(strokeW);
    bg.setCapStyle(Qt::RoundCap);
    p.setPen(bg);
    p.setBrush(Qt::NoBrush);
    p.drawEllipse(box);

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
