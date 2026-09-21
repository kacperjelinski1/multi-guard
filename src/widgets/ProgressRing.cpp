#include "ProgressRing.h"
#include <QPainter>
#include <QPropertyAnimation>
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
    const QRectF box(QRectF(0, 0, side, side).adjusted(10, 10, -10, -10)
                         .translated((width()-side)/2.0, (height()-side)/2.0));

    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing);

    // Subtle inner radial glow
    QRadialGradient glow(box.center(), side * 0.45);
    if (m_mode == "done") {
        glow.setColorAt(0.0, QColor(16, 185, 129, 35));
        glow.setColorAt(0.65, QColor(16, 185, 129, 8));
        glow.setColorAt(1.0, QColor(0, 0, 0, 0));
    } else if (m_mode == "scanning") {
        glow.setColorAt(0.0, QColor(56, 189, 248, 35));
        glow.setColorAt(0.65, QColor(56, 189, 248, 8));
        glow.setColorAt(1.0, QColor(0, 0, 0, 0));
    } else if (m_mode == "threat") {
        glow.setColorAt(0.0, QColor(239, 68, 68, 35));
        glow.setColorAt(0.65, QColor(239, 68, 68, 8));
        glow.setColorAt(1.0, QColor(0, 0, 0, 0));
    } else {
        glow.setColorAt(0.0, QColor(100, 116, 139, 20));
        glow.setColorAt(1.0, QColor(0, 0, 0, 0));
    }
    p.setPen(Qt::NoPen);
    p.setBrush(glow);
    p.drawEllipse(box.adjusted(10, 10, -10, -10));

    // Background track ring
    QPen bg(QColor("#1e293b"));
    bg.setWidthF(side * 0.065);
    bg.setCapStyle(Qt::RoundCap);
    p.setPen(bg);
    p.setBrush(Qt::NoBrush);
    p.drawEllipse(box);

    // Active arc
    QColor fg;
    if (m_mode == "threat")        fg = QColor("#ef4444");
    else if (m_mode == "done")     fg = QColor("#10b981");
    else if (m_mode == "scanning") fg = QColor("#38bdf8");
    else                           fg = QColor("#64748b");

    QPen pen(fg);
    pen.setWidthF(side * 0.065);
    pen.setCapStyle(Qt::RoundCap);
    p.setPen(pen);

    const int span = int(m_displayed * 360.0 * 16.0);
    p.drawArc(box, 90 * 16, -span);

    const QString text = m_centerText.isEmpty()
                             ? QString::number(int(m_displayed * 100)) + "%" : m_centerText;

    if (text == "Bezpieczny" || text == "Chroniony") {
        QFont fIcon = font();
        fIcon.setPointSizeF(fIcon.pointSizeF() * 2.1);
        p.setFont(fIcon);
        p.setPen(QColor("#10b981"));
        QRectF iconRect(rect().x(), rect().y() + rect().height() * 0.17, rect().width(), rect().height() * 0.35);
        p.drawText(iconRect, Qt::AlignCenter, "🛡️");

        QFont fText = font();
        fText.setPointSizeF(fText.pointSizeF() * 1.15);
        fText.setBold(true);
        p.setFont(fText);
        p.setPen(QColor("#f8fafc"));
        QRectF textRect(rect().x(), rect().y() + rect().height() * 0.52, rect().width(), rect().height() * 0.24);
        p.drawText(textRect, Qt::AlignCenter, "System chroniony");

        QFont fSub = font();
        fSub.setPointSizeF(fSub.pointSizeF() * 0.82);
        fSub.setBold(false);
        p.setFont(fSub);
        p.setPen(QColor("#10b981"));
        QRectF subRect(rect().x(), rect().y() + rect().height() * 0.72, rect().width(), rect().height() * 0.18);
        p.drawText(subRect, Qt::AlignCenter, "Ochrona aktywna");
    } else if (text == "Wygasła" || text == "Wymagana aktywacja" || text == "Zagrożony") {
        QFont fIcon = font();
        fIcon.setPointSizeF(fIcon.pointSizeF() * 2.1);
        p.setFont(fIcon);
        QRectF iconRect(rect().x(), rect().y() + rect().height() * 0.17, rect().width(), rect().height() * 0.35);
        p.drawText(iconRect, Qt::AlignCenter, "⚠️");

        QFont fText = font();
        fText.setPointSizeF(fText.pointSizeF() * 1.15);
        fText.setBold(true);
        p.setFont(fText);
        p.setPen(QColor("#f87171"));
        QRectF textRect(rect().x(), rect().y() + rect().height() * 0.52, rect().width(), rect().height() * 0.24);
        p.drawText(textRect, Qt::AlignCenter, "Wymaga uwagi");

        QFont fSub = font();
        fSub.setPointSizeF(fSub.pointSizeF() * 0.82);
        fSub.setBold(false);
        p.setFont(fSub);
        p.setPen(QColor("#94a3b8"));
        QRectF subRect(rect().x(), rect().y() + rect().height() * 0.72, rect().width(), rect().height() * 0.18);
        p.drawText(subRect, Qt::AlignCenter, text);
    } else {
        QFont f = font();
        if (text.length() <= 4) {
            f.setPointSizeF(f.pointSizeF() * 1.9);
        } else if (text.length() <= 8) {
            f.setPointSizeF(f.pointSizeF() * 1.25);
        } else {
            f.setPointSizeF(f.pointSizeF() * 0.95);
        }
        f.setBold(true);
        p.setFont(f);
        p.setPen(QColor("#f8fafc"));
        p.drawText(rect(), Qt::AlignCenter, text);
    }
}

} // namespace verax
