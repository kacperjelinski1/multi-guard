// Toaster.cpp - slide-in toast from top-right (220ms OutBack)
// By Ali Sakkaf - https://alisakkaf.com
#include "Toaster.h"
#include <QLabel>
#include <QHBoxLayout>
#include <QPropertyAnimation>
#include <QTimer>
#include <QGraphicsDropShadowEffect>
#include "../core/Settings.h"

namespace verax {

void Toaster::show(QWidget *anchor, const QString &text, Kind k, int msec)
{
    if (!anchor) return;
    const auto existing = anchor->findChildren<Toaster*>();
    for (auto *t : existing) {
        t->close();
        t->deleteLater();
    }
    auto *t = new Toaster(anchor, text, k);
    t->slideAndAutoClose(msec);
}

Toaster::Toaster(QWidget *anchor, const QString &text, Kind k)
    : QWidget(anchor)
{
    setObjectName("Toaster");
    setAttribute(Qt::WA_DeleteOnClose, true);
    setAttribute(Qt::WA_StyledBackground, true);

    QString kindStr = "info";
    switch (k) {
    case Warn:    kindStr = "warn";    break;
    case Error:   kindStr = "error";   break;
    case Success: kindStr = "success"; break;
    default:      kindStr = "info";    break;
    }
    setProperty("kind", kindStr);

    m_label = new QLabel(text, this);
    m_label->setObjectName("ToasterText");
    m_label->setWordWrap(true);

    auto *lay = new QHBoxLayout(this);
    const int pad = fontMetrics().averageCharWidth() * 2;
    lay->setContentsMargins(pad, pad, pad, pad);
    lay->addWidget(m_label);

    auto *shadow = new QGraphicsDropShadowEffect(this);
    shadow->setBlurRadius(20);
    shadow->setColor(QColor(15, 23, 42, 60));
    shadow->setOffset(0, 6);
    if (verax::Settings::instance().language() != "ar") {
        setGraphicsEffect(shadow);
    }

    adjustSize();
    setFixedWidth(qMin(360, anchor->width() - pad * 2));
}

void Toaster::slideAndAutoClose(int msec)
{
    QWidget *anchor = parentWidget();
    const int margin = fontMetrics().averageCharWidth() * 2;
    const int startX = anchor->width();
    const int endX   = anchor->width() - width() - margin;
    const int y      = margin + (fontMetrics().height() * 24 / 10); // below chrome bar

    move(startX, y);
    QWidget::show();
    raise();

    auto *in = new QPropertyAnimation(this, "pos", this);
    in->setDuration(220);
    in->setStartValue(QPoint(startX, y));
    in->setEndValue(QPoint(endX, y));
    in->setEasingCurve(QEasingCurve::OutBack);
    in->start(QAbstractAnimation::DeleteWhenStopped);

    QTimer::singleShot(msec, this, [this, anchor, y]{
        const int startX = pos().x();
        const int endX   = anchor->width();
        auto *out = new QPropertyAnimation(this, "pos", this);
        out->setDuration(220);
        out->setStartValue(QPoint(startX, y));
        out->setEndValue(QPoint(endX, y));
        out->setEasingCurve(QEasingCurve::InCubic);
        connect(out, &QPropertyAnimation::finished, this, &QWidget::close);
        out->start(QAbstractAnimation::DeleteWhenStopped);
    });
}

} // namespace verax
