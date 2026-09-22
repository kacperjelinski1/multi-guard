// PageTransition.cpp - 220ms smooth page fade
#include "PageTransition.h"
#include <QWidget>
#include <QStackedWidget>
#include <QPropertyAnimation>
#include <QGraphicsOpacityEffect>
#include <QEasingCurve>

namespace verax {

PageTransition::PageTransition(QStackedWidget *stack, QObject *parent)
    : QObject(parent), m_stack(stack)
{
}

void PageTransition::slideTo(int index)
{
    if (!m_stack || index < 0 || index >= m_stack->count()) return;
    if (m_stack->currentIndex() == index) return;

    QWidget *nextWidget = m_stack->widget(index);
    if (!nextWidget) {
        m_stack->setCurrentIndex(index);
        return;
    }

    auto *effect = new QGraphicsOpacityEffect(nextWidget);
    nextWidget->setGraphicsEffect(effect);
    effect->setOpacity(0.08);

    m_stack->setCurrentIndex(index);

    auto *anim = new QPropertyAnimation(effect, "opacity", nextWidget);
    anim->setDuration(220);
    anim->setEasingCurve(QEasingCurve::OutCubic);
    anim->setStartValue(0.08);
    anim->setEndValue(1.0);
    connect(anim, &QPropertyAnimation::finished, [nextWidget, anim]() {
        nextWidget->setGraphicsEffect(nullptr);
        anim->deleteLater();
    });
    anim->start(QAbstractAnimation::DeleteWhenStopped);
}

} // namespace verax
