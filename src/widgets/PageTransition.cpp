// PageTransition.cpp - 220ms smooth page fade
#include "PageTransition.h"
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

    if (m_anim && m_anim->state() == QAbstractAnimation::Running) {
        m_anim->stop();
    }

    if (!m_effect) {
        m_effect = new QGraphicsOpacityEffect(this);
    }

    nextWidget->setGraphicsEffect(m_effect);
    m_effect->setOpacity(0.08);

    m_stack->setCurrentIndex(index);

    if (!m_anim) {
        m_anim = new QPropertyAnimation(m_effect, "opacity", this);
        m_anim->setDuration(220);
        m_anim->setEasingCurve(QEasingCurve::OutCubic);
        connect(m_anim, &QPropertyAnimation::finished, this, [this]() {
            if (m_stack && m_stack->currentWidget()) {
                m_stack->currentWidget()->setGraphicsEffect(nullptr);
            }
        });
    }

    m_anim->setStartValue(0.08);
    m_anim->setEndValue(1.0);
    m_anim->start();
}

} // namespace verax
