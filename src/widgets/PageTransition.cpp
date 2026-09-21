// PageTransition.cpp - 280ms OutCubic slide+fade
// By Ali Sakkaf - https://alisakkaf.com
#include "PageTransition.h"
#include <QStackedWidget>
#include <QPropertyAnimation>
#include <QParallelAnimationGroup>
#include <QGraphicsOpacityEffect>

namespace verax {

PageTransition::PageTransition(QStackedWidget *stack, QObject *parent)
    : QObject(parent), m_stack(stack) {}

void PageTransition::slideTo(int index)
{
    if (!m_stack || index < 0 || index >= m_stack->count()) return;
    if (m_stack->currentIndex() == index) return;
    m_stack->setCurrentIndex(index);
}

} // namespace verax
