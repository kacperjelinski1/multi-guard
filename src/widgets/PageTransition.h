// PageTransition.h - slide + fade animation group between QStackedWidget pages
// By Ali Sakkaf - https://alisakkaf.com
#pragma once
#include <QObject>
class QPropertyAnimation;
class QGraphicsOpacityEffect;

namespace verax {

class PageTransition : public QObject {
    Q_OBJECT
public:
    explicit PageTransition(QStackedWidget *stack, QObject *parent = nullptr);
    void slideTo(int index);

private:
    QStackedWidget *m_stack = nullptr;
    QPropertyAnimation *m_anim = nullptr;
    QGraphicsOpacityEffect *m_effect = nullptr;
};

} // namespace verax
