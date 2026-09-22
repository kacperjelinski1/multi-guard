// PageTransition.h - slide + fade animation group between QStackedWidget pages
#pragma once
#include <QObject>
class QStackedWidget;

namespace verax {

class PageTransition : public QObject {
    Q_OBJECT
public:
    explicit PageTransition(QStackedWidget *stack, QObject *parent = nullptr);
    void slideTo(int index);

private:
    QStackedWidget *m_stack = nullptr;
};

} // namespace verax
