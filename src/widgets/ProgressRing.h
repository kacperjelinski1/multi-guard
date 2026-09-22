#pragma once

#include <QWidget>

class QTimer;

namespace verax {

class ProgressRing : public QWidget {
    Q_OBJECT
    Q_PROPERTY(qreal displayed READ displayed WRITE setDisplayed)

public:
    explicit ProgressRing(QWidget *parent = nullptr);

    qreal displayed() const { return m_displayed; }
    void setDisplayed(qreal v) { m_displayed = v; update(); }

    void setValue(qreal v);
    void setCenterText(const QString &t);
    void setMode(const QString &m);

protected:
    void paintEvent(QPaintEvent *event) override;
    QSize sizeHint() const override;

private:
    qreal m_value = 0.0;
    qreal m_displayed = 0.0;
    QString m_centerText;
    QString m_mode = "idle";
    qreal m_dashAngle = 0.0;
    QTimer *m_animTimer = nullptr;
};

} // namespace verax
