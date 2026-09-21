// FlagIcon.h - procedurally drawn EN / AR flag icons
// By Ali Sakkaf - https://alisakkaf.com
#pragma once
#include <QWidget>

namespace verax {

class FlagIcon : public QWidget {
    Q_OBJECT
public:
    explicit FlagIcon(QWidget *parent = nullptr);
    void setCode(const QString &code);    // "en" or "ar"
    QString code() const { return m_code; }
    QSize sizeHint() const override         { return QSize(32, 22); }

signals:
    void clicked();

protected:
    void paintEvent(QPaintEvent *) override;
    void mouseReleaseEvent(QMouseEvent *e) override;
    void enterEvent(QEvent *e) override;
    void leaveEvent(QEvent *e) override;

private:
    QString m_code = QStringLiteral("pl");
    bool    m_hover = false;
    void paintEn(QPainter &p, const QRectF &r);
    void paintAr(QPainter &p, const QRectF &r);
    void paintPl(QPainter &p, const QRectF &r);
};

} // namespace verax
