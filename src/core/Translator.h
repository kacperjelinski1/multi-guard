// Translator.h - live EN/AR language switch with RTL toggle
// By Ali Sakkaf - https://alisakkaf.com
#pragma once
#include <QObject>
#include <QString>
class QTranslator;

namespace verax {

class Translator : public QObject {
    Q_OBJECT
public:
    static Translator& instance();

    // Loads the .qm file for the given language code ("en" or "ar"),
    // installs it on QApplication, and toggles layoutDirection.
    void install(const QString &code);

    QString currentLanguage() const { return m_current; }
    bool    isRtl() const           { return false; }

signals:
    void localeChanged(const QString &code);

private:
    explicit Translator(QObject *parent = nullptr);

    QTranslator *m_appTr = nullptr;
    QTranslator *m_qtTr  = nullptr;
    QString      m_current = QStringLiteral("pl");
};

} // namespace verax
