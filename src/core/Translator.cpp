// Translator.cpp - live language switch
// By Ali Sakkaf - https://alisakkaf.com
#include "Translator.h"
#include "Logger.h"
#include "Settings.h"

#include <QApplication>
#include <QTranslator>
#include <QLibraryInfo>
#include <QLocale>
#include <QFile>

namespace verax {

Translator& Translator::instance() {
    static Translator t;
    return t;
}

Translator::Translator(QObject *parent) : QObject(parent) {}

void Translator::install(const QString &codeIn)
{
    Q_UNUSED(codeIn);
    const QString code = QStringLiteral("pl");

    if (code == m_current && m_appTr) {
        return;
    }

    Settings::instance().setLanguage(code);

    if (m_appTr) {
        qApp->removeTranslator(m_appTr);
        m_appTr->deleteLater();
        m_appTr = nullptr;
    }
    if (m_qtTr) {
        qApp->removeTranslator(m_qtTr);
        m_qtTr->deleteLater();
        m_qtTr = nullptr;
    }

    // Always install Qt's own Polish translations (for standard dialogs etc.)
    m_qtTr = new QTranslator(qApp);
    if (m_qtTr->load(QStringLiteral("qt_pl"),
                     QLibraryInfo::location(QLibraryInfo::TranslationsPath)))
    {
        qApp->installTranslator(m_qtTr);
    }

    // App translations from qrc
    m_appTr = new QTranslator(qApp);
    if (m_appTr->load(QStringLiteral(":/i18n/verax_pl.qm"))) {
        qApp->installTranslator(m_appTr);
    } else {
        Logger::warn(QStringLiteral("Translation file not found for: pl"));
    }

    qApp->setLayoutDirection(Qt::LeftToRight);

    m_current = code;
    Logger::info(QStringLiteral("Locale set: Polish (pl)"));
    emit localeChanged(code);
}

} // namespace verax
