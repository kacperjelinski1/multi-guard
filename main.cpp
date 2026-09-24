#include <QApplication>
#include <QFontDatabase>
#include "src/ui/MainWindow.h"
#include "src/core/Logger.h"
#include "src/core/Settings.h"
#include "src/core/Translator.h"
#include "src/utils/ThemeManager.h"
#include "harden.h"

int main(int argc, char *argv[])
{
    shield::harden();
    QCoreApplication::setAttribute(Qt::AA_EnableHighDpiScaling);
    QCoreApplication::setAttribute(Qt::AA_UseHighDpiPixmaps);

    QApplication a(argc, argv);

    verax::Logger::init();
    verax::Settings::instance().load();
    verax::Translator::instance().install(verax::Settings::instance().language());
    verax::ThemeManager::applyTheme();

    verax::MainWindow w;
    w.show();

    return a.exec();
}
