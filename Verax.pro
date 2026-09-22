#-----------------------------------------------------------------------
# Verax.pro - VeraxCore Antivirus, Qt 5.14.2 Static, MinGW 32-bit
# Project file kept as Verax.pro on purpose: renaming would orphan the
# Makefile / .obj / .moc / .ui / .qrc trees that qmake has already
# generated. The user-visible binary is set via TARGET below.
# By Ali Sakkaf  -  https://alisakkaf.com
#-----------------------------------------------------------------------

QT       += core gui widgets network concurrent xml sql svg
CONFIG   += c++17 qt warn_off resources_big
TARGET    = Multi-Guard
TEMPLATE  = app
DESTDIR   = $$PWD/RELEASED

# Size optimization (-Os) + dead-code elim + hardening
QMAKE_CXXFLAGS_RELEASE -= -O2
QMAKE_CXXFLAGS_RELEASE += -Os -ffunction-sections -fdata-sections \
                          -fmerge-all-constants -fstack-protector-strong \
                          -D_FORTIFY_SOURCE=2
QMAKE_CFLAGS_RELEASE   -= -O2
QMAKE_CFLAGS_RELEASE   += -Os -ffunction-sections -fdata-sections \
                          -fmerge-all-constants -fstack-protector-strong
static {
    QMAKE_LFLAGS_RELEASE += -static
}
QMAKE_LFLAGS_RELEASE   += -Wl,--gc-sections -s -Wl,--exclude-libs,ALL \
                          -Wl,--build-id=none -Wl,--dynamicbase \
                          -Wl,--nxcompat \
                          -static-libgcc -static-libstdc++


# ─── Stack Protector & Security Flags ─────────────────────────────────

# تمرير أمر الحماية للرابط (Linker) أيضاً لضمان التوافق التام
QMAKE_LFLAGS_RELEASE += -fstack-protector-strong

QMAKE_RESOURCE_FLAGS   += -compress 9 -threshold 1

QTPLUGIN.imageformats   = qjpeg qico
QTPLUGIN.sqldrivers     = qsqlite

DEFINES += QT_DEPRECATED_WARNINGS
win32:DEFINES += _WIN32_WINNT=0x0601 WINVER=0x0601 NTDDI_VERSION=0x06010000 \
                 WIN32_LEAN_AND_MEAN NOMINMAX

INCLUDEPATH += $$PWD \
               $$PWD/src \
               $$PWD/src/core \
               $$PWD/src/ui \
               $$PWD/src/widgets \
               $$PWD/src/utils

# ─── Sources ──────────────────────────────────────────────────────────
SOURCES += \
    main.cpp \
    src/core/ShieldEngine.cpp \
    src/core/Scanner.cpp \
    src/core/SignatureDb.cpp \
    src/core/Quarantine.cpp \
    src/core/Repair.cpp \
    src/core/SystemEnum.cpp \
    src/core/Settings.cpp \
    src/core/Translator.cpp \
    src/core/Logger.cpp \
    src/core/Updater.cpp \
    src/core/RealTimeShield.cpp \
    src/core/WebShield.cpp \
    src/ui/MainWindow.cpp \
    src/widgets/AnimatedButton.cpp \
    src/widgets/ProgressRing.cpp \
    src/widgets/SpinnerRing.cpp \
    src/widgets/ThreatCard.cpp \
    src/widgets/ScanOptionsDialog.cpp \
    src/widgets/DriveTile.cpp \
    src/widgets/Toaster.cpp \
    src/widgets/NotificationAlert.cpp \
    src/widgets/BrandIcon.cpp \
    src/widgets/SurfaceCard.cpp \
    src/widgets/ChromeBar.cpp \
    src/widgets/PageTransition.cpp \
    src/utils/HashUtils.cpp \
    src/utils/FileOps.cpp \
    src/utils/ContextMenuManager.cpp \
    src/core/SystemOptimizer.cpp \
    src/core/StartupManager.cpp \
    src/core/HardwareMonitor.cpp \
    src/utils/ThemeManager.cpp \
    src/core/RansomwareShield.cpp \
    src/core/AuditLogger.cpp \
    src/core/ReportGenerator.cpp \
    src/core/Ed25519.cpp \
    src/core/LicenseManager.cpp \
    src/core/FirewallManager.cpp \
    src/core/BrowserProtectionManager.cpp \
    src/core/tweetnacl.c

HEADERS += \
    Version.h \
    harden.h \
    src/core/ShieldEngine.h \
    src/core/Scanner.h \
    src/core/SignatureDb.h \
    src/core/Quarantine.h \
    src/core/Repair.h \
    src/core/SystemEnum.h \
    src/core/Settings.h \
    src/core/Translator.h \
    src/core/Logger.h \
    src/core/Updater.h \
    src/core/RealTimeShield.h \
    src/core/WebShield.h \
    src/core/FirewallManager.h \
    src/core/BrowserProtectionManager.h \
    src/core/SystemOptimizer.h \
    src/core/StartupManager.h \
    src/core/HardwareMonitor.h \
    src/ui/MainWindow.h \
    src/widgets/AnimatedButton.h \
    src/widgets/ProgressRing.h \
    src/widgets/SpinnerRing.h \
    src/widgets/ThreatCard.h \
    src/widgets/ScanOptionsDialog.h \
    src/widgets/DriveTile.h \
    src/widgets/Toaster.h \
    src/widgets/NotificationAlert.h \
    src/widgets/BrandIcon.h \
    src/widgets/SurfaceCard.h \
    src/widgets/ChromeBar.h \
    src/widgets/PageTransition.h \
    src/utils/HashUtils.h \
    src/utils/FileOps.h \
    src/utils/Strings.h \
    src/utils/ContextMenuManager.h \
    src/utils/ThemeManager.h \
    src/core/RansomwareShield.h \
    src/core/AuditLogger.h \
    src/core/ReportGenerator.h \
    src/core/Ed25519.h \
    src/core/LicenseManager.h \
    src/core/tweetnacl.h

FORMS   += src/ui/mainwindow.ui

# ─── Resources ────────────────────────────────────────────────────────
RESOURCES += Verax.qrc

# ─── Translations ─────────────────────────────────────────────────────
TRANSLATIONS += i18n/verax_pl.ts

# ─── Windows-specific ─────────────────────────────────────────────────
win32 {
    RC_FILE = app.rc
    LIBS += -ladvapi32 -lole32 -lshell32 -luuid -lversion -lwbemuuid \
            -lcrypt32 -lws2_32 -luserenv -lpsapi -lnetapi32 -lshlwapi \
            -lwintrust -lsetupapi -lwtsapi32 -lgdi32 -loleaut32 -limm32 \
            -ldwmapi -luxtheme -lbcrypt -lncrypt
}

# ─── Build folders ────────────────────────────────────────────────────
OBJECTS_DIR = .obj
MOC_DIR     = .moc
RCC_DIR     = .qrc
UI_DIR      = .ui
