#include "NotificationAlert.h"
#include "../utils/ThemeManager.h"

#include <QApplication>
#include <QScreen>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QTimer>
#include <QPropertyAnimation>
#include <QGraphicsOpacityEffect>
#include <QIcon>
#include <QPixmap>
#include <QFont>
#include <QStorageInfo>
#include <QFileInfo>

namespace verax {

NotificationAlert::NotificationAlert(AlertType type, const QString &title, const QString &subtitle,
                                     const QString &details,
                                     const QString &actionText, std::function<void()> actionCb,
                                     const QString &secondaryText, std::function<void()> secondaryCb,
                                     const QString &tertiaryText, std::function<void()> tertiaryCb)
    : QWidget(nullptr, Qt::FramelessWindowHint | Qt::WindowStaysOnTopHint | Qt::Tool | Qt::NoDropShadowWindowHint)
{
    setAttribute(Qt::WA_TranslucentBackground);
    setAttribute(Qt::WA_DeleteOnClose);
    setupUi(type, title, subtitle, details, actionText, actionCb, secondaryText, secondaryCb, tertiaryText, tertiaryCb);
}

void NotificationAlert::setupUi(AlertType type, const QString &title, const QString &subtitle,
                                const QString &details,
                                const QString &actionText, std::function<void()> actionCb,
                                const QString &secondaryText, std::function<void()> secondaryCb,
                                const QString &tertiaryText, std::function<void()> tertiaryCb)
{
    m_type = type;
    const bool isUsb = (type == UsbDevice);
    const bool isThreat = (type == Threat);
    setFixedWidth(isUsb ? 580 : (isThreat ? 600 : 460));

    QString accentColor = "#00e676";
    QString headerIcon = "🛡️";
    QString borderGlow = "rgba(0, 230, 118, 0.4)";
    QString bgGradient = "qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #0d1527, stop:1 #080d19)";

    if (isThreat) {
        accentColor = "#ef4444";
        headerIcon = "⚠️";
        borderGlow = "rgba(239, 68, 68, 0.5)";
        bgGradient = "qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #200d14, stop:1 #0f070b)";
    } else if (isUsb) {
        accentColor = "#0ea5e9";
        headerIcon = "🔌";
        borderGlow = "rgba(14, 165, 233, 0.5)";
        bgGradient = "qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #0a192f, stop:1 #061020)";
    }

    auto *rootCard = new QWidget(this);
    rootCard->setObjectName("alertCard");
    rootCard->setStyleSheet(QString(
        "#alertCard {"
        "  background: %1;"
        "  border: 2px solid %2;"
        "  border-radius: 14px;"
        "}"
    ).arg(bgGradient, accentColor));

    auto *mainLayout = new QVBoxLayout(rootCard);
    mainLayout->setContentsMargins(22, 20, 22, 20);
    mainLayout->setSpacing(14);

    // Top Header Row
    auto *topRow = new QHBoxLayout();
    topRow->setSpacing(12);

    auto *lblIcon = new QLabel(headerIcon, rootCard);
    QFont iconFont = lblIcon->font();
    iconFont.setPointSize(24);
    lblIcon->setFont(iconFont);

    auto *titleCol = new QVBoxLayout();
    titleCol->setSpacing(2);

    auto *lblBrand = new QLabel(QStringLiteral("MULTI-GUARD REAL-TIME ENGINE"), rootCard);
    lblBrand->setStyleSheet("font-size: 10px; font-weight: 800; letter-spacing: 1.5px; color: #94a3b8;");
    titleCol->addWidget(lblBrand);

    auto *lblTitle = new QLabel(title, rootCard);
    QFont titleFont = lblTitle->font();
    titleFont.setBold(true);
    titleFont.setPointSize(14);
    lblTitle->setFont(titleFont);
    lblTitle->setStyleSheet(QString("color: %1; font-weight: 800;").arg(accentColor));
    titleCol->addWidget(lblTitle);

    auto *btnDismiss = new QPushButton(QStringLiteral("✕"), rootCard);
    btnDismiss->setFixedSize(30, 30);
    btnDismiss->setCursor(Qt::PointingHandCursor);
    btnDismiss->setStyleSheet(
        "QPushButton { background: rgba(255, 255, 255, 0.08); color: #94a3b8; border: 1px solid rgba(255, 255, 255, 0.12); font-size: 14px; font-weight: bold; border-radius: 15px; }"
        "QPushButton:hover { color: #ffffff; background: rgba(239, 68, 68, 0.4); border-color: #ef4444; }"
    );
    connect(btnDismiss, &QPushButton::clicked, this, &QWidget::close);

    topRow->addWidget(lblIcon);
    topRow->addLayout(titleCol, 1);
    topRow->addWidget(btnDismiss);
    mainLayout->addLayout(topRow);

    // Subtitle
    auto *lblSub = new QLabel(subtitle, rootCard);
    lblSub->setWordWrap(true);
    lblSub->setStyleSheet("color: #f1f5f9; font-size: 13px; font-weight: 600; line-height: 18px;");
    mainLayout->addWidget(lblSub);

    // Rich Details Box
    if (!details.isEmpty()) {
        auto *detailsFrame = new QFrame(rootCard);
        detailsFrame->setStyleSheet(
            "QFrame { background: rgba(0, 0, 0, 0.45); border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 8px; padding: 10px; }"
        );
        auto *detLayout = new QVBoxLayout(detailsFrame);
        detLayout->setContentsMargins(10, 8, 10, 8);
        detLayout->setSpacing(4);

        auto *lblDet = new QLabel(details, detailsFrame);
        lblDet->setWordWrap(true);
        lblDet->setTextInteractionFlags(Qt::TextSelectableByMouse);
        lblDet->setStyleSheet(isThreat
            ? "color: #fca5a5; font-size: 12px; font-family: 'Consolas', 'Courier New', monospace; font-weight: 600;"
            : "color: #bae6fd; font-size: 12px; font-family: 'Consolas', 'Courier New', monospace; font-weight: 600;");
        detLayout->addWidget(lblDet);

        mainLayout->addWidget(detailsFrame);
    }

    // Action Buttons Row (Wide, prominent buttons)
    if (!actionText.isEmpty() || !secondaryText.isEmpty() || !tertiaryText.isEmpty()) {
        auto *btnRow = new QHBoxLayout();
        btnRow->setSpacing(10);

        // Tertiary Action (e.g. Ignore / Dismiss)
        if (!tertiaryText.isEmpty()) {
            auto *btnTer = new QPushButton(tertiaryText, rootCard);
            btnTer->setFixedHeight(38);
            btnTer->setCursor(Qt::PointingHandCursor);
            btnTer->setStyleSheet(
                "QPushButton { background: rgba(255,255,255,0.06); color: #94a3b8; border: 1px solid rgba(255,255,255,0.18); border-radius: 8px; padding: 0 16px; font-size: 12px; font-weight: 600; }"
                "QPushButton:hover { background: rgba(255,255,255,0.14); color: #ffffff; border-color: rgba(255,255,255,0.3); }"
            );
            connect(btnTer, &QPushButton::clicked, this, [this, tertiaryCb]{
                if (tertiaryCb) tertiaryCb();
                close();
            });
            btnRow->addWidget(btnTer);
        }

        btnRow->addStretch();

        // Secondary Action (e.g. Open Safely or Delete)
        if (!secondaryText.isEmpty()) {
            auto *btnSec = new QPushButton(secondaryText, rootCard);
            btnSec->setFixedHeight(38);
            btnSec->setCursor(Qt::PointingHandCursor);
            btnSec->setStyleSheet(
                "QPushButton { background: rgba(255,255,255,0.1); color: #f1f5f9; border: 1px solid rgba(255,255,255,0.25); border-radius: 8px; padding: 0 18px; font-size: 12px; font-weight: 700; }"
                "QPushButton:hover { background: rgba(255,255,255,0.2); color: #ffffff; border-color: #ffffff; }"
            );
            connect(btnSec, &QPushButton::clicked, this, [this, secondaryCb]{
                if (secondaryCb) secondaryCb();
                close();
            });
            btnRow->addWidget(btnSec);
        }

        // Primary Action (e.g. Scan USB Now or Quarantine Threat)
        if (!actionText.isEmpty()) {
            auto *btnAct = new QPushButton(actionText, rootCard);
            btnAct->setFixedHeight(38);
            btnAct->setCursor(Qt::PointingHandCursor);
            QString btnBg = isThreat
                ? "qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #dc2626, stop:1 #ef4444)"
                : "qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #0284c7, stop:1 #0ea5e9)";
            QString btnHover = isThreat ? "#b91c1c" : "#0369a1";

            btnAct->setStyleSheet(QString(
                "QPushButton { background: %1; color: #ffffff; border: 1px solid rgba(255,255,255,0.3); border-radius: 8px; padding: 0 22px; font-size: 12px; font-weight: 800; }"
                "QPushButton:hover { background: %2; border-color: #ffffff; }"
            ).arg(btnBg, btnHover));
            connect(btnAct, &QPushButton::clicked, this, [this, actionCb]{
                if (actionCb) actionCb();
                close();
            });
            btnRow->addWidget(btnAct);
        }

        mainLayout->addLayout(btnRow);
    }

    auto *rootLayout = new QVBoxLayout(this);
    rootLayout->setContentsMargins(0, 0, 0, 0);
    rootLayout->addWidget(rootCard);

    adjustSize();

    // Auto close only for simple Information popups
    if (type == Information) {
        m_autoCloseTimer = new QTimer(this);
        m_autoCloseTimer->setSingleShot(true);
        m_autoCloseTimer->setInterval(7000);
        connect(m_autoCloseTimer, &QTimer::timeout, this, &QWidget::close);
        m_autoCloseTimer->start();
    }

    repositionAndAnimate();
}

void NotificationAlert::repositionAndAnimate()
{
    QScreen *screen = QGuiApplication::primaryScreen();
    if (!screen) return;

    QRect avail = screen->availableGeometry();
    int targetX = avail.right() - width() - 28;
    int targetY = avail.bottom() - height() - 28;

    move(targetX, targetY + 40);
    show();

    m_anim = new QPropertyAnimation(this, "pos", this);
    m_anim->setDuration(320);
    m_anim->setStartValue(QPoint(targetX, targetY + 40));
    m_anim->setEndValue(QPoint(targetX, targetY));
    m_anim->setEasingCurve(QEasingCurve::OutCubic);
    m_anim->start(QAbstractAnimation::DeleteWhenStopped);
}

void NotificationAlert::enterEvent(QEvent *e)
{
    if (m_autoCloseTimer && m_autoCloseTimer->isActive()) {
        m_autoCloseTimer->stop();
    }
    QWidget::enterEvent(e);
}

void NotificationAlert::leaveEvent(QEvent *e)
{
    if (m_autoCloseTimer && m_type == Information) {
        m_autoCloseTimer->start(4000);
    }
    QWidget::leaveEvent(e);
}

void NotificationAlert::showThreat(const QString &threatName, const QString &filePath,
                                   std::function<void()> onQuarantine,
                                   std::function<void()> onDeletePermanent,
                                   std::function<void()> onIgnore)
{
    QString detailsText = QStringLiteral("Zagrożenie: %1\nŚcieżka pliku: %2").arg(threatName, filePath);
    auto *alert = new NotificationAlert(
        Threat,
        tr("WYKRYTO ZAGROŻENIE W CZASIE RZECZYWISTYM!"),
        tr("System aktywnej tarczy zablokował podejrzaną aktywność złośliwego oprogramowania:"),
        detailsText,
        tr("🛡️ Poddaj kwarantannie"), onQuarantine,
        tr("🗑️ Usuń trwale"), onDeletePermanent,
        tr("⚠️ Zignoruj"), onIgnore
    );
    Q_UNUSED(alert);
}

void NotificationAlert::showUsb(const QString &drivePath,
                                std::function<void()> onScan,
                                std::function<void()> onOpenSafely,
                                std::function<void()> onIgnore)
{
    QStorageInfo storage(drivePath);
    QString driveDetails;
    if (storage.isValid() && storage.isReady()) {
        QString label = storage.name().trimmed();
        if (label.isEmpty()) label = tr("Dysk wymienny");
        double totalGb = storage.bytesTotal() / (1024.0 * 1024.0 * 1024.0);
        double freeGb = storage.bytesAvailable() / (1024.0 * 1024.0 * 1024.0);
        driveDetails = QStringLiteral("Napęd: %1 (%2)\nPojemność: %3 GB (Wolne: %4 GB)\nFormat: %5")
                           .arg(drivePath, label,
                                QString::number(totalGb, 'f', 1),
                                QString::number(freeGb, 'f', 1),
                                QString::fromUtf8(storage.fileSystemType()));
    } else {
        driveDetails = QStringLiteral("Napęd wymienny: %1\nZalecana natychmiastowa weryfikacja plików i sektorów rozruchowych.").arg(drivePath);
    }

    auto *alert = new NotificationAlert(
        UsbDevice,
        tr("WYKRYTO NOWĄ PAMIĘĆ USB"),
        tr("Podłączono zewnętrzny nośnik danych. Czy chcesz sprawdzić zawartość pod kątem wirusów?"),
        driveDetails,
        tr("🔍 Skanuj pamięć USB"), onScan,
        tr("📁 Bezpieczne otwarcie"), onOpenSafely,
        tr("✕ Zignoruj"), onIgnore
    );
    Q_UNUSED(alert);
}

void NotificationAlert::showInfo(const QString &title, const QString &message)
{
    auto *alert = new NotificationAlert(
        Information,
        title,
        message,
        QString(),
        tr("OK"), nullptr
    );
    Q_UNUSED(alert);
}

} // namespace verax
