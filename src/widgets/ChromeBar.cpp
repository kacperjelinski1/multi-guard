// ChromeBar.cpp - title bar for frameless window matching AEGIS design
#include "ChromeBar.h"
#include "../../Version.h"

#include <QLabel>
#include <QPushButton>
#include <QLineEdit>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QMouseEvent>
#include <QFontMetrics>
#include <QPixmap>
#include <QIcon>
#include <QStyle>
#include <QCompleter>
#include <QStandardItemModel>
#include <QAbstractItemView>
#include "../core/Settings.h"

namespace verax {

ChromeBar::ChromeBar(QWidget *parent) : QWidget(parent)
{
    setObjectName("ChromeBar");
    setAttribute(Qt::WA_StyledBackground, true);

    auto *layout = new QHBoxLayout(this);
    layout->setContentsMargins(16, 8, 16, 8);
    layout->setSpacing(12);

    // Balanced spacer to center search bar relative to right-side controls (~230px)
    layout->addSpacing(230);

    // Center Search Bar Pill
    layout->addStretch(1);
    m_searchEdit = new QLineEdit(this);
    m_searchEdit->setObjectName("topSearchBar");
    m_searchEdit->setPlaceholderText(tr("🔍 Szukaj funkcji, ustawień, modułów..."));
    m_searchEdit->setFixedWidth(340);
    m_searchEdit->setFixedHeight(32);
    m_searchEdit->setClearButtonEnabled(true);
    layout->addWidget(m_searchEdit);
    layout->addStretch(1);

    // Notification Bell Button
    m_btnNotifications = new QPushButton(this);
    m_btnNotifications->setObjectName("btnTopBell");
    m_btnNotifications->setIcon(QIcon(":/assets/icons/icon_bell.svg"));
    m_btnNotifications->setIconSize(QSize(20, 20));
    m_btnNotifications->setToolTip(tr("Powiadomienia"));
    m_btnNotifications->setFixedSize(36, 32);
    m_btnNotifications->setCursor(Qt::PointingHandCursor);
    m_btnNotifications->setFocusPolicy(Qt::NoFocus);
    layout->addWidget(m_btnNotifications);

    // User Profile Widget (Kacper | Premium)
    m_userWidget = new QWidget(this);
    m_userWidget->setObjectName("userProfileWidget");
    m_userWidget->setCursor(Qt::PointingHandCursor);
    m_userWidget->setToolTip(tr("Kliknij, aby przejść do zakładki Moje konto"));
    m_userWidget->installEventFilter(this);

    auto *userLayout = new QHBoxLayout(m_userWidget);
    userLayout->setContentsMargins(4, 0, 8, 0);
    userLayout->setSpacing(8);

    auto *lblAvatar = new QLabel(m_userWidget);
    lblAvatar->setObjectName("lblUserAvatar");
    QPixmap avPm(":/assets/user_avatar.png");
    if (!avPm.isNull()) {
        lblAvatar->setPixmap(avPm.scaled(28, 28, Qt::KeepAspectRatio, Qt::SmoothTransformation));
    }
    lblAvatar->setFixedSize(28, 28);
    userLayout->addWidget(lblAvatar);

    auto *textLayout = new QVBoxLayout();
    textLayout->setContentsMargins(0, 0, 0, 0);
    textLayout->setSpacing(0);

    m_userNameLabel = new QLabel(QStringLiteral("Kacper"), m_userWidget);
    m_userNameLabel->setObjectName("lblUserName");
    m_userNameLabel->setStyleSheet("font-weight: 700; font-size: 11px; color: #FFFFFF; line-height: 12px;");
    textLayout->addWidget(m_userNameLabel);

    m_userTierLabel = new QLabel(QStringLiteral("Premium"), m_userWidget);
    m_userTierLabel->setObjectName("lblUserTier");
    m_userTierLabel->setStyleSheet("font-size: 9px; color: #38BDF8; font-weight: 600; line-height: 10px;");
    textLayout->addWidget(m_userTierLabel);

    userLayout->addLayout(textLayout);
    layout->addWidget(m_userWidget);

    layout->addSpacing(6);

    // Window controls: Minimize, Maximize, Close
    m_btnMin = new QPushButton(QStringLiteral("—"), this);
    m_btnMin->setObjectName("btnMinimize");
    m_btnMin->setFixedSize(30, 28);
    m_btnMin->setCursor(Qt::PointingHandCursor);
    m_btnMin->setFocusPolicy(Qt::NoFocus);

    m_btnMax = new QPushButton(QStringLiteral("□"), this);
    m_btnMax->setObjectName("btnMaximize");
    m_btnMax->setFixedSize(30, 28);
    m_btnMax->setCursor(Qt::PointingHandCursor);
    m_btnMax->setFocusPolicy(Qt::NoFocus);

    m_btnClose = new QPushButton(QStringLiteral("✕"), this);
    m_btnClose->setObjectName("btnClose");
    m_btnClose->setFixedSize(30, 28);
    m_btnClose->setCursor(Qt::PointingHandCursor);
    m_btnClose->setFocusPolicy(Qt::NoFocus);

    m_btnMax->setVisible(false);
    layout->addWidget(m_btnMin);
    layout->addWidget(m_btnClose);

    setFixedHeight(48);

    connect(m_btnNotifications, &QPushButton::clicked, this, &ChromeBar::notificationsClicked);
    connect(m_btnMin,           &QPushButton::clicked, this, &ChromeBar::minimizeClicked);
    connect(m_btnMax,           &QPushButton::clicked, this, &ChromeBar::maximizeClicked);
    connect(m_btnClose,         &QPushButton::clicked, this, &ChromeBar::closeClicked);

    setupSearchCompleter();
}

void ChromeBar::setupSearchCompleter()
{
    auto *model = new QStandardItemModel(this);

    struct SearchEntry {
        QString text;
        int pageIndex;
    };

    const QVector<SearchEntry> entries = {
        { tr("🔍 Szybkie skanowanie systemu"), 1 },
        { tr("🔍 Pełne skanowanie dysków"), 1 },
        { tr("🔍 Skanowanie pamięci RAM (Procesy)"), 1 },
        { tr("🛡️ Ochrona w czasie rzeczywistym"), 0 },
        { tr("🌐 Ochrona WWW i przeglądarki (Web Shield)"), 7 },
        { tr("🧱 Zapora sieciowa (Firewall)"), 6 },
        { tr("☣️ Kwarantanna i izolacja plików"), 3 },
        { tr("⚡ Optymalizacja i czytniki wydajności"), 5 },
        { tr("🗑️ Czyszczenie plików tymczasowych (Temp)"), 5 },
        { tr("🚀 Menedżer autostartu programów"), 5 },
        { tr("🩺 Zdalna pomoc i naprawa Multi-Servis"), 8 },
        { tr("📊 Raporty diagnostyczne stacji"), 8 },
        { tr("👤 Moje konto i dane licencji"), 12 },
        { tr("🔑 Zmień klucz licencyjny"), 12 },
        { tr("⚙️ Ustawienia i konfiguracja"), 9 },
        { tr("🚫 Wykluczenia i biała lista"), 9 },
        { tr("🔄 Aktualizacje programu i sygnatur"), 9 },
        { tr("ℹ️ O programie Multi-Guard"), 10 }
    };

    for (const auto &e : entries) {
        auto *item = new QStandardItem(e.text);
        item->setData(e.pageIndex, Qt::UserRole);
        model->appendRow(item);
    }

    auto *completer = new QCompleter(model, this);
    completer->setCaseSensitivity(Qt::CaseInsensitive);
    completer->setFilterMode(Qt::MatchContains);
    completer->setCompletionMode(QCompleter::PopupCompletion);

    auto *popup = completer->popup();
    popup->setStyleSheet(
        "QListView { background-color: #0d1527; color: #f1f5f9; border: 1px solid #1e293b; border-radius: 8px; padding: 4px; selection-background-color: #0284c7; selection-color: #ffffff; }"
        "QListView::item { height: 28px; padding-left: 8px; border-radius: 4px; }"
        "QListView::item:hover { background-color: rgba(2, 132, 199, 0.4); }"
    );

    m_searchEdit->setCompleter(completer);

    connect(completer, QOverload<const QModelIndex &>::of(&QCompleter::activated), this, [this](const QModelIndex &idx){
        int page = idx.data(Qt::UserRole).toInt();
        m_searchEdit->clear();
        emit featureNavRequested(page);
    });

    connect(m_searchEdit, &QLineEdit::returnPressed, this, [this, model]{
        QString text = m_searchEdit->text().trimmed();
        if (text.isEmpty()) return;
        for (int r = 0; r < model->rowCount(); ++r) {
            auto *item = model->item(r);
            if (item && item->text().contains(text, Qt::CaseInsensitive)) {
                int page = item->data(Qt::UserRole).toInt();
                m_searchEdit->clear();
                emit featureNavRequested(page);
                return;
            }
        }
        // Default to search or scan config if no exact match
        emit featureNavRequested(1);
        m_searchEdit->clear();
    });
}

void ChromeBar::updateUserProfile(const QString &name, const QString &tier)
{
    if (m_userNameLabel && !name.isEmpty()) {
        m_userNameLabel->setText(name);
    }
    if (m_userTierLabel && !tier.isEmpty()) {
        m_userTierLabel->setText(tier);
    }
}

bool ChromeBar::eventFilter(QObject *watched, QEvent *event)
{
    if (watched == m_userWidget && event->type() == QEvent::MouseButtonRelease) {
        emit userProfileClicked();
        return true;
    }
    return QWidget::eventFilter(watched, event);
}

void ChromeBar::setTitle(const QString &) {}
void ChromeBar::setStatusText(const QString &) {}
void ChromeBar::setStatusKind(const QString &) {}

void ChromeBar::updateMaximizeIcon(bool isMaximized)
{
    if (m_btnMax) {
        m_btnMax->setText(isMaximized ? QStringLiteral("❐") : QStringLiteral("□"));
    }
}

void ChromeBar::mousePressEvent(QMouseEvent *e)
{
    if (e->button() == Qt::LeftButton) {
        m_dragging = true;
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
        m_dragOrigin = e->globalPosition().toPoint() - window()->pos();
#else
        m_dragOrigin = e->globalPos() - window()->pos();
#endif
        e->accept();
    }
}

void ChromeBar::mouseMoveEvent(QMouseEvent *e)
{
    if (m_dragging && (e->buttons() & Qt::LeftButton)) {
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
        window()->move(e->globalPosition().toPoint() - m_dragOrigin);
#else
        window()->move(e->globalPos() - m_dragOrigin);
#endif
        e->accept();
    }
}

void ChromeBar::mouseReleaseEvent(QMouseEvent *e)
{
    m_dragging = false;
    e->accept();
}

void ChromeBar::mouseDoubleClickEvent(QMouseEvent *e)
{
    // Fixed window size - maximize disabled
    e->accept();
}

} // namespace verax
