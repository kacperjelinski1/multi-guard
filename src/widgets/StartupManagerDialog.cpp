#include "StartupManagerDialog.h"
#include "Toaster.h"
#include <QHeaderView>
#include <QMessageBox>
#include <QIcon>
#include <QGraphicsDropShadowEffect>

namespace verax {

StartupManagerDialog::StartupManagerDialog(QWidget *parent)
    : QDialog(parent)
{
    setWindowTitle(tr("Menedżer Autostartu Windows — Multi-Guard"));
    setWindowIcon(QIcon(QStringLiteral(":/assets/logo.png")));
    setMinimumSize(780, 520);
    resize(840, 560);
    setModal(true);

    setStyleSheet(QStringLiteral(
        "QDialog {"
        "  background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #0B1320, stop:0.5 #0F1B2D, stop:1 #0A111E);"
        "  color: #E2E8F0;"
        "  font-family: 'Segoe UI', system-ui, sans-serif;"
        "}"
        "QLabel { color: #E2E8F0; }"
        "QLineEdit {"
        "  background-color: rgba(15, 23, 42, 0.85);"
        "  border: 1px solid rgba(56, 189, 248, 0.28);"
        "  border-radius: 8px;"
        "  padding: 8px 14px;"
        "  color: #F8FAFC;"
        "  font-size: 10pt;"
        "}"
        "QLineEdit:focus {"
        "  border: 1px solid #38BDF8;"
        "  background-color: rgba(15, 23, 42, 0.98);"
        "}"
        "QTableWidget {"
        "  background-color: rgba(11, 19, 32, 0.85);"
        "  border: 1px solid rgba(56, 189, 248, 0.18);"
        "  border-radius: 10px;"
        "  gridline-color: rgba(56, 189, 248, 0.08);"
        "  color: #E2E8F0;"
        "  selection-background-color: rgba(56, 189, 248, 0.25);"
        "  selection-color: #FFFFFF;"
        "  outline: none;"
        "}"
        "QHeaderView::section {"
        "  background-color: #0F1F35;"
        "  color: #94A3B8;"
        "  padding: 8px;"
        "  font-weight: 700;"
        "  font-size: 9pt;"
        "  border: none;"
        "  border-bottom: 1px solid rgba(56, 189, 248, 0.2);"
        "}"
        "QPushButton {"
        "  background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #1E293B, stop:1 #0F172A);"
        "  border: 1px solid rgba(56, 189, 248, 0.35);"
        "  border-radius: 8px;"
        "  color: #F8FAFC;"
        "  font-weight: 600;"
        "  font-size: 9pt;"
        "  padding: 8px 16px;"
        "}"
        "QPushButton:hover {"
        "  background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #2563EB, stop:1 #1D4ED8);"
        "  border-color: #38BDF8;"
        "}"
        "QPushButton:disabled {"
        "  background: rgba(30, 41, 59, 0.5);"
        "  color: #64748B;"
        "  border-color: rgba(255, 255, 255, 0.1);"
        "}"
    ));

    setupUi();
    refreshEntries();
}

void StartupManagerDialog::setupUi()
{
    auto *root = new QVBoxLayout(this);
    root->setContentsMargins(24, 20, 24, 20);
    root->setSpacing(14);

    // ── Header ──
    auto *headerLayout = new QHBoxLayout();
    headerLayout->setSpacing(14);

    auto *iconLbl = new QLabel(this);
    iconLbl->setPixmap(QIcon(QStringLiteral(":/assets/logo.png")).pixmap(42, 42));
    headerLayout->addWidget(iconLbl);

    auto *titleCol = new QVBoxLayout();
    titleCol->setSpacing(2);

    auto *titleLbl = new QLabel(tr("Menedżer Autostartu Windows"), this);
    titleLbl->setStyleSheet(QStringLiteral("font-size: 15pt; font-weight: 800; color: #FFFFFF;"));
    titleCol->addWidget(titleLbl);

    auto *subtitleLbl = new QLabel(tr("Zarządzaj programami uruchamianymi przy starcie systemu, aby przyspieszyć rozruch."), this);
    subtitleLbl->setStyleSheet(QStringLiteral("font-size: 9pt; color: #94A3B8;"));
    titleCol->addWidget(subtitleLbl);

    headerLayout->addLayout(titleCol);
    headerLayout->addStretch();

    root->addLayout(headerLayout);

    // ── Search & Filter ──
    m_searchBox = new QLineEdit(this);
    m_searchBox->setPlaceholderText(tr("Szukaj programu lub polecenia autostartu..."));
    m_searchBox->setClearButtonEnabled(true);
    connect(m_searchBox, &QLineEdit::textChanged, this, &StartupManagerDialog::onFilterChanged);
    root->addWidget(m_searchBox);

    // ── Table ──
    m_table = new QTableWidget(this);
    m_table->setColumnCount(5);
    m_table->setHorizontalHeaderLabels({
        tr("Nazwa programu"),
        tr("Lokalizacja"),
        tr("Podpis cyfrowy"),
        tr("Stan"),
        tr("Polecenie / Ścieżka")
    });
    m_table->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    m_table->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    m_table->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    m_table->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    m_table->horizontalHeader()->setSectionResizeMode(4, QHeaderView::Stretch);
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setSelectionMode(QAbstractItemView::SingleSelection);
    m_table->verticalHeader()->setVisible(false);
    m_table->setShowGrid(true);
    root->addWidget(m_table, 1);

    // ── Bottom Bar ──
    auto *bottomLayout = new QHBoxLayout();
    bottomLayout->setSpacing(10);

    m_statusLbl = new QLabel(this);
    m_statusLbl->setStyleSheet(QStringLiteral("color: #38BDF8; font-size: 9pt; font-weight: 600;"));
    bottomLayout->addWidget(m_statusLbl);
    bottomLayout->addStretch();

    m_btnToggle = new QPushButton(tr("Włącz / Wyłącz"), this);
    m_btnToggle->setCursor(Qt::PointingHandCursor);
    connect(m_btnToggle, &QPushButton::clicked, this, &StartupManagerDialog::onToggleSelected);
    bottomLayout->addWidget(m_btnToggle);

    m_btnDelete = new QPushButton(tr("Usuń wpis"), this);
    m_btnDelete->setCursor(Qt::PointingHandCursor);
    m_btnDelete->setStyleSheet(QStringLiteral(
        "QPushButton { background: rgba(239, 68, 68, 0.15); border: 1px solid rgba(239, 68, 68, 0.4); color: #FCA5A5; }"
        "QPushButton:hover { background: #DC2626; color: #FFFFFF; border-color: #EF4444; }"
    ));
    connect(m_btnDelete, &QPushButton::clicked, this, &StartupManagerDialog::onDeleteSelected);
    bottomLayout->addWidget(m_btnDelete);

    m_btnRefresh = new QPushButton(tr("Odśwież"), this);
    m_btnRefresh->setCursor(Qt::PointingHandCursor);
    connect(m_btnRefresh, &QPushButton::clicked, this, &StartupManagerDialog::refreshEntries);
    bottomLayout->addWidget(m_btnRefresh);

    m_btnClose = new QPushButton(tr("Zamknij"), this);
    m_btnClose->setCursor(Qt::PointingHandCursor);
    connect(m_btnClose, &QPushButton::clicked, this, &QDialog::accept);
    bottomLayout->addWidget(m_btnClose);

    root->addLayout(bottomLayout);
}

void StartupManagerDialog::refreshEntries()
{
    m_entries = StartupManager::getEntries();
    m_activeCount = 0;
    for (const auto &e : m_entries) {
        if (e.enabled) m_activeCount++;
    }
    updateTableDisplay();
    emit entriesChanged();
}

void StartupManagerDialog::updateTableDisplay()
{
    m_table->setRowCount(0);
    const QString filter = m_searchBox ? m_searchBox->text().trimmed().toLower() : QString();

    for (int i = 0; i < m_entries.size(); ++i) {
        const StartupEntry &e = m_entries[i];

        if (!filter.isEmpty()) {
            if (!e.name.toLower().contains(filter) &&
                !e.command.toLower().contains(filter) &&
                !e.location.toLower().contains(filter)) {
                continue;
            }
        }

        int r = m_table->rowCount();
        m_table->insertRow(r);

        auto *nameItem = new QTableWidgetItem(e.name);
        nameItem->setData(Qt::UserRole, i); // index into m_entries
        nameItem->setFont(QFont(font().family(), 9, QFont::Bold));

        auto *locItem = new QTableWidgetItem(e.location);
        locItem->setForeground(QColor(148, 163, 184));

        auto *signItem = new QTableWidgetItem(e.isSigned ? tr("Zaufany (Authenticode)") : tr("Brak podpisu"));
        signItem->setForeground(e.isSigned ? QColor(52, 211, 153) : QColor(248, 113, 113));

        auto *statusItem = new QTableWidgetItem(e.enabled ? tr("Aktywny") : tr("Wyłączony"));
        statusItem->setForeground(e.enabled ? QColor(56, 189, 248) : QColor(100, 116, 139));
        statusItem->setFont(QFont(font().family(), 9, QFont::DemiBold));

        auto *cmdItem = new QTableWidgetItem(e.command);
        cmdItem->setForeground(QColor(203, 213, 225));

        m_table->setItem(r, 0, nameItem);
        m_table->setItem(r, 1, locItem);
        m_table->setItem(r, 2, signItem);
        m_table->setItem(r, 3, statusItem);
        m_table->setItem(r, 4, cmdItem);
    }

    if (m_statusLbl) {
        m_statusLbl->setText(tr("Wszystkich wpisów: %1 (Aktywnych: %2)")
            .arg(m_entries.size())
            .arg(m_activeCount));
    }
}

void StartupManagerDialog::onFilterChanged(const QString &)
{
    updateTableDisplay();
}

void StartupManagerDialog::onToggleSelected()
{
    int r = m_table->currentRow();
    if (r < 0) {
        QMessageBox::information(this, tr("Autostart"), tr("Wybierz wpis z listy, aby zmienić jego stan."));
        return;
    }

    QTableWidgetItem *item = m_table->item(r, 0);
    if (!item) return;

    int idx = item->data(Qt::UserRole).toInt();
    if (idx < 0 || idx >= m_entries.size()) return;

    StartupEntry &e = m_entries[idx];
    bool newState = !e.enabled;

    if (StartupManager::setEntryEnabled(e, newState)) {
        e.enabled = newState;
        refreshEntries();
        Toaster::show(this, newState ? tr("Włączono autostart dla: %1").arg(e.name)
                                     : tr("Wyłączono autostart dla: %1").arg(e.name),
                      Toaster::Success);
    } else {
        Toaster::show(this, tr("Nie udało się zmienić stanu wpisu autostartu."), Toaster::Error);
    }
}

void StartupManagerDialog::onDeleteSelected()
{
    int r = m_table->currentRow();
    if (r < 0) {
        QMessageBox::information(this, tr("Autostart"), tr("Wybierz wpis z listy, aby go usunąć."));
        return;
    }

    QTableWidgetItem *item = m_table->item(r, 0);
    if (!item) return;

    int idx = item->data(Qt::UserRole).toInt();
    if (idx < 0 || idx >= m_entries.size()) return;

    const StartupEntry &e = m_entries[idx];

    auto reply = QMessageBox::question(this, tr("Potwierdzenie usunięcia"),
        tr("Czy na pewno chcesz bezpowrotnie usunąć wpis autostartu '%1'?\n\nŚcieżka: %2")
        .arg(e.name, e.command),
        QMessageBox::Yes | QMessageBox::No, QMessageBox::No);

    if (reply == QMessageBox::Yes) {
        if (StartupManager::deleteEntry(e)) {
            refreshEntries();
            Toaster::show(this, tr("Pomyślnie usunięto wpis autostartu."), Toaster::Success);
        } else {
            Toaster::show(this, tr("Błąd: Nie udało się usunąć wpisu z rejestru."), Toaster::Error);
        }
    }
}

} // namespace verax
