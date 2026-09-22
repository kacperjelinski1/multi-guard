#pragma once

#include <QDialog>
#include <QTableWidget>
#include <QPushButton>
#include <QLineEdit>
#include <QLabel>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include "../core/StartupManager.h"

namespace verax {

class StartupManagerDialog : public QDialog {
    Q_OBJECT
public:
    explicit StartupManagerDialog(QWidget *parent = nullptr);

    int activeCount() const { return m_activeCount; }
    int totalCount() const { return m_entries.size(); }

signals:
    void entriesChanged();

private slots:
    void refreshEntries();
    void onToggleSelected();
    void onDeleteSelected();
    void onFilterChanged(const QString &text);

private:
    void setupUi();
    void updateTableDisplay();

    QList<StartupEntry> m_entries;
    int m_activeCount = 0;

    QLineEdit    *m_searchBox = nullptr;
    QTableWidget *m_table     = nullptr;
    QLabel       *m_statusLbl = nullptr;
    QPushButton  *m_btnToggle = nullptr;
    QPushButton  *m_btnDelete = nullptr;
    QPushButton  *m_btnRefresh = nullptr;
    QPushButton  *m_btnClose  = nullptr;
};

} // namespace verax
