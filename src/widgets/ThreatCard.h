// ThreatCard.h - card showing one detected threat with selection + repair failure
// By Ali Sakkaf - https://alisakkaf.com
#pragma once
#include "SurfaceCard.h"
#include "../core/Scanner.h"
#include <QLabel>
#include <QPushButton>
#include <QCheckBox>
#include <QStyle>
#include <QVariant>

namespace verax {

class ThreatCard : public SurfaceCard {
    Q_OBJECT
public:
    explicit ThreatCard(const ThreatInfo &info, QWidget *parent = nullptr);
    const ThreatInfo& info() const { return m_info; }
    void retranslate();

    // Switch the card into a "Already actioned" visual state
    void setActioned(const QString &actionLabel);

    // Multi-select support
    bool isSelected() const {
        return m_chkSelect && m_chkSelect->isChecked();
    }
    void setSelected(bool sel) {
        if (m_chkSelect) m_chkSelect->setChecked(sel);
    }

    // When Clean Threat fails: hide quarantine, show delete as primary
    void setRepairFailed() {
        // Hide quarantine — when repair fails, the file is dangerous and must be deleted
        if (m_btnQuar) m_btnQuar->setVisible(false);
        if (m_btnRepair) m_btnRepair->setVisible(false);

        // Make Delete the primary action
        if (m_btnDel) {
            m_btnDel->setProperty("kind", "danger");
            m_btnDel->setText(tr("Delete (must remove)"));
            m_btnDel->setEnabled(true);
            style()->unpolish(m_btnDel);
            style()->polish(m_btnDel);
        }

        // Update action tag
        if (m_lblActionTag) {
            m_lblActionTag->setText(tr("Clean Failed ✗"));
            m_lblActionTag->setProperty("kind", "danger");
            m_lblActionTag->setVisible(true);
            style()->unpolish(m_lblActionTag);
            style()->polish(m_lblActionTag);
        }
    }

    // Filter helpers
    QString severityLevel() const {
        if (m_info.severity >= 8 || m_info.score >= 80 ||
            m_info.family.contains(QLatin1String("Ransom"), Qt::CaseInsensitive) ||
            m_info.family.contains(QLatin1String("Trojan"), Qt::CaseInsensitive) ||
            m_info.family.contains(QLatin1String("Worm"), Qt::CaseInsensitive) ||
            m_info.detectionName.startsWith(QLatin1String("Virus:"), Qt::CaseInsensitive) ||
            m_info.detectionName.startsWith(QLatin1String("Ransom:"), Qt::CaseInsensitive) ||
            m_info.detectionName.startsWith(QLatin1String("Trojan:"), Qt::CaseInsensitive)) {
            return QStringLiteral("high");
        }
        if (m_info.severity >= 5 || m_info.score >= 50) {
            return QStringLiteral("medium");
        }
        return QStringLiteral("low");
    }
    QString familyName() const { return m_info.family; }
    bool isRepairable() const {
        return m_isRepairable;
    }

signals:
    void quarantineRequested(const ThreatInfo &info);
    void deleteRequested    (const ThreatInfo &info);
    void repairRequested    (const ThreatInfo &info);
    void openFolderRequested(const ThreatInfo &info);
    void ignoreRequested    (const ThreatInfo &info);
    void selectionChanged   (bool selected);

private:
    ThreatInfo   m_info;
    QCheckBox   *m_chkSelect  = nullptr;
    QLabel      *m_lblName     = nullptr;
    QLabel      *m_lblFamily   = nullptr;
    QLabel      *m_lblPath     = nullptr;
    QLabel      *m_lblReason   = nullptr;
    QLabel      *m_lblHash     = nullptr;
    QLabel      *m_lblSize     = nullptr;
    QLabel      *m_lblScore    = nullptr;
    QLabel      *m_lblSeverity = nullptr;
    QLabel      *m_lblActionTag = nullptr;
    QPushButton *m_btnQuar    = nullptr;
    QPushButton *m_btnDel     = nullptr;
    QPushButton *m_btnRepair  = nullptr;
    QPushButton *m_btnFolder  = nullptr;
    QPushButton *m_btnIgnore  = nullptr;
    bool         m_isRepairable = false;
};

} // namespace verax
