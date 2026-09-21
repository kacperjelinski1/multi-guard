// ScanOptionsDialog.cpp
// By Ali Sakkaf - https://alisakkaf.com
#include "ScanOptionsDialog.h"

#include <QListWidget>
#include <QCheckBox>
#include <QComboBox>
#include <QSpinBox>
#include "../core/Settings.h"
#include <QLabel>
#include <QPushButton>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QGridLayout>
#include <QGroupBox>
#include <QFileDialog>
#include <QDialogButtonBox>
#include <QStandardPaths>

namespace verax {

ScanOptionsDialog::ScanOptionsDialog(Mode mode,
                                     const ScanRequest &initial,
                                     QWidget *parent)
    : QDialog(parent), m_mode(mode), m_initial(initial), m_result(initial)
{
    setObjectName("ScanOptionsDialog");
    setProperty("class", "ScanOptionsDialog");
    setModal(true);
    setWindowIcon(QIcon(QStringLiteral(":/assets/logo.png")));
    // Sized by content + reasonable minimum so the dialog never feels cramped.
    setMinimumSize(560, 520);
    buildUi();
    seedFromInitial();
    retranslate();
}

void ScanOptionsDialog::buildUi()
{
    auto *root = new QVBoxLayout(this);
    const int pad = fontMetrics().averageCharWidth();
    root->setContentsMargins(pad * 3, pad * 2, pad * 3, pad * 2);
    root->setSpacing(pad * 2);

    // ── Header ──
    m_title = new QLabel(this);
    m_title->setObjectName("ScanOptionsTitle");
    QFont tf = m_title->font();
    tf.setPointSizeF(tf.pointSizeF() * 1.45);
    if (verax::Settings::instance().language() != "ar") {
        tf.setBold(true);
        m_title->setStyleSheet("font-weight: normal;");
        m_title->setStyleSheet("font-weight: normal;");
    }
    m_title->setFont(tf);

    m_subtitle = new QLabel(this);
    m_subtitle->setObjectName("ScanOptionsSubtitle");
    m_subtitle->setWordWrap(true);

    root->addWidget(m_title);
    root->addWidget(m_subtitle);

    // ── Scope group: list of paths the scan will visit ──
    auto *scopeBox = new QGroupBox(this);
    scopeBox->setObjectName("ScanScopeBox");
    auto *scopeLay = new QVBoxLayout(scopeBox);
    scopeLay->setSpacing(pad);
    m_pathsList = new QListWidget(scopeBox);
    m_pathsList->setObjectName("ScanScopeList");
    m_pathsList->setSelectionMode(QAbstractItemView::ExtendedSelection);
    m_pathsList->setMinimumHeight(140);

    auto *scopeBtns = new QHBoxLayout();
    scopeBtns->setSpacing(pad);
    auto *btnAddFolder = new QPushButton(scopeBox);
    btnAddFolder->setObjectName("ScanScopeAddFolder");
    btnAddFolder->setProperty("kind", "ghost");
    btnAddFolder->setText(tr("Add folder..."));
    auto *btnAddFile = new QPushButton(scopeBox);
    btnAddFile->setObjectName("ScanScopeAddFile");
    btnAddFile->setProperty("kind", "ghost");
    btnAddFile->setText(tr("Add file..."));
    auto *btnRemove = new QPushButton(scopeBox);
    btnRemove->setObjectName("ScanScopeRemove");
    btnRemove->setProperty("kind", "danger");
    btnRemove->setText(tr("Remove selected"));
    scopeBtns->addWidget(btnAddFolder);
    scopeBtns->addWidget(btnAddFile);
    scopeBtns->addStretch(1);
    scopeBtns->addWidget(btnRemove);

    scopeLay->addWidget(m_pathsList);
    scopeLay->addLayout(scopeBtns);
    root->addWidget(scopeBox);
    scopeBox->setTitle(tr("Scan scope"));

    connect(btnAddFolder, &QPushButton::clicked, this, &ScanOptionsDialog::onAddPath);
    connect(btnAddFile,   &QPushButton::clicked, this, &ScanOptionsDialog::onAddFile);
    connect(btnRemove,    &QPushButton::clicked, this, &ScanOptionsDialog::onRemoveSelected);

    // ── Engines + filetype groups, side by side ──
    auto *midRow = new QHBoxLayout();
    midRow->setSpacing(pad * 2);

    auto *engBox = new QGroupBox(this);
    engBox->setObjectName("ScanEnginesBox");
    auto *engLay = new QVBoxLayout(engBox);
    engLay->setSpacing(pad);
    m_engSig   = new QCheckBox(tr("Local signature database (SHA-256)"), engBox);
    m_engPe    = new QCheckBox(tr("PE structural inspection (executables)"), engBox);
    m_engHeur  = new QCheckBox(tr("Heuristics (scripts, documents, archives, paths)"), engBox);
    m_engCloud = new QCheckBox(tr("Cloud lookup (MalwareBazaar, requires internet)"), engBox);
    engLay->addWidget(m_engSig);
    engLay->addWidget(m_engPe);
    engLay->addWidget(m_engHeur);
    engLay->addWidget(m_engCloud);
    engLay->addStretch(1);
    engBox->setTitle(tr("Detection engines"));

    auto *extBox = new QGroupBox(this);
    extBox->setObjectName("ScanFileTypesBox");
    auto *extLay = new QVBoxLayout(extBox);
    extLay->setSpacing(pad);
    m_extPe       = new QCheckBox(tr("Executables (.exe .dll .sys .scr ...)"), extBox);
    m_extScripts  = new QCheckBox(tr("Scripts (.bat .cmd .ps1 .vbs .js .hta)"), extBox);
    m_extDocs     = new QCheckBox(tr("Documents (.docm .xlsm .pptm .docx ...)"), extBox);
    m_extArchives = new QCheckBox(tr("Archives (.zip .jar .iso .msix ...)"), extBox);
    m_extAll      = new QCheckBox(tr("Every file (no extension filter)"), extBox);
    extLay->addWidget(m_extPe);
    extLay->addWidget(m_extScripts);
    extLay->addWidget(m_extDocs);
    extLay->addWidget(m_extArchives);
    extLay->addWidget(m_extAll);
    extLay->addStretch(1);
    extBox->setTitle(tr("File types"));

    midRow->addWidget(engBox, 1);
    midRow->addWidget(extBox, 1);
    root->addLayout(midRow);

    // ── Action + threshold ──
    auto *actBox = new QGroupBox(this);
    actBox->setObjectName("ScanActionBox");
    auto *actLay = new QGridLayout(actBox);
    actLay->setHorizontalSpacing(pad * 2);
    actLay->setVerticalSpacing(pad);

    auto *lblAction = new QLabel(tr("On detection:"), actBox);
    m_action = new QComboBox(actBox);
    m_action->addItem(tr("Quarantine (encrypted vault)"), QStringLiteral("quarantine"));
    m_action->addItem(tr("Delete permanently"),           QStringLiteral("delete"));
    m_action->addItem(tr("Report only"),                  QStringLiteral("report"));
    m_action->addItem(tr("Repair (PE infectors)"),        QStringLiteral("repair"));

    auto *lblThreshold = new QLabel(tr("Heuristic threshold:"), actBox);
    m_threshold = new QSpinBox(actBox);
    m_threshold->setRange(20, 100);
    m_threshold->setSuffix(QStringLiteral(" / 100"));
    m_threshold->setToolTip(tr("Score required to flag a file as suspicious. "
                               "Lower = more sensitive."));

    actLay->addWidget(lblAction,    0, 0);
    actLay->addWidget(m_action,     0, 1);
    actLay->addWidget(lblThreshold, 1, 0);
    actLay->addWidget(m_threshold,  1, 1);
    actLay->setColumnStretch(1, 1);
    actBox->setTitle(tr("Action"));
    root->addWidget(actBox);

    // ── Footer buttons ──
    auto *box = new QDialogButtonBox(this);
    box->setObjectName("ScanOptionsButtons");
    auto *btnStart  = box->addButton(tr("Start scan"), QDialogButtonBox::AcceptRole);
    auto *btnCancel = box->addButton(QDialogButtonBox::Cancel);
    btnStart->setProperty("kind", "primary");
    btnCancel->setProperty("kind", "ghost");
    root->addWidget(box);
    connect(btnStart,  &QPushButton::clicked, this, &ScanOptionsDialog::onAccept);
    connect(btnCancel, &QPushButton::clicked, this, &QDialog::reject);
}

void ScanOptionsDialog::seedFromInitial()
{
    m_pathsList->clear();
    for (const QString &t : m_initial.targets) m_pathsList->addItem(t);

    m_engSig->setChecked(m_initial.useSigDb);
    m_engPe->setChecked(m_initial.usePe);
    m_engHeur->setChecked(m_initial.useHeur);
    m_engCloud->setChecked(m_initial.useCloud);

    auto hasAny = [&](std::initializer_list<const char *> exts) {
        for (auto *e : exts)
            if (m_initial.extensionFilter.contains(QString::fromLatin1(e))) return true;
        return false;
    };
    const bool noFilter = m_initial.extensionFilter.isEmpty();
    m_extAll->setChecked(noFilter);
    m_extPe      ->setChecked(noFilter || hasAny({"exe","dll","sys","scr"}));
    m_extScripts ->setChecked(noFilter || hasAny({"bat","cmd","ps1","vbs","js","hta"}));
    m_extDocs    ->setChecked(noFilter || hasAny({"docm","xlsm","pptm","docx","xlsx","pptx"}));
    m_extArchives->setChecked(noFilter || hasAny({"zip","jar","apk","iso","msix","appx"}));

    int idx = m_action->findData(m_initial.action);
    m_action->setCurrentIndex(idx >= 0 ? idx : 0);
    m_threshold->setValue(m_initial.threshold > 0 ? m_initial.threshold : 60);
}

void ScanOptionsDialog::retranslate()
{
    switch (m_mode) {
    case Quick:
        setWindowTitle(tr("Quick Scan — Verax"));
        m_title   ->setText(tr("Quick Scan"));
        m_subtitle->setText(QStringLiteral("<html>") + tr("Sweeps the standard malware drop and persistence "
                               "locations: Temp, Downloads, AppData, ProgramData "
                               "and the Startup folders. Adjust the scope or "
                               "engines below before starting."));
        break;
    case Full:
        setWindowTitle(tr("Full Scan — Verax"));
        m_title   ->setText(tr("Full System Scan"));
        m_subtitle->setText(QStringLiteral("<html>") + tr("Visits every fixed drive on this machine. "
                               "This can take a long time — keep the engines "
                               "you actually need enabled."));
        break;
    case Custom:
        setWindowTitle(tr("Custom Scan — Verax"));
        m_title   ->setText(tr("Custom Scan"));
        m_subtitle->setText(QStringLiteral("<html>") + tr("Pick exactly what to scan, which engines to "
                               "use, and what to do when something is found."));
        break;
    }
}

void ScanOptionsDialog::onAddPath()
{
    const QString d = QFileDialog::getExistingDirectory(this, tr("Add folder"));
    if (d.isEmpty()) return;
    if (m_pathsList->findItems(d, Qt::MatchExactly).isEmpty())
        m_pathsList->addItem(d);
}

void ScanOptionsDialog::onAddFile()
{
    const QString f = QFileDialog::getOpenFileName(this, tr("Add file"));
    if (f.isEmpty()) return;
    if (m_pathsList->findItems(f, Qt::MatchExactly).isEmpty())
        m_pathsList->addItem(f);
}

void ScanOptionsDialog::onRemoveSelected()
{
    const auto items = m_pathsList->selectedItems();
    for (auto *it : items) delete it;
}

void ScanOptionsDialog::onAccept()
{
    m_result.targets.clear();
    for (int i = 0; i < m_pathsList->count(); ++i)
        m_result.targets << m_pathsList->item(i)->text();

    m_result.useSigDb = m_engSig  ->isChecked();
    m_result.usePe    = m_engPe   ->isChecked();
    m_result.useHeur  = m_engHeur ->isChecked();
    m_result.useCloud = m_engCloud->isChecked();

    QStringList exts;
    if (!m_extAll->isChecked()) {
        if (m_extPe->isChecked())
            exts << "exe" << "dll" << "sys" << "scr" << "ocx" << "cpl" << "drv";
        if (m_extScripts->isChecked())
            exts << "bat" << "cmd" << "ps1" << "psm1" << "vbs" << "vbe"
                 << "js"  << "jse" << "wsf" << "hta";
        if (m_extDocs->isChecked())
            exts << "docm" << "xlsm" << "pptm" << "dotm" << "xltm" << "potm"
                 << "docx" << "xlsx" << "pptx";
        if (m_extArchives->isChecked())
            exts << "zip" << "jar" << "apk" << "iso" << "msix" << "appx";
    }
    m_result.extensionFilter = exts;
    m_result.action    = m_action->currentData().toString();
    m_result.threshold = m_threshold->value();

    accept();
}

} // namespace verax
