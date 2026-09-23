// ShieldEngine.cpp - state machine
// By Ali Sakkaf - https://alisakkaf.com
#include "ShieldEngine.h"
#include "SignatureDb.h"
#include "Settings.h"
#include "Logger.h"
#include "LicenseManager.h"

namespace verax {

ShieldEngine& ShieldEngine::instance() {
    static ShieldEngine e;
    return e;
}

ShieldEngine::ShieldEngine(QObject *parent) : QObject(parent)
{
    m_scanner = new Scanner(this);
    connect(m_scanner, &Scanner::started,  this,
            [this]{ setState(Scanning); });
    connect(m_scanner, &Scanner::finished, this,
            [this](const ScanReport &){ setState(Idle); });
    connect(m_scanner, &Scanner::error,    this,
            [this](const QString &){ setState(Idle); });
}

void ShieldEngine::setState(State s) {
    if (m_state == s) return;
    m_state = s;
    emit stateChanged(s);
}

void ShieldEngine::startScan(const ScanRequest &req) {
    if (!LicenseManager::instance().hasCapability(LicenseCapability::BasicScanning)) {
        Logger::warn("ShieldEngine: Pominięto skanowanie — brak uprawnień licencyjnych.");
        return;
    }
    if (m_scanner->isRunning()) return;
    if (m_scanner->request(req)) setState(Scanning);
}

void ShieldEngine::stopScan() { m_scanner->requestStop(); }

void ShieldEngine::pauseScan(bool p)    { m_scanner->requestPause(p); }

void ShieldEngine::updateSignatures()
{
    if (!LicenseManager::instance().hasCapability(LicenseCapability::SignaturesAndUpdates)) {
        Logger::warn("ShieldEngine: Pominięto aktualizację — brak uprawnień licencyjnych.");
        return;
    }
    setState(Updating);
    SignatureDb::instance().updateOnline(Settings::instance().updateUrl());
    connect(&SignatureDb::instance(), &SignatureDb::updateFinished,
            this, [this](int, int, const QString &){ setState(Idle); },
            Qt::UniqueConnection);
}

} // namespace verax
