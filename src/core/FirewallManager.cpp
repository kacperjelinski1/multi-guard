#include "FirewallManager.h"
#include "Logger.h"
#include "LicenseManager.h"

#include <QProcess>
#include <QFileInfo>
#include <QRegularExpression>

#ifdef _WIN32
#include <windows.h>
#endif

namespace verax {

FirewallManager& FirewallManager::instance()
{
    static FirewallManager inst;
    return inst;
}

FirewallManager::FirewallManager(QObject *parent)
    : QObject(parent)
{
}

int FirewallManager::runNetsh(const QStringList &args)
{
#ifndef _WIN32
    Q_UNUSED(args);
    return 0;
#else
    QProcess p;
    p.setCreateProcessArgumentsModifier([](QProcess::CreateProcessArguments *a){
        a->flags |= 0x08000000; /* CREATE_NO_WINDOW */
    });
    p.start(QStringLiteral("netsh.exe"), args);
    if (!p.waitForStarted(4000)) return -1;
    if (!p.waitForFinished(10000)) { p.kill(); return -2; }
    return p.exitCode();
#endif
}

bool FirewallManager::isFirewallEnabled()
{
#ifndef _WIN32
    return true;
#else
    QProcess p;
    p.setCreateProcessArgumentsModifier([](QProcess::CreateProcessArguments *a){
        a->flags |= 0x08000000;
    });
    p.start(QStringLiteral("powershell.exe"), {
        QStringLiteral("-NoProfile"), QStringLiteral("-NonInteractive"), QStringLiteral("-Command"),
        QStringLiteral("(Get-NetFirewallProfile -Profile Domain,Public,Private | Where-Object { $_.Enabled -eq $true }).Count -gt 0")
    });
    if (p.waitForStarted(3000) && p.waitForFinished(6000)) {
        QString out = QString::fromLatin1(p.readAllStandardOutput()).trimmed();
        if (out.compare(QStringLiteral("True"), Qt::CaseInsensitive) == 0) return true;
        if (out.compare(QStringLiteral("False"), Qt::CaseInsensitive) == 0) return false;
    }
    // Netsh fallback
    QProcess p2;
    p2.setCreateProcessArgumentsModifier([](QProcess::CreateProcessArguments *a){
        a->flags |= 0x08000000;
    });
    p2.start(QStringLiteral("netsh.exe"), { QStringLiteral("advfirewall"), QStringLiteral("show"), QStringLiteral("currentprofile") });
    if (p2.waitForStarted(3000) && p2.waitForFinished(6000)) {
        const QString out = QString::fromLocal8Bit(p2.readAllStandardOutput());
        if (out.contains(QStringLiteral("WYŁ"), Qt::CaseInsensitive) || out.contains(QStringLiteral("OFF"), Qt::CaseInsensitive)) {
            return false;
        }
        if (out.contains(QStringLiteral("State                                 ON"), Qt::CaseInsensitive) ||
            out.contains(QStringLiteral("WŁ"), Qt::CaseInsensitive)) {
            return true;
        }
    }
    return true;
#endif
}

bool FirewallManager::setFirewallEnabled(bool enable)
{
#ifndef _WIN32
    Q_UNUSED(enable);
    emit statusChanged(enable, QStringLiteral("Aktywny"));
    return true;
#else
    const QString state = enable ? QStringLiteral("on") : QStringLiteral("off");
    const QString psBool = enable ? QStringLiteral("$true") : QStringLiteral("$false");

    // 1. Run authoritative PowerShell cmdlet
    QProcess p;
    p.setCreateProcessArgumentsModifier([](QProcess::CreateProcessArguments *a){
        a->flags |= 0x08000000;
    });
    p.start(QStringLiteral("powershell.exe"), {
        QStringLiteral("-NoProfile"), QStringLiteral("-NonInteractive"), QStringLiteral("-Command"),
        QStringLiteral("Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled %1 -ErrorAction SilentlyContinue").arg(psBool)
    });
    p.waitForFinished(6000);

    // 2. Also run netsh
    int rc = runNetsh({ QStringLiteral("advfirewall"), QStringLiteral("set"), QStringLiteral("allprofiles"), QStringLiteral("state"), state });
    Logger::info(QStringLiteral("FirewallManager: setFirewallEnabled(%1) -> netsh rc=%2").arg(enable).arg(rc));
    emit statusChanged(enable, activeProfile());
    return true;
#endif
}

QString FirewallManager::activeProfile()
{
#ifndef _WIN32
    return QStringLiteral("Prywatny (Aktywny)");
#else
    QProcess p;
    p.setCreateProcessArgumentsModifier([](QProcess::CreateProcessArguments *a){
        a->flags |= 0x08000000;
    });
    p.start(QStringLiteral("netsh.exe"), { QStringLiteral("advfirewall"), QStringLiteral("show"), QStringLiteral("currentprofile") });
    if (!p.waitForStarted(4000) || !p.waitForFinished(8000)) return QStringLiteral("Standardowy");
    const QString out = QString::fromLocal8Bit(p.readAllStandardOutput());
    if (out.contains(QStringLiteral("Private"), Qt::CaseInsensitive) || out.contains(QStringLiteral("Prywatny"), Qt::CaseInsensitive))
        return QStringLiteral("Sieć prywatna (Domowa)");
    if (out.contains(QStringLiteral("Public"), Qt::CaseInsensitive) || out.contains(QStringLiteral("Publiczny"), Qt::CaseInsensitive))
        return QStringLiteral("Sieć publiczna (Wi-Fi)");
    if (out.contains(QStringLiteral("Domain"), Qt::CaseInsensitive) || out.contains(QStringLiteral("Domenowy"), Qt::CaseInsensitive))
        return QStringLiteral("Sieć domenowa (Firma)");
    return QStringLiteral("Wszystkie profile aktywne");
#endif
}

bool FirewallManager::blockInboundTraffic(bool blockAll)
{
#ifndef _WIN32
    Q_UNUSED(blockAll);
    return true;
#else
    const QString val = blockAll ? QStringLiteral("blockinboundalways,allowoutbound")
                                 : QStringLiteral("blockinbound,allowoutbound");
    int rc = runNetsh({ QStringLiteral("advfirewall"), QStringLiteral("set"), QStringLiteral("allprofiles"), QStringLiteral("firewallpolicy"), val });
    return (rc == 0);
#endif
}

bool FirewallManager::blockPort(int port, const QString &protocol)
{
    const QString rName = QStringLiteral("Multi-Guard Block Port %1 (%2)").arg(port).arg(protocol);
    deleteRule(rName);
    int rc = runNetsh({
        QStringLiteral("advfirewall"), QStringLiteral("firewall"), QStringLiteral("add"), QStringLiteral("rule"),
        QStringLiteral("name=%1").arg(rName),
        QStringLiteral("dir=in"),
        QStringLiteral("action=block"),
        QStringLiteral("protocol=%1").arg(protocol),
        QStringLiteral("localport=%1").arg(port),
        QStringLiteral("enable=yes")
    });
    bool ok = (rc == 0);
    emit ruleAdded(rName, ok);
    return ok;
}

bool FirewallManager::blockApplication(const QString &exePath, const QString &ruleName)
{
    const QString appName = !ruleName.isEmpty() ? ruleName : QFileInfo(exePath).baseName();
    const QString rName = QStringLiteral("Multi-Guard Block App %1").arg(appName);
    deleteRule(rName);
    int rc = runNetsh({
        QStringLiteral("advfirewall"), QStringLiteral("firewall"), QStringLiteral("add"), QStringLiteral("rule"),
        QStringLiteral("name=%1").arg(rName),
        QStringLiteral("dir=out"),
        QStringLiteral("action=block"),
        QStringLiteral("program=%1").arg(exePath),
        QStringLiteral("enable=yes")
    });
    bool ok = (rc == 0);
    emit ruleAdded(rName, ok);
    return ok;
}

bool FirewallManager::deleteRule(const QString &ruleName)
{
    int rc = runNetsh({
        QStringLiteral("advfirewall"), QStringLiteral("firewall"), QStringLiteral("delete"), QStringLiteral("rule"),
        QStringLiteral("name=%1").arg(ruleName)
    });
    return (rc == 0);
}

QVector<FirewallRuleItem> FirewallManager::loadActiveRules()
{
    QVector<FirewallRuleItem> list;
#ifndef _WIN32
    list.append({ QStringLiteral("Multi-Guard Core Protection"), QStringLiteral("IN/OUT"), QStringLiteral("ALLOW"), QStringLiteral("Multi-Guard.exe"), QStringLiteral("Wszystkie"), true });
    list.append({ QStringLiteral("Blokada portu SMB (Zalecana)"), QStringLiteral("IN"), QStringLiteral("BLOCK"), QStringLiteral("System"), QStringLiteral("445"), true });
    list.append({ QStringLiteral("Blokada portu RPC (Zalecana)"), QStringLiteral("IN"), QStringLiteral("BLOCK"), QStringLiteral("System"), QStringLiteral("135"), true });
    return list;
#else
    QProcess p;
    p.setCreateProcessArgumentsModifier([](QProcess::CreateProcessArguments *a){
        a->flags |= 0x08000000;
    });
    p.start(QStringLiteral("netsh.exe"), { QStringLiteral("advfirewall"), QStringLiteral("firewall"), QStringLiteral("show"), QStringLiteral("rule"), QStringLiteral("name=all") });
    if (!p.waitForStarted(4000) || !p.waitForFinished(15000)) return list;

    const QString out = QString::fromLocal8Bit(p.readAllStandardOutput());
    const QStringList blocks = out.split(QStringLiteral("\n\r\n"));
    for (const QString &b : blocks) {
        if (!b.contains(QStringLiteral("Rule Name:"), Qt::CaseInsensitive) &&
            !b.contains(QStringLiteral("Nazwa reguły:"), Qt::CaseInsensitive)) continue;

        FirewallRuleItem item;
        const QStringList lines = b.split(QLatin1Char('\n'));
        for (const QString &line : lines) {
            const QString t = line.trimmed();
            if (t.startsWith(QStringLiteral("Rule Name:"), Qt::CaseInsensitive) || t.startsWith(QStringLiteral("Nazwa reguły:"), Qt::CaseInsensitive))
                item.name = t.section(QLatin1Char(':'), 1).trimmed();
            else if (t.startsWith(QStringLiteral("Direction:"), Qt::CaseInsensitive) || t.startsWith(QStringLiteral("Kierunek:"), Qt::CaseInsensitive))
                item.direction = t.section(QLatin1Char(':'), 1).trimmed();
            else if (t.startsWith(QStringLiteral("Action:"), Qt::CaseInsensitive) || t.startsWith(QStringLiteral("Działanie:"), Qt::CaseInsensitive))
                item.action = t.section(QLatin1Char(':'), 1).trimmed();
            else if (t.startsWith(QStringLiteral("Program:"), Qt::CaseInsensitive))
                item.program = t.section(QLatin1Char(':'), 1).trimmed();
            else if (t.startsWith(QStringLiteral("LocalPort:"), Qt::CaseInsensitive) || t.startsWith(QStringLiteral("Port lokalny:"), Qt::CaseInsensitive))
                item.port = t.section(QLatin1Char(':'), 1).trimmed();
        }
        if (!item.name.isEmpty()) {
            list.append(item);
            if (list.size() >= 50) break; // Limit to 50 rules for UI performance
        }
    }
    return list;
#endif
}

QVector<RealConnectionItem> FirewallManager::loadActiveConnections()
{
    QVector<RealConnectionItem> items;
#ifdef _WIN32
    QProcess p;
    p.setCreateProcessArgumentsModifier([](QProcess::CreateProcessArguments *a){
        a->flags |= 0x08000000;
    });
    p.start(QStringLiteral("powershell.exe"), {
        QStringLiteral("-NoProfile"), QStringLiteral("-NonInteractive"), QStringLiteral("-Command"),
        QStringLiteral("Get-NetTCPConnection -State Established,Listen -ErrorAction SilentlyContinue | "
                       "Select-Object -First 30 OwningProcess, LocalAddress, LocalPort, RemoteAddress, RemotePort, State | "
                       "ForEach-Object { "
                       "  $pName = (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName; "
                       "  if (-not $pName) { $pName = 'System' }; "
                       "  \"$($pName).exe|$($_.LocalAddress):$($_.LocalPort)|$($_.RemoteAddress):$($_.RemotePort)|$($_.State)|$($_.OwningProcess)\" "
                       "}")
    });
    if (p.waitForStarted(4000) && p.waitForFinished(10000)) {
        QString out = QString::fromUtf8(p.readAllStandardOutput());
        const QStringList lines = out.split(QLatin1Char('\n'), Qt::SkipEmptyParts);
        for (const QString &line : lines) {
            const QString trimmed = line.trimmed();
            if (trimmed.isEmpty()) continue;
            const QStringList parts = trimmed.split(QLatin1Char('|'));
            if (parts.size() >= 5) {
                RealConnectionItem ci;
                ci.processName = parts[0].trimmed();
                ci.localAddress = parts[1].trimmed();
                ci.remoteAddress = parts[2].trimmed();
                ci.state = parts[3].trimmed();
                ci.pid = parts[4].trimmed().toInt();
                items.append(ci);
            }
        }
    }
#endif
    return items;
}

bool FirewallManager::resetToDefaults()
{
    int rc = runNetsh({ QStringLiteral("advfirewall"), QStringLiteral("reset") });
    emit statusChanged(isFirewallEnabled(), activeProfile());
    return (rc == 0);
}

} // namespace verax
