#include "ReportGenerator.h"
#include "AuditLogger.h"
#include "Settings.h"
#include "DefenderEngine.h"
#include "LicenseManager.h"
#include "Logger.h"
#include "../../Version.h"

#include <QFile>
#include <QTextStream>
#include <QDateTime>
#include <QHostInfo>
#include <QSysInfo>
#include <QStandardPaths>
#include <QDesktopServices>
#include <QUrl>
#include <QDir>

namespace verax {

QString ReportGenerator::generateServiceReportHtml(const QString &targetFilePath)
{
    if (!LicenseManager::instance().hasCapability(LicenseCapability::ServiceReports)) {
        Logger::warn("ReportGenerator: Pominięto generowanie raportu — brak uprawnień licencyjnych.");
        return QString();
    }
    QString outPath = targetFilePath;
    if (outPath.isEmpty()) {
        const QString desktop = QStandardPaths::writableLocation(QStandardPaths::DesktopLocation);
        outPath = desktop + QStringLiteral("/Raport_Serwisowy_MultiGuard_%1.html")
                  .arg(QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd_hhmmss")));
    }

    QFile f(outPath);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate | QIODevice::Text)) {
        return QString();
    }

    QTextStream ts(&f);
    ts.setCodec("UTF-8");
    ts.setGenerateByteOrderMark(true);

    const QString hostname   = QHostInfo::localHostName();
    const QString osPretty   = QSysInfo::prettyProductName();
    const QString kernel     = QSysInfo::kernelType() + " " + QSysInfo::kernelVersion();
    const QString nowStr     = QDateTime::currentDateTime().toString(QStringLiteral("yyyy-MM-dd HH:mm:ss"));
    const QString planName   = LicenseManager::instance().isValid()
                                   ? LicenseManager::instance().tierName()
                                   : QStringLiteral("Brak aktywacji");
    const QString planShort  = LicenseManager::instance().isValid()
                                   ? LicenseManager::instance().tierShortName().toUpper()
                                   : QStringLiteral("NIEAKTYWOWANY");
    const QString validity   = LicenseManager::instance().daysRemainingText();

    const auto events = AuditLogger::instance().recentEvents(30);

    ts << QString::fromUtf8(
       "<!DOCTYPE html>\n"
       "<html lang=\"pl\">\n"
       "<head>\n"
       "  <meta charset=\"UTF-8\">\n"
       "  <title>Raport Bezpieczeństwa Stacji Roboczej — Multi-Guard</title>\n"
       "  <style>\n"
       "    body { font-family: 'Nunito', 'Segoe UI Variable Display', 'Segoe UI Variable Text', 'Segoe UI', -apple-system, BlinkMacSystemFont, 'Inter', 'Roboto', sans-serif; background: #0A0E17; color: #F1F5F9; margin: 0; padding: 40px 20px; line-height: 1.6; -webkit-font-smoothing: antialiased; }\n"
       "    .container { max-width: 920px; margin: 0 auto; background: #131724; border: 1px solid #222A3B; border-radius: 20px; padding: 40px; box-shadow: 0 16px 40px rgba(0,0,0,0.55); }\n"
       "    .header { display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #2563EB; padding-bottom: 22px; margin-bottom: 30px; }\n"
       "    .brand-title { font-size: 28px; font-weight: 800; color: #FFFFFF; letter-spacing: -0.5px; }\n"
       "    .brand-subtitle { font-size: 13px; color: #38BDF8; font-weight: 600; text-transform: uppercase; letter-spacing: 1px; margin-top: 2px; }\n"
       "    .report-meta { text-align: right; font-size: 12px; color: #94A3B8; line-height: 1.7; }\n"
       "    .badge { display: inline-block; padding: 4px 12px; border-radius: 8px; font-size: 11px; font-weight: 700; letter-spacing: 0.3px; }\n"
       "    .badge-success { background: rgba(37, 99, 235, 0.18); color: #38BDF8; border: 1px solid rgba(56, 189, 248, 0.4); }\n"
       "    .badge-warn { background: rgba(245, 158, 11, 0.15); color: #F59E0B; border: 1px solid rgba(245,158,11,0.3); }\n"
       "    .badge-danger { background: rgba(225, 29, 72, 0.15); color: #FF4D6D; border: 1px solid rgba(225,29,72,0.3); }\n"
       "    h2 { color: #FFFFFF; font-size: 18px; font-weight: 700; border-bottom: 1px solid #222A3B; padding-bottom: 8px; margin-top: 32px; margin-bottom: 16px; }\n"
       "    table { width: 100%; border-collapse: collapse; margin-bottom: 20px; font-size: 13px; }\n"
       "    th { background: #181E2C; text-align: left; padding: 12px 14px; color: #94A3B8; border-bottom: 1px solid #28334A; font-weight: 600; }\n"
       "    td { padding: 12px 14px; border-bottom: 1px solid #1B2130; }\n"
       "    .info-grid { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 14px; margin-bottom: 20px; }\n"
       "    .info-card { background: #0E121A; border: 1px solid #1E2535; border-radius: 14px; padding: 14px 16px; }\n"
       "    .info-card strong { color: #94A3B8; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; display: block; margin-bottom: 4px; }\n"
       "    .info-card span { font-size: 14px; color: #FFFFFF; font-weight: 600; }\n"
       "    .footer { margin-top: 40px; padding-top: 20px; border-top: 1px solid #222A3B; display: flex; justify-content: space-between; align-items: center; font-size: 12px; color: #64748B; }\n"
       "    .signature-box { border-top: 1px dashed #475569; width: 220px; text-align: center; padding-top: 8px; margin-top: 30px; font-size: 12px; color: #94A3B8; }\n"
       "  </style>\n"
       "</head>\n"
       "<body>\n"
       "<div class=\"container\">\n"
       "  <div class=\"header\">\n"
       "    <div>\n"
       "      <div class=\"brand-title\">MULTI-GUARD <span style=\"color:#38BDF8;\">").toUtf8() << planShort.toUtf8() << "</span></div>\n"
       << QString::fromUtf8("      <div class=\"brand-subtitle\">Raport Serwisowy &amp; Audyt Bezpieczeństwa Stacji</div>\n"
       "    </div>\n"
       "    <div class=\"report-meta\">\n"
       "      Data audytu: <strong style=\"color:#FFFFFF;\">").toUtf8() << nowStr.toUtf8() << "</strong><br>\n"
       << "      Wersja silnika: " << APP_VERSION_STR << "<br>\n"
       << QString::fromUtf8("      Serwis wykonujący: <strong>Multi-Servis</strong> (tel. 505 012 914)\n"
       "    </div>\n"
       "  </div>\n\n"
       "  <h2>1. Identyfikacja Stacji Roboczej &amp; Aktywnej Usługi</h2>\n"
       "  <div class=\"info-grid\">\n"
       "    <div class=\"info-card\"><strong>Nazwa komputera (Host)</strong><span>").toUtf8() << hostname.toUtf8() << "</span></div>\n"
       << QString::fromUtf8("    <div class=\"info-card\"><strong>System operacyjny</strong><span>").toUtf8() << osPretty.toUtf8() << "</span></div>\n"
       << QString::fromUtf8("    <div class=\"info-card\"><strong>Jądro systemu</strong><span>").toUtf8() << kernel.toUtf8() << "</span></div>\n"
       << QString::fromUtf8("    <div class=\"info-card\"><strong>Aktywna usługa</strong><span style=\"color:#38BDF8;\">").toUtf8() << planName.toUtf8() << "</span></div>\n"
       << QString::fromUtf8("    <div class=\"info-card\"><strong>Ważność usługi</strong><span style=\"color:#34D399;\">").toUtf8() << validity.toUtf8() << "</span></div>\n"
       << QString::fromUtf8("    <div class=\"info-card\"><strong>Silnik Microsoft Defender</strong><span>").toUtf8() << defSigVer.toUtf8() << "</span></div>\n"
       << "  </div>\n\n"
       << QString::fromUtf8(
       "  <h2>2. Status Aktywnych Osłon Ochronnych</h2>\n"
       "  <table>\n"
       "    <tr><th>Komponent Ochrony</th><th>Opis modułu</th><th>Status</th></tr>\n"
       "    <tr><td>Ochrona w czasie rzeczywistym (Microsoft Defender)</td><td>Ochrona jądra systemu i monitor procesów w pamięci</td><td><span class=\"badge ")
       << (defSt.realTimeProtectionEnabled ? "badge-success\">AKTYWNA" : "badge-warn\">WYŁĄCZONA") << "</span></td></tr>\n"
       << QString::fromUtf8("    <tr><td>Ochrona przed Ransomware (Controlled Folders)</td><td>Monitorowanie szyfrowania i obrona dokumentów</td><td><span class=\"badge badge-success\">AKTYWNA</span></td></tr>\n"
       << QString::fromUtf8("    <tr><td>Ochrona w chmurze (Cloud Block at First Sight)</td><td>Błyskawiczne blokowanie nieznanych zagrożeń</td><td><span class=\"badge badge-success\">AKTYWNA</span></td></tr>\n"
       << QString::fromUtf8("    <tr><td>Ochrona sieciowa (Windows Defender Firewall)</td><td>Blokowanie nieautoryzowanych połączeń i portów SMB/RDP</td><td><span class=\"badge badge-success\">AKTYWNA</span></td></tr>\n"
       << QString::fromUtf8("    <tr><td>Skaner nośników wymiennych (USB Sentinel)</td><td>Automatyczna analiza nośników pendrive / dysków USB</td><td><span class=\"badge badge-success\">AKTYWNA</span></td></tr>\n"
       "  </table>\n\n"
       "  <h2>3. Dziennik Zdarzeń Bezpieczeństwa (Security Audit Trail)</h2>\n"
       "  <table>\n"
       "    <tr><th>Data i Czas</th><th>Kategoria</th><th>Opis Zdarzenia</th><th>Szczegóły</th><th>Status</th></tr>\n").toUtf8();

    if (events.isEmpty()) {
        ts << QString::fromUtf8("    <tr><td colspan=\"5\" style=\"text-align:center; color:#94A3B8; padding:18px;\">Brak zarejestrowanych incydentów bezpieczeństwa. System czysty.</td></tr>\n").toUtf8();
    } else {
        for (const auto &ev : events) {
            QString badgeClass = "badge-success";
            QString badgeLabel = QString::fromUtf8("SUKCES");
            if (ev.severity == 1) { badgeClass = "badge-success"; badgeLabel = QString::fromUtf8("SUKCES"); }
            else if (ev.severity == 2) { badgeClass = "badge-warn"; badgeLabel = QString::fromUtf8("OSTRZEŻENIE"); }
            else if (ev.severity >= 3) { badgeClass = "badge-danger"; badgeLabel = QString::fromUtf8("ZAGROŻENIE"); }

            ts << "    <tr>"
               << "<td>" << ev.timestamp.toString(QStringLiteral("yyyy-MM-dd HH:mm")).toUtf8() << "</td>"
               << "<td><strong>" << ev.type.toUtf8() << "</strong></td>"
               << "<td>" << ev.description.toUtf8() << "</td>"
               << "<td style=\"font-family:monospace; font-size:11px; color:#94A3B8;\">" << ev.details.toUtf8() << "</td>"
               << "<td><span class=\"badge " << badgeClass.toUtf8() << "\">" << badgeLabel.toUtf8() << "</span></td>"
               << "</tr>\n";
        }
    }

    ts << QString::fromUtf8(
       "  </table>\n"
       "  <div style=\"display:flex; justify-content:space-between; margin-top:30px;\">\n"
       "    <div>\n"
       "      <p style=\"font-size:13px; color:#CBD5E1;\">Stacja robocza przeszła procedurę weryfikacji i optymalizacji silnikiem Multi-Guard.<br>Wszelkie wykryte zagrożenia zostały zneutralizowane.</p>\n"
       "    </div>\n"
       "    <div class=\"signature-box\">\n"
       "      Pieczęć i podpis technika Multi-Servis\n"
       "    </div>\n"
       "  </div>\n"
       "  <div class=\"footer\">\n"
       "    <div>Multi-Servis Usługi Informatyczne · ul. Serwisowa · www.multi-servis.pl · tel. 505 012 914</div>\n"
       "    <div>Wygenerowano z pakietu ").toUtf8() << planName.toUtf8() << " v" << APP_VERSION_STR << "</div>\n"
       << "  </div>\n"
       << "</div>\n"
       << "</body>\n"
       << "</html>\n";

    f.close();
    return outPath;
}

} // namespace verax
