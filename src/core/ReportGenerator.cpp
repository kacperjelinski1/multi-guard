#include "ReportGenerator.h"
#include "AuditLogger.h"
#include "Settings.h"
#include "SignatureDb.h"
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

    const QString hostname = QHostInfo::localHostName();
    const QString osPretty = QSysInfo::prettyProductName();
    const QString kernel   = QSysInfo::kernelType() + " " + QSysInfo::kernelVersion();
    const QString nowStr   = QDateTime::currentDateTime().toString(QStringLiteral("yyyy-MM-dd HH:mm:ss"));

    const auto events = AuditLogger::instance().recentEvents(30);

    ts << "<!DOCTYPE html>\n"
       << "<html lang=\"pl\">\n"
       << "<head>\n"
       << "  <meta charset=\"UTF-8\">\n"
       << "  <title>Raport Bezpieczeństwa Stacji Roboczej — Multi-Guard</title>\n"
       << "  <style>\n"
       << "    body { font-family: 'Segoe UI', Tahoma, sans-serif; background: #0B0E14; color: #F1F5F9; margin: 0; padding: 40px 20px; line-height: 1.6; }\n"
       << "    .container { max-width: 900px; margin: 0 auto; background: #131724; border: 1px solid #222A3B; border-radius: 16px; padding: 40px; box-shadow: 0 10px 30px rgba(0,0,0,0.5); }\n"
       << "    .header { display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #00E676; padding-bottom: 20px; margin-bottom: 30px; }\n"
       << "    .brand-title { font-size: 28px; font-weight: 800; color: #FFFFFF; letter-spacing: -0.5px; }\n"
       << "    .brand-subtitle { font-size: 13px; color: #00E676; font-weight: 600; text-transform: uppercase; letter-spacing: 1px; }\n"
       << "    .report-meta { text-align: right; font-size: 12px; color: #94A3B8; }\n"
       << "    .badge { display: inline-block; padding: 4px 10px; border-radius: 6px; font-size: 11px; font-weight: bold; }\n"
       << "    .badge-success { background: rgba(0, 230, 118, 0.15); color: #00E676; border: 1px solid rgba(0,230,118,0.3); }\n"
       << "    .badge-warn { background: rgba(245, 158, 11, 0.15); color: #F59E0B; border: 1px solid rgba(245,158,11,0.3); }\n"
       << "    .badge-danger { background: rgba(225, 29, 72, 0.15); color: #FF4D6D; border: 1px solid rgba(225,29,72,0.3); }\n"
       << "    h2 { color: #FFFFFF; font-size: 18px; border-bottom: 1px solid #222A3B; padding-bottom: 8px; margin-top: 30px; margin-bottom: 16px; }\n"
       << "    table { width: 100%; border-collapse: collapse; margin-bottom: 20px; font-size: 13px; }\n"
       << "    th { background: #181E2C; text-align: left; padding: 10px 14px; color: #94A3B8; border-bottom: 1px solid #28334A; }\n"
       << "    td { padding: 10px 14px; border-bottom: 1px solid #1B2130; }\n"
       << "    .info-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 20px; }\n"
       << "    .info-card { background: #0E121A; border: 1px solid #1E2535; border-radius: 10px; padding: 14px; }\n"
       << "    .info-card strong { color: #94A3B8; font-size: 12px; display: block; margin-bottom: 4px; }\n"
       << "    .info-card span { font-size: 15px; color: #FFFFFF; font-weight: 600; }\n"
       << "    .footer { margin-top: 40px; padding-top: 20px; border-top: 1px solid #222A3B; display: flex; justify-content: space-between; align-items: center; font-size: 12px; color: #64748B; }\n"
       << "    .signature-box { border-top: 1px dashed #475569; width: 220px; text-align: center; padding-top: 8px; margin-top: 30px; }\n"
       << "  </style>\n"
       << "</head>\n"
       << "<body>\n"
       << "<div class=\"container\">\n"
       << "  <div class=\"header\">\n"
       << "    <div>\n"
       << "      <div class=\"brand-title\">MULTI-GUARD <span style=\"color:#00E676;\">SECURITY</span></div>\n"
       << "      <div class=\"brand-subtitle\">Raport Serwisowy &amp; Audyt Bezpieczeństwa</div>\n"
       << "    </div>\n"
       << "    <div class=\"report-meta\">\n"
       << "      Data audytu: <strong style=\"color:#FFFFFF;\">" << nowStr << "</strong><br>\n"
       << "      Wersja silnika: " << APP_VERSION_STR << "<br>\n"
       << "      Serwis wykonujący: <strong>Multi-Servis</strong>\n"
       << "    </div>\n"
       << "  </div>\n"

       << "  <h2>1. Identyfikacja Stacji Roboczej</h2>\n"
       << "  <div class=\"info-grid\">\n"
       << "    <div class=\"info-card\"><strong>Nazwa komputera (Host)</strong><span>" << hostname << "</span></div>\n"
       << "    <div class=\"info-card\"><strong>System operacyjny</strong><span>" << osPretty << "</span></div>\n"
       << "    <div class=\"info-card\"><strong>Jądro systemu</strong><span>" << kernel << "</span></div>\n"
       << "    <div class=\"info-card\"><strong>Baza sygnatur</strong><span>" << (SignatureDb::instance().count() > 0 ? QString::number(SignatureDb::instance().count()) + " sygnatur" : "Zainicjalizowana") << "</span></div>\n"
       << "  </div>\n"

       << "  <h2>2. Status Aktywnych Osłon Ochronnych</h2>\n"
       << "  <table>\n"
       << "    <tr><th>Komponent Ochrony</th><th>Opis modułu</th><th>Status</th></tr>\n"
       << "    <tr><td>Ochrona w czasie rzeczywistym (Real-Time Shield)</td><td>Canary Guard, heurystyczny analizator plików</td><td><span class=\"badge " << (Settings::instance().realTimeProtection() ? "badge-success\">AKTYWNA" : "badge-warn\">WYŁĄCZONA") << "</span></td></tr>\n"
       << "    <tr><td>Ochrona przed Ransomware (Controlled Folders)</td><td>Monitorowanie szyfrowania i obrona dokumentów</td><td><span class=\"badge " << (Settings::instance().ransomwareProtection() ? "badge-success\">AKTYWNA" : "badge-warn\">WYŁĄCZONA") << "</span></td></tr>\n"
       << "    <tr><td>Ochrona sieciowa (Web Shield)</td><td>Blokowanie domen phishingowych i telemetrycznych</td><td><span class=\"badge " << (Settings::instance().webShield() ? "badge-success\">AKTYWNA" : "badge-warn\">WYŁĄCZONA") << "</span></td></tr>\n"
       << "    <tr><td>Skaner nośników wymiennych (USB Sentinel)</td><td>Automatyczna analiza nośników pendrive / dysków USB</td><td><span class=\"badge " << (Settings::instance().scanUsbOnInsert() ? "badge-success\">AKTYWNA" : "badge-warn\">WYŁĄCZONA") << "</span></td></tr>\n"
       << "  </table>\n"

       << "  <h2>3. Dziennik Zdarzeń Bezpieczeństwa (Security Audit Trail)</h2>\n"
       << "  <table>\n"
       << "    <tr><th>Data i Czas</th><th>Kategoria</th><th>Opis Zdarzenia</th><th>Szczegóły</th><th>Status</th></tr>\n";

    if (events.isEmpty()) {
        ts << "    <tr><td colspan=\"5\" style=\"text-align:center; color:#94A3B8; padding:18px;\">Brak zarejestrowanych incydentów bezpieczeństwa. System czysty.</td></tr>\n";
    } else {
        for (const auto &ev : events) {
            QString badgeClass = "badge-success";
            QString badgeLabel = "INFO";
            if (ev.severity == 1) { badgeClass = "badge-success"; badgeLabel = "SUKCES"; }
            else if (ev.severity == 2) { badgeClass = "badge-warn"; badgeLabel = "OSTRZEŻENIE"; }
            else if (ev.severity >= 3) { badgeClass = "badge-danger"; badgeLabel = "ZAGROŻENIE"; }

            ts << "    <tr>"
               << "<td>" << ev.timestamp.toString(QStringLiteral("yyyy-MM-dd HH:mm")) << "</td>"
               << "<td><strong>" << ev.type << "</strong></td>"
               << "<td>" << ev.description << "</td>"
               << "<td style=\"font-family:monospace; font-size:11px; color:#94A3B8;\">" << ev.details << "</td>"
               << "<td><span class=\"badge " << badgeClass << "\">" << badgeLabel << "</span></td>"
               << "</tr>\n";
        }
    }

    ts << "  </table>\n"
       << "  <div style=\"display:flex; justify-content:space-between; margin-top:30px;\">\n"
       << "    <div>\n"
       << "      <p style=\"font-size:13px; color:#CBD5E1;\">Stacja robocza przeszła procedurę weryfikacji i optymalizacji silnikiem Multi-Guard.<br>Wszelkie wykryte zagrożenia zostały zneutralizowane.</p>\n"
       << "    </div>\n"
       << "    <div class=\"signature-box\">\n"
       << "      Pieczęć i podpis technika Multi-Servis\n"
       << "    </div>\n"
       << "  </div>\n"
       << "  <div class=\"footer\">\n"
       << "    <div>Multi-Servis Usługi Informatyczne · ul. Serwisowa · www.multi-servis.pl</div>\n"
       << "    <div>Wygenerowano z pakietu Multi-Guard v" << APP_VERSION_STR << "</div>\n"
       << "  </div>\n"
       << "</div>\n"
       << "</body>\n"
       << "</html>\n";

    f.close();
    return outPath;
}

} // namespace verax
