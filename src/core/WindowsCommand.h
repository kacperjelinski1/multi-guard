#pragma once
#include <QString>
#include <QStringList>
#include <QProcess>
#include <functional>

namespace verax {
struct CommandResult {
    bool ok = false;
    int exitCode = -1;
    QString output;
    QString error;
};

// One checked boundary for supported Windows tools. Tests inject a runner; no
// security settings on the build host are changed by the regression suite.
class WindowsCommand {
public:
#ifdef MULTIGUARD_TESTING
    inline static std::function<CommandResult(const QString &, const QStringList &)> runner;
#endif
    static CommandResult run(const QString &exe, const QStringList &args, int timeout = 15000) {
#ifdef MULTIGUARD_TESTING
        if (runner) return runner(exe, args);
#endif
        CommandResult result;
#ifdef Q_OS_WIN
        QProcess p;
        p.setCreateProcessArgumentsModifier([](QProcess::CreateProcessArguments *a){ a->flags |= 0x08000000; });
        p.start(exe, args);
        if (!p.waitForStarted(3000)) { result.error = p.errorString(); return result; }
        if (!p.waitForFinished(timeout)) {
            p.kill(); p.waitForFinished(2000);
            result.error = QStringLiteral("Przekroczono czas oczekiwania; stan operacji niepotwierdzony.");
            return result;
        }
        result.exitCode = p.exitCode();
        result.output = QString::fromUtf8(p.readAllStandardOutput()).trimmed();
        result.error = QString::fromUtf8(p.readAllStandardError()).trimmed();
        result.ok = p.exitStatus() == QProcess::NormalExit && result.exitCode == 0;
        if (!result.ok && result.error.isEmpty()) result.error = QStringLiteral("Kod błędu %1: %2").arg(result.exitCode).arg(result.output);
#else
        Q_UNUSED(exe); Q_UNUSED(args); Q_UNUSED(timeout);
        result.error = QStringLiteral("Ta funkcja wymaga systemu Windows i Microsoft Defender.");
#endif
        return result;
    }
    static CommandResult powershell(const QString &script, int timeout = 15000) {
        const QString wrapped = QStringLiteral("[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; $ErrorActionPreference='Stop'; try { ")
            + script + QStringLiteral(" } catch { [Console]::Error.WriteLine($_.Exception.Message); exit 1 }");
        return run(QStringLiteral("powershell.exe"), {"-NoProfile", "-NonInteractive", "-Command", wrapped}, timeout);
    }
    static QString quote(QString text) { return "'" + text.replace("'", "''") + "'"; }
};
}
