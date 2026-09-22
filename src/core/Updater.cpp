#include "Updater.h"
#include "Logger.h"
#include "../widgets/Toaster.h"
#include "../../Version.h"

#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QTimer>
#include <QUrl>
#include <QDialog>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QTextBrowser>
#include <QProgressBar>
#include <QFile>
#include <QFileInfo>
#include <QDir>
#include <QStandardPaths>
#include <QProcess>
#include <QDesktopServices>
#include <QCoreApplication>
#include <QGraphicsOpacityEffect>
#include <QPropertyAnimation>
#include <QEasingCurve>

namespace verax {

Updater& Updater::instance() {
    static Updater u;
    return u;
}

Updater::Updater(QObject *parent) : QObject(parent) {}

int Updater::compareVersions(const QString &a, const QString &b)
{
    const QStringList ax = a.split('.', Qt::SkipEmptyParts);
    const QStringList bx = b.split('.', Qt::SkipEmptyParts);
    const int n = std::max(ax.size(), bx.size());
    for (int i = 0; i < n; ++i) {
        const int ai = (i < ax.size() ? ax[i].toInt() : 0);
        const int bi = (i < bx.size() ? bx[i].toInt() : 0);
        if (ai != bi) return ai - bi;
    }
    return 0;
}

UpdateInfo Updater::parseBody(const QString &body)
{
    UpdateInfo info;
    info.downloadUrl = QStringLiteral("https://github.com/kacperjelinski1/multi-guard/releases/latest/download/Multi-Guard-Setup.exe");
    info.releasePageUrl = QString::fromLatin1(APP_DOWNLOAD_URL);

    const QString trimmed = body.trimmed();
    if (trimmed.isEmpty()) return info;

    // Optional direct download url override (Url=>...)
    QString textAfterUrl = trimmed;
    const int urlMarker = trimmed.indexOf(QLatin1String("Url=>"));
    if (urlMarker >= 0) {
        const int urlEnd = trimmed.indexOf('\n', urlMarker);
        if (urlEnd > urlMarker) {
            info.downloadUrl = trimmed.mid(urlMarker + 5, urlEnd - (urlMarker + 5)).trimmed();
            textAfterUrl = trimmed.left(urlMarker).trimmed() + "\n" + trimmed.mid(urlEnd).trimmed();
        } else {
            info.downloadUrl = trimmed.mid(urlMarker + 5).trimmed();
            textAfterUrl = trimmed.left(urlMarker).trimmed();
        }
    }

    // Version & Changelog
    const int marker = textAfterUrl.indexOf(QLatin1String("Changelog=>"));
    QString verLine;
    QString changelog;
    if (marker >= 0) {
        verLine   = textAfterUrl.left(marker).trimmed();
        changelog = textAfterUrl.mid(marker + int(strlen("Changelog=>"))).trimmed();
    } else {
        verLine   = textAfterUrl;
    }

    const QStringList vlines = verLine.split(QRegExp("[\\r\\n]"), Qt::SkipEmptyParts);
    if (!vlines.isEmpty()) {
        info.latestVersion = vlines.first().trimmed();
    }
    info.changelog = changelog;

    static const QRegExp rxVer("^\\d+(\\.\\d+){0,3}$");
    info.valid = rxVer.exactMatch(info.latestVersion);
    if (info.valid) {
        info.newer = compareVersions(info.latestVersion, QString::fromLatin1(APP_VERSION_STR)) > 0;
    }
    return info;
}

void Updater::checkSilently(QWidget *uiOwner)
{
    if (m_inFlight) return;
    m_explicit = false;
    m_owner = uiOwner;
    runCheck();
}

void Updater::checkExplicitly(QWidget *uiOwner)
{
    if (m_inFlight) return;
    m_explicit = true;
    m_owner = uiOwner;
    runCheck();
}

void Updater::runCheck()
{
    m_inFlight = true;

    if (!m_nam) m_nam = new QNetworkAccessManager(this);

    QNetworkRequest req(QUrl(QString::fromLatin1(APP_VERSION_CHECK_URL)));
    req.setHeader(QNetworkRequest::UserAgentHeader,
                  QStringLiteral("%1/%2").arg(APP_NAME, APP_VERSION_STR));
    req.setAttribute(QNetworkRequest::FollowRedirectsAttribute, true);
    req.setRawHeader("Accept", "text/plain");

    QNetworkReply *r = m_nam->get(req);

    auto *to = new QTimer(this);
    to->setSingleShot(true);
    to->setInterval(10000);
    connect(to, &QTimer::timeout, r, &QNetworkReply::abort);
    to->start();

    connect(r, &QNetworkReply::finished, this, [this, r, to]{
        to->stop();
        to->deleteLater();
        m_inFlight = false;

        if (r->error() != QNetworkReply::NoError) {
            const QString err = r->errorString();
            r->deleteLater();
            Logger::warn(QStringLiteral("Updater check failed: %1").arg(err));
            emit checkFailed(err);

            if (m_explicit && m_owner) {
                Toaster::show(m_owner, tr("Błąd sprawdzania aktualizacji: %1").arg(err), Toaster::Error);
            }
            return;
        }

        const QString body = QString::fromUtf8(r->readAll());
        r->deleteLater();

        const UpdateInfo info = parseBody(body);
        if (!info.valid) {
            Logger::warn(QStringLiteral("Updater: malformed payload (%1)").arg(body.left(64).replace('\n', ' ')));
            emit checkFailed(QStringLiteral("Nieprawidłowa odpowiedź serwera"));
            if (m_explicit && m_owner) {
                Toaster::show(m_owner, tr("Nieprawidłowa odpowiedź serwera aktualizacji."), Toaster::Error);
            }
            return;
        }

        if (!info.newer) {
            Logger::info(QStringLiteral("Updater: currently running latest version (%1).").arg(APP_VERSION_STR));
            emit noUpdate();
            if (m_explicit && m_owner) {
                Toaster::show(m_owner, tr("Posiadasz najnowszą wersję Multi-Guard (%1). Brak dostępnych aktualizacji.").arg(APP_VERSION_STR), Toaster::Success);
            }
            return;
        }

        Logger::info(QStringLiteral("Updater: newer version found (%1 → %2)")
                     .arg(QString::fromLatin1(APP_VERSION_STR), info.latestVersion));
        emit updateAvailable(info);

        if (m_owner) {
            showUpdateDialog(m_owner, info);
        }
    });
}

void Updater::showUpdateDialog(QWidget *parent, const UpdateInfo &info)
{
    auto *dlg = new QDialog(parent);
    dlg->setObjectName("UpdaterDialog");
    dlg->setWindowFlag(Qt::Dialog);
    dlg->setWindowFlag(Qt::FramelessWindowHint);
    dlg->setAttribute(Qt::WA_DeleteOnClose, true);
    dlg->setMinimumSize(560, 420);
    dlg->setWindowTitle(tr("Aktualizacja Multi-Guard"));
    dlg->setStyleSheet(
        "QDialog#UpdaterDialog { background-color: #0E131F; border: 1px solid #222D42; border-radius: 16px; }\n"
        "QLabel { font-family: 'Nunito', 'Segoe UI', sans-serif; color: #F1F5F9; }\n"
        "QTextBrowser { background-color: #080B12; border: 1px solid #1E273A; border-radius: 8px; color: #CBD5E1; padding: 10px; font-size: 13px; }\n"
        "QProgressBar { background-color: #141A28; border: 1px solid #2A364F; border-radius: 6px; height: 14px; text-align: center; color: #FFFFFF; font-size: 11px; font-weight: bold; }\n"
        "QProgressBar::chunk { background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #00E676, stop:1 #00B0FF); border-radius: 5px; }\n"
        "QPushButton { font-family: 'Nunito', 'Segoe UI', sans-serif; border-radius: 8px; padding: 8px 16px; font-weight: 600; font-size: 13px; }\n"
    );

    auto *root = new QVBoxLayout(dlg);
    root->setContentsMargins(28, 24, 28, 24);
    root->setSpacing(14);

    // Header
    auto *headerRow = new QHBoxLayout();
    headerRow->setSpacing(14);

    auto *badge = new QLabel(dlg);
    badge->setText(QStringLiteral("🚀"));
    badge->setAlignment(Qt::AlignCenter);
    badge->setStyleSheet("background: rgba(37,99,235,0.18); border: 1px solid rgba(56,189,248,0.4); border-radius: 12px; font-size: 24px;");
    badge->setFixedSize(52, 52);
    headerRow->addWidget(badge);

    auto *titleCol = new QVBoxLayout();
    titleCol->setSpacing(2);
    auto *title = new QLabel(tr("Dostępna jest nowa wersja programu!"), dlg);
    title->setStyleSheet("font-size: 18px; font-weight: 800; color: #FFFFFF;");
    auto *subtitle = new QLabel(tr("Zainstalowana wersja: %1 • Nowa wersja: %2")
                                  .arg(QString::fromLatin1(APP_VERSION_STR), info.latestVersion), dlg);
    subtitle->setStyleSheet("font-size: 13px; color: #38BDF8; font-weight: 600;");
    titleCol->addWidget(title);
    titleCol->addWidget(subtitle);
    headerRow->addLayout(titleCol, 1);
    root->addLayout(headerRow);

    // Changelog
    auto *changeTitle = new QLabel(tr("Lista zmian (Co nowego):"), dlg);
    changeTitle->setStyleSheet("font-size: 13px; font-weight: 700; color: #94A3B8;");
    root->addWidget(changeTitle);

    auto *changeView = new QTextBrowser(dlg);
    const QString changelog = info.changelog.isEmpty() ? tr("Brak opisu zmian.") : info.changelog;
    changeView->setPlainText(changelog);
    root->addWidget(changeView, 1);

    // Status and Progress
    auto *lblStatus = new QLabel(tr("Gotowy do pobrania instalatora."), dlg);
    lblStatus->setStyleSheet("font-size: 12px; color: #94A3B8;");
    root->addWidget(lblStatus);

    auto *progBar = new QProgressBar(dlg);
    progBar->setRange(0, 100);
    progBar->setValue(0);
    progBar->setVisible(false);
    root->addWidget(progBar);

    // Buttons
    auto *btnRow = new QHBoxLayout();
    btnRow->setSpacing(10);
    btnRow->addStretch(1);

    auto *btnBrowser = new QPushButton(tr("Pobierz ręcznie"), dlg);
    btnBrowser->setStyleSheet("background: transparent; border: 1px solid #334155; color: #94A3B8;");
    btnBrowser->setVisible(false);

    auto *btnLater = new QPushButton(tr("Przypomnij później"), dlg);
    btnLater->setStyleSheet("background: transparent; border: 1px solid #334155; color: #94A3B8;");

    auto *btnUpdate = new QPushButton(tr("⬇️ Pobierz i zainstaluj teraz"), dlg);
    btnUpdate->setStyleSheet("background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #00F076, stop:1 #00C853); border: 1px solid #00E676; color: #021206; font-weight: 700;");

    btnRow->addWidget(btnBrowser);
    btnRow->addWidget(btnLater);
    btnRow->addWidget(btnUpdate);
    root->addLayout(btnRow);

    connect(btnLater, &QPushButton::clicked, dlg, &QDialog::reject);
    connect(btnBrowser, &QPushButton::clicked, dlg, [dlg, info]{
        QDesktopServices::openUrl(QUrl(info.releasePageUrl));
        dlg->accept();
    });

    // In-App Auto-Download & Detached Install Execution
    connect(btnUpdate, &QPushButton::clicked, dlg, [this, dlg, info, btnUpdate, btnLater, btnBrowser, progBar, lblStatus]() mutable {
        btnUpdate->setEnabled(false);
        btnLater->setEnabled(false);
        progBar->setVisible(true);
        progBar->setValue(0);
        lblStatus->setText(tr("Nawiązywanie połączenia z serwerem pobierania..."));

        QString tempDir = QStandardPaths::writableLocation(QStandardPaths::TempLocation);
        QString tempPath = tempDir + QStringLiteral("/Multi-Guard-Setup-%1.exe").arg(info.latestVersion);

        auto *file = new QFile(tempPath, dlg);
        if (!file->open(QIODevice::WriteOnly | QIODevice::Truncate)) {
            lblStatus->setText(tr("<font color='#f87171'>Błąd zapisu pliku instalatora w folderze tymczasowym.</font>"));
            btnUpdate->setEnabled(true);
            btnLater->setEnabled(true);
            btnBrowser->setVisible(true);
            return;
        }

        if (!m_nam) m_nam = new QNetworkAccessManager(this);

        QNetworkRequest req(QUrl(info.downloadUrl));
        req.setHeader(QNetworkRequest::UserAgentHeader, QStringLiteral("Multi-Guard-AutoUpdater/%1").arg(APP_VERSION_STR));
        req.setAttribute(QNetworkRequest::FollowRedirectsAttribute, true);

        QNetworkReply *reply = m_nam->get(req);

        connect(reply, &QNetworkReply::readyRead, dlg, [reply, file]{
            file->write(reply->readAll());
        });

        connect(reply, &QNetworkReply::downloadProgress, dlg, [progBar, lblStatus](qint64 bytesReceived, qint64 bytesTotal){
            if (bytesTotal > 0) {
                int pct = static_cast<int>((bytesReceived * 100) / bytesTotal);
                progBar->setValue(pct);
                double mbReceived = bytesReceived / (1024.0 * 1024.0);
                double mbTotal = bytesTotal / (1024.0 * 1024.0);
                lblStatus->setText(QObject::tr("Pobieranie aktualizacji: %1 MB / %2 MB (%3%)")
                                   .arg(QString::number(mbReceived, 'f', 1),
                                        QString::number(mbTotal, 'f', 1),
                                        QString::number(pct)));
            } else {
                double mbReceived = bytesReceived / (1024.0 * 1024.0);
                lblStatus->setText(QObject::tr("Pobieranie aktualizacji: %1 MB...")
                                   .arg(QString::number(mbReceived, 'f', 1)));
            }
        });

        connect(reply, &QNetworkReply::finished, dlg, [reply, file, tempPath, dlg, info, lblStatus, btnBrowser, btnLater]{
            file->flush();
            file->close();

            if (reply->error() != QNetworkReply::NoError) {
                QString err = reply->errorString();
                reply->deleteLater();
                file->remove();
                lblStatus->setText(QObject::tr("<font color='#f87171'>Błąd pobierania (%1).</font>").arg(err));
                btnBrowser->setVisible(true);
                btnLater->setEnabled(true);
                return;
            }

            reply->deleteLater();

            if (QFileInfo(tempPath).size() < 1024) {
                file->remove();
                lblStatus->setText(QObject::tr("<font color='#f87171'>Pobrany plik jest uszkodzony lub niekompletny.</font>"));
                btnBrowser->setVisible(true);
                btnLater->setEnabled(true);
                return;
            }

            lblStatus->setText(QObject::tr("<font color='#4ade80'><b>Pobieranie zakończone!</b> Trwa cicha instalacja aktualizacji...</font>"));

            QTimer::singleShot(1200, dlg, [tempPath, dlg]{
#ifdef Q_OS_WIN
                // Strip Mark-of-the-Web (Zone.Identifier) stream to eliminate Windows SmartScreen warning
                DeleteFileW((LPCWSTR)(tempPath + QStringLiteral(":Zone.Identifier")).utf16());

                QStringList args;
                args << QStringLiteral("/VERYSILENT")
                     << QStringLiteral("/SUPPRESSMSGBOXES")
                     << QStringLiteral("/NORESTART")
                     << QStringLiteral("/CLOSEAPPLICATIONS");

                bool ok = QProcess::startDetached(tempPath, args);
                if (ok) {
                    dlg->accept();
                    QCoreApplication::quit();
                } else {
                    QDesktopServices::openUrl(QUrl::fromLocalFile(tempPath));
                    dlg->accept();
                }
#else
                QDesktopServices::openUrl(QUrl::fromLocalFile(tempPath));
                dlg->accept();
#endif
            });
        });
    });

    dlg->show();
    dlg->raise();
    dlg->activateWindow();
}

} // namespace verax
