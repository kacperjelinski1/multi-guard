#pragma once

#include <QString>
#include <QVector>

namespace verax {

class ReportGenerator {
public:
    static QString generateServiceReportHtml(const QString &targetFilePath = QString());
};

} // namespace verax
