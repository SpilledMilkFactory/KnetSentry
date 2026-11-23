// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include "knetsentry/core/build_info.hpp"

#include <QCoreApplication>
#include <QCommandLineParser>
#include <QString>

#include <iostream>

int main(int argc, char *argv[]) {
    QCoreApplication app(argc, argv);
    QCoreApplication::setApplicationName(QStringLiteral("KnetSentry"));
    QCoreApplication::setApplicationVersion(
        QString::fromUtf8(knetsentry::core::project_version().data(),
                          static_cast<qsizetype>(knetsentry::core::project_version().size())));

    QCommandLineParser parser;
    parser.setApplicationDescription(
        QStringLiteral("KnetSentry M1.1 bootstrap (no GUI or SIEM functionality yet)"));
    parser.addHelpOption();
    parser.addVersionOption();
    parser.process(app);

    std::cout << knetsentry::core::product_name() << " "
              << knetsentry::core::project_version() << " — "
              << knetsentry::core::implementation_state() << '\n';
    return 0;
}
