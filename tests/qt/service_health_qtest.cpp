// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include "service_health_model.hpp"

#include <QSignalSpy>
#include <QTest>
#include <QTemporaryDir>
#include <unistd.h>

using knetsentry::desktop::ServiceHealthModel;

class ServiceHealthTest final : public QObject {
    Q_OBJECT
private Q_SLOTS:
    void unconfigured() {
        ServiceHealthModel model(QString{});
        QSignalSpy spy(&model, &ServiceHealthModel::changed);
        model.start();
        model.refresh();
        QVERIFY(!model.available());
        QCOMPARE(model.status(), QStringLiteral("Not connected — no IPC directory configured"));
        QCOMPARE(model.resources(), QStringLiteral("Uptime, CPU time and memory unavailable."));
        QCOMPARE(spy.count(), 0);
    }
    void absentEndpoint() {
        QTemporaryDir dir(QStringLiteral("/tmp/ks26-qt-XXXXXX"));
        QVERIFY(dir.isValid());
        ServiceHealthModel model(dir.path());
        QSignalSpy spy(&model, &ServiceHealthModel::changed);
        model.start();
        QVERIFY(!model.available());
        QCOMPARE(model.errors(), QStringLiteral("Operational error counters unavailable."));
        if (::geteuid() == 0) {
            QCOMPARE(model.status(), QStringLiteral("Unavailable — root desktop IPC is disabled"));
            QCOMPARE(spy.count(), 0);
        } else {
            QCOMPARE(model.status(), QStringLiteral("Disconnected or unavailable"));
            QCOMPARE(spy.count(), 1);
        }
    }
};

QTEST_GUILESS_MAIN(ServiceHealthTest)
#include "service_health_qtest.moc"
