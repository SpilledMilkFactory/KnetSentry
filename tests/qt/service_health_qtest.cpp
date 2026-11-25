// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include "service_health_model.hpp"

#include <QMetaProperty>
#include <QSignalSpy>
#include <QTest>
#include <QTemporaryDir>
#include <QVariant>
#include <initializer_list>
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
    void scopeIsReadOnly() {
        ServiceHealthModel model(QString{});
        for (const auto* name : {"scopeState", "scopeNetworks", "scopeInterfaces", "scopeDenials",
                                 "agentRegistryStatus", "approvedAgents", "revokedAgents"}) {
            const int index = model.metaObject()->indexOfProperty(name);
            QVERIFY(index >= 0);
            const auto property = model.metaObject()->property(index);
            QVERIFY(property.isReadable());
            QVERIFY(!property.isWritable());
            QVERIFY(property.hasNotifySignal());
            QVERIFY(!property.write(&model, QVariant{QStringLiteral("synthetic approval")}));
        }
        QVERIFY(model.agentRegistryStatus().startsWith(QStringLiteral("Unavailable")));
        QVERIFY(model.approvedAgents().startsWith(QStringLiteral("Unavailable")));
        QVERIFY(model.revokedAgents().startsWith(QStringLiteral("Unavailable")));
        QCOMPARE(model.scopeState(), QStringLiteral("Unavailable — no current verified daemon health"));
        QCOMPARE(model.scopeNetworks(), QStringLiteral("Unavailable — approved network inventory not reported."));
        QCOMPARE(model.scopeInterfaces(), QStringLiteral("Unavailable — approved interface inventory not reported."));
        QCOMPARE(model.scopeDenials(), QStringLiteral("Network connection denials: unavailable (not collected).\n"
                                                       "Local IPC rejected requests: unavailable."));
        model.setDirectory(QStringLiteral("/nonexistent/ks38"));
        model.refresh();
        QVERIFY(!model.available());
        QCOMPARE(model.scopeState(), QStringLiteral("Unavailable — no current verified daemon health"));
        QVERIFY(model.scopeDenials().endsWith(QStringLiteral("unavailable.")));
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
