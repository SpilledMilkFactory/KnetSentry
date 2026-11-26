// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include "service_health_model.hpp"

#include <QMetaProperty>
#include <QSignalSpy>
#include <QTest>
#include <QTemporaryDir>
#include <QVariant>
#include <initializer_list>
#include <string>
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
                                 "agentRegistryStatus", "approvedAgents", "revokedAgents",
                                 "telemetryStatus", "telemetryCollector", "telemetryHealth", "telemetryRate",
                                 "telemetryQueue", "telemetryFailure"}) {
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
    void localTelemetry() {
        ServiceHealthModel model(QString{});
        QCOMPARE(model.telemetryRate(), QStringLiteral("Unavailable"));
        QSignalSpy spy(&model, &ServiceHealthModel::telemetryChanged);
        std::array<int, 2> fds{};
        QVERIFY(::pipe2(fds.data(), O_CLOEXEC) == 0);
        if (::geteuid() == 0) {
            QVERIFY(!model.attachTelemetry(fds[0]));
            ::close(fds[0]);
            ::close(fds[1]);
            return;
        }
        QVERIFY(model.attachTelemetry(fds[0]));
        ::close(fds[0]);
        const auto frame = std::string("KSSTAT1\tjournal\tactive\t") +
            std::to_string(knetsentry::agent::status_now()) + "\t2\t1000\t12\n";
        QVERIFY(::write(fds[1], frame.data(), frame.size()) == static_cast<ssize_t>(frame.size()));
        QTRY_COMPARE(model.telemetryCollector(), QStringLiteral("Journal metadata"));
        QCOMPARE(model.telemetryRate(), QStringLiteral("2.00 observations/s (2 in 1000 ms)"));
        QVERIFY(model.telemetryQueue().startsWith(QStringLiteral("12 / 128")));
        QVERIFY(!model.available()); // Independent of manager health and enrollment.
        QVERIFY(spy.count() >= 2);
        const auto blocked = std::string("KSSTAT1\tjournal\tblocked\t") +
            std::to_string(knetsentry::agent::status_now()) + "\t0\t0\t12\n";
        QVERIFY(::write(fds[1], blocked.data(), blocked.size()) == static_cast<ssize_t>(blocked.size()));
        QTRY_VERIFY(model.telemetryFailure().startsWith(QStringLiteral("Reported source failure")));
        QCOMPARE(model.telemetryRate(), QStringLiteral("Unavailable"));
        ::close(fds[1]);
        QTRY_VERIFY(model.telemetryStatus().contains(QStringLiteral("disconnected")));
        QCOMPARE(model.telemetryCollector(), QStringLiteral("Unavailable"));
        QCOMPARE(model.telemetryQueue(), QStringLiteral("Unavailable"));
        QCOMPARE(model.telemetryRate(), QStringLiteral("Unavailable"));
        QVERIFY(model.telemetryFailure().contains(QStringLiteral("not current")));
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
