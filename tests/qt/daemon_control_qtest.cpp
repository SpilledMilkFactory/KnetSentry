// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include "daemon_control.hpp"

#include <QTest>
#include <unistd.h>

using knetsentry::desktop::DaemonControl;
using knetsentry::desktop::ServiceHealthModel;

class DaemonControlTest final : public QObject {
    Q_OBJECT
private Q_SLOTS:
    void externalIsReadOnly() {
        ServiceHealthModel health(QStringLiteral("/nonexistent/ks29"));
        DaemonControl control(health, true, QStringLiteral(KNETSENTRY_MANAGER_EXECUTABLE));
        QVERIFY(!control.canStart());
        QVERIFY(!control.canStop());
        control.startManager();
        control.stopManager();
        QVERIFY(!health.available());
        QVERIFY(!control.pulse());
        QVERIFY(!control.canStart());
        QVERIFY(!control.canStop());
    }
    void missingExecutable() {
        if (::geteuid() == 0) { QSKIP("Requires ordinary desktop user"); }
        ServiceHealthModel health(QString{});
        DaemonControl control(health, false, QStringLiteral("/nonexistent/ks29-manager"));
        QVERIFY(control.canStart());
        control.startManager();
        QCOMPARE(control.tone(), 0);
        QVERIFY(control.canStart());
        QVERIFY(!control.canStop());
        QVERIFY(!health.available());
    }
    void ownedLifecycle() {
        ServiceHealthModel health(QString{});
        DaemonControl control(health, false, QStringLiteral(KNETSENTRY_MANAGER_EXECUTABLE));
        if (::geteuid() == 0) {
            QVERIFY(!control.canStart());
            control.startManager();
            QVERIFY(!control.canStop());
            return;
        }
        QCOMPARE(control.tone(), 1);
        for (int cycle = 0; cycle < 2; ++cycle) {
            QVERIFY(control.canStart());
            control.startManager();
            control.startManager(); // No duplicate child during startup.
            QTRY_VERIFY_WITH_TIMEOUT(control.tone() == 2, 6000);
            QVERIFY(health.available());
            QVERIFY(control.pulse());
            QVERIFY(control.canStop());
            QVERIFY(!control.canStart());
            QTRY_VERIFY_WITH_TIMEOUT(!control.pulse(), 2000);
            QCOMPARE(control.tone(), 2);
            control.stopManager();
            control.stopManager();
            QVERIFY(!health.available());
            QTRY_VERIFY_WITH_TIMEOUT(control.canStart(), 6000);
            QCOMPARE(control.tone(), 0);
            QCOMPARE(control.status(), QStringLiteral("Desktop-owned daemon stopped"));
            QVERIFY(!control.canStop());
            QVERIFY(!control.pulse());
        }
    }
};
QTEST_GUILESS_MAIN(DaemonControlTest)
#include "daemon_control_qtest.moc"
