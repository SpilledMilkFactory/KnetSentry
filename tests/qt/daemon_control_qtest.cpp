// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include "daemon_control.hpp"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QTest>
#include <cerrno>
#include <csignal>
#include <sys/wait.h>
#include <unistd.h>

namespace knetsentry::desktop {

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
    void closeWhileRunning() {
        if (::geteuid() == 0) { QSKIP("Requires ordinary desktop user"); }
        ServiceHealthModel health(QString{});
        QString path;
        pid_t pid = 0;
        {
            DaemonControl control(health, false, QStringLiteral(KNETSENTRY_MANAGER_EXECUTABLE));
            control.startManager();
            QTRY_VERIFY_WITH_TIMEOUT(control.tone() == 2, 6000);
            QVERIFY(control.directory_);
            path = control.directory_->path();
            pid = static_cast<pid_t>(control.child_.processId());
            QVERIFY(pid > 0);
            QVERIFY(QFileInfo::exists(control.directory_->filePath(QStringLiteral("manager.sock"))));
            // No Stop or explicit shutdown: exercise the destructor fallback.
        }
        QVERIFY(!health.available());
        QVERIFY(!QFileInfo::exists(path));
        int status = 0;
        const auto waited = ::waitpid(pid, &status, WNOHANG);
        const int wait_error = errno;
        QCOMPARE(waited, static_cast<pid_t>(-1));
        QCOMPARE(wait_error, ECHILD);
        const int signalled = ::kill(pid, 0);
        const int signal_error = errno;
        QCOMPARE(signalled, -1);
        QCOMPARE(signal_error, ESRCH);
    }
    void closeDuringStartup() {
        if (::geteuid() == 0) { QSKIP("Requires ordinary desktop user"); }
        ServiceHealthModel health(QString{});
        DaemonControl control(health, false, QStringLiteral(KNETSENTRY_MANAGER_EXECUTABLE));
        control.startManager();
        QVERIFY(control.directory_);
        const QString path = control.directory_->path();
        // No event-loop wait for readiness before closing.
        QVERIFY(control.shutdown());
        QCOMPARE(control.child_.state(), QProcess::NotRunning);
        QVERIFY(!health.available());
        QVERIFY(!QFileInfo::exists(path));
        QVERIFY(!control.canStart());
        QVERIFY(!control.canStop());
        QVERIFY(control.shutdown()); // Idempotent; destructor can call again.
    }
    void preservesUnexpectedData() {
        if (::geteuid() == 0) { QSKIP("Requires ordinary desktop user"); }
        ServiceHealthModel health(QString{});
        DaemonControl control(health, false, QStringLiteral(KNETSENTRY_MANAGER_EXECUTABLE));
        control.startManager();
        QTRY_VERIFY_WITH_TIMEOUT(control.tone() == 2, 6000);
        QVERIFY(control.directory_);
        const QString path = control.directory_->path();
        QFile marker(control.directory_->filePath(QStringLiteral("synthetic-marker")));
        QVERIFY(marker.open(QIODevice::WriteOnly | QIODevice::NewOnly));
        QCOMPARE(marker.write("fixture"), static_cast<qint64>(7));
        marker.close();
        QVERIFY(!control.shutdown());
        QCOMPARE(control.child_.state(), QProcess::NotRunning);
        QVERIFY(!QFileInfo::exists(QDir(path).filePath(QStringLiteral("manager.sock"))));
        QVERIFY(marker.open(QIODevice::ReadOnly));
        QCOMPARE(marker.readAll(), QByteArray("fixture"));
        marker.close();
        QVERIFY(marker.remove()); // Only the test's own disposable marker.
        QVERIFY(QDir().rmdir(path));
        QVERIFY(!control.shutdown());
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
} // namespace knetsentry::desktop

QTEST_GUILESS_MAIN(knetsentry::desktop::DaemonControlTest)
#include "daemon_control_qtest.moc"
