// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include <QProcess>
#include <QProcessEnvironment>
#include <QString>
#include <QStringList>
#include <QTest>

namespace {
class ApplicationQTest final : public QObject {
    Q_OBJECT
private slots:
    void versionWorksWithoutDisplay();
    void helpWorksWithoutDisplay();
    void qmlStartupUsesRealWindow();

private:
    static QProcessEnvironment sterileEnvironment();
    static void start(QProcess& process, const QStringList& arguments);
};

QProcessEnvironment ApplicationQTest::sterileEnvironment() {
    auto environment = QProcessEnvironment::systemEnvironment();
    environment.remove(QStringLiteral("DISPLAY"));
    environment.remove(QStringLiteral("WAYLAND_DISPLAY"));
    environment.insert(QStringLiteral("QT_QPA_PLATFORM"), QStringLiteral("offscreen"));
    environment.insert(QStringLiteral("QT_QUICK_BACKEND"), QStringLiteral("software"));
    environment.insert(QStringLiteral("QT_QUICK_CONTROLS_STYLE"), QStringLiteral("Basic"));
    return environment;
}

void ApplicationQTest::start(QProcess& process, const QStringList& arguments) {
    process.setProcessEnvironment(sterileEnvironment());
    process.setProgram(QString::fromLocal8Bit(KNETSENTRY_DESKTOP_EXECUTABLE));
    process.setArguments(arguments);
    process.start();
    QVERIFY2(process.waitForStarted(10000), "Desktop process failed to start");
    QVERIFY2(process.waitForFinished(20000), "Desktop process timed out");
    QCOMPARE(process.exitStatus(), QProcess::NormalExit);
    QCOMPARE(process.exitCode(), 0);
}

void ApplicationQTest::versionWorksWithoutDisplay() {
    QProcess process;
    start(process, {QStringLiteral("--version")});
    QVERIFY(process.readAllStandardOutput().contains("KnetSentry 0.0.0"));
}

void ApplicationQTest::helpWorksWithoutDisplay() {
    QProcess process;
    start(process, {QStringLiteral("--help")});
    const QByteArray output = process.readAllStandardOutput();
    QVERIFY(output.contains("--version"));
    QVERIFY(output.contains("KnetSentry"));
}

void ApplicationQTest::qmlStartupUsesRealWindow() {
    QProcess process;
    start(process, {QStringLiteral("--self-test-qml")});
    QVERIFY(process.readAllStandardOutput().contains("Kirigami QML smoke: PASS"));
    const QByteArray errors = process.readAllStandardError();
    QVERIFY(errors.contains("\"event\":\"gui_starting\""));
    QVERIFY(errors.contains("\"event\":\"gui_ready\""));
    QVERIFY(!errors.contains("\"event\":\"gui_load_rejected\""));
}
} // namespace

QTEST_GUILESS_MAIN(ApplicationQTest)
#include "application_qtest.moc"
