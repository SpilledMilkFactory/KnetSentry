// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#pragma once

#include "service_health_model.hpp"

#include <QElapsedTimer>
#include <QProcess>
#include <QTemporaryDir>
#include <memory>

namespace knetsentry::desktop {

// Only the desktop-owned child is controllable; no PID discovery or systemd.
class DaemonControl : public QObject {
    Q_OBJECT
    QML_ELEMENT
    QML_UNCREATABLE("The desktop owns daemon control")
    Q_PROPERTY(int tone READ tone NOTIFY changed FINAL)
    Q_PROPERTY(QString status READ status NOTIFY changed FINAL)
    Q_PROPERTY(bool pulse READ pulse NOTIFY changed FINAL)
    Q_PROPERTY(bool canStart READ canStart NOTIFY changed FINAL)
    Q_PROPERTY(bool canStop READ canStop NOTIFY changed FINAL)
public:
    DaemonControl(ServiceHealthModel& health, bool external, const QString& program);
    ~DaemonControl() override;
    [[nodiscard]] int tone() const;
    [[nodiscard]] QString status() const;
    [[nodiscard]] bool pulse() const noexcept { return pulse_; }
    [[nodiscard]] bool canStart() const;
    [[nodiscard]] bool canStop() const;
    Q_INVOKABLE void startManager();
    Q_INVOKABLE void stopManager();
Q_SIGNALS:
    void changed();
private:
    enum class Phase { Idle, Stopped, Starting, Running, Stopping, Failed };
    void healthChanged();
    void finished(int code, QProcess::ExitStatus status);
    void tick();
    ServiceHealthModel& health_;
    const bool external_;
    const QString program_;
    std::unique_ptr<QTemporaryDir> directory_;
    QProcess child_;
    QTimer transition_;
    QTimer pulse_timer_;
    QElapsedTimer deadline_;
    Phase phase_{Phase::Idle};
    bool pulse_{false};
    bool timed_out_{false};
};
} // namespace knetsentry::desktop
