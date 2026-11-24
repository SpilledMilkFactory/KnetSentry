// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include "daemon_control.hpp"

#include <QFileInfo>
#include <QStringList>
#include <unistd.h>

namespace knetsentry::desktop {
DaemonControl::DaemonControl(ServiceHealthModel& health, bool external, const QString& program)
    : health_(health), external_(external), program_(program) {
    transition_.setInterval(250);
    pulse_timer_.setSingleShot(true);
    pulse_timer_.setInterval(900);
    child_.setProcessChannelMode(QProcess::ForwardedChannels);
    connect(&health_, &ServiceHealthModel::changed, this, &DaemonControl::healthChanged);
    connect(&transition_, &QTimer::timeout, this, &DaemonControl::tick);
    connect(&pulse_timer_, &QTimer::timeout, this, [this] {
        pulse_ = false;
        Q_EMIT changed();
    });
    connect(&child_, &QProcess::started, this, [this] {
        if (phase_ == Phase::Starting) { health_.start(); }
        else if (timed_out_) { child_.terminate(); }
        Q_EMIT changed();
    });
    connect(&child_, &QProcess::finished, this, &DaemonControl::finished);
    connect(&child_, &QProcess::errorOccurred, this, [this](QProcess::ProcessError error) {
        if (error == QProcess::FailedToStart) { finished(-1, QProcess::NormalExit); }
    });
}

DaemonControl::~DaemonControl() {
    // No signals into the model while the controller is being dismantled.
    disconnect(&health_, nullptr, this, nullptr);
    disconnect(&child_, nullptr, this, nullptr);
    transition_.stop();
    pulse_timer_.stop();
    if (!external_) { health_.setDirectory(QString{}); }
    if (child_.state() != QProcess::NotRunning) {
        child_.terminate();
        if (!child_.waitForFinished(3000)) {
            // Last resort during desktop shutdown, only our own child.
            if (directory_) { directory_->setAutoRemove(false); }
            child_.kill();
            static_cast<void>(child_.waitForFinished(3000));
        }
        if (directory_ && (child_.exitStatus() != QProcess::NormalExit || child_.exitCode() != 0)) {
            directory_->setAutoRemove(false);
        }
    }
    if (directory_ && QFileInfo::exists(directory_->filePath(QStringLiteral("manager.sock")))) {
        directory_->setAutoRemove(false);
    }
}

bool DaemonControl::canStart() const {
    return !external_ && ::geteuid() != 0 && child_.state() == QProcess::NotRunning &&
           (phase_ == Phase::Idle || phase_ == Phase::Stopped || phase_ == Phase::Failed);
}
bool DaemonControl::canStop() const {
    return !external_ && child_.state() == QProcess::Running &&
           (phase_ == Phase::Running || phase_ == Phase::Failed);
}
int DaemonControl::tone() const {
    if (::geteuid() == 0 || phase_ == Phase::Failed || phase_ == Phase::Stopped) { return 0; }
    if (phase_ == Phase::Starting || phase_ == Phase::Stopping) { return 1; }
    if (health_.available()) { return 2; }
    if (health_.queryState() == service::HealthQueryState::Pending ||
        health_.queryState() == service::HealthQueryState::Idle) {
        return 1;
    }
    return 0;
}
QString DaemonControl::status() const {
    if (::geteuid() == 0) { return tr("Daemon controls unavailable as root"); }
    if (phase_ == Phase::Stopped) { return tr("Desktop-owned daemon stopped"); }
    if (phase_ == Phase::Starting) { return tr("Starting desktop-owned daemon…"); }
    if (phase_ == Phase::Stopping) { return tr("Stopping desktop-owned daemon…"); }
    if (phase_ == Phase::Failed) {
        return child_.state() == QProcess::NotRunning
            ? tr("Desktop-owned daemon failed — start to retry")
            : tr("Daemon transition timed out — stop to retry shutdown");
    }
    if (external_) { return tr("%1 — externally managed; controls disabled").arg(health_.status()); }
    return health_.status();
}

void DaemonControl::startManager() {
    if (!canStart()) { return; }
    const QFileInfo executable(program_);
    if (!executable.isAbsolute() || !executable.isFile() || !executable.isExecutable()) {
        phase_ = Phase::Failed;
        Q_EMIT changed();
        return;
    }
    directory_ = std::make_unique<QTemporaryDir>(QStringLiteral("/tmp/ks29-XXXXXX"));
    if (!directory_->isValid()) {
        directory_.reset();
        phase_ = Phase::Failed;
        Q_EMIT changed();
        return;
    }
    phase_ = Phase::Starting;
    timed_out_ = false;
    health_.setDirectory(directory_->path());
    child_.setProgram(program_);
    child_.setArguments({QStringLiteral("--ipc-dir"), directory_->path()});
    deadline_.start();
    transition_.start();
    child_.start();
    Q_EMIT changed();
}

void DaemonControl::stopManager() {
    if (!canStop()) { return; }
    phase_ = Phase::Stopping;
    timed_out_ = false;
    pulse_timer_.stop();
    pulse_ = false;
    health_.setDirectory(QString{});
    deadline_.start();
    transition_.start();
    child_.terminate();
    Q_EMIT changed();
}

void DaemonControl::healthChanged() {
    if (phase_ == Phase::Starting && health_.available() && child_.state() == QProcess::Running) {
        phase_ = Phase::Running;
        transition_.stop();
    }
    if (health_.available() && (external_ || phase_ == Phase::Running)) {
        pulse_ = true;
        pulse_timer_.start();
    } else {
        pulse_ = false;
        pulse_timer_.stop();
    }
    Q_EMIT changed();
}

void DaemonControl::tick() {
    if (deadline_.elapsed() >= 5000) {
        transition_.stop();
        timed_out_ = true;
        phase_ = Phase::Failed;
        health_.setDirectory(QString{});
        if (child_.state() == QProcess::Running) { child_.terminate(); }
        Q_EMIT changed();
        return;
    }
    if (phase_ == Phase::Starting && child_.state() == QProcess::Running) { health_.refresh(); }
}

void DaemonControl::finished(int code, QProcess::ExitStatus status) {
    const bool stale = directory_ && QFileInfo::exists(directory_->filePath(QStringLiteral("manager.sock")));
    const bool stopped = phase_ == Phase::Stopping && code == 0 &&
                         status == QProcess::NormalExit && !stale;
    transition_.stop();
    pulse_timer_.stop();
    pulse_ = false;
    phase_ = stopped && !timed_out_ ? Phase::Stopped : Phase::Failed;
    health_.setDirectory(QString{});
    // Preserve a stale entry after an abnormal exit; never reuse its directory.
    if (directory_ && stale) {
        directory_->setAutoRemove(false);
    }
    directory_.reset();
    Q_EMIT changed();
}
} // namespace knetsentry::desktop
