// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#pragma once
#include <knetsentry/desktop/workspace_preferences.hpp>
#include <QObject>
#include <QString>
#include <QtQmlIntegration/qqmlintegration.h>

namespace knetsentry::desktop {
class WorkspaceModel : public QObject {
    Q_OBJECT
    QML_ELEMENT
    QML_UNCREATABLE("The desktop owns workspace preferences")
    Q_PROPERTY(int ratio READ ratio NOTIFY changed FINAL)
    Q_PROPERTY(bool charts READ charts NOTIFY changed FINAL)
    Q_PROPERTY(bool health READ health NOTIFY changed FINAL)
    Q_PROPERTY(bool telemetry READ telemetry NOTIFY changed FINAL)
    Q_PROPERTY(QString status READ status NOTIFY changed FINAL)
public:
    explicit WorkspaceModel(bool persistent, QObject* parent = nullptr);
    [[nodiscard]] int ratio() const noexcept { return value_.ratio; }
    [[nodiscard]] bool charts() const noexcept { return (value_.sections & 1) != 0; }
    [[nodiscard]] bool health() const noexcept { return (value_.sections & 2) != 0; }
    [[nodiscard]] bool telemetry() const noexcept { return (value_.sections & 4) != 0; }
    [[nodiscard]] QString status() const { return status_; }
    Q_INVOKABLE void configure(int ratio, bool charts, bool health, bool telemetry);
    Q_INVOKABLE void save();
Q_SIGNALS:
    void changed();
private:
    QString root_, status_;
    WorkspacePreferences value_;
};
} // namespace knetsentry::desktop
