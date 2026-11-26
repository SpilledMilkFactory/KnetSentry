// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#pragma once

#include "knetsentry/service/health_client.hpp"
#include "knetsentry/agent/telemetry_status.hpp"

#include <QByteArray>
#include <QObject>
#include <QString>
#include <QTimer>
#include <QtQmlIntegration/qqmlintegration.h>

namespace knetsentry::desktop {

// Read-only presentation model. QML cannot create a client, change its
// endpoint, issue arbitrary requests or refresh outside the fixed cadence.
class ServiceHealthModel : public QObject {
    Q_OBJECT
    QML_ELEMENT
    QML_UNCREATABLE("The desktop owns the service health model")
    Q_PROPERTY(QString status READ status NOTIFY changed FINAL)
    Q_PROPERTY(QString components READ components NOTIFY changed FINAL)
    Q_PROPERTY(QString resources READ resources NOTIFY changed FINAL)
    Q_PROPERTY(QString errors READ errors NOTIFY changed FINAL)
    Q_PROPERTY(bool available READ available NOTIFY changed FINAL)
    Q_PROPERTY(QString scopeState READ scopeState NOTIFY changed FINAL)
    Q_PROPERTY(QString scopeNetworks READ scopeNetworks NOTIFY changed FINAL)
    Q_PROPERTY(QString scopeInterfaces READ scopeInterfaces NOTIFY changed FINAL)
    Q_PROPERTY(QString scopeDenials READ scopeDenials NOTIFY changed FINAL)
    Q_PROPERTY(QString agentRegistryStatus READ agentRegistryStatus NOTIFY changed FINAL)
    Q_PROPERTY(QString approvedAgents READ approvedAgents NOTIFY changed FINAL)
    Q_PROPERTY(QString revokedAgents READ revokedAgents NOTIFY changed FINAL)
    Q_PROPERTY(QString telemetryStatus READ telemetryStatus NOTIFY telemetryChanged FINAL)
    Q_PROPERTY(QString telemetryCollector READ telemetryCollector NOTIFY telemetryChanged FINAL)
    Q_PROPERTY(QString telemetryHealth READ telemetryHealth NOTIFY telemetryChanged FINAL)
    Q_PROPERTY(QString telemetryRate READ telemetryRate NOTIFY telemetryChanged FINAL)
    Q_PROPERTY(QString telemetryQueue READ telemetryQueue NOTIFY telemetryChanged FINAL)
    Q_PROPERTY(QString telemetryFailure READ telemetryFailure NOTIFY telemetryChanged FINAL)
public:
    explicit ServiceHealthModel(const QString& directory, QObject* parent = nullptr);
    [[nodiscard]] QString status() const;
    [[nodiscard]] QString components() const;
    [[nodiscard]] QString resources() const;
    [[nodiscard]] QString errors() const;
    [[nodiscard]] bool available() const noexcept;
    [[nodiscard]] QString scopeState() const;
    [[nodiscard]] QString scopeNetworks() const;
    [[nodiscard]] QString scopeInterfaces() const;
    [[nodiscard]] QString scopeDenials() const;
    [[nodiscard]] QString agentRegistryStatus() const;
    [[nodiscard]] QString approvedAgents() const;
    [[nodiscard]] QString revokedAgents() const;
    [[nodiscard]] QString telemetryStatus() const;
    [[nodiscard]] QString telemetryCollector() const;
    [[nodiscard]] QString telemetryHealth() const;
    [[nodiscard]] QString telemetryRate() const;
    [[nodiscard]] QString telemetryQueue() const;
    [[nodiscard]] QString telemetryFailure() const;
    bool attachTelemetry(int fd);
    void start();
    void setDirectory(const QString& directory);
    [[nodiscard]] service::HealthQueryState queryState() const noexcept;
    // C++ only: periodic refresh and deterministic test orchestration.
    void refresh();
Q_SIGNALS:
    void changed();
    void telemetryChanged();
private:
    void advance();
    QByteArray directory_;
    service::HealthClient client_;
    service::HealthClient agent_client_;
    QTimer refresh_timer_;
    QTimer exchange_timer_;
    agent::StatusReader telemetry_reader_;
    QTimer telemetry_timer_;
};

} // namespace knetsentry::desktop
