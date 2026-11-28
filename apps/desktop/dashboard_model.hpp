// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#pragma once
#include <knetsentry/service/health_client.hpp>
#include <QObject>
#include <QString>
#include <QByteArray>
#include <QTimer>
#include <QtQmlIntegration/qqmlintegration.h>

namespace knetsentry::desktop {
// Independent read-only page summaries; no mutation, filters or raw evidence API.
class DashboardModel : public QObject {
    Q_OBJECT
    QML_ELEMENT
    QML_UNCREATABLE("The desktop owns the dashboard model")
    Q_PROPERTY(QString eventSummary READ eventSummary NOTIFY changed FINAL)
    Q_PROPERTY(QString alertSummary READ alertSummary NOTIFY changed FINAL)
    Q_PROPERTY(QString detectionSummary READ detectionSummary NOTIFY changed FINAL)
    Q_PROPERTY(bool busy READ busy NOTIFY changed FINAL)
    Q_PROPERTY(bool configured READ configured CONSTANT FINAL)
public:
    explicit DashboardModel(const QString& directory, QObject* parent = nullptr);
    [[nodiscard]] QString eventSummary() const { return events_; }
    [[nodiscard]] QString alertSummary() const { return alerts_; }
    [[nodiscard]] QString detectionSummary() const { return detections_; }
    [[nodiscard]] bool busy() const noexcept { return exchange_.isActive(); }
    [[nodiscard]] bool configured() const noexcept;
    Q_INVOKABLE void refresh();
    Q_INVOKABLE void clear();
Q_SIGNALS:
    void changed();
private:
    void advance();
    void reset();
    void beginAlerts();
    const QByteArray directory_;
    service::HealthClient client_;
    QTimer exchange_, expiry_;
    QString events_, alerts_, detections_;
    std::string event_session_;
    bool reading_alerts_{};
};
} // namespace knetsentry::desktop
