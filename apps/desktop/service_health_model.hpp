// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#pragma once

#include "knetsentry/service/health_client.hpp"

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
public:
    explicit ServiceHealthModel(const QString& directory, QObject* parent = nullptr);
    [[nodiscard]] QString status() const;
    [[nodiscard]] QString components() const;
    [[nodiscard]] QString resources() const;
    [[nodiscard]] QString errors() const;
    [[nodiscard]] bool available() const noexcept;
    void start();
    // C++ only: periodic refresh and deterministic test orchestration.
    void refresh();
Q_SIGNALS:
    void changed();
private:
    void advance();
    QByteArray directory_;
    service::HealthClient client_;
    QTimer refresh_timer_;
    QTimer exchange_timer_;
};

} // namespace knetsentry::desktop
