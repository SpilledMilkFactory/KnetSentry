// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#pragma once
#include <knetsentry/service/health_client.hpp>
#include <QAbstractListModel>
#include <QByteArray>
#include <QString>
#include <QTimer>
#include <QtQmlIntegration/qqmlintegration.h>

namespace knetsentry::desktop {
class EventExplorerModel : public QAbstractListModel {
    Q_OBJECT
    QML_ELEMENT
    QML_UNCREATABLE("The desktop owns the event explorer")
    Q_PROPERTY(QString status READ status NOTIFY changed FINAL)
    Q_PROPERTY(QString detail READ detail NOTIFY changed FINAL)
    Q_PROPERTY(bool busy READ busy NOTIFY changed FINAL)
    Q_PROPERTY(bool more READ more NOTIFY changed FINAL)
public:
    explicit EventExplorerModel(const QString& directory, QObject* parent = nullptr);
    [[nodiscard]] int rowCount(const QModelIndex& parent = {}) const override;
    [[nodiscard]] QVariant data(const QModelIndex& index, int role) const override;
    [[nodiscard]] QHash<int, QByteArray> roleNames() const override;
    [[nodiscard]] QString status() const { return status_; }
    [[nodiscard]] QString detail() const { return detail_; }
    [[nodiscard]] bool busy() const noexcept { return busy_; }
    [[nodiscard]] bool more() const noexcept { return more_; }
    Q_INVOKABLE void search(const QString& source, int mode, int outcome, bool descending);
    Q_INVOKABLE void next();
    Q_INVOKABLE void select(int row);
    Q_INVOKABLE void clear();
Q_SIGNALS:
    void changed();
private:
    void request();
    void advance();
    void discard();
    enum Role { EventLabel = Qt::UserRole + 1 };
    const QByteArray directory_;
    service::HealthClient client_;
    service::EventQuery query_;
    std::vector<storage::EventSummary> rows_;
    QString status_, detail_;
    QTimer exchange_, expiry_;
    bool busy_{}, more_{};
};
} // namespace knetsentry::desktop
