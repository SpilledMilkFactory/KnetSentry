// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#pragma once
#include <knetsentry/service/health_client.hpp>
#include <QAbstractListModel>
#include <QStringList>
#include <QTimer>
#include <QtQmlIntegration/qqmlintegration.h>
namespace knetsentry::desktop {
class AlertModel : public QAbstractListModel {
    Q_OBJECT
    QML_ELEMENT
    QML_UNCREATABLE("The desktop owns the alert model")
    Q_PROPERTY(QString status READ status NOTIFY changed FINAL)
    Q_PROPERTY(QString detail READ detail NOTIFY changed FINAL)
    Q_PROPERTY(QString evidenceDetail READ evidenceDetail NOTIFY changed FINAL)
    Q_PROPERTY(QStringList evidence READ evidence NOTIFY changed FINAL)
    Q_PROPERTY(bool busy READ busy NOTIFY changed FINAL)
    Q_PROPERTY(bool more READ more NOTIFY changed FINAL)
    Q_PROPERTY(bool canAcknowledge READ canAcknowledge NOTIFY changed FINAL)
public:
    explicit AlertModel(const QString& directory, QObject* parent = nullptr);
    [[nodiscard]] int rowCount(const QModelIndex& parent = {}) const override;
    [[nodiscard]] QVariant data(const QModelIndex& index, int role) const override;
    [[nodiscard]] QHash<int,QByteArray> roleNames() const override;
    [[nodiscard]] QString status() const { return status_; }
    [[nodiscard]] QString detail() const { return detail_; }
    [[nodiscard]] QString evidenceDetail() const { return evidence_detail_; }
    [[nodiscard]] QStringList evidence() const { return evidence_; }
    [[nodiscard]] bool busy() const noexcept { return busy_; }
    [[nodiscard]] bool more() const noexcept { return more_; }
    [[nodiscard]] bool canAcknowledge() const noexcept;
    Q_INVOKABLE void search(int severity);
    Q_INVOKABLE void next();
    Q_INVOKABLE void select(int row);
    Q_INVOKABLE void acknowledge();
    Q_INVOKABLE void inspectEvidence(int index);
    Q_INVOKABLE void clear();
Q_SIGNALS:
    void changed();
private:
    void request(const service::AlertQuery& q);
    void advance();
    void discard();
    [[nodiscard]] service::AlertQuery selectedQuery(service::AlertQuery::Operation operation) const;
    enum Role { AlertLabel = Qt::UserRole + 1 };
    const QByteArray directory_;
    service::HealthClient client_;
    service::AlertQuery query_, request_;
    std::vector<service::AlertRow> rows_;
    QString status_, detail_, evidence_detail_;
    QStringList evidence_;
    QTimer exchange_, expiry_;
    int selection_{-1};
    bool busy_{}, more_{}, writable_{};
};
} // namespace knetsentry::desktop
