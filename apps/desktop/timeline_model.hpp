// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#pragma once
#include <knetsentry/service/health_client.hpp>
#include <knetsentry/service/investigation_timeline.hpp>
#include <QObject>
#include <QStringList>
#include <QTimer>
#include <QtQmlIntegration/qqmlintegration.h>

namespace knetsentry::desktop {
class TimelineModel : public QObject {
    Q_OBJECT
    QML_ELEMENT
    QML_UNCREATABLE("The desktop owns the investigation timeline")
    Q_PROPERTY(QString status READ status NOTIFY changed FINAL)
    Q_PROPERTY(QStringList entries READ entries NOTIFY changed FINAL)
    Q_PROPERTY(QString detail READ detail NOTIFY changed FINAL)
    Q_PROPERTY(QStringList related READ related NOTIFY changed FINAL)
    Q_PROPERTY(QStringList evidence READ evidence NOTIFY changed FINAL)
    Q_PROPERTY(QString evidenceDetail READ evidenceDetail NOTIFY changed FINAL)
    Q_PROPERTY(bool busy READ busy NOTIFY changed FINAL)
    Q_PROPERTY(bool configured READ configured CONSTANT FINAL)
public:
    explicit TimelineModel(const QString& directory, QObject* parent = nullptr);
    [[nodiscard]] QString status() const { return status_; }
    [[nodiscard]] QStringList entries() const { return entries_; }
    [[nodiscard]] QString detail() const { return detail_; }
    [[nodiscard]] QStringList related() const { return related_; }
    [[nodiscard]] QStringList evidence() const { return evidence_; }
    [[nodiscard]] QString evidenceDetail() const { return evidence_detail_; }
    [[nodiscard]] bool busy() const noexcept { return exchange_.isActive(); }
    [[nodiscard]] bool configured() const noexcept;
    Q_INVOKABLE void refresh();
    Q_INVOKABLE void clear();
    Q_INVOKABLE void select(int row);
    Q_INVOKABLE void follow(int row);
    Q_INVOKABLE void verifyEvidence(int row);
Q_SIGNALS:
    void changed();
private:
    void advance();
    void reset();
    void fail();
    void requestAlert(const service::AlertQuery& query);
    const QByteArray directory_;
    service::HealthClient client_;
    QTimer exchange_, expiry_;
    service::EventPage events_;
    service::AlertPage alerts_;
    std::vector<service::TimelineEntry> rows_;
    std::vector<int> related_rows_;
    QStringList entries_, related_, evidence_;
    QString status_, detail_, evidence_detail_;
    int selected_{-1};
    enum class Phase { Events, Alerts, Evidence };
    Phase phase_{Phase::Events};
};
} // namespace knetsentry::desktop
