// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#pragma once

#include <QAbstractListModel>
#include <QByteArray>
#include <QHash>
#include <QModelIndex>
#include <QObject>
#include <QString>
#include <QVariant>

namespace knetsentry::desktop {

// Read-only, fixed catalog of the seven non-operational application sections.
// A UI model foundation, NOT a telemetry/event/device model or security authority.
class SectionCatalogModel final : public QAbstractListModel {
    Q_OBJECT
public:
    enum Role : int { SectionIdRole = Qt::UserRole + 1, SectionTitleRole };

    explicit SectionCatalogModel(QObject* parent = nullptr);

    [[nodiscard]] int rowCount(const QModelIndex& parent = {}) const override;
    [[nodiscard]] QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;
    [[nodiscard]] QHash<int, QByteArray> roleNames() const override;
    [[nodiscard]] Qt::ItemFlags flags(const QModelIndex& index) const override;
};

} // namespace knetsentry::desktop
