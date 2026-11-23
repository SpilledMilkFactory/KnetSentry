// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include "section_catalog_model.hpp"

#include <array>
#include <string_view>

namespace knetsentry::desktop {
namespace {
struct Section {
    std::string_view id;
    std::string_view title;
};
constexpr std::array<Section, 7> kSections{{
    {"dashboard", "Dashboard"}, {"assets", "Assets"},
    {"events", "Events"}, {"detections", "Detections"},
    {"alerts", "Alerts"}, {"investigations", "Investigations"},
    {"settings", "Settings"},
}};

QString from_text(std::string_view text) {
    return QString::fromUtf8(text.data(), static_cast<qsizetype>(text.size()));
}
} // namespace

SectionCatalogModel::SectionCatalogModel(QObject* parent) : QAbstractListModel(parent) {}

int SectionCatalogModel::rowCount(const QModelIndex& parent) const {
    return parent.isValid() ? 0 : static_cast<int>(kSections.size());
}

QVariant SectionCatalogModel::data(const QModelIndex& index, int role) const {
    if (!index.isValid() || index.model() != this || index.parent().isValid() ||
        index.column() != 0 || index.row() < 0 ||
        index.row() >= static_cast<int>(kSections.size())) {
        return {};
    }
    const Section& section = kSections[static_cast<std::size_t>(index.row())];
    switch (role) {
    case SectionIdRole: return from_text(section.id);
    case SectionTitleRole:
    case Qt::DisplayRole: return from_text(section.title);
    default: return {};
    }
}

QHash<int, QByteArray> SectionCatalogModel::roleNames() const {
    return {{SectionIdRole, "sectionId"}, {SectionTitleRole, "sectionTitle"}};
}

Qt::ItemFlags SectionCatalogModel::flags(const QModelIndex& index) const {
    if (!index.isValid() || index.model() != this || index.parent().isValid() ||
        index.column() != 0 || index.row() < 0 ||
        index.row() >= static_cast<int>(kSections.size())) {
        return Qt::NoItemFlags;
    }
    return Qt::ItemIsEnabled | Qt::ItemIsSelectable;
}
} // namespace knetsentry::desktop
