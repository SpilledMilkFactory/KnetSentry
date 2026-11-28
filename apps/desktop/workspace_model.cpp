// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include "workspace_model.hpp"
#include <QDir>
#include <QFile>
#include <QStandardPaths>

namespace knetsentry::desktop {
WorkspaceModel::WorkspaceModel(bool persistent, QObject* parent) : QObject(parent) {
    if (persistent) { root_ = QStandardPaths::writableLocation(QStandardPaths::GenericConfigLocation); }
    if (!root_.isEmpty() && QDir::isAbsolutePath(root_)) {
        const auto path = QFile::encodeName(root_);
        if (const auto saved = load_workspace(path.constData())) {
            value_ = *saved;
            status_ = tr("Saved layout restored.");
            return;
        }
    }
    status_ = tr("Safe default layout (no verified saved preferences).");
}
void WorkspaceModel::configure(int ratio, bool charts, bool health, bool telemetry) {
    const WorkspacePreferences next{ratio, (charts ? 1 : 0) | (health ? 2 : 0) | (telemetry ? 4 : 0)};
    if (!valid_workspace(next) || next == value_) { return; }
    value_ = next;
    status_ = tr("Unsaved layout changes.");
    Q_EMIT changed();
}
void WorkspaceModel::save() {
    const auto path = QFile::encodeName(root_);
    const bool ok = !root_.isEmpty() && QDir::isAbsolutePath(root_) && QDir().mkpath(root_) &&
        save_workspace(path.constData(), value_);
    status_ = ok ? tr("Layout saved.") : tr("Layout save not confirmed; current layout remains in memory.");
    Q_EMIT changed();
}
} // namespace knetsentry::desktop
