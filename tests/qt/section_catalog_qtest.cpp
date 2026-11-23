// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include "section_catalog_model.hpp"

#include <QAbstractItemModelTester>
#include <QSignalSpy>
#include <QTest>

#include <array>

namespace {
class SectionCatalogQTest final : public QObject {
    Q_OBJECT
private slots:
    void readOnlyRolesAndOrdering();
    void rejectsInvalidIndexesAndMutation();
    void modelInvariantsAndSignalSilence();
};

void SectionCatalogQTest::readOnlyRolesAndOrdering() {
    knetsentry::desktop::SectionCatalogModel model;
    static constexpr std::array<const char*, 7> kIds{
        "dashboard", "assets", "events", "detections", "alerts",
        "investigations", "settings"};
    static constexpr std::array<const char*, 7> kTitles{
        "Dashboard", "Assets", "Events", "Detections", "Alerts",
        "Investigations", "Settings"};
    QCOMPARE(model.rowCount(), 7);
    QCOMPARE(model.columnCount(), 1);
    const auto roles = model.roleNames();
    QCOMPARE(roles.value(knetsentry::desktop::SectionCatalogModel::SectionIdRole), QByteArray("sectionId"));
    QCOMPARE(roles.value(knetsentry::desktop::SectionCatalogModel::SectionTitleRole), QByteArray("sectionTitle"));
    for (int row = 0; row < model.rowCount(); ++row) {
        const QModelIndex index = model.index(row, 0);
        QVERIFY(index.isValid());
        QCOMPARE(model.data(index, knetsentry::desktop::SectionCatalogModel::SectionIdRole).toString(),
                 QString::fromLatin1(kIds[static_cast<std::size_t>(row)]));
        QCOMPARE(model.data(index, knetsentry::desktop::SectionCatalogModel::SectionTitleRole).toString(),
                 QString::fromLatin1(kTitles[static_cast<std::size_t>(row)]));
        QCOMPARE(model.data(index, Qt::DisplayRole).toString(),
                 QString::fromLatin1(kTitles[static_cast<std::size_t>(row)]));
    }
}

void SectionCatalogQTest::rejectsInvalidIndexesAndMutation() {
    knetsentry::desktop::SectionCatalogModel model;
    const QModelIndex bad = model.index(7, 0);
    QVERIFY(!bad.isValid());
    QVERIFY(!model.data(bad, knetsentry::desktop::SectionCatalogModel::SectionIdRole).isValid());
    QCOMPARE(model.flags(bad), Qt::NoItemFlags);
    QVERIFY(!model.data(model.index(0, 0), Qt::UserRole + 30).isValid());
    QVERIFY(!model.setData(model.index(0, 0), QStringLiteral("forged"),
                           knetsentry::desktop::SectionCatalogModel::SectionIdRole));
    QCOMPARE(model.rowCount(model.index(0, 0)), 0);
    QCOMPARE(model.data(model.index(0, 0), knetsentry::desktop::SectionCatalogModel::SectionIdRole)
                 .toString(), QStringLiteral("dashboard"));
}

void SectionCatalogQTest::modelInvariantsAndSignalSilence() {
    knetsentry::desktop::SectionCatalogModel model;
    QAbstractItemModelTester tester(&model, QAbstractItemModelTester::FailureReportingMode::QtTest);
    QSignalSpy changed(&model, &QAbstractItemModel::dataChanged);
    QVERIFY(changed.isValid());
    for (int row = 0; row < 7; ++row) {
        const QModelIndex index = model.index(row, 0);
        QCOMPARE(model.flags(index), Qt::ItemIsEnabled | Qt::ItemIsSelectable);
        QVERIFY(!model.setData(index, QStringLiteral("overwrite"), Qt::EditRole));
        QVERIFY(!model.data(index, Qt::DecorationRole).isValid());
    }
    QCOMPARE(changed.count(), 0);
}
} // namespace

QTEST_GUILESS_MAIN(SectionCatalogQTest)
#include "section_catalog_qtest.moc"
