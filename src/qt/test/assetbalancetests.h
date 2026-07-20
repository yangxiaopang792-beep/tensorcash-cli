// Copyright (c) 2024 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_TEST_ASSETBALANCETESTS_H
#define BITCOIN_QT_TEST_ASSETBALANCETESTS_H

#include <QObject>
#include <QTest>

class AssetBalanceTests : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void testChangeDetection();
    void testClickToCopyWithSorting();
    void testMetadataUpdateRefresh();
};

#endif // BITCOIN_QT_TEST_ASSETBALANCETESTS_H