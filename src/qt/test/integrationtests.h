// Copyright (c) 2024 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef TENSORCASH_QT_TEST_INTEGRATIONTESTS_H
#define TENSORCASH_QT_TEST_INTEGRATIONTESTS_H

#include <QObject>
#include <QTest>

#include <qt/clientmodel.h>
#include <qt/optionsmodel.h>
#include <qt/platformstyle.h>
#include <qt/receivecoinsdialog.h>
#include <qt/walletmodel.h>

#include <uint256.h>

#include <memory>

class ClientModel;
class OptionsModel;
class PlatformStyle;
class ReceiveCoinsDialog;
class WalletModel;

namespace interfaces {
class Node;
}

namespace qt_tests {
class MockWallet;
}

class IntegrationTests : public QObject
{
    Q_OBJECT

public:
    explicit IntegrationTests(interfaces::Node& node) : m_node(node) {}
    ~IntegrationTests();

private Q_SLOTS:
    void initTestCase();
    void cleanupTestCase();
    void testCompleteAssetFlow();
    void testAssetUriRoundTrip();

private:
    interfaces::Node& m_node;
    qt_tests::MockWallet* m_walletBackend{nullptr};
    std::unique_ptr<OptionsModel> m_optionsModel;
    std::unique_ptr<ClientModel> m_clientModel;
    std::unique_ptr<const PlatformStyle> m_platformStyle;
    std::unique_ptr<WalletModel> m_walletModel;
    std::unique_ptr<ReceiveCoinsDialog> m_receiveDialog;

    uint256 m_testAssetId{};
    QString m_testTicker;
};

#endif // TENSORCASH_QT_TEST_INTEGRATIONTESTS_H
