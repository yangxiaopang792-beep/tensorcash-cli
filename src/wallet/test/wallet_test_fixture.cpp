// Copyright (c) 2016-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/context.h>
#include <wallet/test/util.h>
#include <wallet/test/wallet_test_fixture.h>

#include <scheduler.h>
#include <optional>
#include <util/chaintype.h>

namespace wallet {
WalletTestingSetup::WalletTestingSetup(const ChainType chainType)
    : TestingSetup(chainType),
      m_wallet_loader{interfaces::MakeWalletLoader(*m_node.chain, *Assert(m_node.args))},
      m_wallet(m_node.chain.get(), "", CreateMockableWalletDatabase())
{
    if (WalletContext* ctx = m_wallet_loader->context()) {
        ctx->node_context = &m_node;
    }
    m_wallet.LoadWallet();
    if (WalletContext* ctx = m_wallet_loader->context()) {
        m_wallet_ptr = std::shared_ptr<CWallet>(&m_wallet, [](CWallet*) {});
        wallet::AddWallet(*ctx, m_wallet_ptr);
    }
    m_chain_notifications_handler = m_node.chain->handleNotifications({ &m_wallet, [](CWallet*) {} });
    m_wallet_loader->registerRpcs();
}

WalletTestingSetup::~WalletTestingSetup()
{
    if (WalletContext* ctx = m_wallet_loader->context(); ctx && m_wallet_ptr) {
        wallet::RemoveWallet(*ctx, m_wallet_ptr, std::nullopt);
    }
    if (m_node.scheduler) m_node.scheduler->stop();
}
} // namespace wallet
