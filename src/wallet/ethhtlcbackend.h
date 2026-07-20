// Copyright (c) 2025 The TensorCash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_WALLET_ETHHTLCBACKEND_H
#define BITCOIN_WALLET_ETHHTLCBACKEND_H

#include <wallet/crosschainmanager.h>
#include <univalue.h>

#include <functional>
#include <string>

namespace wallet {

/// Type for injecting bridge command execution.
/// Bound to cosign::g_bridge_manager.SendBridgeCommand() at registration time.
using BridgeCommandFn = std::function<UniValue(const std::string& command, const UniValue& params)>;

/**
 * ETH HTLC backend that wraps cosign bridge commands.
 *
 * Implements HtlcBackend by calling eth_init, eth_lock_htlc,
 * eth_claim_htlc, eth_refund_htlc, and eth_get_swap_status
 * through the bridge process.
 */
class EthHtlcBackend : public HtlcBackend
{
public:
    explicit EthHtlcBackend(BridgeCommandFn bridge_fn);
    ~EthHtlcBackend() override = default;

    bool Init(const std::string& rpc_url) override;

    HtlcStatus GetSwapStatus(const std::string& htlc_address,
                              const std::string& swap_id,
                              const std::string& lock_tx_hash = "") override;

    HtlcTxResult LockHTLC(const std::string& htlc_address,
                           const std::string& swap_id,
                           const std::string& recipient,
                           const std::string& secret_hash,
                           int64_t timelock,
                           const std::string& amount_wei,
                           const std::string& signing_key,
                           const std::string& token_address = "",
                           int64_t gas_limit = 200000,
                           int64_t max_fee_gwei = 50,
                           int64_t max_priority_fee_gwei = 2) override;

    HtlcTxResult ClaimHTLC(const std::string& htlc_address,
                            const std::string& swap_id,
                            const std::string& secret,
                            const std::string& signing_key,
                            int64_t gas_limit = 100000,
                            int64_t max_fee_gwei = 50,
                            int64_t max_priority_fee_gwei = 2) override;

    HtlcTxResult RefundHTLC(const std::string& htlc_address,
                             const std::string& swap_id,
                             const std::string& signing_key,
                             int64_t gas_limit = 100000,
                             int64_t max_fee_gwei = 50,
                             int64_t max_priority_fee_gwei = 2) override;

    AttestationResult VerifyAttestation(
        const std::string& oracle_pubkey,
        const std::string& attestation_json) override;

    std::string ResolveSignerRef(const std::string& signer_ref) override;

    std::string GetChainName() const override { return "ethereum"; }

private:
    BridgeCommandFn m_bridge_fn;
    bool m_initialized{false};
};

} // namespace wallet

#endif // BITCOIN_WALLET_ETHHTLCBACKEND_H
