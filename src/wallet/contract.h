// Copyright (c) 2025 The TensorCash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef TENSORCASH_WALLET_CONTRACT_H
#define TENSORCASH_WALLET_CONTRACT_H

#include <addresstype.h>
#include <consensus/amount.h>
#include <key_io.h>
#include <primitives/transaction.h>
#include <serialize.h>
#include <uint256.h>

#include <cstdint>
#include <ios>
#include <optional>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

class UniValue;

namespace wallet {

class CWallet;

namespace detail {
template <typename Stream, typename = void>
struct stream_has_size : std::false_type {};

template <typename Stream>
struct stream_has_size<Stream, std::void_t<decltype(std::declval<Stream&>().size())>> : std::true_type {};
} // namespace detail

enum class CovenantContractKind : uint8_t {
    REPO = 0,
    FORWARD = 1,
    SPOT = 2,
    DIFFICULTY = 3, // nBits-settled bilateral CFD (see DIFFICULTY_DERIVATIVE.md)
};

enum class ForwardSide : uint8_t {
    LONG = 0,
    SHORT = 1,
};

struct AssetLeg {
    uint256 asset_id;
    bool is_native{false};
    uint64_t units{0};
    std::optional<int> decimals;  // Decimals used when encoding units (preserves precision from GUI)

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        ::Serialize(s, asset_id);
        ::Serialize(s, is_native);
        ::Serialize(s, units);

        // Serialize decimals (backward compatible)
        bool has_decimals = decimals.has_value();
        ::Serialize(s, has_decimals);
        if (has_decimals) {
            ::Serialize(s, *decimals);
        }
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        ::Unserialize(s, asset_id);
        ::Unserialize(s, is_native);
        ::Unserialize(s, units);

        // Unserialize decimals (backward compatible)
        try {
            bool has_decimals{false};
            ::Unserialize(s, has_decimals);
            if (has_decimals) {
                int decimals_tmp;
                ::Unserialize(s, decimals_tmp);
                decimals = decimals_tmp;
            } else {
                decimals.reset();
            }
        } catch (const std::ios_base::failure&) {
            decimals.reset();  // Old record
        }
    }
};

struct ForwardPartyTerms {
    AssetLeg deliver_leg;
    AssetLeg margin_leg;
    CTxDestination margin_dest;
    CTxDestination settlement_receive_dest;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        ::Serialize(s, deliver_leg);
        ::Serialize(s, margin_leg);
        ::Serialize(s, EncodeDestination(margin_dest));
        ::Serialize(s, EncodeDestination(settlement_receive_dest));
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        ::Unserialize(s, deliver_leg);
        ::Unserialize(s, margin_leg);

        std::string margin_encoded;
        std::string settlement_encoded;
        ::Unserialize(s, margin_encoded);
        ::Unserialize(s, settlement_encoded);

        margin_dest = DecodeDestination(margin_encoded);
        settlement_receive_dest = DecodeDestination(settlement_encoded);
        if (!IsValidDestination(margin_dest) || !IsValidDestination(settlement_receive_dest)) {
            throw std::ios_base::failure("Invalid forward contract destination");
        }
    }
};

struct ForwardTerms {
    ForwardPartyTerms long_party;
    ForwardPartyTerms short_party;
    uint32_t deadline_short{0};        // T: Bob must act by this height (replaces maturity_height)
    uint32_t deadline_long{0};         // T+K: Alice must act by this height
    AssetLeg premium_leg;              // Premium asset/amount (P0, may have units=0)
    CTxDestination premium_dest;       // Where premium is paid (only used if premium_leg.units > 0)
    uint32_t safety_k{0};
    uint32_t reorg_conf{0};

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        ::Serialize(s, long_party);
        ::Serialize(s, short_party);
        ::Serialize(s, deadline_short);
        ::Serialize(s, deadline_long);
        ::Serialize(s, premium_leg);
        ::Serialize(s, EncodeDestination(premium_dest));
        ::Serialize(s, safety_k);
        ::Serialize(s, reorg_conf);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        ::Unserialize(s, long_party);
        ::Unserialize(s, short_party);
        ::Unserialize(s, deadline_short);
        ::Unserialize(s, deadline_long);
        ::Unserialize(s, premium_leg);

        std::string premium_encoded;
        ::Unserialize(s, premium_encoded);
        premium_dest = DecodeDestination(premium_encoded);
        if (premium_leg.units > 0 && !IsValidDestination(premium_dest)) {
            throw std::ios_base::failure("Invalid forward premium destination");
        }

        ::Unserialize(s, safety_k);
        ::Unserialize(s, reorg_conf);
    }
};

struct FairSignPolicy {
    bool require_adaptor{true};
    bool reveal_lockstep{false};

    SERIALIZE_METHODS(FairSignPolicy, obj)
    {
        READWRITE(obj.require_adaptor, obj.reveal_lockstep);
    }
};

enum class ForwardContractState : uint8_t {
    PROPOSED = 0,
    ACCEPTED = 1,
    OPENED = 2,
    DELIVERED = 3,
    SETTLED = 4,
    EXPIRED = 5,
    CLOSED = 6,
};

inline std::string ForwardContractStateToString(ForwardContractState state)
{
    switch (state) {
    case ForwardContractState::PROPOSED:
        return "proposed";
    case ForwardContractState::ACCEPTED:
        return "accepted";
    case ForwardContractState::OPENED:
        return "opened";
    case ForwardContractState::DELIVERED:
        return "delivered";
    case ForwardContractState::SETTLED:
        return "settled";
    case ForwardContractState::EXPIRED:
        return "expired";
    case ForwardContractState::CLOSED:
        return "closed";
    }
    return "unknown";
}

struct ForwardContractRecord {
    uint256 contract_id;
    ForwardTerms terms;
    ForwardSide local_side{ForwardSide::LONG};
    FairSignPolicy fs_policy;
    XOnlyPubKey fs_tx_adaptor_point;
    std::optional<uint256> local_fs_tx_adaptor_secret; // Present when this wallet created the offer
    std::optional<XOnlyPubKey> counterparty_adaptor_point; // Counter-adaptor from acceptance
    std::optional<uint256> counterparty_adaptor_secret; // If we accepted
    int created_height{0};
    int64_t created_time{0};
    uint256 salt;
    std::string commitment_hex;
    std::optional<std::string> acceptance_commitment_hex;
    std::optional<uint256> acceptance_salt;
    std::optional<COutPoint> long_margin_vault;
    std::optional<COutPoint> short_margin_vault;
    CAmount long_margin_value{0};
    CAmount short_margin_value{0};
    std::optional<XOnlyPubKey> long_margin_internal_key;
    std::optional<XOnlyPubKey> short_margin_internal_key;
    std::optional<CScript> long_margin_script;
    std::optional<CScript> short_margin_script;

    // Lifecycle state tracking
    std::optional<uint256> open_txid;
    std::optional<uint256> self_delivery_txid;
    std::optional<uint256> coop_close_txid;
    std::optional<uint256> escrow_claim_txid;
    std::optional<uint256> escrow_refund_txid;
    std::optional<uint256> timeout_txid;
    std::optional<int> open_height;
    std::optional<int> settlement_height;
    std::optional<int64_t> open_time;
    std::optional<int64_t> settlement_time;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        ::Serialize(s, contract_id);
        ::Serialize(s, terms);
        ::Serialize(s, static_cast<uint8_t>(local_side));
        ::Serialize(s, fs_policy);
        ::Serialize(s, fs_tx_adaptor_point);

        const bool has_local_secret = local_fs_tx_adaptor_secret.has_value();
        ::Serialize(s, has_local_secret);
        if (has_local_secret) {
            ::Serialize(s, *local_fs_tx_adaptor_secret);
        }

        const bool has_counterparty_point = counterparty_adaptor_point.has_value();
        ::Serialize(s, has_counterparty_point);
        if (has_counterparty_point) {
            ::Serialize(s, *counterparty_adaptor_point);
        }

        const bool has_counterparty_secret = counterparty_adaptor_secret.has_value();
        ::Serialize(s, has_counterparty_secret);
        if (has_counterparty_secret) {
            ::Serialize(s, *counterparty_adaptor_secret);
        }

        ::Serialize(s, created_height);
        ::Serialize(s, created_time);
        ::Serialize(s, salt);
        ::Serialize(s, commitment_hex);

        const bool has_acceptance = acceptance_commitment_hex.has_value();
        ::Serialize(s, has_acceptance);
        if (has_acceptance) {
            ::Serialize(s, *acceptance_commitment_hex);
        }

        const bool has_acceptance_salt = acceptance_salt.has_value();
        ::Serialize(s, has_acceptance_salt);
        if (has_acceptance_salt) {
            ::Serialize(s, *acceptance_salt);
        }

        const bool has_long_vault = long_margin_vault.has_value();
        ::Serialize(s, has_long_vault);
        if (has_long_vault) {
            ::Serialize(s, long_margin_vault->hash);
            ::Serialize(s, long_margin_vault->n);
        }

        const bool has_short_vault = short_margin_vault.has_value();
        ::Serialize(s, has_short_vault);
        if (has_short_vault) {
            ::Serialize(s, short_margin_vault->hash);
            ::Serialize(s, short_margin_vault->n);
        }

        ::Serialize(s, long_margin_value);
        ::Serialize(s, short_margin_value);

        const bool has_long_internal = long_margin_internal_key.has_value();
        ::Serialize(s, has_long_internal);
        if (has_long_internal) {
            ::Serialize(s, *long_margin_internal_key);
        }

        const bool has_short_internal = short_margin_internal_key.has_value();
        ::Serialize(s, has_short_internal);
        if (has_short_internal) {
            ::Serialize(s, *short_margin_internal_key);
        }

        const bool has_long_script = long_margin_script.has_value();
        ::Serialize(s, has_long_script);
        if (has_long_script) {
            ::Serialize(s, *long_margin_script);
        }

        const bool has_short_script = short_margin_script.has_value();
        ::Serialize(s, has_short_script);
        if (has_short_script) {
            ::Serialize(s, *short_margin_script);
        }

        // Lifecycle state tracking
        const bool has_open_txid = open_txid.has_value();
        ::Serialize(s, has_open_txid);
        if (has_open_txid) {
            ::Serialize(s, *open_txid);
        }

        const bool has_self_delivery_txid = self_delivery_txid.has_value();
        ::Serialize(s, has_self_delivery_txid);
        if (has_self_delivery_txid) {
            ::Serialize(s, *self_delivery_txid);
        }

        const bool has_coop_close_txid = coop_close_txid.has_value();
        ::Serialize(s, has_coop_close_txid);
        if (has_coop_close_txid) {
            ::Serialize(s, *coop_close_txid);
        }

        const bool has_escrow_claim_txid = escrow_claim_txid.has_value();
        ::Serialize(s, has_escrow_claim_txid);
        if (has_escrow_claim_txid) {
            ::Serialize(s, *escrow_claim_txid);
        }

        const bool has_escrow_refund_txid = escrow_refund_txid.has_value();
        ::Serialize(s, has_escrow_refund_txid);
        if (has_escrow_refund_txid) {
            ::Serialize(s, *escrow_refund_txid);
        }

        const bool has_timeout_txid = timeout_txid.has_value();
        ::Serialize(s, has_timeout_txid);
        if (has_timeout_txid) {
            ::Serialize(s, *timeout_txid);
        }

        const bool has_open_height = open_height.has_value();
        ::Serialize(s, has_open_height);
        if (has_open_height) {
            ::Serialize(s, *open_height);
        }

        const bool has_settlement_height = settlement_height.has_value();
        ::Serialize(s, has_settlement_height);
        if (has_settlement_height) {
            ::Serialize(s, *settlement_height);
        }

        const bool has_open_time = open_time.has_value();
        ::Serialize(s, has_open_time);
        if (has_open_time) {
            ::Serialize(s, *open_time);
        }

        const bool has_settlement_time = settlement_time.has_value();
        ::Serialize(s, has_settlement_time);
        if (has_settlement_time) {
            ::Serialize(s, *settlement_time);
        }
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        ::Unserialize(s, contract_id);
        ::Unserialize(s, terms);

        uint8_t side_byte;
        ::Unserialize(s, side_byte);
        local_side = static_cast<ForwardSide>(side_byte);

        ::Unserialize(s, fs_policy);
        ::Unserialize(s, fs_tx_adaptor_point);

        bool has_local_secret{false};
        ::Unserialize(s, has_local_secret);
        if (has_local_secret) {
            uint256 secret;
            ::Unserialize(s, secret);
            local_fs_tx_adaptor_secret = secret;
        } else {
            local_fs_tx_adaptor_secret.reset();
        }

        bool has_counterparty_point{false};
        ::Unserialize(s, has_counterparty_point);
        if (has_counterparty_point) {
            XOnlyPubKey point;
            ::Unserialize(s, point);
            counterparty_adaptor_point = point;
        } else {
            counterparty_adaptor_point.reset();
        }

        bool has_counterparty_secret{false};
        ::Unserialize(s, has_counterparty_secret);
        if (has_counterparty_secret) {
            uint256 secret;
            ::Unserialize(s, secret);
            counterparty_adaptor_secret = secret;
        } else {
            counterparty_adaptor_secret.reset();
        }

        ::Unserialize(s, created_height);
        ::Unserialize(s, created_time);
        ::Unserialize(s, salt);
        ::Unserialize(s, commitment_hex);

        bool has_acceptance{false};
        ::Unserialize(s, has_acceptance);
        if (has_acceptance) {
            std::string acceptance;
            ::Unserialize(s, acceptance);
            acceptance_commitment_hex = acceptance;
        } else {
            acceptance_commitment_hex.reset();
        }

        bool has_acceptance_salt{false};
        ::Unserialize(s, has_acceptance_salt);
        if (has_acceptance_salt) {
            uint256 tmp;
            ::Unserialize(s, tmp);
            acceptance_salt = tmp;
        } else {
            acceptance_salt.reset();
        }

        bool has_long_vault{false};
        ::Unserialize(s, has_long_vault);
        if (has_long_vault) {
            Txid txid;
            ::Unserialize(s, txid);
            uint32_t n;
            ::Unserialize(s, n);
            long_margin_vault = COutPoint(txid, n);
        } else {
            long_margin_vault.reset();
        }

        bool has_short_vault{false};
        ::Unserialize(s, has_short_vault);
        if (has_short_vault) {
            Txid txid;
            ::Unserialize(s, txid);
            uint32_t n;
            ::Unserialize(s, n);
            short_margin_vault = COutPoint(txid, n);
        } else {
            short_margin_vault.reset();
        }

        ::Unserialize(s, long_margin_value);
        ::Unserialize(s, short_margin_value);

        bool has_long_internal{false};
        ::Unserialize(s, has_long_internal);
        if (has_long_internal) {
            XOnlyPubKey key;
            ::Unserialize(s, key);
            long_margin_internal_key = key;
        } else {
            long_margin_internal_key.reset();
        }

        bool has_short_internal{false};
        ::Unserialize(s, has_short_internal);
        if (has_short_internal) {
            XOnlyPubKey key;
            ::Unserialize(s, key);
            short_margin_internal_key = key;
        } else {
            short_margin_internal_key.reset();
        }

        bool has_long_script{false};
        ::Unserialize(s, has_long_script);
        if (has_long_script) {
            CScript script;
            ::Unserialize(s, script);
            long_margin_script = script;
        } else {
            long_margin_script.reset();
        }

        bool has_short_script{false};
        ::Unserialize(s, has_short_script);
        if (has_short_script) {
            CScript script;
            ::Unserialize(s, script);
            short_margin_script = script;
        } else {
            short_margin_script.reset();
        }

        // Lifecycle state tracking - backward compatibility
        constexpr bool stream_has_size = detail::stream_has_size<Stream>::value;
        const auto can_read = [&](size_t bytes) -> bool {
            if constexpr (stream_has_size) {
                return s.size() >= bytes;
            } else {
                (void)bytes;
                return true;
            }
        };

        const auto read_optional_uint256 = [&](std::optional<uint256>& target) -> bool {
            if (!can_read(1)) {
                target.reset();
                return false;
            }
            bool has_field{false};
            ::Unserialize(s, has_field);
            if (has_field) {
                if (!can_read(sizeof(uint256))) {
                    throw std::ios_base::failure("ForwardContractRecord: truncated lifecycle txid");
                }
                uint256 tmp;
                ::Unserialize(s, tmp);
                target = tmp;
            } else {
                target.reset();
            }
            return true;
        };

        const auto read_optional_int = [&](std::optional<int>& target) -> bool {
            if (!can_read(1)) {
                target.reset();
                return false;
            }
            bool has_field{false};
            ::Unserialize(s, has_field);
            if (has_field) {
                if (!can_read(sizeof(int))) {
                    throw std::ios_base::failure("ForwardContractRecord: truncated lifecycle height");
                }
                int tmp;
                ::Unserialize(s, tmp);
                target = tmp;
            } else {
                target.reset();
            }
            return true;
        };

        const auto read_optional_int64 = [&](std::optional<int64_t>& target) -> bool {
            if (!can_read(1)) {
                target.reset();
                return false;
            }
            bool has_field{false};
            ::Unserialize(s, has_field);
            if (has_field) {
                if (!can_read(sizeof(int64_t))) {
                    throw std::ios_base::failure("ForwardContractRecord: truncated lifecycle time");
                }
                int64_t tmp;
                ::Unserialize(s, tmp);
                target = tmp;
            } else {
                target.reset();
            }
            return true;
        };

        if (!read_optional_uint256(open_txid)) {
            self_delivery_txid.reset();
            coop_close_txid.reset();
            escrow_claim_txid.reset();
            escrow_refund_txid.reset();
            timeout_txid.reset();
            open_height.reset();
            settlement_height.reset();
            open_time.reset();
            settlement_time.reset();
            return;
        }
        if (!read_optional_uint256(self_delivery_txid)) {
            coop_close_txid.reset();
            escrow_claim_txid.reset();
            escrow_refund_txid.reset();
            timeout_txid.reset();
            open_height.reset();
            settlement_height.reset();
            open_time.reset();
            settlement_time.reset();
            return;
        }
        if (!read_optional_uint256(coop_close_txid)) {
            escrow_claim_txid.reset();
            escrow_refund_txid.reset();
            timeout_txid.reset();
            open_height.reset();
            settlement_height.reset();
            open_time.reset();
            settlement_time.reset();
            return;
        }
        if (!read_optional_uint256(escrow_claim_txid)) {
            escrow_refund_txid.reset();
            timeout_txid.reset();
            open_height.reset();
            settlement_height.reset();
            open_time.reset();
            settlement_time.reset();
            return;
        }
        if (!read_optional_uint256(escrow_refund_txid)) {
            timeout_txid.reset();
            open_height.reset();
            settlement_height.reset();
            open_time.reset();
            settlement_time.reset();
            return;
        }
        if (!read_optional_uint256(timeout_txid)) {
            open_height.reset();
            settlement_height.reset();
            open_time.reset();
            settlement_time.reset();
            return;
        }
        if (!read_optional_int(open_height)) {
            settlement_height.reset();
            open_time.reset();
            settlement_time.reset();
            return;
        }
        if (!read_optional_int(settlement_height)) {
            open_time.reset();
            settlement_time.reset();
            return;
        }
        if (!read_optional_int64(open_time)) {
            settlement_time.reset();
            return;
        }
        read_optional_int64(settlement_time);
    }

    ForwardContractState DerivedState() const
    {
        // Terminal states first (highest precedence)
        if (timeout_txid.has_value()) {
            return ForwardContractState::EXPIRED;
        }
        if (coop_close_txid.has_value()) {
            return ForwardContractState::CLOSED;
        }
        if (escrow_claim_txid.has_value() || escrow_refund_txid.has_value()) {
            return ForwardContractState::SETTLED;
        }

        // Active states
        if (self_delivery_txid.has_value()) {
            return ForwardContractState::DELIVERED;
        }
        // CRITICAL: Require open_height (confirmation) to prevent premature "opened" state
        // during ceremony/pre-broadcast. Vault presence alone is not sufficient.
        if ((open_txid.has_value() && open_height.has_value()) ||
            (long_margin_vault.has_value() && short_margin_vault.has_value() && open_height.has_value())) {
            return ForwardContractState::OPENED;
        }

        // Pre-open states
        if (acceptance_commitment_hex.has_value()) {
            return ForwardContractState::ACCEPTED;
        }
        return ForwardContractState::PROPOSED;
    }
};

enum class SpotSide : uint8_t {
    ALICE = 0,
    BOB = 1,
};

enum class RepoContractState : uint8_t {
    PROPOSED = 0,
    ACCEPTED = 1,
    OPENED = 2,
    REPAID = 3,
    DEFAULTED = 4,
    CLOSED = 5,
};

inline std::string RepoContractStateToString(RepoContractState state)
{
    switch (state) {
    case RepoContractState::PROPOSED:
        return "proposed";
    case RepoContractState::ACCEPTED:
        return "accepted";
    case RepoContractState::OPENED:
        return "opened";
    case RepoContractState::REPAID:
        return "repaid";
    case RepoContractState::DEFAULTED:
        return "defaulted";
    case RepoContractState::CLOSED:
        return "closed";
    }
    return "unknown";
}

// Default BTC amount attached to non-native repo asset outputs (aligns with sendasset anchor/dust of 1k sats)
inline constexpr CAmount DEFAULT_REPO_ASSET_OUTPUT_VALUE{1'000}; // 0.00001 BTC

struct RepoTerms {
    AssetLeg principal_leg;        // Principal asset/amount delivered at open
    AssetLeg interest_leg;         // Interest asset/amount owed at repay
    AssetLeg collateral_leg;       // Collateral asset/amount locked in vault
    uint32_t maturity_height{0};   // Block height when default branch unlocks
    uint32_t safety_k{0};          // Safety window before maturity for UX warnings
    uint32_t reorg_conf{0};        // Required confirmations to treat maturity as stable

    SERIALIZE_METHODS(RepoTerms, obj)
    {
        READWRITE(obj.principal_leg,
                  obj.interest_leg,
                  obj.collateral_leg,
                  obj.maturity_height,
                  obj.safety_k,
                  obj.reorg_conf);
    }
};

struct AssetDeliveryTemplate {
    bool is_native{false};
    uint256 asset_id;
    uint64_t units{0};
    CScript script_pubkey;
    std::vector<unsigned char> vext;
    uint256 commitment;

    AssetDeliveryTemplate()
    {
        asset_id.SetNull();
    }

    SERIALIZE_METHODS(AssetDeliveryTemplate, obj)
    {
        READWRITE(obj.is_native);
        READWRITE(obj.asset_id);
        READWRITE(obj.units);
        READWRITE(obj.script_pubkey);
        READWRITE(obj.vext);
        READWRITE(obj.commitment);
    }

    bool IsValid() const
    {
        if (is_native) {
            return !script_pubkey.empty() && vext.empty() && units > 0;
        }
        return !asset_id.IsNull() && !script_pubkey.empty() && !vext.empty() && units > 0;
    }
};

struct RepoAcceptanceRecord {
    uint256 acceptance_id;
    FairSignPolicy fs_policy;
    XOnlyPubKey fs_tx_adaptor_point;
    uint256 salt;
    std::string commitment_hex;
    CTxDestination repay_dest_ack;   // Repayment sink confirmed/updated by acceptance
    std::optional<uint256> local_fs_tx_adaptor_secret; // Present when this wallet generated the acceptance
    std::optional<AssetDeliveryTemplate> repay_principal_template;
    std::optional<AssetDeliveryTemplate> repay_interest_template;
    std::optional<AssetDeliveryTemplate> default_collateral_template;

    SERIALIZE_METHODS(RepoAcceptanceRecord, obj)
    {
        READWRITE(obj.acceptance_id,
                  obj.fs_policy,
                  obj.fs_tx_adaptor_point,
                  obj.salt,
                  obj.commitment_hex);

        if (ser_action.ForRead()) {
            std::string repay_tmp;
            READWRITE(repay_tmp);
            const_cast<CTxDestination&>(obj.repay_dest_ack) = DecodeDestination(repay_tmp);
            if (!IsValidDestination(obj.repay_dest_ack)) {
                throw std::ios_base::failure("Invalid acceptance repayment destination");
            }
        } else {
            std::string repay_encoded = EncodeDestination(obj.repay_dest_ack);
            READWRITE(repay_encoded);
        }

        bool has_secret = obj.local_fs_tx_adaptor_secret.has_value();
        READWRITE(has_secret);
        if (has_secret) {
            if (ser_action.ForRead()) {
                uint256 secret_tmp;
                READWRITE(secret_tmp);
                const_cast<std::optional<uint256>&>(obj.local_fs_tx_adaptor_secret) = secret_tmp;
            } else {
                READWRITE(*obj.local_fs_tx_adaptor_secret);
            }
        } else if (ser_action.ForRead()) {
            const_cast<std::optional<uint256>&>(obj.local_fs_tx_adaptor_secret).reset();
        }

        bool has_principal_template = obj.repay_principal_template.has_value();
        READWRITE(has_principal_template);
        if (has_principal_template) {
            if (ser_action.ForRead()) {
                AssetDeliveryTemplate tmpl;
                READWRITE(tmpl);
                const_cast<std::optional<AssetDeliveryTemplate>&>(obj.repay_principal_template) = std::move(tmpl);
            } else {
                READWRITE(*obj.repay_principal_template);
            }
        } else if (ser_action.ForRead()) {
            const_cast<std::optional<AssetDeliveryTemplate>&>(obj.repay_principal_template).reset();
        }

        bool has_interest_template = obj.repay_interest_template.has_value();
        READWRITE(has_interest_template);
        if (has_interest_template) {
            if (ser_action.ForRead()) {
                AssetDeliveryTemplate tmpl;
                READWRITE(tmpl);
                const_cast<std::optional<AssetDeliveryTemplate>&>(obj.repay_interest_template) = std::move(tmpl);
            } else {
                READWRITE(*obj.repay_interest_template);
            }
        } else if (ser_action.ForRead()) {
            const_cast<std::optional<AssetDeliveryTemplate>&>(obj.repay_interest_template).reset();
        }

        bool has_default_template = obj.default_collateral_template.has_value();
        READWRITE(has_default_template);
        if (has_default_template) {
            if (ser_action.ForRead()) {
                AssetDeliveryTemplate tmpl;
                READWRITE(tmpl);
                const_cast<std::optional<AssetDeliveryTemplate>&>(obj.default_collateral_template) = std::move(tmpl);
            } else {
                READWRITE(*obj.default_collateral_template);
            }
        } else if (ser_action.ForRead()) {
            const_cast<std::optional<AssetDeliveryTemplate>&>(obj.default_collateral_template).reset();
        }
    }
};

struct RepoOfferRecord {
    uint256 offer_id;
    RepoTerms terms;
    CTxDestination borrower_dest;  // Where borrower receives collateral release
    CTxDestination lender_dest;    // Initial repayment sink (Taproot)
    std::optional<CTxDestination> lender_dest_override; // Optional novated repayment address (after acceptance)
    FairSignPolicy fs_policy;
    XOnlyPubKey fs_tx_adaptor_point;
    std::optional<uint256> local_fs_tx_adaptor_secret; // Present when this wallet created the offer
    int created_height{0};
    int64_t created_time{0};
    uint256 salt;
    std::string commitment_hex;    // Deterministic summary for counterparty validation
    std::optional<RepoAcceptanceRecord> acceptance;
    std::optional<COutPoint> vault_outpoint;
    CAmount vault_amount{0};
    std::optional<CScript> vault_covenant_script;
    std::optional<XOnlyPubKey> borrower_internal_key;  // Internal key for vault construction (needed for tr(KEY, TREE) descriptors)
    std::optional<XOnlyPubKey> lender_internal_key;    // Internal key for lender's repayment address (untweaked)
    std::string maker_role;  // Role of the offer creator: "borrower" or "lender"
    std::string fee_policy_strategy;  // Fee policy preference: "low", "medium", or "high"
    std::string maker_base_psbt;  // Maker's committed base PSBT (unsigned, no witnesses) for immutability
    std::optional<uint256> repay_txid;
    std::optional<uint256> default_txid;
    std::optional<int> repay_height;
    std::optional<int> default_height;
    std::optional<int64_t> repay_time;
    std::optional<int64_t> default_time;

    RepoContractState DerivedState(const CWallet* wallet = nullptr) const;

    CTxDestination RepayDestination() const
    {
        return lender_dest_override ? *lender_dest_override : lender_dest;
    }

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        ::Serialize(s, offer_id);
        ::Serialize(s, terms);

        const std::string borrower = EncodeDestination(borrower_dest);
        const std::string lender = EncodeDestination(lender_dest);
        ::Serialize(s, borrower);
        ::Serialize(s, lender);

        const bool has_override = lender_dest_override.has_value();
        ::Serialize(s, has_override);
        if (has_override) {
            const std::string override_encoded = EncodeDestination(*lender_dest_override);
            ::Serialize(s, override_encoded);
        }

        ::Serialize(s, fs_policy);
        ::Serialize(s, fs_tx_adaptor_point);

        const bool has_local_secret = local_fs_tx_adaptor_secret.has_value();
        ::Serialize(s, has_local_secret);
        if (has_local_secret) {
            ::Serialize(s, *local_fs_tx_adaptor_secret);
        }

        ::Serialize(s, created_height);
        ::Serialize(s, created_time);
        ::Serialize(s, salt);
        ::Serialize(s, commitment_hex);

        const bool has_acceptance = acceptance.has_value();
        ::Serialize(s, has_acceptance);
        if (has_acceptance) {
            ::Serialize(s, *acceptance);
        }

        const bool has_vault = vault_outpoint.has_value();
        ::Serialize(s, has_vault);
        if (has_vault) {
            ::Serialize(s, vault_outpoint->hash);
            ::Serialize(s, vault_outpoint->n);
        }

        ::Serialize(s, vault_amount);

        const bool has_covenant_script = vault_covenant_script.has_value();
        ::Serialize(s, has_covenant_script);
        if (has_covenant_script) {
            ::Serialize(s, *vault_covenant_script);
        }

        const bool has_borrower_internal = borrower_internal_key.has_value();
        ::Serialize(s, has_borrower_internal);
        if (has_borrower_internal) {
            ::Serialize(s, *borrower_internal_key);
        }

        const bool has_lender_internal = lender_internal_key.has_value();
        ::Serialize(s, has_lender_internal);
        if (has_lender_internal) {
            ::Serialize(s, *lender_internal_key);
        }

        const bool has_repay_txid = repay_txid.has_value();
        ::Serialize(s, has_repay_txid);
        if (has_repay_txid) {
            ::Serialize(s, *repay_txid);
        }

        const bool has_default_txid = default_txid.has_value();
        ::Serialize(s, has_default_txid);
        if (has_default_txid) {
            ::Serialize(s, *default_txid);
        }

        const bool has_repay_height = repay_height.has_value();
        ::Serialize(s, has_repay_height);
        if (has_repay_height) {
            ::Serialize(s, *repay_height);
        }

        const bool has_default_height = default_height.has_value();
        ::Serialize(s, has_default_height);
        if (has_default_height) {
            ::Serialize(s, *default_height);
        }

        const bool has_repay_time = repay_time.has_value();
        ::Serialize(s, has_repay_time);
        if (has_repay_time) {
            ::Serialize(s, *repay_time);
        }

        const bool has_default_time = default_time.has_value();
        ::Serialize(s, has_default_time);
        if (has_default_time) {
            ::Serialize(s, *default_time);
        }

        // Fee policy strategy (backwards compatible)
        ::Serialize(s, fee_policy_strategy);

        // Maker role marker (backwards compatible append).
        // Without this, on wallet restart the `i_am_maker ? "lender" : "borrower"`
        // fallback in contract.list flips a borrower-maker to "lender".
        ::Serialize(s, maker_role);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        ::Unserialize(s, offer_id);
        ::Unserialize(s, terms);

        std::string borrower_str;
        std::string lender_str;
        ::Unserialize(s, borrower_str);
        ::Unserialize(s, lender_str);

        borrower_dest = DecodeDestination(borrower_str);
        if (!IsValidDestination(borrower_dest)) {
            throw std::ios_base::failure("Invalid borrower destination");
        }

        lender_dest = DecodeDestination(lender_str);
        if (!IsValidDestination(lender_dest)) {
            throw std::ios_base::failure("Invalid lender destination");
        }

        bool has_override{false};
        ::Unserialize(s, has_override);
        if (has_override) {
            std::string override_str;
            ::Unserialize(s, override_str);
            CTxDestination override_dest = DecodeDestination(override_str);
            if (!IsValidDestination(override_dest)) {
                throw std::ios_base::failure("Invalid lender override destination");
            }
            lender_dest_override = override_dest;
        } else {
            lender_dest_override.reset();
        }

        ::Unserialize(s, fs_policy);
        ::Unserialize(s, fs_tx_adaptor_point);

        bool has_local_secret{false};
        ::Unserialize(s, has_local_secret);
        if (has_local_secret) {
            uint256 secret;
            ::Unserialize(s, secret);
            local_fs_tx_adaptor_secret = secret;
        } else {
            local_fs_tx_adaptor_secret.reset();
        }

        ::Unserialize(s, created_height);
        ::Unserialize(s, created_time);
        ::Unserialize(s, salt);
        ::Unserialize(s, commitment_hex);

        bool has_acceptance{false};
        ::Unserialize(s, has_acceptance);
        if (has_acceptance) {
            RepoAcceptanceRecord acc;
            ::Unserialize(s, acc);
            acceptance = acc;
        } else {
            acceptance.reset();
        }

        bool has_vault{false};
        ::Unserialize(s, has_vault);
        if (has_vault) {
            Txid txid;
            ::Unserialize(s, txid);
            uint32_t n;
            ::Unserialize(s, n);
            vault_outpoint = COutPoint(txid, n);
        } else {
            vault_outpoint.reset();
        }

        ::Unserialize(s, vault_amount);

        // covenant script is optional for legacy entries
        constexpr bool stream_has_size = detail::stream_has_size<Stream>::value;
        const auto can_read = [&](size_t bytes) -> bool {
            if constexpr (stream_has_size) {
                return s.size() >= bytes;
            } else {
                (void)bytes;
                return true;
            }
        };

        if (can_read(1)) {
            bool has_covenant_script{false};
            ::Unserialize(s, has_covenant_script);
            if (has_covenant_script) {
                CScript script;
                ::Unserialize(s, script);
                vault_covenant_script = script;
            } else {
                vault_covenant_script.reset();
            }
        } else {
            vault_covenant_script.reset();
        }

        bool has_borrower_internal{false};
        ::Unserialize(s, has_borrower_internal);
        if (has_borrower_internal) {
            XOnlyPubKey key;
            ::Unserialize(s, key);
            borrower_internal_key = key;
        } else {
            borrower_internal_key.reset();
        }

        // Backwards-compatible: lender_internal_key may not exist in old records
        const auto can_read_prelim = [&](size_t bytes) -> bool {
            if constexpr (stream_has_size) {
                return s.size() >= bytes;
            } else {
                (void)bytes;
                return true;
            }
        };

        if (can_read_prelim(1)) {
            bool has_lender_internal{false};
            ::Unserialize(s, has_lender_internal);
            if (has_lender_internal) {
                if (!can_read_prelim(sizeof(XOnlyPubKey))) {
                    throw std::ios_base::failure("RepoOfferRecord: truncated lender_internal_key");
                }
                XOnlyPubKey key;
                ::Unserialize(s, key);
                lender_internal_key = key;
            } else {
                lender_internal_key.reset();
            }
        } else {
            lender_internal_key.reset();
        }
        const auto read_optional_uint256 = [&](std::optional<uint256>& target) -> bool {
            if (!can_read(1)) {
                target.reset();
                return false;
            }
            bool has_field{false};
            ::Unserialize(s, has_field);
            if (has_field) {
                if (!can_read(sizeof(uint256))) {
                    throw std::ios_base::failure("RepoOfferRecord: truncated repay/default txid");
                }
                uint256 tmp;
                ::Unserialize(s, tmp);
                target = tmp;
            } else {
                target.reset();
            }
            return true;
        };

        const auto read_optional_int = [&](std::optional<int>& target) -> bool {
            if (!can_read(1)) {
                target.reset();
                return false;
            }
            bool has_field{false};
            ::Unserialize(s, has_field);
            if (has_field) {
                if (!can_read(sizeof(int))) {
                    throw std::ios_base::failure("RepoOfferRecord: truncated lifecycle height");
                }
                int tmp;
                ::Unserialize(s, tmp);
                target = tmp;
            } else {
                target.reset();
            }
            return true;
        };

        const auto read_optional_int64 = [&](std::optional<int64_t>& target) -> bool {
            if (!can_read(1)) {
                target.reset();
                return false;
            }
            bool has_field{false};
            ::Unserialize(s, has_field);
            if (has_field) {
                if (!can_read(sizeof(int64_t))) {
                    throw std::ios_base::failure("RepoOfferRecord: truncated lifecycle time");
                }
                int64_t tmp;
                ::Unserialize(s, tmp);
                target = tmp;
            } else {
                target.reset();
            }
            return true;
        };

        if (!read_optional_uint256(repay_txid)) {
            default_txid.reset();
            repay_height.reset();
            default_height.reset();
            repay_time.reset();
            default_time.reset();
            fee_policy_strategy.clear();
            return;
        }
        if (!read_optional_uint256(default_txid)) {
            repay_height.reset();
            default_height.reset();
            repay_time.reset();
            default_time.reset();
            fee_policy_strategy.clear();
            return;
        }
        if (!read_optional_int(repay_height)) {
            default_height.reset();
            repay_time.reset();
            default_time.reset();
            fee_policy_strategy.clear();
            return;
        }
        if (!read_optional_int(default_height)) {
            repay_time.reset();
            default_time.reset();
            fee_policy_strategy.clear();
            return;
        }
        if (!read_optional_int64(repay_time)) {
            default_time.reset();
            fee_policy_strategy.clear();
            return;
        }
        if (!read_optional_int64(default_time)) {
            fee_policy_strategy.clear();
            return;
        }

        // Fee policy strategy (backwards compatible)
        if (can_read(1)) {
            ::Unserialize(s, fee_policy_strategy);
        } else {
            fee_policy_strategy.clear();
        }

        // Maker role (backwards compatible: legacy records lack this and will
        // fall through to the address-ownership fallback in contract.list).
        if (can_read(1)) {
            ::Unserialize(s, maker_role);
        } else {
            maker_role.clear();
        }
    }
};

std::pair<uint256, XOnlyPubKey> GenerateFairSignAdaptor();

struct SpotTerms {
    AssetLeg alice_deliver;
    AssetLeg bob_deliver;
    // Optional ICU commitment requirement (not serialized on disk; derived from RPC terms)
    bool require_commitment_proof{false};

    SERIALIZE_METHODS(SpotTerms, obj)
    {
        // NOTE: Only persist asset legs; require_commitment_proof is a policy hint
        // derived from RPC terms and is not needed for on-disk reconstruction.
        READWRITE(obj.alice_deliver,
                  obj.bob_deliver);
    }
};

struct SpotAcceptanceRecord {
    uint256 acceptance_id;
    FairSignPolicy fs_policy;
    XOnlyPubKey fs_tx_adaptor_point;
    uint256 salt;
    std::string commitment_hex;
    CTxDestination bob_recv_dest;
    std::optional<uint256> local_fs_tx_adaptor_secret;

    SERIALIZE_METHODS(SpotAcceptanceRecord, obj)
    {
        READWRITE(obj.acceptance_id,
                  obj.fs_policy,
                  obj.fs_tx_adaptor_point,
                  obj.salt,
                  obj.commitment_hex);

        if (ser_action.ForRead()) {
            std::string bob_recv_encoded;
            READWRITE(bob_recv_encoded);
            const_cast<CTxDestination&>(obj.bob_recv_dest) = DecodeDestination(bob_recv_encoded);
            if (!IsValidDestination(obj.bob_recv_dest)) {
                throw std::ios_base::failure("Invalid spot acceptance destination");
            }
        } else {
            std::string bob_recv_encoded = EncodeDestination(obj.bob_recv_dest);
            READWRITE(bob_recv_encoded);
        }

        bool has_secret = obj.local_fs_tx_adaptor_secret.has_value();
        READWRITE(has_secret);
        if (has_secret) {
            if (ser_action.ForRead()) {
                uint256 secret_tmp;
                READWRITE(secret_tmp);
                const_cast<std::optional<uint256>&>(obj.local_fs_tx_adaptor_secret) = secret_tmp;
            } else {
                READWRITE(*obj.local_fs_tx_adaptor_secret);
            }
        } else if (ser_action.ForRead()) {
            const_cast<std::optional<uint256>&>(obj.local_fs_tx_adaptor_secret).reset();
        }
    }
};

struct SpotOfferRecord {
    uint256 offer_id;
    SpotTerms terms;
    FairSignPolicy fs_policy;
    XOnlyPubKey fs_tx_adaptor_point;
    std::optional<uint256> local_fs_tx_adaptor_secret;
    int created_height{0};
    int64_t created_time{0};
    uint256 salt;
    std::string commitment_hex;
    CTxDestination alice_recv_dest;
    std::optional<CTxDestination> bob_recv_dest_hint;
    std::optional<SpotAcceptanceRecord> acceptance;
    std::optional<uint256> settle_txid;  // Transaction ID of executed atomic swap

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        ::Serialize(s, offer_id);
        ::Serialize(s, terms);
        ::Serialize(s, fs_policy);
        ::Serialize(s, fs_tx_adaptor_point);

        const bool has_local_secret = local_fs_tx_adaptor_secret.has_value();
        ::Serialize(s, has_local_secret);
        if (has_local_secret) {
            ::Serialize(s, *local_fs_tx_adaptor_secret);
        }

        ::Serialize(s, created_height);
        ::Serialize(s, created_time);
        ::Serialize(s, salt);
        ::Serialize(s, commitment_hex);

        const std::string alice_recv_encoded = EncodeDestination(alice_recv_dest);
        ::Serialize(s, alice_recv_encoded);

        const bool has_bob_hint = bob_recv_dest_hint.has_value();
        ::Serialize(s, has_bob_hint);
        if (has_bob_hint) {
            const std::string bob_encoded = EncodeDestination(*bob_recv_dest_hint);
            ::Serialize(s, bob_encoded);
        }

        const bool has_acceptance = acceptance.has_value();
        ::Serialize(s, has_acceptance);
        if (has_acceptance) {
            ::Serialize(s, *acceptance);
        }

        const bool has_settle_txid = settle_txid.has_value();
        ::Serialize(s, has_settle_txid);
        if (has_settle_txid) {
            ::Serialize(s, *settle_txid);
        }
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        ::Unserialize(s, offer_id);
        ::Unserialize(s, terms);
        ::Unserialize(s, fs_policy);
        ::Unserialize(s, fs_tx_adaptor_point);

        bool has_local_secret{false};
        ::Unserialize(s, has_local_secret);
        if (has_local_secret) {
            uint256 secret_tmp;
            ::Unserialize(s, secret_tmp);
            local_fs_tx_adaptor_secret = secret_tmp;
        } else {
            local_fs_tx_adaptor_secret.reset();
        }

        ::Unserialize(s, created_height);
        ::Unserialize(s, created_time);
        ::Unserialize(s, salt);
        ::Unserialize(s, commitment_hex);

        std::string alice_recv_encoded;
        ::Unserialize(s, alice_recv_encoded);
        alice_recv_dest = DecodeDestination(alice_recv_encoded);
        if (!IsValidDestination(alice_recv_dest)) {
            throw std::ios_base::failure("Invalid spot offer alice destination");
        }

        bool has_bob_hint{false};
        ::Unserialize(s, has_bob_hint);
        if (has_bob_hint) {
            std::string bob_encoded;
            ::Unserialize(s, bob_encoded);
            CTxDestination decoded = DecodeDestination(bob_encoded);
            if (!IsValidDestination(decoded)) {
                throw std::ios_base::failure("Invalid spot offer bob destination");
            }
            bob_recv_dest_hint = decoded;
        } else {
            bob_recv_dest_hint.reset();
        }

        bool has_acceptance{false};
        ::Unserialize(s, has_acceptance);
        if (has_acceptance) {
            SpotAcceptanceRecord acc;
            ::Unserialize(s, acc);
            acceptance = acc;
        } else {
            acceptance.reset();
        }

        // settle_txid field added later - check for end of stream for backward compat
        try {
            bool has_settle_txid{false};
            ::Unserialize(s, has_settle_txid);
            if (has_settle_txid) {
                uint256 txid_tmp;
                ::Unserialize(s, txid_tmp);
                settle_txid = txid_tmp;
            } else {
                settle_txid.reset();
            }
        } catch (const std::ios_base::failure&) {
            // Older record without settle_txid field
            settle_txid.reset();
        }
    }
};

uint256 ComputeAssetDeliveryCommitment(bool is_native,
                                       const uint256& asset_id,
                                       uint64_t units,
                                       const CScript& script_pubkey,
                                       const std::vector<unsigned char>& vext);
uint256 ComputeAssetDeliveryCommitment(const AssetDeliveryTemplate& tmpl);

UniValue RepoTermsToJSON(const RepoTerms& terms);
UniValue RepoOfferCanonicalJson(const RepoOfferRecord& record,
                                const CTxDestination& repay_dest);
UniValue RepoAcceptanceCanonicalJson(const RepoOfferRecord& offer,
                                      const RepoAcceptanceRecord& acceptance);

uint256 ComputeRepoContractMeta(const RepoOfferRecord& record,
                                const CTxDestination& repay_dest);

uint256 ComputeRepoOfferCommitment(const RepoOfferRecord& record,
                                   const CTxDestination& repay_dest);
std::string RepoOfferCommitmentHex(const RepoOfferRecord& record,
                                   const CTxDestination& repay_dest);

uint256 ComputeRepoAcceptanceCommitment(const RepoOfferRecord& offer,
                                        const RepoAcceptanceRecord& acceptance);
std::string RepoAcceptanceCommitmentHex(const RepoOfferRecord& offer,
                                        const RepoAcceptanceRecord& acceptance);

uint256 ComputeForwardOfferCommitment(const ForwardTerms& terms,
                                      ForwardSide proposer_side,
                                      const uint256& salt);

std::string ForwardOfferCommitmentHex(const ForwardTerms& terms,
                                      ForwardSide proposer_side,
                                      const uint256& salt);

UniValue SpotTermsToJSON(const SpotTerms& terms);

UniValue SpotOfferCanonicalJson(const SpotOfferRecord& record);
UniValue SpotAcceptanceCanonicalJson(const SpotOfferRecord& offer,
                                     const SpotAcceptanceRecord& acceptance);

uint256 ComputeSpotContractMeta(const SpotOfferRecord& offer,
                                const SpotAcceptanceRecord* acceptance);

uint256 ComputeForwardContractMeta(const ForwardContractRecord& record);

uint256 ComputeForwardAcceptanceCommitment(const ForwardContractRecord& offer,
                                           const XOnlyPubKey& counterparty_adaptor_point,
                                           const uint256& acceptance_salt);
std::string ForwardAcceptanceCommitmentHex(const ForwardContractRecord& offer,
                                           const XOnlyPubKey& counterparty_adaptor_point,
                                           const uint256& acceptance_salt);

uint256 ComputeSpotOfferCommitment(const SpotOfferRecord& record);
std::string SpotOfferCommitmentHex(const SpotOfferRecord& record);

uint256 ComputeSpotAcceptanceCommitment(const SpotOfferRecord& offer,
                                        const SpotAcceptanceRecord& acceptance);
std::string SpotAcceptanceCommitmentHex(const SpotOfferRecord& offer,
                                        const SpotAcceptanceRecord& acceptance);

UniValue SpotOfferToJSON(const SpotOfferRecord& record);
UniValue SpotAcceptanceToJSON(const SpotOfferRecord& offer,
                              const SpotAcceptanceRecord& acceptance);

std::optional<XOnlyPubKey> ExtractTaprootKey(const CTxDestination& dest);

std::vector<unsigned char> EncodeLE64(uint64_t value);

std::vector<unsigned char> BuildAssetTagTlv(const uint256& asset_id, uint64_t units);

// ---------------------------------------------------------------------------
// Cross-chain settlement records
// ---------------------------------------------------------------------------

/// Supported external chains for cross-chain settlement.
enum class CrossChainKind : uint8_t {
    BTC = 0,
    ETHEREUM = 1,
    TRON = 2,
};

/// Adapter implementation for the external leg.
enum class CrossChainAdapter : uint8_t {
    BTC_SCRIPTLESS_V1 = 0,
    ETH_HTLC_V1 = 1,
    TRON_HTLC_V1 = 2,
};

/// Which side funds first.
enum class CrossChainFundingOrder : uint8_t {
    TSC_FIRST = 0,
    EXTERNAL_FIRST = 1,
};

/// Adapter-neutral cross-chain execution state.
///
/// Mirrors the Rust `CrossChainState` enum in cosign-bridge.
/// Secret revelation is a distinct gated transition.
enum class CrossChainState : uint8_t {
    DRAFT = 0,
    POSTED = 1,
    MATCHED = 2,
    SESSION_ESTABLISHED = 3,
    TERMS_FINALIZED = 4,
    FUNDING_PREPARED = 5,
    COUNTERPARTY_LOCK_SEEN = 6,
    COUNTERPARTY_LOCK_CONFIRMED = 7,
    LOCAL_LOCK_CONFIRMED = 8,
    CLAIM_READY = 9,
    CLAIM_BROADCAST = 10,
    EMERGENCY_CLAIM = 11,
    CLAIM_CONFIRMED = 12,
    REFUND_READY = 13,
    REFUND_BROADCAST = 14,
    REFUNDED = 15,
    COMPLETED = 16,
    ABORTED = 17,
};

/// External settlement profile stored in the wallet.
struct SettlementProfile {
    std::string label;
    CrossChainKind chain{CrossChainKind::BTC};
    std::string address;
    std::string signer_ref;    ///< "derived:auto" or "imported:<key-id>"
    std::string preferred_asset;
    std::string fee_speed;     ///< "normal", "fast", "urgent"

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        ::Serialize(s, label);
        ::Serialize(s, static_cast<uint8_t>(chain));
        ::Serialize(s, address);
        ::Serialize(s, signer_ref);
        ::Serialize(s, preferred_asset);
        ::Serialize(s, fee_speed);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        ::Unserialize(s, label);
        uint8_t chain_raw{0};
        ::Unserialize(s, chain_raw);
        chain = static_cast<CrossChainKind>(chain_raw);
        ::Unserialize(s, address);
        ::Unserialize(s, signer_ref);
        ::Unserialize(s, preferred_asset);
        ::Unserialize(s, fee_speed);
    }
};

/// Check whether a cross-chain state transition is valid per the adjacency graph.
///
/// Mirrors the Rust `CrossChainState::valid_successors()` logic.
/// Both sides must enforce the same rules so that a resumed wallet
/// cannot read a state the protocol should never have produced.
bool IsValidCrossChainTransition(CrossChainState from, CrossChainState to);

/// Persisted cross-chain execution record.
///
/// Contains everything the wallet needs to resume a swap after crash
/// without requiring a live cosign session.
///
/// swap_id and offer_id are strings (not uint256) because they originate
/// as UUID strings from the bulletin board and payload id strings from
/// the cross_chain_spot_v1 schema. Lossless round-trip across the
/// cosign-bridge ↔ wallet boundary requires matching types.
struct CrossChainRecord {
    std::string swap_id;
    std::string offer_id;
    CrossChainState state{CrossChainState::DRAFT};

    /// Full agreed payload (JSON string).
    std::string payload_json;

    /// Our role: "maker" or "taker".
    std::string local_role;

    /// Counterparty Nostr pubkey.
    std::string counterparty_pubkey;

    /// Adapter and chain metadata (derived from payload but persisted
    /// for quick access without re-parsing JSON).
    CrossChainKind external_chain{CrossChainKind::BTC};
    CrossChainAdapter adapter{CrossChainAdapter::BTC_SCRIPTLESS_V1};
    CrossChainFundingOrder funding_order{CrossChainFundingOrder::TSC_FIRST};

    // -- Funding artifacts --
    std::optional<uint256> tsc_funding_txid;
    std::optional<uint256> external_funding_txid;

    // -- Secret binding --
    /// Key-id reference, not the raw secret.
    std::string adaptor_secret_ref;

    // -- Refund artifacts --
    std::string refund_artifact;

    // -- Confirmation tracking --
    uint32_t external_conf_depth{0};
    uint32_t tsc_conf_depth{0};

    // -- Fee tracking --
    uint32_t fee_escalation_level{0};

    // -- Oracle (ETH/TRON only) --
    std::string oracle_attestation;

    // -- HTLC execution artifacts (ETH/TRON, populated during session) --
    /// Contract address of the deployed HTLC (from session negotiation).
    std::string htlc_contract_address;
    /// 32-byte hex swap ID used on the external HTLC (may differ from swap_id).
    std::string htlc_swap_id;
    /// Signing reference for the external chain (signer_ref from profile).
    std::string external_signer_ref;
    /// Claim secret (adaptor secret preimage, set when we are the claimer).
    std::string claim_secret;
    /// Transaction hash of our claim broadcast (for confirmation polling).
    std::string claim_tx_hash;
    /// Transaction hash of our refund broadcast (for confirmation polling).
    std::string refund_tx_hash;
    /// Transaction hash of the counterparty's lock (for confirmation polling).
    std::string external_lock_tx_hash;
    /// On-chain timelock from the HTLC (unix seconds, canonical source of truth).
    int64_t htlc_timelock{0};

    // -- Direct-verification expected values (from session negotiation) --
    /// Expected sha256(secret) on the HTLC (hex, 0x-prefixed).
    std::string expected_secret_hash;
    /// Expected recipient address on the HTLC (hex, 0x-prefixed).
    std::string expected_recipient;
    /// Expected amount locked in the HTLC (hex wei or base units).
    std::string expected_amount;
    /// Expected ERC-20 token address (hex, 0x-prefixed).
    /// Empty or 0x0...0 for native ETH.
    std::string expected_token_address;

    // -- TSC-side session-negotiated addresses --
    /// Taker's TSC address (where they receive the TSC leg of the swap).
    std::string taker_tsc_address;
    /// Taker's external refund address (ETH address, for lock sender/refund).
    std::string taker_refund_address;

    // -- Timestamps --
    int64_t created_time{0};
    int64_t updated_time{0};

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        ::Serialize(s, swap_id);   // string
        ::Serialize(s, offer_id);  // string
        ::Serialize(s, static_cast<uint8_t>(state));
        ::Serialize(s, payload_json);
        ::Serialize(s, local_role);
        ::Serialize(s, counterparty_pubkey);
        ::Serialize(s, static_cast<uint8_t>(external_chain));
        ::Serialize(s, static_cast<uint8_t>(adapter));
        ::Serialize(s, static_cast<uint8_t>(funding_order));

        const bool has_tsc_txid = tsc_funding_txid.has_value();
        ::Serialize(s, has_tsc_txid);
        if (has_tsc_txid) ::Serialize(s, *tsc_funding_txid);

        const bool has_ext_txid = external_funding_txid.has_value();
        ::Serialize(s, has_ext_txid);
        if (has_ext_txid) ::Serialize(s, *external_funding_txid);

        ::Serialize(s, adaptor_secret_ref);
        ::Serialize(s, refund_artifact);
        ::Serialize(s, external_conf_depth);
        ::Serialize(s, tsc_conf_depth);
        ::Serialize(s, fee_escalation_level);
        ::Serialize(s, oracle_attestation);
        ::Serialize(s, created_time);
        ::Serialize(s, updated_time);

        // V2 fields — HTLC execution artifacts
        ::Serialize(s, htlc_contract_address);
        ::Serialize(s, htlc_swap_id);
        ::Serialize(s, external_signer_ref);
        ::Serialize(s, claim_secret);
        ::Serialize(s, claim_tx_hash);
        ::Serialize(s, refund_tx_hash);
        ::Serialize(s, external_lock_tx_hash);
        ::Serialize(s, htlc_timelock);

        // V3 fields — direct-verification expected values + session addresses
        ::Serialize(s, expected_secret_hash);
        ::Serialize(s, expected_recipient);
        ::Serialize(s, expected_amount);
        ::Serialize(s, expected_token_address);
        ::Serialize(s, taker_tsc_address);
        ::Serialize(s, taker_refund_address);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        ::Unserialize(s, swap_id);   // string
        ::Unserialize(s, offer_id);  // string
        uint8_t state_raw{0};
        ::Unserialize(s, state_raw);
        state = static_cast<CrossChainState>(state_raw);
        ::Unserialize(s, payload_json);
        ::Unserialize(s, local_role);
        ::Unserialize(s, counterparty_pubkey);

        uint8_t chain_raw{0}, adapter_raw{0}, order_raw{0};
        ::Unserialize(s, chain_raw);
        external_chain = static_cast<CrossChainKind>(chain_raw);
        ::Unserialize(s, adapter_raw);
        adapter = static_cast<CrossChainAdapter>(adapter_raw);
        ::Unserialize(s, order_raw);
        funding_order = static_cast<CrossChainFundingOrder>(order_raw);

        bool has_tsc_txid{false};
        ::Unserialize(s, has_tsc_txid);
        if (has_tsc_txid) {
            uint256 tmp;
            ::Unserialize(s, tmp);
            tsc_funding_txid = tmp;
        } else {
            tsc_funding_txid.reset();
        }

        bool has_ext_txid{false};
        ::Unserialize(s, has_ext_txid);
        if (has_ext_txid) {
            uint256 tmp;
            ::Unserialize(s, tmp);
            external_funding_txid = tmp;
        } else {
            external_funding_txid.reset();
        }

        ::Unserialize(s, adaptor_secret_ref);
        ::Unserialize(s, refund_artifact);
        ::Unserialize(s, external_conf_depth);
        ::Unserialize(s, tsc_conf_depth);
        ::Unserialize(s, fee_escalation_level);
        ::Unserialize(s, oracle_attestation);
        ::Unserialize(s, created_time);
        ::Unserialize(s, updated_time);

        // V2 fields — read if present, safe for old records
        try {
            ::Unserialize(s, htlc_contract_address);
            ::Unserialize(s, htlc_swap_id);
            ::Unserialize(s, external_signer_ref);
            ::Unserialize(s, claim_secret);
            ::Unserialize(s, claim_tx_hash);
            ::Unserialize(s, refund_tx_hash);
            ::Unserialize(s, external_lock_tx_hash);
            ::Unserialize(s, htlc_timelock);

            // V3 fields — direct-verification expected values + session addresses
            ::Unserialize(s, expected_secret_hash);
            ::Unserialize(s, expected_recipient);
            ::Unserialize(s, expected_amount);
            ::Unserialize(s, expected_token_address);
            ::Unserialize(s, taker_tsc_address);
            ::Unserialize(s, taker_refund_address);
        } catch (...) {
            // Old record without V2/V3 fields — leave defaults
        }
    }
};

} // namespace wallet

#endif // TENSORCASH_WALLET_CONTRACT_H
