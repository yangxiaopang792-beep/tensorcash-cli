// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <base58.h>
#include <chain.h>
#include <coins.h>
#include <consensus/amount.h>
#include <consensus/validation.h>
#include <core_io.h>
#include <crypto/sha256.h>
#include <index/icu_acceptance_index.h>
#include <index/txindex.h>
#include <key_io.h>
#include <node/blockstorage.h>
#include <node/coin.h>
#include <node/context.h>
#include <node/psbt.h>
#include <node/transaction.h>
#include <node/types.h>
#include <policy/packages.h>
#include <policy/policy.h>
#include <policy/rbf.h>
#include <primitives/transaction.h>
#include <psbt.h>
#include <random.h>
#include <rpc/blockchain.h>
#include <rpc/assets.h>
#include <rpc/rawtransaction_util.h>
#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <txdb.h>
#include <assets/asset.h>
#include <assets/canonical_vk.h>
#include <assets/icu_payload.h>
#include <assets/icu_acceptance.h>
#include <assets/icu_acceptance_record.h>
#include <addresstype.h>
#include <rpc/bip322.h>

#include <cctype>
#include <assets/kyc_delegation.h>
#include <wallet/rpc/util.h>
#include <wallet/spend.h>
#include <wallet/coincontrol.h>
#include <wallet/wallet.h>
#include <node/transaction.h>
#include <script/script.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <script/solver.h>
#include <uint256.h>
#include <undo.h>
#include <util/bip32.h>
#include <util/check.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <util/vector.h>
#include <validation.h>
#include <validationinterface.h>

#include <numeric>
#include <stdint.h>
#include <typeinfo>

#include <univalue.h>

using node::AnalyzePSBT;
using node::FindCoins;
using node::GetTransaction;
using node::NodeContext;
using node::PSBTAnalysis;
using node::TransactionError;

#ifdef ENABLE_WALLET
static std::string DescribeRequestContext(const JSONRPCRequest& request)
{
    if (!request.context.has_value()) return "none";
    const std::type_info& type = request.context.type();
    if (type == typeid(node::NodeContext*)) return "node::NodeContext*";
    if (type == typeid(wallet::WalletContext*)) return "wallet::WalletContext*";
    return type.name();
}

static std::shared_ptr<wallet::CWallet> GetWalletForAssetsRPC(const JSONRPCRequest& request)
{
    try {
        return wallet::GetWalletForJSONRPCRequest(request);
    } catch (const UniValue& err) {
        const UniValue& code = err["code"];
        if (code.isNum() && code.getInt<int>() == RPC_INTERNAL_ERROR) {
            const UniValue& message = err["message"];
            const std::string context_desc = DescribeRequestContext(request);
            const std::string original = message.isStr() ? message.get_str() : "Wallet context not found";
            throw JSONRPCError(RPC_WALLET_NOT_FOUND,
                strprintf("%s (ctx=%s)", original, context_desc));
        }
        throw;
    }
}
#endif // ENABLE_WALLET

static void TxToJSON(const CTransaction& tx, const uint256 hashBlock, UniValue& entry,
                     Chainstate& active_chainstate, const CTxUndo* txundo = nullptr,
                     TxVerbosity verbosity = TxVerbosity::SHOW_DETAILS)
{
    CHECK_NONFATAL(verbosity >= TxVerbosity::SHOW_DETAILS);
    // Call into TxToUniv() in bitcoin-common to decode the transaction hex.
    //
    // Blockchain contextual information (confirmations and blocktime) is not
    // available to code in bitcoin-common, so we query them here and push the
    // data into the returned UniValue.
    TxToUniv(tx, /*block_hash=*/uint256(), entry, /*include_hex=*/true, txundo, verbosity);

    if (!hashBlock.IsNull()) {
        LOCK(cs_main);

        entry.pushKV("blockhash", hashBlock.GetHex());
        const CBlockIndex* pindex = active_chainstate.m_blockman.LookupBlockIndex(hashBlock);
        if (pindex) {
            if (active_chainstate.m_chain.Contains(pindex)) {
                entry.pushKV("confirmations", 1 + active_chainstate.m_chain.Height() - pindex->nHeight);
                entry.pushKV("time", pindex->GetBlockTime());
                entry.pushKV("blocktime", pindex->GetBlockTime());
            }
            else
                entry.pushKV("confirmations", 0);
        }
    }
}

static RPCHelpMan rawtxaddoutext()
{
    return RPCHelpMan{"rawtxaddoutext",
        "Attach or replace an output extension (vExt TLV) on a given vout of a raw transaction.",
        {
            {"hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Raw transaction hex (serialized with or without witness)"},
            {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "Output index to modify"},
            {"tlv", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "TLV bytes (type|varint len|value) to set; use \"\" to clear"},
        },
        RPCResult{RPCResult::Type::STR_HEX, "hex", "Modified raw transaction hex"},
        RPCExamples{
            HelpExampleCli("rawtxaddoutext", "\"<hex>\" 0 \"01\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            std::string hex = request.params[0].get_str();
            int vout = request.params[1].getInt<int>();
            std::vector<unsigned char> tlv = ParseHex(request.params[2].get_str());

            CMutableTransaction mtx;
            if (!DecodeHexTx(mtx, hex, /*try_no_witness=*/true, /*try_witness=*/true)) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
            }
            if (vout < 0 || (size_t)vout >= mtx.vout.size()) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "vout index out of range");
            }
            mtx.vout[vout].vExt = std::move(tlv);
            DataStream out;
            out << TX_WITH_WITNESS(mtx);
            return HexStr(out);
        }
    };
}

static RPCHelpMan rawtxattachissuerreg()
{
    return RPCHelpMan{"rawtxattachissuerreg",
        "Attach an IssuerReg TLV (and optionally ICU_TEXT_CHUNK) to the specified vout of a raw transaction.",
        {
            {"hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Raw transaction hex"},
            {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "Output index"},
            {"asset_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "32-byte asset id hex (no 0x)"},
            {"policy_bits", RPCArg::Type::NUM, RPCArg::Optional::NO, "Policy bits (u32)"},
            {"allowed_spk_families", RPCArg::Type::NUM, RPCArg::Default{assets::SPK_DEFAULT_ALLOWED}, "Allowed script family mask (u16)"},
            {"unlock_fees_sats", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Unlock threshold in sats (u64). If not specified, defaults to max(output_value, 500000000). Must be >= output value."},
            {"ticker", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Optional ticker: root [A-Z][A-Z0-9]{2,10}, or one-hop sponsored child ROOT.SUFFIX"},
            {"decimals", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Optional decimals (u8, 0..18)"},
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Optional ZK and ICU governance fields",
                {
                    {"kyc_flags", RPCArg::Type::NUM, RPCArg::Default{0}, "ZK/KYC flags (e.g., KYC_REQUIRED=1)"},
                    {"vk_commitment", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "32-byte ZK verification key commitment"},
                    {"max_root_age", RPCArg::Type::NUM, RPCArg::Default{0}, "Maximum merkle root age in seconds"},
                    {"tfr_flags", RPCArg::Type::NUM, RPCArg::Default{0}, "Transfer flags (e.g., TFR_ANCHOR_REQUIRED)"},
                    {"icu_plain_commit", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "32-byte plaintext commitment (auto-derived from icu_payload if omitted)"},
                    {"icu_ctxt_commit", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "32-byte ciphertext commitment (auto-derived from icu_payload if omitted)"},
                    {"kdf_salt", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "16-byte encryption salt"},
                    {"icu_payload", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Raw ICU payload bytes (caller must attach via separate rawtxaddoutext call)"},
                    {"icu_flags", RPCArg::Type::NUM, RPCArg::Default{0}, "ICU structural flags (e.g., WRAP_REQUIRED=1)"},
                    {"icu_visibility", RPCArg::Type::NUM, RPCArg::Default{0}, "0=public, 1=holder_only"},
                    {"policy_quorum_bps", RPCArg::Type::NUM, RPCArg::Default{0}, "Governance quorum in basis points (0=immutable)"},
                    {"issuance_cap_units", RPCArg::Type::NUM, RPCArg::Default{0}, "Issuance cap (0=unlimited)"},
                    {"canonical_text", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Canonical governance text (alternative to icu_payload)"},
                    {"witness_bundle", RPCArg::Type::OBJ_USER_KEYS, RPCArg::Optional::OMITTED, "Witness bundle JSON object (alternative to icu_payload)",
                        {
                            {"key", RPCArg::Type::STR, RPCArg::Optional::NO, "User-defined witness data key-value pairs"},
                        },
                    },
                    {"dek", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "32-byte Data Encryption Key as hex (required if icu_visibility=1 and using canonical_text). This will be wrapped via ECDH for each recipient."},
                    {"use_compression", RPCArg::Type::BOOL, RPCArg::Default{false}, "Enable zstd compression (deterministic)"},
                }
            },
        },
        RPCResult{RPCResult::Type::STR_HEX, "hex", "Modified hex"},
        RPCExamples{
            HelpExampleCli("rawtxattachissuerreg", "\"<hex>\" 0 \"<asset_id>\" 3 28 100000")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            std::string hex = request.params[0].get_str();
            int vout = request.params[1].getInt<int>();
            std::string asset_hex = request.params[2].get_str();
            if (asset_hex.length() != 64) throw JSONRPCError(RPC_INVALID_PARAMETER, "asset_id must be exactly 64 hex chars");
            auto aid = uint256::FromHex(asset_hex);
            if (!aid) throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid asset_id hex");
            uint32_t policy_bits = request.params[3].getInt<uint32_t>();
            uint16_t allowed = request.params[4].isNull() ? assets::SPK_DEFAULT_ALLOWED : request.params[4].getInt<uint16_t>();
            // Get the output value to validate/default unlock_fees_sats
            CMutableTransaction mtx_check;
            if (!DecodeHexTx(mtx_check, hex, /*try_no_witness=*/true, /*try_witness=*/true)) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
            }
            if (vout < 0 || (size_t)vout >= mtx_check.vout.size()) throw JSONRPCError(RPC_INVALID_PARAMETER, "vout index out of range");
            CAmount bond_value = mtx_check.vout[vout].nValue;

            // unlock_fees_sats defaults to max(bond_value, 5 BTC) if not specified
            bool has_unlock = (request.params.size() > 5) && !request.params[5].isNull();
            uint64_t unlock;
            if (has_unlock) {
                // User specified value - use it (will be validated below)
                unlock = request.params[5].getInt<uint64_t>();
            } else {
                // Not specified - default to max(bond_value, 5 BTC minimum)
                static constexpr uint64_t MIN_BOND_SATS = 500000000; // 5 BTC
                unlock = std::max(static_cast<uint64_t>(bond_value), MIN_BOND_SATS);
            }

            // Validate unlock_fees_sats >= bond_value
            if (unlock < static_cast<uint64_t>(bond_value)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    strprintf("unlock_fees_sats (%d) must be >= bond value (%d)", unlock, bond_value));
            }

            std::string ticker;
            bool has_ticker = (request.params.size() > 6) && !request.params[6].isNull();
            if (has_ticker) ticker = request.params[6].get_str();
            bool has_decimals = (request.params.size() > 7) && !request.params[7].isNull();
            uint8_t decimals = 0;
            if (has_decimals) {
                decimals = request.params[7].getInt<uint8_t>();
                if (decimals > 18) throw JSONRPCError(RPC_INVALID_PARAMETER, "decimals must be 0..18");
            }

            CMutableTransaction mtx;
            // Try both witness and no-witness decoding paths for robustness
            if (!DecodeHexTx(mtx, hex, /*try_no_witness=*/true, /*try_witness=*/true)) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
            }
            if (vout < 0 || (size_t)vout >= mtx.vout.size()) throw JSONRPCError(RPC_INVALID_PARAMETER, "vout index out of range");

            // Build v1 IssuerReg format (deterministic with ZK+ICU sections always present)
            // ZK Whitelist Hardening: Updated from 222 to 254 bytes (added 32-byte compliance_root_commit)
            std::vector<unsigned char> payload;
            payload.reserve(254 + (has_ticker ? ticker.size() : 0));

            // Header (39 bytes)
            payload.insert(payload.end(), aid->begin(), aid->end());  // asset_id (32)
            unsigned char pb[4]; WriteLE32(pb, policy_bits); payload.insert(payload.end(), pb, pb+4);  // policy_bits (4)
            unsigned char ab[2]; ab[0] = allowed & 0xFF; ab[1] = (allowed >> 8) & 0xFF; payload.insert(payload.end(), ab, ab+2);  // allowed_spk (2)
            payload.push_back(assets::ISSUER_REG_FORMAT_V1);  // format_version = 0x01 (1)

            // Optional fields (10+ bytes)
            if (has_ticker) {
                // Uppercase ASCII letters for convenience, then apply the SINGLE shared ticker
                // grammar gate (bare root or one-hop child ROOT.SUFFIX). Do not re-implement ad
                // hoc length/alphabet checks here (ICU_CHILD.md §5.1, §6.2).
                for (char& c : ticker) { if (c >= 'a' && c <= 'z') c = char(c - 32); }
                if (!assets::IsTickerValidForIssuerReg(ticker)) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid ticker: expected root [A-Z][A-Z0-9]{2,10} or one-hop child ROOT.SUFFIX");
                }
                payload.push_back(static_cast<unsigned char>(ticker.size()));  // ticker_len
                payload.insert(payload.end(), ticker.begin(), ticker.end());  // ticker
            } else {
                payload.push_back(0);  // ticker_len = 0 (empty ticker)
            }
            payload.push_back(has_decimals ? decimals : 0xFF);  // decimals (0xFF = not set)
            unsigned char ub[8]; WriteLE64(ub, unlock); payload.insert(payload.end(), ub, ub+8);  // unlock_fees (8)

            // Parse optional ICU/ZK fields from options object
            uint256 icu_plain_commit, icu_ctxt_commit;
            std::array<unsigned char, 16> kdf_salt{};
            std::vector<unsigned char> icu_payload;
            std::optional<assets::IcuStorageEntry> built_storage_entry;
            uint32_t icu_flags = 0;
            uint8_t icu_visibility = 0;
            uint16_t policy_quorum_bps = 0;
            uint64_t issuance_cap_units = 0;

            // ZK parameters
            uint32_t kyc_flags = 0;
            uint256 vk_commitment;
            uint32_t max_root_age = 0;
            uint32_t tfr_flags = 0;

            if (request.params.size() > 8 && !request.params[8].isNull()) {
                const UniValue& opts = request.params[8];

                // Parse icu_payload first (needed for auto-deriving commits)
                if (opts.exists("icu_payload")) {
                    icu_payload = ParseHex(opts["icu_payload"].get_str());
                    if (icu_payload.size() > 100 * 1024) throw JSONRPCError(RPC_INVALID_PARAMETER, "icu_payload exceeds 100 KiB");
                }

                // Parse or auto-derive icu_ctxt_commit
                if (opts.exists("icu_ctxt_commit")) {
                    auto commit = uint256::FromHex(opts["icu_ctxt_commit"].get_str());
                    if (!commit) throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid icu_ctxt_commit hex");
                    icu_ctxt_commit = *commit;

                    // Verify payload hashes to commit if both provided
                    if (!icu_payload.empty()) {
                        CSHA256 hasher;
                        hasher.Write(icu_payload.data(), icu_payload.size());
                        uint256 computed_hash;
                        hasher.Finalize(computed_hash.begin());

                        if (computed_hash != icu_ctxt_commit) {
                            throw JSONRPCError(RPC_INVALID_PARAMETER,
                                strprintf("icu_payload hash mismatch: computed %s, expected %s",
                                    computed_hash.ToString(), icu_ctxt_commit.ToString()));
                        }
                    }
                } else if (!icu_payload.empty()) {
                    // Auto-derive icu_ctxt_commit from payload
                    CSHA256 hasher;
                    hasher.Write(icu_payload.data(), icu_payload.size());
                    hasher.Finalize(icu_ctxt_commit.begin());
                }

                // Parse or auto-derive icu_plain_commit
                if (opts.exists("icu_plain_commit")) {
                    auto commit = uint256::FromHex(opts["icu_plain_commit"].get_str());
                    if (!commit) throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid icu_plain_commit hex");
                    icu_plain_commit = *commit;
                } else if (!icu_payload.empty()) {
                    // No icu_plain_commit explicitly provided: try to derive the SEMANTIC hash.
                    // If the raw payload parses as a CanonicalIcuPayload (i.e. it carries plaintext
                    // canonical structure), the correct icu_plain_commit is SHA256(canonical_text),
                    // which GetCanonicalHash() computes -- not SHA256 over the whole serialized blob.
                    if (auto parsed = assets::ParseCanonicalIcuPayload(icu_payload)) {
                        icu_plain_commit = parsed->GetCanonicalHash();
                    } else {
                        // Opaque/encrypted blob with no parseable plaintext structure: the node
                        // CANNOT derive the semantic canonical_text hash, and SHA256(payload) is the
                        // ciphertext commitment, not the plain commitment. Refuse rather than write a
                        // wrong icu_plain_commit that every later reader would correctly flag as
                        // unverifiable -- a holder-only issuer must pass icu_plain_commit explicitly.
                        throw JSONRPCError(RPC_INVALID_PARAMETER,
                            "icu_payload is opaque/encrypted and cannot be parsed for its canonical hash; "
                            "pass icu_plain_commit explicitly");
                    }
                }

                // Support canonical ICU plaintext helper
                if (opts.exists("icu_payload_plain")) {
                    std::vector<unsigned char> plain_bytes = ParseHex(opts["icu_payload_plain"].get_str());
                    if (plain_bytes.empty()) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "icu_payload_plain cannot be empty");
                    }

                    auto parsed_payload = assets::ParseCanonicalIcuPayload(plain_bytes);
                    if (!parsed_payload) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "Failed to parse icu_payload_plain as CanonicalIcuPayload structure");
                    }

                    std::string canonical_text_str(parsed_payload->canonical_text.begin(), parsed_payload->canonical_text.end());
                    std::string witness_str(parsed_payload->witness_bundle.begin(), parsed_payload->witness_bundle.end());
                    UniValue witness_obj;
                    if (!witness_obj.read(witness_str)) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "Failed to parse witness_bundle JSON");
                    }

                    uint8_t target_visibility = opts.exists("icu_visibility") ? icu_visibility : parsed_payload->visibility;
                    if (target_visibility > 1) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "icu_visibility must be 0 or 1");
                    }
                    icu_visibility = target_visibility;

                    bool use_compression = opts.exists("use_compression") ? opts["use_compression"].get_bool() : (parsed_payload->compression == 1);

                    std::array<unsigned char, 32> dek{};
                    if (icu_visibility == 1) {
                        if (!opts.exists("dek")) {
                            throw JSONRPCError(RPC_INVALID_PARAMETER, "dek (32-byte hex) required when icu_visibility=1 and icu_payload_plain is provided");
                        }
                        const std::string dek_hex = opts["dek"].get_str();
                        if (dek_hex.size() != 64) {
                            throw JSONRPCError(RPC_INVALID_PARAMETER, "dek must be 64 hex characters");
                        }
                        auto dek_bytes = ParseHex(dek_hex);
                        if (dek_bytes.size() != 32) {
                            throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid dek hex");
                        }
                        std::copy(dek_bytes.begin(), dek_bytes.end(), dek.begin());
                        icu_flags |= assets::WRAP_REQUIRED;
                    }

                    uint256 plain_commit;
                    uint256 ctxt_commit;
                    std::array<unsigned char, 16> salt;
                    assets::IcuStorageEntry storage_entry_local;
                    if (!assets::BuildCanonicalIcuPayload(
                            canonical_text_str,
                            witness_obj,
                            icu_visibility,
                            dek,
                            use_compression,
                            plain_commit,
                            ctxt_commit,
                            salt,
                            storage_entry_local,
                            parsed_payload->metadata)) {  // preserve the (inline-context) marker; was silently dropped
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "canonical_text contains unsupported characters");
                    }

                    icu_plain_commit = plain_commit;
                    icu_ctxt_commit = ctxt_commit;
                    std::copy(salt.begin(), salt.end(), kdf_salt.begin());
                    icu_payload = storage_entry_local.icu_cipher;
                    built_storage_entry = storage_entry_local;

                    if (use_compression) {
                        icu_flags |= assets::ICU_COMPRESSED;
                    } else {
                        icu_flags &= ~assets::ICU_COMPRESSED;
                    }
                }

                if (opts.exists("kdf_salt")) {
                    std::string salt_hex = opts["kdf_salt"].get_str();
                    if (salt_hex.length() != 32) throw JSONRPCError(RPC_INVALID_PARAMETER, "kdf_salt must be 16 bytes (32 hex chars)");
                    auto salt_bytes = ParseHex(salt_hex);
                    if (salt_bytes.size() != 16) throw JSONRPCError(RPC_INVALID_PARAMETER, "kdf_salt must be 16 bytes");
                    std::copy(salt_bytes.begin(), salt_bytes.end(), kdf_salt.begin());
                }

                if (opts.exists("icu_flags")) {
                    icu_flags = opts["icu_flags"].getInt<uint32_t>();
                }

                if (opts.exists("icu_visibility")) {
                    icu_visibility = opts["icu_visibility"].getInt<uint8_t>();
                    if (icu_visibility > 1) throw JSONRPCError(RPC_INVALID_PARAMETER, "icu_visibility must be 0 or 1");
                }

                if (opts.exists("policy_quorum_bps")) {
                    policy_quorum_bps = opts["policy_quorum_bps"].getInt<uint16_t>();
                    if (policy_quorum_bps > 10000) throw JSONRPCError(RPC_INVALID_PARAMETER, "policy_quorum_bps must be <= 10000");
                }

                if (opts.exists("issuance_cap_units")) {
                    issuance_cap_units = opts["issuance_cap_units"].getInt<uint64_t>();
                }

                // ZK parameters
                if (opts.exists("kyc_flags")) {
                    kyc_flags = opts["kyc_flags"].getInt<uint32_t>();
                }

                if (opts.exists("vk_commitment")) {
                    std::string vk_hex = opts["vk_commitment"].get_str();
                    if (vk_hex.length() != 64) throw JSONRPCError(RPC_INVALID_PARAMETER, "vk_commitment must be 64 hex chars");
                    auto vk_bytes = ParseHex(vk_hex);
                    if (vk_bytes.size() != 32) throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid vk_commitment hex");
                    std::copy(vk_bytes.begin(), vk_bytes.end(), vk_commitment.begin());
                }

                if (opts.exists("max_root_age")) {
                    max_root_age = opts["max_root_age"].getInt<uint32_t>();
                }

                if (opts.exists("tfr_flags")) {
                    tfr_flags = opts["tfr_flags"].getInt<uint32_t>();
                }

                // NEW: Handle canonical_text + DEK approach (alternative to raw icu_payload)
                if (opts.exists("canonical_text")) {
                    std::string canonical_text = opts["canonical_text"].get_str();

                    // Get witness_bundle (required)
                    if (!opts.exists("witness_bundle")) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "witness_bundle required when canonical_text is provided");
                    }
                    UniValue witness_obj = opts["witness_bundle"];

                    // Get DEK (required for holder-only, ignored for public)
                    std::array<unsigned char, 32> dek{};
                    if (icu_visibility == 1) {
                        if (!opts.exists("dek")) {
                            throw JSONRPCError(RPC_INVALID_PARAMETER, "dek (32-byte hex) required for holder-only assets (icu_visibility=1)");
                        }
                        std::string dek_hex = opts["dek"].get_str();
                        if (dek_hex.length() != 64) {
                            throw JSONRPCError(RPC_INVALID_PARAMETER, "dek must be exactly 64 hex characters (32 bytes)");
                        }
                        auto dek_bytes = ParseHex(dek_hex);
                        if (dek_bytes.size() != 32) {
                            throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid dek hex");
                        }
                        std::copy(dek_bytes.begin(), dek_bytes.end(), dek.begin());
                    }

                    // Get use_compression flag
                    bool use_compression = false;
                    if (opts.exists("use_compression")) {
                        use_compression = opts["use_compression"].get_bool();
                    }

                    // Build canonical ICU payload with encryption/compression
                    uint256 plain_commit, ctxt_commit;
                    std::array<unsigned char, 16> salt;
                    assets::IcuStorageEntry storage_entry_local;

                    bool success = assets::BuildCanonicalIcuPayload(
                        canonical_text,
                        witness_obj,
                        icu_visibility,
                        dek,
                        use_compression,
                        plain_commit,
                        ctxt_commit,
                        salt,
                        storage_entry_local
                    );

                    if (!success) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "canonical_text contains unsupported characters");
                    }

                    // Use the computed values
                    icu_plain_commit = plain_commit;
                    icu_ctxt_commit = ctxt_commit;
                    std::copy(salt.begin(), salt.end(), kdf_salt.begin());
                    icu_payload = storage_entry_local.icu_cipher;
                    built_storage_entry = storage_entry_local;

                    // Set ICU_COMPRESSED flag if compression was used
                    if (use_compression) {
                        icu_flags |= assets::ICU_COMPRESSED;
                    }
                }
            }

            // ZK section (76 bytes) - ZK Whitelist Hardening update
            // Format: kyc_flags(4) + vk_commitment(32) + max_root_age(4) + tfr_flags(4) + compliance_root_commit(32)
            unsigned char zk_buf[76];
            WriteLE32(zk_buf, kyc_flags);
            std::copy(vk_commitment.begin(), vk_commitment.end(), zk_buf + 4);
            WriteLE32(zk_buf + 36, max_root_age);
            WriteLE32(zk_buf + 40, tfr_flags);
            // compliance_root_commit [32] - zero for initial registration (issuer must set via updatecomplianceroot RPC)
            std::fill(zk_buf + 44, zk_buf + 76, 0);
            payload.insert(payload.end(), zk_buf, zk_buf + 76);

            // ICU section (129 bytes with icu_visibility)
            unsigned char icu_buf32[4];
            unsigned char icu_buf64[8];
            unsigned char icu_buf16[2];

            WriteLE32(icu_buf32, icu_flags);
            payload.insert(payload.end(), icu_buf32, icu_buf32+4);

            WriteLE64(icu_buf64, issuance_cap_units);
            payload.insert(payload.end(), icu_buf64, icu_buf64+8);

            if (icu_plain_commit.IsNull() && built_storage_entry.has_value() && !built_storage_entry->canonical_hash.IsNull()) {
                icu_plain_commit = built_storage_entry->canonical_hash;
            }

            payload.insert(payload.end(), icu_ctxt_commit.begin(), icu_ctxt_commit.end()); // 32 bytes
            payload.insert(payload.end(), icu_plain_commit.begin(), icu_plain_commit.end()); // 32 bytes
            payload.insert(payload.end(), kdf_salt.begin(), kdf_salt.end()); // 16 bytes

            payload.push_back(1); // icu_version = 1
            payload.push_back(icu_visibility);

            payload.insert(payload.end(), 32, 0); // core_policy_commit (32 bytes zero for now)
            payload.push_back(0); // policy_epoch = 0

            WriteLE16(icu_buf16, policy_quorum_bps);
            payload.insert(payload.end(), icu_buf16, icu_buf16+2);

            // Wrap IssuerReg in TLV
            std::vector<unsigned char> tlv;
            tlv.push_back(static_cast<uint8_t>(assets::OutExtType::ISSUER_REG));
            if (payload.size() < 253) {
                tlv.push_back(static_cast<uint8_t>(payload.size()));
            } else {
                tlv.push_back(253);
                tlv.push_back(payload.size() & 0xFF);
                tlv.push_back((payload.size() >> 8) & 0xFF);
            }
            tlv.insert(tlv.end(), payload.begin(), payload.end());

            mtx.vout[vout].vExt = std::move(tlv);
            DataStream out; out << TX_WITH_WITNESS(mtx);
            return HexStr(out);
        }
    };
}

static RPCHelpMan rawtxattachassettag()
{
    return RPCHelpMan{"rawtxattachassettag",
        "Attach an AssetTag TLV (optionally with ICU_KEYWRAP) to the specified vout of a raw transaction.",
        {
            {"hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Raw transaction hex"},
            {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "Output index"},
            {"asset_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "32-byte asset id hex (no 0x)"},
            {"amount", RPCArg::Type::NUM, RPCArg::Optional::NO, "Asset amount (u64)"},
            {"flags", RPCArg::Type::NUM, RPCArg::Default{0}, "Asset flags (u32)"},
            {"keywrap", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Optional ICU_KEYWRAP sub-TLV for WRAP_REQUIRED assets",
                {
                    {"asset_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "32-byte asset id hex"},
                    {"ctxt_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "32-byte ciphertext hash"},
                    {"spk_hash32", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "32-byte scriptPubKey hash"},
                    {"wrapped_key", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Wrapped symmetric key (variable length hex)"},
                    {"suite_id", RPCArg::Type::NUM, RPCArg::Default{0}, "Cryptographic suite ID (u8)"},
                    {"extras_mask", RPCArg::Type::NUM, RPCArg::Default{0}, "Extras bitmask: 0x01=wrap_commit, 0x02=kc_tag (u8)"},
                    {"wrap_commit", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "32-byte wrap commitment (if extras_mask & 0x01)"},
                    {"kc_tag", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "16-byte key confirmation tag (if extras_mask & 0x02)"},
                }
            },
        },
        RPCResult{RPCResult::Type::STR_HEX, "hex", "Modified hex"},
        RPCExamples{
            HelpExampleCli("rawtxattachassettag", "\"<hex>\" 1 \"<asset_id>\" 1000000 0") +
            HelpExampleCli("rawtxattachassettag", "\"<hex>\" 1 \"<asset_id>\" 1000000 0 '{\"asset_id\":\"...\", \"ctxt_hash\":\"...\", \"spk_hash32\":\"...\", \"wrapped_key\":\"...\"}'")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            std::string hex = request.params[0].get_str();
            int vout = request.params[1].getInt<int>();
            std::string asset_hex = request.params[2].get_str();
            if (asset_hex.length() != 64) throw JSONRPCError(RPC_INVALID_PARAMETER, "asset_id must be exactly 64 hex chars");
            auto aid = uint256::FromHex(asset_hex);
            if (!aid) throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid asset_id hex");
            uint64_t amount;
            try {
                amount = request.params[3].getInt<uint64_t>();
            } catch (const std::exception&) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "amount too large");
            }
            if (amount == 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "amount must be > 0");
            uint32_t flags = request.params[4].isNull() ? 0u : request.params[4].getInt<uint32_t>();

            CMutableTransaction mtx;
            if (!DecodeHexTx(mtx, hex, /*try_no_witness=*/true, /*try_witness=*/true)) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
            }
            if (vout < 0 || (size_t)vout >= mtx.vout.size()) throw JSONRPCError(RPC_INVALID_PARAMETER, "vout index out of range");

            // Build main AssetTag payload
            std::vector<unsigned char> payload;
            payload.reserve(32 + 8 + 4);
            payload.insert(payload.end(), aid->begin(), aid->end());
            unsigned char abuf[8]; WriteLE64(abuf, amount); payload.insert(payload.end(), abuf, abuf+8);
            unsigned char fbuf[4]; WriteLE32(fbuf, flags); payload.insert(payload.end(), fbuf, fbuf+4);

            // Parse optional keywrap parameter
            if (request.params.size() > 5 && !request.params[5].isNull()) {
                const UniValue& kw = request.params[5];

                // Parse required fields
                std::string kw_asset_hex = kw["asset_id"].get_str();
                if (kw_asset_hex.length() != 64) throw JSONRPCError(RPC_INVALID_PARAMETER, "keywrap.asset_id must be 64 hex chars");
                auto kw_asset_id = uint256::FromHex(kw_asset_hex);
                if (!kw_asset_id) throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid keywrap.asset_id");

                std::string ctxt_hex = kw["ctxt_hash"].get_str();
                if (ctxt_hex.length() != 64) throw JSONRPCError(RPC_INVALID_PARAMETER, "keywrap.ctxt_hash must be 64 hex chars");
                auto ctxt_hash = uint256::FromHex(ctxt_hex);
                if (!ctxt_hash) throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid keywrap.ctxt_hash");

                std::string spk_hex = kw["spk_hash32"].get_str();
                if (spk_hex.length() != 64) throw JSONRPCError(RPC_INVALID_PARAMETER, "keywrap.spk_hash32 must be 64 hex chars");
                auto spk_hash32 = uint256::FromHex(spk_hex);
                if (!spk_hash32) throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid keywrap.spk_hash32");

                std::string wrapped_key_hex = kw["wrapped_key"].get_str();
                auto wrapped_key = ParseHex(wrapped_key_hex);
                if (wrapped_key.empty()) throw JSONRPCError(RPC_INVALID_PARAMETER, "keywrap.wrapped_key cannot be empty");

                // Validate UTF-8 (consensus requirement)
                auto is_valid_utf8 = [](const std::vector<unsigned char>& data) -> bool {
                    size_t i = 0;
                    while (i < data.size()) {
                        unsigned char c = data[i];
                        if ((c & 0x80) == 0) { ++i; continue; }
                        if ((c & 0xE0) == 0xC0) {
                            if (i + 1 >= data.size() || (data[i+1] & 0xC0) != 0x80 || c < 0xC2) return false;
                            i += 2; continue;
                        }
                        if ((c & 0xF0) == 0xE0) {
                            if (i + 2 >= data.size() || (data[i+1] & 0xC0) != 0x80 || (data[i+2] & 0xC0) != 0x80) return false;
                            if (c == 0xE0 && data[i+1] < 0xA0) return false; // overlong
                            if (c == 0xED && data[i+1] >= 0xA0) return false; // surrogate
                            i += 3; continue;
                        }
                        if ((c & 0xF8) == 0xF0) {
                            if (i + 3 >= data.size() || (data[i+1] & 0xC0) != 0x80 || (data[i+2] & 0xC0) != 0x80 || (data[i+3] & 0xC0) != 0x80) return false;
                            if (c == 0xF0 && data[i+1] < 0x90) return false; // overlong
                            if (c >= 0xF4) return false; // beyond U+10FFFF
                            i += 4; continue;
                        }
                        return false;
                    }
                    return true;
                };
                if (!is_valid_utf8(wrapped_key)) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "keywrap.wrapped_key must be valid UTF-8");
                }

                uint8_t suite_id = kw["suite_id"].isNull() ? 0 : kw["suite_id"].getInt<uint8_t>();
                uint8_t extras_mask = kw["extras_mask"].isNull() ? 0 : kw["extras_mask"].getInt<uint8_t>();

                // Validate extras_mask
                const uint8_t allowed_mask = assets::ICU_KEYWRAP_EXTRA_WRAP_COMMIT | assets::ICU_KEYWRAP_EXTRA_KC_TAG;
                if (extras_mask & ~allowed_mask) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "keywrap.extras_mask has unknown bits (allowed: 0x01, 0x02)");
                }

                // Parse optional extras
                uint256 wrap_commit;
                std::array<unsigned char, 16> kc_tag{};

                if (extras_mask & assets::ICU_KEYWRAP_EXTRA_WRAP_COMMIT) {
                    if (!kw.exists("wrap_commit")) throw JSONRPCError(RPC_INVALID_PARAMETER, "extras_mask 0x01 set but wrap_commit missing");
                    std::string wc_hex = kw["wrap_commit"].get_str();
                    if (wc_hex.length() != 64) throw JSONRPCError(RPC_INVALID_PARAMETER, "wrap_commit must be 64 hex chars");
                    auto wc = uint256::FromHex(wc_hex);
                    if (!wc) throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid wrap_commit");
                    wrap_commit = *wc;
                }

                if (extras_mask & assets::ICU_KEYWRAP_EXTRA_KC_TAG) {
                    if (!kw.exists("kc_tag")) throw JSONRPCError(RPC_INVALID_PARAMETER, "extras_mask 0x02 set but kc_tag missing");
                    std::string kc_hex = kw["kc_tag"].get_str();
                    if (kc_hex.length() != 32) throw JSONRPCError(RPC_INVALID_PARAMETER, "kc_tag must be 32 hex chars (16 bytes)");
                    auto kc_bytes = ParseHex(kc_hex);
                    if (kc_bytes.size() != 16) throw JSONRPCError(RPC_INVALID_PARAMETER, "kc_tag must be 16 bytes");
                    std::copy(kc_bytes.begin(), kc_bytes.end(), kc_tag.begin());
                }

                // Build ICU_KEYWRAP sub-TLV payload
                std::vector<unsigned char> kw_payload;
                kw_payload.reserve(32 + 32 + 32 + wrapped_key.size() + 10 +
                    (extras_mask & assets::ICU_KEYWRAP_EXTRA_WRAP_COMMIT ? 32 : 0) +
                    (extras_mask & assets::ICU_KEYWRAP_EXTRA_KC_TAG ? 16 : 0));

                // asset_id (32 bytes)
                kw_payload.insert(kw_payload.end(), kw_asset_id->begin(), kw_asset_id->end());
                // ctxt_hash (32 bytes)
                kw_payload.insert(kw_payload.end(), ctxt_hash->begin(), ctxt_hash->end());
                // spk_hash32 (32 bytes)
                kw_payload.insert(kw_payload.end(), spk_hash32->begin(), spk_hash32->end());

                // wrapped_key (CompactSize length + data)
                VectorWriter kw_writer(kw_payload, kw_payload.size());
                WriteCompactSize(kw_writer, wrapped_key.size());
                kw_payload.insert(kw_payload.end(), wrapped_key.begin(), wrapped_key.end());

                // suite_id (1 byte)
                kw_payload.push_back(suite_id);
                // extras_mask (1 byte)
                kw_payload.push_back(extras_mask);

                // Optional wrap_commit (32 bytes)
                if (extras_mask & assets::ICU_KEYWRAP_EXTRA_WRAP_COMMIT) {
                    kw_payload.insert(kw_payload.end(), wrap_commit.begin(), wrap_commit.end());
                }

                // Optional kc_tag (16 bytes)
                if (extras_mask & assets::ICU_KEYWRAP_EXTRA_KC_TAG) {
                    kw_payload.insert(kw_payload.end(), kc_tag.begin(), kc_tag.end());
                }

                // Append ICU_KEYWRAP sub-TLV to main payload: type (1 byte) + CompactSize length + sub-payload
                payload.push_back(0x03); // ICU_KEYWRAP sub-TLV type
                VectorWriter payload_writer(payload, payload.size());
                WriteCompactSize(payload_writer, kw_payload.size());
                payload.insert(payload.end(), kw_payload.begin(), kw_payload.end());
            }

            // Build final TLV
            std::vector<unsigned char> tlv;
            tlv.push_back(static_cast<uint8_t>(assets::OutExtType::ASSET_TAG));

            // Use CompactSize for length since payload can be large with keywrap
            VectorWriter tlv_writer(tlv, tlv.size());
            WriteCompactSize(tlv_writer, payload.size());
            tlv.insert(tlv.end(), payload.begin(), payload.end());

            mtx.vout[vout].vExt = std::move(tlv);
            DataStream out; out << TX_WITH_WITNESS(mtx);
            return HexStr(out);
        }
    };
}

static RPCHelpMan rawtxattachzkchunk()
{
    return RPCHelpMan{"rawtxattachzkchunk",
        "Attach a ZK_PARAMS_CHUNK TLV to the specified vout of a raw transaction.\n"
        "ZK chunks carry cryptographic verification key parameters for ZK proof validation.",
        {
            {"hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Raw transaction hex"},
            {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "Output index"},
            {"asset_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "32-byte asset id hex (no 0x)"},
            {"vk_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "32-byte verification key hash (matches IssuerReg.vk_commitment)"},
            {"chunk_index", RPCArg::Type::NUM, RPCArg::Optional::NO, "Chunk index (0-based, u16)"},
            {"chunk_count", RPCArg::Type::NUM, RPCArg::Optional::NO, "Total chunk count (u16, max 8)"},
            {"data", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Chunk data (raw hex bytes)"},
        },
        RPCResult{RPCResult::Type::STR_HEX, "hex", "Modified hex"},
        RPCExamples{
            HelpExampleCli("rawtxattachzkchunk", "\"<hex>\" 0 \"<asset_id>\" \"<vk_hash>\" 0 1 \"<data_hex>\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            std::string hex = request.params[0].get_str();
            int vout = request.params[1].getInt<int>();

            std::string asset_hex = request.params[2].get_str();
            if (asset_hex.length() != 64) throw JSONRPCError(RPC_INVALID_PARAMETER, "asset_id must be 64 hex chars");
            auto asset_id = uint256::FromHex(asset_hex);
            if (!asset_id) throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid asset_id hex");

            std::string vk_hex = request.params[3].get_str();
            if (vk_hex.length() != 64) throw JSONRPCError(RPC_INVALID_PARAMETER, "vk_hash must be 64 hex chars");
            auto vk_hash = uint256::FromHex(vk_hex);
            if (!vk_hash) throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid vk_hash hex");

            uint16_t chunk_index = request.params[4].getInt<uint16_t>();
            uint16_t chunk_count = request.params[5].getInt<uint16_t>();

            if (chunk_count == 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "chunk_count must be > 0");
            if (chunk_count > assets::MAX_ZK_CHUNKS) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("chunk_count exceeds MAX_ZK_CHUNKS (%u)", assets::MAX_ZK_CHUNKS));
            }
            if (chunk_index >= chunk_count) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "chunk_index must be < chunk_count");
            }

            std::string data_hex = request.params[6].get_str();
            auto data = ParseHex(data_hex);
            if (data.empty()) throw JSONRPCError(RPC_INVALID_PARAMETER, "chunk data cannot be empty");
            if (data.size() > assets::MAX_ZK_CHUNK_SIZE) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("chunk data exceeds MAX_ZK_CHUNK_SIZE (%u)", assets::MAX_ZK_CHUNK_SIZE));
            }

            CMutableTransaction mtx;
            if (!DecodeHexTx(mtx, hex, /*try_no_witness=*/true, /*try_witness=*/true)) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
            }
            if (vout < 0 || (size_t)vout >= mtx.vout.size()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "vout index out of range");
            }

            // Build ZK_PARAMS_CHUNK payload
            std::vector<unsigned char> payload;
            payload.reserve(32 + 32 + 2 + 2 + data.size());

            // asset_id (32 bytes)
            payload.insert(payload.end(), asset_id->begin(), asset_id->end());
            // vk_hash (32 bytes)
            payload.insert(payload.end(), vk_hash->begin(), vk_hash->end());

            // chunk_index (2 bytes LE)
            unsigned char idx_buf[2];
            WriteLE16(idx_buf, chunk_index);
            payload.insert(payload.end(), idx_buf, idx_buf + 2);

            // chunk_count (2 bytes LE)
            unsigned char cnt_buf[2];
            WriteLE16(cnt_buf, chunk_count);
            payload.insert(payload.end(), cnt_buf, cnt_buf + 2);

            // data (variable length)
            payload.insert(payload.end(), data.begin(), data.end());

            // Build TLV
            std::vector<unsigned char> tlv;
            tlv.push_back(static_cast<uint8_t>(assets::OutExtType::ZK_PARAMS_CHUNK));

            VectorWriter tlv_writer(tlv, tlv.size());
            WriteCompactSize(tlv_writer, payload.size());
            tlv.insert(tlv.end(), payload.begin(), payload.end());

            mtx.vout[vout].vExt = std::move(tlv);
            DataStream out; out << TX_WITH_WITNESS(mtx);
            return HexStr(out);
        }
    };
}

static RPCHelpMan getassetpolicy()
{
    return RPCHelpMan{"getassetpolicy",
        "Return the policy entry for a given asset_id or ticker from the registry (if present)",
        {
            {"asset_id_or_ticker", RPCArg::Type::STR, RPCArg::Optional::NO, "Asset ID (32-byte hex) or ticker (root, or one-hop child ROOT.SUFFIX)"},
            {"include_history", RPCArg::Type::BOOL, RPCArg::Default{false}, "Include governance rotation history"},
        },
        // Either an object (when found) or null (when not found)
        RPCResults{
            RPCResult{RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::STR, "asset_id", "asset id"},
                    {RPCResult::Type::NUM, "policy_bits", "policy bits"},
                    {RPCResult::Type::NUM, "allowed_spk_families", "allowed script family mask"},
                    {RPCResult::Type::STR_HEX, "icu_txid", "ICU txid"},
                    {RPCResult::Type::NUM, "icu_vout", "ICU vout"},
                    {RPCResult::Type::NUM, "unlock_fees_sats", "unlock threshold in sats"},
                    {RPCResult::Type::NUM, "fees_accum_sats", "accumulated fees in sats"},
                    {RPCResult::Type::NUM, "rotation_min_sats", "minimum rotation value in sats"},
                    {RPCResult::Type::BOOL, "is_unlocked", "whether bond has been unlocked"},
                    {RPCResult::Type::NUM, "issued_total", "cumulative minted units"},
                    {RPCResult::Type::NUM, "burned_total", "cumulative burned units"},
                    {RPCResult::Type::STR, "ticker", /*optional=*/true, "asset ticker if set"},
                    {RPCResult::Type::NUM, "decimals", /*optional=*/true, "decimals if set"},
                    {RPCResult::Type::BOOL, "has_kyc", "ZK/KYC enforcement enabled"},
                    {RPCResult::Type::STR_HEX, "zk_vk_commitment", "ZK verifying key commitment"},
                    {RPCResult::Type::NUM, "max_root_age", "Maximum KYC root age in blocks"},
                    {RPCResult::Type::NUM, "tfr_flags", "Transfer flags (e.g., TFR_ANCHOR_REQUIRED)"},
                    {RPCResult::Type::STR_HEX, "compliance_root_commit", /*optional=*/true, "Compliance Merkle root commitment (32-byte hex)"},
                    {RPCResult::Type::STR_HEX, "compliance_delegate_asset_id", /*optional=*/true, "Declared delegation source asset (only when delegating)"},
                    {RPCResult::Type::OBJ, "effective_kyc_policy", /*optional=*/true, "Resolved effective policy when delegating (identity material from the source asset)",
                        {
                            {RPCResult::Type::BOOL, "ok", "Whether delegation resolves (else the spend fails closed)"},
                            {RPCResult::Type::STR, "reason", /*optional=*/true, "Consensus reject reason when ok=false"},
                            {RPCResult::Type::STR_HEX, "source_asset_id", /*optional=*/true, "Effective source asset"},
                            {RPCResult::Type::STR_HEX, "vk_commitment", /*optional=*/true, "Effective VK (from source)"},
                            {RPCResult::Type::STR_HEX, "compliance_root_commit", /*optional=*/true, "Effective root (from source)"},
                            {RPCResult::Type::NUM, "max_root_age", /*optional=*/true, "Effective max_root_age = min(source, follower)"},
                            {RPCResult::Type::NUM, "active_root_activation_height", /*optional=*/true, "Source active-root activation height (heartbeat)"},
                        }
                    },
                    {RPCResult::Type::NUM, "icu_flags", "ICU structural flags (e.g., WRAP_REQUIRED)"},
                    {RPCResult::Type::NUM, "icu_visibility", "ICU visibility (0=public, 1=holder_only)"},
                    {RPCResult::Type::NUM, "issuance_cap_units", "Issuance cap (0=unlimited)"},
                    {RPCResult::Type::STR_HEX, "icu_ctxt_commit", "SHA256 of ICU ciphertext"},
                    {RPCResult::Type::STR_HEX, "icu_plain_commit", "SHA256 of canonical plaintext"},
                    {RPCResult::Type::STR_HEX, "kdf_salt", "16-byte encryption salt"},
                    {RPCResult::Type::NUM, "policy_quorum_bps", "Governance quorum in basis points (0=immutable)"},
                    {RPCResult::Type::NUM, "policy_epoch", "Wallet advisory version counter"},
                    {RPCResult::Type::STR_HEX, "core_policy_commit", "SHA256 of immutable core policy"},
                    {RPCResult::Type::ARR, "rotation_history", /*optional=*/true, "Historical governance snapshots (only if include_history=true)",
                        {
                            {RPCResult::Type::OBJ, "", "",
                                {
                                    {RPCResult::Type::NUM, "policy_epoch", "Epoch number for this snapshot"},
                                    {RPCResult::Type::NUM, "block_height", "Block height when rotation occurred"},
                                    {RPCResult::Type::STR_HEX, "rotation_txid", "Transaction that rotated to next state"},
                                    {RPCResult::Type::NUM, "timestamp", "Block timestamp (Unix epoch)"},
                                    {RPCResult::Type::NUM, "policy_quorum_bps", "Quorum at this epoch"},
                                    {RPCResult::Type::NUM, "issuance_cap_units", "Issuance cap at this epoch"},
                                    {RPCResult::Type::STR_HEX, "icu_ctxt_commit", "ICU ciphertext commitment (for historical text lookup)"},
                                    {RPCResult::Type::STR_HEX, "icu_plain_commit", "ICU plaintext commitment"},
                                }
                            }
                        }
                    },
                }
            },
            RPCResult{RPCResult::Type::NONE, "", "asset entry not found"},
        },
        RPCExamples{
            HelpExampleCli("getassetpolicy", "\"<asset_id>\"") +
            HelpExampleCli("getassetpolicy", "\"GOLD\"") +
            HelpExampleCli("getassetpolicy", "\"GOLD\" true")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            std::string identifier = request.params[0].get_str();
            uint256 asset_id;

            // Try as hex asset_id first
            auto aid = uint256::FromHex(identifier);
            if (aid) {
                asset_id = *aid;
            } else {
                // Try as ticker - uppercase it
                std::string ticker = identifier;
                for (char& c : ticker) {
                    if (c >= 'a' && c <= 'z') c = char(c - 32);
                }

                // Validate ticker grammar via the shared gate: a bare root, or a one-hop
                // sponsored child (ROOT.SUFFIX). Sharing it with the consensus parser is what
                // lets a registered child ticker resolve here (ICU_CHILD.md §5.1, §6.2).
                if (!assets::IsTickerValidForIssuerReg(ticker)) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid asset_id hex or ticker");
                }

                ChainstateManager& chainman = EnsureAnyChainman(request.context);
                LOCK(cs_main);
                Chainstate& active = chainman.ActiveChainstate();

                // Look up ticker
                if (!active.CoinsTip().ReadTickerBinding(ticker, asset_id)) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("Ticker not found: %s", ticker));
                }
            }

            ChainstateManager& chainman = EnsureAnyChainman(request.context);
            LOCK(cs_main);
            Chainstate& active = chainman.ActiveChainstate();
            AssetRegistryEntry e;
            UniValue out(UniValue::VOBJ);
            if (!active.CoinsTip().ReadAssetPolicy(asset_id, e)) {
                // For non-existent asset, return null (or empty object per tests)
                return UniValue();
            }
            out.pushKV("asset_id", asset_id.ToString());
            out.pushKV("policy_bits", e.policy_bits);
            out.pushKV("allowed_spk_families", e.allowed_spk_families);
            out.pushKV("icu_txid", e.icu_outpoint.hash.ToString());
            out.pushKV("icu_vout", (int64_t)e.icu_outpoint.n);
            out.pushKV("unlock_fees_sats", (uint64_t)e.unlock_fees_sats);
            out.pushKV("fees_accum_sats", (uint64_t)e.fees_accum_sats);
            out.pushKV("rotation_min_sats", (uint64_t)e.rotation_min_sats);
            out.pushKV("is_unlocked", e.IsUnlocked());
            out.pushKV("issued_total", e.issued_total);
            out.pushKV("burned_total", e.burned_total);
            if (!e.ticker.empty()) out.pushKV("ticker", e.ticker);
            if (e.decimals != 255) out.pushKV("decimals", (int)e.decimals);

            // ZK fields
            out.pushKV("has_kyc", e.has_kyc);
            out.pushKV("zk_vk_commitment", e.zk_vk_commitment.ToString());
            out.pushKV("max_root_age", e.max_root_age);
            out.pushKV("tfr_flags", e.tfr_flags);
            if (!e.compliance_root_commit.IsNull()) {
                out.pushKV("compliance_root_commit", e.compliance_root_commit.ToString());
            }

            // Delegated / reusable KYC: the declared delegate pointer plus the
            // resolved EFFECTIVE policy (identity material from the source asset A,
            // asset id + tfr kept on B). See REUSABLE_KYC.md.
            if (!e.compliance_delegate_asset_id.IsNull()) {
                out.pushKV("compliance_delegate_asset_id", e.compliance_delegate_asset_id.ToString());
                AssetRegistryEntry src;
                const bool have_src = (e.compliance_delegate_asset_id != asset_id) &&
                    active.CoinsTip().ReadAssetPolicy(e.compliance_delegate_asset_id, src);
                const auto eff = assets::ResolveEffectiveKycPolicy(
                    asset_id, e, have_src ? &src : nullptr, assets::IsCanonicalVk);
                UniValue effobj(UniValue::VOBJ);
                effobj.pushKV("ok", eff.ok);
                if (!eff.ok) {
                    effobj.pushKV("reason", eff.reason);
                } else {
                    effobj.pushKV("source_asset_id", eff.source_asset_id.ToString());
                    effobj.pushKV("vk_commitment", eff.vk_commitment.ToString());
                    if (!eff.compliance_root_commit.IsNull()) {
                        effobj.pushKV("compliance_root_commit", eff.compliance_root_commit.ToString());
                    }
                    effobj.pushKV("max_root_age", eff.max_root_age);
                    effobj.pushKV("active_root_activation_height", eff.active_root_activation_height);
                }
                out.pushKV("effective_kyc_policy", effobj);
            }

            // ICU governance fields
            out.pushKV("icu_flags", e.icu_flags);
            out.pushKV("icu_visibility", (int)e.icu_visibility);
            out.pushKV("issuance_cap_units", e.issuance_cap_units);
            out.pushKV("icu_ctxt_commit", e.icu_ctxt_commit.ToString());
            out.pushKV("icu_plain_commit", e.icu_plain_commit.ToString());
            out.pushKV("kdf_salt", HexStr(e.kdf_salt));
            out.pushKV("policy_quorum_bps", e.policy_quorum_bps);
            out.pushKV("policy_epoch", (int)e.policy_epoch);
            out.pushKV("core_policy_commit", e.core_policy_commit.ToString());

            // Rotation history (optional, controlled by include_history parameter)
            bool include_history = request.params.size() > 1 && request.params[1].get_bool();
            if (include_history && !e.rotation_history.empty()) {
                UniValue history_arr(UniValue::VARR);
                for (const auto& snap : e.rotation_history) {
                    UniValue obj(UniValue::VOBJ);
                    obj.pushKV("policy_epoch", (int)snap.policy_epoch);
                    obj.pushKV("block_height", snap.block_height);
                    obj.pushKV("rotation_txid", snap.rotation_txid.ToString());
                    obj.pushKV("timestamp", (uint64_t)snap.timestamp);
                    obj.pushKV("policy_quorum_bps", (int)snap.policy_quorum_bps);
                    obj.pushKV("issuance_cap_units", snap.issuance_cap_units);
                    obj.pushKV("icu_ctxt_commit", snap.icu_ctxt_commit.ToString());
                    obj.pushKV("icu_plain_commit", snap.icu_plain_commit.ToString());
                    history_arr.push_back(obj);
                }
                out.pushKV("rotation_history", history_arr);
            }

            return out;
        }
    };
}

static RPCHelpMan geticupayload_historical()
{
    return RPCHelpMan{"geticupayload_historical",
        "Retrieve historical ICU payload for a given asset by explicit icu_ctxt_commit.\n"
        "Use this to fetch governance text from prior epochs (available via getassetpolicy rotation_history).",
        {
            {"asset_id_or_ticker", RPCArg::Type::STR, RPCArg::Optional::NO, "Asset ID (32-byte hex) or ticker symbol"},
            {"icu_ctxt_commit", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "ICU ciphertext commitment (32-byte hex) from rotation history"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "icu_cipher", "Encrypted ICU payload (holder-only assets)"},
                {RPCResult::Type::STR_HEX, "canonical_hash", "SHA256 of canonical plaintext"},
                {RPCResult::Type::NUM, "compression", "Compression mode (0=none, 1=zstd)"},
                {RPCResult::Type::NUM, "encryption_mode", "Encryption mode (0=none, 1=AES-GCM, 2=XChaCha20)"},
                {RPCResult::Type::NUM, "visibility", "Visibility (0=public, 1=holder_only)"},
            }
        },
        RPCExamples{
            HelpExampleCli("geticupayload_historical", "\"<asset_id>\" \"<icu_ctxt_commit>\"") +
            HelpExampleCli("geticupayload_historical", "\"GOLD\" \"a1b2c3...\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            std::string identifier = request.params[0].get_str();
            uint256 asset_id;

            // Try as hex asset_id first
            auto aid = uint256::FromHex(identifier);
            if (aid) {
                asset_id = *aid;
            } else {
                // Try as ticker - uppercase it
                std::string ticker = identifier;
                for (char& c : ticker) {
                    if (c >= 'a' && c <= 'z') c = char(c - 32);
                }

                // Validate ticker grammar via the shared gate (root or one-hop child
                // ROOT.SUFFIX) so registered child tickers resolve (ICU_CHILD.md §5.1).
                if (!assets::IsTickerValidForIssuerReg(ticker)) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid asset_id hex or ticker");
                }

                ChainstateManager& chainman = EnsureAnyChainman(request.context);
                LOCK(cs_main);
                Chainstate& active = chainman.ActiveChainstate();

                // Look up ticker
                if (!active.CoinsTip().ReadTickerBinding(ticker, asset_id)) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("Ticker not found: %s", ticker));
                }
            }

            // Parse icu_ctxt_commit
            auto commit_opt = uint256::FromHex(request.params[1].get_str());
            if (!commit_opt) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid icu_ctxt_commit hex");
            }
            uint256 icu_ctxt_commit = *commit_opt;

            // Read ICU payload from database
            ChainstateManager& chainman = EnsureAnyChainman(request.context);
            LOCK(cs_main);
            Chainstate& active = chainman.ActiveChainstate();
            assets::IcuStorageEntry entry;
            if (!active.CoinsTip().ReadIcuPayload(asset_id, icu_ctxt_commit, entry)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                    strprintf("ICU payload not found for asset=%s commit=%s",
                              asset_id.ToString(), icu_ctxt_commit.ToString()));
            }

            // Build result
            UniValue out(UniValue::VOBJ);
            out.pushKV("icu_cipher", HexStr(entry.icu_cipher));
            out.pushKV("canonical_hash", entry.canonical_hash.ToString());
            out.pushKV("compression", (int)entry.compression);
            out.pushKV("encryption_mode", (int)entry.encryption_mode);
            out.pushKV("visibility", (int)entry.visibility);

            return out;
        }
    };
}

static RPCHelpMan geticupayload_prior()
{
    return RPCHelpMan{"geticupayload_prior",
        "Retrieve the ICU payload from the immediately prior epoch (convenience wrapper for geticupayload_historical).\n"
        "Returns the previous governance document if the asset has been rotated at least once.",
        {
            {"asset_id_or_ticker", RPCArg::Type::STR, RPCArg::Optional::NO, "Asset ID (32-byte hex) or ticker symbol"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "icu_cipher", "Encrypted ICU payload (holder-only assets)"},
                {RPCResult::Type::STR_HEX, "canonical_hash", "SHA256 of canonical plaintext"},
                {RPCResult::Type::NUM, "compression", "Compression mode (0=none, 1=zstd)"},
                {RPCResult::Type::NUM, "encryption_mode", "Encryption mode (0=none, 1=AES-GCM, 2=XChaCha20)"},
                {RPCResult::Type::NUM, "visibility", "Visibility (0=public, 1=holder_only)"},
                {RPCResult::Type::NUM, "policy_epoch", "The epoch number for this prior snapshot"},
                {RPCResult::Type::STR_HEX, "icu_ctxt_commit", "The commit hash for this payload"},
            }
        },
        RPCExamples{
            HelpExampleCli("geticupayload_prior", "\"<asset_id>\"") +
            HelpExampleCli("geticupayload_prior", "\"GOLD\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            std::string identifier = request.params[0].get_str();
            uint256 asset_id;

            // Try as hex asset_id first
            auto aid = uint256::FromHex(identifier);
            if (aid) {
                asset_id = *aid;
            } else {
                // Try as ticker - uppercase it
                std::string ticker = identifier;
                for (char& c : ticker) {
                    if (c >= 'a' && c <= 'z') c = char(c - 32);
                }

                // Validate ticker grammar via the shared gate (root or one-hop child
                // ROOT.SUFFIX) so registered child tickers resolve (ICU_CHILD.md §5.1).
                if (!assets::IsTickerValidForIssuerReg(ticker)) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid asset_id hex or ticker");
                }

                ChainstateManager& chainman = EnsureAnyChainman(request.context);
                LOCK(cs_main);
                Chainstate& active = chainman.ActiveChainstate();

                // Look up ticker
                if (!active.CoinsTip().ReadTickerBinding(ticker, asset_id)) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("Ticker not found: %s", ticker));
                }
            }

            // Read current policy with rotation history
            ChainstateManager& chainman = EnsureAnyChainman(request.context);
            LOCK(cs_main);
            Chainstate& active = chainman.ActiveChainstate();
            AssetRegistryEntry e;
            if (!active.CoinsTip().ReadAssetPolicy(asset_id, e)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                    strprintf("Asset not found: %s", asset_id.ToString()));
            }

            // Check if there's any prior epoch
            if (e.policy_epoch == 0) {
                throw JSONRPCError(RPC_INVALID_REQUEST,
                    strprintf("Asset %s has not been rotated yet (policy_epoch=0). No prior ICU to retrieve.",
                              asset_id.ToString()));
            }

            if (e.rotation_history.empty()) {
                throw JSONRPCError(RPC_INVALID_REQUEST,
                    strprintf("Asset %s has policy_epoch=%u but rotation_history is empty. "
                              "Cannot retrieve prior ICU without history.",
                              asset_id.ToString(), e.policy_epoch));
            }

            // Get the most recent prior epoch (last entry in rotation_history)
            const auto& prior_snap = e.rotation_history.back();
            uint256 icu_ctxt_commit = prior_snap.icu_ctxt_commit;

            // Read ICU payload from database
            assets::IcuStorageEntry entry;
            if (!active.CoinsTip().ReadIcuPayload(asset_id, icu_ctxt_commit, entry)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                    strprintf("Prior ICU payload not found for asset=%s commit=%s (epoch=%u)",
                              asset_id.ToString(), icu_ctxt_commit.ToString(), prior_snap.policy_epoch));
            }

            // Build result
            UniValue out(UniValue::VOBJ);
            out.pushKV("icu_cipher", HexStr(entry.icu_cipher));
            out.pushKV("canonical_hash", entry.canonical_hash.ToString());
            out.pushKV("compression", (int)entry.compression);
            out.pushKV("encryption_mode", (int)entry.encryption_mode);
            out.pushKV("visibility", (int)entry.visibility);
            out.pushKV("policy_epoch", (int)prior_snap.policy_epoch);
            out.pushKV("icu_ctxt_commit", icu_ctxt_commit.ToString());

            return out;
        }
    };
}

static RPCHelpMan getassetbyticker()
{
    return RPCHelpMan{"getassetbyticker",
        "Lookup an asset by its consensus ticker.",
        {
            {"ticker", RPCArg::Type::STR, RPCArg::Optional::NO, "Ticker: root [A-Z][A-Z0-9]{2,10}, or one-hop child ROOT.SUFFIX"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "asset_id", "asset id"},
                {RPCResult::Type::STR, "ticker", "ticker symbol"},
                {RPCResult::Type::NUM, "decimals", "decimal places"},
            }
        },
        RPCExamples{HelpExampleCli("getassetbyticker", "ABC")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            std::string ticker = request.params[0].get_str();
            for (char& c : ticker) if (c >= 'a' && c <= 'z') c = char(c - 32);
            ChainstateManager& chainman = EnsureAnyChainman(request.context);
            LOCK(cs_main);
            Chainstate& active = chainman.ActiveChainstate();
            uint256 aid;
            if (!active.CoinsTip().ReadTickerBinding(ticker, aid)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "ticker not found");
            }

            // Read full asset registry entry to get decimals
            AssetRegistryEntry e;
            if (!active.CoinsTip().ReadAssetPolicy(aid, e)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "asset registry entry not found");
            }

            UniValue out(UniValue::VOBJ);
            out.pushKV("asset_id", aid.ToString());
            out.pushKV("ticker", e.ticker);
            out.pushKV("decimals", e.decimals == 255 ? 0 : (int64_t)e.decimals);
            return out;
        }
    };
}

static RPCHelpMan listregisteredassets()
{
    return RPCHelpMan{"listregisteredassets",
        "List every asset in the consensus asset registry, node-wide.\n"
        "\n"
        "Reads the on-disk registry index directly (the DB_ASSET_REG keyspace of the\n"
        "coins database) — it does NOT scan the block chain. This is the authoritative\n"
        "set of registered assets the node maintains for consensus.\n"
        "\n"
        "The result reflects the registry as of the last chainstate flush to disk, so an\n"
        "asset registered in a not-yet-flushed block at the tip may appear after the next\n"
        "flush. Per-asset detail (ticker, decimals, policy) is read from the live\n"
        "chainstate view and is always current. Use getassetinfo / geticuinfo for the\n"
        "full registry entry and ICU document of an individual asset.",
        {
            {"verbose", RPCArg::Type::BOOL, RPCArg::Default{true},
             "If true, include ticker/decimals/policy_bits for each asset. If false, return asset ids only."},
        },
        {
            RPCResult{"if verbose=true",
                RPCResult::Type::ARR, "", "",
                {
                    {RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::STR_HEX, "asset_id", "The 32-byte asset identifier (hex)"},
                            {RPCResult::Type::STR, "ticker", /*optional=*/true, "The consensus ticker symbol; omitted if the asset has none"},
                            {RPCResult::Type::NUM, "decimals", /*optional=*/true, "Number of decimal places (0 if unset)"},
                            {RPCResult::Type::NUM, "policy_bits", /*optional=*/true, "Policy bitfield governing the asset"},
                        }
                    },
                }
            },
            RPCResult{"if verbose=false",
                RPCResult::Type::ARR, "", "",
                {
                    {RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::STR_HEX, "asset_id", "The 32-byte asset identifier (hex)"},
                        }
                    },
                }
            },
        },
        RPCExamples{
            "\nList all registered assets with detail\n"
            + HelpExampleCli("listregisteredassets", "")
            + "\nList only the asset ids\n"
            + HelpExampleCli("listregisteredassets", "false")
            + "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("listregisteredassets", "true")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            const bool verbose = request.params[0].isNull() ? true : request.params[0].get_bool();
            ChainstateManager& chainman = EnsureAnyChainman(request.context);
            LOCK(cs_main);
            Chainstate& active = chainman.ActiveChainstate();

            // Enumerate the on-disk registry, then reconcile with the in-memory
            // chainstate overlay so assets registered since the last periodic
            // flush (e.g. a freshly sponsored child ROOT.SUFFIX) are included —
            // matching the view ReadAssetPolicy/getassetinfo already serve.
            std::set<uint256> id_set;
            for (const uint256& aid : active.CoinsDB().GetAllRegisteredAssets()) id_set.insert(aid);
            std::vector<uint256> staged_added, staged_erased;
            active.CoinsTip().GetStagedAssetPolicyIds(staged_added, staged_erased);
            for (const uint256& aid : staged_added) id_set.insert(aid);
            for (const uint256& aid : staged_erased) id_set.erase(aid);

            UniValue arr(UniValue::VARR);
            for (const uint256& aid : id_set) {
                UniValue o(UniValue::VOBJ);
                o.pushKV("asset_id", aid.ToString());
                if (verbose) {
                    AssetRegistryEntry e;
                    if (active.CoinsTip().ReadAssetPolicy(aid, e)) {
                        if (!e.ticker.empty()) o.pushKV("ticker", e.ticker);
                        o.pushKV("decimals", e.decimals == 255 ? 0 : (int64_t)e.decimals);
                        o.pushKV("policy_bits", (int64_t)e.policy_bits);
                    }
                }
                arr.push_back(o);
            }
            return arr;
        }
    };
}

static RPCHelpMan geticuinfo()
{
    return RPCHelpMan{"geticuinfo",
        "Read ICU payload metadata from LevelDB for a given asset.\n"
        "Returns canonical_hash, witness_hash, visibility, and other metadata.\n"
        "For public assets (visibility=0), also returns the canonical_text and witness bundle.",
        {
            {"asset_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Asset ID (32-byte hex)"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "asset_id", "Asset ID"},
                {RPCResult::Type::STR_HEX, "icu_ctxt_commit", "SHA256 of stored ICU ciphertext"},
                {RPCResult::Type::STR_HEX, "icu_plain_commit", "SHA256 of canonical plaintext (from registry)"},
                {RPCResult::Type::NUM, "visibility", "0 = public, 1 = holder_only"},
                {RPCResult::Type::NUM, "compression", "0 = none, 1 = zstd"},
                {RPCResult::Type::NUM, "encryption_mode", "0 = plaintext, 1 = ChaCha20-Poly1305"},
                {RPCResult::Type::NUM, "size_bytes", "Raw payload size"},
                {RPCResult::Type::STR_HEX, "ciphertext", /*optional=*/true, "Raw encrypted ICU payload bytes (only when encryption_mode != 0); decrypt client-side with the holder DEK"},
                {RPCResult::Type::STR_HEX, "canonical_hash", "SHA256(canonical_text) - computed from payload"},
                {RPCResult::Type::STR_HEX, "witness_hash", "SHA256(witness_bundle) - computed from payload"},
                {RPCResult::Type::STR, "canonical_text", /*optional=*/true, "Canonical text (only if visibility=public and parseable)"},
                {RPCResult::Type::BOOL, "plain_commit_verified", /*optional=*/true, "Whether SHA256(canonical_text) matches the registry icu_plain_commit (only for parseable public payloads)"},
                {RPCResult::Type::STR, "warning", /*optional=*/true, "Set when plain_commit_verified is false: the document and inline context are UNVERIFIED"},
                {RPCResult::Type::OBJ, "context", /*optional=*/true, "Inline TSC-ICU-CONTEXT-1 map embedded in canonical_text (only when present and valid)", {}},
                {RPCResult::Type::STR, "context_source", /*optional=*/true, "\"inline\" when an embedded TSC-ICU-CONTEXT-1 block is present"},
                {RPCResult::Type::STR, "context_error", /*optional=*/true, "Reason the embedded context block is malformed (when present but invalid)"},
                {RPCResult::Type::STR, "witness_bundle", /*optional=*/true, "Witness bundle (only if visibility=public and parseable)"},
            }
        },
        RPCExamples{
            HelpExampleCli("geticuinfo", "\"<asset_id>\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            std::string asset_hex = request.params[0].get_str();
            if (asset_hex.length() != 64) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "asset_id must be 64 hex chars");
            }
            auto asset_id = uint256::FromHex(asset_hex);
            if (!asset_id) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid asset_id hex");
            }

            // Read asset registry to get icu_ctxt_commit
            ChainstateManager& chainman = EnsureAnyChainman(request.context);
            LOCK(cs_main);
            Chainstate& active = chainman.ActiveChainstate();

            AssetRegistryEntry e;
            if (!active.CoinsTip().ReadAssetPolicy(*asset_id, e)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Asset not found in registry");
            }

            // Check if asset has ICU payload
            if (e.icu_ctxt_commit.IsNull()) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Asset has no ICU payload (icu_ctxt_commit is null)");
            }

            // Read ICU storage entry from LevelDB (now includes metadata)
            assets::IcuStorageEntry storage_entry;
            if (!active.CoinsTip().ReadIcuPayload(*asset_id, e.icu_ctxt_commit, storage_entry)) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "ICU payload not found in database despite icu_ctxt_commit being set");
            }

            LogPrintf("ICU_READ_DEBUG: Read IcuStorageEntry from LevelDB:\n");
            LogPrintf("  asset_id=%s commit=%s\n", asset_id->ToString(), e.icu_ctxt_commit.ToString());
            LogPrintf("  icu_cipher size=%u first_bytes=%02x %02x %02x %02x\n",
                      storage_entry.icu_cipher.size(),
                      storage_entry.icu_cipher.size() > 0 ? storage_entry.icu_cipher[0] : 0,
                      storage_entry.icu_cipher.size() > 1 ? storage_entry.icu_cipher[1] : 0,
                      storage_entry.icu_cipher.size() > 2 ? storage_entry.icu_cipher[2] : 0,
                      storage_entry.icu_cipher.size() > 3 ? storage_entry.icu_cipher[3] : 0);
            LogPrintf("  compression=%u encryption_mode=%u visibility=%u\n",
                      storage_entry.compression, storage_entry.encryption_mode, storage_entry.visibility);
            LogPrintf("  canonical_hash=%s\n", storage_entry.canonical_hash.ToString());
            LogPrintf("  witness_hash=%s\n", storage_entry.witness_hash.ToString());

            UniValue out(UniValue::VOBJ);
            out.pushKV("asset_id", asset_id->ToString());
            out.pushKV("icu_ctxt_commit", e.icu_ctxt_commit.ToString());
            out.pushKV("icu_plain_commit", e.icu_plain_commit.ToString());
            out.pushKV("visibility", (int)storage_entry.visibility);
            out.pushKV("compression", (int)storage_entry.compression);
            out.pushKV("encryption_mode", (int)storage_entry.encryption_mode);
            out.pushKV("size_bytes", (uint64_t)storage_entry.icu_cipher.size());
            // Raw stored ICU payload bytes. For encrypted (holder-only) assets
            // this is the ciphertext, so a holder can decrypt client-side with
            // their DEK (the node never sees the key) — same bytes geticupayload
            // returns, but exposed here without a wallet context.
            if (storage_entry.encryption_mode != 0) {
                out.pushKV("ciphertext", HexStr(storage_entry.icu_cipher));
            }
            out.pushKV("canonical_hash", storage_entry.canonical_hash.ToString());

            // witness_hash may be null for holder-only assets
            if (!storage_entry.witness_hash.IsNull()) {
                out.pushKV("witness_hash", storage_entry.witness_hash.ToString());
            } else {
                out.pushKV("witness_hash", "unknown");
            }

            // For public assets, parse and return plaintext content
            if (storage_entry.visibility == 0 && storage_entry.encryption_mode == 0) {
                // Decompress if necessary
                std::vector<unsigned char> plaintext_bytes;
                if (storage_entry.compression == 1) {
                    // Zstd compressed - decompress first
                    LogPrintf("geticuinfo: Decompressing ICU payload (compressed size: %d bytes)\n", storage_entry.icu_cipher.size());
                    auto decompressed = assets::DecompressZstd(storage_entry.icu_cipher);
                    if (!decompressed) {
                        throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to decompress ICU payload");
                    }
                    plaintext_bytes = *decompressed;
                    LogPrintf("geticuinfo: Decompressed to %d bytes\n", plaintext_bytes.size());
                } else {
                    // Not compressed - use as-is
                    plaintext_bytes = storage_entry.icu_cipher;
                }

                LogPrintf("geticuinfo: Parsing canonical ICU payload (%d bytes)\n", plaintext_bytes.size());
                auto parsed = assets::ParseCanonicalIcuPayload(plaintext_bytes);
                if (parsed) {
                    LogPrintf("geticuinfo: Successfully parsed canonical payload\n");
                    // Canonical text
                    std::string canonical_text_str(
                        parsed->canonical_text.begin(),
                        parsed->canonical_text.end()
                    );
                    out.pushKV("canonical_text", canonical_text_str);

                    // Recompute-or-refuse: storage_entry.canonical_hash is the declared registry
                    // icu_plain_commit; confirm it matches SHA256(canonical_text) before the inline
                    // clauses below are treated as authentic (consensus never checks this).
                    {
                        const bool plain_ok = assets::VerifyIcuPlainCommit(*parsed, storage_entry.canonical_hash);
                        out.pushKV("plain_commit_verified", plain_ok);
                        if (!plain_ok) {
                            out.pushKV("warning",
                                "declared icu_plain_commit does not match SHA256(canonical_text); "
                                "document and inline context are UNVERIFIED");
                        }
                    }

                    // Inline TSC-ICU-CONTEXT-1 block (Option A): the authoritative clause map lives
                    // inside canonical_text under icu_plain_commit. Surface it read-only -- never
                    // throw on a malformed block, just report the error field.
                    {
                        std::string norm_text = canonical_text_str;
                        if (auto normalized = assets::NormalizeCanonicalText(canonical_text_str)) {
                            norm_text = *normalized;
                        }
                        bool ctx_present = false;
                        std::string ctx_error;
                        auto ctx = assets::ExtractInlineIcuContext(norm_text, ctx_present, ctx_error);
                        if (ctx_present) {
                            out.pushKV("context_source", "inline");
                            if (ctx) {
                                out.pushKV("context", *ctx);
                            } else {
                                out.pushKV("context_error", ctx_error);
                            }
                        }
                    }

                    // Witness bundle (try to parse as JSON, otherwise return as string)
                    std::string witness_str(
                        parsed->witness_bundle.begin(),
                        parsed->witness_bundle.end()
                    );
                    out.pushKV("witness_bundle", witness_str);
                } else {
                    LogPrintf("geticuinfo: WARNING - ParseCanonicalIcuPayload returned nullopt for %d byte payload\n", plaintext_bytes.size());
                }
            }

            return out;
        }
    };
}

static RPCHelpMan decrypticupayload()
{
    return RPCHelpMan{"decrypticupayload",
        "Decrypt a holder-only ICU payload using a DEK (Data Encryption Key).\n"
        "This RPC decrypts an encrypted ICU payload stored in LevelDB and returns the plaintext canonical structure.\n"
        "In production, the wallet would unwrap the DEK from ICU_KEYWRAP using ECDH. For testing, DEK can be provided directly.",
        {
            {"asset_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Asset ID (32-byte hex)"},
            {"dek", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "32-byte Data Encryption Key as hex (unwrapped from ICU_KEYWRAP by wallet)"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "asset_id", "Asset ID"},
                {RPCResult::Type::STR, "canonical_text", "Decrypted canonical text (UTF-8)"},
                {RPCResult::Type::OBJ, "context", /*optional=*/true, "Inline TSC-ICU-CONTEXT-1 map embedded in canonical_text (only when present and valid)", {}},
                {RPCResult::Type::STR, "context_source", /*optional=*/true, "\"inline\" when an embedded TSC-ICU-CONTEXT-1 block is present"},
                {RPCResult::Type::STR, "context_error", /*optional=*/true, "Reason the embedded context block is malformed (when present but invalid)"},
                {RPCResult::Type::STR, "witness_bundle", "Decrypted witness bundle (JSON)"},
                {RPCResult::Type::NUM, "visibility", "0 = public, 1 = holder_only"},
                {RPCResult::Type::NUM, "compression", "0 = none, 1 = zstd"},
                {RPCResult::Type::NUM, "encryption_mode", "0 = plaintext, 1 = ChaCha20-Poly1305"},
                {RPCResult::Type::STR_HEX, "canonical_hash", "SHA256(canonical_text)"},
                {RPCResult::Type::STR_HEX, "witness_hash", "SHA256(witness_bundle)"},
                {RPCResult::Type::STR_HEX, "recomputed_canonical_hash", "SHA256(NormalizeCanonicalText(canonical_text)) - recompute-or-refuse value"},
                {RPCResult::Type::BOOL, "plain_commit_verified", /*optional=*/true, "Whether the recomputed canonical hash matches the registry icu_plain_commit (only when the registry value is set)"},
            }
        },
        RPCExamples{
            HelpExampleCli("decrypticupayload", "\"<asset_id>\" \"<64-char-hex-dek>\"") +
            HelpExampleRpc("decrypticupayload", "\"<asset_id>\", \"<64-char-hex-dek>\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            // Parse asset_id
            std::optional<uint256> asset_id = ParseHashV(request.params[0], "asset_id");

            // Parse DEK
            std::string dek_hex = request.params[1].get_str();
            if (dek_hex.length() != 64) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "dek must be exactly 64 hex characters (32 bytes)");
            }
            auto dek_bytes = ParseHex(dek_hex);
            if (dek_bytes.size() != 32) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid dek hex");
            }
            std::array<unsigned char, 32> dek;
            std::copy(dek_bytes.begin(), dek_bytes.end(), dek.begin());

            if (!asset_id) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid asset_id");
            }

            // Get chainman and active chainstate
            const NodeContext& node = EnsureAnyNodeContext(request.context);
            ChainstateManager& chainman = EnsureChainman(node);
            LOCK(cs_main);
            Chainstate& active = chainman.ActiveChainstate();

            // Get asset policy from registry
            AssetRegistryEntry e;
            if (!active.CoinsTip().ReadAssetPolicy(*asset_id, e)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Asset not found in registry");
            }

            // Check visibility
            if (e.icu_visibility == 0) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Asset ICU is public - no decryption needed. Use geticuinfo instead.");
            }

            // Check if asset has ICU payload
            if (e.icu_ctxt_commit.IsNull()) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Asset has no ICU payload (icu_ctxt_commit is null)");
            }

            // Read ICU storage entry from LevelDB (includes metadata)
            assets::IcuStorageEntry storage_entry;
            if (!active.CoinsTip().ReadIcuPayload(*asset_id, e.icu_ctxt_commit, storage_entry)) {
                throw JSONRPCError(RPC_DATABASE_ERROR, "ICU payload not found in database despite icu_ctxt_commit being set");
            }

            // Use stored encryption parameters from metadata
            uint8_t encryption_mode = storage_entry.encryption_mode;
            uint8_t compression = storage_entry.compression;

            // For holder-only assets with unknown compression, try both 0 and 1
            bool try_both_compression = (storage_entry.visibility == 1 && storage_entry.compression == 0);

            // Convert kdf_salt from registry to array
            std::array<unsigned char, 16> kdf_salt;
            std::copy_n(e.kdf_salt.begin(), 16, kdf_salt.begin());

            // Decrypt the payload
            auto decrypted = assets::DecryptCanonicalIcuPayload(
                storage_entry.icu_cipher,
                dek,
                kdf_salt,
                encryption_mode,
                compression
            );

            // If decryption failed and we should try alternate compression, retry
            if (!decrypted && try_both_compression) {
                compression = 1;  // Try with compression enabled
                decrypted = assets::DecryptCanonicalIcuPayload(
                    storage_entry.icu_cipher,
                    dek,
                    kdf_salt,
                    encryption_mode,
                    compression
                );
            }

            if (!decrypted) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Decryption failed - incorrect DEK or corrupted payload");
            }

            // Build response
            UniValue out(UniValue::VOBJ);
            out.pushKV("asset_id", asset_id->ToString());

            // Convert canonical_text to string
            std::string canonical_text_str(decrypted->canonical_text.begin(), decrypted->canonical_text.end());
            out.pushKV("canonical_text", canonical_text_str);

            // Inline TSC-ICU-CONTEXT-1 block (Option A): the authoritative clause map lives inside
            // canonical_text under icu_plain_commit. Surface it read-only -- never throw on a
            // malformed block, just report the error field.
            {
                std::string norm_text = canonical_text_str;
                if (auto normalized = assets::NormalizeCanonicalText(canonical_text_str)) {
                    norm_text = *normalized;
                }
                bool ctx_present = false;
                std::string ctx_error;
                auto ctx = assets::ExtractInlineIcuContext(norm_text, ctx_present, ctx_error);
                if (ctx_present) {
                    out.pushKV("context_source", "inline");
                    if (ctx) {
                        out.pushKV("context", *ctx);
                    } else {
                        out.pushKV("context_error", ctx_error);
                    }
                }
            }

            // Convert witness_bundle to string (should be JSON)
            std::string witness_str(decrypted->witness_bundle.begin(), decrypted->witness_bundle.end());
            out.pushKV("witness_bundle", witness_str);

            out.pushKV("visibility", decrypted->visibility);
            out.pushKV("compression", decrypted->compression);
            out.pushKV("encryption_mode", decrypted->encryption_mode);

            // Compute hashes
            out.pushKV("canonical_hash", decrypted->GetCanonicalHash().ToString());
            out.pushKV("witness_hash", decrypted->GetWitnessHash().ToString());

            // Recompute-or-refuse gate: consensus stores icu_plain_commit without verifying it,
            // so compare the decrypted document's recomputed canonical hash against the registry's
            // declared icu_plain_commit. A holder MUST treat plain_commit_verified=false as a
            // non-authentic document.
            out.pushKV("recomputed_canonical_hash", decrypted->GetCanonicalHash().ToString());
            if (!e.icu_plain_commit.IsNull()) {
                out.pushKV("plain_commit_verified",
                           assets::VerifyIcuPlainCommit(*decrypted, e.icu_plain_commit));
            }

            return out;
        }
    };
}

static std::vector<RPCResult> DecodeTxDoc(const std::string& txid_field_doc)
{
    return {
        {RPCResult::Type::STR_HEX, "txid", txid_field_doc},
        {RPCResult::Type::STR_HEX, "hash", "The transaction hash (differs from txid for witness transactions)"},
        {RPCResult::Type::NUM, "size", "The serialized transaction size"},
        {RPCResult::Type::NUM, "vsize", "The virtual transaction size (differs from size for witness transactions)"},
        {RPCResult::Type::NUM, "weight", "The transaction's weight (between vsize*4-3 and vsize*4)"},
        {RPCResult::Type::NUM, "version", "The version"},
        {RPCResult::Type::NUM_TIME, "locktime", "The lock time"},
        {RPCResult::Type::ARR, "vin", "",
        {
            {RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "coinbase", /*optional=*/true, "The coinbase value (only if coinbase transaction)"},
                {RPCResult::Type::STR_HEX, "txid", /*optional=*/true, "The transaction id (if not coinbase transaction)"},
                {RPCResult::Type::NUM, "vout", /*optional=*/true, "The output number (if not coinbase transaction)"},
                {RPCResult::Type::OBJ, "scriptSig", /*optional=*/true, "The script (if not coinbase transaction)",
                {
                    {RPCResult::Type::STR, "asm", "Disassembly of the signature script"},
                    {RPCResult::Type::STR_HEX, "hex", "The raw signature script bytes, hex-encoded"},
                }},
                {RPCResult::Type::ARR, "txinwitness", /*optional=*/true, "",
                {
                    {RPCResult::Type::STR_HEX, "hex", "hex-encoded witness data (if any)"},
                }},
                {RPCResult::Type::NUM, "sequence", "The script sequence number"},
            }},
        }},
        {RPCResult::Type::ARR, "vout", "",
        {
            {RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_AMOUNT, "value", "The value in " + CURRENCY_UNIT},
                {RPCResult::Type::NUM, "n", "index"},
                {RPCResult::Type::OBJ, "scriptPubKey", "", ScriptPubKeyDoc()},
                // TensorCash: per-output extension TLV (vExt) as hex when present
                {RPCResult::Type::STR_HEX, "outext", /*optional=*/true, "Output extension TLV (hex), if present"},
            }},
        }},
    };
}

static RPCHelpMan registerasset()
{
    return RPCHelpMan{"registerasset",
        "Create a raw IssuerReg registration transaction (unsigned).",
        {
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "ICU destination address"},
            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "ICU BTC amount"},
            {"asset_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "32-byte asset id hex"},
            {"policy_bits", RPCArg::Type::NUM, RPCArg::Optional::NO, "Policy bits (u32)"},
            {"allowed_spk_families", RPCArg::Type::NUM, RPCArg::Default{assets::SPK_DEFAULT_ALLOWED}, "Allowed script families (u16)"},
            {"unlock_fees_sats", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Unlock threshold sats"},
            {"ticker", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Ticker [A-Z0-9]{3,11}, first letter"},
            {"decimals", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Decimals (0..18)"},
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Options",
                {
                    {"autofund", RPCArg::Type::BOOL, RPCArg::Default{false}, "Automatically fund using loaded wallet"},
                    {"broadcast", RPCArg::Type::BOOL, RPCArg::Default{false}, "Broadcast after signing with loaded wallet"},
                    {"fee_rate", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Fee rate in sat/vB"},
                    {"replaceable", RPCArg::Type::BOOL, RPCArg::DefaultHint{"wallet default"}, "Signal RBF"},
                    {"psbt", RPCArg::Type::BOOL, RPCArg::Default{false}, "Return a PSBT instead of raw hex when a wallet is loaded"},
                    {"sign", RPCArg::Type::BOOL, RPCArg::Default{true}, "Attempt signing the PSBT when psbt=true and wallet is loaded"},
                    {"finalize", RPCArg::Type::BOOL, RPCArg::Default{false}, "Finalize & return hex if signing completed (psbt=true)"},
                }
            },
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "hex", "Raw transaction hex (may be funded/signed depending on options and wallet)"},
                {RPCResult::Type::STR_HEX, "txid", /*optional=*/true, "Broadcast txid if broadcast=true"},
            }
        },
        RPCExamples{HelpExampleCli("registerasset", "<address> 1.0 <asset_id> 3 28 10000 ABC 8")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            CTxDestination dest = DecodeDestination(request.params[0].get_str());
            if (!IsValidDestination(dest)) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
            CAmount amt = AmountFromValue(request.params[1]);
            auto aid = uint256::FromHex(request.params[2].get_str());
            if (!aid) throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid asset_id hex");
            uint32_t policy_bits = request.params[3].getInt<uint32_t>();
            uint16_t allowed = request.params[4].isNull() ? assets::SPK_DEFAULT_ALLOWED : request.params[4].getInt<uint16_t>();
            bool has_unlock = (request.params.size() > 5) && !request.params[5].isNull();
            uint64_t unlock = has_unlock ? request.params[5].getInt<uint64_t>() : 0;
            bool has_ticker = (request.params.size() > 6) && !request.params[6].isNull();
            std::string ticker = has_ticker ? request.params[6].get_str() : std::string();
            bool has_decimals = (request.params.size() > 7) && !request.params[7].isNull();
            uint8_t decimals = has_decimals ? request.params[7].getInt<uint8_t>() : 0;

            CMutableTransaction mtx;
            mtx.vout.emplace_back(amt, GetScriptForDestination(dest));

            // Build IssuerReg TLV payload
            std::vector<unsigned char> payload;
            payload.reserve(32 + 4 + 2 + (has_unlock ? 8 : 0) + (has_ticker ? (1 + ticker.size() + (has_decimals ? 1 : 0)) : 0));
            payload.insert(payload.end(), aid->begin(), aid->end());
            unsigned char pb[4]; WriteLE32(pb, policy_bits); payload.insert(payload.end(), pb, pb+4);
            unsigned char ab[2]; ab[0] = allowed & 0xFF; ab[1] = (allowed >> 8) & 0xFF; payload.insert(payload.end(), ab, ab+2);
            if (has_unlock) { unsigned char ub[8]; WriteLE64(ub, unlock); payload.insert(payload.end(), ub, ub+8); }
            if (has_ticker) {
                for (char& c : ticker) if (c >= 'a' && c <= 'z') c = char(c - 32);
                // Root-only: dotted child tickers (ROOT.SUFFIX) register via sponsorchildasset,
                // not this raw registration path (ICU_CHILD.md §6.2).
                if (ticker.find('.') != std::string::npos) throw JSONRPCError(RPC_INVALID_PARAMETER, "child tickers (ROOT.SUFFIX) must use sponsorchildasset");
                if (!assets::IsRootTicker(ticker)) throw JSONRPCError(RPC_INVALID_PARAMETER, "ticker must be a root [A-Z][A-Z0-9]{2,10}");
                if (ticker == "TSC" || ticker == "XTC" || ticker == "TAK") throw JSONRPCError(RPC_INVALID_PARAMETER, "ticker is reserved");
                payload.push_back((unsigned char)ticker.size());
                payload.insert(payload.end(), ticker.begin(), ticker.end());
                if (has_decimals) {
                    if (decimals > 18) throw JSONRPCError(RPC_INVALID_PARAMETER, "decimals 0..18");
                    payload.push_back(decimals);
                }
            }
            std::vector<unsigned char> tlv; tlv.push_back((uint8_t)assets::OutExtType::ISSUER_REG);
            tlv.push_back((uint8_t)payload.size());
            tlv.insert(tlv.end(), payload.begin(), payload.end());
            mtx.vout[0].vExt = std::move(tlv);
            // Handle wallet options
            UniValue result(UniValue::VOBJ);
            std::shared_ptr<wallet::CWallet> pwallet;
            bool autofund = false, broadcast = false, want_psbt=false, do_sign=true, do_finalize=false; std::optional<double> fee_rate_vb; std::optional<bool> replaceable;
            if (!request.params[8].isNull()) {
                const UniValue& opt = request.params[8];
                autofund = opt.exists("autofund") && opt["autofund"].get_bool();
                broadcast = opt.exists("broadcast") && opt["broadcast"].get_bool();
                if (opt.exists("fee_rate")) fee_rate_vb = opt["fee_rate"].get_real();
                if (opt.exists("replaceable")) replaceable = opt["replaceable"].get_bool();
                want_psbt = opt.exists("psbt") && opt["psbt"].get_bool();
                if (opt.exists("sign")) do_sign = opt["sign"].get_bool();
                if (opt.exists("finalize")) do_finalize = opt["finalize"].get_bool();
            }
            if (autofund || broadcast || want_psbt) {
                pwallet = GetWalletForAssetsRPC(request);
            }
            if (autofund && pwallet) {
                const auto snapshots = wallet::CollectOutputExtensionSnapshots(mtx);
                wallet::CCoinControl cc;
                if (fee_rate_vb) { cc.fOverrideFeeRate = true; cc.m_feerate = CFeeRate((CAmount)(*fee_rate_vb * 1000.0)); }
                if (replaceable) cc.m_signal_bip125_rbf = *replaceable;
                if (aid) {
                    cc.m_required_asset_id = *aid;
                }
                cc.m_allow_icu_selection = true;
                cc.m_allow_other_inputs = true;
                auto txr = wallet::FundTransaction(*pwallet, mtx, /*recipients=*/{}, /*change_pos=*/std::nullopt, /*lockUnspents=*/false, cc);
                if (!txr) throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(txr).original);
                CMutableTransaction funded(*txr->tx);
                wallet::ReapplyOutputExtensionSnapshots(snapshots, funded);
                const wallet::AssetIdScanResult scan = wallet::ScanAssetIds(funded.vout);
                if (scan.conflict) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "registerasset does not yet support multiple asset ids in one call");
                }

                if (want_psbt) {
                    PartiallySignedTransaction psbtx(funded);
                    bool complete = false;
                    const auto err = pwallet->FillPSBT(psbtx, complete, SIGHASH_ALL, do_sign, /*bip32derivs=*/false);
                    if (err) throw JSONRPCPSBTError(*err);
                    if (do_finalize && complete) {
                        CMutableTransaction mfinal;
                        if (!FinalizeAndExtractPSBT(psbtx, mfinal)) throw JSONRPCError(RPC_WALLET_ERROR, "PSBT finalize failed");
                        DataStream ds; ds << TX_WITH_WITNESS(mfinal);
                        result.pushKV("hex", HexStr(ds));
                        return result;
                    }
                    DataStream ss; ss << psbtx;
                    result.pushKV("psbt", EncodeBase64(ss));
                    result.pushKV("complete", complete);
                    return result;
                }

                if (broadcast) {
                    PartiallySignedTransaction psbtx(funded);
                    bool complete = false;
                    const auto err = pwallet->FillPSBT(psbtx, complete, SIGHASH_ALL, /*sign=*/true, /*bip32derivs=*/false);
                    if (err) throw JSONRPCPSBTError(*err);
                    CMutableTransaction mfinal;
                    if (!FinalizeAndExtractPSBT(psbtx, mfinal)) {
                        throw JSONRPCError(RPC_WALLET_ERROR, "PSBT finalize failed");
                    }
                    NodeContext& node = EnsureAnyNodeContext(request.context);
                    std::string err_string;
                    const TransactionError errcode = BroadcastTransaction(node, MakeTransactionRef(CTransaction(mfinal)), err_string, /*max_tx_fee=*/0, /*relay=*/true, /*wait_callback=*/true);
                    if (errcode != TransactionError::OK) throw JSONRPCError(RPC_VERIFY_ERROR, err_string);
                    result.pushKV("txid", CTransaction(mfinal).GetHash().ToString());
                    DataStream ds; ds << TX_WITH_WITNESS(mfinal);
                    result.pushKV("hex", HexStr(ds));
                    return result;
                }

                DataStream ds; ds << TX_WITH_WITNESS(funded);
                result.pushKV("hex", HexStr(ds));
                return result;
            } else {
                DataStream ds; ds << TX_WITH_WITNESS(mtx);
                result.pushKV("hex", HexStr(ds));
                if (autofund && !pwallet) result.pushKV("warning", "No wallet loaded; returning unsigned raw tx");
                return result;
            }
        }
    };
}

static RPCHelpMan mintasset()
{
    return RPCHelpMan{"mintasset",
        "Create a raw mint transaction (unsigned): spends ICU, rotates ICU, and creates one AssetTag output.",
        {
            {"icu_txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "ICU txid"},
            {"icu_vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "ICU vout"},
            {"icu_address", RPCArg::Type::STR, RPCArg::Optional::NO, "New ICU destination"},
            {"icu_amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "New ICU BTC amount"},
            {"asset_address", RPCArg::Type::STR, RPCArg::Optional::NO, "Asset output BTC address"},
            {"asset_amount_btc", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Asset output BTC amount"},
            {"asset_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Asset id"},
            {"asset_units", RPCArg::Type::NUM, RPCArg::Optional::NO, "Asset units (u64)"},
            {"policy_bits", RPCArg::Type::NUM, RPCArg::Optional::NO, "Policy bits (u32)"},
            {"allowed_spk_families", RPCArg::Type::NUM, RPCArg::Default{assets::SPK_DEFAULT_ALLOWED}, "Allowed families (u16)"},
            {"unlock_fees_sats", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Unlock threshold sats"},
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Options",
                {
                    {"autofund", RPCArg::Type::BOOL, RPCArg::Default{false}, "Automatically fund using loaded wallet"},
                    {"broadcast", RPCArg::Type::BOOL, RPCArg::Default{false}, "Broadcast after signing with loaded wallet"},
                    {"fee_rate", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Fee rate in sat/vB"},
                    {"replaceable", RPCArg::Type::BOOL, RPCArg::DefaultHint{"wallet default"}, "Signal RBF"},
                }
            },
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "hex", "Raw transaction hex (may be funded/signed depending on options and wallet)"},
                {RPCResult::Type::STR_HEX, "txid", /*optional=*/true, "Broadcast txid if broadcast=true"},
            }
        },
        RPCExamples{""},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            Txid icu_tx = Txid::FromHex(request.params[0].get_str()).value();
            uint32_t icu_vout = request.params[1].getInt<uint32_t>();
            CTxDestination icu_dest = DecodeDestination(request.params[2].get_str());
            if (!IsValidDestination(icu_dest)) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid icu address");
            CAmount icu_amt = AmountFromValue(request.params[3]);
            CTxDestination asset_dest = DecodeDestination(request.params[4].get_str());
            if (!IsValidDestination(asset_dest)) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid asset address");
            CAmount asset_btc = AmountFromValue(request.params[5]);
            auto aid = uint256::FromHex(request.params[6].get_str()); if (!aid) throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid asset_id");
            uint64_t units = request.params[7].getInt<uint64_t>(); if (units == 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "asset units must be > 0");
            uint32_t policy_bits = request.params[8].getInt<uint32_t>();
            uint16_t allowed = request.params[9].isNull() ? assets::SPK_DEFAULT_ALLOWED : request.params[9].getInt<uint16_t>();
            bool has_unlock = (request.params.size() > 10) && !request.params[10].isNull(); uint64_t unlock = has_unlock ? request.params[10].getInt<uint64_t>() : 0;

            CMutableTransaction mtx; mtx.vin.emplace_back(COutPoint(icu_tx, icu_vout));
            // vout0: ICU rotation with IssuerReg
            mtx.vout.emplace_back(icu_amt, GetScriptForDestination(icu_dest));
            // vout1: AssetTag output
            mtx.vout.emplace_back(asset_btc, GetScriptForDestination(asset_dest));

            // IssuerReg TLV
            std::vector<unsigned char> regp; regp.insert(regp.end(), aid->begin(), aid->end()); unsigned char pb[4]; WriteLE32(pb, policy_bits); regp.insert(regp.end(), pb, pb+4); unsigned char ab[2]; ab[0]=allowed&0xFF; ab[1]=(allowed>>8)&0xFF; regp.insert(regp.end(), ab, ab+2); if (has_unlock){ unsigned char ub[8]; WriteLE64(ub, unlock); regp.insert(regp.end(), ub, ub+8);} std::vector<unsigned char> regtlv; regtlv.push_back((uint8_t)assets::OutExtType::ISSUER_REG); regtlv.push_back((uint8_t)regp.size()); regtlv.insert(regtlv.end(), regp.begin(), regp.end()); mtx.vout[0].vExt = std::move(regtlv);

            // AssetTag TLV
            std::vector<unsigned char> tagp; tagp.insert(tagp.end(), aid->begin(), aid->end()); unsigned char a8[8]; WriteLE64(a8, units); tagp.insert(tagp.end(), a8, a8+8); std::vector<unsigned char> tagtlv; tagtlv.push_back((uint8_t)assets::OutExtType::ASSET_TAG); tagtlv.push_back((uint8_t)tagp.size()); tagtlv.insert(tagtlv.end(), tagp.begin(), tagp.end()); mtx.vout[1].vExt = std::move(tagtlv);

            UniValue result(UniValue::VOBJ);
            std::shared_ptr<wallet::CWallet> pwallet;
            bool autofund=false, broadcast=false, want_psbt=false, do_sign=true, do_finalize=false; std::optional<double> fee_rate_vb; std::optional<bool> replaceable;
            if (!request.params[11].isNull()) {
                const UniValue& opt = request.params[11];
                autofund = opt.exists("autofund") && opt["autofund"].get_bool();
                broadcast = opt.exists("broadcast") && opt["broadcast"].get_bool();
                if (opt.exists("fee_rate")) fee_rate_vb = opt["fee_rate"].get_real();
                if (opt.exists("replaceable")) replaceable = opt["replaceable"].get_bool();
                want_psbt = opt.exists("psbt") && opt["psbt"].get_bool();
                if (opt.exists("sign")) do_sign = opt["sign"].get_bool();
                if (opt.exists("finalize")) do_finalize = opt["finalize"].get_bool();
            }
            if (autofund || broadcast || want_psbt) {
                pwallet = GetWalletForAssetsRPC(request);
            }
            if (autofund && pwallet) {
                const auto snapshots = wallet::CollectOutputExtensionSnapshots(mtx);
                wallet::CCoinControl cc;
                if (fee_rate_vb){ cc.fOverrideFeeRate=true; cc.m_feerate = CFeeRate((CAmount)(*fee_rate_vb*1000.0)); }
                if (replaceable) cc.m_signal_bip125_rbf=*replaceable;
                if (aid) cc.m_required_asset_id = *aid;
                cc.m_allow_icu_selection = true;
                cc.m_allow_other_inputs = true;
                auto txr = wallet::FundTransaction(*pwallet, mtx, {}, std::nullopt, false, cc);
                if (!txr) throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(txr).original);
                CMutableTransaction funded(*txr->tx);
                wallet::ReapplyOutputExtensionSnapshots(snapshots, funded);
                const wallet::AssetIdScanResult scan = wallet::ScanAssetIds(funded.vout);
                if (scan.conflict) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "mintasset does not yet support multiple asset ids in one call");
                }

                if (want_psbt) {
                    PartiallySignedTransaction psbtx(funded);
                    bool complete=false;
                    const auto err = pwallet->FillPSBT(psbtx, complete, SIGHASH_ALL, do_sign, false);
                    if (err) throw JSONRPCPSBTError(*err);
                    if (do_finalize && complete) {
                        CMutableTransaction mfinal;
                        if (!FinalizeAndExtractPSBT(psbtx, mfinal)) throw JSONRPCError(RPC_WALLET_ERROR, "PSBT finalize failed");
                        DataStream ds; ds << TX_WITH_WITNESS(mfinal);
                        result.pushKV("hex", HexStr(ds));
                        return result;
                    }
                    DataStream ss; ss << psbtx;
                    result.pushKV("psbt", EncodeBase64(ss));
                    result.pushKV("complete", complete);
                    return result;
                }

                if (broadcast) {
                    PartiallySignedTransaction psbtx(funded);
                    bool complete=false;
                    const auto err = pwallet->FillPSBT(psbtx, complete, SIGHASH_ALL, true, false);
                    if (err) throw JSONRPCPSBTError(*err);
                    CMutableTransaction mfinal;
                    if (!FinalizeAndExtractPSBT(psbtx, mfinal)) throw JSONRPCError(RPC_WALLET_ERROR, "PSBT finalize failed");
                    NodeContext& node = EnsureAnyNodeContext(request.context);
                    std::string err_string;
                    auto errc = BroadcastTransaction(node, MakeTransactionRef(CTransaction(mfinal)), err_string, 0, true, true);
                    if (errc != TransactionError::OK) throw JSONRPCError(RPC_VERIFY_ERROR, err_string);
                    result.pushKV("txid", CTransaction(mfinal).GetHash().ToString());
                    DataStream ds; ds << TX_WITH_WITNESS(mfinal);
                    result.pushKV("hex", HexStr(ds));
                    return result;
                }

                DataStream ds; ds << TX_WITH_WITNESS(funded);
                result.pushKV("hex", HexStr(ds));
                return result;
            } else {
                DataStream ds; ds << TX_WITH_WITNESS(mtx);
                result.pushKV("hex", HexStr(ds));
                if (autofund && !pwallet) result.pushKV("warning","No wallet loaded; returning unsigned raw tx");
                return result;
            }
        }
    };
}

static RPCHelpMan burnasset()
{
    return RPCHelpMan{"burnasset",
        "Create a raw burn transaction (unsigned): spends ICU and one AssetTag input; no AssetTag outputs are created.",
        {
            {"icu_txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "ICU txid"},
            {"icu_vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "ICU vout"},
            {"asset_txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Asset UTXO txid"},
            {"asset_vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "Asset UTXO vout"},
            {"icu_address", RPCArg::Type::STR, RPCArg::Optional::NO, "New ICU destination"},
            {"icu_amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "New ICU BTC amount"},
            {"asset_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Asset id"},
            {"policy_bits", RPCArg::Type::NUM, RPCArg::Optional::NO, "Policy bits (u32)"},
            {"allowed_spk_families", RPCArg::Type::NUM, RPCArg::Default{assets::SPK_DEFAULT_ALLOWED}, "Allowed families (u16)"},
            {"unlock_fees_sats", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Unlock threshold sats"},
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Options",
                {
                    {"autofund", RPCArg::Type::BOOL, RPCArg::Default{false}, "Automatically fund using loaded wallet"},
                    {"broadcast", RPCArg::Type::BOOL, RPCArg::Default{false}, "Broadcast after signing with loaded wallet"},
                    {"fee_rate", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Fee rate in sat/vB"},
                    {"replaceable", RPCArg::Type::BOOL, RPCArg::DefaultHint{"wallet default"}, "Signal RBF"},
                }
            },
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "hex", "Raw transaction hex (may be funded/signed depending on options and wallet)"},
                {RPCResult::Type::STR_HEX, "txid", /*optional=*/true, "Broadcast txid if broadcast=true"},
            }
        },
        RPCExamples{""},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            Txid icu_tx = Txid::FromHex(request.params[0].get_str()).value();
            uint32_t icu_vout = request.params[1].getInt<uint32_t>();
            Txid atx = Txid::FromHex(request.params[2].get_str()).value();
            uint32_t avout = request.params[3].getInt<uint32_t>();
            CTxDestination icu_dest = DecodeDestination(request.params[4].get_str());
            if (!IsValidDestination(icu_dest)) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid icu address");
            CAmount icu_amt = AmountFromValue(request.params[5]);
            auto aid = uint256::FromHex(request.params[6].get_str()); if (!aid) throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid asset_id");
            uint32_t policy_bits = request.params[7].getInt<uint32_t>();
            uint16_t allowed = request.params[8].isNull() ? assets::SPK_DEFAULT_ALLOWED : request.params[8].getInt<uint16_t>();
            bool has_unlock = (request.params.size() > 9) && !request.params[9].isNull(); uint64_t unlock = has_unlock ? request.params[9].getInt<uint64_t>() : 0;

            CMutableTransaction mtx; mtx.vin.emplace_back(COutPoint(icu_tx, icu_vout)); mtx.vin.emplace_back(COutPoint(atx, avout));
            mtx.vout.emplace_back(icu_amt, GetScriptForDestination(icu_dest));
            // IssuerReg rotation
            std::vector<unsigned char> regp; regp.insert(regp.end(), aid->begin(), aid->end()); unsigned char pb[4]; WriteLE32(pb, policy_bits); regp.insert(regp.end(), pb, pb+4); unsigned char ab[2]; ab[0]=allowed&0xFF; ab[1]=(allowed>>8)&0xFF; regp.insert(regp.end(), ab, ab+2); if (has_unlock){ unsigned char ub[8]; WriteLE64(ub, unlock); regp.insert(regp.end(), ub, ub+8);} std::vector<unsigned char> regtlv; regtlv.push_back((uint8_t)assets::OutExtType::ISSUER_REG); regtlv.push_back((uint8_t)regp.size()); regtlv.insert(regtlv.end(), regp.begin(), regp.end()); mtx.vout[0].vExt = std::move(regtlv);
            UniValue result(UniValue::VOBJ);
            std::shared_ptr<wallet::CWallet> pwallet;
            bool autofund=false, broadcast=false, want_psbt=false, do_sign=true, do_finalize=false; std::optional<double> fee_rate_vb; std::optional<bool> replaceable;
            if (!request.params[10].isNull()) {
                const UniValue& opt = request.params[10];
                autofund = opt.exists("autofund") && opt["autofund"].get_bool();
                broadcast = opt.exists("broadcast") && opt["broadcast"].get_bool();
                if (opt.exists("fee_rate")) fee_rate_vb = opt["fee_rate"].get_real();
                if (opt.exists("replaceable")) replaceable = opt["replaceable"].get_bool();
                if (opt.exists("psbt")) want_psbt = opt["psbt"].get_bool();
                if (opt.exists("sign")) do_sign = opt["sign"].get_bool();
                if (opt.exists("finalize")) do_finalize = opt["finalize"].get_bool();
            }
            if (autofund || broadcast || want_psbt) {
                pwallet = GetWalletForAssetsRPC(request);
            }
            if (autofund && pwallet) {
                const auto snapshots = wallet::CollectOutputExtensionSnapshots(mtx);
                wallet::CCoinControl cc;
                if (fee_rate_vb){ cc.fOverrideFeeRate=true; cc.m_feerate = CFeeRate((CAmount)(*fee_rate_vb*1000.0)); }
                if (replaceable) cc.m_signal_bip125_rbf=*replaceable;
                if (aid) cc.m_required_asset_id = *aid;
                cc.m_allow_icu_selection = true;
                cc.m_allow_other_inputs = true;
                auto txr = wallet::FundTransaction(*pwallet, mtx, {}, std::nullopt, false, cc);
                if (!txr) throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(txr).original);
                CMutableTransaction funded(*txr->tx);
                wallet::ReapplyOutputExtensionSnapshots(snapshots, funded);
                const wallet::AssetIdScanResult scan = wallet::ScanAssetIds(funded.vout);
                if (scan.conflict) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "burnasset does not yet support multiple asset ids in one call");
                }

                if (want_psbt) {
                    PartiallySignedTransaction psbtx(funded);
                    bool complete=false;
                    const auto err = pwallet->FillPSBT(psbtx, complete, SIGHASH_ALL, do_sign, false);
                    if (err) throw JSONRPCPSBTError(*err);
                    if (do_finalize && complete) {
                        CMutableTransaction mfinal;
                        if (!FinalizeAndExtractPSBT(psbtx, mfinal)) throw JSONRPCError(RPC_WALLET_ERROR, "PSBT finalize failed");
                        DataStream ds; ds << TX_WITH_WITNESS(mfinal);
                        result.pushKV("hex", HexStr(ds));
                        return result;
                    }
                    DataStream ss; ss << psbtx;
                    result.pushKV("psbt", EncodeBase64(ss));
                    result.pushKV("complete", complete);
                    return result;
                }

                if (broadcast) {
                    PartiallySignedTransaction psbtx(funded);
                    bool complete=false;
                    const auto err = pwallet->FillPSBT(psbtx, complete, SIGHASH_ALL, true, false);
                    if (err) throw JSONRPCPSBTError(*err);
                    CMutableTransaction mfinal;
                    if (!FinalizeAndExtractPSBT(psbtx, mfinal)) throw JSONRPCError(RPC_WALLET_ERROR, "PSBT finalize failed");
                    NodeContext& node = EnsureAnyNodeContext(request.context);
                    std::string err_string;
                    auto errc = BroadcastTransaction(node, MakeTransactionRef(CTransaction(mfinal)), err_string, 0, true, true);
                    if (errc != TransactionError::OK) throw JSONRPCError(RPC_VERIFY_ERROR, err_string);
                    result.pushKV("txid", CTransaction(mfinal).GetHash().ToString());
                    DataStream ds; ds << TX_WITH_WITNESS(mfinal);
                    result.pushKV("hex", HexStr(ds));
                    return result;
                }

                DataStream ds; ds << TX_WITH_WITNESS(funded);
                result.pushKV("hex", HexStr(ds));
                return result;
            } else {
                DataStream ds; ds << TX_WITH_WITNESS(mtx);
                result.pushKV("hex", HexStr(ds));
                if (autofund && !pwallet) result.pushKV("warning","No wallet loaded; returning unsigned raw tx");
                return result;
            }
        }
    };
}

static RPCHelpMan transferasset()
{
    return RPCHelpMan{"transferasset",
        "Create a raw asset transfer transaction preserving conservation (Δ=0).\n"
        "Note: This creates an unsigned transaction. Use fundrawtransaction to add fee inputs, "
        "then sign with signrawtransactionwithwallet and broadcast with sendrawtransaction.",
        {
            {"inputs", RPCArg::Type::ARR, RPCArg::Optional::NO, "Array of asset UTXOs to spend",
                {
                    {"input", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                        {
                            {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Transaction ID"},
                            {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "Output number"},
                            {"asset_units", RPCArg::Type::NUM, RPCArg::Optional::NO, "Asset units in this UTXO"},
                        },
                    },
                },
            },
            {"outputs", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Object with addresses and asset amounts",
                {
                    {"address", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Asset units to this address (raw units, not decimal)"},
                },
            },
            {"asset_id_or_ticker", RPCArg::Type::STR, RPCArg::Optional::NO, "Asset ID (hex) or ticker symbol"},
            {"btc_amounts", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "BTC amounts for outputs (defaults to 0.00001 BTC each)",
                {
                    {"address", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "BTC amount for this address"},
                },
            },
        },
        RPCResult{RPCResult::Type::STR_HEX, "hex", "Raw transaction hex (unsigned)"},
        RPCExamples{
            HelpExampleCli("transferasset", "'[{\"txid\":\"abc...\",\"vout\":0,\"asset_units\":1000}]' '{\"bc1q...\":600, \"bc1qchange...\":400}' \"GOLD\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            // Parse inputs
            const UniValue& inputs_val = request.params[0].get_array();
            const UniValue& outputs_val = request.params[1].get_obj();
            const std::string asset_identifier = request.params[2].get_str();

            // Resolve asset ID
            uint256 asset_id;
            if (asset_identifier.size() == 64) {
                auto aid = uint256::FromHex(asset_identifier);
                if (!aid) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid asset_id hex");
                }
                asset_id = *aid;
            } else {
                // Try ticker resolution
                // Try ticker resolution
                ChainstateManager& chainman = EnsureAnyChainman(request.context);
                LOCK(cs_main);
                Chainstate& active = chainman.ActiveChainstate();
                uint256 resolved_id;
                if (!active.CoinsTip().ReadTickerBinding(asset_identifier, resolved_id)) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Unknown ticker: %s", asset_identifier));
                }
                asset_id = resolved_id;
            }

            // Parse inputs and calculate total input units
            CMutableTransaction mtx;
            uint64_t total_input_units = 0;
            for (size_t i = 0; i < inputs_val.size(); ++i) {
                const UniValue& input = inputs_val[i];
                Txid txid = Txid::FromHex(input["txid"].get_str()).value();
                uint32_t vout = input["vout"].getInt<uint32_t>();
                uint64_t units = input["asset_units"].getInt<uint64_t>();

                mtx.vin.emplace_back(COutPoint(txid, vout));
                total_input_units += units;
            }

            // Parse outputs and calculate total output units
            uint64_t total_output_units = 0;
            std::vector<std::pair<CTxDestination, uint64_t>> asset_outputs;
            for (const std::string& key : outputs_val.getKeys()) {
                CTxDestination dest = DecodeDestination(key);
                if (!IsValidDestination(dest)) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("Invalid address: %s", key));
                }
                uint64_t units = outputs_val[key].getInt<uint64_t>();
                asset_outputs.push_back({dest, units});
                total_output_units += units;
            }

            // Check conservation
            if (total_input_units != total_output_units) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf(
                    "Asset conservation violation: inputs=%llu, outputs=%llu (Δ=%lld)",
                    (unsigned long long)total_input_units,
                    (unsigned long long)total_output_units,
                    (long long)(total_input_units - total_output_units)
                ));
            }

            // Parse BTC amounts if provided, otherwise use default
            std::map<CTxDestination, CAmount> btc_amounts;
            if (!request.params[3].isNull()) {
                const UniValue& btc_val = request.params[3].get_obj();
                for (const std::string& key : btc_val.getKeys()) {
                    CTxDestination dest = DecodeDestination(key);
                    if (!IsValidDestination(dest)) {
                        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("Invalid address: %s", key));
                    }
                    btc_amounts[dest] = AmountFromValue(btc_val[key]);
                }
            }

            // Create outputs with asset tags
            for (const auto& [dest, units] : asset_outputs) {
                CAmount btc_value = 1000; // 0.00001 BTC (1k sats) default for asset outputs
                auto it = btc_amounts.find(dest);
                if (it != btc_amounts.end()) {
                    btc_value = it->second;
                }

                CTxOut output(btc_value, GetScriptForDestination(dest));

                // Create AssetTag TLV
                std::vector<unsigned char> tag_payload;
                tag_payload.insert(tag_payload.end(), asset_id.begin(), asset_id.end());
                unsigned char units_buf[8];
                WriteLE64(units_buf, units);
                tag_payload.insert(tag_payload.end(), units_buf, units_buf + 8);

                std::vector<unsigned char> tag_tlv;
                tag_tlv.push_back(static_cast<uint8_t>(assets::OutExtType::ASSET_TAG));
                tag_tlv.push_back(static_cast<uint8_t>(tag_payload.size()));
                tag_tlv.insert(tag_tlv.end(), tag_payload.begin(), tag_payload.end());

                output.vExt = std::move(tag_tlv);
                mtx.vout.push_back(output);
            }

            // Return raw transaction hex
            DataStream ds;
            ds << TX_WITH_WITNESS(mtx);
            return HexStr(ds);
        }
    };
}

static RPCHelpMan validateassetconservation()
{
    return RPCHelpMan{"validateassetconservation",
        "Validate asset conservation (Δ=0) for a transaction.",
        {
            {"hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Raw transaction hex"},
            {"resolve_tickers", RPCArg::Type::BOOL, RPCArg::Default{true}, "Include ticker information if available"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::BOOL, "valid", "Whether all assets conserve (Δ=0)"},
                {RPCResult::Type::OBJ_DYN, "assets", "Per-asset conservation details (keys are asset IDs)",
                    {
                        {RPCResult::Type::OBJ, "asset_id", "Conservation for this asset",
                            {
                                {RPCResult::Type::STR, "ticker", /*optional=*/true, "Ticker symbol if available"},
                                {RPCResult::Type::NUM, "inputs", "Total input units"},
                                {RPCResult::Type::NUM, "outputs", "Total output units"},
                                {RPCResult::Type::NUM, "delta", "Difference (inputs - outputs)"},
                                {RPCResult::Type::BOOL, "valid", "Whether this asset conserves"},
                                {RPCResult::Type::NUM, "decimals", /*optional=*/true, "Decimal places for this asset"},
                                {RPCResult::Type::STR, "inputs_decimal", /*optional=*/true, "Formatted input amount with decimals"},
                                {RPCResult::Type::STR, "outputs_decimal", /*optional=*/true, "Formatted output amount with decimals"},
                            }
                        }
                    }
                },
                {RPCResult::Type::ARR, "errors", "List of conservation errors",
                    {
                        {RPCResult::Type::STR, "error", "Error description"},
                    }
                },
            }
        },
        RPCExamples{
            HelpExampleCli("validateassetconservation", "\"hexstring\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            CMutableTransaction mtx;
            if (!DecodeHexTx(mtx, request.params[0].get_str())) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
            }

            bool resolve_tickers = request.params[1].isNull() ? true : request.params[1].get_bool();

            // Map to track units per asset
            std::map<uint256, int64_t> asset_deltas;  // Can be negative
            std::map<uint256, uint64_t> asset_inputs;
            std::map<uint256, uint64_t> asset_outputs;
            std::map<uint256, std::string> asset_tickers;
            std::map<uint256, uint8_t> asset_decimals;

            // Get chainstate for UTXO lookup
            ChainstateManager& chainman = EnsureAnyChainman(request.context);
            LOCK(cs_main);
            Chainstate& active = chainman.ActiveChainstate();

            // Process inputs - look up prevouts to get input asset amounts
            UniValue errors(UniValue::VARR);
            for (const CTxIn& txin : mtx.vin) {
                // Try UTXO set first, then mempool
                auto coin_opt = active.CoinsTip().GetCoin(txin.prevout);
                if (!coin_opt) {
                    // Check mempool
                    CTxMemPool* mempool = active.GetMempool();
                    const CTransactionRef ptx = mempool ? mempool->get(txin.prevout.hash) : nullptr;
                    if (!ptx || txin.prevout.n >= ptx->vout.size()) {
                        errors.push_back(strprintf("Could not find prevout %s:%d",
                                                  txin.prevout.hash.ToString(), txin.prevout.n));
                        continue;
                    }
                    coin_opt = Coin(ptx->vout[txin.prevout.n], MEMPOOL_HEIGHT, false);
                }
                const Coin& coin = *coin_opt;

                // Check for asset tag in the prevout
                auto tag = assets::ParseAssetTag(coin.out.vExt);
                if (tag) {
                    asset_inputs[tag->id] += tag->amount;
                    asset_deltas[tag->id] += static_cast<int64_t>(tag->amount);  // Inputs are positive

                    // Try to resolve ticker if requested
                    if (resolve_tickers && asset_tickers.find(tag->id) == asset_tickers.end()) {
                        AssetRegistryEntry e;
                        if (active.CoinsTip().ReadAssetPolicy(tag->id, e)) {
                            if (!e.ticker.empty()) {
                                asset_tickers[tag->id] = e.ticker;
                            }
                            if (e.decimals != 255) {
                                asset_decimals[tag->id] = e.decimals;
                            }
                        }
                    }
                }
            }

            // Process outputs
            for (size_t i = 0; i < mtx.vout.size(); ++i) {
                const CTxOut& out = mtx.vout[i];

                // Check for AssetTag
                auto tag = assets::ParseAssetTag(out.vExt);
                if (tag) {
                    asset_outputs[tag->id] += tag->amount;
                    asset_deltas[tag->id] -= static_cast<int64_t>(tag->amount);  // Outputs are negative

                    // Try to resolve ticker if requested
                    if (resolve_tickers && asset_tickers.find(tag->id) == asset_tickers.end()) {
                        AssetRegistryEntry e;
                        if (active.CoinsTip().ReadAssetPolicy(tag->id, e)) {
                            if (!e.ticker.empty()) {
                                asset_tickers[tag->id] = e.ticker;
                            }
                            if (e.decimals != 255) {
                                asset_decimals[tag->id] = e.decimals;
                            }
                        }
                    }
                }

                // Check for ICU (mint/burn operations)
                auto reg = assets::ParseIssuerReg(out.vExt);
                if (reg) {
                    // ICU movements don't affect conservation directly
                    // but we note them for completeness
                }
            }

            // Build result
            UniValue result(UniValue::VOBJ);
            UniValue assets_obj(UniValue::VOBJ);
            bool all_valid = errors.size() == 0;

            for (const auto& [asset_id, delta] : asset_deltas) {
                UniValue asset_info(UniValue::VOBJ);

                // Add ticker if available
                auto ticker_it = asset_tickers.find(asset_id);
                if (ticker_it != asset_tickers.end()) {
                    asset_info.pushKV("ticker", ticker_it->second);
                }

                // Show input and output amounts
                uint64_t inputs = asset_inputs[asset_id];
                uint64_t outputs = asset_outputs[asset_id];

                asset_info.pushKV("inputs", inputs);
                asset_info.pushKV("outputs", outputs);
                asset_info.pushKV("delta", delta);
                asset_info.pushKV("valid", delta == 0);

                // Add decimal formatting if available
                auto decimals_it = asset_decimals.find(asset_id);
                if (decimals_it != asset_decimals.end()) {
                    asset_info.pushKV("decimals", static_cast<int64_t>(decimals_it->second));
                    // Format amounts with decimals
                    auto format_amount = [](uint64_t amount, uint8_t dec) -> std::string {
                        if (dec == 0) return std::to_string(amount);
                        std::string s = std::to_string(amount);
                        while (s.length() <= dec) s = "0" + s;
                        s.insert(s.length() - dec, ".");
                        return s;
                    };
                    asset_info.pushKV("inputs_decimal", format_amount(inputs, decimals_it->second));
                    asset_info.pushKV("outputs_decimal", format_amount(outputs, decimals_it->second));
                }

                if (delta != 0) {
                    all_valid = false;
                }

                assets_obj.pushKV(asset_id.ToString(), asset_info);
            }

            result.pushKV("valid", all_valid);
            result.pushKV("assets", assets_obj);
            result.pushKV("errors", errors);

            return result;
        }
    };
}

static RPCHelpMan decodeassettransaction()
{
    return RPCHelpMan{"decodeassettransaction",
        "Decode transaction with enhanced asset information.",
        {
            {"hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Raw transaction hex"},
            {"resolve_tickers", RPCArg::Type::BOOL, RPCArg::Default{true}, "Resolve tickers for display"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "Decoded transaction with asset info",
            {
                // Standard decode fields are included via ...
                {RPCResult::Type::ELISION, "", "Standard decoderawtransaction output"},
                {RPCResult::Type::OBJ, "asset_summary", "Asset transfer summary",
                    {
                        {RPCResult::Type::BOOL, "has_assets", "Whether transaction contains asset transfers"},
                        {RPCResult::Type::OBJ, "assets", "Per-asset summary",
                            {
                                {RPCResult::Type::OBJ, "asset_id", "Summary for this asset",
                                    {
                                        {RPCResult::Type::STR, "ticker", /*optional=*/true, "Ticker symbol if resolvable"},
                                        {RPCResult::Type::NUM, "outputs", "Total output units"},
                                        {RPCResult::Type::STR, "outputs_decimal", /*optional=*/true, "Formatted if decimals known"},
                                    }
                                }
                            }
                        },
                        {RPCResult::Type::BOOL, "has_icu", "Whether transaction has ICU operations"},
                        {RPCResult::Type::STR_HEX, "icu_asset_id", /*optional=*/true, "Asset ID for ICU operations"},
                    }
                },
            }
        },
        RPCExamples{
            HelpExampleCli("decodeassettransaction", "\"hexstring\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            CMutableTransaction mtx;
            if (!DecodeHexTx(mtx, request.params[0].get_str())) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
            }

            bool resolve_tickers = request.params[1].isNull() ? true : request.params[1].get_bool();

            // First get standard decode output
            // First get standard decode output
            UniValue result(UniValue::VOBJ);
            TxToUniv(CTransaction(mtx), /*block_hash=*/uint256(), result);

            // Add asset-specific information
            UniValue asset_summary(UniValue::VOBJ);
            UniValue assets_obj(UniValue::VOBJ);
            bool has_assets = false;
            bool has_icu = false;
            uint256 icu_asset_id;

            // Map to track assets
            std::map<uint256, uint64_t> asset_inputs;
            std::map<uint256, uint64_t> asset_outputs;
            std::map<uint256, std::string> asset_tickers;
            std::map<uint256, uint8_t> asset_decimals;

            // Get chainstate for UTXO lookup
            ChainstateManager& chainman = EnsureAnyChainman(request.context);
            LOCK(cs_main);
            Chainstate& active = chainman.ActiveChainstate();

            // Process inputs - look up prevouts to get input asset amounts
            for (const CTxIn& txin : mtx.vin) {
                // Try UTXO set first, then mempool
                auto coin_opt = active.CoinsTip().GetCoin(txin.prevout);
                if (!coin_opt) {
                    // Check mempool
                    CTxMemPool* mempool = active.GetMempool();
                    const CTransactionRef ptx = mempool ? mempool->get(txin.prevout.hash) : nullptr;
                    if (!ptx || txin.prevout.n >= ptx->vout.size()) {
                        // Can't find prevout - skip
                        continue;
                    }
                    coin_opt = Coin(ptx->vout[txin.prevout.n], MEMPOOL_HEIGHT, false);
                }
                const Coin& coin = *coin_opt;

                // Check for asset tag in the prevout
                auto tag = assets::ParseAssetTag(coin.out.vExt);
                if (tag) {
                    has_assets = true;
                    asset_inputs[tag->id] += tag->amount;

                    // Try to resolve ticker if requested
                    if (resolve_tickers && asset_tickers.find(tag->id) == asset_tickers.end()) {
                        AssetRegistryEntry e;
                        if (active.CoinsTip().ReadAssetPolicy(tag->id, e)) {
                            if (!e.ticker.empty()) {
                                asset_tickers[tag->id] = e.ticker;
                            }
                            if (e.decimals != 255) {
                                asset_decimals[tag->id] = e.decimals;
                            }
                        }
                    }
                }
            }

            // Process outputs for asset tags and ICU operations
            for (size_t i = 0; i < mtx.vout.size(); ++i) {
                const CTxOut& out = mtx.vout[i];

                // Check for AssetTag
                auto tag = assets::ParseAssetTag(out.vExt);
                if (tag) {
                    has_assets = true;
                    asset_outputs[tag->id] += tag->amount;

                    // Try to resolve ticker and decimals if requested
                    if (resolve_tickers && asset_tickers.find(tag->id) == asset_tickers.end()) {
                        AssetRegistryEntry entry;
                        if (active.CoinsTip().ReadAssetPolicy(tag->id, entry)) {
                            if (!entry.ticker.empty()) {
                                asset_tickers[tag->id] = entry.ticker;
                            }
                            if (entry.decimals != std::numeric_limits<uint8_t>::max()) {
                                asset_decimals[tag->id] = entry.decimals;
                            }
                        }
                    }
                }

                // Check for IssuerReg (ICU operations)
                auto reg = assets::ParseIssuerReg(out.vExt);
                if (reg) {
                    has_icu = true;
                    icu_asset_id = reg->asset_id;
                }
            }

            // Build assets object - include all assets from both inputs and outputs
            std::set<uint256> all_asset_ids;
            for (const auto& [id, _] : asset_inputs) all_asset_ids.insert(id);
            for (const auto& [id, _] : asset_outputs) all_asset_ids.insert(id);

            for (const uint256& asset_id : all_asset_ids) {
                UniValue asset_info(UniValue::VOBJ);

                // Add ticker if available
                auto ticker_it = asset_tickers.find(asset_id);
                if (ticker_it != asset_tickers.end()) {
                    asset_info.pushKV("ticker", ticker_it->second);
                }

                uint64_t inputs = asset_inputs[asset_id];
                uint64_t outputs = asset_outputs[asset_id];
                int64_t delta = static_cast<int64_t>(inputs) - static_cast<int64_t>(outputs);

                asset_info.pushKV("inputs", inputs);
                asset_info.pushKV("outputs", outputs);
                asset_info.pushKV("delta", delta);
                asset_info.pushKV("conservation", delta == 0);

                // Add decimal formatting if available
                auto decimals_it = asset_decimals.find(asset_id);
                if (decimals_it != asset_decimals.end()) {
                    asset_info.pushKV("decimals", static_cast<int64_t>(decimals_it->second));
                    // Format decimal amounts
                    auto format_amount = [](uint64_t amount, uint8_t dec) -> std::string {
                        if (dec == 0) return std::to_string(amount);
                        std::string s = std::to_string(amount);
                        while (s.length() <= dec) s = "0" + s;
                        s.insert(s.length() - dec, ".");
                        return s;
                    };
                    asset_info.pushKV("inputs_decimal", format_amount(inputs, decimals_it->second));
                    asset_info.pushKV("outputs_decimal", format_amount(outputs, decimals_it->second));
                }

                assets_obj.pushKV(asset_id.ToString(), asset_info);
            }

            asset_summary.pushKV("has_assets", has_assets);
            asset_summary.pushKV("assets", assets_obj);
            asset_summary.pushKV("has_icu", has_icu);
            if (has_icu) {
                asset_summary.pushKV("icu_asset_id", icu_asset_id.ToString());
            }

            result.pushKV("asset_summary", asset_summary);

            return result;
        }
    };
}

static RPCHelpMan createassettransaction()
{
    return RPCHelpMan{"createassettransaction",
        "Create a complex asset transaction with multiple operations.\n"
        "Supports mixed asset transfers, ICU operations, and standard BTC outputs.\n"
        "Note: This creates an unsigned transaction requiring manual fee handling.",
        {
            {"inputs", RPCArg::Type::ARR, RPCArg::Optional::NO, "Array of inputs to spend",
                {
                    {"input", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                        {
                            {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Transaction ID"},
                            {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "Output number"},
                            {"sequence", RPCArg::Type::NUM, RPCArg::Default{0xfffffffe}, "Sequence number"},
                        },
                    },
                },
            },
            {"outputs", RPCArg::Type::ARR, RPCArg::Optional::NO, "Array of outputs to create",
                {
                    {"output", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                        {
                            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "Destination address"},
                            {"btc_amount", RPCArg::Type::AMOUNT, RPCArg::Default{"0.00001"}, "BTC amount"},
                            {"asset_id", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Asset ID or ticker"},
                            {"asset_units", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Asset units"},
                            {"icu_operation", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "ICU operation details",
                                {
                                    {"asset_id", RPCArg::Type::STR, RPCArg::Optional::NO, "Asset ID for ICU"},
                                    {"policy_bits", RPCArg::Type::NUM, RPCArg::Optional::NO, "Policy bits"},
                                    {"allowed_families", RPCArg::Type::NUM, RPCArg::Optional::NO, "Allowed SPK families"},
                                    {"unlock_fees", RPCArg::Type::NUM, RPCArg::Optional::NO, "Unlock fees in satoshis"},
                                },
                            },
                        },
                    },
                },
            },
            {"locktime", RPCArg::Type::NUM, RPCArg::Default{0}, "Locktime value"},
        },
        RPCResult{RPCResult::Type::STR_HEX, "hex", "Raw transaction hex (unsigned)"},
        RPCExamples{
            HelpExampleCli("createassettransaction",
                "'[{\"txid\":\"abc...\",\"vout\":0}]' "
                "'[{\"address\":\"bc1q...\",\"btc_amount\":0.00001,\"asset_id\":\"GOLD\",\"asset_units\":1000}]'")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            const UniValue& inputs_val = request.params[0].get_array();
            const UniValue& outputs_val = request.params[1].get_array();
            uint32_t locktime = request.params[2].isNull() ? 0 : request.params[2].getInt<uint32_t>();

            CMutableTransaction mtx;
            mtx.nLockTime = locktime;

            // Process inputs
            for (size_t i = 0; i < inputs_val.size(); ++i) {
                const UniValue& input = inputs_val[i];
                Txid txid = Txid::FromHex(input["txid"].get_str()).value();
                uint32_t vout = input["vout"].getInt<uint32_t>();
                uint32_t sequence = 0xfffffffe;
                if (input.exists("sequence")) {
                    sequence = input["sequence"].getInt<uint32_t>();
                }
                mtx.vin.emplace_back(COutPoint(txid, vout), CScript(), sequence);
            }

            // Process outputs
            for (size_t i = 0; i < outputs_val.size(); ++i) {
                const UniValue& output = outputs_val[i];

                // Parse destination
                CTxDestination dest = DecodeDestination(output["address"].get_str());
                if (!IsValidDestination(dest)) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                        strprintf("Invalid address: %s", output["address"].get_str()));
                }

                // Parse BTC amount
                CAmount btc_amount = 1000; // 0.00001 BTC (1k sats) default for asset outputs
                if (output.exists("btc_amount")) {
                    btc_amount = AmountFromValue(output["btc_amount"]);
                }

                // Create base output
                CTxOut txout(btc_amount, GetScriptForDestination(dest));

                // Handle asset transfer
                if (output.exists("asset_id") && output.exists("asset_units")) {
                    std::string asset_identifier = output["asset_id"].get_str();
                    uint64_t units = output["asset_units"].getInt<uint64_t>();

                    // Resolve asset ID
                    uint256 asset_id;
                    if (asset_identifier.size() == 64) {
                        auto aid = uint256::FromHex(asset_identifier);
                        if (!aid) {
                            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid asset_id hex");
                        }
                        asset_id = *aid;
                    } else {
                        // Try ticker resolution
                        ChainstateManager& chainman = EnsureAnyChainman(request.context);
                        LOCK(cs_main);
                        Chainstate& active = chainman.ActiveChainstate();
                        if (!active.CoinsTip().ReadTickerBinding(asset_identifier, asset_id)) {
                            throw JSONRPCError(RPC_INVALID_PARAMETER,
                                strprintf("Unknown ticker: %s", asset_identifier));
                        }
                    }

                    // Create AssetTag TLV
                    std::vector<unsigned char> tag_payload;
                    tag_payload.insert(tag_payload.end(), asset_id.begin(), asset_id.end());
                    unsigned char units_buf[8];
                    WriteLE64(units_buf, units);
                    tag_payload.insert(tag_payload.end(), units_buf, units_buf + 8);

                    std::vector<unsigned char> tag_tlv;
                    tag_tlv.push_back(static_cast<uint8_t>(assets::OutExtType::ASSET_TAG));
                    tag_tlv.push_back(static_cast<uint8_t>(tag_payload.size()));
                    tag_tlv.insert(tag_tlv.end(), tag_payload.begin(), tag_payload.end());

                    txout.vExt = std::move(tag_tlv);
                }

                // Handle ICU operation
                if (output.exists("icu_operation")) {
                    const UniValue& icu_op = output["icu_operation"];

                    std::string asset_identifier = icu_op["asset_id"].get_str();
                    uint8_t policy_bits = icu_op["policy_bits"].getInt<uint8_t>();
                    uint8_t allowed_families = icu_op["allowed_families"].getInt<uint8_t>();
                    uint64_t unlock_fees = icu_op["unlock_fees"].getInt<uint64_t>();

                    // Resolve asset ID
                    uint256 asset_id;
                    if (asset_identifier.size() == 64) {
                        auto aid = uint256::FromHex(asset_identifier);
                        if (!aid) {
                            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid ICU asset_id hex");
                        }
                        asset_id = *aid;
                    } else {
                        // Try ticker resolution
                        ChainstateManager& chainman = EnsureAnyChainman(request.context);
                        LOCK(cs_main);
                        Chainstate& active = chainman.ActiveChainstate();
                        uint256 resolved_id;
                        if (!active.CoinsTip().ReadTickerBinding(asset_identifier, resolved_id)) {
                            throw JSONRPCError(RPC_INVALID_PARAMETER,
                                strprintf("Unknown ticker: %s", asset_identifier));
                        }
                        asset_id = resolved_id;
                    }

                    // Create IssuerReg TLV
                    std::vector<unsigned char> reg_payload;
                    reg_payload.insert(reg_payload.end(), asset_id.begin(), asset_id.end());
                    reg_payload.push_back(policy_bits);
                    reg_payload.push_back(allowed_families);
                    unsigned char fees_buf[8];
                    WriteLE64(fees_buf, unlock_fees);
                    reg_payload.insert(reg_payload.end(), fees_buf, fees_buf + 8);

                    std::vector<unsigned char> reg_tlv;
                    reg_tlv.push_back(static_cast<uint8_t>(assets::OutExtType::ISSUER_REG));
                    reg_tlv.push_back(static_cast<uint8_t>(reg_payload.size()));
                    reg_tlv.insert(reg_tlv.end(), reg_payload.begin(), reg_payload.end());

                    // ICU outputs should not have asset tags
                    if (output.exists("asset_id")) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER,
                            "Output cannot have both asset_id and icu_operation");
                    }

                    txout.vExt = std::move(reg_tlv);
                }

                mtx.vout.push_back(txout);
            }

            // Return raw transaction hex
            DataStream ds;
            ds << TX_WITH_WITNESS(mtx);
            return HexStr(ds);
        }
    };
}

static RPCHelpMan decodeoutext()
{
    return RPCHelpMan{"decodeoutext",
        "Decode an output extension TLV (hex) into structured fields.",
        {
            {"tlv", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "TLV hex"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "type", "ASSET_TAG or ISSUER_REG"},
                {RPCResult::Type::STR_HEX, "asset_id", /*optional=*/true, "asset id"},
                {RPCResult::Type::NUM, "amount", /*optional=*/true, "asset units (u64)"},
                {RPCResult::Type::NUM, "policy_bits", /*optional=*/true, "policy bits"},
                {RPCResult::Type::NUM, "allowed_spk_families", /*optional=*/true, "allowed families"},
                {RPCResult::Type::NUM, "unlock_fees_sats", /*optional=*/true, "unlock threshold"},
                {RPCResult::Type::STR, "ticker", /*optional=*/true, "ticker"},
                {RPCResult::Type::NUM, "decimals", /*optional=*/true, "decimals"},
            }
        },
        RPCExamples{""},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            std::vector<unsigned char> tlv = ParseHex(request.params[0].get_str());
            UniValue out(UniValue::VOBJ);
            if (auto tag = assets::ParseAssetTag(tlv)) {
                out.pushKV("type", "ASSET_TAG");
                out.pushKV("asset_id", tag->id.ToString());
                out.pushKV("amount", (uint64_t)tag->amount);
                return out;
            }
            if (auto reg = assets::ParseIssuerReg(tlv)) {
                out.pushKV("type", "ISSUER_REG");
                out.pushKV("asset_id", reg->asset_id.ToString());
                out.pushKV("policy_bits", reg->policy_bits);
                out.pushKV("allowed_spk_families", reg->allowed_spk_families);
                if (reg->unlock_fees_sats != std::numeric_limits<uint64_t>::max()) out.pushKV("unlock_fees_sats", (uint64_t)reg->unlock_fees_sats);
                if (!reg->ticker.empty()) out.pushKV("ticker", reg->ticker);
                if (reg->decimals != 0xFF) out.pushKV("decimals", (int)reg->decimals);
                return out;
            }
            throw JSONRPCError(RPC_INVALID_PARAMETER, "unknown or malformed TLV");
        }
    };
}
static std::vector<RPCArg> CreateTxDoc()
{
    return {
        {"inputs", RPCArg::Type::ARR, RPCArg::Optional::NO, "The inputs",
            {
                {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                    {
                        {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction id"},
                        {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "The output number"},
                        {"sequence", RPCArg::Type::NUM, RPCArg::DefaultHint{"depends on the value of the 'replaceable' and 'locktime' arguments"}, "The sequence number"},
                    },
                },
            },
        },
        {"outputs", RPCArg::Type::ARR, RPCArg::Optional::NO, "The outputs specified as key-value pairs.\n"
                "Each key may only appear once, i.e. there can only be one 'data' output, and no address may be duplicated.\n"
                "At least one output of either type must be specified.\n"
                "For compatibility reasons, a dictionary, which holds the key-value pairs directly, is also\n"
                "                             accepted as second parameter.",
            {
                {"", RPCArg::Type::OBJ_USER_KEYS, RPCArg::Optional::OMITTED, "",
                    {
                        {"address", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "A key-value pair. The key (string) is the bitcoin address, the value (float or string) is the amount in " + CURRENCY_UNIT},
                    },
                },
                {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                    {
                        {"data", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "A key-value pair. The key must be \"data\", the value is hex-encoded data that becomes a part of an OP_RETURN output"},
                    },
                },
            },
         RPCArgOptions{.skip_type_check = true}},
        {"locktime", RPCArg::Type::NUM, RPCArg::Default{0}, "Raw locktime. Non-0 value also locktime-activates inputs"},
        {"replaceable", RPCArg::Type::BOOL, RPCArg::Default{true}, "Marks this transaction as BIP125-replaceable.\n"
                "Allows this transaction to be replaced by a transaction with higher fees. If provided, it is an error if explicit sequence numbers are incompatible."},
    };
}

// Update PSBT with information from the mempool, the UTXO set, the txindex, and the provided descriptors.
// Optionally, sign the inputs that we can using information from the descriptors.
PartiallySignedTransaction ProcessPSBT(const std::string& psbt_string, const std::any& context, const HidingSigningProvider& provider, int sighash_type, bool finalize)
{
    // Unserialize the transactions
    PartiallySignedTransaction psbtx;
    std::string error;
    if (!DecodeBase64PSBT(psbtx, psbt_string, error)) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, strprintf("TX decode failed %s", error));
    }

    if (g_txindex) g_txindex->BlockUntilSyncedToCurrentChain();
    const NodeContext& node = EnsureAnyNodeContext(context);

    // If we can't find the corresponding full transaction for all of our inputs,
    // this will be used to find just the utxos for the segwit inputs for which
    // the full transaction isn't found
    std::map<COutPoint, Coin> coins;

    // Fetch previous transactions:
    // First, look in the txindex and the mempool
    for (unsigned int i = 0; i < psbtx.tx->vin.size(); ++i) {
        PSBTInput& psbt_input = psbtx.inputs.at(i);
        const CTxIn& tx_in = psbtx.tx->vin.at(i);

        // The `non_witness_utxo` is the whole previous transaction
        if (psbt_input.non_witness_utxo) continue;

        CTransactionRef tx;

        // Look in the txindex
        if (g_txindex) {
            uint256 block_hash;
            g_txindex->FindTx(tx_in.prevout.hash, block_hash, tx);
        }
        // If we still don't have it look in the mempool
        if (!tx) {
            tx = node.mempool->get(tx_in.prevout.hash);
        }
        if (tx) {
            psbt_input.non_witness_utxo = tx;
        } else {
            coins[tx_in.prevout]; // Create empty map entry keyed by prevout
        }
    }

    // If we still haven't found all of the inputs, look for the missing ones in the utxo set
    if (!coins.empty()) {
        FindCoins(node, coins);
        for (unsigned int i = 0; i < psbtx.tx->vin.size(); ++i) {
            PSBTInput& input = psbtx.inputs.at(i);

            // If there are still missing utxos, add them if they were found in the utxo set
            if (!input.non_witness_utxo) {
                const CTxIn& tx_in = psbtx.tx->vin.at(i);
                const Coin& coin = coins.at(tx_in.prevout);
                if (!coin.out.IsNull() && IsSegWitOutput(provider, coin.out.scriptPubKey)) {
                    input.witness_utxo = coin.out;
                }
            }
        }
    }

    const PrecomputedTransactionData& txdata = PrecomputePSBTData(psbtx);

    for (unsigned int i = 0; i < psbtx.tx->vin.size(); ++i) {
        if (PSBTInputSigned(psbtx.inputs.at(i))) {
            continue;
        }

        // Update script/keypath information using descriptor data.
        // Note that SignPSBTInput does a lot more than just constructing ECDSA signatures.
        // We only actually care about those if our signing provider doesn't hide private
        // information, as is the case with `descriptorprocesspsbt`
        SignPSBTInput(provider, psbtx, /*index=*/i, &txdata, sighash_type, /*out_sigdata=*/nullptr, finalize);
    }

    // Update script/keypath information using descriptor data.
    for (unsigned int i = 0; i < psbtx.tx->vout.size(); ++i) {
        UpdatePSBTOutput(provider, psbtx, i);
    }

    RemoveUnnecessaryTransactions(psbtx, /*sighash_type=*/1);

    return psbtx;
}

static RPCHelpMan getrawtransaction()
{
    return RPCHelpMan{
                "getrawtransaction",

                "By default, this call only returns a transaction if it is in the mempool. If -txindex is enabled\n"
                "and no blockhash argument is passed, it will return the transaction if it is in the mempool or any block.\n"
                "If a blockhash argument is passed, it will return the transaction if\n"
                "the specified block is available and the transaction is in that block.\n\n"
                "Hint: Use gettransaction for wallet transactions.\n\n"

                "If verbosity is 0 or omitted, returns the serialized transaction as a hex-encoded string.\n"
                "If verbosity is 1, returns a JSON Object with information about the transaction.\n"
                "If verbosity is 2, returns a JSON Object with information about the transaction, including fee and prevout information.",
                {
                    {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction id"},
                    {"verbosity|verbose", RPCArg::Type::NUM, RPCArg::Default{0}, "0 for hex-encoded data, 1 for a JSON object, and 2 for JSON object with fee and prevout",
                     RPCArgOptions{.skip_type_check = true}},
                    {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "The block in which to look for the transaction"},
                },
                {
                    RPCResult{"if verbosity is not set or set to 0",
                         RPCResult::Type::STR, "data", "The serialized transaction as a hex-encoded string for 'txid'"
                     },
                     RPCResult{"if verbosity is set to 1",
                         RPCResult::Type::OBJ, "", "",
                         Cat<std::vector<RPCResult>>(
                         {
                             {RPCResult::Type::BOOL, "in_active_chain", /*optional=*/true, "Whether specified block is in the active chain or not (only present with explicit \"blockhash\" argument)"},
                             {RPCResult::Type::STR_HEX, "blockhash", /*optional=*/true, "the block hash"},
                             {RPCResult::Type::NUM, "confirmations", /*optional=*/true, "The confirmations"},
                             {RPCResult::Type::NUM_TIME, "blocktime", /*optional=*/true, "The block time expressed in " + UNIX_EPOCH_TIME},
                             {RPCResult::Type::NUM, "time", /*optional=*/true, "Same as \"blocktime\""},
                             {RPCResult::Type::STR_HEX, "hex", "The serialized, hex-encoded data for 'txid'"},
                         },
                         DecodeTxDoc(/*txid_field_doc=*/"The transaction id (same as provided)")),
                    },
                    RPCResult{"for verbosity = 2",
                        RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::ELISION, "", "Same output as verbosity = 1"},
                            {RPCResult::Type::NUM, "fee", /*optional=*/true, "transaction fee in " + CURRENCY_UNIT + ", omitted if block undo data is not available"},
                            {RPCResult::Type::ARR, "vin", "",
                            {
                                {RPCResult::Type::OBJ, "", "utxo being spent",
                                {
                                    {RPCResult::Type::ELISION, "", "Same output as verbosity = 1"},
                                    {RPCResult::Type::OBJ, "prevout", /*optional=*/true, "The previous output, omitted if block undo data is not available",
                                    {
                                        {RPCResult::Type::BOOL, "generated", "Coinbase or not"},
                                        {RPCResult::Type::NUM, "height", "The height of the prevout"},
                                        {RPCResult::Type::STR_AMOUNT, "value", "The value in " + CURRENCY_UNIT},
                                        {RPCResult::Type::OBJ, "scriptPubKey", "", ScriptPubKeyDoc()},
                                    }},
                                }},
                            }},
                        }},
                },
                RPCExamples{
                    HelpExampleCli("getrawtransaction", "\"mytxid\"")
            + HelpExampleCli("getrawtransaction", "\"mytxid\" 1")
            + HelpExampleRpc("getrawtransaction", "\"mytxid\", 1")
            + HelpExampleCli("getrawtransaction", "\"mytxid\" 0 \"myblockhash\"")
            + HelpExampleCli("getrawtransaction", "\"mytxid\" 1 \"myblockhash\"")
            + HelpExampleCli("getrawtransaction", "\"mytxid\" 2 \"myblockhash\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const NodeContext& node = EnsureAnyNodeContext(request.context);
    ChainstateManager& chainman = EnsureChainman(node);

    uint256 hash = ParseHashV(request.params[0], "parameter 1");
    const CBlockIndex* blockindex = nullptr;

    if (hash == chainman.GetParams().GenesisBlock().hashMerkleRoot) {
        // Special exception for the genesis block coinbase transaction
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "The genesis block coinbase is not considered an ordinary transaction and cannot be retrieved");
    }

    int verbosity{ParseVerbosity(request.params[1], /*default_verbosity=*/0, /*allow_bool=*/true)};

    if (!request.params[2].isNull()) {
        LOCK(cs_main);

        uint256 blockhash = ParseHashV(request.params[2], "parameter 3");
        blockindex = chainman.m_blockman.LookupBlockIndex(blockhash);
        if (!blockindex) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block hash not found");
        }
    }

    bool f_txindex_ready = false;
    if (g_txindex && !blockindex) {
        f_txindex_ready = g_txindex->BlockUntilSyncedToCurrentChain();
    }

    uint256 hash_block;
    const CTransactionRef tx = GetTransaction(blockindex, node.mempool.get(), hash, hash_block, chainman.m_blockman);
    if (!tx) {
        std::string errmsg;
        if (blockindex) {
            const bool block_has_data = WITH_LOCK(::cs_main, return blockindex->nStatus & BLOCK_HAVE_DATA);
            if (!block_has_data) {
                throw JSONRPCError(RPC_MISC_ERROR, "Block not available");
            }
            errmsg = "No such transaction found in the provided block";
        } else if (!g_txindex) {
            errmsg = "No such mempool transaction. Use -txindex or provide a block hash to enable blockchain transaction queries";
        } else if (!f_txindex_ready) {
            errmsg = "No such mempool transaction. Blockchain transactions are still in the process of being indexed";
        } else {
            errmsg = "No such mempool or blockchain transaction";
        }
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, errmsg + ". Use gettransaction for wallet transactions.");
    }

    if (verbosity <= 0) {
        return EncodeHexTx(*tx);
    }

    UniValue result(UniValue::VOBJ);
    if (blockindex) {
        LOCK(cs_main);
        result.pushKV("in_active_chain", chainman.ActiveChain().Contains(blockindex));
    }
    // If request is verbosity >= 1 but no blockhash was given, then look up the blockindex
    if (request.params[2].isNull()) {
        LOCK(cs_main);
        blockindex = chainman.m_blockman.LookupBlockIndex(hash_block); // May be nullptr for mempool transactions
    }
    if (verbosity == 1) {
        TxToJSON(*tx, hash_block, result, chainman.ActiveChainstate());
        return result;
    }

    CBlockUndo blockUndo;
    CBlock block;

    if (tx->IsCoinBase() || !blockindex || WITH_LOCK(::cs_main, return !(blockindex->nStatus & BLOCK_HAVE_MASK))) {
        TxToJSON(*tx, hash_block, result, chainman.ActiveChainstate());
        return result;
    }
    if (!chainman.m_blockman.ReadBlockUndo(blockUndo, *blockindex)) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Undo data expected but can't be read. This could be due to disk corruption or a conflict with a pruning event.");
    }
    if (!chainman.m_blockman.ReadBlock(block, *blockindex)) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Block data expected but can't be read. This could be due to disk corruption or a conflict with a pruning event.");
    }

    CTxUndo* undoTX {nullptr};
    auto it = std::find_if(block.vtx.begin(), block.vtx.end(), [tx](CTransactionRef t){ return *t == *tx; });
    if (it != block.vtx.end()) {
        // -1 as blockundo does not have coinbase tx
        undoTX = &blockUndo.vtxundo.at(it - block.vtx.begin() - 1);
    }
    TxToJSON(*tx, hash_block, result, chainman.ActiveChainstate(), undoTX, TxVerbosity::SHOW_DETAILS_AND_PREVOUT);
    return result;
},
    };
}

static RPCHelpMan createrawtransaction()
{
    return RPCHelpMan{"createrawtransaction",
                "\nCreate a transaction spending the given inputs and creating new outputs.\n"
                "Outputs can be addresses or data.\n"
                "Returns hex-encoded raw transaction.\n"
                "Note that the transaction's inputs are not signed, and\n"
                "it is not stored in the wallet or transmitted to the network.\n",
                CreateTxDoc(),
                RPCResult{
                    RPCResult::Type::STR_HEX, "transaction", "hex string of the transaction"
                },
                RPCExamples{
                    HelpExampleCli("createrawtransaction", "\"[{\\\"txid\\\":\\\"myid\\\",\\\"vout\\\":0}]\" \"[{\\\"address\\\":0.01}]\"")
            + HelpExampleCli("createrawtransaction", "\"[{\\\"txid\\\":\\\"myid\\\",\\\"vout\\\":0}]\" \"[{\\\"data\\\":\\\"00010203\\\"}]\"")
            + HelpExampleRpc("createrawtransaction", "\"[{\\\"txid\\\":\\\"myid\\\",\\\"vout\\\":0}]\", \"[{\\\"address\\\":0.01}]\"")
            + HelpExampleRpc("createrawtransaction", "\"[{\\\"txid\\\":\\\"myid\\\",\\\"vout\\\":0}]\", \"[{\\\"data\\\":\\\"00010203\\\"}]\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::optional<bool> rbf;
    if (!request.params[3].isNull()) {
        rbf = request.params[3].get_bool();
    }
    CMutableTransaction rawTx = ConstructTransaction(request.params[0], request.params[1], request.params[2], rbf);

    return EncodeHexTx(CTransaction(rawTx));
},
    };
}

static RPCHelpMan decoderawtransaction()
{
    return RPCHelpMan{"decoderawtransaction",
                "Return a JSON object representing the serialized, hex-encoded transaction.",
                {
                    {"hexstring", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction hex string"},
                    {"iswitness", RPCArg::Type::BOOL, RPCArg::DefaultHint{"depends on heuristic tests"}, "Whether the transaction hex is a serialized witness transaction.\n"
                        "If iswitness is not present, heuristic tests will be used in decoding.\n"
                        "If true, only witness deserialization will be tried.\n"
                        "If false, only non-witness deserialization will be tried.\n"
                        "This boolean should reflect whether the transaction has inputs\n"
                        "(e.g. fully valid, or on-chain transactions), if known by the caller."
                    },
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    DecodeTxDoc(/*txid_field_doc=*/"The transaction id"),
                },
                RPCExamples{
                    HelpExampleCli("decoderawtransaction", "\"hexstring\"")
            + HelpExampleRpc("decoderawtransaction", "\"hexstring\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    CMutableTransaction mtx;

    bool try_witness = request.params[1].isNull() ? true : request.params[1].get_bool();
    bool try_no_witness = request.params[1].isNull() ? true : !request.params[1].get_bool();

    if (!DecodeHexTx(mtx, request.params[0].get_str(), try_no_witness, try_witness)) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
    }

    UniValue result(UniValue::VOBJ);
    TxToUniv(CTransaction(std::move(mtx)), /*block_hash=*/uint256(), /*entry=*/result, /*include_hex=*/false);

    return result;
},
    };
}

static RPCHelpMan decodescript()
{
    return RPCHelpMan{
        "decodescript",
        "\nDecode a hex-encoded script.\n",
        {
            {"hexstring", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "the hex-encoded script"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "asm", "Disassembly of the script"},
                {RPCResult::Type::STR, "desc", "Inferred descriptor for the script"},
                {RPCResult::Type::STR, "type", "The output type (e.g. " + GetAllOutputTypes() + ")"},
                {RPCResult::Type::STR, "address", /*optional=*/true, "The Bitcoin address (only if a well-defined address exists)"},
                {RPCResult::Type::STR, "p2sh", /*optional=*/true,
                 "address of P2SH script wrapping this redeem script (not returned for types that should not be wrapped)"},
                {RPCResult::Type::OBJ, "segwit", /*optional=*/true,
                 "Result of a witness output script wrapping this redeem script (not returned for types that should not be wrapped)",
                 {
                     {RPCResult::Type::STR, "asm", "Disassembly of the output script"},
                     {RPCResult::Type::STR_HEX, "hex", "The raw output script bytes, hex-encoded"},
                     {RPCResult::Type::STR, "type", "The type of the output script (e.g. witness_v0_keyhash or witness_v0_scripthash)"},
                     {RPCResult::Type::STR, "address", /*optional=*/true, "The Bitcoin address (only if a well-defined address exists)"},
                     {RPCResult::Type::STR, "desc", "Inferred descriptor for the script"},
                     {RPCResult::Type::STR, "p2sh-segwit", "address of the P2SH script wrapping this witness redeem script"},
                 }},
            },
        },
        RPCExamples{
            HelpExampleCli("decodescript", "\"hexstring\"")
          + HelpExampleRpc("decodescript", "\"hexstring\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    UniValue r(UniValue::VOBJ);
    CScript script;
    if (request.params[0].get_str().size() > 0){
        std::vector<unsigned char> scriptData(ParseHexV(request.params[0], "argument"));
        script = CScript(scriptData.begin(), scriptData.end());
    } else {
        // Empty scripts are valid
    }
    ScriptToUniv(script, /*out=*/r, /*include_hex=*/false, /*include_address=*/true);

    std::vector<std::vector<unsigned char>> solutions_data;
    const TxoutType which_type{Solver(script, solutions_data)};

    const bool can_wrap{[&] {
        switch (which_type) {
        case TxoutType::MULTISIG:
        case TxoutType::NONSTANDARD:
        case TxoutType::PUBKEY:
        case TxoutType::PUBKEYHASH:
        case TxoutType::WITNESS_V0_KEYHASH:
        case TxoutType::WITNESS_V0_SCRIPTHASH:
            // Can be wrapped if the checks below pass
            break;
        case TxoutType::NULL_DATA:
        case TxoutType::SCRIPTHASH:
        case TxoutType::WITNESS_UNKNOWN:
        case TxoutType::WITNESS_V1_TAPROOT:
        case TxoutType::WITNESS_V2_TAPROOT:
        case TxoutType::ANCHOR:
            // Should not be wrapped
            return false;
        } // no default case, so the compiler can warn about missing cases
        if (!script.HasValidOps() || script.IsUnspendable()) {
            return false;
        }
        for (CScript::const_iterator it{script.begin()}; it != script.end();) {
            opcodetype op;
            CHECK_NONFATAL(script.GetOp(it, op));
            if (op == OP_CHECKSIGADD || IsOpSuccess(op)) {
                return false;
            }
        }
        return true;
    }()};

    if (can_wrap) {
        r.pushKV("p2sh", EncodeDestination(ScriptHash(script)));
        // P2SH and witness programs cannot be wrapped in P2WSH, if this script
        // is a witness program, don't return addresses for a segwit programs.
        const bool can_wrap_P2WSH{[&] {
            switch (which_type) {
            case TxoutType::MULTISIG:
            case TxoutType::PUBKEY:
            // Uncompressed pubkeys cannot be used with segwit checksigs.
            // If the script contains an uncompressed pubkey, skip encoding of a segwit program.
                for (const auto& solution : solutions_data) {
                    if ((solution.size() != 1) && !CPubKey(solution).IsCompressed()) {
                        return false;
                    }
                }
                return true;
            case TxoutType::NONSTANDARD:
            case TxoutType::PUBKEYHASH:
                // Can be P2WSH wrapped
                return true;
            case TxoutType::NULL_DATA:
            case TxoutType::SCRIPTHASH:
            case TxoutType::WITNESS_UNKNOWN:
            case TxoutType::WITNESS_V0_KEYHASH:
            case TxoutType::WITNESS_V0_SCRIPTHASH:
            case TxoutType::WITNESS_V1_TAPROOT:
            case TxoutType::WITNESS_V2_TAPROOT:
            case TxoutType::ANCHOR:
                // Should not be wrapped
                return false;
            } // no default case, so the compiler can warn about missing cases
            NONFATAL_UNREACHABLE();
        }()};
        if (can_wrap_P2WSH) {
            UniValue sr(UniValue::VOBJ);
            CScript segwitScr;
            FlatSigningProvider provider;
            if (which_type == TxoutType::PUBKEY) {
                segwitScr = GetScriptForDestination(WitnessV0KeyHash(Hash160(solutions_data[0])));
            } else if (which_type == TxoutType::PUBKEYHASH) {
                segwitScr = GetScriptForDestination(WitnessV0KeyHash(uint160{solutions_data[0]}));
            } else {
                // Scripts that are not fit for P2WPKH are encoded as P2WSH.
                provider.scripts[CScriptID(script)] = script;
                segwitScr = GetScriptForDestination(WitnessV0ScriptHash(script));
            }
            ScriptToUniv(segwitScr, /*out=*/sr, /*include_hex=*/true, /*include_address=*/true, /*provider=*/&provider);
            sr.pushKV("p2sh-segwit", EncodeDestination(ScriptHash(segwitScr)));
            r.pushKV("segwit", std::move(sr));
        }
    }

    return r;
},
    };
}

static RPCHelpMan combinerawtransaction()
{
    return RPCHelpMan{"combinerawtransaction",
                "\nCombine multiple partially signed transactions into one transaction.\n"
                "The combined transaction may be another partially signed transaction or a \n"
                "fully signed transaction.",
                {
                    {"txs", RPCArg::Type::ARR, RPCArg::Optional::NO, "The hex strings of partially signed transactions",
                        {
                            {"hexstring", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "A hex-encoded raw transaction"},
                        },
                        },
                },
                RPCResult{
                    RPCResult::Type::STR, "", "The hex-encoded raw transaction with signature(s)"
                },
                RPCExamples{
                    HelpExampleCli("combinerawtransaction", R"('["myhex1", "myhex2", "myhex3"]')")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{

    UniValue txs = request.params[0].get_array();
    std::vector<CMutableTransaction> txVariants(txs.size());

    for (unsigned int idx = 0; idx < txs.size(); idx++) {
        if (!DecodeHexTx(txVariants[idx], txs[idx].get_str())) {
            throw JSONRPCError(RPC_DESERIALIZATION_ERROR, strprintf("TX decode failed for tx %d. Make sure the tx has at least one input.", idx));
        }
    }

    if (txVariants.empty()) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Missing transactions");
    }

    // mergedTx will end up with all the signatures; it
    // starts as a clone of the rawtx:
    CMutableTransaction mergedTx(txVariants[0]);

    // Fetch previous transactions (inputs):
    CCoinsView viewDummy;
    CCoinsViewCache view(&viewDummy);
    {
        NodeContext& node = EnsureAnyNodeContext(request.context);
        const CTxMemPool& mempool = EnsureMemPool(node);
        ChainstateManager& chainman = EnsureChainman(node);
        LOCK2(cs_main, mempool.cs);
        CCoinsViewCache &viewChain = chainman.ActiveChainstate().CoinsTip();
        CCoinsViewMemPool viewMempool(&viewChain, mempool);
        view.SetBackend(viewMempool); // temporarily switch cache backend to db+mempool view

        for (const CTxIn& txin : mergedTx.vin) {
            view.AccessCoin(txin.prevout); // Load entries from viewChain into view; can fail.
        }

        view.SetBackend(viewDummy); // switch back to avoid locking mempool for too long
    }

    // Use CTransaction for the constant parts of the
    // transaction to avoid rehashing.
    const CTransaction txConst(mergedTx);
    // Sign what we can:
    for (unsigned int i = 0; i < mergedTx.vin.size(); i++) {
        CTxIn& txin = mergedTx.vin[i];
        const Coin& coin = view.AccessCoin(txin.prevout);
        if (coin.IsSpent()) {
            throw JSONRPCError(RPC_VERIFY_ERROR, "Input not found or already spent");
        }
        SignatureData sigdata;

        // ... and merge in other signatures:
        for (const CMutableTransaction& txv : txVariants) {
            if (txv.vin.size() > i) {
                sigdata.MergeSignatureData(DataFromTransaction(txv, i, coin.out));
            }
        }
        ProduceSignature(DUMMY_SIGNING_PROVIDER, MutableTransactionSignatureCreator(mergedTx, i, coin.out.nValue, 1), coin.out.scriptPubKey, sigdata);

        UpdateInput(txin, sigdata);
    }

    return EncodeHexTx(CTransaction(mergedTx));
},
    };
}

static RPCHelpMan signrawtransactionwithkey()
{
    return RPCHelpMan{"signrawtransactionwithkey",
                "\nSign inputs for raw transaction (serialized, hex-encoded).\n"
                "The second argument is an array of base58-encoded private\n"
                "keys that will be the only keys used to sign the transaction.\n"
                "The third optional argument (may be null) is an array of previous transaction outputs that\n"
                "this transaction depends on but may not yet be in the block chain.\n",
                {
                    {"hexstring", RPCArg::Type::STR, RPCArg::Optional::NO, "The transaction hex string"},
                    {"privkeys", RPCArg::Type::ARR, RPCArg::Optional::NO, "The base58-encoded private keys for signing",
                        {
                            {"privatekey", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "private key in base58-encoding"},
                        },
                        },
                    {"prevtxs", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "The previous dependent transaction outputs",
                        {
                            {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                                {
                                    {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction id"},
                                    {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "The output number"},
                                    {"scriptPubKey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "output script"},
                                    {"redeemScript", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "(required for P2SH) redeem script"},
                                    {"witnessScript", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "(required for P2WSH or P2SH-P2WSH) witness script"},
                                    {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::OMITTED, "(required for Segwit inputs) the amount spent"},
                                },
                                },
                        },
                        },
                    {"sighashtype", RPCArg::Type::STR, RPCArg::Default{"DEFAULT for Taproot, ALL otherwise"}, "The signature hash type. Must be one of:\n"
            "       \"DEFAULT\"\n"
            "       \"ALL\"\n"
            "       \"NONE\"\n"
            "       \"SINGLE\"\n"
            "       \"ALL|ANYONECANPAY\"\n"
            "       \"NONE|ANYONECANPAY\"\n"
            "       \"SINGLE|ANYONECANPAY\"\n"
                    },
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "hex", "The hex-encoded raw transaction with signature(s)"},
                        {RPCResult::Type::BOOL, "complete", "If the transaction has a complete set of signatures"},
                        {RPCResult::Type::ARR, "errors", /*optional=*/true, "Script verification errors (if there are any)",
                        {
                            {RPCResult::Type::OBJ, "", "",
                            {
                                {RPCResult::Type::STR_HEX, "txid", "The hash of the referenced, previous transaction"},
                                {RPCResult::Type::NUM, "vout", "The index of the output to spent and used as input"},
                                {RPCResult::Type::ARR, "witness", "",
                                {
                                    {RPCResult::Type::STR_HEX, "witness", ""},
                                }},
                                {RPCResult::Type::STR_HEX, "scriptSig", "The hex-encoded signature script"},
                                {RPCResult::Type::NUM, "sequence", "Script sequence number"},
                                {RPCResult::Type::STR, "error", "Verification or signing error related to the input"},
                            }},
                        }},
                    }
                },
                RPCExamples{
                    HelpExampleCli("signrawtransactionwithkey", "\"myhex\" \"[\\\"key1\\\",\\\"key2\\\"]\"")
            + HelpExampleRpc("signrawtransactionwithkey", "\"myhex\", \"[\\\"key1\\\",\\\"key2\\\"]\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    CMutableTransaction mtx;
    if (!DecodeHexTx(mtx, request.params[0].get_str())) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed. Make sure the tx has at least one input.");
    }

    FlatSigningProvider keystore;
    const UniValue& keys = request.params[1].get_array();
    for (unsigned int idx = 0; idx < keys.size(); ++idx) {
        UniValue k = keys[idx];
        CKey key = DecodeSecret(k.get_str());
        if (!key.IsValid()) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid private key");
        }

        CPubKey pubkey = key.GetPubKey();
        CKeyID key_id = pubkey.GetID();
        keystore.pubkeys.emplace(key_id, pubkey);
        keystore.keys.emplace(key_id, key);
    }

    // Fetch previous transactions (inputs):
    std::map<COutPoint, Coin> coins;
    for (const CTxIn& txin : mtx.vin) {
        coins[txin.prevout]; // Create empty map entry keyed by prevout.
    }
    NodeContext& node = EnsureAnyNodeContext(request.context);
    FindCoins(node, coins);

    // Parse the prevtxs array
    ParsePrevouts(request.params[2], &keystore, coins);

    UniValue result(UniValue::VOBJ);
    SignTransaction(mtx, &keystore, coins, request.params[3], result);
    return result;
},
    };
}

const RPCResult decodepsbt_inputs{
    RPCResult::Type::ARR, "inputs", "",
    {
        {RPCResult::Type::OBJ, "", "",
        {
            {RPCResult::Type::OBJ, "non_witness_utxo", /*optional=*/true, "Decoded network transaction for non-witness UTXOs",
            {
                {RPCResult::Type::ELISION, "",""},
            }},
            {RPCResult::Type::OBJ, "witness_utxo", /*optional=*/true, "Transaction output for witness UTXOs",
            {
                {RPCResult::Type::NUM, "amount", "The value in " + CURRENCY_UNIT},
                {RPCResult::Type::OBJ, "scriptPubKey", "",
                {
                    {RPCResult::Type::STR, "asm", "Disassembly of the output script"},
                    {RPCResult::Type::STR, "desc", "Inferred descriptor for the output"},
                    {RPCResult::Type::STR_HEX, "hex", "The raw output script bytes, hex-encoded"},
                    {RPCResult::Type::STR, "type", "The type, eg 'pubkeyhash'"},
                    {RPCResult::Type::STR, "address", /*optional=*/true, "The Bitcoin address (only if a well-defined address exists)"},
                }},
            }},
            {RPCResult::Type::OBJ_DYN, "partial_signatures", /*optional=*/true, "",
            {
                {RPCResult::Type::STR, "pubkey", "The public key and signature that corresponds to it."},
            }},
            {RPCResult::Type::STR, "sighash", /*optional=*/true, "The sighash type to be used"},
            {RPCResult::Type::OBJ, "redeem_script", /*optional=*/true, "",
            {
                {RPCResult::Type::STR, "asm", "Disassembly of the redeem script"},
                {RPCResult::Type::STR_HEX, "hex", "The raw redeem script bytes, hex-encoded"},
                {RPCResult::Type::STR, "type", "The type, eg 'pubkeyhash'"},
            }},
            {RPCResult::Type::OBJ, "witness_script", /*optional=*/true, "",
            {
                {RPCResult::Type::STR, "asm", "Disassembly of the witness script"},
                {RPCResult::Type::STR_HEX, "hex", "The raw witness script bytes, hex-encoded"},
                {RPCResult::Type::STR, "type", "The type, eg 'pubkeyhash'"},
            }},
            {RPCResult::Type::ARR, "bip32_derivs", /*optional=*/true, "",
            {
                {RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::STR, "pubkey", "The public key with the derivation path as the value."},
                    {RPCResult::Type::STR, "master_fingerprint", "The fingerprint of the master key"},
                    {RPCResult::Type::STR, "path", "The path"},
                }},
            }},
            {RPCResult::Type::OBJ, "final_scriptSig", /*optional=*/true, "",
            {
                {RPCResult::Type::STR, "asm", "Disassembly of the final signature script"},
                {RPCResult::Type::STR_HEX, "hex", "The raw final signature script bytes, hex-encoded"},
            }},
            {RPCResult::Type::ARR, "final_scriptwitness", /*optional=*/true, "",
            {
                {RPCResult::Type::STR_HEX, "", "hex-encoded witness data (if any)"},
            }},
            {RPCResult::Type::OBJ_DYN, "ripemd160_preimages", /*optional=*/ true, "",
            {
                {RPCResult::Type::STR, "hash", "The hash and preimage that corresponds to it."},
            }},
            {RPCResult::Type::OBJ_DYN, "sha256_preimages", /*optional=*/ true, "",
            {
                {RPCResult::Type::STR, "hash", "The hash and preimage that corresponds to it."},
            }},
            {RPCResult::Type::OBJ_DYN, "hash160_preimages", /*optional=*/ true, "",
            {
                {RPCResult::Type::STR, "hash", "The hash and preimage that corresponds to it."},
            }},
            {RPCResult::Type::OBJ_DYN, "hash256_preimages", /*optional=*/ true, "",
            {
                {RPCResult::Type::STR, "hash", "The hash and preimage that corresponds to it."},
            }},
            {RPCResult::Type::STR_HEX, "taproot_key_path_sig", /*optional=*/ true, "hex-encoded signature for the Taproot key path spend"},
            {RPCResult::Type::ARR, "taproot_script_path_sigs", /*optional=*/ true, "",
            {
                {RPCResult::Type::OBJ, "signature", /*optional=*/ true, "The signature for the pubkey and leaf hash combination",
                {
                    {RPCResult::Type::STR, "pubkey", "The x-only pubkey for this signature"},
                    {RPCResult::Type::STR, "leaf_hash", "The leaf hash for this signature"},
                    {RPCResult::Type::STR, "sig", "The signature itself"},
                }},
            }},
            {RPCResult::Type::ARR, "taproot_scripts", /*optional=*/ true, "",
            {
                {RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::STR_HEX, "script", "A leaf script"},
                    {RPCResult::Type::NUM, "leaf_ver", "The version number for the leaf script"},
                    {RPCResult::Type::ARR, "control_blocks", "The control blocks for this script",
                    {
                        {RPCResult::Type::STR_HEX, "control_block", "A hex-encoded control block for this script"},
                    }},
                }},
            }},
            {RPCResult::Type::ARR, "taproot_bip32_derivs", /*optional=*/ true, "",
            {
                {RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::STR, "pubkey", "The x-only public key this path corresponds to"},
                    {RPCResult::Type::STR, "master_fingerprint", "The fingerprint of the master key"},
                    {RPCResult::Type::STR, "path", "The path"},
                    {RPCResult::Type::ARR, "leaf_hashes", "The hashes of the leaves this pubkey appears in",
                    {
                        {RPCResult::Type::STR_HEX, "hash", "The hash of a leaf this pubkey appears in"},
                    }},
                }},
            }},
            {RPCResult::Type::STR_HEX, "taproot_internal_key", /*optional=*/ true, "The hex-encoded Taproot x-only internal key"},
            {RPCResult::Type::STR_HEX, "taproot_merkle_root", /*optional=*/ true, "The hex-encoded Taproot merkle root"},
            {RPCResult::Type::ARR, "musig2_participant_pubkeys", /*optional=*/true, "",
            {
                {RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::STR_HEX, "aggregate_pubkey", "The compressed aggregate public key for which the participants create."},
                    {RPCResult::Type::ARR, "participant_pubkeys", "",
                    {
                        {RPCResult::Type::STR_HEX, "pubkey", "The compressed public keys that are aggregated for aggregate_pubkey."},
                    }},
                }},
            }},
            {RPCResult::Type::ARR, "musig2_pubnonces", /*optional=*/true, "",
            {
                {RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::STR_HEX, "participant_pubkey", "The compressed public key of the participant that created this pubnonce."},
                    {RPCResult::Type::STR_HEX, "aggregate_pubkey", "The compressed aggregate public key for which this pubnonce is for."},
                    {RPCResult::Type::STR_HEX, "leaf_hash", /*optional=*/true, "The hash of the leaf script that contains the aggregate pubkey being signed for. Omitted when signing for the internal key."},
                    {RPCResult::Type::STR_HEX, "pubnonce", "The public nonce itself."},
                }},
            }},
            {RPCResult::Type::ARR, "musig2_partial_sigs", /*optional=*/true, "",
            {
                {RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::STR_HEX, "participant_pubkey", "The compressed public key of the participant that created this partial signature."},
                    {RPCResult::Type::STR_HEX, "aggregate_pubkey", "The compressed aggregate public key for which this partial signature is for."},
                    {RPCResult::Type::STR_HEX, "leaf_hash", /*optional=*/true, "The hash of the leaf script that contains the aggregate pubkey being signed for. Omitted when signing for the internal key."},
                    {RPCResult::Type::STR_HEX, "partial_sig", "The partial signature itself."},
                }},
            }},
            {RPCResult::Type::OBJ_DYN, "unknown", /*optional=*/ true, "The unknown input fields",
            {
                {RPCResult::Type::STR_HEX, "key", "(key-value pair) An unknown key-value pair"},
            }},
            {RPCResult::Type::ARR, "proprietary", /*optional=*/true, "The input proprietary map",
            {
                {RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::STR_HEX, "identifier", "The hex string for the proprietary identifier"},
                    {RPCResult::Type::NUM, "subtype", "The number for the subtype"},
                    {RPCResult::Type::STR_HEX, "key", "The hex for the key"},
                    {RPCResult::Type::STR_HEX, "value", "The hex for the value"},
                }},
            }},
        }},
    }
};

const RPCResult decodepsbt_outputs{
    RPCResult::Type::ARR, "outputs", "",
    {
        {RPCResult::Type::OBJ, "", "",
        {
            {RPCResult::Type::OBJ, "redeem_script", /*optional=*/true, "",
            {
                {RPCResult::Type::STR, "asm", "Disassembly of the redeem script"},
                {RPCResult::Type::STR_HEX, "hex", "The raw redeem script bytes, hex-encoded"},
                {RPCResult::Type::STR, "type", "The type, eg 'pubkeyhash'"},
            }},
            {RPCResult::Type::OBJ, "witness_script", /*optional=*/true, "",
            {
                {RPCResult::Type::STR, "asm", "Disassembly of the witness script"},
                {RPCResult::Type::STR_HEX, "hex", "The raw witness script bytes, hex-encoded"},
                {RPCResult::Type::STR, "type", "The type, eg 'pubkeyhash'"},
            }},
            {RPCResult::Type::ARR, "bip32_derivs", /*optional=*/true, "",
            {
                {RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::STR, "pubkey", "The public key this path corresponds to"},
                    {RPCResult::Type::STR, "master_fingerprint", "The fingerprint of the master key"},
                    {RPCResult::Type::STR, "path", "The path"},
                }},
            }},
            {RPCResult::Type::STR_HEX, "taproot_internal_key", /*optional=*/ true, "The hex-encoded Taproot x-only internal key"},
            {RPCResult::Type::ARR, "taproot_tree", /*optional=*/ true, "The tuples that make up the Taproot tree, in depth first search order",
            {
                {RPCResult::Type::OBJ, "tuple", /*optional=*/ true, "A single leaf script in the taproot tree",
                {
                    {RPCResult::Type::NUM, "depth", "The depth of this element in the tree"},
                    {RPCResult::Type::NUM, "leaf_ver", "The version of this leaf"},
                    {RPCResult::Type::STR, "script", "The hex-encoded script itself"},
                }},
            }},
            {RPCResult::Type::ARR, "taproot_bip32_derivs", /*optional=*/ true, "",
            {
                {RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::STR, "pubkey", "The x-only public key this path corresponds to"},
                    {RPCResult::Type::STR, "master_fingerprint", "The fingerprint of the master key"},
                    {RPCResult::Type::STR, "path", "The path"},
                    {RPCResult::Type::ARR, "leaf_hashes", "The hashes of the leaves this pubkey appears in",
                    {
                        {RPCResult::Type::STR_HEX, "hash", "The hash of a leaf this pubkey appears in"},
                    }},
                }},
            }},
            {RPCResult::Type::ARR, "musig2_participant_pubkeys", /*optional=*/true, "",
            {
                {RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::STR_HEX, "aggregate_pubkey", "The compressed aggregate public key for which the participants create."},
                    {RPCResult::Type::ARR, "participant_pubkeys", "",
                    {
                        {RPCResult::Type::STR_HEX, "pubkey", "The compressed public keys that are aggregated for aggregate_pubkey."},
                    }},
                }},
            }},
            {RPCResult::Type::OBJ_DYN, "unknown", /*optional=*/true, "The unknown output fields",
            {
                {RPCResult::Type::STR_HEX, "key", "(key-value pair) An unknown key-value pair"},
            }},
            {RPCResult::Type::ARR, "proprietary", /*optional=*/true, "The output proprietary map",
            {
                {RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::STR_HEX, "identifier", "The hex string for the proprietary identifier"},
                    {RPCResult::Type::NUM, "subtype", "The number for the subtype"},
                    {RPCResult::Type::STR_HEX, "key", "The hex for the key"},
                    {RPCResult::Type::STR_HEX, "value", "The hex for the value"},
                }},
            }},
        }},
    }
};

static RPCHelpMan decodepsbt()
{
    return RPCHelpMan{
        "decodepsbt",
        "Return a JSON object representing the serialized, base64-encoded partially signed Bitcoin transaction.",
                {
                    {"psbt", RPCArg::Type::STR, RPCArg::Optional::NO, "The PSBT base64 string"},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::OBJ, "tx", "The decoded network-serialized unsigned transaction.",
                        {
                            {RPCResult::Type::ELISION, "", "The layout is the same as the output of decoderawtransaction."},
                        }},
                        {RPCResult::Type::ARR, "global_xpubs", "",
                        {
                            {RPCResult::Type::OBJ, "", "",
                            {
                                {RPCResult::Type::STR, "xpub", "The extended public key this path corresponds to"},
                                {RPCResult::Type::STR_HEX, "master_fingerprint", "The fingerprint of the master key"},
                                {RPCResult::Type::STR, "path", "The path"},
                            }},
                        }},
                        {RPCResult::Type::NUM, "psbt_version", "The PSBT version number. Not to be confused with the unsigned transaction version"},
                        {RPCResult::Type::ARR, "proprietary", "The global proprietary map",
                        {
                            {RPCResult::Type::OBJ, "", "",
                            {
                                {RPCResult::Type::STR_HEX, "identifier", "The hex string for the proprietary identifier"},
                                {RPCResult::Type::NUM, "subtype", "The number for the subtype"},
                                {RPCResult::Type::STR_HEX, "key", "The hex for the key"},
                                {RPCResult::Type::STR_HEX, "value", "The hex for the value"},
                            }},
                        }},
                        {RPCResult::Type::OBJ_DYN, "unknown", "The unknown global fields",
                        {
                             {RPCResult::Type::STR_HEX, "key", "(key-value pair) An unknown key-value pair"},
                        }},
                        decodepsbt_inputs,
                        decodepsbt_outputs,
                        {RPCResult::Type::STR_AMOUNT, "fee", /*optional=*/true, "The transaction fee paid if all UTXOs slots in the PSBT have been filled."},
                    }
                },
                RPCExamples{
                    HelpExampleCli("decodepsbt", "\"psbt\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    // Unserialize the transactions
    PartiallySignedTransaction psbtx;
    std::string error;
    if (!DecodeBase64PSBT(psbtx, request.params[0].get_str(), error)) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, strprintf("TX decode failed %s", error));
    }

    UniValue result(UniValue::VOBJ);

    // Add the decoded tx
    UniValue tx_univ(UniValue::VOBJ);
    TxToUniv(CTransaction(*psbtx.tx), /*block_hash=*/uint256(), /*entry=*/tx_univ, /*include_hex=*/false);
    result.pushKV("tx", std::move(tx_univ));

    // Add the global xpubs
    UniValue global_xpubs(UniValue::VARR);
    for (std::pair<KeyOriginInfo, std::set<CExtPubKey>> xpub_pair : psbtx.m_xpubs) {
        for (auto& xpub : xpub_pair.second) {
            std::vector<unsigned char> ser_xpub;
            ser_xpub.assign(BIP32_EXTKEY_WITH_VERSION_SIZE, 0);
            xpub.EncodeWithVersion(ser_xpub.data());

            UniValue keypath(UniValue::VOBJ);
            keypath.pushKV("xpub", EncodeBase58Check(ser_xpub));
            keypath.pushKV("master_fingerprint", HexStr(std::span<unsigned char>(xpub_pair.first.fingerprint, xpub_pair.first.fingerprint + 4)));
            keypath.pushKV("path", WriteHDKeypath(xpub_pair.first.path));
            global_xpubs.push_back(std::move(keypath));
        }
    }
    result.pushKV("global_xpubs", std::move(global_xpubs));

    // PSBT version
    result.pushKV("psbt_version", static_cast<uint64_t>(psbtx.GetVersion()));

    // Proprietary
    UniValue proprietary(UniValue::VARR);
    for (const auto& entry : psbtx.m_proprietary) {
        UniValue this_prop(UniValue::VOBJ);
        this_prop.pushKV("identifier", HexStr(entry.identifier));
        this_prop.pushKV("subtype", entry.subtype);
        this_prop.pushKV("key", HexStr(entry.key));
        this_prop.pushKV("value", HexStr(entry.value));
        proprietary.push_back(std::move(this_prop));
    }
    result.pushKV("proprietary", std::move(proprietary));

    // Unknown data
    UniValue unknowns(UniValue::VOBJ);
    for (auto entry : psbtx.unknown) {
        unknowns.pushKV(HexStr(entry.first), HexStr(entry.second));
    }
    result.pushKV("unknown", std::move(unknowns));

    // inputs
    CAmount total_in = 0;
    bool have_all_utxos = true;
    UniValue inputs(UniValue::VARR);
    for (unsigned int i = 0; i < psbtx.inputs.size(); ++i) {
        const PSBTInput& input = psbtx.inputs[i];
        UniValue in(UniValue::VOBJ);
        // UTXOs
        bool have_a_utxo = false;
        CTxOut txout;
        if (!input.witness_utxo.IsNull()) {
            txout = input.witness_utxo;

            UniValue o(UniValue::VOBJ);
            ScriptToUniv(txout.scriptPubKey, /*out=*/o, /*include_hex=*/true, /*include_address=*/true);

            UniValue out(UniValue::VOBJ);
            out.pushKV("amount", ValueFromAmount(txout.nValue));
            out.pushKV("scriptPubKey", std::move(o));

            in.pushKV("witness_utxo", std::move(out));

            have_a_utxo = true;
        }
        if (input.non_witness_utxo) {
            txout = input.non_witness_utxo->vout[psbtx.tx->vin[i].prevout.n];

            UniValue non_wit(UniValue::VOBJ);
            TxToUniv(*input.non_witness_utxo, /*block_hash=*/uint256(), /*entry=*/non_wit, /*include_hex=*/false);
            in.pushKV("non_witness_utxo", std::move(non_wit));

            have_a_utxo = true;
        }
        if (have_a_utxo) {
            if (MoneyRange(txout.nValue) && MoneyRange(total_in + txout.nValue)) {
                total_in += txout.nValue;
            } else {
                // Hack to just not show fee later
                have_all_utxos = false;
            }
        } else {
            have_all_utxos = false;
        }

        // Partial sigs
        if (!input.partial_sigs.empty()) {
            UniValue partial_sigs(UniValue::VOBJ);
            for (const auto& sig : input.partial_sigs) {
                partial_sigs.pushKV(HexStr(sig.second.first), HexStr(sig.second.second));
            }
            in.pushKV("partial_signatures", std::move(partial_sigs));
        }

        // Sighash
        if (input.sighash_type != std::nullopt) {
            in.pushKV("sighash", SighashToStr((unsigned char)*input.sighash_type));
        }

        // Redeem script and witness script
        if (!input.redeem_script.empty()) {
            UniValue r(UniValue::VOBJ);
            ScriptToUniv(input.redeem_script, /*out=*/r);
            in.pushKV("redeem_script", std::move(r));
        }
        if (!input.witness_script.empty()) {
            UniValue r(UniValue::VOBJ);
            ScriptToUniv(input.witness_script, /*out=*/r);
            in.pushKV("witness_script", std::move(r));
        }

        // keypaths
        if (!input.hd_keypaths.empty()) {
            UniValue keypaths(UniValue::VARR);
            for (auto entry : input.hd_keypaths) {
                UniValue keypath(UniValue::VOBJ);
                keypath.pushKV("pubkey", HexStr(entry.first));

                keypath.pushKV("master_fingerprint", strprintf("%08x", ReadBE32(entry.second.fingerprint)));
                keypath.pushKV("path", WriteHDKeypath(entry.second.path));
                keypaths.push_back(std::move(keypath));
            }
            in.pushKV("bip32_derivs", std::move(keypaths));
        }

        // Final scriptSig and scriptwitness
        if (!input.final_script_sig.empty()) {
            UniValue scriptsig(UniValue::VOBJ);
            scriptsig.pushKV("asm", ScriptToAsmStr(input.final_script_sig, true));
            scriptsig.pushKV("hex", HexStr(input.final_script_sig));
            in.pushKV("final_scriptSig", std::move(scriptsig));
        }
        if (!input.final_script_witness.IsNull()) {
            UniValue txinwitness(UniValue::VARR);
            for (const auto& item : input.final_script_witness.stack) {
                txinwitness.push_back(HexStr(item));
            }
            in.pushKV("final_scriptwitness", std::move(txinwitness));
        }

        // Ripemd160 hash preimages
        if (!input.ripemd160_preimages.empty()) {
            UniValue ripemd160_preimages(UniValue::VOBJ);
            for (const auto& [hash, preimage] : input.ripemd160_preimages) {
                ripemd160_preimages.pushKV(HexStr(hash), HexStr(preimage));
            }
            in.pushKV("ripemd160_preimages", std::move(ripemd160_preimages));
        }

        // Sha256 hash preimages
        if (!input.sha256_preimages.empty()) {
            UniValue sha256_preimages(UniValue::VOBJ);
            for (const auto& [hash, preimage] : input.sha256_preimages) {
                sha256_preimages.pushKV(HexStr(hash), HexStr(preimage));
            }
            in.pushKV("sha256_preimages", std::move(sha256_preimages));
        }

        // Hash160 hash preimages
        if (!input.hash160_preimages.empty()) {
            UniValue hash160_preimages(UniValue::VOBJ);
            for (const auto& [hash, preimage] : input.hash160_preimages) {
                hash160_preimages.pushKV(HexStr(hash), HexStr(preimage));
            }
            in.pushKV("hash160_preimages", std::move(hash160_preimages));
        }

        // Hash256 hash preimages
        if (!input.hash256_preimages.empty()) {
            UniValue hash256_preimages(UniValue::VOBJ);
            for (const auto& [hash, preimage] : input.hash256_preimages) {
                hash256_preimages.pushKV(HexStr(hash), HexStr(preimage));
            }
            in.pushKV("hash256_preimages", std::move(hash256_preimages));
        }

        // Taproot key path signature
        if (!input.m_tap_key_sig.empty()) {
            in.pushKV("taproot_key_path_sig", HexStr(input.m_tap_key_sig));
        }

        // Taproot script path signatures
        if (!input.m_tap_script_sigs.empty()) {
            UniValue script_sigs(UniValue::VARR);
            for (const auto& [pubkey_leaf, sig] : input.m_tap_script_sigs) {
                const auto& [xonly, leaf_hash] = pubkey_leaf;
                UniValue sigobj(UniValue::VOBJ);
                sigobj.pushKV("pubkey", HexStr(xonly));
                sigobj.pushKV("leaf_hash", HexStr(leaf_hash));
                sigobj.pushKV("sig", HexStr(sig));
                script_sigs.push_back(std::move(sigobj));
            }
            in.pushKV("taproot_script_path_sigs", std::move(script_sigs));
        }

        // Taproot leaf scripts
        if (!input.m_tap_scripts.empty()) {
            UniValue tap_scripts(UniValue::VARR);
            for (const auto& [leaf, control_blocks] : input.m_tap_scripts) {
                const auto& [script, leaf_ver] = leaf;
                UniValue script_info(UniValue::VOBJ);
                script_info.pushKV("script", HexStr(script));
                script_info.pushKV("leaf_ver", leaf_ver);
                UniValue control_blocks_univ(UniValue::VARR);
                for (const auto& control_block : control_blocks) {
                    control_blocks_univ.push_back(HexStr(control_block));
                }
                script_info.pushKV("control_blocks", std::move(control_blocks_univ));
                tap_scripts.push_back(std::move(script_info));
            }
            in.pushKV("taproot_scripts", std::move(tap_scripts));
        }

        // Taproot bip32 keypaths
        if (!input.m_tap_bip32_paths.empty()) {
            UniValue keypaths(UniValue::VARR);
            for (const auto& [xonly, leaf_origin] : input.m_tap_bip32_paths) {
                const auto& [leaf_hashes, origin] = leaf_origin;
                UniValue path_obj(UniValue::VOBJ);
                path_obj.pushKV("pubkey", HexStr(xonly));
                path_obj.pushKV("master_fingerprint", strprintf("%08x", ReadBE32(origin.fingerprint)));
                path_obj.pushKV("path", WriteHDKeypath(origin.path));
                UniValue leaf_hashes_arr(UniValue::VARR);
                for (const auto& leaf_hash : leaf_hashes) {
                    leaf_hashes_arr.push_back(HexStr(leaf_hash));
                }
                path_obj.pushKV("leaf_hashes", std::move(leaf_hashes_arr));
                keypaths.push_back(std::move(path_obj));
            }
            in.pushKV("taproot_bip32_derivs", std::move(keypaths));
        }

        // Taproot internal key
        if (!input.m_tap_internal_key.IsNull()) {
            in.pushKV("taproot_internal_key", HexStr(input.m_tap_internal_key));
        }

        // Write taproot merkle root
        if (!input.m_tap_merkle_root.IsNull()) {
            in.pushKV("taproot_merkle_root", HexStr(input.m_tap_merkle_root));
        }

        // Write MuSig2 fields
        if (!input.m_musig2_participants.empty()) {
            UniValue musig_pubkeys(UniValue::VARR);
            for (const auto& [agg, parts] : input.m_musig2_participants) {
                UniValue musig_part(UniValue::VOBJ);
                musig_part.pushKV("aggregate_pubkey", HexStr(agg));
                UniValue part_pubkeys(UniValue::VARR);
                for (const auto& pub : parts) {
                    part_pubkeys.push_back(HexStr(pub));
                }
                musig_part.pushKV("participant_pubkeys", part_pubkeys);
                musig_pubkeys.push_back(musig_part);
            }
            in.pushKV("musig2_participant_pubkeys", musig_pubkeys);
        }
        if (!input.m_musig2_pubnonces.empty()) {
            UniValue musig_pubnonces(UniValue::VARR);
            for (const auto& [agg_lh, part_pubnonce] : input.m_musig2_pubnonces) {
                const auto& [agg, lh] = agg_lh;
                for (const auto& [part, pubnonce] : part_pubnonce) {
                    UniValue info(UniValue::VOBJ);
                    info.pushKV("participant_pubkey", HexStr(part));
                    info.pushKV("aggregate_pubkey", HexStr(agg));
                    if (!lh.IsNull()) info.pushKV("leaf_hash", HexStr(lh));
                    info.pushKV("pubnonce", HexStr(pubnonce));
                    musig_pubnonces.push_back(info);
                }
            }
            in.pushKV("musig2_pubnonces", musig_pubnonces);
        }
        if (!input.m_musig2_partial_sigs.empty()) {
            UniValue musig_partial_sigs(UniValue::VARR);
            for (const auto& [agg_lh, part_psig] : input.m_musig2_partial_sigs) {
                const auto& [agg, lh] = agg_lh;
                for (const auto& [part, psig] : part_psig) {
                    UniValue info(UniValue::VOBJ);
                    info.pushKV("participant_pubkey", HexStr(part));
                    info.pushKV("aggregate_pubkey", HexStr(agg));
                    if (!lh.IsNull()) info.pushKV("leaf_hash", HexStr(lh));
                    info.pushKV("partial_sig", HexStr(psig));
                    musig_partial_sigs.push_back(info);
                }
            }
            in.pushKV("musig2_partial_sigs", musig_partial_sigs);
        }

        // Proprietary
        if (!input.m_proprietary.empty()) {
            UniValue proprietary(UniValue::VARR);
            for (const auto& entry : input.m_proprietary) {
                UniValue this_prop(UniValue::VOBJ);
                this_prop.pushKV("identifier", HexStr(entry.identifier));
                this_prop.pushKV("subtype", entry.subtype);
                this_prop.pushKV("key", HexStr(entry.key));
                this_prop.pushKV("value", HexStr(entry.value));
                proprietary.push_back(std::move(this_prop));
            }
            in.pushKV("proprietary", std::move(proprietary));
        }

        // Unknown data
        if (input.unknown.size() > 0) {
            UniValue unknowns(UniValue::VOBJ);
            for (auto entry : input.unknown) {
                unknowns.pushKV(HexStr(entry.first), HexStr(entry.second));
            }
            in.pushKV("unknown", std::move(unknowns));
        }

        inputs.push_back(std::move(in));
    }
    result.pushKV("inputs", std::move(inputs));

    // outputs
    CAmount output_value = 0;
    UniValue outputs(UniValue::VARR);
    for (unsigned int i = 0; i < psbtx.outputs.size(); ++i) {
        const PSBTOutput& output = psbtx.outputs[i];
        UniValue out(UniValue::VOBJ);
        // Redeem script and witness script
        if (!output.redeem_script.empty()) {
            UniValue r(UniValue::VOBJ);
            ScriptToUniv(output.redeem_script, /*out=*/r);
            out.pushKV("redeem_script", std::move(r));
        }
        if (!output.witness_script.empty()) {
            UniValue r(UniValue::VOBJ);
            ScriptToUniv(output.witness_script, /*out=*/r);
            out.pushKV("witness_script", std::move(r));
        }

        // keypaths
        if (!output.hd_keypaths.empty()) {
            UniValue keypaths(UniValue::VARR);
            for (auto entry : output.hd_keypaths) {
                UniValue keypath(UniValue::VOBJ);
                keypath.pushKV("pubkey", HexStr(entry.first));
                keypath.pushKV("master_fingerprint", strprintf("%08x", ReadBE32(entry.second.fingerprint)));
                keypath.pushKV("path", WriteHDKeypath(entry.second.path));
                keypaths.push_back(std::move(keypath));
            }
            out.pushKV("bip32_derivs", std::move(keypaths));
        }

        // Taproot internal key
        if (!output.m_tap_internal_key.IsNull()) {
            out.pushKV("taproot_internal_key", HexStr(output.m_tap_internal_key));
        }

        // Taproot tree
        if (!output.m_tap_tree.empty()) {
            UniValue tree(UniValue::VARR);
            for (const auto& [depth, leaf_ver, script] : output.m_tap_tree) {
                UniValue elem(UniValue::VOBJ);
                elem.pushKV("depth", (int)depth);
                elem.pushKV("leaf_ver", (int)leaf_ver);
                elem.pushKV("script", HexStr(script));
                tree.push_back(std::move(elem));
            }
            out.pushKV("taproot_tree", std::move(tree));
        }

        // Taproot bip32 keypaths
        if (!output.m_tap_bip32_paths.empty()) {
            UniValue keypaths(UniValue::VARR);
            for (const auto& [xonly, leaf_origin] : output.m_tap_bip32_paths) {
                const auto& [leaf_hashes, origin] = leaf_origin;
                UniValue path_obj(UniValue::VOBJ);
                path_obj.pushKV("pubkey", HexStr(xonly));
                path_obj.pushKV("master_fingerprint", strprintf("%08x", ReadBE32(origin.fingerprint)));
                path_obj.pushKV("path", WriteHDKeypath(origin.path));
                UniValue leaf_hashes_arr(UniValue::VARR);
                for (const auto& leaf_hash : leaf_hashes) {
                    leaf_hashes_arr.push_back(HexStr(leaf_hash));
                }
                path_obj.pushKV("leaf_hashes", std::move(leaf_hashes_arr));
                keypaths.push_back(std::move(path_obj));
            }
            out.pushKV("taproot_bip32_derivs", std::move(keypaths));
        }

        // Write MuSig2 fields
        if (!output.m_musig2_participants.empty()) {
            UniValue musig_pubkeys(UniValue::VARR);
            for (const auto& [agg, parts] : output.m_musig2_participants) {
                UniValue musig_part(UniValue::VOBJ);
                musig_part.pushKV("aggregate_pubkey", HexStr(agg));
                UniValue part_pubkeys(UniValue::VARR);
                for (const auto& pub : parts) {
                    part_pubkeys.push_back(HexStr(pub));
                }
                musig_part.pushKV("participant_pubkeys", part_pubkeys);
                musig_pubkeys.push_back(musig_part);
            }
            out.pushKV("musig2_participant_pubkeys", musig_pubkeys);
        }

        // Proprietary
        if (!output.m_proprietary.empty()) {
            UniValue proprietary(UniValue::VARR);
            for (const auto& entry : output.m_proprietary) {
                UniValue this_prop(UniValue::VOBJ);
                this_prop.pushKV("identifier", HexStr(entry.identifier));
                this_prop.pushKV("subtype", entry.subtype);
                this_prop.pushKV("key", HexStr(entry.key));
                this_prop.pushKV("value", HexStr(entry.value));
                proprietary.push_back(std::move(this_prop));
            }
            out.pushKV("proprietary", std::move(proprietary));
        }

        // Unknown data
        if (output.unknown.size() > 0) {
            UniValue unknowns(UniValue::VOBJ);
            for (auto entry : output.unknown) {
                unknowns.pushKV(HexStr(entry.first), HexStr(entry.second));
            }
            out.pushKV("unknown", std::move(unknowns));
        }

        outputs.push_back(std::move(out));

        // Fee calculation
        if (MoneyRange(psbtx.tx->vout[i].nValue) && MoneyRange(output_value + psbtx.tx->vout[i].nValue)) {
            output_value += psbtx.tx->vout[i].nValue;
        } else {
            // Hack to just not show fee later
            have_all_utxos = false;
        }
    }
    result.pushKV("outputs", std::move(outputs));
    if (have_all_utxos) {
        result.pushKV("fee", ValueFromAmount(total_in - output_value));
    }

    return result;
},
    };
}

static RPCHelpMan combinepsbt()
{
    return RPCHelpMan{"combinepsbt",
                "\nCombine multiple partially signed Bitcoin transactions into one transaction.\n"
                "Implements the Combiner role.\n",
                {
                    {"txs", RPCArg::Type::ARR, RPCArg::Optional::NO, "The base64 strings of partially signed transactions",
                        {
                            {"psbt", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "A base64 string of a PSBT"},
                        },
                        },
                },
                RPCResult{
                    RPCResult::Type::STR, "", "The base64-encoded partially signed transaction"
                },
                RPCExamples{
                    HelpExampleCli("combinepsbt", R"('["mybase64_1", "mybase64_2", "mybase64_3"]')")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    // Unserialize the transactions
    std::vector<PartiallySignedTransaction> psbtxs;
    UniValue txs = request.params[0].get_array();
    if (txs.empty()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Parameter 'txs' cannot be empty");
    }
    for (unsigned int i = 0; i < txs.size(); ++i) {
        PartiallySignedTransaction psbtx;
        std::string error;
        if (!DecodeBase64PSBT(psbtx, txs[i].get_str(), error)) {
            throw JSONRPCError(RPC_DESERIALIZATION_ERROR, strprintf("TX decode failed %s", error));
        }
        psbtxs.push_back(psbtx);
    }

    PartiallySignedTransaction merged_psbt;
    if (!CombinePSBTs(merged_psbt, psbtxs)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "PSBTs not compatible (different transactions)");
    }

    DataStream ssTx{};
    ssTx << merged_psbt;
    return EncodeBase64(ssTx);
},
    };
}

static RPCHelpMan finalizepsbt()
{
    return RPCHelpMan{"finalizepsbt",
                "Finalize the inputs of a PSBT. If the transaction is fully signed, it will produce a\n"
                "network serialized transaction which can be broadcast with sendrawtransaction. Otherwise a PSBT will be\n"
                "created which has the final_scriptSig and final_scriptWitness fields filled for inputs that are complete.\n"
                "Implements the Finalizer and Extractor roles.\n",
                {
                    {"psbt", RPCArg::Type::STR, RPCArg::Optional::NO, "A base64 string of a PSBT"},
                    {"extract", RPCArg::Type::BOOL, RPCArg::Default{true}, "If true and the transaction is complete,\n"
            "                             extract and return the complete transaction in normal network serialization instead of the PSBT."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR, "psbt", /*optional=*/true, "The base64-encoded partially signed transaction if not extracted"},
                        {RPCResult::Type::STR_HEX, "hex", /*optional=*/true, "The hex-encoded network transaction if extracted"},
                        {RPCResult::Type::BOOL, "complete", "If the transaction has a complete set of signatures"},
                    }
                },
                RPCExamples{
                    HelpExampleCli("finalizepsbt", "\"psbt\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    // Unserialize the transactions
    PartiallySignedTransaction psbtx;
    std::string error;
    if (!DecodeBase64PSBT(psbtx, request.params[0].get_str(), error)) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, strprintf("TX decode failed %s", error));
    }

    bool extract = request.params[1].isNull() || (!request.params[1].isNull() && request.params[1].get_bool());

    CMutableTransaction mtx;
    bool complete = FinalizeAndExtractPSBT(psbtx, mtx);

    UniValue result(UniValue::VOBJ);
    DataStream ssTx{};
    std::string result_str;

    if (complete && extract) {
        ssTx << TX_WITH_WITNESS(mtx);
        result_str = HexStr(ssTx);
        result.pushKV("hex", result_str);
    } else {
        ssTx << psbtx;
        result_str = EncodeBase64(ssTx.str());
        result.pushKV("psbt", result_str);
    }
    result.pushKV("complete", complete);

    return result;
},
    };
}

static RPCHelpMan createpsbt()
{
    return RPCHelpMan{"createpsbt",
                "\nCreates a transaction in the Partially Signed Transaction format.\n"
                "Implements the Creator role.\n"
                "Note that the transaction's inputs are not signed, and\n"
                "it is not stored in the wallet or transmitted to the network.\n",
                CreateTxDoc(),
                RPCResult{
                    RPCResult::Type::STR, "", "The resulting raw transaction (base64-encoded string)"
                },
                RPCExamples{
                    HelpExampleCli("createpsbt", "\"[{\\\"txid\\\":\\\"myid\\\",\\\"vout\\\":0}]\" \"[{\\\"address\\\":0.01}]\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{

    std::optional<bool> rbf;
    if (!request.params[3].isNull()) {
        rbf = request.params[3].get_bool();
    }
    CMutableTransaction rawTx = ConstructTransaction(request.params[0], request.params[1], request.params[2], rbf);

    // Make a blank psbt
    PartiallySignedTransaction psbtx;
    psbtx.tx = rawTx;
    for (unsigned int i = 0; i < rawTx.vin.size(); ++i) {
        psbtx.inputs.emplace_back();
    }
    for (unsigned int i = 0; i < rawTx.vout.size(); ++i) {
        psbtx.outputs.emplace_back();
    }

    // Serialize the PSBT
    DataStream ssTx{};
    ssTx << psbtx;

    return EncodeBase64(ssTx);
},
    };
}

static RPCHelpMan converttopsbt()
{
    return RPCHelpMan{"converttopsbt",
                "\nConverts a network serialized transaction to a PSBT. This should be used only with createrawtransaction and fundrawtransaction\n"
                "createpsbt and walletcreatefundedpsbt should be used for new applications.\n",
                {
                    {"hexstring", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The hex string of a raw transaction"},
                    {"permitsigdata", RPCArg::Type::BOOL, RPCArg::Default{false}, "If true, any signatures in the input will be discarded and conversion\n"
                            "                              will continue. If false, RPC will fail if any signatures are present."},
                    {"iswitness", RPCArg::Type::BOOL, RPCArg::DefaultHint{"depends on heuristic tests"}, "Whether the transaction hex is a serialized witness transaction.\n"
                        "If iswitness is not present, heuristic tests will be used in decoding.\n"
                        "If true, only witness deserialization will be tried.\n"
                        "If false, only non-witness deserialization will be tried.\n"
                        "This boolean should reflect whether the transaction has inputs\n"
                        "(e.g. fully valid, or on-chain transactions), if known by the caller."
                    },
                },
                RPCResult{
                    RPCResult::Type::STR, "", "The resulting raw transaction (base64-encoded string)"
                },
                RPCExamples{
                            "\nCreate a transaction\n"
                            + HelpExampleCli("createrawtransaction", "\"[{\\\"txid\\\":\\\"myid\\\",\\\"vout\\\":0}]\" \"[{\\\"data\\\":\\\"00010203\\\"}]\"") +
                            "\nConvert the transaction to a PSBT\n"
                            + HelpExampleCli("converttopsbt", "\"rawtransaction\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    // parse hex string from parameter
    CMutableTransaction tx;
    bool permitsigdata = request.params[1].isNull() ? false : request.params[1].get_bool();
    bool witness_specified = !request.params[2].isNull();
    bool iswitness = witness_specified ? request.params[2].get_bool() : false;
    const bool try_witness = witness_specified ? iswitness : true;
    const bool try_no_witness = witness_specified ? !iswitness : true;
    if (!DecodeHexTx(tx, request.params[0].get_str(), try_no_witness, try_witness)) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
    }

    // Remove all scriptSigs and scriptWitnesses from inputs
    for (CTxIn& input : tx.vin) {
        if ((!input.scriptSig.empty() || !input.scriptWitness.IsNull()) && !permitsigdata) {
            throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Inputs must not have scriptSigs and scriptWitnesses");
        }
        input.scriptSig.clear();
        input.scriptWitness.SetNull();
    }

    // Make a blank psbt
    PartiallySignedTransaction psbtx;
    psbtx.tx = tx;
    for (unsigned int i = 0; i < tx.vin.size(); ++i) {
        psbtx.inputs.emplace_back();
    }
    for (unsigned int i = 0; i < tx.vout.size(); ++i) {
        psbtx.outputs.emplace_back();
    }

    // Serialize the PSBT
    DataStream ssTx{};
    ssTx << psbtx;

    return EncodeBase64(ssTx);
},
    };
}

static RPCHelpMan utxoupdatepsbt()
{
    return RPCHelpMan{"utxoupdatepsbt",
            "\nUpdates all segwit inputs and outputs in a PSBT with data from output descriptors, the UTXO set, txindex, or the mempool.\n",
            {
                {"psbt", RPCArg::Type::STR, RPCArg::Optional::NO, "A base64 string of a PSBT"},
                {"descriptors", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "An array of either strings or objects", {
                    {"", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "An output descriptor"},
                    {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "An object with an output descriptor and extra information", {
                         {"desc", RPCArg::Type::STR, RPCArg::Optional::NO, "An output descriptor"},
                         {"range", RPCArg::Type::RANGE, RPCArg::Default{1000}, "Up to what index HD chains should be explored (either end or [begin,end])"},
                    }},
                }},
            },
            RPCResult {
                    RPCResult::Type::STR, "", "The base64-encoded partially signed transaction with inputs updated"
            },
            RPCExamples {
                HelpExampleCli("utxoupdatepsbt", "\"psbt\"")
            },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    // Parse descriptors, if any.
    FlatSigningProvider provider;
    if (!request.params[1].isNull()) {
        auto descs = request.params[1].get_array();
        for (size_t i = 0; i < descs.size(); ++i) {
            EvalDescriptorStringOrObject(descs[i], provider);
        }
    }

    // We don't actually need private keys further on; hide them as a precaution.
    const PartiallySignedTransaction& psbtx = ProcessPSBT(
        request.params[0].get_str(),
        request.context,
        HidingSigningProvider(&provider, /*hide_secret=*/true, /*hide_origin=*/false),
        /*sighash_type=*/SIGHASH_ALL,
        /*finalize=*/false);

    DataStream ssTx{};
    ssTx << psbtx;
    return EncodeBase64(ssTx);
},
    };
}

static RPCHelpMan joinpsbts()
{
    return RPCHelpMan{"joinpsbts",
            "\nJoins multiple distinct PSBTs with different inputs and outputs into one PSBT with inputs and outputs from all of the PSBTs\n"
            "No input in any of the PSBTs can be in more than one of the PSBTs.\n",
            {
                {"txs", RPCArg::Type::ARR, RPCArg::Optional::NO, "The base64 strings of partially signed transactions",
                    {
                        {"psbt", RPCArg::Type::STR, RPCArg::Optional::NO, "A base64 string of a PSBT"}
                    }}
            },
            RPCResult {
                    RPCResult::Type::STR, "", "The base64-encoded partially signed transaction"
            },
            RPCExamples {
                HelpExampleCli("joinpsbts", "\"psbt\"")
            },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    // Unserialize the transactions
    std::vector<PartiallySignedTransaction> psbtxs;
    UniValue txs = request.params[0].get_array();

    if (txs.size() <= 1) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "At least two PSBTs are required to join PSBTs.");
    }

    uint32_t best_version = 1;
    uint32_t best_locktime = 0xffffffff;
    for (unsigned int i = 0; i < txs.size(); ++i) {
        PartiallySignedTransaction psbtx;
        std::string error;
        if (!DecodeBase64PSBT(psbtx, txs[i].get_str(), error)) {
            throw JSONRPCError(RPC_DESERIALIZATION_ERROR, strprintf("TX decode failed %s", error));
        }
        psbtxs.push_back(psbtx);
        // Choose the highest version number
        if (psbtx.tx->version > best_version) {
            best_version = psbtx.tx->version;
        }
        // Choose the lowest lock time
        if (psbtx.tx->nLockTime < best_locktime) {
            best_locktime = psbtx.tx->nLockTime;
        }
    }

    // Create a blank psbt where everything will be added
    PartiallySignedTransaction merged_psbt;
    merged_psbt.tx = CMutableTransaction();
    merged_psbt.tx->version = best_version;
    merged_psbt.tx->nLockTime = best_locktime;

    // Merge
    for (auto& psbt : psbtxs) {
        for (unsigned int i = 0; i < psbt.tx->vin.size(); ++i) {
            if (!merged_psbt.AddInput(psbt.tx->vin[i], psbt.inputs[i])) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Input %s:%d exists in multiple PSBTs", psbt.tx->vin[i].prevout.hash.ToString(), psbt.tx->vin[i].prevout.n));
            }
        }
        for (unsigned int i = 0; i < psbt.tx->vout.size(); ++i) {
            merged_psbt.AddOutput(psbt.tx->vout[i], psbt.outputs[i]);
        }
        for (auto& xpub_pair : psbt.m_xpubs) {
            if (merged_psbt.m_xpubs.count(xpub_pair.first) == 0) {
                merged_psbt.m_xpubs[xpub_pair.first] = xpub_pair.second;
            } else {
                merged_psbt.m_xpubs[xpub_pair.first].insert(xpub_pair.second.begin(), xpub_pair.second.end());
            }
        }
        merged_psbt.unknown.insert(psbt.unknown.begin(), psbt.unknown.end());
    }

    // Generate list of shuffled indices for shuffling inputs and outputs of the merged PSBT
    std::vector<int> input_indices(merged_psbt.inputs.size());
    std::iota(input_indices.begin(), input_indices.end(), 0);
    std::vector<int> output_indices(merged_psbt.outputs.size());
    std::iota(output_indices.begin(), output_indices.end(), 0);

    // Shuffle input and output indices lists
    std::shuffle(input_indices.begin(), input_indices.end(), FastRandomContext());
    std::shuffle(output_indices.begin(), output_indices.end(), FastRandomContext());

    PartiallySignedTransaction shuffled_psbt;
    shuffled_psbt.tx = CMutableTransaction();
    shuffled_psbt.tx->version = merged_psbt.tx->version;
    shuffled_psbt.tx->nLockTime = merged_psbt.tx->nLockTime;
    for (int i : input_indices) {
        shuffled_psbt.AddInput(merged_psbt.tx->vin[i], merged_psbt.inputs[i]);
    }
    for (int i : output_indices) {
        shuffled_psbt.AddOutput(merged_psbt.tx->vout[i], merged_psbt.outputs[i]);
    }
    shuffled_psbt.unknown.insert(merged_psbt.unknown.begin(), merged_psbt.unknown.end());

    DataStream ssTx{};
    ssTx << shuffled_psbt;
    return EncodeBase64(ssTx);
},
    };
}

static RPCHelpMan analyzepsbt()
{
    return RPCHelpMan{"analyzepsbt",
            "\nAnalyzes and provides information about the current status of a PSBT and its inputs\n",
            {
                {"psbt", RPCArg::Type::STR, RPCArg::Optional::NO, "A base64 string of a PSBT"}
            },
            RPCResult {
                RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::ARR, "inputs", /*optional=*/true, "",
                    {
                        {RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::BOOL, "has_utxo", "Whether a UTXO is provided"},
                            {RPCResult::Type::BOOL, "is_final", "Whether the input is finalized"},
                            {RPCResult::Type::OBJ, "missing", /*optional=*/true, "Things that are missing that are required to complete this input",
                            {
                                {RPCResult::Type::ARR, "pubkeys", /*optional=*/true, "",
                                {
                                    {RPCResult::Type::STR_HEX, "keyid", "Public key ID, hash160 of the public key, of a public key whose BIP 32 derivation path is missing"},
                                }},
                                {RPCResult::Type::ARR, "signatures", /*optional=*/true, "",
                                {
                                    {RPCResult::Type::STR_HEX, "keyid", "Public key ID, hash160 of the public key, of a public key whose signature is missing"},
                                }},
                                {RPCResult::Type::STR_HEX, "redeemscript", /*optional=*/true, "Hash160 of the redeem script that is missing"},
                                {RPCResult::Type::STR_HEX, "witnessscript", /*optional=*/true, "SHA256 of the witness script that is missing"},
                            }},
                            {RPCResult::Type::STR, "next", /*optional=*/true, "Role of the next person that this input needs to go to"},
                        }},
                    }},
                    {RPCResult::Type::NUM, "estimated_vsize", /*optional=*/true, "Estimated vsize of the final signed transaction"},
                    {RPCResult::Type::STR_AMOUNT, "estimated_feerate", /*optional=*/true, "Estimated feerate of the final signed transaction in " + CURRENCY_UNIT + "/kvB. Shown only if all UTXO slots in the PSBT have been filled"},
                    {RPCResult::Type::STR_AMOUNT, "fee", /*optional=*/true, "The transaction fee paid. Shown only if all UTXO slots in the PSBT have been filled"},
                    {RPCResult::Type::STR, "next", "Role of the next person that this psbt needs to go to"},
                    {RPCResult::Type::STR, "error", /*optional=*/true, "Error message (if there is one)"},
                }
            },
            RPCExamples {
                HelpExampleCli("analyzepsbt", "\"psbt\"")
            },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    // Unserialize the transaction
    PartiallySignedTransaction psbtx;
    std::string error;
    if (!DecodeBase64PSBT(psbtx, request.params[0].get_str(), error)) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, strprintf("TX decode failed %s", error));
    }

    PSBTAnalysis psbta = AnalyzePSBT(psbtx);

    UniValue result(UniValue::VOBJ);
    UniValue inputs_result(UniValue::VARR);
    for (const auto& input : psbta.inputs) {
        UniValue input_univ(UniValue::VOBJ);
        UniValue missing(UniValue::VOBJ);

        input_univ.pushKV("has_utxo", input.has_utxo);
        input_univ.pushKV("is_final", input.is_final);
        input_univ.pushKV("next", PSBTRoleName(input.next));

        if (!input.missing_pubkeys.empty()) {
            UniValue missing_pubkeys_univ(UniValue::VARR);
            for (const CKeyID& pubkey : input.missing_pubkeys) {
                missing_pubkeys_univ.push_back(HexStr(pubkey));
            }
            missing.pushKV("pubkeys", std::move(missing_pubkeys_univ));
        }
        if (!input.missing_redeem_script.IsNull()) {
            missing.pushKV("redeemscript", HexStr(input.missing_redeem_script));
        }
        if (!input.missing_witness_script.IsNull()) {
            missing.pushKV("witnessscript", HexStr(input.missing_witness_script));
        }
        if (!input.missing_sigs.empty()) {
            UniValue missing_sigs_univ(UniValue::VARR);
            for (const CKeyID& pubkey : input.missing_sigs) {
                missing_sigs_univ.push_back(HexStr(pubkey));
            }
            missing.pushKV("signatures", std::move(missing_sigs_univ));
        }
        if (!missing.getKeys().empty()) {
            input_univ.pushKV("missing", std::move(missing));
        }
        inputs_result.push_back(std::move(input_univ));
    }
    if (!inputs_result.empty()) result.pushKV("inputs", std::move(inputs_result));

    if (psbta.estimated_vsize != std::nullopt) {
        result.pushKV("estimated_vsize", (int)*psbta.estimated_vsize);
    }
    if (psbta.estimated_feerate != std::nullopt) {
        result.pushKV("estimated_feerate", ValueFromAmount(psbta.estimated_feerate->GetFeePerK()));
    }
    if (psbta.fee != std::nullopt) {
        result.pushKV("fee", ValueFromAmount(*psbta.fee));
    }
    result.pushKV("next", PSBTRoleName(psbta.next));
    if (!psbta.error.empty()) {
        result.pushKV("error", psbta.error);
    }

    return result;
},
    };
}

RPCHelpMan descriptorprocesspsbt()
{
    return RPCHelpMan{"descriptorprocesspsbt",
                "\nUpdate all segwit inputs in a PSBT with information from output descriptors, the UTXO set or the mempool. \n"
                "Then, sign the inputs we are able to with information from the output descriptors. ",
                {
                    {"psbt", RPCArg::Type::STR, RPCArg::Optional::NO, "The transaction base64 string"},
                    {"descriptors", RPCArg::Type::ARR, RPCArg::Optional::NO, "An array of either strings or objects", {
                        {"", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "An output descriptor"},
                        {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "An object with an output descriptor and extra information", {
                             {"desc", RPCArg::Type::STR, RPCArg::Optional::NO, "An output descriptor"},
                             {"range", RPCArg::Type::RANGE, RPCArg::Default{1000}, "Up to what index HD chains should be explored (either end or [begin,end])"},
                        }},
                    }},
                    {"sighashtype", RPCArg::Type::STR, RPCArg::Default{"DEFAULT for Taproot, ALL otherwise"}, "The signature hash type to sign with if not specified by the PSBT. Must be one of\n"
            "       \"DEFAULT\"\n"
            "       \"ALL\"\n"
            "       \"NONE\"\n"
            "       \"SINGLE\"\n"
            "       \"ALL|ANYONECANPAY\"\n"
            "       \"NONE|ANYONECANPAY\"\n"
            "       \"SINGLE|ANYONECANPAY\""},
                    {"bip32derivs", RPCArg::Type::BOOL, RPCArg::Default{true}, "Include BIP 32 derivation paths for public keys if we know them"},
                    {"finalize", RPCArg::Type::BOOL, RPCArg::Default{true}, "Also finalize inputs if possible"},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR, "psbt", "The base64-encoded partially signed transaction"},
                        {RPCResult::Type::BOOL, "complete", "If the transaction has a complete set of signatures"},
                        {RPCResult::Type::STR_HEX, "hex", /*optional=*/true, "The hex-encoded network transaction if complete"},
                    }
                },
                RPCExamples{
                    HelpExampleCli("descriptorprocesspsbt", "\"psbt\" \"[\\\"descriptor1\\\", \\\"descriptor2\\\"]\"") +
                    HelpExampleCli("descriptorprocesspsbt", "\"psbt\" \"[{\\\"desc\\\":\\\"mydescriptor\\\", \\\"range\\\":21}]\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    // Add descriptor information to a signing provider
    FlatSigningProvider provider;

    auto descs = request.params[1].get_array();
    for (size_t i = 0; i < descs.size(); ++i) {
        EvalDescriptorStringOrObject(descs[i], provider, /*expand_priv=*/true);
    }

    int sighash_type = ParseSighashString(request.params[2]);
    bool bip32derivs = request.params[3].isNull() ? true : request.params[3].get_bool();
    bool finalize = request.params[4].isNull() ? true : request.params[4].get_bool();

    const PartiallySignedTransaction& psbtx = ProcessPSBT(
        request.params[0].get_str(),
        request.context,
        HidingSigningProvider(&provider, /*hide_secret=*/false, !bip32derivs),
        sighash_type,
        finalize);

    // Check whether or not all of the inputs are now signed
    bool complete = true;
    for (const auto& input : psbtx.inputs) {
        complete &= PSBTInputSigned(input);
    }

    DataStream ssTx{};
    ssTx << psbtx;

    UniValue result(UniValue::VOBJ);

    result.pushKV("psbt", EncodeBase64(ssTx));
    result.pushKV("complete", complete);
    if (complete) {
        CMutableTransaction mtx;
        PartiallySignedTransaction psbtx_copy = psbtx;
        CHECK_NONFATAL(FinalizeAndExtractPSBT(psbtx_copy, mtx));
        DataStream ssTx_final;
        ssTx_final << TX_WITH_WITNESS(mtx);
        result.pushKV("hex", HexStr(ssTx_final));
    }
    return result;
},
    };
}

// Result of the wallet-free chain resolution shared by icu.acceptance.prepare/.verify.
struct IcuAcceptancePrep {
    uint256 asset_id;
    std::string issuer_address;
    std::string holder_address;
    uint64_t holder_units{0};       // asset units in the bound holder prevout
    uint256 canonical_hash;         // = registry icu_plain_commit (the document hash / on-chain anchor)
    assets::IcuAcceptanceMode mode{assets::IcuAcceptanceMode::ACKNOWLEDGE};
    bool commitment_onchain{true};  // false => OP_RETURN omitted (KYC/TFR returns, multi-op-return policy)
    bool holder_utxo_live{false};   // holder prevout still unspent now
    std::string prevout_source;     // "utxo" (live) or "txindex" (spent; fetched from creating tx)
    std::string message;            // BIP-322 message a holder signs to attribute an acknowledgment
    uint256 context_hash;           // SHA256(committed context metadata); bound into the V2 message (legacy only)
    bool context_acceptance{false}; // true => the message carries body_refs (V2 metadata-context or V3 inline)
    bool inline_context{false};     // true => Option A inline-context asset => message is TSC-ICU-DOC-ACCEPT-3
    int accept_version{1};          // acceptance message version actually built: 1 (doc), 2 (metadata-context), 3 (inline)
    std::vector<std::string> body_refs;  // affirmed body keys (deduped + sorted) for context acceptance
};

// Read the committed TSC-ICU-CONTEXT-1 map for an asset, or nullopt if it has none. Holder-only
// payloads require the supplied DEK to decrypt -- nothing is published in cleartext, and the holder
// still had to decrypt the text to know what they were affirming. Throws on access/decrypt errors.
//
// Two context models are supported:
//  - Option A (inline): the authoritative TSC-ICU-CONTEXT-1 map is embedded inside canonical_text and
//    is therefore covered by icu_plain_commit. is_inline is set true and context_hash is left null
//    (the V3 message binds icu_plain_commit, not a separate context_hash). The recompute-or-refuse
//    gate (VerifyIcuPlainCommit) MUST pass.
//  - Legacy (metadata): the map lives in CanonicalIcuPayload.metadata, OUTSIDE the text hash, so a
//    stable context_hash over the metadata bytes is bound into the V2 message. is_inline stays false.
static std::optional<UniValue> ResolveIcuContext(
    CCoinsViewCache& view, const uint256& asset_id, const AssetRegistryEntry& entry,
    const std::optional<std::array<unsigned char, 32>>& dek, uint256& context_hash, bool& is_inline)
{
    is_inline = false;
    if (entry.icu_ctxt_commit.IsNull()) return std::nullopt;
    assets::IcuStorageEntry se;
    if (!view.ReadIcuPayload(asset_id, entry.icu_ctxt_commit, se)) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "ICU payload not found for asset");
    }
    std::optional<assets::CanonicalIcuPayload> payload;
    if (se.encryption_mode == 0) {
        std::vector<unsigned char> bytes = se.icu_cipher;
        if (se.compression == 1) {
            auto d = assets::DecompressZstd(bytes);
            if (!d) throw JSONRPCError(RPC_INTERNAL_ERROR, "ICU decompression failed");
            bytes = *d;
        }
        payload = assets::ParseCanonicalIcuPayload(bytes);
    } else {
        if (!dek) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                "holder-only asset: supply the 32-byte asset DEK ('dek') so the node can read the committed context map and determine the acceptance policy");
        }
        payload = assets::DecryptCanonicalIcuPayload(se.icu_cipher, *dek, entry.kdf_salt,
                                                     se.encryption_mode, se.compression);
        if (!payload) throw JSONRPCError(RPC_INVALID_PARAMETER, "supplied dek failed to decrypt the ICU payload");
    }
    if (!payload) throw JSONRPCError(RPC_INTERNAL_ERROR, "could not parse the ICU payload");

    // Defense / recompute-or-refuse: the decrypted/parsed canonical text MUST hash to the registry
    // commitment (consensus stores icu_plain_commit without verifying it).
    if (!entry.icu_plain_commit.IsNull()) {
        if (!assets::VerifyIcuPlainCommit(*payload, entry.icu_plain_commit)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "decrypted canonical text does not match the registry commitment");
        }
    }

    // Option A (inline): the authoritative map is embedded in canonical_text under icu_plain_commit.
    // Prefer it over any metadata map. Locate it on the NORMALIZED text (the form that was hashed).
    {
        const std::string canon_raw(payload->canonical_text.begin(), payload->canonical_text.end());
        std::string norm_text = canon_raw;
        if (auto normalized = assets::NormalizeCanonicalText(canon_raw)) {
            norm_text = *normalized;
        }
        bool ctx_present = false;
        std::string ctx_error;
        auto inline_ctx = assets::ExtractInlineIcuContext(norm_text, ctx_present, ctx_error);
        if (ctx_present) {
            if (!inline_ctx) {
                // Block exists but malformed/ambiguous -- fail-closed (this is a write/accept path).
                throw JSONRPCError(RPC_INVALID_PARAMETER, "committed inline context block is invalid: " + ctx_error);
            }
            is_inline = true;
            context_hash.SetNull();  // V3 binds icu_plain_commit, not a separate context_hash
            return inline_ctx;
        }
    }

    if (payload->metadata.empty()) return std::nullopt;
    UniValue meta;
    const std::string meta_str(payload->metadata.begin(), payload->metadata.end());
    if (!meta.read(meta_str) || !meta.isObject() || !meta.exists("spec") ||
        !meta["spec"].isStr() || meta["spec"].get_str() != assets::ICU_CONTEXT_SPEC_V1) {
        return std::nullopt;  // metadata present but not a context map (e.g. an inline-marker object)
    }
    // Consensus does NOT enforce the context schema -- validate it on every read so a crafted or
    // pre-fix asset cannot bypass the parse-version / duplicate-key / body-hash / substring rules.
    const std::string canon(payload->canonical_text.begin(), payload->canonical_text.end());
    std::string verr;
    if (!assets::ValidateIcuContext(meta, canon, verr)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "committed context map is invalid: " + verr);
    }
    // Stable acceptance-message binding: hash the committed metadata bytes. Survives benign
    // re-encryption/re-key (bytes preserved) and changes iff the committed map changes.
    CSHA256().Write(payload->metadata.data(), payload->metadata.size()).Finalize(context_hash.begin());
    return meta;
}

// Resolve issuer/holder/canonical from chain state, with no wallet and no keys. The
// acceptance anchor is the canonical document hash = the registry's icu_plain_commit;
// there is no per-clause commitment. `expected_canonical` is confirm-only: the registry
// is the sole source of truth, and a supplied value is checked against it, never used as
// a substitute when the registry has none.
static IcuAcceptancePrep ResolveIcuAcceptance(
    const JSONRPCRequest& request,
    const std::string& identifier,
    assets::IcuAcceptanceMode mode,
    const COutPoint& holder_op,
    const std::optional<uint256>& expected_canonical,
    const std::optional<std::string>& holder_addr_expected,
    bool allow_unknown_terms,
    bool allow_txindex_fallback,
    const std::vector<std::string>& body_refs,
    const std::optional<std::array<unsigned char, 32>>& dek)
{
    const bool is_ack = (mode == assets::IcuAcceptanceMode::ACKNOWLEDGE);

    IcuAcceptancePrep p;
    p.mode = mode;

    CScript holder_spk;
    std::vector<unsigned char> holder_vext;

    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    {
        LOCK(cs_main);
        Chainstate& active = chainman.ActiveChainstate();
        CCoinsViewCache& view = active.CoinsTip();

        if (auto aid = uint256::FromHex(identifier)) {
            p.asset_id = *aid;
        } else {
            std::string ticker = identifier;
            std::transform(ticker.begin(), ticker.end(), ticker.begin(),
                           [](unsigned char c) { return std::toupper(c); });
            if (!view.ReadTickerBinding(ticker, p.asset_id)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown asset ticker");
            }
        }
        AssetRegistryEntry entry;
        if (!view.ReadAssetPolicy(p.asset_id, entry)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Asset is not registered");
        }
        if (entry.icu_outpoint.IsNull()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Asset registry has no ICU outpoint");
        }
        auto icu_coin = view.GetCoin(entry.icu_outpoint);
        if (!icu_coin) throw JSONRPCError(RPC_INVALID_PARAMETER, "Issuer ICU outpoint not found in the UTXO set");
        CTxDestination idest;
        if (!ExtractDestination(icu_coin->out.scriptPubKey, idest)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Failed to resolve issuer ICU address");
        }
        p.issuer_address = EncodeDestination(idest);

        // Holder prevout: capture from the live UTXO set if still unspent.
        if (auto holder_coin = view.GetCoin(holder_op)) {
            holder_spk = holder_coin->out.scriptPubKey;
            holder_vext = holder_coin->out.vExt;
            p.holder_utxo_live = true;
            p.prevout_source = "utxo";
        }

        // Registry is the sole source of canonical truth on a hoster endpoint.
        p.canonical_hash = entry.icu_plain_commit;

        // Acceptance POLICY is authoritative and lives in the COMMITTED context map -- it is NOT a
        // caller choice. For every acknowledge we resolve the committed map (decrypting a holder-only
        // payload with the supplied DEK; ResolveIcuContext throws if holder-only without a DEK, so a
        // V1 document-only acceptance can never be SILENTLY certified for an asset that might require
        // V2). A "required" map forces TSC-ICU-DOC-ACCEPT-2 over all bodies; "optional" permits V1 or
        // a V2 subset; no map => legacy V1.
        if (is_ack) {
            uint256 ctx_hash;
            bool ctx_inline = false;
            std::optional<UniValue> ctx = ResolveIcuContext(view, p.asset_id, entry, dek, ctx_hash, ctx_inline);

            std::vector<std::string> uniq = body_refs;
            std::sort(uniq.begin(), uniq.end());
            uniq.erase(std::unique(uniq.begin(), uniq.end()), uniq.end());

            if (ctx) {
                p.inline_context = ctx_inline;  // Option A => bind via TSC-ICU-DOC-ACCEPT-3
                const UniValue& bodies = (*ctx)["bodies"];
                for (const std::string& r : uniq) {
                    if (!bodies.exists(r)) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER,
                            strprintf("body_ref %s is not a designated body in the committed context", r));
                    }
                }
                const std::string acceptance = (*ctx)["acceptance"].get_str();  // validated => present
                if (acceptance == "required") {
                    if (uniq.size() != (size_t)bodies.size()) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER,
                            "context acceptance is \"required\": all designated bodies must be affirmed (body_refs)");
                    }
                    p.context_acceptance = true;
                    p.context_hash = ctx_hash;
                    p.body_refs = uniq;
                } else {  // "optional"
                    if (!uniq.empty()) {
                        p.context_acceptance = true;
                        p.context_hash = ctx_hash;
                        p.body_refs = uniq;
                    }
                    // optional + no refs => whole-document acknowledge (no body_refs in the message)
                }
            } else if (!uniq.empty()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "asset has no committed TSC-ICU-CONTEXT-1 map; body_refs not applicable");
            }
        } else if (!body_refs.empty()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                "body_refs apply to acknowledge only (subdoc affirmation is not a return act)");
        }

        // Mirror the wallet rule: the commitment rides a dedicated OP_RETURN only when the
        // transfer emits no other OP_RETURN metadata (relay policy permits at most the tfr+zk
        // pair). Acknowledge is always a single-OP_RETURN native tx; KYC/TFR returns omit it.
        p.commitment_onchain = is_ack || !(entry.has_kyc || (entry.tfr_flags & assets::TFR_ANCHOR_REQUIRED));
    }

    // Hybrid prevout resolution: if the holder outpoint is already spent (e.g. a confirmed
    // return), fall back to its creating transaction via txindex so verify still works
    // post-broadcast. prepare passes allow_txindex_fallback=false (it must act on a live UTXO).
    if (!p.holder_utxo_live) {
        if (!allow_txindex_fallback) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "holder_txid:holder_vout is not an unspent output");
        }
        if (!g_txindex) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                "holder prevout unavailable: the outpoint is spent and txindex is disabled. Enable txindex=1, or verify before the spend is mined.");
        }
        g_txindex->BlockUntilSyncedToCurrentChain();
        CTransactionRef prevtx;
        uint256 prev_block;
        if (!g_txindex->FindTx(holder_op.hash, prev_block, prevtx) || holder_op.n >= prevtx->vout.size()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                "holder prevout unavailable: could not locate holder_txid via txindex. Enable txindex, or verify before the spend is mined.");
        }
        holder_spk = prevtx->vout[holder_op.n].scriptPubKey;
        holder_vext = prevtx->vout[holder_op.n].vExt;
        p.prevout_source = "txindex";  // p.holder_utxo_live stays false
    }

    // Validate the prevout carries this asset and resolve the holder address (works for both
    // the live-UTXO and txindex paths).
    {
        auto tag = assets::ParseAssetTag(holder_vext);
        if (!tag || tag->id != p.asset_id) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "holder prevout does not carry this asset");
        }
        CTxDestination hdest;
        if (!ExtractDestination(holder_spk, hdest)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Failed to resolve holder address from the prevout");
        }
        p.holder_address = EncodeDestination(hdest);
        p.holder_units = tag->amount;
    }

    if (expected_canonical && !p.canonical_hash.IsNull() && *expected_canonical != p.canonical_hash) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            strprintf("expected_canonical_hash %s does not match the registry commitment %s",
                      expected_canonical->ToString(), p.canonical_hash.ToString()));
    }
    if (holder_addr_expected && *holder_addr_expected != p.holder_address) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            strprintf("holder_address %s does not match the address of holder_txid:holder_vout (%s)",
                      *holder_addr_expected, p.holder_address));
    }
    if (p.canonical_hash.IsNull()) {
        if (is_ack) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                "Canonical document hash unavailable: the registry has no icu_plain_commit for this asset. Acceptance must bind the reviewed document.");
        }
        if (!allow_unknown_terms) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                "Canonical document hash unavailable; set allow_unknown_terms to return without binding the terms");
        }
    }

    // Message selection (p.inline_context is set only on the acknowledge path, where the committed
    // context is resolved; a RETURN is attributed by the asset-input spend and never signs a message,
    // so it stays on the legacy ACCEPT-1 form):
    //  - inline-context (Option A) acknowledge => TSC-ICU-DOC-ACCEPT-3, ALWAYS (even a whole-document
    //    acknowledge with no body_refs): such an asset MUST NOT be acknowledged through ACCEPT-1/-2.
    //    V3 binds icu_plain_commit (= canonical_hash), which already moves on any clause change, so no
    //    separate context_hash is needed.
    //  - legacy metadata-context acknowledge with affirmed body_refs => TSC-ICU-DOC-ACCEPT-2.
    //  - otherwise (no context, or a return) => legacy TSC-ICU-DOC-ACCEPT-1.
    if (p.inline_context) {
        p.accept_version = 3;
        p.message = assets::BuildAcceptanceMessageV3(
            p.mode, p.asset_id, p.canonical_hash, p.holder_address, p.body_refs);
    } else if (p.context_acceptance) {
        p.accept_version = 2;
        p.message = assets::BuildAcceptanceMessageV2(
            p.asset_id, p.canonical_hash, p.context_hash, p.holder_address, p.body_refs);
    } else {
        p.accept_version = 1;
        p.message = assets::BuildAcceptanceMessage(
            p.mode, p.asset_id, p.canonical_hash, p.holder_address);
    }
    return p;
}

// Parse the shared (asset, mode, holder_txid, holder_vout) leading params used by both
// icu.acceptance.prepare and .verify.
static void ParseIcuAcceptanceLeading(const JSONRPCRequest& request,
                                      std::string& identifier_out,
                                      assets::IcuAcceptanceMode& mode_out,
                                      COutPoint& holder_op_out)
{
    identifier_out = request.params[0].get_str();
    std::string mode_str = request.params[1].get_str();
    std::transform(mode_str.begin(), mode_str.end(), mode_str.begin(),
                   [](unsigned char c) { return std::toupper(c); });
    if (mode_str == "ACKNOWLEDGE" || mode_str == "ACK") {
        mode_out = assets::IcuAcceptanceMode::ACKNOWLEDGE;
    } else if (mode_str == "RETURN") {
        mode_out = assets::IcuAcceptanceMode::RETURN;
    } else {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "mode must be \"acknowledge\" or \"return\"");
    }
    auto htxid = Txid::FromHex(request.params[2].get_str());
    if (!htxid) throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid holder_txid");
    holder_op_out = COutPoint(*htxid, request.params[3].getInt<uint32_t>());
}

static RPCHelpMan icu_acceptance_prepare()
{
    return RPCHelpMan{
        "icu.acceptance.prepare",
        "Wallet-free preparation of an ICU document acceptance (or return) for the non-custodial\n"
        "operator hoster flow. Resolves the issuer ICU address and the canonical document hash (the\n"
        "asset registry's icu_plain_commit) from chain state, verifies a supplied holder UTXO carries\n"
        "the asset, and returns the OP_RETURN data/script to embed plus the message the holder must\n"
        "BIP-322-sign (acknowledge). The acceptance object is just the document hash -- no per-clause\n"
        "fields. Holds no keys; does not unlock, fund, or sign.",
        {
            {"asset_id_or_ticker", RPCArg::Type::STR, RPCArg::Optional::NO, "Asset ID (32-byte hex) or ticker"},
            {"mode", RPCArg::Type::STR, RPCArg::Optional::NO, "\"acknowledge\" or \"return\""},
            {"holder_txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Txid of an unspent output that holds the asset for this holder"},
            {"holder_vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "Output index of the holder UTXO"},
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                {
                    {"holder_address", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Expected holder address; must match the address derived from holder_txid:holder_vout"},
                    {"expected_canonical_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Confirm-only: if supplied, must equal the registry icu_plain_commit. The registry is the sole source of truth; never used as a substitute."},
                    {"allow_unknown_terms", RPCArg::Type::BOOL, RPCArg::Default{false}, "Return: permit an undeterminable canonical hash"},
                    {"body_refs", RPCArg::Type::ARR, RPCArg::Optional::OMITTED,
                        "Acknowledge: body keys (raw-digest hex) to affirm under the asset's TSC-ICU-CONTEXT-1 map; builds/validates a TSC-ICU-DOC-ACCEPT-3 (inline-context asset) or -2 (legacy metadata-context asset) message",
                        {{"body_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "A committed body key"}}},
                    {"dek", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED,
                        "32-byte asset DEK (hex). Required for a holder-only asset so the node can decrypt and read the committed context map for body_refs enforcement"},
                }
            },
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "mode", "acknowledge or return"},
                {RPCResult::Type::STR_HEX, "asset_id", "Resolved asset id"},
                {RPCResult::Type::STR, "issuer_address", "Authoritatively-resolved issuer ICU address"},
                {RPCResult::Type::STR, "holder_address", "Address derived from the supplied holder UTXO"},
                {RPCResult::Type::STR_HEX, "canonical_hash", "The canonical document hash = registry icu_plain_commit (the acceptance anchor)"},
                {RPCResult::Type::BOOL, "commitment_onchain", "Whether to embed the OP_RETURN on-chain. False for KYC/TFR returns (which already emit metadata OP_RETURNs); record off-chain instead."},
                {RPCResult::Type::STR_HEX, "op_return_data", "Bytes to place after OP_RETURN: the 32-byte canonical document hash. Embed only when commitment_onchain is true."},
                {RPCResult::Type::STR_HEX, "op_return_scriptpubkey", "Full OP_RETURN scriptPubKey for a zero-value output."},
                {RPCResult::Type::STR, "message_to_sign", "Acknowledge: the message the holder must BIP-322-sign with holder_address. (Return is attributed by the asset spend.)"},
                {RPCResult::Type::NUM, "accept_version", "Acceptance message version built: 3 = inline-context (TSC-ICU-DOC-ACCEPT-3), 2 = metadata-context (ACCEPT-2), 1 = document-only (ACCEPT-1)"},
            }
        },
        RPCExamples{
            HelpExampleCli("icu.acceptance.prepare", "\"SHARE\" \"acknowledge\" \"<txid>\" 0")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::string identifier;
            assets::IcuAcceptanceMode mode;
            COutPoint holder_op;
            ParseIcuAcceptanceLeading(request, identifier, mode, holder_op);
            const bool is_ack = (mode == assets::IcuAcceptanceMode::ACKNOWLEDGE);

            std::optional<std::string> holder_addr_expected;
            std::optional<uint256> expected_canonical;
            bool allow_unknown_terms = false;
            std::vector<std::string> body_refs;
            std::optional<std::array<unsigned char, 32>> dek;
            if (!request.params[4].isNull()) {
                const UniValue& opt = request.params[4];
                if (!opt.isObject()) throw JSONRPCError(RPC_INVALID_PARAMETER, "options must be an object");
                if (opt.exists("holder_address")) holder_addr_expected = opt["holder_address"].get_str();
                if (opt.exists("expected_canonical_hash")) {
                    auto ch = uint256::FromHex(opt["expected_canonical_hash"].get_str());
                    if (!ch) throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid expected_canonical_hash (expect 32-byte hex)");
                    expected_canonical = *ch;
                }
                if (opt.exists("allow_unknown_terms")) allow_unknown_terms = opt["allow_unknown_terms"].get_bool();
                if (opt.exists("body_refs")) {
                    const UniValue& arr = opt["body_refs"].get_array();
                    for (size_t i = 0; i < arr.size(); ++i) body_refs.push_back(arr[i].get_str());
                }
                if (opt.exists("dek")) {
                    const std::vector<unsigned char> raw = ParseHex(opt["dek"].get_str());
                    if (raw.size() != 32) throw JSONRPCError(RPC_INVALID_PARAMETER, "dek must be 32-byte hex");
                    std::array<unsigned char, 32> d{};
                    std::copy_n(raw.begin(), 32, d.begin());
                    dek = d;
                }
            }

            const IcuAcceptancePrep p = ResolveIcuAcceptance(
                request, identifier, mode, holder_op, expected_canonical, holder_addr_expected,
                allow_unknown_terms, /*allow_txindex_fallback=*/false, body_refs, dek);  // prepare must act on a live UTXO

            const CScript op_return_spk = CScript() << OP_RETURN << ToByteVector(p.canonical_hash);

            UniValue result(UniValue::VOBJ);
            result.pushKV("mode", is_ack ? "acknowledge" : "return");
            result.pushKV("asset_id", p.asset_id.ToString());
            result.pushKV("issuer_address", p.issuer_address);
            result.pushKV("holder_address", p.holder_address);
            result.pushKV("canonical_hash", p.canonical_hash.ToString());
            result.pushKV("commitment_onchain", p.commitment_onchain);
            result.pushKV("op_return_data", HexStr(p.canonical_hash));
            result.pushKV("op_return_scriptpubkey", HexStr(op_return_spk));
            result.pushKV("message_to_sign", p.message);
            result.pushKV("accept_version", p.accept_version);  // 3 = inline-context (ACCEPT-3), 2 = metadata-context, 1 = document-only
            return result;
        },
    };
}

static RPCHelpMan icu_acceptance_verify()
{
    return RPCHelpMan{
        "icu.acceptance.verify",
        "Wallet-free verification of a submitted non-custodial ICU acceptance/return. Re-resolves the\n"
        "canonical document hash (registry icu_plain_commit) and issuer from chain state, then checks the\n"
        "submitted transaction. ACKNOWLEDGE: the tx carries OP_RETURN(document hash) and the holder's BIP-322\n"
        "signature over the acceptance message validates for the holder address -- the asset is untouched, so\n"
        "the SIGNATURE (not the tx inputs) attributes the holder. RETURN: the tx spends the bound holder\n"
        "outpoint and sends those units to the issuer ICU address (the spend attributes the holder), and for\n"
        "plain assets carries OP_RETURN(document hash). Holds no keys. `verified` is protocol validity only;\n"
        "holder_utxo_live separately reports whether the prevout is still unspent (anti-replay). The prevout\n"
        "is read live, falling back to the creating tx via txindex when spent (a confirmed return), so verify\n"
        "works pre- and post-broadcast given txindex=1 for the post-spend case.",
        {
            {"asset_id_or_ticker", RPCArg::Type::STR, RPCArg::Optional::NO, "Asset ID (32-byte hex) or ticker"},
            {"mode", RPCArg::Type::STR, RPCArg::Optional::NO, "\"acknowledge\" or \"return\""},
            {"holder_txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Txid of the holder UTXO bound at prepare time"},
            {"holder_vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "Output index of the holder UTXO"},
            {"rawtx", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The signed transaction the client built"},
            {"holder_signature", RPCArg::Type::STR, RPCArg::Optional::NO, "Acknowledge: BIP-322 signature by holder_address over message_to_sign. Ignored for return."},
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                {
                    {"holder_address", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Expected holder address; must match the UTXO"},
                    {"expected_canonical_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Confirm-only; must equal registry icu_plain_commit"},
                    {"allow_unknown_terms", RPCArg::Type::BOOL, RPCArg::Default{false}, "Return: permit an undeterminable canonical hash"},
                    {"body_refs", RPCArg::Type::ARR, RPCArg::Optional::OMITTED,
                        "Acknowledge: body keys (raw-digest hex) to affirm under the asset's TSC-ICU-CONTEXT-1 map; builds/validates a TSC-ICU-DOC-ACCEPT-3 (inline-context asset) or -2 (legacy metadata-context asset) message",
                        {{"body_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "A committed body key"}}},
                    {"dek", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED,
                        "32-byte asset DEK (hex). Required for a holder-only asset so the node can decrypt and read the committed context map for body_refs enforcement"},
                }
            },
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::BOOL, "verified", "Protocol validity: acknowledge => OP_RETURN(document hash) present and BIP-322 valid; return => bound holder UTXO spent, its units sent to the issuer, and (plain assets) OP_RETURN present"},
                {RPCResult::Type::BOOL, "op_return_found", "Transaction carries OP_RETURN(canonical document hash)"},
                {RPCResult::Type::BOOL, "commitment_onchain", "Whether the OP_RETURN is required on-chain (false for KYC/TFR returns)"},
                {RPCResult::Type::BOOL, "holder_utxo_live", "Whether the holder prevout is still unspent now (anti-replay signal; false after a return is mined)"},
                {RPCResult::Type::STR, "prevout_source", "Where the holder prevout was resolved: \"utxo\" (live) or \"txindex\" (spent; from the creating tx)"},
                {RPCResult::Type::BOOL, "signature_valid", /*optional=*/true, "Acknowledge: holder BIP-322 signature over the acceptance message verifies for holder_address"},
                {RPCResult::Type::STR, "message_to_sign", /*optional=*/true, "Acknowledge: the message the signature must cover"},
                {RPCResult::Type::BOOL, "spends_holder_op", /*optional=*/true, "Return: the tx spends the bound holder_txid:holder_vout"},
                {RPCResult::Type::BOOL, "asset_to_issuer", /*optional=*/true, "Return: an output for this asset carrying the bound holder units is sent to the issuer ICU address"},
                {RPCResult::Type::NUM, "holder_units", /*optional=*/true, "Return: asset units in the bound holder UTXO"},
                {RPCResult::Type::STR_HEX, "txid", "Transaction id of the submitted tx"},
                {RPCResult::Type::STR_HEX, "canonical_hash", "The canonical document hash (registry icu_plain_commit) checked against the OP_RETURN"},
                {RPCResult::Type::STR, "holder_address", "Resolved holder address"},
                {RPCResult::Type::STR, "issuer_address", "Resolved issuer ICU address"},
                {RPCResult::Type::STR_HEX, "asset_id", "Resolved asset id"},
                {RPCResult::Type::NUM, "accept_version", "Acceptance message version reconstructed/verified: 3 = inline-context, 2 = metadata-context, 1 = document-only"},
            }
        },
        RPCExamples{
            HelpExampleCli("icu.acceptance.verify", "\"SHARE\" \"acknowledge\" \"<txid>\" 0 \"<rawtxhex>\" \"<bip322sig>\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::string identifier;
            assets::IcuAcceptanceMode mode;
            COutPoint holder_op;
            ParseIcuAcceptanceLeading(request, identifier, mode, holder_op);
            const bool is_ack = (mode == assets::IcuAcceptanceMode::ACKNOWLEDGE);

            CMutableTransaction mtx;
            if (!DecodeHexTx(mtx, request.params[4].get_str(), /*try_no_witness=*/true, /*try_witness=*/true)) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Could not decode rawtx");
            }
            const std::string holder_signature = request.params[5].get_str();

            std::optional<std::string> holder_addr_expected;
            std::optional<uint256> expected_canonical;
            bool allow_unknown_terms = false;
            std::vector<std::string> body_refs;
            std::optional<std::array<unsigned char, 32>> dek;
            if (!request.params[6].isNull()) {
                const UniValue& opt = request.params[6];
                if (!opt.isObject()) throw JSONRPCError(RPC_INVALID_PARAMETER, "options must be an object");
                if (opt.exists("holder_address")) holder_addr_expected = opt["holder_address"].get_str();
                if (opt.exists("expected_canonical_hash")) {
                    auto ch = uint256::FromHex(opt["expected_canonical_hash"].get_str());
                    if (!ch) throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid expected_canonical_hash (expect 32-byte hex)");
                    expected_canonical = *ch;
                }
                if (opt.exists("allow_unknown_terms")) allow_unknown_terms = opt["allow_unknown_terms"].get_bool();
                if (opt.exists("body_refs")) {
                    const UniValue& arr = opt["body_refs"].get_array();
                    for (size_t i = 0; i < arr.size(); ++i) body_refs.push_back(arr[i].get_str());
                }
                if (opt.exists("dek")) {
                    const std::vector<unsigned char> raw = ParseHex(opt["dek"].get_str());
                    if (raw.size() != 32) throw JSONRPCError(RPC_INVALID_PARAMETER, "dek must be 32-byte hex");
                    std::array<unsigned char, 32> d{};
                    std::copy_n(raw.begin(), 32, d.begin());
                    dek = d;
                }
            }

            const IcuAcceptancePrep p = ResolveIcuAcceptance(
                request, identifier, mode, holder_op, expected_canonical, holder_addr_expected,
                allow_unknown_terms, /*allow_txindex_fallback=*/true, body_refs, dek);  // verify may run post-broadcast

            const CScript expected_op_return = CScript() << OP_RETURN << ToByteVector(p.canonical_hash);
            bool op_return_found = false;
            bool asset_to_issuer = false;   // return: an output for this asset, carrying the bound
                                            // holder units, to the issuer ICU address
            for (const CTxOut& out : mtx.vout) {
                if (!op_return_found && out.scriptPubKey == expected_op_return) op_return_found = true;
                if (!is_ack && !asset_to_issuer) {
                    auto tag = assets::ParseAssetTag(out.vExt);
                    if (tag && tag->id == p.asset_id && tag->amount == p.holder_units) {
                        CTxDestination d;
                        if (ExtractDestination(out.scriptPubKey, d) && EncodeDestination(d) == p.issuer_address) {
                            asset_to_issuer = true;
                        }
                    }
                }
            }

            // The tx must actually relinquish the bound holder UTXO; otherwise a forged tx could
            // syntactically contain a matching issuer output without spending the holding.
            bool spends_holder_op = false;
            for (const CTxIn& in : mtx.vin) {
                if (in.prevout == holder_op) { spends_holder_op = true; break; }
            }

            const bool opreturn_ok = !p.commitment_onchain || op_return_found;
            bool signature_valid = false;
            bool verified;
            if (is_ack) {
                // The asset is not spent, so attribution is the BIP-322 signature by the holder's
                // share address -- NOT the tx input signature (which may be any wallet key).
                signature_valid = VerifyBIP322Signature(p.holder_address, holder_signature, p.message);
                verified = op_return_found && signature_valid;
            } else {
                // The holder spends their asset UTXO to the issuer; that spend (enforced at broadcast)
                // is the holder attribution, so no BIP-322 is required.
                verified = opreturn_ok && spends_holder_op && asset_to_issuer;
            }

            UniValue result(UniValue::VOBJ);
            result.pushKV("verified", verified);
            result.pushKV("op_return_found", op_return_found);
            result.pushKV("commitment_onchain", p.commitment_onchain);
            result.pushKV("holder_utxo_live", p.holder_utxo_live);
            result.pushKV("prevout_source", p.prevout_source);
            if (is_ack) {
                result.pushKV("signature_valid", signature_valid);
                result.pushKV("message_to_sign", p.message);
            } else {
                result.pushKV("spends_holder_op", spends_holder_op);
                result.pushKV("asset_to_issuer", asset_to_issuer);
                result.pushKV("holder_units", UniValue(p.holder_units));
            }
            result.pushKV("txid", mtx.GetHash().ToString());
            result.pushKV("canonical_hash", p.canonical_hash.ToString());
            result.pushKV("holder_address", p.holder_address);
            result.pushKV("issuer_address", p.issuer_address);
            result.pushKV("asset_id", p.asset_id.ToString());
            result.pushKV("accept_version", p.accept_version);  // version of the acceptance message that was reconstructed/verified
            return result;
        },
    };
}

// Local UniValue helper for the moved on-chain acceptance-record RPCs. (The library deliberately
// does not depend on UniValue, so IcuBodyRefsToJson stays defined where it is used.)
static UniValue IcuBodyRefsToJson(const std::vector<std::array<unsigned char, 32>>& refs)
{
    UniValue arr(UniValue::VARR);
    for (const auto& ref : refs) arr.push_back(HexStr(ref));
    return arr;
}

// Parse an optional 32-byte hex DEK from an options object (key "dek"); nullopt when absent.
static std::optional<std::array<unsigned char, 32>> ParseOptionalIcuDek(const UniValue& opt)
{
    if (!opt.exists("dek")) return std::nullopt;
    const std::vector<unsigned char> raw = ParseHex(opt["dek"].get_str());
    if (raw.size() != 32) throw JSONRPCError(RPC_INVALID_PARAMETER, "dek must be 32-byte hex");
    std::array<unsigned char, 32> d{};
    std::copy_n(raw.begin(), 32, d.begin());
    return d;
}

static RPCHelpMan icu_acceptance_record_verify()
{
    return RPCHelpMan{
        "icu.acceptance.record.verify",
        "Verify an on-chain ICU acceptance record (0x40 vExt). Wallet-free: callable on a -disablewallet "
        "node. Fetches the acceptance transaction by txid FROM the node (mempool / block / -txindex; pass "
        "options.blockhash to avoid -txindex), so an UNPUBLISHED tx cannot verify. Reads the record from the "
        "fetched tx's vout[vout].vExt, then binds it to the holder UTXO the record names -- resolved live from "
        "the UTXO set, else historically via the creating tx (needs -txindex) -- and verifies the holder "
        "authorization: SECP_SCHNORR_RAW against the taproot output key in the prevout spk; SECP_BIP322_HASH "
        "requires options.revealed_bip322_proof and checks BOTH the H(proof) commitment AND the BIP-322 proof "
        "over the record message against the holder address; NONE/return by requiring this tx to spend the "
        "holder prevout AND send the units back to an issuer ICU address. NONE/return is ROTATION-DURABLE: the "
        "verifier walks the icu_outpoint rotation chain and accepts any current-or-historical issuer ICU "
        "address (needs -txindex to resolve spent ancestors), so a return stays verified across issuer ICU "
        "rotations. A document rotation likewise does NOT invalidate a historical acceptance -- reported as "
        "doc_current=false.",
        {
            {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "txid of the acceptance transaction carrying the 0x40 record (fetched from the node)"},
            {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "index of the output whose vExt is the 0x40 acceptance record"},
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                {
                    {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED,
                        "the block containing the acceptance tx (lets the node fetch it without -txindex)"},
                    {"revealed_bip322_proof", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED,
                        "for a SECP_BIP322_HASH record: the revealed BIP-322 proof to match against the on-chain commitment"},
                    {"dek", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED,
                        "32-byte asset DEK (hex) to read a holder-only asset's committed context for the body_refs check; without it a holder-only context-bearing acknowledge fails closed."},
                }},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::BOOL, "verified", "true iff the acceptance tx is MINED in the active chain, on a zero-value unspendable carrier, the asset is registered, the holder binding matches, the signature verifies, AND body_refs are consistent with the committed context (a stale document does NOT clear this)"},
                {RPCResult::Type::STR, "scheme", "the record's signature scheme"},
                {RPCResult::Type::STR_HEX, "asset_id", "the asset the record binds"},
                {RPCResult::Type::STR_HEX, "acceptance_txid", "txid of the acceptance transaction"},
                {RPCResult::Type::BOOL, "acceptance_mined", "the acceptance tx is in a block on the ACTIVE chain (false = mempool-only or a stale/reorged block -> verified is false)"},
                {RPCResult::Type::BOOL, "carrier_shape_ok", "the record rides a zero-value, unspendable (OP_RETURN) carrier output"},
                {RPCResult::Type::BOOL, "asset_registered", "the asset is present in the registry"},
                {RPCResult::Type::BOOL, "doc_current", "record icu_plain_commit == the CURRENT registry icu_plain_commit (false = accepted an older, since-rotated document)"},
                {RPCResult::Type::STR, "prevout_source", "where the holder prevout was resolved: \"utxo\" (live), \"txindex\" (spent; from the creating tx), or \"none\""},
                {RPCResult::Type::BOOL, "holder_utxo_live", "the bound holder prevout is still an unspent UTXO"},
                {RPCResult::Type::BOOL, "holder_spk_matches", "SHA256(prevout scriptPubKey) == record holder_spk_hash"},
                {RPCResult::Type::BOOL, "units_match", "prevout asset units == record accepted_units"},
                {RPCResult::Type::BOOL, "signature_valid", "holder authorization verifies (acknowledge: the signature; return/NONE: this tx spends the holder prevout and sends the units to a current-or-historical issuer ICU address)"},
                {RPCResult::Type::BOOL, "body_refs_ok", "the record's body_refs are a subset of the committed ICU context's designated clauses (and all of them when the context is 'required'); true with no refs when the asset has no context"},
                {RPCResult::Type::STR, "reason", "empty when verified, else the first failing check"},
            }},
        RPCExamples{HelpExampleCli("icu.acceptance.record.verify", "\"<acceptance_txid>\" 0 '{\"blockhash\":\"<block>\"}'")},
        [](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            const NodeContext& node = EnsureAnyNodeContext(request.context);
            ChainstateManager& chainman = EnsureChainman(node);

            const uint256 acceptance_txid = ParseHashV(request.params[0], "txid");
            const uint32_t vout = request.params[1].getInt<uint32_t>();

            const CBlockIndex* pblockindex = nullptr;
            std::optional<std::vector<unsigned char>> revealed_proof;
            std::optional<std::array<unsigned char, 32>> dek;
            if (request.params.size() > 2 && !request.params[2].isNull()) {
                const UniValue& opt = request.params[2];
                if (!opt.isObject()) throw JSONRPCError(RPC_INVALID_PARAMETER, "options must be an object");
                if (opt.exists("blockhash")) {
                    const uint256 bh = ParseHashV(opt["blockhash"], "blockhash");
                    LOCK(cs_main);
                    pblockindex = chainman.m_blockman.LookupBlockIndex(bh);
                    if (!pblockindex) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "blockhash not found");
                }
                if (opt.exists("revealed_bip322_proof")) {
                    revealed_proof = ParseHex(opt["revealed_bip322_proof"].get_str());
                }
                dek = ParseOptionalIcuDek(opt);
            }

            // Provenance + on-chain proof: fetch the tx FROM the node. An unpublished tx is not found, so
            // it cannot verify. The record bytes are read from the node's copy of the tx, not the caller.
            uint256 hash_block;
            const CTransactionRef tx = node::GetTransaction(pblockindex, node.mempool.get(),
                                                            acceptance_txid, hash_block, chainman.m_blockman);
            if (!tx) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                    "acceptance transaction not found (provide options.blockhash, run -txindex, or the tx must be in the mempool)");
            }
            if (vout >= tx->vout.size()) throw JSONRPCError(RPC_INVALID_PARAMETER, "vout out of range");
            auto rec_opt = assets::ParseIcuAcceptanceTLV(tx->vout[vout].vExt);
            if (!rec_opt) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "vout does not carry a well-formed 0x40 ICU acceptance record");
            }
            const assets::IcuAcceptanceRecord& rec = *rec_opt;
            // A tx "found" in a block may be in a STALE (reorged-out) block; only ACTIVE-chain membership
            // is notarized. (getrawtransaction uses the same in_active_chain check.) A reorg therefore
            // flips acceptance_mined back to false and clears verified.
            bool acceptance_mined = false;
            if (!hash_block.IsNull()) {
                LOCK(cs_main);
                const CBlockIndex* pindex = chainman.m_blockman.LookupBlockIndex(hash_block);
                acceptance_mined = pindex && chainman.ActiveChain().Contains(pindex);
            }
            // Carrier shape: a zero-value, unspendable (OP_RETURN) carrier output -- the create-path
            // shape. Consensus/policy only whitelist a parseable 0x40 on ANY output, so enforce here that a
            // record cannot be smuggled onto a spendable/funded output.
            const bool carrier_shape_ok = (tx->vout[vout].nValue == 0) && tx->vout[vout].scriptPubKey.IsUnspendable();

            const auto scheme_name = [](uint8_t s) -> std::string {
                switch (static_cast<assets::IcuAcceptSigScheme>(s)) {
                case assets::IcuAcceptSigScheme::NONE: return "none";
                case assets::IcuAcceptSigScheme::SECP_SCHNORR_RAW: return "schnorr-raw";
                case assets::IcuAcceptSigScheme::SECP_BIP322_HASH: return "bip322-hash";
                }
                return "unknown";
            };

            UniValue result(UniValue::VOBJ);
            result.pushKV("scheme", scheme_name(rec.sig_scheme));
            result.pushKV("asset_id", rec.asset_id.ToString());
            result.pushKV("acceptance_txid", acceptance_txid.ToString());
            result.pushKV("acceptance_mined", acceptance_mined);
            result.pushKV("carrier_shape_ok", carrier_shape_ok);

            Chainstate& active = chainman.ActiveChainstate();
            CCoinsViewCache& view = active.CoinsTip();

            // The asset must be registered (we can't validate an acceptance against a non-existent asset).
            // A document rotation does NOT invalidate a historical signature -- it bound the document it
            // bound -- so report doc_current separately and do NOT gate `verified` on it.
            AssetRegistryEntry entry;
            bool asset_registered = false, doc_current = false;
            {
                LOCK(cs_main);
                if (view.ReadAssetPolicy(rec.asset_id, entry)) {
                    asset_registered = true;
                    doc_current = (entry.icu_plain_commit == rec.icu_plain_commit);
                }
            }
            result.pushKV("asset_registered", asset_registered);
            result.pushKV("doc_current", doc_current);

            // Resolve the holder prevout: live UTXO first, then historically via the creating tx so an
            // acceptance stays verifiable after the holder sells/transfers the asset.
            const COutPoint holder_op(Txid::FromUint256(rec.holder_prevout_txid), rec.holder_prevout_vout);
            CTxOut holder_out;
            bool holder_found = false, holder_utxo_live = false;
            std::string prevout_source = "none";
            {
                LOCK(cs_main);
                if (auto coin = view.GetCoin(holder_op); coin && !coin->IsSpent()) {
                    holder_out = coin->out; holder_found = true; holder_utxo_live = true; prevout_source = "utxo";
                }
            }
            if (!holder_found) {
                uint256 hb;
                if (auto htx = node::GetTransaction(/*block_index=*/nullptr, node.mempool.get(),
                                                    holder_op.hash, hb, chainman.m_blockman)) {
                    if (holder_op.n < htx->vout.size()) {
                        holder_out = htx->vout[holder_op.n]; holder_found = true; prevout_source = "txindex";
                    }
                }
            }
            result.pushKV("prevout_source", prevout_source);
            result.pushKV("holder_utxo_live", holder_utxo_live);

            std::string reason;
            bool holder_spk_matches = false, units_match = false, signature_valid = false;
            if (!asset_registered) {
                reason = "asset is not registered; cannot verify an acceptance against an unknown asset";
            } else if (!holder_found) {
                reason = "holder prevout not found (a spent prevout needs -txindex)";
            } else {
                holder_spk_matches = (assets::IcuHolderSpkHash(holder_out.scriptPubKey) == rec.holder_spk_hash);
                if (auto tag = assets::ParseAssetTag(holder_out.vExt)) {
                    units_match = (tag->amount == rec.accepted_units) && (tag->id == rec.asset_id);
                }
                const auto scheme = static_cast<assets::IcuAcceptSigScheme>(rec.sig_scheme);
                if (scheme == assets::IcuAcceptSigScheme::SECP_SCHNORR_RAW) {
                    TxoutType type{TxoutType::NONSTANDARD};
                    if (auto okey = assets::ExtractTaprootOutputKeyFromSpk(holder_out.scriptPubKey, type)) {
                        signature_valid = assets::VerifyIcuAcceptanceRecordSchnorr(rec, *okey);
                    } else {
                        reason = "holder prevout is not a taproot output";
                    }
                } else if (scheme == assets::IcuAcceptSigScheme::SECP_BIP322_HASH) {
                    // Commit-reveal: (1) the revealed proof must hash to the on-chain commitment, AND
                    // (2) it must be a valid BIP-322 signature over the record message by the holder's
                    // address. The committed/revealed proof is the base64 BIP-322 signature's bytes.
                    if (!revealed_proof) {
                        reason = "SECP_BIP322_HASH record requires options.revealed_bip322_proof";
                    } else if (!assets::VerifyIcuAcceptanceCommit(rec, *revealed_proof)) {
                        reason = "revealed_bip322_proof does not match the on-chain commitment";
                    } else {
                        CTxDestination hd;
                        if (!ExtractDestination(holder_out.scriptPubKey, hd)) {
                            reason = "cannot derive the holder address from the prevout scriptPubKey";
                        } else {
                            const std::string proof_b64(revealed_proof->begin(), revealed_proof->end());
                            const std::string msg = assets::IcuAcceptanceRecordSigningMessage(rec);
                            signature_valid = VerifyBIP322Signature(EncodeDestination(hd), proof_b64, msg);
                            if (!signature_valid) reason = "BIP-322 proof failed verification against the holder address";
                        }
                    }
                } else if (scheme == assets::IcuAcceptSigScheme::NONE) {
                    // RETURN: attributed by the spend. This tx must (a) spend the holder prevout AND
                    // (b) send accepted_units of the asset back to an issuer ICU address. To be durable
                    // across issuer ICU rotations, accept ANY current-or-historical issuer ICU address:
                    // walk the icu_outpoint rotation chain (each ICU output carries ISSUER_REG for the
                    // asset; its creating tx spent the previous ICU output) and collect every script. The
                    // issuer controls all its historical ICU addresses, so a since-rotated address is
                    // still a valid return target; a third-party address is not in the chain -> rejected.
                    const bool spends_holder = std::any_of(tx->vin.begin(), tx->vin.end(),
                        [&](const CTxIn& in) { return in.prevout == holder_op; });

                    // Resolve an outpoint's output: live UTXO first, else the creating tx via -txindex.
                    const auto resolve_out = [&](const COutPoint& op, CTxOut& out) -> bool {
                        {
                            LOCK(cs_main);
                            if (auto c = view.GetCoin(op); c && !c->IsSpent()) {
                                out = c->out; return true;
                            }
                        }
                        uint256 hb;
                        if (auto t = node::GetTransaction(nullptr, node.mempool.get(), op.hash, hb, chainman.m_blockman)) {
                            if (op.n < t->vout.size()) { out = t->vout[op.n]; return true; }
                        }
                        return false;
                    };

                    std::vector<CScript> issuer_scripts;
                    if (!entry.icu_outpoint.IsNull()) {
                        COutPoint cur = entry.icu_outpoint;
                        for (int guard = 0; !cur.IsNull() && guard < 1000; ++guard) {
                            CTxOut out;
                            if (!resolve_out(cur, out)) break;
                            issuer_scripts.push_back(out.scriptPubKey);
                            uint256 hb;
                            CTransactionRef ctx = node::GetTransaction(nullptr, node.mempool.get(), cur.hash, hb, chainman.m_blockman);
                            if (!ctx) break;  // can't walk further without -txindex/block data
                            COutPoint prev; bool found_prev = false;
                            for (const auto& in : ctx->vin) {
                                CTxOut pout;
                                if (!resolve_out(in.prevout, pout)) continue;
                                if (auto reg = assets::ParseIssuerReg(pout.vExt); reg && reg->asset_id == rec.asset_id) {
                                    prev = in.prevout; found_prev = true; break;
                                }
                            }
                            if (!found_prev) break;  // reached the genesis/registration ICU output
                            cur = prev;
                        }
                    }

                    bool asset_to_issuer = false;
                    for (const auto& o : tx->vout) {
                        if (std::find(issuer_scripts.begin(), issuer_scripts.end(), o.scriptPubKey) == issuer_scripts.end()) continue;
                        if (auto t = assets::ParseAssetTag(o.vExt); t && t->id == rec.asset_id && t->amount == rec.accepted_units) {
                            asset_to_issuer = true; break;
                        }
                    }
                    signature_valid = spends_holder && asset_to_issuer;
                    if (!signature_valid) {
                        reason = !spends_holder ? "return tx does not spend the holder prevout"
                               : issuer_scripts.empty() ? "could not resolve any issuer ICU address (need -txindex to walk rotations)"
                               : "return tx does not send the units back to a current-or-historical issuer ICU address";
                    }
                }
            }
            result.pushKV("holder_spk_matches", holder_spk_matches);
            result.pushKV("units_match", units_match);
            result.pushKV("signature_valid", signature_valid);

            // Read-layer body_refs enforcement: the record's affirmed body_refs must be a subset of the
            // asset's committed ICU context (every ref is a real designated clause), and for a 'required'
            // context ALL designated clauses must be affirmed. A no-context asset must carry no refs. This
            // stops a hand-crafted record with a valid holder signature over BOGUS refs from verifying.
            // Reuses the node-side ResolveIcuContext for the committed-context read (ONE strict verifier).
            bool body_refs_ok = true;
            std::string body_refs_reason;
            if (asset_registered) {
                const bool is_ack = (rec.mode == 1);  // RETURN (mode 2) relinquishes; it affirms no clauses
                if (!is_ack) {
                    // RETURN: body_refs is empty by validation; nothing to check.
                } else if (entry.icu_ctxt_commit.IsNull()) {
                    // No committed payload at all -> no clauses; body_refs must be empty.
                    body_refs_ok = assets::CheckIcuBodyRefsAgainstContext(rec.body_refs, /*has_context=*/false, {}, false, body_refs_reason);
                } else {
                    // ACK on a context-bearing asset: read the committed context (fail-closed) and validate.
                    try {
                        LOCK(cs_main);
                        uint256 ch; bool inl = false;
                        std::optional<UniValue> ctx = ResolveIcuContext(view, rec.asset_id, entry, dek, ch, inl);
                        if (ctx) {
                            std::set<std::string> designated;
                            for (auto& k : (*ctx)["bodies"].getKeys()) designated.insert(k);
                            bool required = (*ctx).exists("acceptance") && (*ctx)["acceptance"].isStr() &&
                                            (*ctx)["acceptance"].get_str() == "required";
                            body_refs_ok = assets::CheckIcuBodyRefsAgainstContext(rec.body_refs, /*has_context=*/true, designated, required, body_refs_reason);
                        } else {
                            // committed payload but no clause context (plain doc) -> whole-doc; refs must be empty
                            body_refs_ok = assets::CheckIcuBodyRefsAgainstContext(rec.body_refs, /*has_context=*/false, {}, false, body_refs_reason);
                        }
                    } catch (const UniValue& e) {
                        body_refs_ok = false;
                        body_refs_reason = e.exists("message") && e["message"].isStr() ? e["message"].get_str() : "cannot read/validate committed ICU context";
                    } catch (const std::exception& e) {
                        body_refs_ok = false; body_refs_reason = e.what();
                    }
                }
            }
            result.pushKV("body_refs_ok", body_refs_ok);

            // verified = MINED in the active chain + zero-value unspendable carrier + asset registered +
            // holder binding + signature + body_refs consistent with the committed context. A mempool-only /
            // stale-block tx (acceptance_mined=false) is NOT verified; a stale document does NOT clear it.
            const bool verified = acceptance_mined && carrier_shape_ok && asset_registered &&
                                  holder_found && holder_spk_matches && units_match && signature_valid && body_refs_ok;
            if (!verified && reason.empty()) {
                reason = !acceptance_mined ? "acceptance transaction is not mined in the active chain (mempool-only or stale/reorged block)"
                       : !carrier_shape_ok ? "record is not on a zero-value unspendable (OP_RETURN) carrier output"
                       : !holder_spk_matches ? "holder_spk_hash mismatch"
                       : !units_match ? "accepted_units mismatch"
                       : !signature_valid ? "signature/commitment invalid"
                       : !body_refs_ok ? body_refs_reason
                       : "verification failed";
            }
            result.pushKV("verified", verified);
            result.pushKV("reason", verified ? "" : reason);
            return result;
        },
    };
}

static RPCHelpMan icu_acceptance_record_list()
{
    return RPCHelpMan{
        "icu.acceptance.record.list",
        "List ACCEPTED on-chain ICU acceptance records (0x40) bound to an asset. Wallet-free: callable on a "
        "-disablewallet node. Each candidate 0x40 record is run through the same verifier as "
        "icu.acceptance.record.verify and only verified records are returned by default (set "
        "options.include_invalid=true to return all candidates, each tagged with verified + reason). "
        "Candidates come from the -icuacceptanceindex (only the blocks holding this asset's records) when it "
        "is enabled and caught up; otherwise (no index, or index still syncing) this falls back to a full "
        "active-chain scan (like scantxoutset) -- use options.from_height to bound it. NOTE: "
        "'verified' uses the same verifier as icu.acceptance.record.verify, which is rotation-durable (RETURN "
        "is matched against any current-or-historical issuer ICU address by walking the icu_outpoint chain). "
        "Without -txindex, spent issuer ancestors may be unresolvable, which can drop a historical RETURN "
        "from the default list; use include_invalid and the per-record reason to surface those.",
        {
            {"asset_id_or_ticker", RPCArg::Type::STR, RPCArg::Optional::NO, "Asset identifier (hex) or ticker"},
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                {
                    {"from_height", RPCArg::Type::NUM, RPCArg::Default{0}, "Start the scan at this block height"},
                    {"mode", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Filter to \"acknowledge\" or \"return\""},
                    {"include_invalid", RPCArg::Type::BOOL, RPCArg::Default{false}, "Also return candidate records that fail verification (each tagged with verified)"},
                    {"revealed_bip322_proof", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED,
                        "for SECP_BIP322_HASH records: the revealed BIP-322 proof passed into each per-record verify. "
                        "BEST-EFFORT: one proof is forwarded to EVERY candidate, so a scan covering multiple commit-reveal "
                        "records (each needs its own distinct proof) cannot mark them all verified -- call verify per record "
                        "with that record's own proof. Records lacking their proof appear under include_invalid (verified=false)"},
                    {"dek", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED,
                        "32-byte asset DEK (hex) forwarded to the per-record verify so a holder-only context-bearing acknowledge can be checked "
                        "(single DEK applied to every candidate -- best-effort, same caveat as revealed_bip322_proof)"},
                }},
        },
        RPCResult{RPCResult::Type::ARR, "", "",
            {
                {RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "acceptance_txid", "txid of the tx carrying the record"},
                        {RPCResult::Type::NUM, "acceptance_vout", "output index carrying the 0x40 record"},
                        {RPCResult::Type::NUM, "height", "block height of the record"},
                        {RPCResult::Type::BOOL, "verified", "the record passed full verification (current-state)"},
                        {RPCResult::Type::STR, "reason", "empty when verified, else why it failed (e.g. adversarial return, rotated issuer, missing -txindex)"},
                        {RPCResult::Type::BOOL, "signature_valid", "the holder authorization verified"},
                        {RPCResult::Type::BOOL, "carrier_shape_ok", "the record rode a zero-value unspendable carrier"},
                        {RPCResult::Type::BOOL, "acceptance_mined", "the record's tx is in the active chain"},
                        {RPCResult::Type::BOOL, "body_refs_ok", "body_refs are consistent with the committed ICU context"},
                        {RPCResult::Type::STR, "mode", "acknowledge or return"},
                        {RPCResult::Type::STR, "scheme", "the record's signature scheme"},
                        {RPCResult::Type::STR_HEX, "icu_plain_commit", "the document hash the record accepted"},
                        {RPCResult::Type::BOOL, "doc_current", "record icu_plain_commit == the current registry icu_plain_commit"},
                        {RPCResult::Type::ARR, "body_refs", "affirmed clause body hashes (acknowledge)", {{RPCResult::Type::STR_HEX, "body_ref", "32-byte body hash"}}},
                        {RPCResult::Type::STR_HEX, "holder_txid", "bound holder prevout txid"},
                        {RPCResult::Type::NUM, "holder_vout", "bound holder prevout vout"},
                        {RPCResult::Type::NUM, "accepted_units", "asset units bound by the record"},
                    }},
            }},
        RPCExamples{HelpExampleCli("icu.acceptance.record.list", "\"SHARE\"")},
        [](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            const NodeContext& node = EnsureAnyNodeContext(request.context);
            ChainstateManager& chainman = EnsureChainman(node);

            const std::string identifier = request.params[0].get_str();
            uint256 asset_id;
            uint256 current_commit;

            int from_height = 0;
            bool include_invalid = false;
            std::optional<uint8_t> mode_filter;
            std::optional<std::string> revealed_proof_hex;
            std::optional<std::array<unsigned char, 32>> dek;
            if (request.params.size() > 1 && !request.params[1].isNull()) {
                const UniValue& opt = request.params[1];
                if (!opt.isObject()) throw JSONRPCError(RPC_INVALID_PARAMETER, "options must be an object");
                if (opt.exists("from_height")) from_height = opt["from_height"].getInt<int>();
                if (opt.exists("include_invalid")) include_invalid = opt["include_invalid"].get_bool();
                if (opt.exists("revealed_bip322_proof")) revealed_proof_hex = opt["revealed_bip322_proof"].get_str();
                dek = ParseOptionalIcuDek(opt);
                if (opt.exists("mode")) {
                    std::string m = opt["mode"].get_str();
                    std::transform(m.begin(), m.end(), m.begin(), [](unsigned char c) { return std::toupper(c); });
                    if (m == "ACK") m = "ACKNOWLEDGE";
                    if (m == "ACKNOWLEDGE") mode_filter = 1;
                    else if (m == "RETURN") mode_filter = 2;
                    else throw JSONRPCError(RPC_INVALID_PARAMETER, "mode filter must be \"acknowledge\" or \"return\"");
                }
            }

            {
                LOCK(cs_main);
                CCoinsViewCache& view = chainman.ActiveChainstate().CoinsTip();
                if (auto aid = uint256::FromHex(identifier)) {
                    asset_id = *aid;
                } else {
                    std::string ticker = identifier;
                    std::transform(ticker.begin(), ticker.end(), ticker.begin(), [](unsigned char c) { return std::toupper(c); });
                    if (!view.ReadTickerBinding(ticker, asset_id)) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown asset ticker");
                    }
                }
                AssetRegistryEntry entry;
                if (view.ReadAssetPolicy(asset_id, entry)) current_commit = entry.icu_plain_commit;
            }

            const auto scheme_name = [](uint8_t s) -> std::string {
                switch (static_cast<assets::IcuAcceptSigScheme>(s)) {
                case assets::IcuAcceptSigScheme::NONE: return "none";
                case assets::IcuAcceptSigScheme::SECP_SCHNORR_RAW: return "schnorr-raw";
                case assets::IcuAcceptSigScheme::SECP_BIP322_HASH: return "bip322-hash";
                }
                return "unknown";
            };

            UniValue out(UniValue::VARR);

            // Verify one candidate with the SAME verifier list always uses (so list reflects ACCEPTED
            // records, not just well-formed 0x40 bytes), and append it. Returns early on a mode-filter miss
            // or, unless include_invalid, on a record that does not verify.
            const auto emit_candidate = [&](const CBlockIndex* pindex, const CTransactionRef& tx, size_t vo,
                                            const assets::IcuAcceptanceRecord& rec) {
                if (mode_filter && rec.mode != *mode_filter) return;
                bool verified = false, sig_valid = false, carrier_ok = false, mined = false, brefs_ok = false;
                std::string vreason;
                try {
                    JSONRPCRequest sub = request;
                    UniValue vp(UniValue::VARR);
                    vp.push_back(tx->GetHash().ToString());
                    vp.push_back(static_cast<int>(vo));
                    UniValue vopt(UniValue::VOBJ);
                    vopt.pushKV("blockhash", pindex->GetBlockHash().ToString());
                    if (revealed_proof_hex) vopt.pushKV("revealed_bip322_proof", *revealed_proof_hex);
                    if (dek) vopt.pushKV("dek", HexStr(*dek));
                    vp.push_back(vopt);
                    sub.params = vp;
                    sub.mode = JSONRPCRequest::EXECUTE;
                    const UniValue vres = icu_acceptance_record_verify().HandleRequest(sub);
                    verified = vres.exists("verified") && vres["verified"].get_bool();
                    if (vres.exists("reason") && vres["reason"].isStr()) vreason = vres["reason"].get_str();
                    sig_valid = vres.exists("signature_valid") && vres["signature_valid"].get_bool();
                    carrier_ok = vres.exists("carrier_shape_ok") && vres["carrier_shape_ok"].get_bool();
                    mined = vres.exists("acceptance_mined") && vres["acceptance_mined"].get_bool();
                    brefs_ok = vres.exists("body_refs_ok") && vres["body_refs_ok"].get_bool();
                } catch (const UniValue& e) {
                    vreason = (e.exists("message") && e["message"].isStr()) ? e["message"].get_str() : "verification error";
                } catch (const std::exception& e) {
                    vreason = e.what();
                } catch (...) {
                    vreason = "verification error";
                }
                if (!verified && !include_invalid) return;

                UniValue o(UniValue::VOBJ);
                o.pushKV("acceptance_txid", tx->GetHash().ToString());
                o.pushKV("acceptance_vout", static_cast<uint64_t>(vo));
                o.pushKV("height", pindex->nHeight);
                o.pushKV("verified", verified);
                o.pushKV("reason", verified ? "" : vreason);
                o.pushKV("signature_valid", sig_valid);
                o.pushKV("carrier_shape_ok", carrier_ok);
                o.pushKV("acceptance_mined", mined);
                o.pushKV("body_refs_ok", brefs_ok);
                o.pushKV("mode", rec.mode == 2 ? "return" : "acknowledge");
                o.pushKV("scheme", scheme_name(rec.sig_scheme));
                o.pushKV("icu_plain_commit", rec.icu_plain_commit.ToString());
                o.pushKV("doc_current", !current_commit.IsNull() && rec.icu_plain_commit == current_commit);
                o.pushKV("body_refs", IcuBodyRefsToJson(rec.body_refs));
                o.pushKV("holder_txid", rec.holder_prevout_txid.ToString());
                o.pushKV("holder_vout", static_cast<uint64_t>(rec.holder_prevout_vout));
                o.pushKV("accepted_units", rec.accepted_units);
                out.push_back(o);
            };

            // Phase 1 (under cs_main): decide which blocks to read. Prefer the asset index (only the blocks
            // holding this asset's records) over a full block scan. Snapshot, then read disk without the lock.
            struct Hint { const CBlockIndex* pindex; bool indexed; uint256 txid; uint32_t vout; };
            std::vector<Hint> hints;
            // Use the index ONLY if it is caught up to the tip. BlockUntilSyncedToCurrentChain() returns
            // false while the index is still catching up from far behind -- in that case fall back to the
            // full block scan so list never silently returns partial/empty results.
            const bool use_index = g_icu_acceptance_index && g_icu_acceptance_index->BlockUntilSyncedToCurrentChain();
            {
                LOCK(cs_main);
                const CChain& active = chainman.ActiveChain();
                if (use_index) {
                    std::vector<IcuAcceptanceLoc> locs;
                    g_icu_acceptance_index->FindByAsset(asset_id, locs);
                    for (const auto& loc : locs) {
                        if (loc.height < std::max(0, from_height)) continue;
                        if (const CBlockIndex* pi = active[loc.height]) hints.push_back({pi, true, loc.txid, loc.vout});
                    }
                } else {
                    for (int h = std::max(0, from_height); h <= active.Height(); ++h) {
                        if (const CBlockIndex* pi = active[h]) hints.push_back({pi, false, uint256(), 0});
                    }
                }
            }

            // Phase 2 (no lock): read each block and verify its candidate(s).
            for (const auto& hint : hints) {
                CBlock block;
                if (!chainman.m_blockman.ReadBlock(block, *hint.pindex)) continue;
                if (hint.indexed) {
                    for (const auto& tx : block.vtx) {
                        if (tx->GetHash() != hint.txid) continue;  // stale/reorged index entry -> skip
                        if (hint.vout < tx->vout.size()) {
                            if (auto rec = assets::ParseIcuAcceptanceTLV(tx->vout[hint.vout].vExt); rec && rec->asset_id == asset_id) {
                                emit_candidate(hint.pindex, tx, hint.vout, *rec);
                            }
                        }
                        break;
                    }
                } else {
                    for (const auto& tx : block.vtx) {
                        for (size_t vo = 0; vo < tx->vout.size(); ++vo) {
                            if (tx->vout[vo].vExt.empty()) continue;
                            auto rec = assets::ParseIcuAcceptanceTLV(tx->vout[vo].vExt);
                            if (rec && rec->asset_id == asset_id) emit_candidate(hint.pindex, tx, vo, *rec);
                        }
                    }
                }
            }
            return out;
        },
    };
}

// --- Non-custodial (keyless) ICU acceptance RECORD flow ----------------------------------------
//
// prepare + assemble build the SAME 0x40 acceptance record the custodial wallet path
// (icu.acceptance.record.create) builds, but WITHOUT any wallet or holder key on the node:
//   * prepare resolves the holder prevout / committed context / body_refs from chain state and returns
//     the exact message_to_sign (+ signing_hash) the CLIENT signs locally with its own holder key.
//   * assemble takes back the client's signature material, RE-VERIFIES it (so a bad client sig is
//     rejected before assembly), re-validates body_refs, then emits the 0x40 vExt TLV, an unspendable
//     zero-value carrier output, and an UNFUNDED carrier-only raw tx for the client to fund+sign+send.
// The node never holds the holder key; the client funds/signs the fee inputs and broadcasts.

// Local raw-digest body-ref parser (the wallet-side ParseIcuBodyRefs lives in wallet/rpc/assets.cpp,
// which the node binary does not link). Accepts 32-byte hex; returns a sorted, de-duplicated set.
static std::vector<std::array<unsigned char, 32>> ParseRecordBodyRefs(const UniValue& arr, std::string_view field)
{
    std::vector<std::array<unsigned char, 32>> refs;
    if (arr.isNull()) return refs;
    if (!arr.isArray()) throw JSONRPCError(RPC_INVALID_PARAMETER, std::string(field) + " must be an array");
    for (size_t i = 0; i < arr.size(); ++i) {
        const std::vector<unsigned char> raw = ParseHex(arr[i].get_str());
        if (raw.size() != 32) throw JSONRPCError(RPC_INVALID_PARAMETER, std::string(field) + " entries must be 32-byte hex");
        std::array<unsigned char, 32> a{};
        std::copy_n(raw.begin(), 32, a.begin());
        refs.push_back(a);
    }
    std::sort(refs.begin(), refs.end());
    refs.erase(std::unique(refs.begin(), refs.end()), refs.end());
    return refs;
}

// Resolve the committed-context designated-clause set for an asset (raw-digest hex keys), fail-closed.
// Mirrors the record verifier: no committed payload => no clauses; otherwise read via ResolveIcuContext
// (decrypting holder-only with `dek`) and surface whether acceptance is "required".
static void ResolveRecordContextDesignated(CCoinsViewCache& view, const uint256& asset_id,
                                           const AssetRegistryEntry& entry,
                                           const std::optional<std::array<unsigned char, 32>>& dek,
                                           bool& has_context, std::set<std::string>& designated_hex, bool& required)
{
    has_context = false;
    required = false;
    designated_hex.clear();
    if (entry.icu_ctxt_commit.IsNull()) return;  // no committed payload at all -> no clause context
    uint256 ch; bool inl = false;
    std::optional<UniValue> ctx = ResolveIcuContext(view, asset_id, entry, dek, ch, inl);
    if (!ctx) return;  // committed payload but no clause context (plain doc) -> whole-doc; refs must be empty
    has_context = true;
    for (auto& k : (*ctx)["bodies"].getKeys()) designated_hex.insert(k);
    required = (*ctx).exists("acceptance") && (*ctx)["acceptance"].isStr() && (*ctx)["acceptance"].get_str() == "required";
}

// Build the unsigned record (mode=acknowledge) bound to a holder prevout, resolving family/scheme,
// accepted_units and body_refs exactly like the custodial create path. Shared by prepare and assemble.
// `body_refs_provided` distinguishes an explicit (possibly empty) caller set from "omitted" (auto-fill
// all designated clauses when the committed context is "required", as create does).
static assets::IcuAcceptanceRecord BuildUnsignedAckRecord(
    CCoinsViewCache& view, const NodeContext& node, ChainstateManager& chainman,
    const uint256& asset_id, const AssetRegistryEntry& entry, const COutPoint& holder_op,
    bool body_refs_provided, std::vector<std::array<unsigned char, 32>> body_refs,
    const std::optional<std::array<unsigned char, 32>>& dek,
    CScript& holder_spk_out, uint8_t& sig_scheme_out, std::string& scheme_name_out)
{
    if (entry.icu_plain_commit.IsNull()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            "Asset registry has no icu_plain_commit; acceptance records must bind a reviewed document");
    }

    (void)node; (void)chainman;  // LIVE-ONLY resolution below; no historical (-txindex) fallback.

    // Resolve the holder prevout from the LIVE UTXO set ONLY. You can only acknowledge an asset you
    // currently hold: refusing a spent/nonexistent prevout stops a former holder (who kept the key) from
    // preparing an ACK after transferring the asset. (The custodial create is implicitly live-only too,
    // since it scans the wallet's unspent asset UTXOs.)
    CScript holder_spk;
    std::vector<unsigned char> holder_vext;
    bool holder_found = false;
    {
        LOCK(cs_main);
        if (auto coin = view.GetCoin(holder_op); coin && !coin->IsSpent()) {
            holder_spk = coin->out.scriptPubKey; holder_vext = coin->out.vExt; holder_found = true;
        }
    }
    if (!holder_found) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            "holder prevout is not a live UTXO (already spent or nonexistent); you can only acknowledge an asset you currently hold");
    }

    // The prevout must carry THIS asset; capture accepted_units from its ASSET_TAG.
    auto tag = assets::ParseAssetTag(holder_vext);
    if (!tag || tag->id != asset_id) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "holder prevout does not carry this asset");
    }
    const uint64_t accepted_units = tag->amount;
    if (accepted_units == 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "holder prevout carries zero units of this asset");
    }

    // body_refs against the committed context (fail-closed), exactly like create:
    //  - no context => refs must be empty;
    //  - context "required" + refs omitted => affirm ALL designated;
    //  - provided refs must be a subset of designated (and ALL of them when "required").
    bool has_context = false, required = false;
    std::set<std::string> designated_hex;
    {
        LOCK(cs_main);
        ResolveRecordContextDesignated(view, asset_id, entry, dek, has_context, designated_hex, required);
    }
    if (!has_context) {
        if (body_refs_provided && !body_refs.empty()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                "asset has no committed ICU context; body_refs are not applicable");
        }
        body_refs.clear();
    } else {
        if (!body_refs_provided && required) {
            body_refs.clear();
            for (const std::string& k : designated_hex) {
                const std::vector<unsigned char> raw = ParseHex(k);
                std::array<unsigned char, 32> a{};
                if (raw.size() == 32) std::copy_n(raw.begin(), 32, a.begin());
                body_refs.push_back(a);
            }
            std::sort(body_refs.begin(), body_refs.end());
        }
        std::string br_reason;
        if (!assets::CheckIcuBodyRefsAgainstContext(body_refs, /*has_context=*/true, designated_hex, required, br_reason)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "body_refs invalid against committed context: " + br_reason);
        }
    }

    // Family/scheme from the holder spk: taproot => SCHNORR_RAW; else => BIP322_HASH (commit-reveal).
    TxoutType htype{TxoutType::NONSTANDARD};
    const bool is_taproot = static_cast<bool>(assets::ExtractTaprootOutputKeyFromSpk(holder_spk, htype));

    assets::IcuAcceptanceRecord rec;
    rec.mode = static_cast<uint8_t>(assets::IcuAcceptanceMode::ACKNOWLEDGE);
    rec.asset_id = asset_id;
    rec.icu_plain_commit = entry.icu_plain_commit;
    rec.holder_prevout_txid = holder_op.hash.ToUint256();
    rec.holder_prevout_vout = holder_op.n;
    rec.holder_spk_hash = assets::IcuHolderSpkHash(holder_spk);
    rec.accepted_units = accepted_units;
    rec.sig_scheme = static_cast<uint8_t>(is_taproot ? assets::IcuAcceptSigScheme::SECP_SCHNORR_RAW
                                                     : assets::IcuAcceptSigScheme::SECP_BIP322_HASH);
    rec.body_refs = std::move(body_refs);  // already sorted/unique

    holder_spk_out = holder_spk;
    sig_scheme_out = rec.sig_scheme;
    scheme_name_out = is_taproot ? "schnorr-raw" : "bip322-hash";
    return rec;
}

static RPCHelpMan icu_acceptance_record_prepare()
{
    return RPCHelpMan{
        "icu.acceptance.record.prepare",
        "Keyless (wallet-free) preparation of an on-chain ICU acceptance RECORD (0x40), for the\n"
        "NON-CUSTODIAL flow. Resolves the holder prevout, the registry icu_plain_commit and the committed\n"
        "context / body_refs from chain state, and returns the exact record fields plus the message the\n"
        "CLIENT must sign LOCALLY with its OWN holder key (BIP-322 for hash-hidden families, raw Schnorr\n"
        "over signing_hash for taproot). The node holds no key and does not sign/fund/broadcast. Feed the\n"
        "returned fields + the client signature into icu.acceptance.record.assemble.",
        {
            {"asset", RPCArg::Type::STR, RPCArg::Optional::NO, "Asset id (32-byte hex) or ticker"},
            {"mode", RPCArg::Type::STR, RPCArg::Optional::NO, "\"acknowledge\" (the only keyless record mode)"},
            {"holder_txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Holder asset UTXO txid (the acceptor)"},
            {"holder_vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "Holder asset UTXO vout"},
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                {
                    {"body_refs", RPCArg::Type::ARR, RPCArg::Optional::OMITTED,
                        "Clause body hashes (32-byte raw-digest hex) to affirm; omit to auto-affirm all designated bodies when the committed context is 'required'",
                        {{"body_ref", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "32-byte body hash hex"}}},
                    {"expected_canonical_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Guard: must equal the registry icu_plain_commit"},
                    {"dek", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "32-byte asset DEK (hex), required for a holder-only context-bearing asset"},
                }},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "mode", "acknowledge"},
                {RPCResult::Type::STR_HEX, "asset_id", "Resolved asset id"},
                {RPCResult::Type::STR_HEX, "icu_plain_commit", "Canonical document hash bound by the record"},
                {RPCResult::Type::STR_HEX, "holder_txid", "Bound holder prevout txid"},
                {RPCResult::Type::NUM, "holder_vout", "Bound holder prevout vout"},
                {RPCResult::Type::STR_HEX, "holder_spk_hash", "SHA256(holder scriptPubKey)"},
                {RPCResult::Type::STR, "holder_address", "Address decoded from the holder prevout scriptPubKey"},
                {RPCResult::Type::NUM, "accepted_units", "Asset units on the bound holder prevout"},
                {RPCResult::Type::NUM, "sig_scheme", "Record sig_scheme int (1=SECP_SCHNORR_RAW, 2=SECP_BIP322_HASH)"},
                {RPCResult::Type::STR, "scheme", "schnorr-raw (taproot) or bip322-hash (hash-hidden)"},
                {RPCResult::Type::ARR, "body_refs", "Affirmed clause body hashes", {{RPCResult::Type::STR_HEX, "body_ref", "32-byte body hash"}}},
                {RPCResult::Type::STR, "message_to_sign", "The domain-separated record message; BIP-322-sign this for bip322-hash"},
                {RPCResult::Type::STR_HEX, "signing_hash", "The 32-byte tagged hash; raw-Schnorr-sign this for schnorr-raw"},
            }},
        RPCExamples{HelpExampleCli("icu.acceptance.record.prepare", "\"SHARE\" acknowledge \"<holder_txid>\" 0")},
        [](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            const NodeContext& node = EnsureAnyNodeContext(request.context);
            ChainstateManager& chainman = EnsureChainman(node);

            const std::string identifier = request.params[0].get_str();
            std::string mode_str = request.params[1].get_str();
            std::transform(mode_str.begin(), mode_str.end(), mode_str.begin(), [](unsigned char c) { return std::toupper(c); });
            if (mode_str != "ACKNOWLEDGE" && mode_str != "ACK") {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "mode must be \"acknowledge\" (the only keyless record mode)");
            }
            auto htxid = Txid::FromHex(request.params[2].get_str());
            if (!htxid) throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid holder_txid");
            const COutPoint holder_op(*htxid, request.params[3].getInt<uint32_t>());

            bool body_refs_provided = false;
            std::vector<std::array<unsigned char, 32>> body_refs;
            std::optional<uint256> expected_canonical;
            std::optional<std::array<unsigned char, 32>> dek;
            if (request.params.size() > 4 && !request.params[4].isNull()) {
                const UniValue& opt = request.params[4];
                if (!opt.isObject()) throw JSONRPCError(RPC_INVALID_PARAMETER, "options must be an object");
                if (opt.exists("body_refs")) {
                    body_refs_provided = true;
                    body_refs = ParseRecordBodyRefs(opt["body_refs"], "body_refs");
                }
                if (opt.exists("expected_canonical_hash")) {
                    auto ch = uint256::FromHex(opt["expected_canonical_hash"].get_str());
                    if (!ch) throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid expected_canonical_hash (expect 32-byte hex)");
                    expected_canonical = *ch;
                }
                dek = ParseOptionalIcuDek(opt);
            }

            Chainstate& active = chainman.ActiveChainstate();
            CCoinsViewCache& view = active.CoinsTip();

            uint256 asset_id;
            AssetRegistryEntry entry;
            {
                LOCK(cs_main);
                if (auto aid = uint256::FromHex(identifier)) {
                    asset_id = *aid;
                } else {
                    std::string ticker = identifier;
                    std::transform(ticker.begin(), ticker.end(), ticker.begin(), [](unsigned char c) { return std::toupper(c); });
                    if (!view.ReadTickerBinding(ticker, asset_id)) throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown asset ticker");
                }
                if (!view.ReadAssetPolicy(asset_id, entry)) throw JSONRPCError(RPC_INVALID_PARAMETER, "Asset is not registered");
            }
            if (expected_canonical && *expected_canonical != entry.icu_plain_commit) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    strprintf("expected_canonical_hash %s does not match registry icu_plain_commit %s",
                              expected_canonical->ToString(), entry.icu_plain_commit.ToString()));
            }

            CScript holder_spk;
            uint8_t sig_scheme{0};
            std::string scheme_name;
            assets::IcuAcceptanceRecord rec = BuildUnsignedAckRecord(
                view, node, chainman, asset_id, entry, holder_op,
                body_refs_provided, std::move(body_refs), dek, holder_spk, sig_scheme, scheme_name);

            // NOTE: rec.sig is intentionally empty here -- prepare returns the message the CLIENT signs;
            // full ValidateIcuAcceptanceRecord (which checks scheme/sig-length pairing) runs in assemble.

            CTxDestination hdest;
            std::string holder_address;
            if (ExtractDestination(holder_spk, hdest)) holder_address = EncodeDestination(hdest);

            UniValue result(UniValue::VOBJ);
            result.pushKV("mode", "acknowledge");
            result.pushKV("asset_id", rec.asset_id.ToString());
            result.pushKV("icu_plain_commit", rec.icu_plain_commit.ToString());
            result.pushKV("holder_txid", holder_op.hash.ToString());
            result.pushKV("holder_vout", static_cast<uint64_t>(holder_op.n));
            result.pushKV("holder_spk_hash", rec.holder_spk_hash.ToString());
            result.pushKV("holder_address", holder_address);
            result.pushKV("accepted_units", rec.accepted_units);
            result.pushKV("sig_scheme", static_cast<int>(rec.sig_scheme));
            result.pushKV("scheme", scheme_name);
            result.pushKV("body_refs", IcuBodyRefsToJson(rec.body_refs));
            result.pushKV("message_to_sign", assets::IcuAcceptanceRecordSigningMessage(rec));
            result.pushKV("signing_hash", assets::IcuAcceptanceRecordSigningHash(rec).ToString());
            return result;
        },
    };
}

static RPCHelpMan icu_acceptance_record_assemble()
{
    return RPCHelpMan{
        "icu.acceptance.record.assemble",
        "Keyless (wallet-free) assembly of an on-chain ICU acceptance RECORD (0x40) from the record fields\n"
        "returned by icu.acceptance.record.prepare PLUS the client's locally-produced holder signature.\n"
        "RE-VERIFIES the signature (rejecting a bad client sig) and re-validates body_refs against the\n"
        "committed context, then emits the 0x40 vExt TLV, a zero-value unspendable OP_RETURN carrier output,\n"
        "and an UNFUNDED carrier-only raw transaction the client funds + signs + broadcasts. Holds no key.",
        {
            {"asset", RPCArg::Type::STR, RPCArg::Optional::NO, "Asset id (32-byte hex) or ticker"},
            {"mode", RPCArg::Type::STR, RPCArg::Optional::NO, "\"acknowledge\""},
            {"icu_plain_commit", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Canonical document hash from prepare"},
            {"holder_txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Bound holder prevout txid"},
            {"holder_vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "Bound holder prevout vout"},
            {"holder_spk_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "SHA256(holder scriptPubKey) from prepare"},
            {"accepted_units", RPCArg::Type::NUM, RPCArg::Optional::NO, "Asset units on the holder prevout from prepare"},
            {"sig_scheme", RPCArg::Type::NUM, RPCArg::Optional::NO, "1=SECP_SCHNORR_RAW, 2=SECP_BIP322_HASH"},
            {"body_refs", RPCArg::Type::ARR, RPCArg::Optional::NO, "Affirmed clause body hashes from prepare (may be empty)",
                {{"body_ref", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "32-byte body hash hex"}}},
            {"client_signature", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Client signature material",
                {
                    {"record_signature", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "SECP_SCHNORR_RAW: the 64-byte raw Schnorr signature over signing_hash"},
                    {"revealed_bip322_proof", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "SECP_BIP322_HASH: the base64 BIP-322 proof over message_to_sign"},
                    {"holder_address", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "SECP_BIP322_HASH: the holder address the proof is verified against"},
                    {"dek", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "32-byte asset DEK (hex) for a holder-only context-bearing asset's body_refs re-check"},
                }},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "acceptance_vext", "Serialized 0x40 ICU_ACCEPTANCE vExt TLV"},
                {RPCResult::Type::STR_HEX, "carrier_script", "scriptPubKey of the unspendable carrier output (OP_RETURN)"},
                {RPCResult::Type::STR_HEX, "rawtx", "UNFUNDED carrier-only raw transaction (serialized with the vExt); client funds + signs + broadcasts"},
                {RPCResult::Type::NUM, "acceptance_vout", "Output index carrying the 0x40 record (0)"},
                {RPCResult::Type::STR, "revealed_bip322_proof", /*optional=*/true, "bip322-hash: echo of the proof for the holder to RETAIN"},
            }},
        RPCExamples{HelpExampleCli("icu.acceptance.record.assemble", "\"SHARE\" acknowledge ...")},
        [](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            const NodeContext& node = EnsureAnyNodeContext(request.context);
            ChainstateManager& chainman = EnsureChainman(node);

            const std::string identifier = request.params[0].get_str();
            std::string mode_str = request.params[1].get_str();
            std::transform(mode_str.begin(), mode_str.end(), mode_str.begin(), [](unsigned char c) { return std::toupper(c); });
            if (mode_str != "ACKNOWLEDGE" && mode_str != "ACK") {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "mode must be \"acknowledge\"");
            }
            const uint256 icu_plain_commit = ParseHashV(request.params[2], "icu_plain_commit");
            auto htxid = Txid::FromHex(request.params[3].get_str());
            if (!htxid) throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid holder_txid");
            const COutPoint holder_op(*htxid, request.params[4].getInt<uint32_t>());
            const uint256 holder_spk_hash = ParseHashV(request.params[5], "holder_spk_hash");
            const uint64_t accepted_units = request.params[6].getInt<uint64_t>();
            const uint8_t sig_scheme = static_cast<uint8_t>(request.params[7].getInt<int>());
            std::vector<std::array<unsigned char, 32>> body_refs = ParseRecordBodyRefs(request.params[8], "body_refs");

            const UniValue& sig = request.params[9];
            if (!sig.isObject()) throw JSONRPCError(RPC_INVALID_PARAMETER, "client_signature must be an object");
            std::optional<std::array<unsigned char, 32>> dek = ParseOptionalIcuDek(sig);

            // Resolve asset + registry.
            Chainstate& active = chainman.ActiveChainstate();
            CCoinsViewCache& view = active.CoinsTip();
            uint256 asset_id;
            AssetRegistryEntry entry;
            {
                LOCK(cs_main);
                if (auto aid = uint256::FromHex(identifier)) {
                    asset_id = *aid;
                } else {
                    std::string ticker = identifier;
                    std::transform(ticker.begin(), ticker.end(), ticker.begin(), [](unsigned char c) { return std::toupper(c); });
                    if (!view.ReadTickerBinding(ticker, asset_id)) throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown asset ticker");
                }
                if (!view.ReadAssetPolicy(asset_id, entry)) throw JSONRPCError(RPC_INVALID_PARAMETER, "Asset is not registered");
            }
            if (!entry.icu_plain_commit.IsNull() && entry.icu_plain_commit != icu_plain_commit) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "icu_plain_commit does not match the registry icu_plain_commit");
            }

            // Resolve the holder prevout from the LIVE UTXO set ONLY (no historical -txindex fallback): an
            // ACK can only be assembled for an asset the holder still holds (see prepare). holder_spk is the
            // AUTHORITATIVE source for family/scheme and the BIP-322 address -- caller-supplied values are
            // only cross-checked against it, never trusted.
            CScript holder_spk;
            std::vector<unsigned char> holder_vext;
            bool holder_found = false;
            {
                LOCK(cs_main);
                if (auto coin = view.GetCoin(holder_op); coin && !coin->IsSpent()) {
                    holder_spk = coin->out.scriptPubKey; holder_vext = coin->out.vExt; holder_found = true;
                }
            }
            if (!holder_found) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "holder prevout is not a live UTXO (already spent or nonexistent); you can only acknowledge an asset you currently hold");
            }
            // Bind: SHA256(spk) must equal the supplied holder_spk_hash, and units must match the prevout.
            if (assets::IcuHolderSpkHash(holder_spk) != holder_spk_hash) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "holder_spk_hash does not match the holder prevout scriptPubKey");
            }
            if (auto tag = assets::ParseAssetTag(holder_vext); !tag || tag->id != asset_id || tag->amount != accepted_units) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "accepted_units/asset do not match the holder prevout");
            }
            // Family -> scheme is determined by the prevout spk, NOT the caller. Reject a mismatched sig_scheme.
            {
                TxoutType htype{TxoutType::NONSTANDARD};
                const bool is_taproot = static_cast<bool>(assets::ExtractTaprootOutputKeyFromSpk(holder_spk, htype));
                const uint8_t expected_scheme = static_cast<uint8_t>(
                    is_taproot ? assets::IcuAcceptSigScheme::SECP_SCHNORR_RAW
                               : assets::IcuAcceptSigScheme::SECP_BIP322_HASH);
                if (sig_scheme != expected_scheme) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                        "sig_scheme does not match the holder prevout family (taproot=>schnorr-raw, otherwise=>bip322-hash)");
                }
            }

            // Reconstruct the record (sans sig).
            assets::IcuAcceptanceRecord rec;
            rec.mode = static_cast<uint8_t>(assets::IcuAcceptanceMode::ACKNOWLEDGE);
            rec.asset_id = asset_id;
            rec.icu_plain_commit = entry.icu_plain_commit.IsNull() ? icu_plain_commit : entry.icu_plain_commit;
            rec.holder_prevout_txid = holder_op.hash.ToUint256();
            rec.holder_prevout_vout = holder_op.n;
            rec.holder_spk_hash = holder_spk_hash;
            rec.accepted_units = accepted_units;
            rec.sig_scheme = sig_scheme;
            rec.body_refs = body_refs;  // already sorted/unique by ParseRecordBodyRefs

            std::string echo_proof;
            const auto scheme = static_cast<assets::IcuAcceptSigScheme>(sig_scheme);
            if (scheme == assets::IcuAcceptSigScheme::SECP_SCHNORR_RAW) {
                if (!sig.exists("record_signature")) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "SECP_SCHNORR_RAW requires signature.record_signature (64-byte hex)");
                }
                const std::vector<unsigned char> raw = ParseHex(sig["record_signature"].get_str());
                if (raw.size() != 64) throw JSONRPCError(RPC_INVALID_PARAMETER, "record_signature must be 64-byte hex");
                rec.sig = raw;
                TxoutType htype{TxoutType::NONSTANDARD};
                auto okey = assets::ExtractTaprootOutputKeyFromSpk(holder_spk, htype);
                if (!okey) throw JSONRPCError(RPC_INVALID_PARAMETER, "holder prevout is not a taproot output for SECP_SCHNORR_RAW");
                if (!assets::VerifyIcuAcceptanceRecordSchnorr(rec, *okey)) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "record_signature does not verify against the holder taproot output key");
                }
            } else if (scheme == assets::IcuAcceptSigScheme::SECP_BIP322_HASH) {
                if (!sig.exists("revealed_bip322_proof")) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "SECP_BIP322_HASH requires signature.revealed_bip322_proof");
                }
                const std::string proof_b64 = sig["revealed_bip322_proof"].get_str();
                // On-chain commitment = SHA256(proof bytes), matching the create path exactly.
                unsigned char digest[CSHA256::OUTPUT_SIZE];
                CSHA256().Write(reinterpret_cast<const unsigned char*>(proof_b64.data()), proof_b64.size()).Finalize(digest);
                rec.sig.assign(digest, digest + CSHA256::OUTPUT_SIZE);
                // Verify the commitment AND the BIP-322 proof over the record message.
                const std::vector<unsigned char> proof_bytes(proof_b64.begin(), proof_b64.end());
                if (!assets::VerifyIcuAcceptanceCommit(rec, proof_bytes)) {
                    throw JSONRPCError(RPC_INTERNAL_ERROR, "internal: H(proof) commitment mismatch");
                }
                // The address the proof is verified against is DERIVED from the holder prevout's scriptPubKey
                // -- never trusted from the caller (a client could otherwise sign with an unrelated key/address
                // and assemble a record that fails canonical verify). A supplied holder_address must match.
                CTxDestination hd;
                if (!ExtractDestination(holder_spk, hd)) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "holder prevout scriptPubKey has no address for BIP-322 verification");
                }
                const std::string holder_address = EncodeDestination(hd);
                if (sig.exists("holder_address") && sig["holder_address"].get_str() != holder_address) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "supplied holder_address does not match the holder prevout address");
                }
                const std::string message = assets::IcuAcceptanceRecordSigningMessage(rec);
                if (!VerifyBIP322Signature(holder_address, proof_b64, message)) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "revealed_bip322_proof failed BIP-322 verification against the holder prevout address");
                }
                // Echo the proof in the SAME hex-of-base64 form icu.acceptance.record.verify expects for
                // options.revealed_bip322_proof (it ParseHex()es it back to the base64 bytes). The client
                // RETAINS this to verify the record at/after spend.
                echo_proof = HexStr(MakeUCharSpan(proof_b64));
            } else {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "sig_scheme must be 1 (SECP_SCHNORR_RAW) or 2 (SECP_BIP322_HASH) for a keyless acknowledge");
            }

            // Re-validate body_refs against the committed context (a client cannot assemble bogus refs).
            bool has_context = false, required = false;
            std::set<std::string> designated_hex;
            {
                LOCK(cs_main);
                ResolveRecordContextDesignated(view, asset_id, entry, dek, has_context, designated_hex, required);
            }
            std::string br_reason;
            if (!assets::CheckIcuBodyRefsAgainstContext(rec.body_refs, has_context, designated_hex, required, br_reason)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "body_refs invalid against committed context: " + br_reason);
            }

            // Final structural/semantic validation (scheme/sig-length pairing etc.).
            std::string validation_reason;
            if (!assets::ValidateIcuAcceptanceRecord(rec, validation_reason)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "assembled record is invalid: " + validation_reason);
            }

            // Build the 0x40 TLV + the zero-value unspendable OP_RETURN carrier output (mirror create).
            const std::vector<unsigned char> acceptance_vext = assets::BuildIcuAcceptanceTLV(rec);
            CTxOut carrier;
            carrier.nValue = 0;
            carrier.scriptPubKey = CScript() << OP_RETURN;
            carrier.vExt = acceptance_vext;

            // UNFUNDED carrier-only raw tx (no inputs). Serialized WITH the vExt by EncodeHexTx.
            CMutableTransaction mtx;
            mtx.vout.push_back(carrier);

            UniValue result(UniValue::VOBJ);
            result.pushKV("acceptance_vext", HexStr(acceptance_vext));
            result.pushKV("carrier_script", HexStr(carrier.scriptPubKey));
            result.pushKV("rawtx", EncodeHexTx(CTransaction(mtx)));
            result.pushKV("acceptance_vout", 0);
            if (!echo_proof.empty()) result.pushKV("revealed_bip322_proof", echo_proof);
            return result;
        },
    };
}

void RegisterRawTransactionRPCCommands(CRPCTable& t)
{
    static const CRPCCommand commands[]{
        {"rawtransactions", &getrawtransaction},
        {"rawtransactions", &icu_acceptance_prepare},
        {"rawtransactions", &icu_acceptance_verify},
        {"rawtransactions", &icu_acceptance_record_verify},
        {"rawtransactions", &icu_acceptance_record_prepare},
        {"rawtransactions", &icu_acceptance_record_assemble},
        {"rawtransactions", &icu_acceptance_record_list},
        {"rawtransactions", &createrawtransaction},
        {"rawtransactions", &decoderawtransaction},
        {"rawtransactions", &rawtxattachissuerreg},
        {"rawtransactions", &rawtxattachassettag},
        {"rawtransactions", &rawtxattachzkchunk},
        {"rawtransactions", &getassetpolicy},
        {"rawtransactions", &geticupayload_historical},
        {"rawtransactions", &geticupayload_prior},
        {"rawtransactions", &getassetbyticker},
        {"rawtransactions", &listregisteredassets},
        {"rawtransactions", &geticuinfo},
        {"rawtransactions", &decrypticupayload},
        {"rawtransactions", &rawtxaddoutext},
        {"rawtransactions", &decodeoutext},
        {"rawtransactions", &decodescript},
        {"rawtransactions", &combinerawtransaction},
        {"rawtransactions", &signrawtransactionwithkey},
        {"rawtransactions", &decodepsbt},
        {"rawtransactions", &combinepsbt},
        {"rawtransactions", &finalizepsbt},
        {"rawtransactions", &createpsbt},
        {"rawtransactions", &converttopsbt},
        {"rawtransactions", &utxoupdatepsbt},
        {"rawtransactions", &descriptorprocesspsbt},
        {"rawtransactions", &joinpsbts},
        {"rawtransactions", &analyzepsbt},
        {"rawtransactions", &transferasset},
        {"rawtransactions", &createassettransaction},
        {"rawtransactions", &validateassetconservation},
        {"rawtransactions", &decodeassettransaction},
    };
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }

}

RPCHelpMan RegisterAsset()
{
    return registerasset();
}

RPCHelpMan MintAsset()
{
    return mintasset();
}

RPCHelpMan BurnAsset()
{
    return burnasset();
}
