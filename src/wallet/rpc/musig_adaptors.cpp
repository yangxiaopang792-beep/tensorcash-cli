// Copyright (c) 2025 The TensorCash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

// MuSig2 Adaptor Signature RPCs
// Provides coordination layer for organizations using MuSig2 internally
// to participate in adversarial adaptor-based atomic swaps

#include <wallet/rpc/util.h>
#include <wallet/wallet.h>

#include <hash.h>
#include <key.h>
#include <logging.h>
#include <random.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <secp256k1.h>
#include <secp256k1_musig.h>
#include <support/cleanse.h>
#include <tinyformat.h>
#include <uint256.h>
#include <univalue.h>

namespace wallet {

// Get secp256k1 context for signing operations
static const secp256k1_context* GetSigningContext() {
    static secp256k1_context* ctx = nullptr;
    if (!ctx) {
        ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    }
    return ctx;
}

RPCHelpMan musig_nonce_gen()
{
    return RPCHelpMan(
        "musig.nonce_gen",
        "Generate MuSig2 nonce for an input in an adaptor ceremony. "
        "Returns public nonce to exchange with co-signers.",
        {
            {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Transaction ID"},
            {"input_index", RPCArg::Type::NUM, RPCArg::Optional::NO, "Input index"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "pubnonce", "Public nonce (66 bytes hex)"},
            }
        },
        RPCExamples{
            HelpExampleCli("musig.nonce_gen", "\"txid\" 0")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            uint256 txid = ParseHashV(request.params[0], "txid");
            size_t input_index = request.params[1].getInt<size_t>();

            LOCK(pwallet->cs_wallet);

            // Get existing state
            FairSignInputState* state = pwallet->GetMutableFairSignInputState(txid, input_index);
            if (!state) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "No Fair-Sign state for this input. Call adaptor.prepare first.");
            }

            if (!state->has_keyagg_cache) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "Input not configured for MuSig2. Use single-key mode or call musig.keyagg first.");
            }

            // Initialize MuSig2 ephemeral state if not already present
            if (!state->musig_state) {
                state->musig_state = std::make_unique<MuSigEphemeralState>();
            }

            // Create session ID for deterministic nonce generation
            // H("fs/musig2_adaptor_session", txid || input_index || adaptor_point || msg)
            HashWriter session_hw = TaggedHash(std::string("fs/musig2_adaptor_session"));
            session_hw << txid;
            session_hw << static_cast<uint64_t>(input_index);
            session_hw << state->adaptor_point;
            session_hw << uint256(state->message_digest);
            uint256 session_id = session_hw.GetSHA256();

            // Get signing keypair (TODO: retrieve actual wallet private key for this input)
            unsigned char dummy_secret[32];
            GetStrongRandBytes(dummy_secret);

            secp256k1_keypair keypair;
            if (!secp256k1_keypair_create(GetSigningContext(), &keypair, dummy_secret)) {
                memory_cleanse(dummy_secret, sizeof(dummy_secret));
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to create keypair");
            }

            // Generate MuSig2 nonce
            // secp256k1_musig_nonce_gen(ctx, secnonce, pubnonce, session_id32, seckey, pubkey, msg32, keyagg_cache, extra_input32)
            // pubkey parameter cannot be NULL - need to get pubkey from keypair
            secp256k1_pubkey pubkey;
            if (!secp256k1_keypair_pub(GetSigningContext(), &pubkey, &keypair)) {
                memory_cleanse(dummy_secret, sizeof(dummy_secret));
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to extract pubkey from keypair");
            }

            if (!secp256k1_musig_nonce_gen(GetSigningContext(),
                                           &state->musig_state->secnonce,
                                           &state->musig_state->pubnonce,
                                           session_id.data(),
                                           dummy_secret,
                                           &pubkey,
                                           state->message_digest.data(),
                                           &state->keyagg_cache,
                                           nullptr)) {  // extra_input (optional)
                memory_cleanse(dummy_secret, sizeof(dummy_secret));
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to generate MuSig2 nonce");
            }

            memory_cleanse(dummy_secret, sizeof(dummy_secret));

            // Serialize pubnonce
            unsigned char pubnonce_bytes[66];
            if (!secp256k1_musig_pubnonce_serialize(GetSigningContext(), pubnonce_bytes, &state->musig_state->pubnonce)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to serialize pubnonce");
            }

            UniValue result(UniValue::VOBJ);
            result.pushKV("pubnonce", HexStr(pubnonce_bytes));

            return result;
        }
    );
}

RPCHelpMan musig_nonce_agg()
{
    return RPCHelpMan(
        "musig.nonce_agg",
        "Aggregate MuSig2 nonces from all co-signers for an input.",
        {
            {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Transaction ID"},
            {"input_index", RPCArg::Type::NUM, RPCArg::Optional::NO, "Input index"},
            {"pubnonces", RPCArg::Type::ARR, RPCArg::Optional::NO, "Array of public nonces from all co-signers",
                {
                    {"pubnonce", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Public nonce (66-byte hex)"},
                }
            },
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "aggnonce", "Aggregated nonce"},
            }
        },
        RPCExamples{
            HelpExampleCli("musig.nonce_agg", "\"txid\" 0 '[\"pubnonce1\", \"pubnonce2\"]'")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            uint256 txid = ParseHashV(request.params[0], "txid");
            size_t input_index = request.params[1].getInt<size_t>();
            const UniValue& pubnonces_arr = request.params[2].get_array();

            if (pubnonces_arr.size() < 2) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Need at least 2 pubnonces for MuSig2");
            }

            LOCK(pwallet->cs_wallet);

            FairSignInputState* state = pwallet->GetMutableFairSignInputState(txid, input_index);
            if (!state || !state->musig_state) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "No MuSig2 state. Call musig.nonce_gen first.");
            }

            // Parse pubnonces
            std::vector<secp256k1_musig_pubnonce> pubnonces;
            std::vector<const secp256k1_musig_pubnonce*> pubnonce_ptrs;

            for (size_t i = 0; i < pubnonces_arr.size(); ++i) {
                const std::string pubnonce_hex = pubnonces_arr[i].get_str();
                auto pubnonce_bytes = ParseHex(pubnonce_hex);
                if (pubnonce_bytes.size() != 66) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid pubnonce length (expected 66 bytes)");
                }

                secp256k1_musig_pubnonce pn;
                if (!secp256k1_musig_pubnonce_parse(GetSigningContext(), &pn, pubnonce_bytes.data())) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid pubnonce at index %u", (unsigned)i));
                }

                pubnonces.push_back(pn);
                pubnonce_ptrs.push_back(&pubnonces[i]);
            }

            // Aggregate nonces → R (base nonce)
            secp256k1_musig_aggnonce aggnonce;
            if (!secp256k1_musig_nonce_agg(GetSigningContext(), &aggnonce, pubnonce_ptrs.data(), pubnonces.size())) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to aggregate nonces");
            }

            // Store aggnonce in state
            std::memcpy(&state->musig_state->aggnonce, &aggnonce, sizeof(aggnonce));

            // Serialize aggnonce
            unsigned char aggnonce_bytes[66];
            secp256k1_musig_aggnonce_serialize(GetSigningContext(), aggnonce_bytes, &aggnonce);

            UniValue result(UniValue::VOBJ);
            result.pushKV("aggnonce", HexStr(aggnonce_bytes));

            return result;
        }
    );
}

RPCHelpMan musig_partial_sign()
{
    return RPCHelpMan(
        "musig.partial_sign",
        "Compute MuSig2 partial signature for an input using adaptor challenge e' = H(R' || Q || m). "
        "IMPORTANT: Uses R' (adaptor nonce) not R (base nonce) for challenge computation.",
        {
            {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Transaction ID"},
            {"input_index", RPCArg::Type::NUM, RPCArg::Optional::NO, "Input index"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "partial_sig", "Partial signature (32 bytes)"},
            }
        },
        RPCExamples{
            HelpExampleCli("musig.partial_sign", "\"txid\" 0")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            uint256 txid = ParseHashV(request.params[0], "txid");
            size_t input_index = request.params[1].getInt<size_t>();

            LOCK(pwallet->cs_wallet);

            FairSignInputState* state = pwallet->GetMutableFairSignInputState(txid, input_index);
            if (!state || !state->musig_state) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "No MuSig2 state. Complete nonce aggregation first.");
            }

            if (!state->r_prime.has_value()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "No adaptor nonce R' computed. Call adaptor.prepare first.");
            }

            // Parse adaptor point T from state
            // Convert XOnlyPubKey to secp256k1_pubkey for MuSig2 API
            secp256k1_xonly_pubkey adaptor_xonly;
            if (!secp256k1_xonly_pubkey_parse(GetSigningContext(), &adaptor_xonly, state->adaptor_point.data())) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to parse adaptor point T");
            }

            // Convert xonly to full pubkey (even Y)
            secp256k1_pubkey adaptor_pubkey;
            unsigned char adaptor_bytes[33];
            adaptor_bytes[0] = 0x02;  // Even Y
            std::memcpy(adaptor_bytes + 1, state->adaptor_point.data(), 32);
            if (!secp256k1_ec_pubkey_parse(GetSigningContext(), &adaptor_pubkey, adaptor_bytes, 33)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to convert adaptor point to pubkey");
            }

            // Process nonces with ADAPTOR point
            // CRITICAL: Passing adaptor_pubkey (not nullptr) makes library compute e' = H(R' || Q || m) internally
            // where R' = R + T. This is what makes it proper adaptor MuSig2.
            secp256k1_musig_aggnonce aggnonce;
            std::memcpy(&aggnonce, &state->musig_state->aggnonce, sizeof(aggnonce));

            if (!secp256k1_musig_nonce_process(GetSigningContext(),
                                                &state->musig_state->session,
                                                &aggnonce,
                                                state->message_digest.data(),
                                                &state->keyagg_cache,
                                                &adaptor_pubkey)) {  // PASS ADAPTOR POINT HERE
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to process nonces with adaptor");
            }

            // Get signing keypair (TODO: retrieve actual wallet key)
            unsigned char dummy_secret[32];
            GetStrongRandBytes(dummy_secret);
            secp256k1_keypair keypair;
            if (!secp256k1_keypair_create(GetSigningContext(), &keypair, dummy_secret)) {
                memory_cleanse(dummy_secret, sizeof(dummy_secret));
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to create keypair");
            }

            // Compute partial signature
            // Since we passed adaptor point to musig_nonce_process, the session now contains
            // the correct challenge e' = H(R' || Q || m) where R' = R + T
            // So secp256k1_musig_partial_sign will produce the correct partial signature for adaptors
            secp256k1_musig_partial_sig partial_sig;
            if (!secp256k1_musig_partial_sign(GetSigningContext(), &partial_sig,
                                               &state->musig_state->secnonce,
                                               &keypair,
                                               &state->keyagg_cache,
                                               &state->musig_state->session)) {
                memory_cleanse(dummy_secret, sizeof(dummy_secret));
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to compute partial signature");
            }

            memory_cleanse(dummy_secret, sizeof(dummy_secret));

            // Serialize partial signature
            unsigned char partial_sig_bytes[32];
            if (!secp256k1_musig_partial_sig_serialize(GetSigningContext(), partial_sig_bytes, &partial_sig)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to serialize partial signature");
            }

            UniValue result(UniValue::VOBJ);
            result.pushKV("partial_sig", HexStr(partial_sig_bytes));

            return result;
        }
    );
}

RPCHelpMan musig_partial_sig_agg()
{
    return RPCHelpMan(
        "musig.partial_sig_agg",
        "Aggregate MuSig2 partial signatures to create adaptor pre-signature s'.",
        {
            {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Transaction ID"},
            {"input_index", RPCArg::Type::NUM, RPCArg::Optional::NO, "Input index"},
            {"partial_sigs", RPCArg::Type::ARR, RPCArg::Optional::NO, "Array of partial signatures from all co-signers",
                {
                    {"partial_sig", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Partial signature (32-byte hex)"},
                }
            },
        },
        RPCResult{RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "adaptor_presig", "Aggregated adaptor pre-signature s' (32 bytes)"},
            }
        },
        RPCExamples{
            HelpExampleCli("musig.partial_sig_agg", "\"txid\" 0 '[\"partial1\", \"partial2\"]'")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            uint256 txid = ParseHashV(request.params[0], "txid");
            size_t input_index = request.params[1].getInt<size_t>();
            const UniValue& partial_sigs_arr = request.params[2].get_array();

            if (partial_sigs_arr.size() < 2) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Need at least 2 partial signatures for MuSig2");
            }

            LOCK(pwallet->cs_wallet);

            FairSignInputState* state = pwallet->GetMutableFairSignInputState(txid, input_index);
            if (!state || !state->musig_state) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "No MuSig2 state.");
            }

            // Parse partial signatures
            std::vector<secp256k1_musig_partial_sig> partial_sigs;
            std::vector<const secp256k1_musig_partial_sig*> partial_sig_ptrs;

            for (size_t i = 0; i < partial_sigs_arr.size(); ++i) {
                const std::string partial_sig_hex = partial_sigs_arr[i].get_str();
                auto partial_sig_bytes = ParseHex(partial_sig_hex);
                if (partial_sig_bytes.size() != 32) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid partial signature length (expected 32 bytes)");
                }

                secp256k1_musig_partial_sig ps;
                if (!secp256k1_musig_partial_sig_parse(GetSigningContext(), &ps, partial_sig_bytes.data())) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid partial signature at index %u", (unsigned)i));
                }

                partial_sigs.push_back(ps);
                partial_sig_ptrs.push_back(&partial_sigs[i]);
            }

            // Aggregate partial signatures
            unsigned char agg_sig64[64];
            if (!secp256k1_musig_partial_sig_agg(GetSigningContext(), agg_sig64,
                                                   &state->musig_state->session,
                                                   partial_sig_ptrs.data(),
                                                   partial_sigs.size())) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to aggregate partial signatures");
            }

            // Extract s' (second 32 bytes of sig is the scalar)
            unsigned char s_prime[32];
            std::memcpy(s_prime, agg_sig64 + 32, 32);

            // Store in state as adaptor pre-signature
            std::memcpy(state->pre_sig.data(), state->r_prime->begin(), 32);  // R'_x
            std::memcpy(state->pre_sig.data() + 32, s_prime, 32);              // s'
            state->has_partial = true;

            UniValue result(UniValue::VOBJ);
            result.pushKV("adaptor_presig", HexStr(s_prime));

            return result;
        }
    );
}

} // namespace wallet
