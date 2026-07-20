// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/fuzz/fuzz.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/util.h>

#include <assets/asset.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <serialize.h>
#include <util/strencodings.h>

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <limits>
#include <optional>
#include <vector>

namespace {

std::vector<unsigned char> EncodeLE64(uint64_t value)
{
    std::vector<unsigned char> result(8);
    WriteLE64(result.data(), value);
    return result;
}

// Build a transaction with controllable outputs to test OP_OUTPUTMATCH_*
CMutableTransaction BuildCovenantTestTx(FuzzedDataProvider& fuzzed_data_provider)
{
    CMutableTransaction mtx;
    mtx.version = 2;
    mtx.nLockTime = fuzzed_data_provider.ConsumeIntegral<uint32_t>();

    // Add some dummy inputs
    const size_t num_inputs = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(1, 5);
    for (size_t i = 0; i < num_inputs; ++i) {
        CTxIn in;
        in.prevout = COutPoint(ConsumeUInt256(fuzzed_data_provider), fuzzed_data_provider.ConsumeIntegral<uint32_t>());
        in.nSequence = fuzzed_data_provider.ConsumeIntegral<uint32_t>();
        mtx.vin.push_back(in);
    }

    // Add outputs with various combinations of native/asset outputs
    const size_t num_outputs = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, 128);
    for (size_t i = 0; i < num_outputs; ++i) {
        CTxOut out;
        out.nValue = fuzzed_data_provider.ConsumeIntegral<CAmount>();
        out.scriptPubKey = ConsumeScript(fuzzed_data_provider);

        // Randomly add asset TLV
        if (fuzzed_data_provider.ConsumeBool()) {
            const uint256 asset_id = ConsumeUInt256(fuzzed_data_provider);
            const uint64_t amount = fuzzed_data_provider.ConsumeIntegral<uint64_t>();

            std::vector<unsigned char> payload;
            payload.insert(payload.end(), asset_id.begin(), asset_id.end());
            auto amount_bytes = EncodeLE64(amount);
            payload.insert(payload.end(), amount_bytes.begin(), amount_bytes.end());

            std::vector<unsigned char> tlv;
            tlv.push_back(static_cast<unsigned char>(assets::OutExtType::ASSET_TAG));
            tlv.push_back(static_cast<unsigned char>(payload.size()));
            tlv.insert(tlv.end(), payload.begin(), payload.end());
            out.vExt = tlv;
        }

        mtx.vout.push_back(out);
    }

    return mtx;
}

// Test OP_OUTPUTMATCH_NATIVE script execution
void FuzzOutputMatchNative(FuzzedDataProvider& fuzzed_data_provider)
{
    CMutableTransaction mtx = BuildCovenantTestTx(fuzzed_data_provider);
    const CTransaction tx(mtx);

    // Build a script with OP_OUTPUTMATCH_NATIVE
    CScript script;
    const CScript target_spk = ConsumeScript(fuzzed_data_provider);
    const uint256 script_hash = (HashWriter{} << target_spk).GetSHA256();
    const uint64_t amount = fuzzed_data_provider.ConsumeIntegral<uint64_t>();

    script << std::vector<unsigned char>(script_hash.begin(), script_hash.end());
    script << EncodeLE64(amount);
    script << OP_OUTPUTMATCH_NATIVE;

    // Execute with various flags
    const unsigned int flags = fuzzed_data_provider.ConsumeIntegral<unsigned int>();
    std::vector<std::vector<unsigned char>> stack;
    ScriptError error;
    const BaseSignatureChecker checker;

    // Test with different input indices
    const unsigned int input_idx = fuzzed_data_provider.ConsumeIntegral<unsigned int>() % std::max<size_t>(1, tx.vin.size());

    // Should not crash regardless of result
    (void)EvalScript(stack, script, flags, checker, SigVersion::TAPSCRIPT, &error);
}

// Test OP_OUTPUTMATCH_ASSET script execution
void FuzzOutputMatchAsset(FuzzedDataProvider& fuzzed_data_provider)
{
    CMutableTransaction mtx = BuildCovenantTestTx(fuzzed_data_provider);
    const CTransaction tx(mtx);

    // Build a script with OP_OUTPUTMATCH_ASSET
    CScript script;
    const CScript target_spk = ConsumeScript(fuzzed_data_provider);
    const uint256 script_hash = (HashWriter{} << target_spk).GetSHA256();
    const uint256 asset_id = ConsumeUInt256(fuzzed_data_provider);
    const uint64_t amount = fuzzed_data_provider.ConsumeIntegral<uint64_t>();

    script << std::vector<unsigned char>(script_hash.begin(), script_hash.end());
    script << std::vector<unsigned char>(asset_id.begin(), asset_id.end());
    script << EncodeLE64(amount);
    script << OP_OUTPUTMATCH_ASSET;

    // Execute with various flags
    const unsigned int flags = fuzzed_data_provider.ConsumeIntegral<unsigned int>();
    std::vector<std::vector<unsigned char>> stack;
    ScriptError error;
    const BaseSignatureChecker checker;

    const unsigned int input_idx = fuzzed_data_provider.ConsumeIntegral<unsigned int>() % std::max<size_t>(1, tx.vin.size());

    // Should not crash regardless of result
    (void)EvalScript(stack, script, flags, checker, SigVersion::TAPSCRIPT, &error);
}

// Test edge cases
void FuzzCovenantEdgeCases(FuzzedDataProvider& fuzzed_data_provider)
{
    CMutableTransaction mtx = BuildCovenantTestTx(fuzzed_data_provider);
    const CTransaction tx(mtx);

    // Test with zero amount
    {
        CScript script;
        const uint256 script_hash = ConsumeUInt256(fuzzed_data_provider);
        script << std::vector<unsigned char>(script_hash.begin(), script_hash.end());
        script << EncodeLE64(0);
        script << (fuzzed_data_provider.ConsumeBool() ? OP_OUTPUTMATCH_NATIVE : OP_OUTPUTMATCH_ASSET);

        std::vector<std::vector<unsigned char>> stack;
        ScriptError error;
        const BaseSignatureChecker checker;
        (void)EvalScript(stack, script, SCRIPT_VERIFY_NONE, checker, SigVersion::TAPSCRIPT, &error);
    }

    // Test with maximum amount
    {
        CScript script;
        const uint256 script_hash = ConsumeUInt256(fuzzed_data_provider);
        script << std::vector<unsigned char>(script_hash.begin(), script_hash.end());
        script << EncodeLE64(std::numeric_limits<uint64_t>::max());
        script << (fuzzed_data_provider.ConsumeBool() ? OP_OUTPUTMATCH_NATIVE : OP_OUTPUTMATCH_ASSET);

        std::vector<std::vector<unsigned char>> stack;
        ScriptError error;
        const BaseSignatureChecker checker;
        (void)EvalScript(stack, script, SCRIPT_VERIFY_NONE, checker, SigVersion::TAPSCRIPT, &error);
    }

    // Test with malformed amount encoding (wrong size)
    {
        CScript script;
        const uint256 script_hash = ConsumeUInt256(fuzzed_data_provider);
        script << std::vector<unsigned char>(script_hash.begin(), script_hash.end());
        script << ConsumeRandomLengthByteVector(fuzzed_data_provider, 20); // Wrong size
        script << OP_OUTPUTMATCH_NATIVE;

        std::vector<std::vector<unsigned char>> stack;
        ScriptError error;
        const BaseSignatureChecker checker;
        (void)EvalScript(stack, script, SCRIPT_VERIFY_NONE, checker, SigVersion::TAPSCRIPT, &error);
    }

    // Test with wrong script hash size
    {
        CScript script;
        script << ConsumeRandomLengthByteVector(fuzzed_data_provider, 64); // Wrong size
        script << EncodeLE64(fuzzed_data_provider.ConsumeIntegral<uint64_t>());
        script << OP_OUTPUTMATCH_NATIVE;

        std::vector<std::vector<unsigned char>> stack;
        ScriptError error;
        const BaseSignatureChecker checker;
        (void)EvalScript(stack, script, SCRIPT_VERIFY_NONE, checker, SigVersion::TAPSCRIPT, &error);
    }
}

} // namespace

FUZZ_TARGET(script_covenant)
{
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());

    const uint8_t choice = fuzzed_data_provider.ConsumeIntegral<uint8_t>() % 3;

    switch (choice) {
    case 0:
        FuzzOutputMatchNative(fuzzed_data_provider);
        break;
    case 1:
        FuzzOutputMatchAsset(fuzzed_data_provider);
        break;
    case 2:
        FuzzCovenantEdgeCases(fuzzed_data_provider);
        break;
    }
}
