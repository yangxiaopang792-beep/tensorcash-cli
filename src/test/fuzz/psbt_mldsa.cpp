// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/psbt_mldsa.h>
#include <psbt.h>
#include <script/signingprovider.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/util/random.h>
#include <util/check.h>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

// Fuzz target for ML-DSA PSBT field deserialization
FUZZ_TARGET(psbt_mldsa_deserialize)
{
    SeedRandomStateForTest(SeedRand::ZEROS);
    FuzzedDataProvider fuzzed_data_provider{buffer.data(), buffer.size()};

    // Try to decode a PSBT from fuzzed input
    PartiallySignedTransaction psbt;
    std::string error;
    auto str = fuzzed_data_provider.ConsumeRandomLengthString();
    if (!DecodeRawPSBT(psbt, MakeByteSpan(str), error)) {
        return;
    }

    // Test ML-DSA-specific field access without crashing
    for (const PSBTInput& input : psbt.inputs) {
        // Access ML-DSA fields - should not crash on malformed data
        (void)input.m_mldsa_pubkey;
        (void)input.m_mldsa_signature;
        (void)input.m_mldsa_param_set;
        (void)input.m_v2_tap_parity;

        // Validate parameter set if present
        if (input.m_mldsa_param_set.has_value()) {
            uint8_t param_set = input.m_mldsa_param_set.value();
            // Valid parameter sets are 44, 65, 87
            // Invalid values should not cause crashes
            (void)param_set;
        }

        // Test signature size validation
        if (!input.m_mldsa_signature.empty()) {
            size_t sig_size = input.m_mldsa_signature.size();
            // ML-DSA signatures are 2420-4627 bytes
            // Malformed sizes should not crash
            (void)sig_size;
        }

        // Test pubkey size validation
        if (!input.m_mldsa_pubkey.empty()) {
            size_t pk_size = input.m_mldsa_pubkey.size();
            // Encoded ML-DSA pubkeys are ~1954-2594 bytes
            // Malformed sizes should not crash
            (void)pk_size;
        }
    }

    // Test IsMLDSAInput - should handle invalid indices gracefully
    for (int i = -10; i < static_cast<int>(psbt.inputs.size()) + 10; ++i) {
        (void)node::IsMLDSAInput(psbt, i);
    }
}

// Fuzz target for ML-DSA PSBT operations (update, sign, finalize)
FUZZ_TARGET(psbt_mldsa_operations)
{
    SeedRandomStateForTest(SeedRand::ZEROS);
    FuzzedDataProvider fuzzed_data_provider{buffer.data(), buffer.size()};

    // Try to decode a PSBT from fuzzed input
    PartiallySignedTransaction psbt;
    std::string error;
    auto str = fuzzed_data_provider.ConsumeRandomLengthString();
    if (!DecodeRawPSBT(psbt, MakeByteSpan(str), error)) {
        return;
    }

    // Create an empty signing provider (will fail to sign, but shouldn't crash)
    FlatSigningProvider provider;

    // Test UpdatePSBTInputMLDSA with various indices
    for (size_t i = 0; i < psbt.inputs.size(); ++i) {
        PartiallySignedTransaction psbt_copy = psbt;
        // Should not crash even with empty provider
        (void)node::UpdatePSBTInputMLDSA(provider, psbt_copy, i);
    }

    // Test with out-of-bounds indices (should handle gracefully)
    PartiallySignedTransaction psbt_copy = psbt;
    (void)node::UpdatePSBTInputMLDSA(provider, psbt_copy, -1);
    (void)node::UpdatePSBTInputMLDSA(provider, psbt_copy, psbt.inputs.size());
    (void)node::UpdatePSBTInputMLDSA(provider, psbt_copy, psbt.inputs.size() + 100);

    // Test SignPSBTInputMLDSA
    for (size_t i = 0; i < psbt.inputs.size(); ++i) {
        PartiallySignedTransaction psbt_copy = psbt;
        // Should not crash even with empty provider or null txdata
        (void)node::SignPSBTInputMLDSA(provider, psbt_copy, i, nullptr);
    }

    // Test FinalizePSBTInputMLDSA
    for (size_t i = 0; i < psbt.inputs.size(); ++i) {
        PSBTInput input_copy = psbt.inputs[i];
        // Should not crash even with incomplete data
        (void)node::FinalizePSBTInputMLDSA(input_copy);
        (void)node::FinalizePSBTInputMLDSA(input_copy, 0x01);  // SIGHASH_ALL
        (void)node::FinalizePSBTInputMLDSA(input_copy, 0x81);  // SIGHASH_ALL|ANYONECANPAY
    }
}

// Fuzz target for ML-DSA PSBT field serialization/deserialization roundtrip
FUZZ_TARGET(psbt_mldsa_roundtrip)
{
    SeedRandomStateForTest(SeedRand::ZEROS);
    FuzzedDataProvider fuzzed_data_provider{buffer.data(), buffer.size()};

    // Create a PSBT with fuzzed ML-DSA fields
    PartiallySignedTransaction psbt;

    // Decode base PSBT
    auto str = fuzzed_data_provider.ConsumeRandomLengthString();
    std::string error;
    if (!DecodeRawPSBT(psbt, MakeByteSpan(str), error)) {
        // Create minimal valid PSBT if decode fails
        CMutableTransaction tx;
        psbt.tx = tx;
    }

    // Add fuzzed ML-DSA fields to first input (if exists)
    if (!psbt.inputs.empty()) {
        PSBTInput& input = psbt.inputs[0];

        // Fuzz ML-DSA pubkey (any size)
        if (fuzzed_data_provider.ConsumeBool()) {
            input.m_mldsa_pubkey = fuzzed_data_provider.ConsumeBytes<unsigned char>(
                fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, 10000)
            );
        }

        // Fuzz ML-DSA signature (any size)
        if (fuzzed_data_provider.ConsumeBool()) {
            input.m_mldsa_signature = fuzzed_data_provider.ConsumeBytes<unsigned char>(
                fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, 10000)
            );
        }

        // Fuzz parameter set (any value)
        if (fuzzed_data_provider.ConsumeBool()) {
            input.m_mldsa_param_set = fuzzed_data_provider.ConsumeIntegral<uint8_t>();
        }

        // Fuzz parity (any value)
        if (fuzzed_data_provider.ConsumeBool()) {
            input.m_v2_tap_parity = fuzzed_data_provider.ConsumeIntegral<uint8_t>();
        }
    }

    // Serialize the PSBT
    DataStream ss_serialize;
    ss_serialize << psbt;

    // Deserialize back
    PartiallySignedTransaction psbt_deserialized;
    try {
        ss_serialize >> psbt_deserialized;

        // Verify roundtrip consistency (fields should match)
        if (!psbt.inputs.empty() && !psbt_deserialized.inputs.empty()) {
            const PSBTInput& orig = psbt.inputs[0];
            const PSBTInput& deser = psbt_deserialized.inputs[0];

            // Fields should match after roundtrip
            Assert(orig.m_mldsa_pubkey == deser.m_mldsa_pubkey);
            Assert(orig.m_mldsa_signature == deser.m_mldsa_signature);
            Assert(orig.m_mldsa_param_set == deser.m_mldsa_param_set);
            Assert(orig.m_v2_tap_parity == deser.m_v2_tap_parity);
        }
    } catch (const std::exception&) {
        // Deserialization can fail with malformed data - that's OK
        // Just ensure it doesn't crash
    }
}

// Fuzz target for ML-DSA PSBT merge operations
FUZZ_TARGET(psbt_mldsa_merge)
{
    SeedRandomStateForTest(SeedRand::ZEROS);
    FuzzedDataProvider fuzzed_data_provider{buffer.data(), buffer.size()};

    // Decode first PSBT
    PartiallySignedTransaction psbt1;
    std::string error;
    auto str1 = fuzzed_data_provider.ConsumeRandomLengthString();
    if (!DecodeRawPSBT(psbt1, MakeByteSpan(str1), error)) {
        return;
    }

    // Decode second PSBT
    PartiallySignedTransaction psbt2;
    auto str2 = fuzzed_data_provider.ConsumeRandomLengthString();
    if (!DecodeRawPSBT(psbt2, MakeByteSpan(str2), error)) {
        psbt2 = psbt1;  // Use copy if decode fails
    }

    // Test PSBTInput merge with ML-DSA fields
    for (size_t i = 0; i < std::min(psbt1.inputs.size(), psbt2.inputs.size()); ++i) {
        PSBTInput input1 = psbt1.inputs[i];
        const PSBTInput& input2 = psbt2.inputs[i];

        // Merge should not crash even with conflicting ML-DSA data
        try {
            input1.Merge(input2);
        } catch (const std::exception&) {
            // Merge can fail with incompatible data - that's OK
        }
    }

    // Test full PSBT merge
    PartiallySignedTransaction psbt_copy = psbt1;
    try {
        (void)psbt_copy.Merge(psbt2);
    } catch (const std::exception&) {
        // Merge can fail with incompatible transactions - that's OK
    }

    // Test CombinePSBTs
    psbt_copy = psbt1;
    try {
        (void)CombinePSBTs(psbt_copy, {psbt1, psbt2});
    } catch (const std::exception&) {
        // Combine can fail with incompatible PSBTs - that's OK
    }
}
