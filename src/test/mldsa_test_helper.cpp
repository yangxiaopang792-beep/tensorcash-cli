// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ML-DSA test helper tool - generates keys and signatures for functional tests

#include <crypto/mldsaverify.h>
#include <util/strencodings.h>

#include <iostream>
#include <array>
#include <vector>
#include <cstring>

#ifdef ENABLE_MLDSA
#include <oqs/oqs.h>

static void print_usage()
{
    std::cerr << "Usage: mldsa_test_helper <command> [args]\n";
    std::cerr << "Commands:\n";
    std::cerr << "  keygen <level>           - Generate keypair (44/65/87)\n";
    std::cerr << "  sign <skhex> <msghex>    - Sign message with secret key\n";
    std::cerr << "  verify <pkhex> <msghex> <sighex> - Verify signature\n";
}

static std::vector<uint8_t> hex_to_bytes(const std::string& hex)
{
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byte_str = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(std::strtol(byte_str.c_str(), nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

static std::string bytes_to_hex(const uint8_t* data, size_t len)
{
    std::string hex;
    for (size_t i = 0; i < len; ++i) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", data[i]);
        hex += buf;
    }
    return hex;
}

static const char* get_oqs_alg(int level)
{
    switch (level) {
    case 44: return OQS_SIG_alg_ml_dsa_44;
    case 65: return OQS_SIG_alg_ml_dsa_65;
    case 87: return OQS_SIG_alg_ml_dsa_87;
    default: return nullptr;
    }
}

static int cmd_keygen(int level)
{
    const char* alg = get_oqs_alg(level);
    if (!alg) {
        std::cerr << "Invalid level: " << level << "\n";
        return 1;
    }

    OQS_SIG* sig = OQS_SIG_new(alg);
    if (!sig) {
        std::cerr << "Failed to create OQS_SIG\n";
        return 1;
    }

    std::vector<uint8_t> public_key(sig->length_public_key);
    std::vector<uint8_t> secret_key(sig->length_secret_key);

    if (OQS_SIG_keypair(sig, public_key.data(), secret_key.data()) != OQS_SUCCESS) {
        std::cerr << "Keypair generation failed\n";
        OQS_SIG_free(sig);
        return 1;
    }

    std::cout << "pk:" << bytes_to_hex(public_key.data(), public_key.size()) << "\n";
    std::cout << "sk:" << bytes_to_hex(secret_key.data(), secret_key.size()) << "\n";

    OQS_SIG_free(sig);
    return 0;
}

static int cmd_sign(const std::string& sk_hex, const std::string& msg_hex)
{
    auto sk_bytes = hex_to_bytes(sk_hex);
    auto msg_bytes = hex_to_bytes(msg_hex);

    if (msg_bytes.size() != 32) {
        std::cerr << "Message must be exactly 32 bytes\n";
        return 1;
    }

    // Determine algorithm from secret key size
    const char* alg = nullptr;
    if (sk_bytes.size() == OQS_SIG_ml_dsa_44_length_secret_key) {
        alg = OQS_SIG_alg_ml_dsa_44;
    } else if (sk_bytes.size() == OQS_SIG_ml_dsa_65_length_secret_key) {
        alg = OQS_SIG_alg_ml_dsa_65;
    } else if (sk_bytes.size() == OQS_SIG_ml_dsa_87_length_secret_key) {
        alg = OQS_SIG_alg_ml_dsa_87;
    } else {
        std::cerr << "Invalid secret key size: " << sk_bytes.size() << "\n";
        return 1;
    }

    OQS_SIG* sig_obj = OQS_SIG_new(alg);
    if (!sig_obj) {
        std::cerr << "Failed to create OQS_SIG\n";
        return 1;
    }

    std::vector<uint8_t> signature(sig_obj->length_signature);
    size_t sig_len;

    if (OQS_SIG_sign(sig_obj, signature.data(), &sig_len, msg_bytes.data(), msg_bytes.size(), sk_bytes.data()) != OQS_SUCCESS) {
        std::cerr << "Signing failed\n";
        OQS_SIG_free(sig_obj);
        return 1;
    }

    std::cout << "sig:" << bytes_to_hex(signature.data(), sig_len) << "\n";

    OQS_SIG_free(sig_obj);
    return 0;
}

static int cmd_verify(const std::string& pk_hex, const std::string& msg_hex, const std::string& sig_hex)
{
    auto pk_bytes = hex_to_bytes(pk_hex);
    auto msg_bytes = hex_to_bytes(msg_hex);
    auto sig_bytes = hex_to_bytes(sig_hex);

    if (msg_bytes.size() != 32) {
        std::cerr << "Message must be exactly 32 bytes\n";
        return 1;
    }

    // Determine algorithm from public key size
    const char* alg = nullptr;
    if (pk_bytes.size() == OQS_SIG_ml_dsa_44_length_public_key) {
        alg = OQS_SIG_alg_ml_dsa_44;
    } else if (pk_bytes.size() == OQS_SIG_ml_dsa_65_length_public_key) {
        alg = OQS_SIG_alg_ml_dsa_65;
    } else if (pk_bytes.size() == OQS_SIG_ml_dsa_87_length_public_key) {
        alg = OQS_SIG_alg_ml_dsa_87;
    } else {
        std::cerr << "Invalid public key size: " << pk_bytes.size() << "\n";
        return 1;
    }

    OQS_SIG* sig_obj = OQS_SIG_new(alg);
    if (!sig_obj) {
        std::cerr << "Failed to create OQS_SIG\n";
        return 1;
    }

    OQS_STATUS status = OQS_SIG_verify(sig_obj, msg_bytes.data(), msg_bytes.size(), sig_bytes.data(), sig_bytes.size(), pk_bytes.data());

    if (status == OQS_SUCCESS) {
        std::cout << "valid\n";
    } else {
        std::cout << "invalid\n";
    }

    OQS_SIG_free(sig_obj);
    return (status == OQS_SUCCESS) ? 0 : 1;
}

int main(int argc, char** argv)
{
    if (argc < 2) {
        print_usage();
        return 1;
    }

    std::string cmd = argv[1];

    if (cmd == "keygen" && argc == 3) {
        int level = std::atoi(argv[2]);
        return cmd_keygen(level);
    } else if (cmd == "sign" && argc == 4) {
        return cmd_sign(argv[2], argv[3]);
    } else if (cmd == "verify" && argc == 5) {
        return cmd_verify(argv[2], argv[3], argv[4]);
    } else {
        print_usage();
        return 1;
    }
}

#else // !ENABLE_MLDSA

int main()
{
    std::cerr << "ML-DSA support not enabled (missing liboqs)\n";
    return 1;
}

#endif // ENABLE_MLDSA
