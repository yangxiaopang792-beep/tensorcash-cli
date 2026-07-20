// Copyright (c) 2024 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef TENSORCASH_QT_TEST_MOCKWALLET_H
#define TENSORCASH_QT_TEST_MOCKWALLET_H

#include <addresstype.h>
#include <interfaces/handler.h>
#include <interfaces/wallet.h>
#include <key.h>
#include <key_io.h>
#include <outputtype.h>
#include <support/allocators/secure.h>
#include <uint256.h>
#include <util/result.h>
#include <util/translation.h>
#include <wallet/coincontrol.h>
#include <wallet/types.h>

#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace qt_tests {

class MockHandler : public interfaces::Handler {
public:
    void disconnect() override {}
};

/**
 * Lightweight wallet interface used by Qt unit tests.
 * Provides controllable asset balances and receive-request storage without
 * requiring a full CWallet instance.
 */
class MockWallet : public interfaces::Wallet {
public:
    std::vector<interfaces::AssetBalance> asset_balances;
    bool external_signer{false};
    std::string wallet_name{"test_wallet"};

    // Map of (address, id) -> serialized request blob
    std::map<std::pair<std::string, std::string>, std::string> receive_requests;

    // Interfaces::Wallet implementation ----------------------------------
    bool encryptWallet(const SecureString& wallet_passphrase) override { return false; }
    bool isCrypted() override { return false; }
    bool lock() override { return false; }
    bool unlock(const SecureString& wallet_passphrase) override { return true; }
    bool isLocked() override { return false; }
    bool changeWalletPassphrase(const SecureString& old_wallet_passphrase,
                                const SecureString& new_wallet_passphrase) override { return false; }
    void abortRescan() override {}
    bool backupWallet(const std::string& filename) override { return false; }

    std::string getWalletName() override { return wallet_name; }

    util::Result<CTxDestination> getNewDestination(const OutputType type,
                                                   const std::string& label) override
    {
        // Use a static pre-generated address for testing to avoid ECC context issues
        static int address_counter = 0;
        address_counter++;

        // Generate deterministic test addresses based on the counter
        std::vector<unsigned char> data(20);
        for (size_t i = 0; i < data.size(); ++i) {
            data[i] = (address_counter + i) & 0xFF;
        }

        CTxDestination dest;
        if (type == OutputType::BECH32) {
            dest = WitnessV0KeyHash(uint160(data));
        } else if (type == OutputType::LEGACY) {
            dest = PKHash(uint160(data));
        } else if (type == OutputType::P2SH_SEGWIT) {
            dest = ScriptHash(uint160(data));
        } else {
            // For other types, just return a PKHash as fallback
            dest = PKHash(uint160(data));
        }
        return dest;
    }

    bool getPubKey(const CScript& script, const CKeyID& address, CPubKey& pub_key) override { return false; }
    SigningResult signMessage(const std::string& message, const PKHash& pkhash, std::string& str_sig) override
    {
        return SigningResult::SIGNING_FAILED;
    }
    bool isSpendable(const CTxDestination& dest) override { return true; }
    bool setAddressBook(const CTxDestination& dest, const std::string& name,
                        const std::optional<wallet::AddressPurpose>& purpose) override { return true; }
    bool delAddressBook(const CTxDestination& dest) override { return true; }
    bool getAddress(const CTxDestination& dest,
                    std::string* name,
                    wallet::isminetype* is_mine,
                    wallet::AddressPurpose* purpose) override
    {
        return false;
    }
    std::vector<interfaces::WalletAddress> getAddresses() override { return {}; }

    std::vector<std::string> getAddressReceiveRequests() override
    {
        std::vector<std::string> values;
        values.reserve(receive_requests.size());
        for (const auto& entry : receive_requests) {
            values.push_back(entry.second);
        }
        return values;
    }

    bool setAddressReceiveRequest(const CTxDestination& dest, const std::string& id,
                                  const std::string& value) override
    {
        const auto key = std::make_pair(EncodeDestination(dest), id);
        if (value.empty()) {
            receive_requests.erase(key);
        } else {
            receive_requests[key] = value;
        }
        return true;
    }

    util::Result<void> displayAddress(const CTxDestination& dest) override
    {
        return util::Result<void>();
    }

    bool lockCoin(const COutPoint& output, const bool write_to_db) override { return true; }
    bool unlockCoin(const COutPoint& output) override { return true; }
    bool isLockedCoin(const COutPoint& output) override { return false; }
    void listLockedCoins(std::vector<COutPoint>& outputs) override {}

    util::Result<CTransactionRef> createTransaction(const std::vector<wallet::CRecipient>& recipients,
                                                    const wallet::CCoinControl& coin_control,
                                                    bool sign,
                                                    int& change_pos,
                                                    CAmount& fee) override
    {
        return util::Error{Untranslated("Not implemented")};
    }

    util::Result<interfaces::FundTransactionResult> fundTransaction(const CMutableTransaction& tx,
                                                                     const std::vector<wallet::CRecipient>& recipients,
                                                                     const wallet::CCoinControl& coin_control) override
    {
        return util::Error{Untranslated("Not implemented")};
    }

    void commitTransaction(CTransactionRef tx, interfaces::WalletValueMap value_map,
                           interfaces::WalletOrderForm order_form) override {}
    bool transactionCanBeAbandoned(const Txid& txid) override { return false; }
    bool abandonTransaction(const Txid& txid) override { return false; }
    bool transactionCanBeBumped(const Txid& txid) override { return false; }
    bool createBumpTransaction(const Txid& txid, const wallet::CCoinControl& coin_control,
                               std::vector<bilingual_str>& errors, CAmount& old_fee,
                               CAmount& new_fee, CMutableTransaction& mtx) override { return false; }
    bool signBumpTransaction(CMutableTransaction& mtx) override { return false; }
    bool commitBumpTransaction(const Txid& txid, CMutableTransaction&& mtx,
                               std::vector<bilingual_str>& errors, Txid& bumped_txid) override
    {
        return false;
    }

    CTransactionRef getTx(const Txid& txid) override { return {}; }
    interfaces::WalletTx getWalletTx(const Txid& txid) override { return {}; }
    std::set<interfaces::WalletTx> getWalletTxs() override { return {}; }

    bool tryGetTxStatus(const Txid& txid, interfaces::WalletTxStatus& tx_status,
                        int& num_blocks, int64_t& block_time) override
    {
        return false;
    }

    interfaces::WalletTx getWalletTxDetails(const Txid& txid,
                                            interfaces::WalletTxStatus& tx_status,
                                            interfaces::WalletOrderForm& order_form,
                                            bool& in_mempool,
                                            int& num_blocks) override
    {
        return interfaces::WalletTx{};
    }

    std::optional<common::PSBTError> fillPSBT(int sighash_type, bool sign, bool bip32derivs,
                                              size_t* n_signed,
                                              PartiallySignedTransaction& psbtx,
                                              bool& complete) override
    {
        return std::nullopt;
    }

    interfaces::WalletBalances getBalances() override { return interfaces::WalletBalances{}; }

    std::vector<interfaces::AssetBalance> getAssetBalances() override { return asset_balances; }

    std::optional<std::string> getAssetDek(const uint256& asset_id) override { return std::nullopt; }

    std::vector<interfaces::AssetUtxo> getAssetUtxos(const uint256& asset_id, int min_depth = 1) override
    {
        return {}; // Return empty vector for mock
    }

    bool tryGetBalances(interfaces::WalletBalances& balances, uint256& block_hash) override
    {
        balances = interfaces::WalletBalances{};
        block_hash.SetNull();
        return true;
    }

    CAmount getBalance() override { return 0; }
    CAmount getAvailableBalance(const wallet::CCoinControl& coin_control) override { return 0; }

    wallet::isminetype txinIsMine(const CTxIn& txin) override { return wallet::ISMINE_NO; }
    wallet::isminetype txoutIsMine(const CTxOut& txout) override { return wallet::ISMINE_NO; }
    CAmount getDebit(const CTxIn& txin, wallet::isminefilter filter) override { return 0; }
    CAmount getCredit(const CTxOut& txout, wallet::isminefilter filter) override { return 0; }

    interfaces::Wallet::CoinsList listCoins() override { return {}; }
    std::vector<interfaces::WalletTxOut> getCoins(const std::vector<COutPoint>& outputs) override
    {
        return {};
    }

    CAmount getRequiredFee(unsigned int tx_bytes) override { return 0; }
    CAmount getMinimumFee(unsigned int tx_bytes, const wallet::CCoinControl& coin_control,
                          int* returned_target, FeeReason* reason) override
    {
        return 0;
    }

    unsigned int getConfirmTarget() override { return 0; }

    bool hdEnabled() override { return false; }
    bool canGetAddresses() override { return true; }
    bool hasExternalSigner() override { return external_signer; }
    bool privateKeysDisabled() override { return false; }
    bool taprootEnabled() override { return true; }

    OutputType getDefaultAddressType() override { return OutputType::BECH32; }
    CAmount getDefaultMaxTxFee() override { return 1000000; }

    void remove() override {}

    std::unique_ptr<interfaces::Handler> handleUnload(UnloadFn fn) override
    {
        return std::make_unique<MockHandler>();
    }
    std::unique_ptr<interfaces::Handler> handleShowProgress(ShowProgressFn fn) override
    {
        return std::make_unique<MockHandler>();
    }
    std::unique_ptr<interfaces::Handler> handleStatusChanged(StatusChangedFn fn) override
    {
        return std::make_unique<MockHandler>();
    }
    std::unique_ptr<interfaces::Handler> handleAddressBookChanged(AddressBookChangedFn fn) override
    {
        return std::make_unique<MockHandler>();
    }
    std::unique_ptr<interfaces::Handler> handleTransactionChanged(TransactionChangedFn fn) override
    {
        return std::make_unique<MockHandler>();
    }
    std::unique_ptr<interfaces::Handler> handleCanGetAddressesChanged(CanGetAddressesChangedFn fn) override
    {
        return std::make_unique<MockHandler>();
    }

    wallet::CWallet* wallet() override { return nullptr; }
};

} // namespace qt_tests

#endif // TENSORCASH_QT_TEST_MOCKWALLET_H
