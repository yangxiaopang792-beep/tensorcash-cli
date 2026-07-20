// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/wallet.h>
#include <wallet/contract.h>
#include <wallet/crosschainmanager.h>
#include <wallet/pricing/pricing_context.h>

#include <bitcoin-build-config.h> // IWYU pragma: keep
#include <addresstype.h>
#include <blockfilter.h>
#include <chain.h>
#include <coins.h>
#include <common/args.h>
#include <common/messages.h>
#include <common/settings.h>
#include <common/signmessage.h>
#include <common/system.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <consensus/validation.h>
#include <external_signer.h>
#include <interfaces/chain.h>
#include <interfaces/handler.h>
#include <interfaces/wallet.h>
#include <kernel/chain.h>
#include <kernel/mempool_removal_reason.h>
#include <key.h>
#include <key_io.h>
#include <logging.h>
#include <node/types.h>
#include <outputtype.h>
#include <policy/feerate.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <psbt.h>
#include <pubkey.h>
#include <random.h>
#include <script/descriptor.h>
#include <script/interpreter.h>
#include <support/cleanse.h>
#include <script/script.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <script/solver.h>
#include <serialize.h>
#include <span.h>
#include <streams.h>
#include <support/allocators/secure.h>
#include <support/allocators/zeroafterfree.h>
#include <support/cleanse.h>
#include <sync.h>
#include <tinyformat.h>
#include <uint256.h>
#include <univalue.h>
#include <util/check.h>
#include <util/fs.h>
#include <util/fs_helpers.h>
#include <util/moneystr.h>
#include <util/result.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <util/time.h>
#include <util/translation.h>
#include <wallet/coincontrol.h>
#include <wallet/context.h>
#include <wallet/crypter.h>
#include <wallet/db.h>
#include <wallet/external_signer_scriptpubkeyman.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/transaction.h>
#include <wallet/types.h>
#include <wallet/walletdb.h>
#include <wallet/walletutil.h>
#include <assets/asset.h>

#include <algorithm>
#include <cassert>
#include <condition_variable>
#include <exception>
#include <map>
#include <limits>
#include <mutex>
#include <optional>
#include <set>
#include <stdexcept>
#include <thread>
#include <tuple>
#include <variant>

struct KeyOriginInfo;

using common::AmountErrMsg;
using common::AmountHighWarn;
using common::PSBTError;
using interfaces::FoundBlock;
using util::ReplaceAll;
using util::ToString;

namespace wallet {

namespace {

bool AssetMetadataEquals(const AssetMetadata& lhs, const AssetMetadata& rhs)
{
    if (lhs.asset_id != rhs.asset_id) return false;
    if (lhs.is_issuer_credential != rhs.is_issuer_credential) return false;
    if (lhs.has_ticker != rhs.has_ticker) return false;
    if (lhs.has_ticker && lhs.ticker != rhs.ticker) return false;
    if (lhs.has_decimals != rhs.has_decimals) return false;
    if (lhs.has_decimals && lhs.decimals != rhs.decimals) return false;
    return true;
}

} // namespace

bool AddWalletSetting(interfaces::Chain& chain, const std::string& wallet_name)
{
    const auto update_function = [&wallet_name](common::SettingsValue& setting_value) {
        if (!setting_value.isArray()) setting_value.setArray();
        for (const auto& value : setting_value.getValues()) {
            if (value.isStr() && value.get_str() == wallet_name) return interfaces::SettingsAction::SKIP_WRITE;
        }
        setting_value.push_back(wallet_name);
        return interfaces::SettingsAction::WRITE;
    };
    return chain.updateRwSetting("wallet", update_function);
}

bool RemoveWalletSetting(interfaces::Chain& chain, const std::string& wallet_name)
{
    const auto update_function = [&wallet_name](common::SettingsValue& setting_value) {
        if (!setting_value.isArray()) return interfaces::SettingsAction::SKIP_WRITE;
        common::SettingsValue new_value(common::SettingsValue::VARR);
        for (const auto& value : setting_value.getValues()) {
            if (!value.isStr() || value.get_str() != wallet_name) new_value.push_back(value);
        }
        if (new_value.size() == setting_value.size()) return interfaces::SettingsAction::SKIP_WRITE;
        setting_value = std::move(new_value);
        return interfaces::SettingsAction::WRITE;
    };
    return chain.updateRwSetting("wallet", update_function);
}

static void UpdateWalletSetting(interfaces::Chain& chain,
                                const std::string& wallet_name,
                                std::optional<bool> load_on_startup,
                                std::vector<bilingual_str>& warnings)
{
    if (!load_on_startup) return;
    if (load_on_startup.value() && !AddWalletSetting(chain, wallet_name)) {
        warnings.emplace_back(Untranslated("Wallet load on startup setting could not be updated, so wallet may not be loaded next node startup."));
    } else if (!load_on_startup.value() && !RemoveWalletSetting(chain, wallet_name)) {
        warnings.emplace_back(Untranslated("Wallet load on startup setting could not be updated, so wallet may still be loaded next node startup."));
    }
}

/**
 * Refresh mempool status so the wallet is in an internally consistent state and
 * immediately knows the transaction's status: Whether it can be considered
 * trusted and is eligible to be abandoned ...
 */
static void RefreshMempoolStatus(CWalletTx& tx, interfaces::Chain& chain)
{
    if (chain.isInMempool(tx.GetHash())) {
        tx.m_state = TxStateInMempool();
    } else if (tx.state<TxStateInMempool>()) {
        tx.m_state = TxStateInactive();
    }
}

bool AddWallet(WalletContext& context, const std::shared_ptr<CWallet>& wallet)
{
    LOCK(context.wallets_mutex);
    assert(wallet);
    std::vector<std::shared_ptr<CWallet>>::const_iterator i = std::find(context.wallets.begin(), context.wallets.end(), wallet);
    if (i != context.wallets.end()) return false;
    context.wallets.push_back(wallet);
    wallet->ConnectScriptPubKeyManNotifiers();
    wallet->NotifyCanGetAddressesChanged();
    return true;
}

bool RemoveWallet(WalletContext& context, const std::shared_ptr<CWallet>& wallet, std::optional<bool> load_on_start, std::vector<bilingual_str>& warnings)
{
    assert(wallet);

    interfaces::Chain& chain = wallet->chain();
    std::string name = wallet->GetName();

    // Unregister with the validation interface which also drops shared pointers.
    wallet->m_chain_notifications_handler.reset();
    {
        LOCK(context.wallets_mutex);
        std::vector<std::shared_ptr<CWallet>>::iterator i = std::find(context.wallets.begin(), context.wallets.end(), wallet);
        if (i == context.wallets.end()) return false;
        context.wallets.erase(i);
    }
    // Notify unload so that upper layers release the shared pointer.
    wallet->NotifyUnload();

    // Write the wallet setting
    UpdateWalletSetting(chain, name, load_on_start, warnings);

    return true;
}

bool RemoveWallet(WalletContext& context, const std::shared_ptr<CWallet>& wallet, std::optional<bool> load_on_start)
{
    std::vector<bilingual_str> warnings;
    return RemoveWallet(context, wallet, load_on_start, warnings);
}

std::vector<std::shared_ptr<CWallet>> GetWallets(WalletContext& context)
{
    LOCK(context.wallets_mutex);
    return context.wallets;
}

std::shared_ptr<CWallet> GetDefaultWallet(WalletContext& context, size_t& count)
{
    LOCK(context.wallets_mutex);
    count = context.wallets.size();
    return count == 1 ? context.wallets[0] : nullptr;
}

std::shared_ptr<CWallet> GetWallet(WalletContext& context, const std::string& name)
{
    LOCK(context.wallets_mutex);
    for (const std::shared_ptr<CWallet>& wallet : context.wallets) {
        if (wallet->GetName() == name) return wallet;
    }
    return nullptr;
}

std::unique_ptr<interfaces::Handler> HandleLoadWallet(WalletContext& context, LoadWalletFn load_wallet)
{
    LOCK(context.wallets_mutex);
    auto it = context.wallet_load_fns.emplace(context.wallet_load_fns.end(), std::move(load_wallet));
    return interfaces::MakeCleanupHandler([&context, it] { LOCK(context.wallets_mutex); context.wallet_load_fns.erase(it); });
}

void NotifyWalletLoaded(WalletContext& context, const std::shared_ptr<CWallet>& wallet)
{
    LOCK(context.wallets_mutex);
    for (auto& load_wallet : context.wallet_load_fns) {
        load_wallet(interfaces::MakeWallet(context, wallet));
    }
}

static GlobalMutex g_loading_wallet_mutex;
static GlobalMutex g_wallet_release_mutex;
static std::condition_variable g_wallet_release_cv;
static std::set<std::string> g_loading_wallet_set GUARDED_BY(g_loading_wallet_mutex);
static std::set<std::string> g_unloading_wallet_set GUARDED_BY(g_wallet_release_mutex);

// Custom deleter for shared_ptr<CWallet>.
static void FlushAndDeleteWallet(CWallet* wallet)
{
    const std::string name = wallet->GetName();
    wallet->WalletLogPrintf("Releasing wallet %s..\n", name);
    delete wallet;
    // Wallet is now released, notify WaitForDeleteWallet, if any.
    {
        LOCK(g_wallet_release_mutex);
        if (g_unloading_wallet_set.erase(name) == 0) {
            // WaitForDeleteWallet was not called for this wallet, all done.
            return;
        }
    }
    g_wallet_release_cv.notify_all();
}

void WaitForDeleteWallet(std::shared_ptr<CWallet>&& wallet)
{
    // Mark wallet for unloading.
    const std::string name = wallet->GetName();
    {
        LOCK(g_wallet_release_mutex);
        g_unloading_wallet_set.insert(name);
        // Do not expect to be the only one removing this wallet.
        // Multiple threads could simultaneously be waiting for deletion.
    }

    // Time to ditch our shared_ptr and wait for FlushAndDeleteWallet call.
    wallet.reset();
    {
        WAIT_LOCK(g_wallet_release_mutex, lock);
        while (g_unloading_wallet_set.count(name) == 1) {
            g_wallet_release_cv.wait(lock);
        }
    }
}

namespace {
std::shared_ptr<CWallet> LoadWalletInternal(WalletContext& context, const std::string& name, std::optional<bool> load_on_start, const DatabaseOptions& options, DatabaseStatus& status, bilingual_str& error, std::vector<bilingual_str>& warnings)
{
    try {
        std::unique_ptr<WalletDatabase> database = MakeWalletDatabase(name, options, status, error);
        if (!database) {
            error = Untranslated("Wallet file verification failed.") + Untranslated(" ") + error;
            return nullptr;
        }

        context.chain->initMessage(_("Loading wallet…"));
        std::shared_ptr<CWallet> wallet = CWallet::Create(context, name, std::move(database), options.create_flags, error, warnings);
        if (!wallet) {
            error = Untranslated("Wallet loading failed.") + Untranslated(" ") + error;
            status = DatabaseStatus::FAILED_LOAD;
            return nullptr;
        }

        // Legacy wallets are being deprecated, warn if the loaded wallet is legacy
        if (!wallet->IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS)) {
            warnings.emplace_back(_("Wallet loaded successfully. The legacy wallet type is being deprecated and support for creating and opening legacy wallets will be removed in the future. Legacy wallets can be migrated to a descriptor wallet with migratewallet."));
        }

        NotifyWalletLoaded(context, wallet);
        AddWallet(context, wallet);
        wallet->postInitProcess();

        // Write the wallet setting
        UpdateWalletSetting(*context.chain, name, load_on_start, warnings);

        return wallet;
    } catch (const std::runtime_error& e) {
        error = Untranslated(e.what());
        status = DatabaseStatus::FAILED_LOAD;
        return nullptr;
    }
}

class FastWalletRescanFilter
{
public:
    FastWalletRescanFilter(const CWallet& wallet) : m_wallet(wallet)
    {
        // create initial filter with scripts from all ScriptPubKeyMans
        for (auto spkm : m_wallet.GetAllScriptPubKeyMans()) {
            auto desc_spkm{dynamic_cast<DescriptorScriptPubKeyMan*>(spkm)};
            assert(desc_spkm != nullptr);
            AddScriptPubKeys(desc_spkm);
            // save each range descriptor's end for possible future filter updates
            if (desc_spkm->IsHDEnabled()) {
                m_last_range_ends.emplace(desc_spkm->GetID(), desc_spkm->GetEndRange());
            }
        }
    }

    void UpdateIfNeeded()
    {
        // repopulate filter with new scripts if top-up has happened since last iteration
        for (const auto& [desc_spkm_id, last_range_end] : m_last_range_ends) {
            auto desc_spkm{dynamic_cast<DescriptorScriptPubKeyMan*>(m_wallet.GetScriptPubKeyMan(desc_spkm_id))};
            assert(desc_spkm != nullptr);
            int32_t current_range_end{desc_spkm->GetEndRange()};
            if (current_range_end > last_range_end) {
                AddScriptPubKeys(desc_spkm, last_range_end);
                m_last_range_ends.at(desc_spkm->GetID()) = current_range_end;
            }
        }
    }

    std::optional<bool> MatchesBlock(const uint256& block_hash) const
    {
        return m_wallet.chain().blockFilterMatchesAny(BlockFilterType::BASIC, block_hash, m_filter_set);
    }

private:
    const CWallet& m_wallet;
    /** Map for keeping track of each range descriptor's last seen end range.
      * This information is used to detect whether new addresses were derived
      * (that is, if the current end range is larger than the saved end range)
      * after processing a block and hence a filter set update is needed to
      * take possible keypool top-ups into account.
      */
    std::map<uint256, int32_t> m_last_range_ends;
    GCSFilter::ElementSet m_filter_set;

    void AddScriptPubKeys(const DescriptorScriptPubKeyMan* desc_spkm, int32_t last_range_end = 0)
    {
        for (const auto& script_pub_key : desc_spkm->GetScriptPubKeys(last_range_end)) {
            m_filter_set.emplace(script_pub_key.begin(), script_pub_key.end());
        }
    }
};
} // namespace

std::shared_ptr<CWallet> LoadWallet(WalletContext& context, const std::string& name, std::optional<bool> load_on_start, const DatabaseOptions& options, DatabaseStatus& status, bilingual_str& error, std::vector<bilingual_str>& warnings)
{
    auto result = WITH_LOCK(g_loading_wallet_mutex, return g_loading_wallet_set.insert(name));
    if (!result.second) {
        error = Untranslated("Wallet already loading.");
        status = DatabaseStatus::FAILED_LOAD;
        return nullptr;
    }
    auto wallet = LoadWalletInternal(context, name, load_on_start, options, status, error, warnings);
    WITH_LOCK(g_loading_wallet_mutex, g_loading_wallet_set.erase(result.first));
    return wallet;
}

std::shared_ptr<CWallet> CreateWallet(WalletContext& context, const std::string& name, std::optional<bool> load_on_start, DatabaseOptions& options, DatabaseStatus& status, bilingual_str& error, std::vector<bilingual_str>& warnings)
{
    uint64_t wallet_creation_flags = options.create_flags;
    const SecureString& passphrase = options.create_passphrase;

    if (wallet_creation_flags & WALLET_FLAG_DESCRIPTORS) options.require_format = DatabaseFormat::SQLITE;
    else {
        error = Untranslated("Legacy wallets can no longer be created");
        status = DatabaseStatus::FAILED_CREATE;
        return nullptr;
    }

    // Indicate that the wallet is actually supposed to be blank and not just blank to make it encrypted
    bool create_blank = (wallet_creation_flags & WALLET_FLAG_BLANK_WALLET);

    // Born encrypted wallets need to be created blank first.
    if (!passphrase.empty()) {
        wallet_creation_flags |= WALLET_FLAG_BLANK_WALLET;
    }

    // Private keys must be disabled for an external signer wallet
    if ((wallet_creation_flags & WALLET_FLAG_EXTERNAL_SIGNER) && !(wallet_creation_flags & WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
        error = Untranslated("Private keys must be disabled when using an external signer");
        status = DatabaseStatus::FAILED_CREATE;
        return nullptr;
    }

    // Descriptor support must be enabled for an external signer wallet
    if ((wallet_creation_flags & WALLET_FLAG_EXTERNAL_SIGNER) && !(wallet_creation_flags & WALLET_FLAG_DESCRIPTORS)) {
        error = Untranslated("Descriptor support must be enabled when using an external signer");
        status = DatabaseStatus::FAILED_CREATE;
        return nullptr;
    }

    // Do not allow a passphrase when private keys are disabled
    if (!passphrase.empty() && (wallet_creation_flags & WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
        error = Untranslated("Passphrase provided but private keys are disabled. A passphrase is only used to encrypt private keys, so cannot be used for wallets with private keys disabled.");
        status = DatabaseStatus::FAILED_CREATE;
        return nullptr;
    }

    // Wallet::Verify will check if we're trying to create a wallet with a duplicate name.
    std::unique_ptr<WalletDatabase> database = MakeWalletDatabase(name, options, status, error);
    if (!database) {
        error = Untranslated("Wallet file verification failed.") + Untranslated(" ") + error;
        status = DatabaseStatus::FAILED_VERIFY;
        return nullptr;
    }

    // Make the wallet
    context.chain->initMessage(_("Loading wallet…"));
    std::shared_ptr<CWallet> wallet = CWallet::Create(context, name, std::move(database), wallet_creation_flags, error, warnings);
    if (!wallet) {
        error = Untranslated("Wallet creation failed.") + Untranslated(" ") + error;
        status = DatabaseStatus::FAILED_CREATE;
        return nullptr;
    }

    // Encrypt the wallet
    if (!passphrase.empty() && !(wallet_creation_flags & WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
        if (!wallet->EncryptWallet(passphrase)) {
            error = Untranslated("Error: Wallet created but failed to encrypt.");
            status = DatabaseStatus::FAILED_ENCRYPT;
            return nullptr;
        }
        if (!create_blank) {
            // Unlock the wallet
            if (!wallet->Unlock(passphrase)) {
                error = Untranslated("Error: Wallet was encrypted but could not be unlocked");
                status = DatabaseStatus::FAILED_ENCRYPT;
                return nullptr;
            }

            // Set a seed for the wallet
            {
                LOCK(wallet->cs_wallet);
                if (wallet->IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS)) {
                    wallet->SetupDescriptorScriptPubKeyMans();
                } else {
                    for (auto spk_man : wallet->GetActiveScriptPubKeyMans()) {
                        if (!spk_man->SetupGeneration()) {
                            error = Untranslated("Unable to generate initial keys");
                            status = DatabaseStatus::FAILED_CREATE;
                            return nullptr;
                        }
                    }
                }
            }

            // Relock the wallet
            wallet->Lock();
        }
    }

    NotifyWalletLoaded(context, wallet);
    AddWallet(context, wallet);
    wallet->postInitProcess();

    // Write the wallet settings
    UpdateWalletSetting(*context.chain, name, load_on_start, warnings);

    // Legacy wallets are being deprecated, warn if a newly created wallet is legacy
    if (!(wallet_creation_flags & WALLET_FLAG_DESCRIPTORS)) {
        warnings.emplace_back(_("Wallet created successfully. The legacy wallet type is being deprecated and support for creating and opening legacy wallets will be removed in the future."));
    }

    status = DatabaseStatus::SUCCESS;
    return wallet;
}

// Re-creates wallet from the backup file by renaming and moving it into the wallet's directory.
// If 'load_after_restore=true', the wallet object will be fully initialized and appended to the context.
std::shared_ptr<CWallet> RestoreWallet(WalletContext& context, const fs::path& backup_file, const std::string& wallet_name, std::optional<bool> load_on_start, DatabaseStatus& status, bilingual_str& error, std::vector<bilingual_str>& warnings, bool load_after_restore)
{
    DatabaseOptions options;
    ReadDatabaseArgs(*context.args, options);
    options.require_existing = true;

    const fs::path wallet_path = fsbridge::AbsPathJoin(GetWalletDir(), fs::u8path(wallet_name));
    auto wallet_file = wallet_path / "wallet.dat";
    std::shared_ptr<CWallet> wallet;

    try {
        if (!fs::exists(backup_file)) {
            error = Untranslated("Backup file does not exist");
            status = DatabaseStatus::FAILED_INVALID_BACKUP_FILE;
            return nullptr;
        }

        if (fs::exists(wallet_path) || !TryCreateDirectories(wallet_path)) {
            error = Untranslated(strprintf("Failed to create database path '%s'. Database already exists.", fs::PathToString(wallet_path)));
            status = DatabaseStatus::FAILED_ALREADY_EXISTS;
            return nullptr;
        }

        fs::copy_file(backup_file, wallet_file, fs::copy_options::none);

        if (load_after_restore) {
            wallet = LoadWallet(context, wallet_name, load_on_start, options, status, error, warnings);
        }
    } catch (const std::exception& e) {
        assert(!wallet);
        if (!error.empty()) error += Untranslated("\n");
        error += Untranslated(strprintf("Unexpected exception: %s", e.what()));
    }

    // Remove created wallet path only when loading fails
    if (load_after_restore && !wallet) {
        fs::remove_all(wallet_path);
    }

    return wallet;
}

/** @defgroup mapWallet
 *
 * @{
 */

const CWalletTx* CWallet::GetWalletTx(const Txid& hash) const
{
    AssertLockHeld(cs_wallet);
    const auto it = mapWallet.find(hash);
    if (it == mapWallet.end())
        return nullptr;
    return &(it->second);
}

void CWallet::UpgradeDescriptorCache()
{
    if (!IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS) || IsLocked() || IsWalletFlagSet(WALLET_FLAG_LAST_HARDENED_XPUB_CACHED)) {
        return;
    }

    for (ScriptPubKeyMan* spkm : GetAllScriptPubKeyMans()) {
        DescriptorScriptPubKeyMan* desc_spkm = dynamic_cast<DescriptorScriptPubKeyMan*>(spkm);
        desc_spkm->UpgradeDescriptorCache();
    }
    SetWalletFlag(WALLET_FLAG_LAST_HARDENED_XPUB_CACHED);
}

/* Given a wallet passphrase string and an unencrypted master key, determine the proper key
 * derivation parameters (should take at least 100ms) and encrypt the master key. */
static bool EncryptMasterKey(const SecureString& wallet_passphrase, const CKeyingMaterial& plain_master_key, CMasterKey& master_key)
{
    constexpr MillisecondsDouble target{100};
    auto start{SteadyClock::now()};
    CCrypter crypter;

    crypter.SetKeyFromPassphrase(wallet_passphrase, master_key.vchSalt, master_key.nDeriveIterations, master_key.nDerivationMethod);
    master_key.nDeriveIterations = static_cast<unsigned int>(master_key.nDeriveIterations * target / (SteadyClock::now() - start));

    start = SteadyClock::now();
    crypter.SetKeyFromPassphrase(wallet_passphrase, master_key.vchSalt, master_key.nDeriveIterations, master_key.nDerivationMethod);
    master_key.nDeriveIterations = (master_key.nDeriveIterations + static_cast<unsigned int>(master_key.nDeriveIterations * target / (SteadyClock::now() - start))) / 2;

    if (master_key.nDeriveIterations < CMasterKey::DEFAULT_DERIVE_ITERATIONS) {
        master_key.nDeriveIterations = CMasterKey::DEFAULT_DERIVE_ITERATIONS;
    }

    if (!crypter.SetKeyFromPassphrase(wallet_passphrase, master_key.vchSalt, master_key.nDeriveIterations, master_key.nDerivationMethod)) {
        return false;
    }
    if (!crypter.Encrypt(plain_master_key, master_key.vchCryptedKey)) {
        return false;
    }

    return true;
}

static bool DecryptMasterKey(const SecureString& wallet_passphrase, const CMasterKey& master_key, CKeyingMaterial& plain_master_key)
{
    CCrypter crypter;
    if (!crypter.SetKeyFromPassphrase(wallet_passphrase, master_key.vchSalt, master_key.nDeriveIterations, master_key.nDerivationMethod)) {
        return false;
    }
    if (!crypter.Decrypt(master_key.vchCryptedKey, plain_master_key)) {
        return false;
    }

    return true;
}

bool CWallet::Unlock(const SecureString& strWalletPassphrase)
{
    CKeyingMaterial plain_master_key;

    {
        LOCK(cs_wallet);
        for (const auto& [_, master_key] : mapMasterKeys)
        {
            if (!DecryptMasterKey(strWalletPassphrase, master_key, plain_master_key)) {
                continue; // try another master key
            }
            if (Unlock(plain_master_key)) {
                // Now that we've unlocked, upgrade the descriptor cache
                UpgradeDescriptorCache();
                return true;
            }
        }
    }
    return false;
}

bool CWallet::ChangeWalletPassphrase(const SecureString& strOldWalletPassphrase, const SecureString& strNewWalletPassphrase)
{
    bool fWasLocked = IsLocked();

    {
        LOCK2(m_relock_mutex, cs_wallet);
        Lock();

        CKeyingMaterial plain_master_key;
        for (auto& [master_key_id, master_key] : mapMasterKeys)
        {
            if (!DecryptMasterKey(strOldWalletPassphrase, master_key, plain_master_key)) {
                return false;
            }
            if (Unlock(plain_master_key))
            {
                if (!EncryptMasterKey(strNewWalletPassphrase, plain_master_key, master_key)) {
                    return false;
                }
                WalletLogPrintf("Wallet passphrase changed to an nDeriveIterations of %i\n", master_key.nDeriveIterations);

                WalletBatch(GetDatabase()).WriteMasterKey(master_key_id, master_key);
                if (fWasLocked)
                    Lock();
                return true;
            }
        }
    }

    return false;
}

void CWallet::chainStateFlushed(ChainstateRole role, const CBlockLocator& loc)
{
    // Don't update the best block until the chain is attached so that in case of a shutdown,
    // the rescan will be restarted at next startup.
    if (m_attaching_chain || role == ChainstateRole::BACKGROUND) {
        return;
    }
    WalletBatch batch(GetDatabase());
    batch.WriteBestBlock(loc);
}

void CWallet::SetMinVersion(enum WalletFeature nVersion, WalletBatch* batch_in)
{
    LOCK(cs_wallet);
    if (nWalletVersion >= nVersion)
        return;
    WalletLogPrintf("Setting minversion to %d\n", nVersion);
    nWalletVersion = nVersion;

    {
        WalletBatch* batch = batch_in ? batch_in : new WalletBatch(GetDatabase());
        if (nWalletVersion > 40000)
            batch->WriteMinVersion(nWalletVersion);
        if (!batch_in)
            delete batch;
    }
}

std::set<Txid> CWallet::GetConflicts(const Txid& txid) const
{
    std::set<Txid> result;
    AssertLockHeld(cs_wallet);

    const auto it = mapWallet.find(txid);
    if (it == mapWallet.end())
        return result;
    const CWalletTx& wtx = it->second;

    std::pair<TxSpends::const_iterator, TxSpends::const_iterator> range;

    for (const CTxIn& txin : wtx.tx->vin)
    {
        if (mapTxSpends.count(txin.prevout) <= 1)
            continue;  // No conflict if zero or one spends
        range = mapTxSpends.equal_range(txin.prevout);
        for (TxSpends::const_iterator _it = range.first; _it != range.second; ++_it)
            result.insert(_it->second);
    }
    return result;
}

bool CWallet::HasWalletSpend(const CTransactionRef& tx) const
{
    AssertLockHeld(cs_wallet);
    const Txid& txid = tx->GetHash();
    for (unsigned int i = 0; i < tx->vout.size(); ++i) {
        if (IsSpent(COutPoint(txid, i))) {
            return true;
        }
    }
    return false;
}

void CWallet::Close()
{
    GetDatabase().Close();
}

void CWallet::SyncMetaData(std::pair<TxSpends::iterator, TxSpends::iterator> range)
{
    // We want all the wallet transactions in range to have the same metadata as
    // the oldest (smallest nOrderPos).
    // So: find smallest nOrderPos:

    int nMinOrderPos = std::numeric_limits<int>::max();
    const CWalletTx* copyFrom = nullptr;
    for (TxSpends::iterator it = range.first; it != range.second; ++it) {
        const CWalletTx* wtx = &mapWallet.at(it->second);
        if (wtx->nOrderPos < nMinOrderPos) {
            nMinOrderPos = wtx->nOrderPos;
            copyFrom = wtx;
        }
    }

    if (!copyFrom) {
        return;
    }

    // Now copy data from copyFrom to rest:
    for (TxSpends::iterator it = range.first; it != range.second; ++it)
    {
        const Txid& hash = it->second;
        CWalletTx* copyTo = &mapWallet.at(hash);
        if (copyFrom == copyTo) continue;
        assert(copyFrom && "Oldest wallet transaction in range assumed to have been found.");
        if (!copyFrom->IsEquivalentTo(*copyTo)) continue;
        copyTo->mapValue = copyFrom->mapValue;
        copyTo->vOrderForm = copyFrom->vOrderForm;
        // fTimeReceivedIsTxTime not copied on purpose
        // nTimeReceived not copied on purpose
        copyTo->nTimeSmart = copyFrom->nTimeSmart;
        // nOrderPos not copied on purpose
        // cached members not copied on purpose
    }
}

/**
 * Outpoint is spent if any non-conflicted transaction
 * spends it:
 */
bool CWallet::IsSpent(const COutPoint& outpoint) const
{
    std::pair<TxSpends::const_iterator, TxSpends::const_iterator> range;
    range = mapTxSpends.equal_range(outpoint);

    for (TxSpends::const_iterator it = range.first; it != range.second; ++it) {
        const Txid& txid = it->second;
        const auto mit = mapWallet.find(txid);
        if (mit != mapWallet.end()) {
            const auto& wtx = mit->second;
            if (!wtx.isAbandoned() && !wtx.isBlockConflicted() && !wtx.isMempoolConflicted())
                return true; // Spent
        }
    }
    return false;
}

void CWallet::AddToSpends(const COutPoint& outpoint, const Txid& txid, WalletBatch* batch)
{
    mapTxSpends.insert(std::make_pair(outpoint, txid));

    if (batch) {
        UnlockCoin(outpoint, batch);
    } else {
        WalletBatch temp_batch(GetDatabase());
        UnlockCoin(outpoint, &temp_batch);
    }

    std::pair<TxSpends::iterator, TxSpends::iterator> range;
    range = mapTxSpends.equal_range(outpoint);
    SyncMetaData(range);
}


void CWallet::AddToSpends(const CWalletTx& wtx, WalletBatch* batch)
{
    if (wtx.IsCoinBase()) // Coinbases don't spend anything!
        return;

    for (const CTxIn& txin : wtx.tx->vin)
        AddToSpends(txin.prevout, wtx.GetHash(), batch);
}

bool CWallet::EncryptWallet(const SecureString& strWalletPassphrase)
{
    if (IsCrypted())
        return false;

    CKeyingMaterial plain_master_key;

    plain_master_key.resize(WALLET_CRYPTO_KEY_SIZE);
    GetStrongRandBytes(plain_master_key);

    CMasterKey master_key;

    master_key.vchSalt.resize(WALLET_CRYPTO_SALT_SIZE);
    GetStrongRandBytes(master_key.vchSalt);

    if (!EncryptMasterKey(strWalletPassphrase, plain_master_key, master_key)) {
        return false;
    }
    WalletLogPrintf("Encrypting Wallet with an nDeriveIterations of %i\n", master_key.nDeriveIterations);

    {
        LOCK2(m_relock_mutex, cs_wallet);
        mapMasterKeys[++nMasterKeyMaxID] = master_key;
        WalletBatch* encrypted_batch = new WalletBatch(GetDatabase());
        if (!encrypted_batch->TxnBegin()) {
            delete encrypted_batch;
            encrypted_batch = nullptr;
            return false;
        }
        encrypted_batch->WriteMasterKey(nMasterKeyMaxID, master_key);

        for (const auto& spk_man_pair : m_spk_managers) {
            auto spk_man = spk_man_pair.second.get();
            if (!spk_man->Encrypt(plain_master_key, encrypted_batch)) {
                encrypted_batch->TxnAbort();
                delete encrypted_batch;
                encrypted_batch = nullptr;
                // We now probably have half of our keys encrypted in memory, and half not...
                // die and let the user reload the unencrypted wallet.
                assert(false);
            }
        }

        // Encrypt ML-DSA keys
        // Load all unencrypted ML-DSA keys and encrypt them
        DataStream mldsa_prefix;
        mldsa_prefix << DBKeys::MLDSA_KEY;
        std::unique_ptr<DatabaseCursor> mldsa_cursor = encrypted_batch->GetNewPrefixCursor(mldsa_prefix);
        if (mldsa_cursor) {
            DataStream mldsa_key_ds, mldsa_value_ds;
            while (mldsa_cursor->Next(mldsa_key_ds, mldsa_value_ds) == DatabaseCursor::Status::MORE) {
                // Parse the key (DBKeys::MLDSA_KEY || pk_hash)
                std::string key_type;
                uint256 pk_hash;
                mldsa_key_ds >> key_type >> pk_hash;
                assert(key_type == DBKeys::MLDSA_KEY);

                // Parse the value (vchData || checksum)
                std::vector<unsigned char> vchData;
                uint256 checksum;
                mldsa_value_ds >> vchData >> checksum;

                // Verify checksum
                if (Hash(vchData) != checksum) {
                    WalletLogPrintf("Warning: ML-DSA key checksum mismatch during encryption, skipping\n");
                    continue;
                }

                // Parse vchData: level || pk_len || pubkey || sk_len || seckey
                if (vchData.size() < 9) {
                    WalletLogPrintf("Warning: ML-DSA key data too short during encryption, skipping\n");
                    continue;
                }

                size_t pos = 0;
                uint8_t level = vchData[pos++];

                // Read public key length
                uint32_t pk_len = static_cast<uint32_t>(vchData[pos]) |
                                 (static_cast<uint32_t>(vchData[pos + 1]) << 8) |
                                 (static_cast<uint32_t>(vchData[pos + 2]) << 16) |
                                 (static_cast<uint32_t>(vchData[pos + 3]) << 24);
                pos += 4;

                if (pos + pk_len + 4 > vchData.size()) {
                    WalletLogPrintf("Warning: ML-DSA key public key length invalid during encryption, skipping\n");
                    continue;
                }

                std::vector<uint8_t> pubkey(vchData.begin() + pos, vchData.begin() + pos + pk_len);
                pos += pk_len;

                // Read secret key length
                uint32_t sk_len = static_cast<uint32_t>(vchData[pos]) |
                                 (static_cast<uint32_t>(vchData[pos + 1]) << 8) |
                                 (static_cast<uint32_t>(vchData[pos + 2]) << 16) |
                                 (static_cast<uint32_t>(vchData[pos + 3]) << 24);
                pos += 4;

                if (pos + sk_len != vchData.size()) {
                    WalletLogPrintf("Warning: ML-DSA key secret key length invalid during encryption, skipping\n");
                    continue;
                }

                std::vector<uint8_t> seckey(vchData.begin() + pos, vchData.begin() + pos + sk_len);

                // Encrypt the secret key using the same method as ECDSA keys
                CKeyingMaterial secret{seckey.begin(), seckey.end()};
                std::vector<unsigned char> crypted_secret;
                uint256 pk_hash_for_iv = Hash(pubkey);  // Use pubkey hash as IV
                if (!EncryptSecret(plain_master_key, secret, pk_hash_for_iv, crypted_secret)) {
                    encrypted_batch->TxnAbort();
                    delete encrypted_batch;
                    encrypted_batch = nullptr;
                    WalletLogPrintf("Error: Failed to encrypt ML-DSA key\n");
                    assert(false);
                }

                // Read metadata (if exists)
                CKeyMetadata metadata;
                if (encrypted_batch->ReadFromBatch(std::make_pair(DBKeys::MLDSA_KEYMETA, pk_hash), metadata)) {
                    // Metadata exists, good
                } else {
                    // No metadata, create default
                    metadata.nCreateTime = GetTime();
                    metadata.nVersion = CKeyMetadata::CURRENT_VERSION;
                }

                // Write encrypted key
                if (!encrypted_batch->WriteCryptedMLDSAKey(pk_hash, pubkey, crypted_secret, level, metadata)) {
                    encrypted_batch->TxnAbort();
                    delete encrypted_batch;
                    encrypted_batch = nullptr;
                    WalletLogPrintf("Error: Failed to write encrypted ML-DSA key\n");
                    assert(false);
                }

                WalletLogPrintf("Encrypted ML-DSA key (level=%d, pk_hash=%s)\n", level, pk_hash.GetHex());
            }
        }

        // Encryption was introduced in version 0.4.0
        SetMinVersion(FEATURE_WALLETCRYPT, encrypted_batch);

        if (!encrypted_batch->TxnCommit()) {
            delete encrypted_batch;
            encrypted_batch = nullptr;
            // We now have keys encrypted in memory, but not on disk...
            // die to avoid confusion and let the user reload the unencrypted wallet.
            assert(false);
        }

        delete encrypted_batch;
        encrypted_batch = nullptr;

        Lock();
        Unlock(strWalletPassphrase);

        // If we are using descriptors, make new descriptors with a new seed
        if (IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS) && !IsWalletFlagSet(WALLET_FLAG_BLANK_WALLET)) {
            SetupDescriptorScriptPubKeyMans();
        }
        Lock();

        // Need to completely rewrite the wallet file; if we don't, the database might keep
        // bits of the unencrypted private key in slack space in the database file.
        GetDatabase().Rewrite();
    }
    NotifyStatusChanged(this);

    return true;
}

DBErrors CWallet::ReorderTransactions()
{
    LOCK(cs_wallet);
    WalletBatch batch(GetDatabase());

    // Old wallets didn't have any defined order for transactions
    // Probably a bad idea to change the output of this

    // First: get all CWalletTx into a sorted-by-time multimap.
    typedef std::multimap<int64_t, CWalletTx*> TxItems;
    TxItems txByTime;

    for (auto& entry : mapWallet)
    {
        CWalletTx* wtx = &entry.second;
        txByTime.insert(std::make_pair(wtx->nTimeReceived, wtx));
    }

    nOrderPosNext = 0;
    std::vector<int64_t> nOrderPosOffsets;
    for (TxItems::iterator it = txByTime.begin(); it != txByTime.end(); ++it)
    {
        CWalletTx *const pwtx = (*it).second;
        int64_t& nOrderPos = pwtx->nOrderPos;

        if (nOrderPos == -1)
        {
            nOrderPos = nOrderPosNext++;
            nOrderPosOffsets.push_back(nOrderPos);

            if (!batch.WriteTx(*pwtx))
                return DBErrors::LOAD_FAIL;
        }
        else
        {
            int64_t nOrderPosOff = 0;
            for (const int64_t& nOffsetStart : nOrderPosOffsets)
            {
                if (nOrderPos >= nOffsetStart)
                    ++nOrderPosOff;
            }
            nOrderPos += nOrderPosOff;
            nOrderPosNext = std::max(nOrderPosNext, nOrderPos + 1);

            if (!nOrderPosOff)
                continue;

            // Since we're changing the order, write it back
            if (!batch.WriteTx(*pwtx))
                return DBErrors::LOAD_FAIL;
        }
    }
    batch.WriteOrderPosNext(nOrderPosNext);

    return DBErrors::LOAD_OK;
}

int64_t CWallet::IncOrderPosNext(WalletBatch* batch)
{
    AssertLockHeld(cs_wallet);
    int64_t nRet = nOrderPosNext++;
    if (batch) {
        batch->WriteOrderPosNext(nOrderPosNext);
    } else {
        WalletBatch(GetDatabase()).WriteOrderPosNext(nOrderPosNext);
    }
    return nRet;
}

void CWallet::MarkDirty()
{
    {
        LOCK(cs_wallet);
        for (auto& [_, wtx] : mapWallet)
            wtx.MarkDirty();
    }
}

bool CWallet::MarkReplaced(const Txid& originalHash, const Txid& newHash)
{
    LOCK(cs_wallet);

    auto mi = mapWallet.find(originalHash);

    // There is a bug if MarkReplaced is not called on an existing wallet transaction.
    assert(mi != mapWallet.end());

    CWalletTx& wtx = (*mi).second;

    // Ensure for now that we're not overwriting data
    assert(wtx.mapValue.count("replaced_by_txid") == 0);

    wtx.mapValue["replaced_by_txid"] = newHash.ToString();

    // Refresh mempool status without waiting for transactionRemovedFromMempool or transactionAddedToMempool
    RefreshMempoolStatus(wtx, chain());

    WalletBatch batch(GetDatabase());

    bool success = true;
    if (!batch.WriteTx(wtx)) {
        WalletLogPrintf("%s: Updating batch tx %s failed\n", __func__, wtx.GetHash().ToString());
        success = false;
    }

    NotifyTransactionChanged(originalHash, CT_UPDATED);

    return success;
}

void CWallet::SetSpentKeyState(WalletBatch& batch, const Txid& hash, unsigned int n, bool used, std::set<CTxDestination>& tx_destinations)
{
    AssertLockHeld(cs_wallet);
    const CWalletTx* srctx = GetWalletTx(hash);
    if (!srctx) return;

    CTxDestination dst;
    if (ExtractDestination(srctx->tx->vout[n].scriptPubKey, dst)) {
        if (IsMine(dst)) {
            if (used != IsAddressPreviouslySpent(dst)) {
                if (used) {
                    tx_destinations.insert(dst);
                }
                SetAddressPreviouslySpent(batch, dst, used);
            }
        }
    }
}

bool CWallet::IsSpentKey(const CScript& scriptPubKey) const
{
    AssertLockHeld(cs_wallet);
    CTxDestination dest;
    if (!ExtractDestination(scriptPubKey, dest)) {
        return false;
    }
    if (IsAddressPreviouslySpent(dest)) {
        return true;
    }
    return false;
}

CWalletTx* CWallet::AddToWallet(CTransactionRef tx, const TxState& state, const UpdateWalletTxFn& update_wtx, bool rescanning_old_block)
{
    LOCK(cs_wallet);

    WalletBatch batch(GetDatabase());

    Txid hash = tx->GetHash();

    if (IsWalletFlagSet(WALLET_FLAG_AVOID_REUSE)) {
        // Mark used destinations
        std::set<CTxDestination> tx_destinations;

        for (const CTxIn& txin : tx->vin) {
            const COutPoint& op = txin.prevout;
            SetSpentKeyState(batch, op.hash, op.n, true, tx_destinations);
        }

        MarkDestinationsDirty(tx_destinations);
    }

    // Inserts only if not already there, returns tx inserted or tx found
    auto ret = mapWallet.emplace(std::piecewise_construct, std::forward_as_tuple(hash), std::forward_as_tuple(tx, state));
    CWalletTx& wtx = (*ret.first).second;
    bool fInsertedNew = ret.second;
    bool fUpdated = update_wtx && update_wtx(wtx, fInsertedNew);
    if (fInsertedNew) {
        wtx.nTimeReceived = GetTime();
        wtx.nOrderPos = IncOrderPosNext(&batch);
        wtx.m_it_wtxOrdered = wtxOrdered.insert(std::make_pair(wtx.nOrderPos, &wtx));
        wtx.nTimeSmart = ComputeTimeSmart(wtx, rescanning_old_block);
        AddToSpends(wtx, &batch);

        // Update birth time when tx time is older than it.
        MaybeUpdateBirthTime(wtx.GetTxTime());
    }

    if (!fInsertedNew)
    {
        if (state.index() != wtx.m_state.index()) {
            wtx.m_state = state;
            fUpdated = true;
        } else {
            assert(TxStateSerializedIndex(wtx.m_state) == TxStateSerializedIndex(state));
            assert(TxStateSerializedBlockHash(wtx.m_state) == TxStateSerializedBlockHash(state));
        }
        // If we have a witness-stripped version of this transaction, and we
        // see a new version with a witness, then we must be upgrading a pre-segwit
        // wallet.  Store the new version of the transaction with the witness,
        // as the stripped-version must be invalid.
        // TODO: Store all versions of the transaction, instead of just one.
        if (tx->HasWitness() && !wtx.tx->HasWitness()) {
            wtx.SetTx(tx);
            fUpdated = true;
        }
    }

    // Mark inactive coinbase transactions and their descendants as abandoned
    if (wtx.IsCoinBase() && wtx.isInactive()) {
        std::vector<CWalletTx*> txs{&wtx};

        TxStateInactive inactive_state = TxStateInactive{/*abandoned=*/true};

        while (!txs.empty()) {
            CWalletTx* desc_tx = txs.back();
            txs.pop_back();
            desc_tx->m_state = inactive_state;
            // Break caches since we have changed the state
            desc_tx->MarkDirty();
            batch.WriteTx(*desc_tx);
            MarkInputsDirty(desc_tx->tx);
            for (unsigned int i = 0; i < desc_tx->tx->vout.size(); ++i) {
                COutPoint outpoint(desc_tx->GetHash(), i);
                std::pair<TxSpends::const_iterator, TxSpends::const_iterator> range = mapTxSpends.equal_range(outpoint);
                for (TxSpends::const_iterator it = range.first; it != range.second; ++it) {
                    const auto wit = mapWallet.find(it->second);
                    if (wit != mapWallet.end()) {
                        txs.push_back(&wit->second);
                    }
                }
            }
        }
    }

    // Track asset metadata for wallet-owned TLVs.
    std::map<uint256, assets::IssuerReg> issuer_regs;
    for (const auto& txout : tx->vout) {
        if (auto reg = assets::ParseIssuerReg(txout.vExt)) {
            issuer_regs.emplace(reg->asset_id, *reg);
        }
    }

    const auto merge_known_metadata = [&](AssetMetadata& meta) EXCLUSIVE_LOCKS_REQUIRED(cs_wallet) {
        for (const auto& [outpoint, existing] : m_asset_metadata) {
            if (existing.asset_id != meta.asset_id) continue;
            if (!meta.has_ticker && existing.has_ticker) {
                meta.has_ticker = true;
                meta.ticker = existing.ticker;
            }
            if (!meta.has_decimals && existing.has_decimals) {
                meta.has_decimals = true;
                meta.decimals = existing.decimals;
            }
            if (meta.has_ticker && meta.has_decimals) {
                break;
            }
        }
    };

    std::set<COutPoint> observed_asset_outpoints;
    for (unsigned int i = 0; i < tx->vout.size(); ++i) {
        const CTxOut& output = tx->vout[i];
        const COutPoint outpoint(hash, i);
        const bool owned = IsMine(output) != ISMINE_NO;

        const auto asset_tag = assets::ParseAssetTag(output.vExt);
        const auto issuer_reg = assets::ParseIssuerReg(output.vExt);

        if (owned && asset_tag) {
            AssetMetadata meta;
            meta.asset_id = asset_tag->id;
            meta.is_issuer_credential = false;

            if (auto it = issuer_regs.find(meta.asset_id); it != issuer_regs.end()) {
                if (!it->second.ticker.empty()) {
                    meta.has_ticker = true;
                    meta.ticker = it->second.ticker;
                }
                if (it->second.decimals != 0xFF) {
                    meta.has_decimals = true;
                    meta.decimals = it->second.decimals;
                }
            }

            if (!meta.has_ticker || !meta.has_decimals) {
                merge_known_metadata(meta);
            }

            if (!SetAssetMetadataWithDB(batch, outpoint, meta)) {
                return nullptr;
            }
            observed_asset_outpoints.insert(outpoint);
            continue;
        }

        if (owned && issuer_reg) {
            AssetMetadata meta;
            meta.asset_id = issuer_reg->asset_id;
            meta.is_issuer_credential = true;
            if (!issuer_reg->ticker.empty()) {
                meta.has_ticker = true;
                meta.ticker = issuer_reg->ticker;
            }
            if (issuer_reg->decimals != 0xFF) {
                meta.has_decimals = true;
                meta.decimals = issuer_reg->decimals;
            }

            if (!meta.has_ticker || !meta.has_decimals) {
                merge_known_metadata(meta);
            }

            if (!SetAssetMetadataWithDB(batch, outpoint, meta)) {
                return nullptr;
            }
            observed_asset_outpoints.insert(outpoint);
            continue;
        }

        if (m_asset_metadata.count(outpoint)) {
            if (!EraseAssetMetadataWithDB(batch, outpoint)) {
                return nullptr;
            }
        }
    }

    std::vector<COutPoint> stale_asset_entries;
    for (auto it = m_asset_metadata.lower_bound(COutPoint(hash, 0)); it != m_asset_metadata.end() && it->first.hash == hash; ++it) {
        if (!observed_asset_outpoints.count(it->first)) {
            stale_asset_entries.push_back(it->first);
        }
    }
    for (const auto& stale : stale_asset_entries) {
        if (!EraseAssetMetadataWithDB(batch, stale)) {
            return nullptr;
        }
    }

    //// debug print
    WalletLogPrintf("AddToWallet %s  %s%s %s\n", hash.ToString(), (fInsertedNew ? "new" : ""), (fUpdated ? "update" : ""), TxStateString(state));

    // Write to disk
    if (fInsertedNew || fUpdated)
        if (!batch.WriteTx(wtx))
            return nullptr;

    // Break debit/credit balance caches:
    wtx.MarkDirty();

    // Notify UI of new or updated transaction
    NotifyTransactionChanged(hash, fInsertedNew ? CT_NEW : CT_UPDATED);

#if HAVE_SYSTEM
    // notify an external script when a wallet transaction comes in or is updated
    std::string strCmd = m_notify_tx_changed_script;

    if (!strCmd.empty())
    {
        ReplaceAll(strCmd, "%s", hash.GetHex());
        if (auto* conf = wtx.state<TxStateConfirmed>())
        {
            ReplaceAll(strCmd, "%b", conf->confirmed_block_hash.GetHex());
            ReplaceAll(strCmd, "%h", ToString(conf->confirmed_block_height));
        } else {
            ReplaceAll(strCmd, "%b", "unconfirmed");
            ReplaceAll(strCmd, "%h", "-1");
        }
#ifndef WIN32
        // Substituting the wallet name isn't currently supported on windows
        // because windows shell escaping has not been implemented yet:
        // https://github.com/bitcoin/bitcoin/pull/13339#issuecomment-537384875
        // A few ways it could be implemented in the future are described in:
        // https://github.com/bitcoin/bitcoin/pull/13339#issuecomment-461288094
        ReplaceAll(strCmd, "%w", ShellEscape(GetName()));
#endif
        std::thread t(runCommand, strCmd);
        t.detach(); // thread runs free
    }
#endif

    return &wtx;
}

bool CWallet::LoadToWallet(const Txid& hash, const UpdateWalletTxFn& fill_wtx)
{
    const auto& ins = mapWallet.emplace(std::piecewise_construct, std::forward_as_tuple(hash), std::forward_as_tuple(nullptr, TxStateInactive{}));
    CWalletTx& wtx = ins.first->second;
    if (!fill_wtx(wtx, ins.second)) {
        return false;
    }
    // If wallet doesn't have a chain (e.g when using bitcoin-wallet tool),
    // don't bother to update txn.
    if (HaveChain()) {
      wtx.updateState(chain());
    }
    if (/* insertion took place */ ins.second) {
        wtx.m_it_wtxOrdered = wtxOrdered.insert(std::make_pair(wtx.nOrderPos, &wtx));
    }
    AddToSpends(wtx);
    for (const CTxIn& txin : wtx.tx->vin) {
        auto it = mapWallet.find(txin.prevout.hash);
        if (it != mapWallet.end()) {
            CWalletTx& prevtx = it->second;
            if (auto* prev = prevtx.state<TxStateBlockConflicted>()) {
                MarkConflicted(prev->conflicting_block_hash, prev->conflicting_block_height, wtx.GetHash());
            }
        }
    }

    // Update birth time when tx time is older than it.
    MaybeUpdateBirthTime(wtx.GetTxTime());

    return true;
}

bool CWallet::AddToWalletIfInvolvingMe(const CTransactionRef& ptx, const SyncTxState& state, bool fUpdate, bool rescanning_old_block)
{
    const CTransaction& tx = *ptx;
    {
        AssertLockHeld(cs_wallet);

        if (auto* conf = std::get_if<TxStateConfirmed>(&state)) {
            for (const CTxIn& txin : tx.vin) {
                std::pair<TxSpends::const_iterator, TxSpends::const_iterator> range = mapTxSpends.equal_range(txin.prevout);
                while (range.first != range.second) {
                    if (range.first->second != tx.GetHash()) {
                        WalletLogPrintf("Transaction %s (in block %s) conflicts with wallet transaction %s (both spend %s:%i)\n", tx.GetHash().ToString(), conf->confirmed_block_hash.ToString(), range.first->second.ToString(), range.first->first.hash.ToString(), range.first->first.n);
                        MarkConflicted(conf->confirmed_block_hash, conf->confirmed_block_height, range.first->second);
                    }
                    range.first++;
                }
            }
        }

        bool forward_related = false;
        for (const CTxIn& txin : tx.vin) {
            if (FindForwardContractByVault(txin.prevout)) {
                forward_related = true;
                break;
            }
        }

        bool fExisted = mapWallet.count(tx.GetHash()) != 0;
        if (fExisted && !fUpdate) return false;
        if (fExisted || IsMine(tx) || IsFromMe(tx) || forward_related)
        {
            /* Check if any keys in the wallet keypool that were supposed to be unused
             * have appeared in a new transaction. If so, remove those keys from the keypool.
             * This can happen when restoring an old wallet backup that does not contain
             * the mostly recently created transactions from newer versions of the wallet.
             */

            // loop though all outputs
            for (const CTxOut& txout: tx.vout) {
                for (const auto& spk_man : GetScriptPubKeyMans(txout.scriptPubKey)) {
                    for (auto &dest : spk_man->MarkUnusedAddresses(txout.scriptPubKey)) {
                        // If internal flag is not defined try to infer it from the ScriptPubKeyMan
                        if (!dest.internal.has_value()) {
                            dest.internal = IsInternalScriptPubKeyMan(spk_man);
                        }

                        // skip if can't determine whether it's a receiving address or not
                        if (!dest.internal.has_value()) continue;

                        // If this is a receiving address and it's not in the address book yet
                        // (e.g. it wasn't generated on this node or we're restoring from backup)
                        // add it to the address book for proper transaction accounting
                        if (!*dest.internal && !FindAddressBookEntry(dest.dest, /* allow_change= */ false)) {
                            SetAddressBook(dest.dest, "", AddressPurpose::RECEIVE);
                        }
                    }
                }
            }

            // Block disconnection override an abandoned tx as unconfirmed
            // which means user may have to call abandontransaction again
            TxState tx_state = std::visit([](auto&& s) -> TxState { return s; }, state);
            CWalletTx* wtx = AddToWallet(MakeTransactionRef(tx), tx_state, /*update_wtx=*/nullptr, rescanning_old_block);
            if (!wtx) {
                // Can only be nullptr if there was a db write error (missing db, read-only db or a db engine internal writing error).
                // As we only store arriving transaction in this process, and we don't want an inconsistent state, let's throw an error.
                throw std::runtime_error("DB error adding transaction to wallet, write failed");
            }
            return true;
        }
    }
    return false;
}

bool CWallet::TransactionCanBeAbandoned(const Txid& hashTx) const
{
    LOCK(cs_wallet);
    const CWalletTx* wtx = GetWalletTx(hashTx);
    return wtx && !wtx->isAbandoned() && GetTxDepthInMainChain(*wtx) == 0 && !wtx->InMempool();
}

void CWallet::MarkInputsDirty(const CTransactionRef& tx)
{
    for (const CTxIn& txin : tx->vin) {
        auto it = mapWallet.find(txin.prevout.hash);
        if (it != mapWallet.end()) {
            it->second.MarkDirty();
        }
    }
}

bool CWallet::AbandonTransaction(const Txid& hashTx)
{
    LOCK(cs_wallet);
    auto it = mapWallet.find(hashTx);
    assert(it != mapWallet.end());
    return AbandonTransaction(it->second);
}

bool CWallet::AbandonTransaction(CWalletTx& tx)
{
    // Can't mark abandoned if confirmed or in mempool
    if (GetTxDepthInMainChain(tx) != 0 || tx.InMempool()) {
        return false;
    }

    auto try_updating_state = [](CWalletTx& wtx) EXCLUSIVE_LOCKS_REQUIRED(cs_wallet) {
        // If the orig tx was not in block/mempool, none of its spends can be.
        assert(!wtx.isConfirmed());
        assert(!wtx.InMempool());
        // If already conflicted or abandoned, no need to set abandoned
        if (!wtx.isBlockConflicted() && !wtx.isAbandoned()) {
            wtx.m_state = TxStateInactive{/*abandoned=*/true};
            return TxUpdate::NOTIFY_CHANGED;
        }
        return TxUpdate::UNCHANGED;
    };

    // Iterate over all its outputs, and mark transactions in the wallet that spend them abandoned too.
    // States are not permanent, so these transactions can become unabandoned if they are re-added to the
    // mempool, or confirmed in a block, or conflicted.
    // Note: If the reorged coinbase is re-added to the main chain, the descendants that have not had their
    // states change will remain abandoned and will require manual broadcast if the user wants them.

    RecursiveUpdateTxState(tx.GetHash(), try_updating_state);

    return true;
}

void CWallet::MarkConflicted(const uint256& hashBlock, int conflicting_height, const Txid& hashTx)
{
    LOCK(cs_wallet);

    // If number of conflict confirms cannot be determined, this means
    // that the block is still unknown or not yet part of the main chain,
    // for example when loading the wallet during a reindex. Do nothing in that
    // case.
    if (m_last_block_processed_height < 0 || conflicting_height < 0) {
        return;
    }
    int conflictconfirms = (m_last_block_processed_height - conflicting_height + 1) * -1;
    if (conflictconfirms >= 0)
        return;

    auto try_updating_state = [&](CWalletTx& wtx) EXCLUSIVE_LOCKS_REQUIRED(cs_wallet) {
        if (conflictconfirms < GetTxDepthInMainChain(wtx)) {
            // Block is 'more conflicted' than current confirm; update.
            // Mark transaction as conflicted with this block.
            wtx.m_state = TxStateBlockConflicted{hashBlock, conflicting_height};
            return TxUpdate::CHANGED;
        }
        return TxUpdate::UNCHANGED;
    };

    // Iterate over all its outputs, and mark transactions in the wallet that spend them conflicted too.
    RecursiveUpdateTxState(hashTx, try_updating_state);

}

void CWallet::RecursiveUpdateTxState(const Txid& tx_hash, const TryUpdatingStateFn& try_updating_state) {
    WalletBatch batch(GetDatabase());
    RecursiveUpdateTxState(&batch, tx_hash, try_updating_state);
}

void CWallet::RecursiveUpdateTxState(WalletBatch* batch, const Txid& tx_hash, const TryUpdatingStateFn& try_updating_state) {
    std::set<Txid> todo;
    std::set<Txid> done;

    todo.insert(tx_hash);

    while (!todo.empty()) {
        Txid now = *todo.begin();
        todo.erase(now);
        done.insert(now);
        auto it = mapWallet.find(now);
        assert(it != mapWallet.end());
        CWalletTx& wtx = it->second;

        TxUpdate update_state = try_updating_state(wtx);
        if (update_state != TxUpdate::UNCHANGED) {
            wtx.MarkDirty();
            if (batch) batch->WriteTx(wtx);
            // Iterate over all its outputs, and update those tx states as well (if applicable)
            for (unsigned int i = 0; i < wtx.tx->vout.size(); ++i) {
                std::pair<TxSpends::const_iterator, TxSpends::const_iterator> range = mapTxSpends.equal_range(COutPoint(now, i));
                for (TxSpends::const_iterator iter = range.first; iter != range.second; ++iter) {
                    if (!done.count(iter->second)) {
                        todo.insert(iter->second);
                    }
                }
            }

            if (update_state == TxUpdate::NOTIFY_CHANGED) {
                NotifyTransactionChanged(wtx.GetHash(), CT_UPDATED);
            }

            // If a transaction changes its tx state, that usually changes the balance
            // available of the outputs it spends. So force those to be recomputed
            MarkInputsDirty(wtx.tx);
        }
    }
}

void CWallet::SyncTransaction(const CTransactionRef& ptx, const SyncTxState& state, bool update_tx, bool rescanning_old_block)
{
    AssertLockHeld(cs_wallet);

    if (!AddToWalletIfInvolvingMe(ptx, state, update_tx, rescanning_old_block)) {
        return; // Not one of ours
    }

    // Auto-persist vault outpoints for ACCEPTED forward/repo contracts when opening tx confirms
    // This allows short/lender wallets to transition to OPENED state without manual coordination
    // Check all ACCEPTED forward contracts
    for (auto& [contract_id, record] : m_forward_contracts) {
        const ForwardContractState lifecycle = record.DerivedState();
        if (lifecycle == ForwardContractState::ACCEPTED ||
            lifecycle == ForwardContractState::OPENED) {
            // Attempt to extract and persist (or refresh) vault outpoints from this transaction
            VerifyAndPersistForwardVaults(contract_id, ptx, /*allow_open_discovery=*/true);
        }
        const Txid txid = ptx->GetHash();

        WalletLogPrintf("SyncTransaction: tx=%s, contract=%s, lifecycle=%d\n",
                        txid.ToString(), contract_id.GetHex(), static_cast<int>(lifecycle));

        const bool tx_matches_record =
            (record.open_txid && *record.open_txid == txid) ||
            (record.self_delivery_txid && *record.self_delivery_txid == txid) ||
            (record.coop_close_txid && *record.coop_close_txid == txid) ||
            (record.escrow_claim_txid && *record.escrow_claim_txid == txid) ||
            (record.escrow_refund_txid && *record.escrow_refund_txid == txid) ||
            (record.timeout_txid && *record.timeout_txid == txid);
        const bool spends_forward = TransactionSpendsForwardVault(record, ptx);

        WalletLogPrintf("  tx_matches_record=%d, spends_forward=%d\n", tx_matches_record, spends_forward);

        if (lifecycle == ForwardContractState::OPENED ||
            lifecycle == ForwardContractState::DELIVERED ||
            tx_matches_record ||
            spends_forward) {
            WalletLogPrintf("  -> Calling MaybeRecordForwardStateTransition\n");
            MaybeRecordForwardStateTransition(contract_id, record, ptx, state);
        } else {
            WalletLogPrintf("  -> Skipping MaybeRecordForwardStateTransition (conditions not met)\n");
        }
    }

    // Check all ACCEPTED repo contracts
    for (auto& [offer_id, record] : m_repo_offers) {
        const RepoContractState lifecycle = record.DerivedState();
        if (lifecycle == RepoContractState::ACCEPTED) {
            // Attempt to extract and persist vault outpoint from this transaction
            VerifyAndPersistRepoVault(offer_id, ptx);
        }
        if (lifecycle == RepoContractState::OPENED ||
            (record.repay_txid && *record.repay_txid == ptx->GetHash()) ||
            (record.default_txid && *record.default_txid == ptx->GetHash())) {
            MaybeRecordRepoClosure(offer_id, record, ptx, state);
        }
    }

    // Check all ACCEPTED spot contracts and record settlement txid
    for (auto& [offer_id, record] : m_spot_offers) {
        if (record.acceptance.has_value() && !record.settle_txid.has_value()) {
            // SPOT contract is accepted but not yet marked as settled
            // Check if this transaction settles the SPOT swap
            // The settlement tx should spend both Alice's asset output and Bob's native output
            // For simplicity, mark any wallet tx involving an accepted SPOT as the settlement
            // (More precise matching could check specific inputs/outputs against the SPOT terms)
            if (IsMine(*ptx) != ISMINE_NO) {
                record.settle_txid = ptx->GetHash();
                WalletBatch batch(GetDatabase());
                if (!batch.WriteSpotOffer(record)) {
                    WalletLogPrintf("Failed to persist settle_txid for SPOT offer %s\n", offer_id.GetHex());
                } else {
                    WalletLogPrintf("Recorded settle_txid %s for SPOT offer %s\n",
                                    ptx->GetHash().ToString(), offer_id.GetHex());
                }
            }
        }
    }

    // If a transaction changes 'conflicted' state, that changes the balance
    // available of the outputs it spends. So force those to be
    // recomputed, also:
    MarkInputsDirty(ptx);
}

void CWallet::transactionAddedToMempool(const CTransactionRef& tx) {
    LOCK(cs_wallet);
    SyncTransaction(tx, TxStateInMempool{});

    auto it = mapWallet.find(tx->GetHash());
    if (it != mapWallet.end()) {
        RefreshMempoolStatus(it->second, chain());
    }

    const Txid& txid = tx->GetHash();

    for (const CTxIn& tx_in : tx->vin) {
        // For each wallet transaction spending this prevout..
        for (auto range = mapTxSpends.equal_range(tx_in.prevout); range.first != range.second; range.first++) {
            const Txid& spent_id = range.first->second;
            // Skip the recently added tx
            if (spent_id == txid) continue;
            RecursiveUpdateTxState(/*batch=*/nullptr, spent_id, [&txid](CWalletTx& wtx) EXCLUSIVE_LOCKS_REQUIRED(cs_wallet) {
                return wtx.mempool_conflicts.insert(txid).second ? TxUpdate::CHANGED : TxUpdate::UNCHANGED;
            });
        }
    }
}

void CWallet::transactionRemovedFromMempool(const CTransactionRef& tx, MemPoolRemovalReason reason) {
    LOCK(cs_wallet);
    auto it = mapWallet.find(tx->GetHash());
    if (it != mapWallet.end()) {
        RefreshMempoolStatus(it->second, chain());
    }
    // Handle transactions that were removed from the mempool because they
    // conflict with transactions in a newly connected block.
    if (reason == MemPoolRemovalReason::CONFLICT) {
        // Trigger external -walletnotify notifications for these transactions.
        // Set Status::UNCONFIRMED instead of Status::CONFLICTED for a few reasons:
        //
        // 1. The transactionRemovedFromMempool callback does not currently
        //    provide the conflicting block's hash and height, and for backwards
        //    compatibility reasons it may not be not safe to store conflicted
        //    wallet transactions with a null block hash. See
        //    https://github.com/bitcoin/bitcoin/pull/18600#discussion_r420195993.
        // 2. For most of these transactions, the wallet's internal conflict
        //    detection in the blockConnected handler will subsequently call
        //    MarkConflicted and update them with CONFLICTED status anyway. This
        //    applies to any wallet transaction that has inputs spent in the
        //    block, or that has ancestors in the wallet with inputs spent by
        //    the block.
        // 3. Longstanding behavior since the sync implementation in
        //    https://github.com/bitcoin/bitcoin/pull/9371 and the prior sync
        //    implementation before that was to mark these transactions
        //    unconfirmed rather than conflicted.
        //
        // Nothing described above should be seen as an unchangeable requirement
        // when improving this code in the future. The wallet's heuristics for
        // distinguishing between conflicted and unconfirmed transactions are
        // imperfect, and could be improved in general, see
        // https://github.com/bitcoin-core/bitcoin-devwiki/wiki/Wallet-Transaction-Conflict-Tracking
        SyncTransaction(tx, TxStateInactive{});
    }

    const Txid& txid = tx->GetHash();

    for (const CTxIn& tx_in : tx->vin) {
        // Iterate over all wallet transactions spending txin.prev
        // and recursively mark them as no longer conflicting with
        // txid
        for (auto range = mapTxSpends.equal_range(tx_in.prevout); range.first != range.second; range.first++) {
            const Txid& spent_id = range.first->second;

            RecursiveUpdateTxState(/*batch=*/nullptr, spent_id, [&txid](CWalletTx& wtx) EXCLUSIVE_LOCKS_REQUIRED(cs_wallet) {
                return wtx.mempool_conflicts.erase(txid) ? TxUpdate::CHANGED : TxUpdate::UNCHANGED;
            });
        }
    }
}

void CWallet::blockConnected(ChainstateRole role, const interfaces::BlockInfo& block)
{
    if (role == ChainstateRole::BACKGROUND) {
        return;
    }
    assert(block.data);
    LOCK(cs_wallet);

    m_last_block_processed_height = block.height;
    m_last_block_processed = block.hash;

    // No need to scan block if it was created before the wallet birthday.
    // Uses chain max time and twice the grace period to adjust time for block time variability.
    if (block.chain_time_max < m_birth_time.load() - (TIMESTAMP_WINDOW * 2)) return;

    // Scan block
    for (size_t index = 0; index < block.data->vtx.size(); index++) {
        SyncTransaction(block.data->vtx[index], TxStateConfirmed{block.hash, block.height, static_cast<int>(index)});
        transactionRemovedFromMempool(block.data->vtx[index], MemPoolRemovalReason::BLOCK);
    }

    RefreshAssetMetadataLocked();
}

void CWallet::blockDisconnected(const interfaces::BlockInfo& block)
{
    assert(block.data);
    LOCK(cs_wallet);

    // At block disconnection, this will change an abandoned transaction to
    // be unconfirmed, whether or not the transaction is added back to the mempool.
    // User may have to call abandontransaction again. It may be addressed in the
    // future with a stickier abandoned state or even removing abandontransaction call.
    m_last_block_processed_height = block.height - 1;
    m_last_block_processed = *Assert(block.prev_hash);

    int disconnect_height = block.height;

    for (size_t index = 0; index < block.data->vtx.size(); index++) {
        const CTransactionRef& ptx = block.data->vtx[index];
        // Coinbase transactions are not only inactive but also abandoned,
        // meaning they should never be relayed standalone via the p2p protocol.
        SyncTransaction(ptx, TxStateInactive{/*abandoned=*/index == 0});

        for (const CTxIn& tx_in : ptx->vin) {
            // No other wallet transactions conflicted with this transaction
            if (mapTxSpends.count(tx_in.prevout) < 1) continue;

            std::pair<TxSpends::const_iterator, TxSpends::const_iterator> range = mapTxSpends.equal_range(tx_in.prevout);

            // For all of the spends that conflict with this transaction
            for (TxSpends::const_iterator _it = range.first; _it != range.second; ++_it) {
                CWalletTx& wtx = mapWallet.find(_it->second)->second;

                if (!wtx.isBlockConflicted()) continue;

                auto try_updating_state = [&](CWalletTx& tx) {
                    if (!tx.isBlockConflicted()) return TxUpdate::UNCHANGED;
                    if (tx.state<TxStateBlockConflicted>()->conflicting_block_height >= disconnect_height) {
                        tx.m_state = TxStateInactive{};
                        return TxUpdate::CHANGED;
                    }
                    return TxUpdate::UNCHANGED;
                };

                RecursiveUpdateTxState(wtx.tx->GetHash(), try_updating_state);
            }
        }
    }

    RefreshAssetMetadataLocked();
}

void CWallet::updatedBlockTip()
{
    m_best_block_time = GetTime();
}

void CWallet::BlockUntilSyncedToCurrentChain() const {
    AssertLockNotHeld(cs_wallet);
    // Skip the queue-draining stuff if we know we're caught up with
    // chain().Tip(), otherwise put a callback in the validation interface queue and wait
    // for the queue to drain enough to execute it (indicating we are caught up
    // at least with the time we entered this function).
    uint256 last_block_hash = WITH_LOCK(cs_wallet, return m_last_block_processed);
    chain().waitForNotificationsIfTipChanged(last_block_hash);
}

// Note that this function doesn't distinguish between a 0-valued input,
// and a not-"is mine" (according to the filter) input.
CAmount CWallet::GetDebit(const CTxIn &txin, const isminefilter& filter) const
{
    {
        LOCK(cs_wallet);
        const auto mi = mapWallet.find(txin.prevout.hash);
        if (mi != mapWallet.end())
        {
            const CWalletTx& prev = (*mi).second;
            if (txin.prevout.n < prev.tx->vout.size())
                if (IsMine(prev.tx->vout[txin.prevout.n]) & filter)
                    return prev.tx->vout[txin.prevout.n].nValue;
        }
    }
    return 0;
}

isminetype CWallet::IsMine(const CTxOut& txout) const
{
    AssertLockHeld(cs_wallet);
    return IsMine(txout.scriptPubKey);
}

isminetype CWallet::IsMine(const CTxDestination& dest) const
{
    AssertLockHeld(cs_wallet);
    return IsMine(GetScriptForDestination(dest));
}

isminetype CWallet::IsMine(const CScript& script) const
{
    AssertLockHeld(cs_wallet);

    // Search the cache so that IsMine is called only on the relevant SPKMs instead of on everything in m_spk_managers
    const auto& it = m_cached_spks.find(script);
    if (it != m_cached_spks.end()) {
        isminetype res = ISMINE_NO;
        for (const auto& spkm : it->second) {
            res = std::max(res, spkm->IsMine(script));
        }
        Assume(res == ISMINE_SPENDABLE);
        return res;
    }

    return ISMINE_NO;
}

bool CWallet::IsMine(const CTransaction& tx) const
{
    AssertLockHeld(cs_wallet);
    for (const CTxOut& txout : tx.vout)
        if (IsMine(txout))
            return true;
    return false;
}

isminetype CWallet::IsMine(const COutPoint& outpoint) const
{
    AssertLockHeld(cs_wallet);
    auto wtx = GetWalletTx(outpoint.hash);
    if (!wtx) {
        return ISMINE_NO;
    }
    if (outpoint.n >= wtx->tx->vout.size()) {
        return ISMINE_NO;
    }
    return IsMine(wtx->tx->vout[outpoint.n]);
}

bool CWallet::IsFromMe(const CTransaction& tx) const
{
    return (GetDebit(tx, ISMINE_ALL) > 0);
}

CAmount CWallet::GetDebit(const CTransaction& tx, const isminefilter& filter) const
{
    CAmount nDebit = 0;
    for (const CTxIn& txin : tx.vin)
    {
        nDebit += GetDebit(txin, filter);
        if (!MoneyRange(nDebit))
            throw std::runtime_error(std::string(__func__) + ": value out of range");
    }
    return nDebit;
}

bool CWallet::IsHDEnabled() const
{
    // All Active ScriptPubKeyMans must be HD for this to be true
    bool result = false;
    for (const auto& spk_man : GetActiveScriptPubKeyMans()) {
        if (!spk_man->IsHDEnabled()) return false;
        result = true;
    }
    return result;
}

bool CWallet::CanGetAddresses(bool internal) const
{
    LOCK(cs_wallet);
    if (m_spk_managers.empty()) return false;
    for (OutputType t : OUTPUT_TYPES) {
        auto spk_man = GetScriptPubKeyMan(t, internal);
        if (spk_man && spk_man->CanGetAddresses(internal)) {
            return true;
        }
    }
    return false;
}

void CWallet::SetWalletFlag(uint64_t flags)
{
    WalletBatch batch(GetDatabase());
    return SetWalletFlagWithDB(batch, flags);
}

void CWallet::SetWalletFlagWithDB(WalletBatch& batch, uint64_t flags)
{
    LOCK(cs_wallet);
    m_wallet_flags |= flags;
    if (!batch.WriteWalletFlags(m_wallet_flags))
        throw std::runtime_error(std::string(__func__) + ": writing wallet flags failed");
}

void CWallet::UnsetWalletFlag(uint64_t flag)
{
    WalletBatch batch(GetDatabase());
    UnsetWalletFlagWithDB(batch, flag);
}

void CWallet::UnsetWalletFlagWithDB(WalletBatch& batch, uint64_t flag)
{
    LOCK(cs_wallet);
    m_wallet_flags &= ~flag;
    if (!batch.WriteWalletFlags(m_wallet_flags))
        throw std::runtime_error(std::string(__func__) + ": writing wallet flags failed");
}

void CWallet::UnsetBlankWalletFlag(WalletBatch& batch)
{
    UnsetWalletFlagWithDB(batch, WALLET_FLAG_BLANK_WALLET);
}

bool CWallet::IsWalletFlagSet(uint64_t flag) const
{
    return (m_wallet_flags & flag);
}

bool CWallet::LoadWalletFlags(uint64_t flags)
{
    LOCK(cs_wallet);
    if (((flags & KNOWN_WALLET_FLAGS) >> 32) ^ (flags >> 32)) {
        // contains unknown non-tolerable wallet flags
        return false;
    }
    m_wallet_flags = flags;

    return true;
}

void CWallet::InitWalletFlags(uint64_t flags)
{
    LOCK(cs_wallet);

    // We should never be writing unknown non-tolerable wallet flags
    assert(((flags & KNOWN_WALLET_FLAGS) >> 32) == (flags >> 32));
    // This should only be used once, when creating a new wallet - so current flags are expected to be blank
    assert(m_wallet_flags == 0);

    if (!WalletBatch(GetDatabase()).WriteWalletFlags(flags)) {
        throw std::runtime_error(std::string(__func__) + ": writing wallet flags failed");
    }

    if (!LoadWalletFlags(flags)) assert(false);
}

void CWallet::MaybeUpdateBirthTime(int64_t time)
{
    int64_t birthtime = m_birth_time.load();
    if (time < birthtime) {
        m_birth_time = time;
    }
}

/**
 * Scan active chain for relevant transactions after importing keys. This should
 * be called whenever new keys are added to the wallet, with the oldest key
 * creation time.
 *
 * @return Earliest timestamp that could be successfully scanned from. Timestamp
 * returned will be higher than startTime if relevant blocks could not be read.
 */
int64_t CWallet::RescanFromTime(int64_t startTime, const WalletRescanReserver& reserver, bool update)
{
    // Find starting block. May be null if nCreateTime is greater than the
    // highest blockchain timestamp, in which case there is nothing that needs
    // to be scanned.
    int start_height = 0;
    uint256 start_block;
    bool start = chain().findFirstBlockWithTimeAndHeight(startTime - TIMESTAMP_WINDOW, 0, FoundBlock().hash(start_block).height(start_height));
    WalletLogPrintf("%s: Rescanning last %i blocks\n", __func__, start ? WITH_LOCK(cs_wallet, return GetLastBlockHeight()) - start_height + 1 : 0);

    if (start) {
        // TODO: this should take into account failure by ScanResult::USER_ABORT
        ScanResult result = ScanForWalletTransactions(start_block, start_height, /*max_height=*/{}, reserver, /*fUpdate=*/update, /*save_progress=*/false);
        if (result.status == ScanResult::FAILURE) {
            int64_t time_max;
            CHECK_NONFATAL(chain().findBlock(result.last_failed_block, FoundBlock().maxTime(time_max)));
            return time_max + TIMESTAMP_WINDOW + 1;
        }
    }
    return startTime;
}

/**
 * Scan the block chain (starting in start_block) for transactions
 * from or to us. If fUpdate is true, found transactions that already
 * exist in the wallet will be updated. If max_height is not set, the
 * mempool will be scanned as well.
 *
 * @param[in] start_block Scan starting block. If block is not on the active
 *                        chain, the scan will return SUCCESS immediately.
 * @param[in] start_height Height of start_block
 * @param[in] max_height  Optional max scanning height. If unset there is
 *                        no maximum and scanning can continue to the tip
 *
 * @return ScanResult returning scan information and indicating success or
 *         failure. Return status will be set to SUCCESS if scan was
 *         successful. FAILURE if a complete rescan was not possible (due to
 *         pruning or corruption). USER_ABORT if the rescan was aborted before
 *         it could complete.
 *
 * @pre Caller needs to make sure start_block (and the optional stop_block) are on
 * the main chain after to the addition of any new keys you want to detect
 * transactions for.
 */
CWallet::ScanResult CWallet::ScanForWalletTransactions(const uint256& start_block, int start_height, std::optional<int> max_height, const WalletRescanReserver& reserver, bool fUpdate, const bool save_progress)
{
    constexpr auto INTERVAL_TIME{60s};
    auto current_time{reserver.now()};
    auto start_time{reserver.now()};

    assert(reserver.isReserved());

    uint256 block_hash = start_block;
    ScanResult result;

    std::unique_ptr<FastWalletRescanFilter> fast_rescan_filter;
    if (chain().hasBlockFilterIndex(BlockFilterType::BASIC)) fast_rescan_filter = std::make_unique<FastWalletRescanFilter>(*this);

    WalletLogPrintf("Rescan started from block %s... (%s)\n", start_block.ToString(),
                    fast_rescan_filter ? "fast variant using block filters" : "slow variant inspecting all blocks");

    fAbortRescan = false;
    ShowProgress(strprintf("%s %s", GetDisplayName(), _("Rescanning…")), 0); // show rescan progress in GUI as dialog or on splashscreen, if rescan required on startup (e.g. due to corruption)
    uint256 tip_hash = WITH_LOCK(cs_wallet, return GetLastBlockHash());
    uint256 end_hash = tip_hash;
    if (max_height) chain().findAncestorByHeight(tip_hash, *max_height, FoundBlock().hash(end_hash));
    double progress_begin = chain().guessVerificationProgress(block_hash);
    double progress_end = chain().guessVerificationProgress(end_hash);
    double progress_current = progress_begin;
    int block_height = start_height;
    while (!fAbortRescan && !chain().shutdownRequested()) {
        if (progress_end - progress_begin > 0.0) {
            m_scanning_progress = (progress_current - progress_begin) / (progress_end - progress_begin);
        } else { // avoid divide-by-zero for single block scan range (i.e. start and stop hashes are equal)
            m_scanning_progress = 0;
        }
        if (block_height % 100 == 0 && progress_end - progress_begin > 0.0) {
            ShowProgress(strprintf("%s %s", GetDisplayName(), _("Rescanning…")), std::max(1, std::min(99, (int)(m_scanning_progress * 100))));
        }

        bool next_interval = reserver.now() >= current_time + INTERVAL_TIME;
        if (next_interval) {
            current_time = reserver.now();
            WalletLogPrintf("Still rescanning. At block %d. Progress=%f\n", block_height, progress_current);
        }

        bool fetch_block{true};
        if (fast_rescan_filter) {
            fast_rescan_filter->UpdateIfNeeded();
            auto matches_block{fast_rescan_filter->MatchesBlock(block_hash)};
            if (matches_block.has_value()) {
                if (*matches_block) {
                    LogDebug(BCLog::SCAN, "Fast rescan: inspect block %d [%s] (filter matched)\n", block_height, block_hash.ToString());
                } else {
                    result.last_scanned_block = block_hash;
                    result.last_scanned_height = block_height;
                    fetch_block = false;
                }
            } else {
                LogDebug(BCLog::SCAN, "Fast rescan: inspect block %d [%s] (WARNING: block filter not found!)\n", block_height, block_hash.ToString());
            }
        }

        // Find next block separately from reading data above, because reading
        // is slow and there might be a reorg while it is read.
        bool block_still_active = false;
        bool next_block = false;
        uint256 next_block_hash;
        chain().findBlock(block_hash, FoundBlock().inActiveChain(block_still_active).nextBlock(FoundBlock().inActiveChain(next_block).hash(next_block_hash)));

        if (fetch_block) {
            // Read block data
            CBlock block;
            chain().findBlock(block_hash, FoundBlock().data(block));

            if (!block.IsNull()) {
                LOCK(cs_wallet);
                if (!block_still_active) {
                    // Abort scan if current block is no longer active, to prevent
                    // marking transactions as coming from the wrong block.
                    result.last_failed_block = block_hash;
                    result.status = ScanResult::FAILURE;
                    break;
                }
                for (size_t posInBlock = 0; posInBlock < block.vtx.size(); ++posInBlock) {
                    SyncTransaction(block.vtx[posInBlock], TxStateConfirmed{block_hash, block_height, static_cast<int>(posInBlock)}, fUpdate, /*rescanning_old_block=*/true);
                }
                // scan succeeded, record block as most recent successfully scanned
                result.last_scanned_block = block_hash;
                result.last_scanned_height = block_height;

                if (save_progress && next_interval) {
                    CBlockLocator loc = m_chain->getActiveChainLocator(block_hash);

                    if (!loc.IsNull()) {
                        WalletLogPrintf("Saving scan progress %d.\n", block_height);
                        WalletBatch batch(GetDatabase());
                        batch.WriteBestBlock(loc);
                    }
                }
            } else {
                // could not scan block, keep scanning but record this block as the most recent failure
                result.last_failed_block = block_hash;
                result.status = ScanResult::FAILURE;
            }
        }
        if (max_height && block_height >= *max_height) {
            break;
        }
        // If rescanning was triggered with cs_wallet permanently locked (AttachChain), additional blocks that were connected during the rescan
        // aren't processed here but will be processed with the pending blockConnected notifications after the lock is released.
        // If rescanning without a permanent cs_wallet lock, additional blocks that were added during the rescan will be re-processed if
        // the notification was processed and the last block height was updated.
        if (block_height >= WITH_LOCK(cs_wallet, return GetLastBlockHeight())) {
            break;
        }

        {
            if (!next_block) {
                // break successfully when rescan has reached the tip, or
                // previous block is no longer on the chain due to a reorg
                break;
            }

            // increment block and verification progress
            block_hash = next_block_hash;
            ++block_height;
            progress_current = chain().guessVerificationProgress(block_hash);

            // handle updated tip hash
            const uint256 prev_tip_hash = tip_hash;
            tip_hash = WITH_LOCK(cs_wallet, return GetLastBlockHash());
            if (!max_height && prev_tip_hash != tip_hash) {
                // in case the tip has changed, update progress max
                progress_end = chain().guessVerificationProgress(tip_hash);
            }
        }
    }
    if (!max_height) {
        WalletLogPrintf("Scanning current mempool transactions.\n");
        WITH_LOCK(cs_wallet, chain().requestMempoolTransactions(*this));
    }
    ShowProgress(strprintf("%s %s", GetDisplayName(), _("Rescanning…")), 100); // hide progress dialog in GUI
    if (block_height && fAbortRescan) {
        WalletLogPrintf("Rescan aborted at block %d. Progress=%f\n", block_height, progress_current);
        result.status = ScanResult::USER_ABORT;
    } else if (block_height && chain().shutdownRequested()) {
        WalletLogPrintf("Rescan interrupted by shutdown request at block %d. Progress=%f\n", block_height, progress_current);
        result.status = ScanResult::USER_ABORT;
    } else {
        WalletLogPrintf("Rescan completed in %15dms\n", Ticks<std::chrono::milliseconds>(reserver.now() - start_time));
    }
    return result;
}

bool CWallet::SubmitTxMemoryPoolAndRelay(CWalletTx& wtx, std::string& err_string, bool relay) const
{
    AssertLockHeld(cs_wallet);

    // Can't relay if wallet is not broadcasting
    if (!GetBroadcastTransactions()) return false;
    // Don't relay abandoned transactions
    if (wtx.isAbandoned()) return false;
    // Don't try to submit coinbase transactions. These would fail anyway but would
    // cause log spam.
    if (wtx.IsCoinBase()) return false;
    // Don't try to submit conflicted or confirmed transactions.
    if (GetTxDepthInMainChain(wtx) != 0) return false;

    // Submit transaction to mempool for relay
    WalletLogPrintf("Submitting wtx %s to mempool for relay\n", wtx.GetHash().ToString());
    // We must set TxStateInMempool here. Even though it will also be set later by the
    // entered-mempool callback, if we did not there would be a race where a
    // user could call sendmoney in a loop and hit spurious out of funds errors
    // because we think that this newly generated transaction's change is
    // unavailable as we're not yet aware that it is in the mempool.
    //
    // If broadcast fails for any reason, trying to set wtx.m_state here would be incorrect.
    // If transaction was previously in the mempool, it should be updated when
    // TransactionRemovedFromMempool fires.
    bool ret = chain().broadcastTransaction(wtx.tx, m_default_max_tx_fee, relay, err_string);
    if (ret) wtx.m_state = TxStateInMempool{};
    return ret;
}

std::set<Txid> CWallet::GetTxConflicts(const CWalletTx& wtx) const
{
    AssertLockHeld(cs_wallet);

    const Txid myHash{wtx.GetHash()};
    std::set<Txid> result{GetConflicts(myHash)};
    result.erase(myHash);
    return result;
}

bool CWallet::ShouldResend() const
{
    // Don't attempt to resubmit if the wallet is configured to not broadcast
    if (!fBroadcastTransactions) return false;

    // During reindex, importing and IBD, old wallet transactions become
    // unconfirmed. Don't resend them as that would spam other nodes.
    // We only allow forcing mempool submission when not relaying to avoid this spam.
    if (!chain().isReadyToBroadcast()) return false;

    // Do this infrequently and randomly to avoid giving away
    // that these are our transactions.
    if (NodeClock::now() < m_next_resend) return false;

    return true;
}

NodeClock::time_point CWallet::GetDefaultNextResend() { return FastRandomContext{}.rand_uniform_delay(NodeClock::now() + 12h, 24h); }

// Resubmit transactions from the wallet to the mempool, optionally asking the
// mempool to relay them. On startup, we will do this for all unconfirmed
// transactions but will not ask the mempool to relay them. We do this on startup
// to ensure that our own mempool is aware of our transactions. There
// is a privacy side effect here as not broadcasting on startup also means that we won't
// inform the world of our wallet's state, particularly if the wallet (or node) is not
// yet synced.
//
// Otherwise this function is called periodically in order to relay our unconfirmed txs.
// We do this on a random timer to slightly obfuscate which transactions
// come from our wallet.
//
// TODO: Ideally, we'd only resend transactions that we think should have been
// mined in the most recent block. Any transaction that wasn't in the top
// blockweight of transactions in the mempool shouldn't have been mined,
// and so is probably just sitting in the mempool waiting to be confirmed.
// Rebroadcasting does nothing to speed up confirmation and only damages
// privacy.
//
// The `force` option results in all unconfirmed transactions being submitted to
// the mempool. This does not necessarily result in those transactions being relayed,
// that depends on the `relay` option. Periodic rebroadcast uses the pattern
// relay=true force=false, while loading into the mempool
// (on start, or after import) uses relay=false force=true.
void CWallet::ResubmitWalletTransactions(bool relay, bool force)
{
    // Don't attempt to resubmit if the wallet is configured to not broadcast,
    // even if forcing.
    if (!fBroadcastTransactions) return;

    int submitted_tx_count = 0;

    { // cs_wallet scope
        LOCK(cs_wallet);

        // First filter for the transactions we want to rebroadcast.
        // We use a set with WalletTxOrderComparator so that rebroadcasting occurs in insertion order
        std::set<CWalletTx*, WalletTxOrderComparator> to_submit;
        for (auto& [txid, wtx] : mapWallet) {
            // Only rebroadcast unconfirmed txs
            if (!wtx.isUnconfirmed()) continue;

            // Attempt to rebroadcast all txes more than 5 minutes older than
            // the last block, or all txs if forcing.
            if (!force && wtx.nTimeReceived > m_best_block_time - 5 * 60) continue;
            to_submit.insert(&wtx);
        }
        // Now try submitting the transactions to the memory pool and (optionally) relay them.
        for (auto wtx : to_submit) {
            std::string unused_err_string;
            if (SubmitTxMemoryPoolAndRelay(*wtx, unused_err_string, relay)) ++submitted_tx_count;
        }
    } // cs_wallet

    if (submitted_tx_count > 0) {
        WalletLogPrintf("%s: resubmit %u unconfirmed transactions\n", __func__, submitted_tx_count);
    }
}

/** @} */ // end of mapWallet

void MaybeResendWalletTxs(WalletContext& context)
{
    for (const std::shared_ptr<CWallet>& pwallet : GetWallets(context)) {
        if (!pwallet->ShouldResend()) continue;
        pwallet->ResubmitWalletTransactions(/*relay=*/true, /*force=*/false);
        pwallet->SetNextResend();
    }
}


bool CWallet::SignTransaction(CMutableTransaction& tx) const
{
    AssertLockHeld(cs_wallet);

    // Build coins map
    std::map<COutPoint, Coin> coins;
    for (auto& input : tx.vin) {
        const auto mi = mapWallet.find(input.prevout.hash);
        if(mi == mapWallet.end() || input.prevout.n >= mi->second.tx->vout.size()) {
            return false;
        }
        const CWalletTx& wtx = mi->second;
        int prev_height = wtx.state<TxStateConfirmed>() ? wtx.state<TxStateConfirmed>()->confirmed_block_height : 0;
        coins[input.prevout] = Coin(wtx.tx->vout[input.prevout.n], prev_height, wtx.IsCoinBase());
    }
    std::map<int, bilingual_str> input_errors;
    return SignTransaction(tx, coins, SIGHASH_DEFAULT, input_errors);
}

bool CWallet::SignTransaction(CMutableTransaction& tx, const std::map<COutPoint, Coin>& coins, int sighash, std::map<int, bilingual_str>& input_errors) const
{
    // Check if any inputs are witness v2 (ML-DSA) - if so, use PSBT signing path
    bool has_mldsa_input = false;
    for (size_t i = 0; i < tx.vin.size() && !has_mldsa_input; ++i) {
        const auto& coin_it = coins.find(tx.vin[i].prevout);
        if (coin_it != coins.end()) {
            const CScript& scriptPubKey = coin_it->second.out.scriptPubKey;
            int version;
            std::vector<unsigned char> program;
            if (scriptPubKey.IsWitnessProgram(version, program) && version == 2) {
                has_mldsa_input = true;
            }
        }
    }

    // If we have ML-DSA inputs, convert to PSBT and use PSBT signing path
    if (has_mldsa_input) {
        PartiallySignedTransaction psbtx(tx);

        // Add UTXOs to PSBT
        for (size_t i = 0; i < tx.vin.size(); ++i) {
            const auto& coin_it = coins.find(tx.vin[i].prevout);
            if (coin_it != coins.end()) {
                psbtx.inputs[i].witness_utxo = coin_it->second.out;
            }
        }

        // Sign using PSBT infrastructure
        bool complete = false;
        const auto error = FillPSBT(psbtx, complete, sighash, /*sign=*/true, /*bip32derivs=*/false, /*n_signed=*/nullptr, /*finalize=*/true);
        if (error) {
            for (size_t i = 0; i < psbtx.inputs.size(); ++i) {
                if (!PSBTInputSignedAndVerified(psbtx, i, nullptr)) {
                    input_errors[i] = _("Failed to sign PSBT input");
                }
            }
            return false;
        }

        // Update transaction with signed data
        if (complete) {
            tx = CMutableTransaction(*psbtx.tx);
            for (size_t i = 0; i < tx.vin.size(); ++i) {
                if (!psbtx.inputs[i].final_script_sig.empty()) {
                    tx.vin[i].scriptSig = psbtx.inputs[i].final_script_sig;
                }
                if (!psbtx.inputs[i].final_script_witness.IsNull()) {
                    tx.vin[i].scriptWitness = psbtx.inputs[i].final_script_witness;
                }
            }
        }
        return complete;
    }

    // Try to sign with all ScriptPubKeyMans (non-ML-DSA inputs)
    for (ScriptPubKeyMan* spk_man : GetAllScriptPubKeyMans()) {
        // spk_man->SignTransaction will return true if the transaction is complete,
        // so we can exit early and return true if that happens
        if (spk_man->SignTransaction(tx, coins, sighash, input_errors)) {
            return true;
        }
    }

    // At this point, one input was not fully signed otherwise we would have exited already
    return false;
}

std::optional<PSBTError> CWallet::FillPSBT(PartiallySignedTransaction& psbtx, bool& complete, int sighash_type, bool sign, bool bip32derivs, size_t * n_signed, bool finalize) const
{
    if (n_signed) {
        *n_signed = 0;
    }
    LOCK(cs_wallet);
    // Get all of the previous transactions
    for (unsigned int i = 0; i < psbtx.tx->vin.size(); ++i) {
        const CTxIn& txin = psbtx.tx->vin[i];
        PSBTInput& input = psbtx.inputs.at(i);

        if (PSBTInputSigned(input)) {
            continue;
        }

        // If we have no utxo, grab it from the wallet.
        if (!input.non_witness_utxo) {
            const Txid& txhash = txin.prevout.hash;
            const auto it = mapWallet.find(txhash);
            if (it != mapWallet.end()) {
                const CWalletTx& wtx = it->second;
                // We only need the non_witness_utxo, which is a superset of the witness_utxo.
                //   The signing code will switch to the smaller witness_utxo if this is ok.
                input.non_witness_utxo = wtx.tx;
            }
        }
    }

    const PrecomputedTransactionData txdata = PrecomputePSBTData(psbtx);

    // Fill in information from ScriptPubKeyMans
    for (ScriptPubKeyMan* spk_man : GetAllScriptPubKeyMans()) {
        int n_signed_this_spkm = 0;
        const auto error{spk_man->FillPSBT(psbtx, txdata, sighash_type, sign, bip32derivs, &n_signed_this_spkm, finalize)};
        if (error) {
            return error;
        }

        if (n_signed) {
            (*n_signed) += n_signed_this_spkm;
        }
    }

    RemoveUnnecessaryTransactions(psbtx, sighash_type);

    // Complete if every input is now signed
    complete = true;
    for (size_t i = 0; i < psbtx.inputs.size(); ++i) {
        complete &= PSBTInputSignedAndVerified(psbtx, i, &txdata);
    }

    return {};
}

bool CWallet::SignMessageBIP322(const std::string& address, const std::string& message, std::string& signature_out, std::string& error_out) const
{
    AssertLockHeld(cs_wallet);

    signature_out.clear();
    error_out.clear();

    CTxDestination dest = DecodeDestination(address);
    if (!IsValidDestination(dest)) {
        error_out = strprintf("Invalid address: %s", address);
        return false;
    }

    const CScript script_pubkey = GetScriptForDestination(dest);

    // Construct the virtual to_spend transaction defined by BIP-322
    // BIP-322: Hash the raw message bytes, not serialized as varstring
    HashWriter ss{};
    ss.write(MakeByteSpan(message));
    const uint256 message_hash = ss.GetHash();

    CMutableTransaction to_spend;
    to_spend.version = 0;
    to_spend.nLockTime = 0;
    to_spend.vin.resize(1);
    to_spend.vin[0].prevout.SetNull();
    to_spend.vin[0].scriptSig = CScript() << OP_0 << ToByteVector(message_hash);
    to_spend.vin[0].nSequence = 0;
    to_spend.vout.resize(1);
    to_spend.vout[0].nValue = 0;
    to_spend.vout[0].scriptPubKey = script_pubkey;

    // Construct to_sign spending the virtual output
    CMutableTransaction to_sign;
    to_sign.version = 0;
    to_sign.nLockTime = 0;
    to_sign.vin.resize(1);
    to_sign.vin[0].prevout = COutPoint(to_spend.GetHash(), 0);
    to_sign.vin[0].scriptSig = CScript();
    to_sign.vin[0].nSequence = 0;
    to_sign.vout.resize(1);
    to_sign.vout[0].nValue = 0;
    to_sign.vout[0].scriptPubKey = CScript() << OP_RETURN;

    std::vector<std::vector<unsigned char>> solutions;
    const TxoutType script_type = Solver(script_pubkey, solutions);
    const bool is_witness = script_type == TxoutType::WITNESS_V0_KEYHASH ||
                            script_type == TxoutType::WITNESS_V0_SCRIPTHASH ||
                            script_type == TxoutType::WITNESS_V1_TAPROOT;
    const int sighash = script_type == TxoutType::WITNESS_V1_TAPROOT ? SIGHASH_DEFAULT : SIGHASH_ALL;

    PartiallySignedTransaction psbt(to_sign);
    psbt.inputs[0].sighash_type = sighash;
    psbt.inputs[0].witness_utxo = to_spend.vout[0];
    psbt.inputs[0].non_witness_utxo = MakeTransactionRef(CTransaction(to_spend));

    bool complete = false;
    if (const auto err = FillPSBT(psbt, complete, sighash, /*sign=*/true, /*bip32derivs=*/false, /*n_signed=*/nullptr, /*finalize=*/true)) {
        error_out = PSBTErrorString(*err).original;
        return false;
    }
    if (!complete) {
        error_out = "PSBT incomplete";
        return false;
    }

    CMutableTransaction signed_tx;
    if (!FinalizeAndExtractPSBT(psbt, signed_tx)) {
        error_out = "Failed to finalize PSBT";
        return false;
    }

    DataStream ss_sig{};
    if (is_witness) {
        const CScriptWitness& witness = signed_tx.vin[0].scriptWitness;
        ss_sig << witness.stack;
    } else {
        ss_sig << signed_tx.vin[0].scriptSig;
    }

    signature_out = EncodeBase64(MakeByteSpan(ss_sig));
    return true;
}

SigningResult CWallet::SignMessage(const std::string& message, const PKHash& pkhash, std::string& str_sig) const
{
    SignatureData sigdata;
    CScript script_pub_key = GetScriptForDestination(pkhash);
    for (const auto& spk_man_pair : m_spk_managers) {
        if (spk_man_pair.second->CanProvide(script_pub_key, sigdata)) {
            LOCK(cs_wallet);  // DescriptorScriptPubKeyMan calls IsLocked which can lock cs_wallet in a deadlocking order
            return spk_man_pair.second->SignMessage(message, pkhash, str_sig);
        }
    }
    return SigningResult::PRIVATE_KEY_NOT_AVAILABLE;
}

OutputType CWallet::TransactionChangeType(const std::optional<OutputType>& change_type, const std::vector<CRecipient>& vecSend) const
{
    // If -changetype is specified, always use that change type.
    if (change_type) {
        return *change_type;
    }

    // if m_default_address_type is legacy, use legacy address as change.
    if (m_default_address_type == OutputType::LEGACY) {
        return OutputType::LEGACY;
    }

    bool any_tr{false};
    bool any_wpkh{false};
    bool any_sh{false};
    bool any_pkh{false};

    for (const auto& recipient : vecSend) {
        if (std::get_if<WitnessV1Taproot>(&recipient.dest)) {
            any_tr = true;
        } else if (std::get_if<WitnessV0KeyHash>(&recipient.dest)) {
            any_wpkh = true;
        } else if (std::get_if<ScriptHash>(&recipient.dest)) {
            any_sh = true;
        } else if (std::get_if<PKHash>(&recipient.dest)) {
            any_pkh = true;
        }
    }

    const bool has_bech32m_spkman(GetScriptPubKeyMan(OutputType::BECH32M, /*internal=*/true));
    if (has_bech32m_spkman && any_tr) {
        // Currently tr is the only type supported by the BECH32M spkman
        return OutputType::BECH32M;
    }
    const bool has_bech32_spkman(GetScriptPubKeyMan(OutputType::BECH32, /*internal=*/true));
    if (has_bech32_spkman && any_wpkh) {
        // Currently wpkh is the only type supported by the BECH32 spkman
        return OutputType::BECH32;
    }
    const bool has_p2sh_segwit_spkman(GetScriptPubKeyMan(OutputType::P2SH_SEGWIT, /*internal=*/true));
    if (has_p2sh_segwit_spkman && any_sh) {
        // Currently sh_wpkh is the only type supported by the P2SH_SEGWIT spkman
        // As of 2021 about 80% of all SH are wrapping WPKH, so use that
        return OutputType::P2SH_SEGWIT;
    }
    const bool has_legacy_spkman(GetScriptPubKeyMan(OutputType::LEGACY, /*internal=*/true));
    if (has_legacy_spkman && any_pkh) {
        // Currently pkh is the only type supported by the LEGACY spkman
        return OutputType::LEGACY;
    }

    if (has_bech32m_spkman) {
        return OutputType::BECH32M;
    }
    if (has_bech32_spkman) {
        return OutputType::BECH32;
    }
    // else use m_default_address_type for change
    return m_default_address_type;
}

void CWallet::CommitTransaction(CTransactionRef tx, mapValue_t mapValue, std::vector<std::pair<std::string, std::string>> orderForm)
{
    LOCK(cs_wallet);
    WalletLogPrintf("CommitTransaction:\n%s\n", util::RemoveSuffixView(tx->ToString(), "\n"));

    // Add tx to wallet, because if it has change it's also ours,
    // otherwise just for transaction history.
    CWalletTx* wtx = AddToWallet(tx, TxStateInactive{}, [&](CWalletTx& wtx, bool new_tx) {
        CHECK_NONFATAL(wtx.mapValue.empty());
        CHECK_NONFATAL(wtx.vOrderForm.empty());
        wtx.mapValue = std::move(mapValue);
        wtx.vOrderForm = std::move(orderForm);
        wtx.fTimeReceivedIsTxTime = true;
        return true;
    });

    // wtx can only be null if the db write failed.
    if (!wtx) {
        throw std::runtime_error(std::string(__func__) + ": Wallet db error, transaction commit failed");
    }

    // Notify that old coins are spent
    for (const CTxIn& txin : tx->vin) {
        CWalletTx &coin = mapWallet.at(txin.prevout.hash);
        coin.MarkDirty();
        NotifyTransactionChanged(coin.GetHash(), CT_UPDATED);
    }

    if (!fBroadcastTransactions) {
        // Don't submit tx to the mempool
        return;
    }

    std::string err_string;
    if (!SubmitTxMemoryPoolAndRelay(*wtx, err_string, true)) {
        WalletLogPrintf("CommitTransaction(): Transaction cannot be broadcast immediately, %s\n", err_string);
        // TODO: if we expect the failure to be long term or permanent, instead delete wtx from the wallet and return failure.
    }
}

DBErrors CWallet::LoadWallet()
{
    LOCK(cs_wallet);

    Assert(m_spk_managers.empty());
    Assert(m_wallet_flags == 0);
    DBErrors nLoadWalletRet = WalletBatch(GetDatabase()).LoadWallet(this);
    if (nLoadWalletRet == DBErrors::NEED_REWRITE)
    {
        if (GetDatabase().Rewrite("\x04pool"))
        {
            for (const auto& spk_man_pair : m_spk_managers) {
                spk_man_pair.second->RewriteDB();
            }
        }
    }

    if (m_spk_managers.empty()) {
        assert(m_external_spk_managers.empty());
        assert(m_internal_spk_managers.empty());
    }

    // CRITICAL: Re-register forward vault scripts after wallet load
    // Vault registrations are in-memory only and lost on restart
    // We must rebuild them so the watcher can recognize vault spends
    if (nLoadWalletRet == DBErrors::LOAD_OK && !m_forward_contracts.empty()) {
        WalletLogPrintf("Re-registering forward vault scripts after wallet load (%zu contracts)...\n",
                       m_forward_contracts.size());
        size_t registered_count = 0;
        size_t skipped_count = 0;
        for (const auto& [contract_id, record] : m_forward_contracts) {
            if (!record.long_margin_internal_key || !record.short_margin_internal_key) {
                WalletLogPrintf("Forward[%s]: Skipping vault re-registration (missing internal keys)\n",
                              contract_id.GetHex());
                skipped_count++;
                continue;
            }
            try {
                // CacheForwardVaultScripts registers both LONG and SHORT vaults
                CacheForwardVaultScripts(*this, record);
                registered_count++;
                WalletLogPrintf("Forward[%s]: Re-registered vault scripts\n", contract_id.GetHex());
            } catch (const std::exception& e) {
                WalletLogPrintf("Forward[%s]: ERROR during vault re-registration: %s\n",
                              contract_id.GetHex(), e.what());
                skipped_count++;
            }
        }
        WalletLogPrintf("Vault re-registration complete: %zu registered, %zu skipped\n",
                       registered_count, skipped_count);
    }

    return nLoadWalletRet;
}

util::Result<void> CWallet::RemoveTxs(std::vector<Txid>& txs_to_remove)
{
    AssertLockHeld(cs_wallet);
    bilingual_str str_err;  // future: make RunWithinTxn return a util::Result
    bool was_txn_committed = RunWithinTxn(GetDatabase(), /*process_desc=*/"remove transactions", [&](WalletBatch& batch) EXCLUSIVE_LOCKS_REQUIRED(cs_wallet) {
        util::Result<void> result{RemoveTxs(batch, txs_to_remove)};
        if (!result) str_err = util::ErrorString(result);
        return result.has_value();
    });
    if (!str_err.empty()) return util::Error{str_err};
    if (!was_txn_committed) return util::Error{_("Error starting/committing db txn for wallet transactions removal process")};
    return {}; // all good
}

util::Result<void> CWallet::RemoveTxs(WalletBatch& batch, std::vector<Txid>& txs_to_remove)
{
    AssertLockHeld(cs_wallet);
    if (!batch.HasActiveTxn()) return util::Error{strprintf(_("The transactions removal process can only be executed within a db txn"))};

    // Check for transaction existence and remove entries from disk
    struct ErasedTxInfo {
        decltype(mapWallet)::const_iterator it;
        std::vector<COutPoint> asset_outpoints;
    };
    std::vector<ErasedTxInfo> erased_txs;
    bilingual_str str_err;
    for (const Txid& hash : txs_to_remove) {
        auto it_wtx = mapWallet.find(hash);
        if (it_wtx == mapWallet.end()) {
            return util::Error{strprintf(_("Transaction %s does not belong to this wallet"), hash.GetHex())};
        }
        std::vector<COutPoint> asset_outpoints;
        if (it_wtx->second.tx) {
            for (uint32_t n = 0; n < it_wtx->second.tx->vout.size(); ++n) {
                COutPoint outpoint{hash, n};
                if (m_asset_metadata.count(outpoint)) {
                    asset_outpoints.push_back(outpoint);
                    if (!batch.EraseAssetMetadata(outpoint)) {
                        return util::Error{strprintf(_("Failure removing asset metadata for %s:%u"), hash.GetHex(), n)};
                    }
                }
            }
        }
        if (!batch.EraseTx(hash)) {
            return util::Error{strprintf(_("Failure removing transaction: %s"), hash.GetHex())};
        }
        erased_txs.push_back(ErasedTxInfo{it_wtx, std::move(asset_outpoints)});
    }

    // Register callback to update the memory state only when the db txn is actually dumped to disk
    batch.RegisterTxnListener({.on_commit=[&, erased_txs]() EXCLUSIVE_LOCKS_REQUIRED(cs_wallet) {
        // Update the in-memory state and notify upper layers about the removals
        for (const auto& info : erased_txs) {
            const Txid hash{info.it->first};
            wtxOrdered.erase(info.it->second.m_it_wtxOrdered);
            for (const auto& txin : info.it->second.tx->vin)
                mapTxSpends.erase(txin.prevout);
            for (const auto& asset_out : info.asset_outpoints) {
                m_asset_metadata.erase(asset_out);
            }
            mapWallet.erase(info.it);
            NotifyTransactionChanged(hash, CT_DELETED);
        }

        MarkDirty();
    }, .on_abort={}});

    return {};
}

bool CWallet::SetAddressBookWithDB(WalletBatch& batch, const CTxDestination& address, const std::string& strName, const std::optional<AddressPurpose>& new_purpose)
{
    bool fUpdated = false;
    bool is_mine;
    std::optional<AddressPurpose> purpose;
    {
        LOCK(cs_wallet);
        std::map<CTxDestination, CAddressBookData>::iterator mi = m_address_book.find(address);
        fUpdated = mi != m_address_book.end() && !mi->second.IsChange();

        CAddressBookData& record = mi != m_address_book.end() ? mi->second : m_address_book[address];
        record.SetLabel(strName);
        is_mine = IsMine(address) != ISMINE_NO;
        if (new_purpose) { /* update purpose only if requested */
            record.purpose = new_purpose;
        }
        purpose = record.purpose;
    }

    const std::string& encoded_dest = EncodeDestination(address);
    if (new_purpose && !batch.WritePurpose(encoded_dest, PurposeToString(*new_purpose))) {
        WalletLogPrintf("Error: fail to write address book 'purpose' entry\n");
        return false;
    }
    if (!batch.WriteName(encoded_dest, strName)) {
        WalletLogPrintf("Error: fail to write address book 'name' entry\n");
        return false;
    }

    // In very old wallets, address purpose may not be recorded so we derive it from IsMine
    NotifyAddressBookChanged(address, strName, is_mine,
                             purpose.value_or(is_mine ? AddressPurpose::RECEIVE : AddressPurpose::SEND),
                             (fUpdated ? CT_UPDATED : CT_NEW));
    return true;
}

bool CWallet::SetAddressBook(const CTxDestination& address, const std::string& strName, const std::optional<AddressPurpose>& purpose)
{
    WalletBatch batch(GetDatabase());
    return SetAddressBookWithDB(batch, address, strName, purpose);
}

bool CWallet::DelAddressBook(const CTxDestination& address)
{
    return RunWithinTxn(GetDatabase(), /*process_desc=*/"address book entry removal", [&](WalletBatch& batch){
        return DelAddressBookWithDB(batch, address);
    });
}

bool CWallet::DelAddressBookWithDB(WalletBatch& batch, const CTxDestination& address)
{
    const std::string& dest = EncodeDestination(address);
    {
        LOCK(cs_wallet);
        // If we want to delete receiving addresses, we should avoid calling EraseAddressData because it will delete the previously_spent value. Could instead just erase the label so it becomes a change address, and keep the data.
        // NOTE: This isn't a problem for sending addresses because they don't have any data that needs to be kept.
        // When adding new address data, it should be considered here whether to retain or delete it.
        if (IsMine(address)) {
            WalletLogPrintf("%s called with IsMine address, NOT SUPPORTED. Please report this bug! %s\n", __func__, CLIENT_BUGREPORT);
            return false;
        }
        // Delete data rows associated with this address
        if (!batch.EraseAddressData(address)) {
            WalletLogPrintf("Error: cannot erase address book entry data\n");
            return false;
        }

        // Delete purpose entry
        if (!batch.ErasePurpose(dest)) {
            WalletLogPrintf("Error: cannot erase address book entry purpose\n");
            return false;
        }

        // Delete name entry
        if (!batch.EraseName(dest)) {
            WalletLogPrintf("Error: cannot erase address book entry name\n");
            return false;
        }

        // finally, remove it from the map
        m_address_book.erase(address);
    }

    // All good, signal changes
    NotifyAddressBookChanged(address, "", /*is_mine=*/false, AddressPurpose::SEND, CT_DELETED);
    return true;
}

size_t CWallet::KeypoolCountExternalKeys() const
{
    AssertLockHeld(cs_wallet);

    unsigned int count = 0;
    for (auto spk_man : m_external_spk_managers) {
        count += spk_man.second->GetKeyPoolSize();
    }

    return count;
}

unsigned int CWallet::GetKeyPoolSize() const
{
    AssertLockHeld(cs_wallet);

    unsigned int count = 0;
    for (auto spk_man : GetActiveScriptPubKeyMans()) {
        count += spk_man->GetKeyPoolSize();
    }
    return count;
}

bool CWallet::TopUpKeyPool(unsigned int kpSize)
{
    LOCK(cs_wallet);
    bool res = true;
    for (auto spk_man : GetActiveScriptPubKeyMans()) {
        res &= spk_man->TopUp(kpSize);
    }
    return res;
}

util::Result<CTxDestination> CWallet::GetNewDestination(const OutputType type, const std::string label)
{
    LOCK(cs_wallet);
    auto spk_man = GetScriptPubKeyMan(type, /*internal=*/false);
    if (!spk_man) {
        return util::Error{strprintf(_("Error: No %s addresses available."), FormatOutputType(type))};
    }

    auto op_dest = spk_man->GetNewDestination(type);
    if (op_dest) {
        SetAddressBook(*op_dest, label, AddressPurpose::RECEIVE);
    }

    return op_dest;
}

util::Result<CTxDestination> CWallet::GetNewChangeDestination(const OutputType type)
{
    LOCK(cs_wallet);

    ReserveDestination reservedest(this, type);
    auto op_dest = reservedest.GetReservedDestination(true);
    if (op_dest) reservedest.KeepDestination();

    return op_dest;
}

std::optional<int64_t> CWallet::GetOldestKeyPoolTime() const
{
    LOCK(cs_wallet);
    if (m_spk_managers.empty()) {
        return std::nullopt;
    }

    std::optional<int64_t> oldest_key{std::numeric_limits<int64_t>::max()};
    for (const auto& spk_man_pair : m_spk_managers) {
        oldest_key = std::min(oldest_key, spk_man_pair.second->GetOldestKeyPoolTime());
    }
    return oldest_key;
}

void CWallet::MarkDestinationsDirty(const std::set<CTxDestination>& destinations) {
    for (auto& entry : mapWallet) {
        CWalletTx& wtx = entry.second;
        if (wtx.m_is_cache_empty) continue;
        for (unsigned int i = 0; i < wtx.tx->vout.size(); i++) {
            CTxDestination dst;
            if (ExtractDestination(wtx.tx->vout[i].scriptPubKey, dst) && destinations.count(dst)) {
                wtx.MarkDirty();
                break;
            }
        }
    }
}

void CWallet::ForEachAddrBookEntry(const ListAddrBookFunc& func) const
{
    AssertLockHeld(cs_wallet);
    for (const std::pair<const CTxDestination, CAddressBookData>& item : m_address_book) {
        const auto& entry = item.second;
        func(item.first, entry.GetLabel(), entry.IsChange(), entry.purpose);
    }
}

std::vector<CTxDestination> CWallet::ListAddrBookAddresses(const std::optional<AddrBookFilter>& _filter) const
{
    AssertLockHeld(cs_wallet);
    std::vector<CTxDestination> result;
    AddrBookFilter filter = _filter ? *_filter : AddrBookFilter();
    ForEachAddrBookEntry([&result, &filter](const CTxDestination& dest, const std::string& label, bool is_change, const std::optional<AddressPurpose>& purpose) {
        // Filter by change
        if (filter.ignore_change && is_change) return;
        // Filter by label
        if (filter.m_op_label && *filter.m_op_label != label) return;
        // All good
        result.emplace_back(dest);
    });
    return result;
}

std::set<std::string> CWallet::ListAddrBookLabels(const std::optional<AddressPurpose> purpose) const
{
    AssertLockHeld(cs_wallet);
    std::set<std::string> label_set;
    ForEachAddrBookEntry([&](const CTxDestination& _dest, const std::string& _label,
                             bool _is_change, const std::optional<AddressPurpose>& _purpose) {
        if (_is_change) return;
        if (!purpose || purpose == _purpose) {
            label_set.insert(_label);
        }
    });
    return label_set;
}

util::Result<CTxDestination> ReserveDestination::GetReservedDestination(bool internal)
{
    m_spk_man = pwallet->GetScriptPubKeyMan(type, internal);
    if (!m_spk_man) {
        return util::Error{strprintf(_("Error: No %s addresses available."), FormatOutputType(type))};
    }

    if (nIndex == -1) {
        int64_t index;
        auto op_address = m_spk_man->GetReservedDestination(type, internal, index);
        if (!op_address) return op_address;
        nIndex = index;
        address = *op_address;
    }
    return address;
}

void ReserveDestination::KeepDestination()
{
    if (nIndex != -1) {
        m_spk_man->KeepDestination(nIndex, type);
    }
    nIndex = -1;
    address = CNoDestination();
}

void ReserveDestination::ReturnDestination()
{
    if (nIndex != -1) {
        m_spk_man->ReturnDestination(nIndex, fInternal, address);
    }
    nIndex = -1;
    address = CNoDestination();
}

util::Result<void> CWallet::DisplayAddress(const CTxDestination& dest)
{
    CScript scriptPubKey = GetScriptForDestination(dest);
    for (const auto& spk_man : GetScriptPubKeyMans(scriptPubKey)) {
        auto signer_spk_man = dynamic_cast<ExternalSignerScriptPubKeyMan *>(spk_man);
        if (signer_spk_man == nullptr) {
            continue;
        }
        ExternalSigner signer = ExternalSignerScriptPubKeyMan::GetExternalSigner();
        return signer_spk_man->DisplayAddress(dest, signer);
    }
    return util::Error{_("There is no ScriptPubKeyManager for this address")};
}

bool CWallet::LockCoin(const COutPoint& output, WalletBatch* batch)
{
    AssertLockHeld(cs_wallet);
    setLockedCoins.insert(output);
    if (batch) {
        return batch->WriteLockedUTXO(output);
    }
    return true;
}

bool CWallet::UnlockCoin(const COutPoint& output, WalletBatch* batch)
{
    AssertLockHeld(cs_wallet);
    bool was_locked = setLockedCoins.erase(output);
    if (batch && was_locked) {
        return batch->EraseLockedUTXO(output);
    }
    return true;
}

bool CWallet::UnlockAllCoins()
{
    AssertLockHeld(cs_wallet);
    bool success = true;
    WalletBatch batch(GetDatabase());
    for (auto it = setLockedCoins.begin(); it != setLockedCoins.end(); ++it) {
        success &= batch.EraseLockedUTXO(*it);
    }
    setLockedCoins.clear();
    return success;
}

bool CWallet::IsLockedCoin(const COutPoint& output) const
{
    AssertLockHeld(cs_wallet);
    return setLockedCoins.count(output) > 0;
}

bool CWallet::IsCovenantVault(const CScript& script, wallet::VaultRole& out_role) const
{
    AssertLockHeld(cs_wallet);
    // Only descriptor scriptpubkey managers support vaults
    for (const auto& spk_man_pair : m_spk_managers) {
        const auto& spk_man = spk_man_pair.second;
        auto desc_spk = dynamic_cast<DescriptorScriptPubKeyMan*>(spk_man.get());
        if (!desc_spk) continue;

        if (desc_spk->IsCovenantVault(script)) {
            auto meta = desc_spk->GetVaultMetadata(script);
            if (!meta) return false;
            out_role = meta->role;
            return true;
        }
    }
    return false;
}

bool CWallet::GetCovenantVaultMetadata(const CScript& script, wallet::VaultMetadata& out_meta) const
{
    AssertLockHeld(cs_wallet);
    // Only descriptor scriptpubkey managers support vaults
    for (const auto& spk_man_pair : m_spk_managers) {
        const auto& spk_man = spk_man_pair.second;
        auto desc_spk = dynamic_cast<DescriptorScriptPubKeyMan*>(spk_man.get());
        if (!desc_spk) continue;

        auto meta = desc_spk->GetVaultMetadata(script);
        if (meta) {
            out_meta = *meta;
            return true;
        }
    }
    return false;
}

void CWallet::ListLockedCoins(std::vector<COutPoint>& vOutpts) const
{
    AssertLockHeld(cs_wallet);
    for (std::set<COutPoint>::iterator it = setLockedCoins.begin();
         it != setLockedCoins.end(); it++) {
        COutPoint outpt = (*it);
        vOutpts.push_back(outpt);
    }
}

/**
 * Compute smart timestamp for a transaction being added to the wallet.
 *
 * Logic:
 * - If sending a transaction, assign its timestamp to the current time.
 * - If receiving a transaction outside a block, assign its timestamp to the
 *   current time.
 * - If receiving a transaction during a rescanning process, assign all its
 *   (not already known) transactions' timestamps to the block time.
 * - If receiving a block with a future timestamp, assign all its (not already
 *   known) transactions' timestamps to the current time.
 * - If receiving a block with a past timestamp, before the most recent known
 *   transaction (that we care about), assign all its (not already known)
 *   transactions' timestamps to the same timestamp as that most-recent-known
 *   transaction.
 * - If receiving a block with a past timestamp, but after the most recent known
 *   transaction, assign all its (not already known) transactions' timestamps to
 *   the block time.
 *
 * For more information see CWalletTx::nTimeSmart,
 * https://bitcointalk.org/?topic=54527, or
 * https://github.com/bitcoin/bitcoin/pull/1393.
 */
unsigned int CWallet::ComputeTimeSmart(const CWalletTx& wtx, bool rescanning_old_block) const
{
    std::optional<uint256> block_hash;
    if (auto* conf = wtx.state<TxStateConfirmed>()) {
        block_hash = conf->confirmed_block_hash;
    } else if (auto* conf = wtx.state<TxStateBlockConflicted>()) {
        block_hash = conf->conflicting_block_hash;
    }

    unsigned int nTimeSmart = wtx.nTimeReceived;
    if (block_hash) {
        int64_t blocktime;
        int64_t block_max_time;
        if (chain().findBlock(*block_hash, FoundBlock().time(blocktime).maxTime(block_max_time))) {
            if (rescanning_old_block) {
                nTimeSmart = block_max_time;
            } else {
                int64_t latestNow = wtx.nTimeReceived;
                int64_t latestEntry = 0;

                // Tolerate times up to the last timestamp in the wallet not more than 5 minutes into the future
                int64_t latestTolerated = latestNow + 300;
                const TxItems& txOrdered = wtxOrdered;
                for (auto it = txOrdered.rbegin(); it != txOrdered.rend(); ++it) {
                    CWalletTx* const pwtx = it->second;
                    if (pwtx == &wtx) {
                        continue;
                    }
                    int64_t nSmartTime;
                    nSmartTime = pwtx->nTimeSmart;
                    if (!nSmartTime) {
                        nSmartTime = pwtx->nTimeReceived;
                    }
                    if (nSmartTime <= latestTolerated) {
                        latestEntry = nSmartTime;
                        if (nSmartTime > latestNow) {
                            latestNow = nSmartTime;
                        }
                        break;
                    }
                }

                nTimeSmart = std::max(latestEntry, std::min(blocktime, latestNow));
            }
        } else {
            WalletLogPrintf("%s: found %s in block %s not in index\n", __func__, wtx.GetHash().ToString(), block_hash->ToString());
        }
    }
    return nTimeSmart;
}

bool CWallet::SetAddressPreviouslySpent(WalletBatch& batch, const CTxDestination& dest, bool used)
{
    if (std::get_if<CNoDestination>(&dest))
        return false;

    if (!used) {
        if (auto* data{common::FindKey(m_address_book, dest)}) data->previously_spent = false;
        return batch.WriteAddressPreviouslySpent(dest, false);
    }

    LoadAddressPreviouslySpent(dest);
    return batch.WriteAddressPreviouslySpent(dest, true);
}

void CWallet::LoadAddressPreviouslySpent(const CTxDestination& dest)
{
    m_address_book[dest].previously_spent = true;
}

void CWallet::LoadAddressReceiveRequest(const CTxDestination& dest, const std::string& id, const std::string& request)
{
    m_address_book[dest].receive_requests[id] = request;
}

void CWallet::SetAssetMetadata(const COutPoint& outpoint, const AssetMetadata& meta)
{
    AssertLockHeld(cs_wallet);
    m_asset_metadata[outpoint] = meta;
}

bool CWallet::SetAssetMetadataWithDB(WalletBatch& batch, const COutPoint& outpoint, const AssetMetadata& meta)
{
    AssertLockHeld(cs_wallet);
    SetAssetMetadata(outpoint, meta);
    return batch.WriteAssetMetadata(outpoint, meta);
}

void CWallet::EraseAssetMetadata(const COutPoint& outpoint)
{
    AssertLockHeld(cs_wallet);
    m_asset_metadata.erase(outpoint);
}

bool CWallet::EraseAssetMetadataWithDB(WalletBatch& batch, const COutPoint& outpoint)
{
    AssertLockHeld(cs_wallet);
    EraseAssetMetadata(outpoint);
    return batch.EraseAssetMetadata(outpoint);
}

std::optional<AssetMetadata> CWallet::GetAssetMetadata(const COutPoint& outpoint) const
{
    AssertLockHeld(cs_wallet);
    const auto it = m_asset_metadata.find(outpoint);
    if (it == m_asset_metadata.end()) return std::nullopt;
    return it->second;
}

void CWallet::RefreshAssetMetadataLocked()
{
    AssertLockHeld(cs_wallet);

    std::map<COutPoint, AssetMetadata> refreshed;

    for (const auto& [txid, wtx] : mapWallet) {
        if (!wtx.tx) continue;

        std::map<uint256, assets::IssuerReg> issuer_regs;
        for (const auto& txout : wtx.tx->vout) {
            if (auto reg = assets::ParseIssuerReg(txout.vExt)) {
                issuer_regs.emplace(reg->asset_id, *reg);
            }
        }

        for (unsigned int i = 0; i < wtx.tx->vout.size(); ++i) {
            const CTxOut& txout = wtx.tx->vout[i];
            if (IsMine(txout) == ISMINE_NO) continue;

            const COutPoint outpoint(txid, i);

            AssetMetadata meta;
            bool populated = false;

            if (auto tag = assets::ParseAssetTag(txout.vExt)) {
                meta.asset_id = tag->id;
                meta.is_issuer_credential = false;
                populated = true;

                auto it = issuer_regs.find(meta.asset_id);
                if (it != issuer_regs.end()) {
                    if (!it->second.ticker.empty()) {
                        meta.has_ticker = true;
                        meta.ticker = it->second.ticker;
                    }
                    if (it->second.decimals != 0xFF) {
                        meta.has_decimals = true;
                        meta.decimals = it->second.decimals;
                    }
                }
            } else if (auto reg = assets::ParseIssuerReg(txout.vExt)) {
                meta.asset_id = reg->asset_id;
                meta.is_issuer_credential = true;
                populated = true;
                if (!reg->ticker.empty()) {
                    meta.has_ticker = true;
                    meta.ticker = reg->ticker;
                }
                if (reg->decimals != 0xFF) {
                    meta.has_decimals = true;
                    meta.decimals = reg->decimals;
                }
            }

            if (!populated) continue;

            if (auto existing = m_asset_metadata.find(outpoint); existing != m_asset_metadata.end()) {
                if (!meta.has_ticker && existing->second.has_ticker) {
                    meta.has_ticker = true;
                    meta.ticker = existing->second.ticker;
                }
                if (!meta.has_decimals && existing->second.has_decimals) {
                    meta.has_decimals = true;
                    meta.decimals = existing->second.decimals;
                }
            }

            if (HaveChain()) {
                if (auto entry = chain().getAssetRegistryEntry(meta.asset_id)) {
                    if (!meta.has_ticker && !entry->ticker.empty()) {
                        meta.has_ticker = true;
                        meta.ticker = entry->ticker;
                    }
                    if (!meta.has_decimals && entry->decimals != std::numeric_limits<uint8_t>::max()) {
                        meta.has_decimals = true;
                        meta.decimals = entry->decimals;
                    }
                }
            }

            refreshed.emplace(outpoint, std::move(meta));
        }
    }

    std::vector<std::pair<COutPoint, AssetMetadata>> to_write;
    to_write.reserve(refreshed.size());
    for (const auto& [outpoint, meta] : refreshed) {
        auto it = m_asset_metadata.find(outpoint);
        if (it == m_asset_metadata.end() || !AssetMetadataEquals(it->second, meta)) {
            to_write.emplace_back(outpoint, meta);
        }
    }

    std::vector<COutPoint> to_erase;
    for (const auto& [outpoint, meta] : m_asset_metadata) {
        if (!refreshed.count(outpoint)) {
            to_erase.push_back(outpoint);
        }
    }

    if (to_write.empty() && to_erase.empty()) {
        return;
    }

    WalletBatch batch(GetDatabase());

    for (const auto& [outpoint, meta] : to_write) {
        SetAssetMetadata(outpoint, meta);
        if (!batch.WriteAssetMetadata(outpoint, meta)) {
            throw std::runtime_error("Failed to write asset metadata during RefreshAssetMetadataLocked");
        }
    }

    for (const auto& outpoint : to_erase) {
        EraseAssetMetadata(outpoint);
        if (!batch.EraseAssetMetadata(outpoint)) {
            throw std::runtime_error("Failed to erase asset metadata during RefreshAssetMetadataLocked");
        }
    }
}

void CWallet::LoadAssetDek(const uint256& asset_id, const std::string& dek)
{
    AssertLockHeld(cs_wallet);
    m_asset_deks[asset_id] = dek;
}

std::optional<std::string> CWallet::GetAssetDek(const uint256& asset_id) const
{
    AssertLockHeld(cs_wallet);
    const auto it = m_asset_deks.find(asset_id);
    if (it == m_asset_deks.end()) return std::nullopt;
    return it->second;
}

bool CWallet::SetAssetDekWithDB(WalletBatch& batch, const uint256& asset_id, const std::string& dek)
{
    AssertLockHeld(cs_wallet);
    m_asset_deks[asset_id] = dek;
    return batch.WriteAssetDek(asset_id, dek);
}

std::string CWallet::GetOrCreateAssetDek(const uint256& asset_id)
{
    AssertLockHeld(cs_wallet);
    auto it = m_asset_deks.find(asset_id);
    if (it != m_asset_deks.end()) return it->second;

    std::vector<unsigned char> raw(32);
    GetStrongRandBytes(raw);
    std::string encoded = EncodeBase64(raw);

    WalletBatch batch(GetDatabase());
    if (!SetAssetDekWithDB(batch, asset_id, encoded)) {
        throw std::runtime_error("Failed to persist ICU data encryption key");
    }
    return encoded;
}

bool CWallet::IsAddressPreviouslySpent(const CTxDestination& dest) const
{
    if (auto* data{common::FindKey(m_address_book, dest)}) return data->previously_spent;
    return false;
}

std::vector<std::string> CWallet::GetAddressReceiveRequests() const
{
    std::vector<std::string> values;
    for (const auto& [dest, entry] : m_address_book) {
        for (const auto& [id, request] : entry.receive_requests) {
            values.emplace_back(request);
        }
    }
    return values;
}

bool CWallet::SetAddressReceiveRequest(WalletBatch& batch, const CTxDestination& dest, const std::string& id, const std::string& value)
{
    if (!batch.WriteAddressReceiveRequest(dest, id, value)) return false;
    m_address_book[dest].receive_requests[id] = value;
    return true;
}

bool CWallet::EraseAddressReceiveRequest(WalletBatch& batch, const CTxDestination& dest, const std::string& id)
{
    if (!batch.EraseAddressReceiveRequest(dest, id)) return false;
    m_address_book[dest].receive_requests.erase(id);
    return true;
}

static util::Result<fs::path> GetWalletPath(const std::string& name)
{
    // Do some checking on wallet path. It should be either a:
    //
    // 1. Path where a directory can be created.
    // 2. Path to an existing directory.
    // 3. Path to a symlink to a directory.
    // 4. For backwards compatibility, the name of a data file in -walletdir.
    const fs::path wallet_path = fsbridge::AbsPathJoin(GetWalletDir(), fs::PathFromString(name));
    fs::file_type path_type = fs::symlink_status(wallet_path).type();
    if (!(path_type == fs::file_type::not_found || path_type == fs::file_type::directory ||
          (path_type == fs::file_type::symlink && fs::is_directory(wallet_path)) ||
          (path_type == fs::file_type::regular && fs::PathFromString(name).filename() == fs::PathFromString(name)))) {
        return util::Error{Untranslated(strprintf(
              "Invalid -wallet path '%s'. -wallet path should point to a directory where wallet.dat and "
              "database/log.?????????? files can be stored, a location where such a directory could be created, "
              "or (for backwards compatibility) the name of an existing data file in -walletdir (%s)",
              name, fs::quoted(fs::PathToString(GetWalletDir()))))};
    }
    return wallet_path;
}

std::unique_ptr<WalletDatabase> MakeWalletDatabase(const std::string& name, const DatabaseOptions& options, DatabaseStatus& status, bilingual_str& error_string)
{
    const auto& wallet_path = GetWalletPath(name);
    if (!wallet_path) {
        error_string = util::ErrorString(wallet_path);
        status = DatabaseStatus::FAILED_BAD_PATH;
        return nullptr;
    }
    return MakeDatabase(*wallet_path, options, status, error_string);
}

std::shared_ptr<CWallet> CWallet::Create(WalletContext& context, const std::string& name, std::unique_ptr<WalletDatabase> database, uint64_t wallet_creation_flags, bilingual_str& error, std::vector<bilingual_str>& warnings)
{
    interfaces::Chain* chain = context.chain;
    ArgsManager& args = *Assert(context.args);
    const std::string& walletFile = database->Filename();

    const auto start{SteadyClock::now()};
    // TODO: Can't use std::make_shared because we need a custom deleter but
    // should be possible to use std::allocate_shared.
    std::shared_ptr<CWallet> walletInstance(new CWallet(chain, name, std::move(database)), FlushAndDeleteWallet);
    walletInstance->m_keypool_size = std::max(args.GetIntArg("-keypool", DEFAULT_KEYPOOL_SIZE), int64_t{1});
    walletInstance->m_notify_tx_changed_script = args.GetArg("-walletnotify", "");

    // Load wallet
    bool rescan_required = false;
    DBErrors nLoadWalletRet = walletInstance->LoadWallet();
    if (nLoadWalletRet != DBErrors::LOAD_OK) {
        if (nLoadWalletRet == DBErrors::CORRUPT) {
            error = strprintf(_("Error loading %s: Wallet corrupted"), walletFile);
            return nullptr;
        }
        else if (nLoadWalletRet == DBErrors::NONCRITICAL_ERROR)
        {
            warnings.push_back(strprintf(_("Error reading %s! All keys read correctly, but transaction data"
                                           " or address metadata may be missing or incorrect."),
                walletFile));
        }
        else if (nLoadWalletRet == DBErrors::TOO_NEW) {
            error = strprintf(_("Error loading %s: Wallet requires newer version of %s"), walletFile, CLIENT_NAME);
            return nullptr;
        }
        else if (nLoadWalletRet == DBErrors::EXTERNAL_SIGNER_SUPPORT_REQUIRED) {
            error = strprintf(_("Error loading %s: External signer wallet being loaded without external signer support compiled"), walletFile);
            return nullptr;
        }
        else if (nLoadWalletRet == DBErrors::NEED_REWRITE)
        {
            error = strprintf(_("Wallet needed to be rewritten: restart %s to complete"), CLIENT_NAME);
            return nullptr;
        } else if (nLoadWalletRet == DBErrors::NEED_RESCAN) {
            warnings.push_back(strprintf(_("Error reading %s! Transaction data may be missing or incorrect."
                                           " Rescanning wallet."), walletFile));
            rescan_required = true;
        } else if (nLoadWalletRet == DBErrors::UNKNOWN_DESCRIPTOR) {
            error = strprintf(_("Unrecognized descriptor found. Loading wallet %s\n\n"
                                "The wallet might had been created on a newer version.\n"
                                "Please try running the latest software version.\n"), walletFile);
            return nullptr;
        } else if (nLoadWalletRet == DBErrors::UNEXPECTED_LEGACY_ENTRY) {
            error = strprintf(_("Unexpected legacy entry in descriptor wallet found. Loading wallet %s\n\n"
                                "The wallet might have been tampered with or created with malicious intent.\n"), walletFile);
            return nullptr;
        } else if (nLoadWalletRet == DBErrors::LEGACY_WALLET) {
            error = strprintf(_("Error loading %s: Wallet is a legacy wallet. Please migrate to a descriptor wallet using the migration tool (migratewallet RPC)."), walletFile);
            return nullptr;
        } else {
            error = strprintf(_("Error loading %s"), walletFile);
            return nullptr;
        }
    }

    // This wallet is in its first run if there are no ScriptPubKeyMans and it isn't blank or no privkeys
    const bool fFirstRun = walletInstance->m_spk_managers.empty() &&
                     !walletInstance->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS) &&
                     !walletInstance->IsWalletFlagSet(WALLET_FLAG_BLANK_WALLET);
    if (fFirstRun)
    {
        // ensure this wallet.dat can only be opened by clients supporting HD with chain split and expects no default key
        walletInstance->SetMinVersion(FEATURE_LATEST);

        walletInstance->InitWalletFlags(wallet_creation_flags);

        // Only descriptor wallets can be created
        assert(walletInstance->IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS));

        if ((wallet_creation_flags & WALLET_FLAG_EXTERNAL_SIGNER) || !(wallet_creation_flags & (WALLET_FLAG_DISABLE_PRIVATE_KEYS | WALLET_FLAG_BLANK_WALLET))) {
            LOCK(walletInstance->cs_wallet);
            if (walletInstance->IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS)) {
                walletInstance->SetupDescriptorScriptPubKeyMans();
                // SetupDescriptorScriptPubKeyMans already calls SetupGeneration for us so we don't need to call SetupGeneration separately
            } else {
                // Legacy wallets need SetupGeneration here.
                for (auto spk_man : walletInstance->GetActiveScriptPubKeyMans()) {
                    if (!spk_man->SetupGeneration()) {
                        error = _("Unable to generate initial keys");
                        return nullptr;
                    }
                }
            }
        }

        if (chain) {
            walletInstance->chainStateFlushed(ChainstateRole::NORMAL, chain->getTipLocator());
        }
    } else if (wallet_creation_flags & WALLET_FLAG_DISABLE_PRIVATE_KEYS) {
        // Make it impossible to disable private keys after creation
        error = strprintf(_("Error loading %s: Private keys can only be disabled during creation"), walletFile);
        return nullptr;
    } else if (walletInstance->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
        for (auto spk_man : walletInstance->GetActiveScriptPubKeyMans()) {
            if (spk_man->HavePrivateKeys()) {
                warnings.push_back(strprintf(_("Warning: Private keys detected in wallet {%s} with disabled private keys"), walletFile));
                break;
            }
        }
    }

    if (!args.GetArg("-addresstype", "").empty()) {
        std::optional<OutputType> parsed = ParseOutputType(args.GetArg("-addresstype", ""));
        if (!parsed) {
            error = strprintf(_("Unknown address type '%s'"), args.GetArg("-addresstype", ""));
            return nullptr;
        }
        walletInstance->m_default_address_type = parsed.value();
    }

    if (!args.GetArg("-changetype", "").empty()) {
        std::optional<OutputType> parsed = ParseOutputType(args.GetArg("-changetype", ""));
        if (!parsed) {
            error = strprintf(_("Unknown change type '%s'"), args.GetArg("-changetype", ""));
            return nullptr;
        }
        walletInstance->m_default_change_type = parsed.value();
    }

    if (const auto arg{args.GetArg("-mintxfee")}) {
        std::optional<CAmount> min_tx_fee = ParseMoney(*arg);
        if (!min_tx_fee) {
            error = AmountErrMsg("mintxfee", *arg);
            return nullptr;
        } else if (min_tx_fee.value() > HIGH_TX_FEE_PER_KB) {
            warnings.push_back(AmountHighWarn("-mintxfee") + Untranslated(" ") +
                               _("This is the minimum transaction fee you pay on every transaction."));
        }

        walletInstance->m_min_fee = CFeeRate{min_tx_fee.value()};
    }

    if (const auto arg{args.GetArg("-maxapsfee")}) {
        const std::string& max_aps_fee{*arg};
        if (max_aps_fee == "-1") {
            walletInstance->m_max_aps_fee = -1;
        } else if (std::optional<CAmount> max_fee = ParseMoney(max_aps_fee)) {
            if (max_fee.value() > HIGH_APS_FEE) {
                warnings.push_back(AmountHighWarn("-maxapsfee") + Untranslated(" ") +
                                  _("This is the maximum transaction fee you pay (in addition to the normal fee) to prioritize partial spend avoidance over regular coin selection."));
            }
            walletInstance->m_max_aps_fee = max_fee.value();
        } else {
            error = AmountErrMsg("maxapsfee", max_aps_fee);
            return nullptr;
        }
    }

    if (const auto arg{args.GetArg("-fallbackfee")}) {
        std::optional<CAmount> fallback_fee = ParseMoney(*arg);
        if (!fallback_fee) {
            error = strprintf(_("Invalid amount for %s=<amount>: '%s'"), "-fallbackfee", *arg);
            return nullptr;
        } else if (fallback_fee.value() > HIGH_TX_FEE_PER_KB) {
            warnings.push_back(AmountHighWarn("-fallbackfee") + Untranslated(" ") +
                               _("This is the transaction fee you may pay when fee estimates are not available."));
        }
        walletInstance->m_fallback_fee = CFeeRate{fallback_fee.value()};
    }

    // Disable fallback fee in case value was set to 0, enable if non-null value
    walletInstance->m_allow_fallback_fee = walletInstance->m_fallback_fee.GetFeePerK() != 0;

    if (const auto arg{args.GetArg("-discardfee")}) {
        std::optional<CAmount> discard_fee = ParseMoney(*arg);
        if (!discard_fee) {
            error = strprintf(_("Invalid amount for %s=<amount>: '%s'"), "-discardfee", *arg);
            return nullptr;
        } else if (discard_fee.value() > HIGH_TX_FEE_PER_KB) {
            warnings.push_back(AmountHighWarn("-discardfee") + Untranslated(" ") +
                               _("This is the transaction fee you may discard if change is smaller than dust at this level"));
        }
        walletInstance->m_discard_rate = CFeeRate{discard_fee.value()};
    }

    if (const auto arg{args.GetArg("-paytxfee")}) {
        warnings.push_back(_("-paytxfee is deprecated and will be fully removed in v31.0."));

        std::optional<CAmount> pay_tx_fee = ParseMoney(*arg);
        if (!pay_tx_fee) {
            error = AmountErrMsg("paytxfee", *arg);
            return nullptr;
        } else if (pay_tx_fee.value() > HIGH_TX_FEE_PER_KB) {
            warnings.push_back(AmountHighWarn("-paytxfee") + Untranslated(" ") +
                               _("This is the transaction fee you will pay if you send a transaction."));
        }

        walletInstance->m_pay_tx_fee = CFeeRate{pay_tx_fee.value(), 1000};

        if (chain && walletInstance->m_pay_tx_fee < chain->relayMinFee()) {
            error = strprintf(_("Invalid amount for %s=<amount>: '%s' (must be at least %s)"),
                "-paytxfee", *arg, chain->relayMinFee().ToString());
            return nullptr;
        }
    }

    if (const auto arg{args.GetArg("-maxtxfee")}) {
        std::optional<CAmount> max_fee = ParseMoney(*arg);
        if (!max_fee) {
            error = AmountErrMsg("maxtxfee", *arg);
            return nullptr;
        } else if (max_fee.value() > HIGH_MAX_TX_FEE) {
            warnings.push_back(strprintf(_("%s is set very high! Fees this large could be paid on a single transaction."), "-maxtxfee"));
        }

        if (chain && CFeeRate{max_fee.value(), 1000} < chain->relayMinFee()) {
            error = strprintf(_("Invalid amount for %s=<amount>: '%s' (must be at least the minrelay fee of %s to prevent stuck transactions)"),
                "-maxtxfee", *arg, chain->relayMinFee().ToString());
            return nullptr;
        }

        walletInstance->m_default_max_tx_fee = max_fee.value();
    }

    if (const auto arg{args.GetArg("-consolidatefeerate")}) {
        if (std::optional<CAmount> consolidate_feerate = ParseMoney(*arg)) {
            walletInstance->m_consolidate_feerate = CFeeRate(*consolidate_feerate);
        } else {
            error = AmountErrMsg("consolidatefeerate", *arg);
            return nullptr;
        }
    }

    if (chain && chain->relayMinFee().GetFeePerK() > HIGH_TX_FEE_PER_KB) {
        warnings.push_back(AmountHighWarn("-minrelaytxfee") + Untranslated(" ") +
                           _("The wallet will avoid paying less than the minimum relay fee."));
    }

    walletInstance->m_confirm_target = args.GetIntArg("-txconfirmtarget", DEFAULT_TX_CONFIRM_TARGET);
    walletInstance->m_spend_zero_conf_change = args.GetBoolArg("-spendzeroconfchange", DEFAULT_SPEND_ZEROCONF_CHANGE);
    walletInstance->m_signal_rbf = args.GetBoolArg("-walletrbf", DEFAULT_WALLET_RBF);

    walletInstance->WalletLogPrintf("Wallet completed loading in %15dms\n", Ticks<std::chrono::milliseconds>(SteadyClock::now() - start));

    // Try to top up keypool. No-op if the wallet is locked.
    walletInstance->TopUpKeyPool();

    // Cache the first key time
    std::optional<int64_t> time_first_key;
    for (auto spk_man : walletInstance->GetAllScriptPubKeyMans()) {
        int64_t time = spk_man->GetTimeFirstKey();
        if (!time_first_key || time < *time_first_key) time_first_key = time;
    }
    if (time_first_key) walletInstance->MaybeUpdateBirthTime(*time_first_key);

    if (chain && !AttachChain(walletInstance, *chain, rescan_required, error, warnings)) {
        walletInstance->m_chain_notifications_handler.reset(); // Reset this pointer so that the wallet will actually be unloaded
        return nullptr;
    }

    {
        LOCK(walletInstance->cs_wallet);
        walletInstance->SetBroadcastTransactions(args.GetBoolArg("-walletbroadcast", DEFAULT_WALLETBROADCAST));
        walletInstance->WalletLogPrintf("setKeyPool.size() = %u\n",      walletInstance->GetKeyPoolSize());
        walletInstance->WalletLogPrintf("mapWallet.size() = %u\n",       walletInstance->mapWallet.size());
        walletInstance->WalletLogPrintf("m_address_book.size() = %u\n",  walletInstance->m_address_book.size());
    }

    return walletInstance;
}

bool CWallet::AttachChain(const std::shared_ptr<CWallet>& walletInstance, interfaces::Chain& chain, const bool rescan_required, bilingual_str& error, std::vector<bilingual_str>& warnings)
{
    LOCK(walletInstance->cs_wallet);
    // allow setting the chain if it hasn't been set already but prevent changing it
    assert(!walletInstance->m_chain || walletInstance->m_chain == &chain);
    walletInstance->m_chain = &chain;

    // Unless allowed, ensure wallet files are not reused across chains:
    if (!gArgs.GetBoolArg("-walletcrosschain", DEFAULT_WALLETCROSSCHAIN)) {
        WalletBatch batch(walletInstance->GetDatabase());
        CBlockLocator locator;
        if (batch.ReadBestBlock(locator) && locator.vHave.size() > 0 && chain.getHeight()) {
            // Wallet is assumed to be from another chain, if genesis block in the active
            // chain differs from the genesis block known to the wallet.
            if (chain.getBlockHash(0) != locator.vHave.back()) {
                error = Untranslated("Wallet files should not be reused across chains. Restart bitcoind with -walletcrosschain to override.");
                return false;
            }
        }
    }

    // Register wallet with validationinterface. It's done before rescan to avoid
    // missing block connections during the rescan.
    // Because of the wallet lock being held, block connection notifications are going to
    // be pending on the validation-side until lock release. Blocks that are connected while the
    // rescan is ongoing will not be processed in the rescan but with the block connected notifications,
    // so the wallet will only be completeley synced after the notifications delivery.
    // chainStateFlushed notifications are ignored until the rescan is finished
    // so that in case of a shutdown event, the rescan will be repeated at the next start.
    // This is temporary until rescan and notifications delivery are unified under same
    // interface.
    walletInstance->m_attaching_chain = true; //ignores chainStateFlushed notifications
    walletInstance->m_chain_notifications_handler = walletInstance->chain().handleNotifications(walletInstance);

    // If rescan_required = true, rescan_height remains equal to 0
    int rescan_height = 0;
    if (!rescan_required)
    {
        WalletBatch batch(walletInstance->GetDatabase());
        CBlockLocator locator;
        if (batch.ReadBestBlock(locator)) {
            if (const std::optional<int> fork_height = chain.findLocatorFork(locator)) {
                rescan_height = *fork_height;
            }
        }
    }

    const std::optional<int> tip_height = chain.getHeight();
    if (tip_height) {
        walletInstance->m_last_block_processed = chain.getBlockHash(*tip_height);
        walletInstance->m_last_block_processed_height = *tip_height;
    } else {
        walletInstance->m_last_block_processed.SetNull();
        walletInstance->m_last_block_processed_height = -1;
    }

    if (tip_height && *tip_height != rescan_height)
    {
        // No need to read and scan block if block was created before
        // our wallet birthday (as adjusted for block time variability)
        std::optional<int64_t> time_first_key = walletInstance->m_birth_time.load();
        if (time_first_key) {
            FoundBlock found = FoundBlock().height(rescan_height);
            chain.findFirstBlockWithTimeAndHeight(*time_first_key - TIMESTAMP_WINDOW, rescan_height, found);
            if (!found.found) {
                // We were unable to find a block that had a time more recent than our earliest timestamp
                // or a height higher than the wallet was synced to, indicating that the wallet is newer than the
                // current chain tip. Skip rescanning in this case.
                rescan_height = *tip_height;
            }
        }

        // Technically we could execute the code below in any case, but performing the
        // `while` loop below can make startup very slow, so only check blocks on disk
        // if necessary.
        if (chain.havePruned() || chain.hasAssumedValidChain()) {
            int block_height = *tip_height;
            while (block_height > 0 && chain.haveBlockOnDisk(block_height - 1) && rescan_height != block_height) {
                --block_height;
            }

            if (rescan_height != block_height) {
                // We can't rescan beyond blocks we don't have data for, stop and throw an error.
                // This might happen if a user uses an old wallet within a pruned node
                // or if they ran -disablewallet for a longer time, then decided to re-enable
                // Exit early and print an error.
                // It also may happen if an assumed-valid chain is in use and therefore not
                // all block data is available.
                // If a block is pruned after this check, we will load the wallet,
                // but fail the rescan with a generic error.

                error = chain.havePruned() ?
                     _("Prune: last wallet synchronisation goes beyond pruned data. You need to -reindex (download the whole blockchain again in case of pruned node)") :
                     strprintf(_(
                        "Error loading wallet. Wallet requires blocks to be downloaded, "
                        "and software does not currently support loading wallets while "
                        "blocks are being downloaded out of order when using assumeutxo "
                        "snapshots. Wallet should be able to load successfully after "
                        "node sync reaches height %s"), block_height);
                return false;
            }
        }

        chain.initMessage(_("Rescanning…"));
        walletInstance->WalletLogPrintf("Rescanning last %i blocks (from block %i)...\n", *tip_height - rescan_height, rescan_height);

        {
            WalletRescanReserver reserver(*walletInstance);
            if (!reserver.reserve() || (ScanResult::SUCCESS != walletInstance->ScanForWalletTransactions(chain.getBlockHash(rescan_height), rescan_height, /*max_height=*/{}, reserver, /*fUpdate=*/true, /*save_progress=*/true).status)) {
                error = _("Failed to rescan the wallet during initialization");
                return false;
            }
        }
        walletInstance->m_attaching_chain = false;
        walletInstance->chainStateFlushed(ChainstateRole::NORMAL, chain.getTipLocator());
    }
    walletInstance->m_attaching_chain = false;

    return true;
}

const CAddressBookData* CWallet::FindAddressBookEntry(const CTxDestination& dest, bool allow_change) const
{
    const auto& address_book_it = m_address_book.find(dest);
    if (address_book_it == m_address_book.end()) return nullptr;
    if ((!allow_change) && address_book_it->second.IsChange()) {
        return nullptr;
    }
    return &address_book_it->second;
}

bool CWallet::UpgradeWallet(int version, bilingual_str& error)
{
    int prev_version = GetVersion();
    if (version == 0) {
        WalletLogPrintf("Performing wallet upgrade to %i\n", FEATURE_LATEST);
        version = FEATURE_LATEST;
    } else {
        WalletLogPrintf("Allowing wallet upgrade up to %i\n", version);
    }
    if (version < prev_version) {
        error = strprintf(_("Cannot downgrade wallet from version %i to version %i. Wallet version unchanged."), prev_version, version);
        return false;
    }

    LOCK(cs_wallet);

    // Do not upgrade versions to any version between HD_SPLIT and FEATURE_PRE_SPLIT_KEYPOOL unless already supporting HD_SPLIT
    if (!CanSupportFeature(FEATURE_HD_SPLIT) && version >= FEATURE_HD_SPLIT && version < FEATURE_PRE_SPLIT_KEYPOOL) {
        error = strprintf(_("Cannot upgrade a non HD split wallet from version %i to version %i without upgrading to support pre-split keypool. Please use version %i or no version specified."), prev_version, version, FEATURE_PRE_SPLIT_KEYPOOL);
        return false;
    }

    // Permanently upgrade to the version
    SetMinVersion(GetClosestWalletFeature(version));

    for (auto spk_man : GetActiveScriptPubKeyMans()) {
        if (!spk_man->Upgrade(prev_version, version, error)) {
            return false;
        }
    }
    return true;
}

void CWallet::postInitProcess()
{
    // Add wallet transactions that aren't already in a block to mempool
    // Do this here as mempool requires genesis block to be loaded
    ResubmitWalletTransactions(/*relay=*/false, /*force=*/true);

    // Update wallet transactions with current mempool transactions.
    WITH_LOCK(cs_wallet, chain().requestMempoolTransactions(*this));
}

bool CWallet::BackupWallet(const std::string& strDest) const
{
    if (m_chain) {
        CBlockLocator loc;
        WITH_LOCK(cs_wallet, chain().findBlock(m_last_block_processed, FoundBlock().locator(loc)));
        if (!loc.IsNull()) {
            WalletBatch batch(GetDatabase());
            batch.WriteBestBlock(loc);
        }
    }
    return GetDatabase().Backup(strDest);
}

int CWallet::GetTxDepthInMainChain(const CWalletTx& wtx) const
{
    AssertLockHeld(cs_wallet);
    if (auto* conf = wtx.state<TxStateConfirmed>()) {
        assert(conf->confirmed_block_height >= 0);
        return GetLastBlockHeight() - conf->confirmed_block_height + 1;
    } else if (auto* conf = wtx.state<TxStateBlockConflicted>()) {
        assert(conf->conflicting_block_height >= 0);
        return -1 * (GetLastBlockHeight() - conf->conflicting_block_height + 1);
    } else {
        return 0;
    }
}

int CWallet::GetTxBlocksToMaturity(const CWalletTx& wtx) const
{
    AssertLockHeld(cs_wallet);

    if (!wtx.IsCoinBase()) {
        return 0;
    }
    int chain_depth = GetTxDepthInMainChain(wtx);
    assert(chain_depth >= 0); // coinbase tx should not be conflicted
    return std::max(0, (COINBASE_MATURITY+1) - chain_depth);
}

bool CWallet::IsTxImmatureCoinBase(const CWalletTx& wtx) const
{
    AssertLockHeld(cs_wallet);

    // note GetBlocksToMaturity is 0 for non-coinbase tx
    return GetTxBlocksToMaturity(wtx) > 0;
}

bool CWallet::IsCrypted() const
{
    return HasEncryptionKeys();
}

bool CWallet::IsLocked() const
{
    if (!IsCrypted()) {
        return false;
    }
    LOCK(cs_wallet);
    return vMasterKey.empty();
}

bool CWallet::Lock()
{
    if (!IsCrypted())
        return false;

    {
        LOCK2(m_relock_mutex, cs_wallet);
        if (!vMasterKey.empty()) {
            memory_cleanse(vMasterKey.data(), vMasterKey.size() * sizeof(decltype(vMasterKey)::value_type));
            vMasterKey.clear();
        }
    }

    NotifyStatusChanged(this);
    return true;
}

bool CWallet::Unlock(const CKeyingMaterial& vMasterKeyIn)
{
    {
        LOCK(cs_wallet);
        for (const auto& spk_man_pair : m_spk_managers) {
            if (!spk_man_pair.second->CheckDecryptionKey(vMasterKeyIn)) {
                return false;
            }
        }
        vMasterKey = vMasterKeyIn;
    }
    NotifyStatusChanged(this);
    return true;
}

std::set<ScriptPubKeyMan*> CWallet::GetActiveScriptPubKeyMans() const
{
    std::set<ScriptPubKeyMan*> spk_mans;
    for (bool internal : {false, true}) {
        for (OutputType t : OUTPUT_TYPES) {
            auto spk_man = GetScriptPubKeyMan(t, internal);
            if (spk_man) {
                spk_mans.insert(spk_man);
            }
        }
    }
    return spk_mans;
}

bool CWallet::IsActiveScriptPubKeyMan(const ScriptPubKeyMan& spkm) const
{
    for (const auto& [_, ext_spkm] : m_external_spk_managers) {
        if (ext_spkm == &spkm) return true;
    }
    for (const auto& [_, int_spkm] : m_internal_spk_managers) {
        if (int_spkm == &spkm) return true;
    }
    return false;
}

std::set<ScriptPubKeyMan*> CWallet::GetAllScriptPubKeyMans() const
{
    std::set<ScriptPubKeyMan*> spk_mans;
    for (const auto& spk_man_pair : m_spk_managers) {
        spk_mans.insert(spk_man_pair.second.get());
    }
    return spk_mans;
}

ScriptPubKeyMan* CWallet::GetScriptPubKeyMan(const OutputType& type, bool internal) const
{
    const std::map<OutputType, ScriptPubKeyMan*>& spk_managers = internal ? m_internal_spk_managers : m_external_spk_managers;
    std::map<OutputType, ScriptPubKeyMan*>::const_iterator it = spk_managers.find(type);
    if (it == spk_managers.end()) {
        return nullptr;
    }
    return it->second;
}

std::set<ScriptPubKeyMan*> CWallet::GetScriptPubKeyMans(const CScript& script) const
{
    std::set<ScriptPubKeyMan*> spk_mans;

    // Search the cache for relevant SPKMs instead of iterating m_spk_managers
    const auto& it = m_cached_spks.find(script);
    if (it != m_cached_spks.end()) {
        spk_mans.insert(it->second.begin(), it->second.end());
    }
    SignatureData sigdata;
    Assume(std::all_of(spk_mans.begin(), spk_mans.end(), [&script, &sigdata](ScriptPubKeyMan* spkm) { return spkm->CanProvide(script, sigdata); }));

    return spk_mans;
}

ScriptPubKeyMan* CWallet::GetScriptPubKeyMan(const uint256& id) const
{
    if (m_spk_managers.count(id) > 0) {
        return m_spk_managers.at(id).get();
    }
    return nullptr;
}

bool CWallet::LoadRepoOffer(const RepoOfferRecord& record)
{
    AssertLockHeld(cs_wallet);
    m_repo_offers[record.offer_id] = record;
    return true;
}

bool CWallet::LoadSpotOffer(const SpotOfferRecord& record)
{
    AssertLockHeld(cs_wallet);
    m_spot_offers[record.offer_id] = record;
    return true;
}

RepoOfferRecord CWallet::RegisterRepoOffer(RepoOfferRecord record)
{
    LOCK(cs_wallet);
    auto [it, inserted] = m_repo_offers.insert_or_assign(record.offer_id, record);
    RepoOfferRecord& stored = it->second;

    WalletBatch batch(GetDatabase());
    if (!batch.WriteRepoOffer(stored)) {
        WalletLogPrintf("Warning: failed to write repo offer %s to database\n", stored.offer_id.GetHex());
    }

    return stored;
}

SpotOfferRecord CWallet::RegisterSpotOffer(SpotOfferRecord record)
{
    LOCK(cs_wallet);
    auto [it, inserted] = m_spot_offers.insert_or_assign(record.offer_id, record);
    SpotOfferRecord& stored = it->second;

    WalletBatch batch(GetDatabase());
    if (!batch.WriteSpotOffer(stored)) {
        WalletLogPrintf("Warning: failed to write spot offer %s to database\n", stored.offer_id.GetHex());
    }

    return stored;
}

std::optional<RepoOfferRecord> CWallet::FindRepoOffer(const uint256& offer_id) const
{
    LOCK(cs_wallet);
    auto it = m_repo_offers.find(offer_id);
    if (it == m_repo_offers.end()) {
        return std::nullopt;
    }
    return it->second;
}

std::optional<SpotOfferRecord> CWallet::FindSpotOffer(const uint256& offer_id) const
{
    LOCK(cs_wallet);
    auto it = m_spot_offers.find(offer_id);
    if (it == m_spot_offers.end()) {
        return std::nullopt;
    }
    return it->second;
}

std::vector<RepoOfferRecord> CWallet::ListRepoOffers() const
{
    LOCK(cs_wallet);
    std::vector<RepoOfferRecord> out;
    out.reserve(m_repo_offers.size());
    for (const auto& entry : m_repo_offers) {
        out.push_back(entry.second);
    }
    return out;
}

std::vector<SpotOfferRecord> CWallet::ListSpotOffers() const
{
    LOCK(cs_wallet);
    std::vector<SpotOfferRecord> out;
    out.reserve(m_spot_offers.size());
    for (const auto& entry : m_spot_offers) {
        out.push_back(entry.second);
    }
    return out;
}

namespace {

void ZeroizeFairSignInputState(FairSignInputState& state)
{
    // Cleanse ephemeral MuSig state (contains nonces and session)
    if (state.musig_state) {
        memory_cleanse(state.musig_state.get(), sizeof(MuSigEphemeralState));
        state.musig_state.reset();
    }
    memory_cleanse(state.pre_sig.data(), state.pre_sig.size());
    memory_cleanse(state.message_digest.data(), state.message_digest.size());
    if (state.adaptor_secret) {
        memory_cleanse(state.adaptor_secret->data(), state.adaptor_secret->size());
        state.adaptor_secret.reset();
    }
    state.has_partial = false;
    state.tapleaf_hash.reset();
    state.tapleaf_script.clear();
    state.tapleaf_control_block.clear();
    state.has_tapleaf_witness = false;
    state.tapleaf_signers.clear();
    state.tapleaf_signer_slot = -1;
    state.vault_intent_purpose.reset();
    if (state.has_keyagg_cache) {
        memory_cleanse(&state.keyagg_cache, sizeof(state.keyagg_cache));
        state.has_keyagg_cache = false;
    }
    state.musig_local_index = -1;
    state.musig_total_signers = 0;
}

} // namespace

RepoOfferRecord CWallet::RegisterRepoAcceptance(const uint256& offer_id,
                                                RepoAcceptanceRecord acceptance)
{
    LOCK(cs_wallet);
    auto it = m_repo_offers.find(offer_id);
    if (it == m_repo_offers.end()) {
        throw std::runtime_error("Unknown repo offer id");
    }

    RepoOfferRecord& stored = it->second;

    if (stored.acceptance) {
        if (stored.acceptance->commitment_hex != acceptance.commitment_hex) {
            throw std::runtime_error("Acceptance commitment mismatch");
        }
        // Preserve existing local secrets if the new record lacks them.
        if (!acceptance.local_fs_tx_adaptor_secret && stored.acceptance->local_fs_tx_adaptor_secret) {
            acceptance.local_fs_tx_adaptor_secret = stored.acceptance->local_fs_tx_adaptor_secret;
        }
    }

    stored.acceptance = acceptance;
    if (stored.acceptance->repay_dest_ack != stored.lender_dest) {
        stored.lender_dest_override = stored.acceptance->repay_dest_ack;
    }

    WalletBatch batch(GetDatabase());
    if (!batch.WriteRepoOffer(stored)) {
        WalletLogPrintf("Warning: failed to persist acceptance for repo offer %s\n", offer_id.GetHex());
    }
    return stored;
}

SpotOfferRecord CWallet::RegisterSpotAcceptance(const uint256& offer_id,
                                                SpotAcceptanceRecord acceptance)
{
    LOCK(cs_wallet);
    auto it = m_spot_offers.find(offer_id);
    if (it == m_spot_offers.end()) {
        throw std::runtime_error("Unknown spot offer id");
    }

    SpotOfferRecord& stored = it->second;

    if (stored.acceptance) {
        if (stored.acceptance->commitment_hex != acceptance.commitment_hex) {
            throw std::runtime_error("Acceptance commitment mismatch");
        }
        if (!acceptance.local_fs_tx_adaptor_secret && stored.acceptance->local_fs_tx_adaptor_secret) {
            acceptance.local_fs_tx_adaptor_secret = stored.acceptance->local_fs_tx_adaptor_secret;
        }
    }

    stored.acceptance = acceptance;
    stored.bob_recv_dest_hint = stored.acceptance->bob_recv_dest;

    WalletBatch batch(GetDatabase());
    if (!batch.WriteSpotOffer(stored)) {
        WalletLogPrintf("Warning: failed to persist acceptance for spot offer %s\n", offer_id.GetHex());
    }
    return stored;
}

bool CWallet::SetRepoVaultOutpoint(const uint256& offer_id,
                                   const COutPoint& outpoint,
                                   CAmount amount,
                                   const CScript& covenant_script)
{
    LOCK(cs_wallet);
    auto it = m_repo_offers.find(offer_id);
    if (it == m_repo_offers.end()) return false;
    it->second.vault_outpoint = outpoint;
    it->second.vault_amount = amount;
    it->second.vault_covenant_script = covenant_script;

    WalletBatch batch(GetDatabase());
    if (!batch.WriteRepoOffer(it->second)) {
        WalletLogPrintf("Warning: failed to persist vault outpoint for repo offer %s\n", offer_id.GetHex());
    }
    return true;
}

bool CWallet::SetRepoVaultCovenantScript(const uint256& offer_id, const CScript& covenant_script)
{
    AssertLockHeld(cs_wallet);
    auto it = m_repo_offers.find(offer_id);
    if (it == m_repo_offers.end()) return false;
    it->second.vault_covenant_script = covenant_script;

    WalletBatch batch(GetDatabase());
    if (!batch.WriteRepoOffer(it->second)) {
        WalletLogPrintf("Warning: failed to persist vault covenant script for repo offer %s\n", offer_id.GetHex());
        return false;
    }
    return true;
}

bool CWallet::SetRepoVaultTemplate(const uint256& offer_id,
                                   CAmount amount,
                                   const CScript& covenant_script)
{
    LOCK(cs_wallet);
    auto it = m_repo_offers.find(offer_id);
    if (it == m_repo_offers.end()) return false;

    RepoOfferRecord& record = it->second;
    bool changed = false;

    if (!record.vault_outpoint) {
        if (!record.vault_covenant_script || *record.vault_covenant_script != covenant_script) {
            record.vault_covenant_script = covenant_script;
            changed = true;
        }
        if (record.vault_amount != amount) {
            record.vault_amount = amount;
            changed = true;
        }
    } else {
        // Vault already finalized; ensure script is populated for completeness.
        if (!record.vault_covenant_script) {
            record.vault_covenant_script = covenant_script;
            changed = true;
        }
    }

    if (!changed) return true;

    WalletBatch batch(GetDatabase());
    if (!batch.WriteRepoOffer(record)) {
        WalletLogPrintf("Warning: failed to persist vault template for repo offer %s\n", offer_id.GetHex());
        return false;
    }
    return true;
}

bool CWallet::VerifyAndPersistRepoVault(const uint256& offer_id,
                                        const PartiallySignedTransaction& psbt)
{
    if (!psbt.tx) {
        return false;
    }
    CTransactionRef tx = MakeTransactionRef(CTransaction(*psbt.tx));
    return VerifyAndPersistRepoVault(offer_id, tx);
}

bool CWallet::VerifyAndPersistRepoVault(const uint256& offer_id,
                                        const CTransactionRef& tx)
{
    LOCK(cs_wallet);

    auto it = m_repo_offers.find(offer_id);
    if (it == m_repo_offers.end()) {
        WalletLogPrintf("Warning: Repo offer %s not found for vault verification\n", offer_id.GetHex());
        return false;
    }

    RepoOfferRecord& record = it->second;
    const RepoTerms& terms = record.terms;

    // Parse the transaction to extract vault outpoint
    const Txid txid = tx->GetHash();

    WalletLogPrintf("DEBUG: VerifyAndPersistRepoVault for offer %s, tx %s, has_vault_covenant_script=%d\n",
                    offer_id.GetHex(), txid.ToString(), record.vault_covenant_script.has_value());

    const CAmount expected_vault = terms.principal_leg.is_native ?
        (static_cast<CAmount>(terms.principal_leg.units) + static_cast<CAmount>(terms.collateral_leg.units)) :
        static_cast<CAmount>(terms.collateral_leg.units);

    // Find vault output in the transaction
    std::optional<std::pair<uint32_t, CAmount>> vault;
    std::optional<std::pair<uint32_t, CAmount>> heuristic_match;
    bool heuristic_ambiguous = false;

    const auto collateral_matches = [&](const CTxOut& output) -> bool {
        if (terms.collateral_leg.is_native) {
            return output.nValue == expected_vault;
        }
        if (auto tag = assets::ParseAssetTag(output.vExt)) {
            return tag->id == terms.collateral_leg.asset_id && tag->amount == terms.collateral_leg.units;
        }
        return false;
    };

    for (size_t i = 0; i < tx->vout.size(); ++i) {
        const CTxOut& output = tx->vout[i];

        int witversion;
        std::vector<unsigned char> witprogram;
        if (!output.scriptPubKey.IsWitnessProgram(witversion, witprogram) || witversion != 1 || witprogram.size() != 32) {
            continue;
        }

        const bool script_matches = record.vault_covenant_script && output.scriptPubKey == *record.vault_covenant_script;
        const bool value_matches = collateral_matches(output);

        if (script_matches) {
            vault = {static_cast<uint32_t>(i), output.nValue};
            if (!value_matches) {
                WalletLogPrintf("Warning: repo vault candidate %s:%u matched covenant script but failed collateral metadata check\n",
                                txid.ToString(), static_cast<unsigned>(i));
            }
            break;
        }

        if (!record.vault_covenant_script && value_matches) {
            if (!heuristic_match) {
                heuristic_match = {static_cast<uint32_t>(i), output.nValue};
            } else if (heuristic_match->first != i) {
                heuristic_ambiguous = true;
            }
        }
    }

    if (!vault && record.vault_covenant_script) {
        WalletLogPrintf("Warning: repo vault covenant script not found for offer %s in tx %s\n",
                        offer_id.GetHex(), txid.ToString());
    }
    if (!vault && heuristic_match && !heuristic_ambiguous) {
        vault = heuristic_match;
    } else if (!vault && heuristic_ambiguous) {
        WalletLogPrintf("Warning: multiple heuristic matches for repo vault detection in tx %s; refusing to persist\n",
                        txid.ToString());
    }

    // Persist vault outpoint if found
    bool updated = false;
    if (vault && !record.vault_outpoint) {
        record.vault_outpoint = COutPoint(txid, vault->first);
        record.vault_amount = vault->second;
        if (!record.vault_covenant_script) {
            record.vault_covenant_script = tx->vout[vault->first].scriptPubKey;
        }
        updated = true;
        WalletLogPrintf("Persisted repo vault for offer %s: %s:%d (amount: %s)\n",
                       offer_id.GetHex(), txid.ToString(), vault->first,
                       FormatMoney(vault->second));
    }

    if (updated) {
        WalletBatch batch(GetDatabase());
        if (!batch.WriteRepoOffer(record)) {
            WalletLogPrintf("Warning: failed to persist vault metadata for repo offer %s\n",
                          offer_id.GetHex());
            return false;
        }
    }

    // Return true if we have the vault persisted
    return record.vault_outpoint.has_value();
}

bool CWallet::MaybeRecordRepoClosure(const uint256& offer_id,
                                     RepoOfferRecord& record,
                                     const CTransactionRef& tx,
                                     const SyncTxState& state)
{
    AssertLockHeld(cs_wallet);

    const Txid txid = tx->GetHash();
    const bool matches_repay = record.repay_txid && *record.repay_txid == txid;
    const bool matches_default = record.default_txid && *record.default_txid == txid;
    const bool spends_vault = record.vault_outpoint && std::any_of(tx->vin.begin(), tx->vin.end(),
        [&](const CTxIn& in) { return in.prevout == *record.vault_outpoint; });

    const TxStateConfirmed* confirmed = std::get_if<TxStateConfirmed>(&state);
    if (!confirmed) {
        // Only transition lifecycle once the spend is confirmed.
        return false;
    }

    const CScript lender_spk = GetScriptForDestination(record.RepayDestination());
    const CAmount expected_principal_value = record.terms.principal_leg.is_native ?
        static_cast<CAmount>(record.terms.principal_leg.units) : DEFAULT_REPO_ASSET_OUTPUT_VALUE;
    const CAmount expected_interest_value = record.terms.interest_leg.is_native ?
        static_cast<CAmount>(record.terms.interest_leg.units) : DEFAULT_REPO_ASSET_OUTPUT_VALUE;
    const CAmount expected_default_value = static_cast<CAmount>(record.terms.collateral_leg.units);

    // Check if principal and interest should be merged (same asset)
    const bool should_merge = (record.terms.principal_leg.is_native == record.terms.interest_leg.is_native) &&
                              (record.terms.principal_leg.is_native ||
                               record.terms.principal_leg.asset_id == record.terms.interest_leg.asset_id);

    bool has_principal_output = false;
    bool has_interest_output = false;
    bool has_merged_repay_output = false;
    bool has_default_output = false;

    for (const CTxOut& out : tx->vout) {
        if (out.scriptPubKey != lender_spk) continue;

        if (should_merge) {
            // MERGED PATH: Look for single output with combined principal+interest
            const uint64_t total_repay_units = record.terms.principal_leg.units + record.terms.interest_leg.units;
            if (record.terms.principal_leg.is_native) {
                if (out.nValue == static_cast<CAmount>(total_repay_units)) {
                    has_merged_repay_output = true;
                }
            } else {
                if (out.nValue == DEFAULT_REPO_ASSET_OUTPUT_VALUE) {
                    auto tag = assets::ParseAssetTag(out.vExt);
                    if (tag && tag->id == record.terms.principal_leg.asset_id && tag->amount == total_repay_units) {
                        has_merged_repay_output = true;
                    }
                }
            }
        } else {
            // DUAL PATH: Look for separate principal and interest outputs
            // Check for principal payment
            if (record.terms.principal_leg.is_native) {
                if (out.nValue == expected_principal_value) {
                    has_principal_output = true;
                }
            } else {
                if (out.nValue == DEFAULT_REPO_ASSET_OUTPUT_VALUE) {
                    auto tag = assets::ParseAssetTag(out.vExt);
                    if (tag && tag->id == record.terms.principal_leg.asset_id && tag->amount == record.terms.principal_leg.units) {
                        has_principal_output = true;
                    }
                }
            }

            // Check for interest payment
            if (record.terms.interest_leg.is_native) {
                if (out.nValue == expected_interest_value) {
                    has_interest_output = true;
                }
            } else {
                if (out.nValue == DEFAULT_REPO_ASSET_OUTPUT_VALUE) {
                    auto tag = assets::ParseAssetTag(out.vExt);
                    if (tag && tag->id == record.terms.interest_leg.asset_id && tag->amount == record.terms.interest_leg.units) {
                        has_interest_output = true;
                    }
                }
            }
        }

        // Check for default (collateral seizure)
        if (out.nValue == expected_default_value) {
            has_default_output = true;
        }
    }

    if (!spends_vault && !matches_repay && !matches_default &&
        !has_principal_output && !has_interest_output && !has_merged_repay_output && !has_default_output) {
        return false;
    }

    bool changed = false;
    bool classify_repay = matches_repay;
    bool classify_default = matches_default;
    if (!classify_repay && !classify_default) {
        // Repayment detection: merged single output OR dual outputs
        if (should_merge) {
            if (has_merged_repay_output) {
                classify_repay = true;
            } else if (has_default_output) {
                classify_default = true;
            } else if (spends_vault) {
                classify_default = true;
            } else {
                return false;
            }
        } else {
            // Repayment requires BOTH principal and interest outputs (dual case)
            if (has_principal_output && has_interest_output) {
                classify_repay = true;
            } else if (has_default_output) {
                classify_default = true;
            } else if (spends_vault) {
                classify_default = true;
            } else {
                return false;
            }
        }
    }

    auto update_height_time = [&](bool is_repay) {
        std::optional<int> height_opt;
        std::optional<int64_t> time_opt;

        int height = confirmed->confirmed_block_height;
        int cache_height = height;
        int64_t block_time = 0;

        if (height >= 0) {
            height_opt = height;
        }

        if (chain().findBlock(confirmed->confirmed_block_hash, FoundBlock().height(cache_height).time(block_time))) {
            if (cache_height >= 0) height_opt = cache_height;
            time_opt = block_time;
        }

        if (is_repay) {
            if (height_opt && record.repay_height != height_opt) {
                record.repay_height = height_opt;
                changed = true;
            }
            if (time_opt && record.repay_time != time_opt) {
                record.repay_time = time_opt;
                changed = true;
            }
        } else {
            if (height_opt && record.default_height != height_opt) {
                record.default_height = height_opt;
                changed = true;
            }
            if (time_opt && record.default_time != time_opt) {
                record.default_time = time_opt;
                changed = true;
            }
        }
    };

    if (classify_repay) {
        if (!record.repay_txid || *record.repay_txid != txid) {
            record.repay_txid = txid;
            record.default_txid.reset();
            record.default_height.reset();
            record.default_time.reset();
            changed = true;
        }
        update_height_time(true);
    } else if (classify_default) {
        if (!record.default_txid || *record.default_txid != txid) {
            record.default_txid = txid;
            changed = true;
        }
        if (record.repay_txid && *record.repay_txid != txid) {
            record.repay_txid.reset();
            record.repay_height.reset();
            record.repay_time.reset();
            changed = true;
        }
        update_height_time(false);
    }

    if (changed) {
        WalletBatch batch(GetDatabase());
        if (!batch.WriteRepoOffer(record)) {
            WalletLogPrintf("Warning: failed to persist lifecycle update for repo offer %s\n", offer_id.GetHex());
        }
    }
    return changed;
}

bool CWallet::EnsureRepoClosureMetadata(const uint256& offer_id)
{
    AssertLockHeld(cs_wallet);
    auto it = m_repo_offers.find(offer_id);
    if (it == m_repo_offers.end()) return false;
    RepoOfferRecord& record = it->second;
    if (record.repay_txid || record.default_txid) {
        return true;
    }
    bool updated = false;

    if (record.vault_outpoint) {
        auto spend_range = mapTxSpends.equal_range(*record.vault_outpoint);
        for (auto it_spend = spend_range.first; it_spend != spend_range.second; ++it_spend) {
            const Txid& txid = it_spend->second;
            auto wallet_it = mapWallet.find(txid);
            if (wallet_it == mapWallet.end()) continue;
            const CWalletTx& wtx = wallet_it->second;
            if (!wtx.tx) continue;
            if (const TxStateConfirmed* confirmed = wtx.state<TxStateConfirmed>()) {
                if (MaybeRecordRepoClosure(offer_id, record, wtx.tx, *confirmed)) {
                    updated = true;
                    break;
                }
            }
        }
        if (updated) return true;
    }

    for (const auto& [txid, wtx] : mapWallet) {
        if (record.repay_txid || record.default_txid) break;
        if (!wtx.tx) continue;
        if (const TxStateConfirmed* confirmed = wtx.state<TxStateConfirmed>()) {
            if (MaybeRecordRepoClosure(offer_id, record, wtx.tx, *confirmed)) {
                updated = true;
                break;
            }
        }
    }
    return updated;
}

bool CWallet::MaybeRecordForwardStateTransition(const uint256& contract_id,
                                                ForwardContractRecord& record,
                                                const CTransactionRef& tx,
                                                const SyncTxState& state)
{
    AssertLockHeld(cs_wallet);

    const Txid txid = tx->GetHash();

    // Check if we already recorded this transaction
    const bool matches_open = record.open_txid && *record.open_txid == txid;
    const bool matches_self_delivery = record.self_delivery_txid && *record.self_delivery_txid == txid;
    const bool matches_coop_close = record.coop_close_txid && *record.coop_close_txid == txid;
    const bool matches_escrow_claim = record.escrow_claim_txid && *record.escrow_claim_txid == txid;
    const bool matches_escrow_refund = record.escrow_refund_txid && *record.escrow_refund_txid == txid;
    const bool matches_timeout = record.timeout_txid && *record.timeout_txid == txid;

    // Check if transaction spends known margin vaults
    const bool spends_long_vault = record.long_margin_vault && std::any_of(tx->vin.begin(), tx->vin.end(),
        [&](const CTxIn& in) { return in.prevout == *record.long_margin_vault; });
    const bool spends_short_vault = record.short_margin_vault && std::any_of(tx->vin.begin(), tx->vin.end(),
        [&](const CTxIn& in) { return in.prevout == *record.short_margin_vault; });

    // Check if transaction spends ANY vault for this contract (including escrow vaults)
    const bool spends_any_contract_vault = TransactionSpendsForwardVault(record, tx);

    // Check if transaction creates vaults (open transaction)
    bool candidate_vault_tx = false;
        if (!record.long_margin_vault && !record.short_margin_vault) {
            // Asset margin vaults use the same 1k-sat anchor as other asset transactions
            constexpr CAmount DEFAULT_ASSET_OUTPUT_VALUE{1000};
            const CAmount expected_long = record.terms.long_party.margin_leg.is_native
                ? static_cast<CAmount>(record.terms.long_party.margin_leg.units)
                : DEFAULT_ASSET_OUTPUT_VALUE;
            const CAmount expected_short = record.terms.short_party.margin_leg.is_native
                ? static_cast<CAmount>(record.terms.short_party.margin_leg.units)
            : DEFAULT_ASSET_OUTPUT_VALUE;

        bool long_found = false;
        bool short_found = false;
        for (const CTxOut& out : tx->vout) {
            int witness_version;
            std::vector<unsigned char> witness_program;
            const bool is_taproot = out.scriptPubKey.IsWitnessProgram(witness_version, witness_program) &&
                witness_version == 1 && witness_program.size() == 32;
            if (!is_taproot) continue;
            if (!long_found && out.nValue == expected_long) {
                long_found = true;
                continue;
            }
            if (!short_found && out.nValue == expected_short) {
                short_found = true;
            }
        }
        candidate_vault_tx = long_found && short_found;
    }

    const TxStateConfirmed* confirmed = std::get_if<TxStateConfirmed>(&state);
    if (!confirmed) {
        // Only transition lifecycle once the transaction is confirmed
        return false;
    }

    // Quick exit if not relevant to this contract
    if (!matches_open && !matches_self_delivery && !matches_coop_close &&
        !matches_escrow_claim && !matches_escrow_refund && !matches_timeout &&
        !spends_any_contract_vault && !candidate_vault_tx) {
        return false;
    }

    bool changed = false;

    // Helper to extract height and time from confirmed state
    auto update_height_time = [&](std::optional<int>& height_field, std::optional<int64_t>& time_field) {
        std::optional<int> height_opt;
        std::optional<int64_t> time_opt;

        int height = confirmed->confirmed_block_height;
        int cache_height = height;
        int64_t block_time = 0;

        if (height >= 0) {
            height_opt = height;
        }

        if (chain().findBlock(confirmed->confirmed_block_hash, FoundBlock().height(cache_height).time(block_time))) {
            if (cache_height >= 0) height_opt = cache_height;
            time_opt = block_time;
        }

        if (height_opt && height_field != height_opt) {
            height_field = height_opt;
            changed = true;
        }
        if (time_opt && time_field != time_opt) {
            time_field = time_opt;
            changed = true;
        }
    };

    // Classify transaction type
    enum class TxType { UNKNOWN, OPEN, SELF_DELIVERY, COOP_CLOSE, ESCROW_CLAIM, ESCROW_REFUND, TIMEOUT };
    TxType tx_type = TxType::UNKNOWN;

    bool creates_vaults = candidate_vault_tx;
    if (creates_vaults) {
        if (record.created_height > 0 && confirmed->confirmed_block_height < record.created_height) {
            creates_vaults = false;
        }
    }

    // Scan outputs once for all classification paths
    const CScript long_settlement = GetScriptForDestination(record.terms.long_party.settlement_receive_dest);
    const CScript short_settlement = GetScriptForDestination(record.terms.short_party.settlement_receive_dest);
    const CScript long_margin = GetScriptForDestination(record.terms.long_party.margin_dest);
    const CScript short_margin = GetScriptForDestination(record.terms.short_party.margin_dest);

    bool has_long_settlement = false;
    bool has_short_settlement = false;
    bool has_long_margin_return = false;
    bool has_short_margin_return = false;
    int escrow_outputs = 0;

    for (const CTxOut& out : tx->vout) {
        if (out.scriptPubKey == long_settlement) has_long_settlement = true;
        if (out.scriptPubKey == short_settlement) has_short_settlement = true;
        if (out.scriptPubKey == long_margin) has_long_margin_return = true;
        if (out.scriptPubKey == short_margin) has_short_margin_return = true;
        // Count potential escrow outputs (taproot outputs)
        int witness_version;
        std::vector<unsigned char> witness_program;
        if (out.scriptPubKey.IsWitnessProgram(witness_version, witness_program) &&
            witness_version == 1 && witness_program.size() == 32) {
            escrow_outputs++;
        }
    }

    if (matches_open) {
        tx_type = TxType::OPEN;
    } else if (matches_self_delivery) {
        tx_type = TxType::SELF_DELIVERY;
    } else if (matches_coop_close) {
        tx_type = TxType::COOP_CLOSE;
    } else if (matches_escrow_claim) {
        tx_type = TxType::ESCROW_CLAIM;
    } else if (matches_escrow_refund) {
        tx_type = TxType::ESCROW_REFUND;
    } else if (matches_timeout) {
        tx_type = TxType::TIMEOUT;
    } else if (creates_vaults) {
        // Transaction creates both vaults -> OPEN
        tx_type = TxType::OPEN;
    } else if (spends_any_contract_vault) {
        // Transaction spends vault(s) for this contract - classify based on outputs
        if (has_long_settlement && has_short_settlement && has_long_margin_return && has_short_margin_return) {
            // Cooperative close: delivers to both parties, returns both margins
            tx_type = TxType::COOP_CLOSE;
        } else if (escrow_outputs > 0 && (has_long_margin_return || has_short_margin_return)) {
            // Self-delivery: creates escrow output, returns margin
            tx_type = TxType::SELF_DELIVERY;
        } else if (has_long_settlement || has_short_settlement) {
            // Escrow claim or IM timeout sweep
            // Differentiate by checking if escrow is being spent
            bool spends_escrow = false;
            if (record.self_delivery_txid) {
                spends_escrow = std::any_of(tx->vin.begin(), tx->vin.end(),
                    [&](const CTxIn& in) { return in.prevout.hash == *record.self_delivery_txid; });
            }

            if (spends_long_vault && spends_short_vault) {
                // Spending both vaults unlikely unless timeout
                tx_type = TxType::TIMEOUT;
            } else if (spends_escrow) {
                // Spends escrow + vault(s) -> escrow claim or refund
                tx_type = TxType::ESCROW_CLAIM;
            } else {
                // Single vault spend without escrow -> IM timeout sweep
                // Do not transition contract state for IM sweeps
                tx_type = TxType::UNKNOWN;
            }
        } else {
            // Unknown vault spend pattern
            tx_type = TxType::UNKNOWN;
        }
    }

    // Record state transition
    switch (tx_type) {
    case TxType::OPEN:
        if (!record.long_margin_vault || !record.short_margin_vault) {
            WalletLogPrintf("Forward[%s]: Skipping OPEN transition for tx %s (vault metadata unavailable)\n",
                            contract_id.GetHex(), txid.ToString());
            break;
        }
        if (!record.open_txid || *record.open_txid != txid) {
            record.open_txid = txid;
            changed = true;
        }
        update_height_time(record.open_height, record.open_time);

        // Check if this OPEN transaction also includes escrow output (self-delivery at opening)
        // This happens when one party self-delivers their obligation in the same transaction that creates the vaults
        if (!record.self_delivery_txid) {
            const CAmount long_deliver_amt = record.terms.long_party.deliver_leg.units;
            const CAmount short_deliver_amt = record.terms.short_party.deliver_leg.units;
            const CAmount long_margin_amt = record.terms.long_party.margin_leg.units;
            const CAmount short_margin_amt = record.terms.short_party.margin_leg.units;

            for (size_t i = 0; i < tx->vout.size(); ++i) {
                const CTxOut& out = tx->vout[i];
                const CAmount amt = out.nValue;

                // Skip vault outputs (identified by margin amounts)
                if (amt == long_margin_amt || amt == short_margin_amt) {
                    continue;
                }

                // Check if this output matches expected escrow amount (deliver amount)
                if (amt == long_deliver_amt || amt == short_deliver_amt) {
                    // Found escrow output - this is also a self-delivery transaction
                    record.self_delivery_txid = txid;
                    update_height_time(record.settlement_height, record.settlement_time);
                    changed = true;
                    break;
                }
            }
        }
        break;

    case TxType::SELF_DELIVERY:
        if (!record.self_delivery_txid || *record.self_delivery_txid != txid) {
            record.self_delivery_txid = txid;
            changed = true;
        }
        update_height_time(record.settlement_height, record.settlement_time);
        break;

    case TxType::COOP_CLOSE:
        if (!record.coop_close_txid || *record.coop_close_txid != txid) {
            record.coop_close_txid = txid;
            // Clear conflicting states
            record.self_delivery_txid.reset();
            record.escrow_claim_txid.reset();
            record.escrow_refund_txid.reset();
            record.timeout_txid.reset();
            changed = true;
        }
        update_height_time(record.settlement_height, record.settlement_time);
        break;

    case TxType::ESCROW_CLAIM:
        if (!record.escrow_claim_txid || *record.escrow_claim_txid != txid) {
            record.escrow_claim_txid = txid;
            // Clear conflicting states
            record.coop_close_txid.reset();
            record.timeout_txid.reset();
            changed = true;
        }
        update_height_time(record.settlement_height, record.settlement_time);
        break;

    case TxType::ESCROW_REFUND:
        if (!record.escrow_refund_txid || *record.escrow_refund_txid != txid) {
            record.escrow_refund_txid = txid;
            // Clear conflicting states
            record.coop_close_txid.reset();
            record.timeout_txid.reset();
            changed = true;
        }
        update_height_time(record.settlement_height, record.settlement_time);
        break;

    case TxType::TIMEOUT:
        if (!record.timeout_txid || *record.timeout_txid != txid) {
            record.timeout_txid = txid;
            // Clear conflicting states
            record.coop_close_txid.reset();
            record.escrow_claim_txid.reset();
            record.escrow_refund_txid.reset();
            changed = true;
        }
        update_height_time(record.settlement_height, record.settlement_time);
        break;

    case TxType::UNKNOWN:
        // Don't record unknown transaction types
        break;
    }

    if (changed) {
        WalletBatch batch(GetDatabase());
        if (!batch.WriteForwardContract(record)) {
            WalletLogPrintf("Warning: failed to persist lifecycle update for forward contract %s\n", contract_id.GetHex());
        }
    }
    return changed;
}

bool CWallet::EnsureForwardStateMetadata(const uint256& contract_id)
{
    AssertLockHeld(cs_wallet);
    auto it = m_forward_contracts.find(contract_id);
    if (it == m_forward_contracts.end()) return false;
    ForwardContractRecord& record = it->second;

    WalletLogPrintf("Forward[%s]: EnsureForwardStateMetadata start (open=%s self=%s coop=%s escrow_claim=%s escrow_refund=%s timeout=%s)\n",
                    contract_id.GetHex(),
                    record.open_txid ? record.open_txid->GetHex() : "unset",
                    record.self_delivery_txid ? record.self_delivery_txid->GetHex() : "unset",
                    record.coop_close_txid ? record.coop_close_txid->GetHex() : "unset",
                    record.escrow_claim_txid ? record.escrow_claim_txid->GetHex() : "unset",
                    record.escrow_refund_txid ? record.escrow_refund_txid->GetHex() : "unset",
                    record.timeout_txid ? record.timeout_txid->GetHex() : "unset");

    // If we already have terminal state, no need to scan
    if (record.coop_close_txid || record.timeout_txid ||
        record.escrow_claim_txid || record.escrow_refund_txid) {
        WalletLogPrintf("Forward[%s]: EnsureForwardStateMetadata early exit (terminal state present)\n",
                        contract_id.GetHex());
        return true;
    }

    bool updated = false;

    // Scan vault spends
    if (record.long_margin_vault) {
        WalletLogPrintf("Forward[%s]: scanning spends of LONG vault %s\n",
                        contract_id.GetHex(), record.long_margin_vault->ToString());
        auto spend_range = mapTxSpends.equal_range(*record.long_margin_vault);
        for (auto it_spend = spend_range.first; it_spend != spend_range.second; ++it_spend) {
            const Txid& txid = it_spend->second;
            auto wallet_it = mapWallet.find(txid);
            if (wallet_it == mapWallet.end()) continue;
            const CWalletTx& wtx = wallet_it->second;
            if (!wtx.tx) continue;
            if (const TxStateConfirmed* confirmed = wtx.state<TxStateConfirmed>()) {
                WalletLogPrintf("Forward[%s]: MaybeRecordForwardStateTransition via long vault spend %s\n",
                                contract_id.GetHex(), txid.ToString());
                if (MaybeRecordForwardStateTransition(contract_id, record, wtx.tx, *confirmed)) {
                    WalletLogPrintf("Forward[%s]: state transition recorded via long vault spend %s\n",
                                    contract_id.GetHex(), txid.ToString());
                    updated = true;
                }
            }
        }
    }

    if (record.short_margin_vault) {
        WalletLogPrintf("Forward[%s]: scanning spends of SHORT vault %s\n",
                        contract_id.GetHex(), record.short_margin_vault->ToString());
        auto spend_range = mapTxSpends.equal_range(*record.short_margin_vault);
        for (auto it_spend = spend_range.first; it_spend != spend_range.second; ++it_spend) {
            const Txid& txid = it_spend->second;
            auto wallet_it = mapWallet.find(txid);
            if (wallet_it == mapWallet.end()) continue;
            const CWalletTx& wtx = wallet_it->second;
            if (!wtx.tx) continue;
            if (const TxStateConfirmed* confirmed = wtx.state<TxStateConfirmed>()) {
                WalletLogPrintf("Forward[%s]: MaybeRecordForwardStateTransition via short vault spend %s\n",
                                contract_id.GetHex(), txid.ToString());
                if (MaybeRecordForwardStateTransition(contract_id, record, wtx.tx, *confirmed)) {
                    WalletLogPrintf("Forward[%s]: state transition recorded via short vault spend %s\n",
                                    contract_id.GetHex(), txid.ToString());
                    updated = true;
                }
            }
        }
    }

    // If still no state found, scan entire wallet
    if (!record.open_txid && !record.self_delivery_txid && !record.coop_close_txid &&
        !record.escrow_claim_txid && !record.escrow_refund_txid && !record.timeout_txid) {
        WalletLogPrintf("Forward[%s]: scanning entire wallet for relevant txns (fallback)\n",
                        contract_id.GetHex());
        for (const auto& [txid, wtx] : mapWallet) {
            if (!wtx.tx) continue;
            if (const TxStateConfirmed* confirmed = wtx.state<TxStateConfirmed>()) {
                WalletLogPrintf("Forward[%s]: MaybeRecordForwardStateTransition via wallet tx %s\n",
                                contract_id.GetHex(), txid.ToString());
                if (MaybeRecordForwardStateTransition(contract_id, record, wtx.tx, *confirmed)) {
                    WalletLogPrintf("Forward[%s]: state transition recorded via wallet tx %s\n",
                                    contract_id.GetHex(), txid.ToString());
                    updated = true;
                }
            }
        }
    }

    WalletLogPrintf("Forward[%s]: EnsureForwardStateMetadata done (updated=%d state=%s)\n",
                    contract_id.GetHex(), updated,
                    ForwardContractStateToString(record.DerivedState()));

    return updated;
}

void CWallet::SetFairSignInputState(const uint256& txid,
                                    size_t index,
                                    FairSignInputState state)
{
    LOCK(cs_wallet);
    auto& session = m_fairsign_sessions[txid];
    auto it = session.inputs.find(index);
    if (it != session.inputs.end()) {
        ZeroizeFairSignInputState(it->second);
    }
    session.inputs[index] = std::move(state);
}

bool CWallet::GetFairSignInputState(const uint256& txid,
                                    size_t index,
                                    FairSignInputState& out) const
{
    LOCK(cs_wallet);
    auto session_it = m_fairsign_sessions.find(txid);
    if (session_it == m_fairsign_sessions.end()) return false;
    const auto input_it = session_it->second.inputs.find(index);
    if (input_it == session_it->second.inputs.end()) return false;

    // Copy all fields except musig_state (which is ephemeral and not copyable)
    const auto& src = input_it->second;
    out.pre_sig = src.pre_sig;
    out.nonce_parity = src.nonce_parity;
    out.r_nonce = src.r_nonce;
    out.adaptor_point = src.adaptor_point;
    out.commitment = src.commitment;
    out.sighash_type = src.sighash_type;
    out.is_keypath = src.is_keypath;
    out.tapleaf_hash = src.tapleaf_hash;
    out.tapleaf_script = src.tapleaf_script;
    out.tapleaf_control_block = src.tapleaf_control_block;
    out.has_tapleaf_witness = src.has_tapleaf_witness;
    out.tapleaf_signers = src.tapleaf_signers;
    out.tapleaf_signer_slot = src.tapleaf_signer_slot;
    out.message_digest = src.message_digest;
    out.signing_key = src.signing_key;
    out.has_partial = src.has_partial;
    out.adaptor_secret = src.adaptor_secret;
    out.keyagg_cache = src.keyagg_cache;
    out.has_keyagg_cache = src.has_keyagg_cache;
    out.musig_local_index = src.musig_local_index;
    out.musig_total_signers = src.musig_total_signers;
    out.vault_intent_purpose = src.vault_intent_purpose;
    // Note: musig_state, nonce_secret, tweaked_secret, r_prime are ephemeral (not copied)

    return true;
}

FairSignInputState* CWallet::GetMutableFairSignInputState(const uint256& txid, size_t index)
{
    AssertLockHeld(cs_wallet);  // Caller must hold lock
    auto session_it = m_fairsign_sessions.find(txid);
    if (session_it == m_fairsign_sessions.end()) return nullptr;
    auto input_it = session_it->second.inputs.find(index);
    if (input_it == session_it->second.inputs.end()) return nullptr;
    return &input_it->second;
}

void CWallet::ClearFairSignSession(const uint256& txid)
{
    LOCK(cs_wallet);
    auto it = m_fairsign_sessions.find(txid);
    if (it == m_fairsign_sessions.end()) {
        return;
    }
    for (auto& [idx, state] : it->second.inputs) {
        ZeroizeFairSignInputState(state);
    }
    m_fairsign_sessions.erase(it);
}

size_t CWallet::CleanupExpiredFairSignSessions()
{
    AssertLockHeld(cs_wallet);

    size_t cleaned_count = 0;
    std::vector<uint256> expired_txids;

    // First pass: identify expired sessions
    for (const auto& [txid, session] : m_fairsign_sessions) {
        if (session.IsExpired()) {
            expired_txids.push_back(txid);
        }
    }

    // Second pass: clean up expired sessions
    for (const auto& txid : expired_txids) {
        auto it = m_fairsign_sessions.find(txid);
        if (it == m_fairsign_sessions.end()) continue;

        // Unlock UTXOs if configured
        if (it->second.auto_unlock_on_timeout) {
            for (const auto& outpoint : it->second.locked_utxos) {
                UnlockCoin(outpoint);
            }
        }

        // Zero sensitive data
        for (auto& [idx, state] : it->second.inputs) {
            ZeroizeFairSignInputState(state);
        }

        m_fairsign_sessions.erase(it);
        ++cleaned_count;

        WalletLogPrintf("Fair-Sign session for tx %s expired and cleaned up (TTL exceeded)\n", txid.ToString());
    }

    return cleaned_count;
}

bool CWallet::LockFairSignUTXOs(const uint256& txid, const std::vector<COutPoint>& utxos)
{
    AssertLockHeld(cs_wallet);

    auto it = m_fairsign_sessions.find(txid);
    if (it == m_fairsign_sessions.end()) {
        // Initialize session if it doesn't exist
        m_fairsign_sessions[txid].created_time = GetTime();
    }

    auto& session = m_fairsign_sessions[txid];

    for (const auto& outpoint : utxos) {
        if (LockCoin(outpoint)) {
            session.locked_utxos.insert(outpoint);
        } else {
            // Lock failed - rollback already locked coins
            for (const auto& locked : session.locked_utxos) {
                UnlockCoin(locked);
            }
            session.locked_utxos.clear();
            return false;
        }
    }

    return true;
}

bool CWallet::UnlockFairSignUTXOs(const uint256& txid)
{
    AssertLockHeld(cs_wallet);

    auto it = m_fairsign_sessions.find(txid);
    if (it == m_fairsign_sessions.end()) {
        return false;
    }

    bool all_unlocked = true;
    for (const auto& outpoint : it->second.locked_utxos) {
        if (!UnlockCoin(outpoint)) {
            all_unlocked = false;
        }
    }

    it->second.locked_utxos.clear();
    return all_unlocked;
}

std::pair<size_t, size_t> CWallet::UnlockAllFairSignUTXOs()
{
    AssertLockHeld(cs_wallet);

    size_t unlocked_count = 0;
    size_t sessions_cleaned = 0;

    // Clean up expired sessions first
    sessions_cleaned = CleanupExpiredFairSignSessions();

    // Force unlock all remaining Fair-Sign UTXOs
    for (auto& [txid, session] : m_fairsign_sessions) {
        for (const auto& outpoint : session.locked_utxos) {
            if (UnlockCoin(outpoint)) {
                ++unlocked_count;
            }
        }
        session.locked_utxos.clear();
    }

    return {unlocked_count, sessions_cleaned};
}

const CWallet::FairSignSessionState* CWallet::GetFairSignSession(const uint256& txid) const
{
    AssertLockHeld(cs_wallet);

    auto it = m_fairsign_sessions.find(txid);
    if (it == m_fairsign_sessions.end()) {
        return nullptr;
    }
    return &it->second;
}

void CWallet::InitFairSignSession(const uint256& txid, int64_t ttl_seconds)
{
    AssertLockHeld(cs_wallet);

    auto& session = m_fairsign_sessions[txid];
    session.created_time = GetTime();
    session.ttl_seconds = ttl_seconds;
    session.auto_unlock_on_timeout = true;
}

bool CWallet::UpdateRepoRepayDestination(const uint256& offer_id,
                                         const CTxDestination& dest,
                                         const std::optional<XOnlyPubKey>& internal_key)
{
    LOCK(cs_wallet);
    auto it = m_repo_offers.find(offer_id);
    if (it == m_repo_offers.end()) return false;
    it->second.lender_dest_override = dest;
    if (internal_key.has_value()) {
        it->second.lender_internal_key = *internal_key;
    }

    WalletBatch batch(GetDatabase());
    if (!batch.WriteRepoOffer(it->second)) {
        WalletLogPrintf("Warning: failed to persist repayment override for repo offer %s\n", offer_id.GetHex());
    }
    return true;
}

bool CWallet::LoadForwardContract(const ForwardContractRecord& record)
{
    AssertLockHeld(cs_wallet);
    m_forward_contracts[record.contract_id] = record;
    return true;
}

ForwardContractRecord CWallet::RegisterForwardContract(ForwardContractRecord record)
{
    LOCK(cs_wallet);
    auto [it, inserted] = m_forward_contracts.insert_or_assign(record.contract_id, record);
    ForwardContractRecord& stored = it->second;

    WalletBatch batch(GetDatabase());
    if (!batch.WriteForwardContract(stored)) {
        WalletLogPrintf("Warning: failed to write forward contract %s to database\n", stored.contract_id.GetHex());
    }

    return stored;
}

std::optional<ForwardContractRecord> CWallet::FindForwardContract(const uint256& contract_id) const
{
    LOCK(cs_wallet);
    auto it = m_forward_contracts.find(contract_id);
    if (it == m_forward_contracts.end()) {
        return std::nullopt;
    }
    return it->second;
}

std::vector<ForwardContractRecord> CWallet::ListForwardContracts() const
{
    LOCK(cs_wallet);
    std::vector<ForwardContractRecord> out;
    out.reserve(m_forward_contracts.size());
    for (const auto& entry : m_forward_contracts) {
        out.push_back(entry.second);
    }
    return out;
}

bool CWallet::LoadDifficultyContract(const DifficultyContractRecord& record)
{
    AssertLockHeld(cs_wallet);
    m_difficulty_contracts[record.contract_id] = record;
    return true;
}

DifficultyContractRecord CWallet::RegisterDifficultyContract(DifficultyContractRecord record)
{
    LOCK(cs_wallet);
    const uint256 contract_id = record.contract_id;
    auto [it, inserted] = m_difficulty_contracts.insert_or_assign(contract_id, std::move(record));
    DifficultyContractRecord& stored = it->second;

    WalletBatch batch(GetDatabase());
    if (!batch.WriteDifficultyContract(stored)) {
        // The on-disk record must agree with the registered vault metadata, otherwise build_settlement
        // would not find the contract after a restart. Surface the failure (roll back the in-memory
        // insert) rather than silently diverging; callers (build_open RPC) propagate it as an error.
        m_difficulty_contracts.erase(contract_id);
        throw std::runtime_error(strprintf("Failed to persist difficulty contract %s to the wallet database", contract_id.GetHex()));
    }

    return stored;
}

std::optional<DifficultyContractRecord> CWallet::FindDifficultyContract(const uint256& contract_id) const
{
    LOCK(cs_wallet);
    auto it = m_difficulty_contracts.find(contract_id);
    if (it == m_difficulty_contracts.end()) {
        return std::nullopt;
    }
    return it->second;
}

std::vector<DifficultyContractRecord> CWallet::ListDifficultyContracts() const
{
    LOCK(cs_wallet);
    std::vector<DifficultyContractRecord> out;
    out.reserve(m_difficulty_contracts.size());
    for (const auto& entry : m_difficulty_contracts) {
        out.push_back(entry.second);
    }
    return out;
}

bool CWallet::LoadOptionSeries(const OptionSeriesRecord& record)
{
    AssertLockHeld(cs_wallet);
    m_option_series[record.series_id] = record;
    return true;
}

OptionSeriesRecord CWallet::RegisterOptionSeries(OptionSeriesRecord record)
{
    LOCK(cs_wallet);
    // Never persist a record whose id does not derive from its terms, or whose vault set is malformed.
    std::string verr;
    if (!ValidateOptionSeriesRecord(record, /*expected_key=*/nullptr, verr)) {
        throw std::runtime_error(strprintf("Refusing to persist invalid option series: %s", verr));
    }
    const uint256 series_id = record.series_id;

    // Snapshot prior state for a TRUE rollback (insert_or_assign overwrites an existing record).
    const auto prev_it = m_option_series.find(series_id);
    const bool had_prev = prev_it != m_option_series.end();
    OptionSeriesRecord prev = had_prev ? prev_it->second : OptionSeriesRecord{};

    m_option_series.insert_or_assign(series_id, record);

    WalletBatch batch(GetDatabase());
    if (!batch.WriteOptionSeries(record)) {
        // Restore the previous record (or remove the new insert) so memory matches disk, then surface.
        if (had_prev) m_option_series[series_id] = std::move(prev);
        else m_option_series.erase(series_id);
        throw std::runtime_error(strprintf("Failed to persist option series %s to the wallet database", series_id.GetHex()));
    }

    return record;
}

std::optional<OptionSeriesRecord> CWallet::FindOptionSeries(const uint256& series_id) const
{
    LOCK(cs_wallet);
    auto it = m_option_series.find(series_id);
    if (it == m_option_series.end()) {
        return std::nullopt;
    }
    return it->second;
}

std::vector<OptionSeriesRecord> CWallet::ListOptionSeries() const
{
    LOCK(cs_wallet);
    std::vector<OptionSeriesRecord> out;
    out.reserve(m_option_series.size());
    for (const auto& entry : m_option_series) {
        out.push_back(entry.second);
    }
    return out;
}

bool CWallet::LoadScalarNotePair(const ScalarNotePairRecord& record)
{
    AssertLockHeld(cs_wallet);
    m_scalar_note_pairs[record.pair_id] = record;
    return true;
}

ScalarNotePairRecord CWallet::RegisterScalarNotePair(ScalarNotePairRecord record)
{
    LOCK(cs_wallet);
    // Never persist a record whose id does not derive from its terms, or whose vault set is malformed.
    std::string verr;
    if (!ValidateScalarNotePairRecord(record, /*expected_key=*/nullptr, verr)) {
        throw std::runtime_error(strprintf("Refusing to persist invalid scalar note pair: %s", verr));
    }
    const uint256 pair_id = record.pair_id;

    const auto prev_it = m_scalar_note_pairs.find(pair_id);
    const bool had_prev = prev_it != m_scalar_note_pairs.end();
    ScalarNotePairRecord prev = had_prev ? prev_it->second : ScalarNotePairRecord{};

    m_scalar_note_pairs.insert_or_assign(pair_id, record);

    WalletBatch batch(GetDatabase());
    if (!batch.WriteScalarNotePair(record)) {
        if (had_prev) m_scalar_note_pairs[pair_id] = std::move(prev);
        else m_scalar_note_pairs.erase(pair_id);
        throw std::runtime_error(strprintf("Failed to persist scalar note pair %s to the wallet database", pair_id.GetHex()));
    }

    return record;
}

std::optional<ScalarNotePairRecord> CWallet::FindScalarNotePair(const uint256& pair_id) const
{
    LOCK(cs_wallet);
    auto it = m_scalar_note_pairs.find(pair_id);
    if (it == m_scalar_note_pairs.end()) {
        return std::nullopt;
    }
    return it->second;
}

std::vector<ScalarNotePairRecord> CWallet::ListScalarNotePairs() const
{
    LOCK(cs_wallet);
    std::vector<ScalarNotePairRecord> out;
    out.reserve(m_scalar_note_pairs.size());
    for (const auto& entry : m_scalar_note_pairs) {
        out.push_back(entry.second);
    }
    return out;
}

bool CWallet::LoadScalarCfdContract(const ScalarCfdContractRecord& record)
{
    AssertLockHeld(cs_wallet);
    m_scalar_cfd_contracts[record.contract_id] = record;
    return true;
}

ScalarCfdContractRecord CWallet::RegisterScalarCfdContract(ScalarCfdContractRecord record)
{
    LOCK(cs_wallet);
    // Never persist a record that fails the full integrity gate (id == H(terms,salt), valid terms, NUMS
    // vault internals, valid coop internals, complete Fair-Sign state).
    std::string verr;
    if (!ValidateScalarCfdContractRecord(record, /*expected_key=*/nullptr, verr)) {
        throw std::runtime_error(strprintf("Refusing to persist invalid scalar CFD contract: %s", verr));
    }
    const uint256 contract_id = record.contract_id;

    const auto prev_it = m_scalar_cfd_contracts.find(contract_id);
    const bool had_prev = prev_it != m_scalar_cfd_contracts.end();
    ScalarCfdContractRecord prev = had_prev ? prev_it->second : ScalarCfdContractRecord{};

    m_scalar_cfd_contracts.insert_or_assign(contract_id, record);

    WalletBatch batch(GetDatabase());
    if (!batch.WriteScalarCfdContract(record)) {
        if (had_prev) m_scalar_cfd_contracts[contract_id] = std::move(prev);
        else m_scalar_cfd_contracts.erase(contract_id);
        throw std::runtime_error(strprintf("Failed to persist scalar CFD contract %s to the wallet database", contract_id.GetHex()));
    }

    return record;
}

std::optional<ScalarCfdContractRecord> CWallet::FindScalarCfdContract(const uint256& contract_id) const
{
    LOCK(cs_wallet);
    auto it = m_scalar_cfd_contracts.find(contract_id);
    if (it == m_scalar_cfd_contracts.end()) {
        return std::nullopt;
    }
    return it->second;
}

std::vector<ScalarCfdContractRecord> CWallet::ListScalarCfdContracts() const
{
    LOCK(cs_wallet);
    std::vector<ScalarCfdContractRecord> out;
    out.reserve(m_scalar_cfd_contracts.size());
    for (const auto& entry : m_scalar_cfd_contracts) {
        out.push_back(entry.second);
    }
    return out;
}

// ---------------------------------------------------------------------------
// Cross-chain settlement
// ---------------------------------------------------------------------------

bool CWallet::LoadCrossChainRecord(const CrossChainRecord& record)
{
    AssertLockHeld(cs_wallet);
    m_cross_chain_records[record.swap_id] = record;
    return true;
}

CrossChainRecord CWallet::RegisterCrossChainRecord(CrossChainRecord record)
{
    LOCK(cs_wallet);

    // Persist first — if this fails, do not mutate in-memory state
    WalletBatch batch(GetDatabase());
    if (!batch.WriteCrossChainRecord(record)) {
        WalletLogPrintf("Error: failed to write cross-chain record %s to database\n", record.swap_id);
        return record; // return unmodified; caller can check via FindCrossChainRecord
    }

    auto [it, inserted] = m_cross_chain_records.insert_or_assign(record.swap_id, record);
    return it->second;
}

std::optional<CrossChainRecord> CWallet::FindCrossChainRecord(const std::string& swap_id) const
{
    LOCK(cs_wallet);
    auto it = m_cross_chain_records.find(swap_id);
    if (it == m_cross_chain_records.end()) {
        return std::nullopt;
    }
    return it->second;
}

std::vector<CrossChainRecord> CWallet::ListCrossChainRecords() const
{
    LOCK(cs_wallet);
    std::vector<CrossChainRecord> out;
    out.reserve(m_cross_chain_records.size());
    for (const auto& entry : m_cross_chain_records) {
        out.push_back(entry.second);
    }
    return out;
}

bool CWallet::UpdateCrossChainState(const std::string& swap_id, CrossChainState new_state)
{
    LOCK(cs_wallet);
    auto it = m_cross_chain_records.find(swap_id);
    if (it == m_cross_chain_records.end()) {
        return false;
    }

    // Validate adjacency before persisting
    if (!IsValidCrossChainTransition(it->second.state, new_state)) {
        WalletLogPrintf("Error: invalid cross-chain state transition %d -> %d for swap %s\n",
                        static_cast<int>(it->second.state),
                        static_cast<int>(new_state),
                        swap_id);
        return false;
    }

    // Build updated record, persist first, then mutate in-memory
    CrossChainRecord updated = it->second;
    updated.state = new_state;
    updated.updated_time = GetTime();

    WalletBatch batch(GetDatabase());
    if (!batch.WriteCrossChainRecord(updated)) {
        WalletLogPrintf("Error: failed to persist cross-chain state update for swap %s\n", swap_id);
        return false;
    }

    it->second = updated;
    return true;
}

bool CWallet::UpdateCrossChainMonitoring(const std::string& swap_id,
                                         uint32_t external_conf_depth,
                                         uint32_t tsc_conf_depth,
                                         uint32_t fee_escalation_level)
{
    LOCK(cs_wallet);
    auto it = m_cross_chain_records.find(swap_id);
    if (it == m_cross_chain_records.end()) {
        return false;
    }

    // Only persist if something actually changed
    if (it->second.external_conf_depth == external_conf_depth &&
        it->second.tsc_conf_depth == tsc_conf_depth &&
        it->second.fee_escalation_level == fee_escalation_level) {
        return true; // No change needed
    }

    CrossChainRecord updated = it->second;
    updated.external_conf_depth = external_conf_depth;
    updated.tsc_conf_depth = tsc_conf_depth;
    updated.fee_escalation_level = fee_escalation_level;
    updated.updated_time = GetTime();

    WalletBatch batch(GetDatabase());
    if (!batch.WriteCrossChainRecord(updated)) {
        WalletLogPrintf("Error: failed to persist cross-chain monitoring update for swap %s\n", swap_id);
        return false;
    }

    it->second = updated;
    return true;
}

CrossChainSwapManager& CWallet::GetOrCreateSwapManager()
{
    if (!m_cross_chain_manager) {
        m_cross_chain_manager = std::make_unique<CrossChainSwapManager>(*this);
    }
    return *m_cross_chain_manager;
}

void CWallet::StopSwapManager()
{
    if (m_cross_chain_manager) {
        m_cross_chain_manager->Stop();
    }
}

bool CWallet::UpdateCrossChainOracleAttestation(
    const std::string& swap_id,
    const std::string& oracle_attestation)
{
    LOCK(cs_wallet);
    auto it = m_cross_chain_records.find(swap_id);
    if (it == m_cross_chain_records.end()) {
        return false;
    }

    CrossChainRecord updated = it->second;
    updated.oracle_attestation = oracle_attestation;
    updated.updated_time = GetTime();

    WalletBatch batch(GetDatabase());
    if (!batch.WriteCrossChainRecord(updated)) {
        WalletLogPrintf("Error: failed to persist oracle attestation for swap %s\n", swap_id);
        return false;
    }

    it->second = updated;
    return true;
}

bool CWallet::UpdateCrossChainHtlcArtifacts(
    const std::string& swap_id,
    const std::string& htlc_contract_address,
    const std::string& htlc_swap_id,
    const std::string& external_signer_ref,
    const std::string& claim_secret,
    const std::string& claim_tx_hash,
    const std::string& refund_tx_hash,
    const std::string& external_lock_tx_hash,
    int64_t htlc_timelock)
{
    LOCK(cs_wallet);
    auto it = m_cross_chain_records.find(swap_id);
    if (it == m_cross_chain_records.end()) {
        return false;
    }

    CrossChainRecord updated = it->second;
    updated.htlc_contract_address = htlc_contract_address;
    updated.htlc_swap_id = htlc_swap_id;
    updated.external_signer_ref = external_signer_ref;
    updated.claim_secret = claim_secret;
    updated.claim_tx_hash = claim_tx_hash;
    updated.refund_tx_hash = refund_tx_hash;
    updated.external_lock_tx_hash = external_lock_tx_hash;
    updated.htlc_timelock = htlc_timelock;
    updated.updated_time = GetTime();

    WalletBatch batch(GetDatabase());
    if (!batch.WriteCrossChainRecord(updated)) {
        WalletLogPrintf("Error: failed to persist HTLC artifacts for swap %s\n", swap_id);
        return false;
    }

    it->second = updated;
    return true;
}

bool CWallet::UpdateCrossChainExpectedValues(
    const std::string& swap_id,
    const std::string& expected_secret_hash,
    const std::string& expected_recipient,
    const std::string& expected_amount,
    const std::string& expected_token_address)
{
    LOCK(cs_wallet);
    auto it = m_cross_chain_records.find(swap_id);
    if (it == m_cross_chain_records.end()) {
        return false;
    }

    CrossChainRecord updated = it->second;
    updated.expected_secret_hash = expected_secret_hash;
    updated.expected_recipient = expected_recipient;
    updated.expected_amount = expected_amount;
    updated.expected_token_address = expected_token_address;
    updated.updated_time = GetTime();

    WalletBatch batch(GetDatabase());
    if (!batch.WriteCrossChainRecord(updated)) {
        WalletLogPrintf("Error: failed to persist expected values for swap %s\n", swap_id);
        return false;
    }

    it->second = updated;
    return true;
}

bool CWallet::UpdateCrossChainSessionAddresses(
    const std::string& swap_id,
    const std::string& taker_tsc_address,
    const std::string& taker_refund_address)
{
    LOCK(cs_wallet);
    auto it = m_cross_chain_records.find(swap_id);
    if (it == m_cross_chain_records.end()) {
        return false;
    }

    CrossChainRecord updated = it->second;
    updated.taker_tsc_address = taker_tsc_address;
    updated.taker_refund_address = taker_refund_address;
    updated.updated_time = GetTime();

    WalletBatch batch(GetDatabase());
    if (!batch.WriteCrossChainRecord(updated)) {
        WalletLogPrintf("Error: failed to persist session addresses for swap %s\n", swap_id);
        return false;
    }

    it->second = updated;
    return true;
}

// ---------------------------------------------------------------------------
// Settlement profiles
// ---------------------------------------------------------------------------

bool CWallet::LoadSettlementProfile(const std::string& profile_id, const SettlementProfile& profile)
{
    AssertLockHeld(cs_wallet);
    m_settlement_profiles[profile_id] = profile;
    return true;
}

bool CWallet::AddSettlementProfile(const std::string& profile_id, SettlementProfile profile)
{
    LOCK(cs_wallet);

    // Persist first
    WalletBatch batch(GetDatabase());
    if (!batch.WriteSettlementProfile(profile_id, profile)) {
        WalletLogPrintf("Error: failed to write settlement profile %s to database\n", profile_id);
        return false;
    }

    m_settlement_profiles[profile_id] = std::move(profile);
    return true;
}

bool CWallet::RemoveSettlementProfile(const std::string& profile_id)
{
    LOCK(cs_wallet);
    auto it = m_settlement_profiles.find(profile_id);
    if (it == m_settlement_profiles.end()) {
        return false;
    }

    // Erase from disk first
    WalletBatch batch(GetDatabase());
    if (!batch.EraseSettlementProfile(profile_id)) {
        WalletLogPrintf("Error: failed to erase settlement profile %s from database\n", profile_id);
        return false;
    }

    m_settlement_profiles.erase(it);
    return true;
}

std::optional<SettlementProfile> CWallet::FindSettlementProfile(const std::string& profile_id) const
{
    LOCK(cs_wallet);
    auto it = m_settlement_profiles.find(profile_id);
    if (it == m_settlement_profiles.end()) {
        return std::nullopt;
    }
    return it->second;
}

std::vector<std::pair<std::string, SettlementProfile>> CWallet::ListSettlementProfiles() const
{
    LOCK(cs_wallet);
    std::vector<std::pair<std::string, SettlementProfile>> out;
    out.reserve(m_settlement_profiles.size());
    for (const auto& entry : m_settlement_profiles) {
        out.push_back(entry);
    }
    return out;
}

bool CWallet::MarkForwardContractAccepted(const uint256& contract_id,
                                          const std::string& acceptance_commitment,
                                          const uint256& acceptance_salt,
                                          const XOnlyPubKey& counterparty_adaptor_point,
                                          const std::optional<uint256>& counterparty_adaptor_secret)
{
    LOCK(cs_wallet);
    auto it = m_forward_contracts.find(contract_id);
    if (it == m_forward_contracts.end()) {
        return false;
    }

    it->second.acceptance_commitment_hex = acceptance_commitment;
    it->second.acceptance_salt = acceptance_salt;
    it->second.counterparty_adaptor_point = counterparty_adaptor_point;
    if (counterparty_adaptor_secret) {
        it->second.counterparty_adaptor_secret = *counterparty_adaptor_secret;
    }

    WalletBatch batch(GetDatabase());
    if (!batch.WriteForwardContract(it->second)) {
        WalletLogPrintf("Warning: failed to persist acceptance for forward contract %s\n", contract_id.GetHex());
    }
    return true;
}

bool CWallet::SetForwardMarginVault(const uint256& contract_id,
                                    ForwardSide side,
                                    const COutPoint& outpoint,
                                    CAmount amount)
{
    LOCK(cs_wallet);
    auto it = m_forward_contracts.find(contract_id);
    if (it == m_forward_contracts.end()) {
        return false;
    }

    if (side == ForwardSide::LONG) {
        it->second.long_margin_vault = outpoint;
        it->second.long_margin_value = amount;
    } else {
        it->second.short_margin_vault = outpoint;
        it->second.short_margin_value = amount;
    }

    WalletBatch batch(GetDatabase());
    if (!batch.WriteForwardContract(it->second)) {
        WalletLogPrintf("Warning: failed to persist margin vault for forward contract %s\n", contract_id.GetHex());
    }
    return true;
}

bool CWallet::VerifyAndPersistForwardVaults(const uint256& contract_id,
                                           const PartiallySignedTransaction& psbt,
                                           bool allow_open_discovery)
{
    if (!psbt.tx) {
        return false;
    }
    CTransactionRef tx = MakeTransactionRef(CTransaction(*psbt.tx));
    return VerifyAndPersistForwardVaults(contract_id, tx, allow_open_discovery);
}

bool CWallet::VerifyAndPersistForwardVaults(const uint256& contract_id,
                                           const CTransactionRef& tx,
                                           bool allow_open_discovery)
{
    LOCK(cs_wallet);

    auto it = m_forward_contracts.find(contract_id);
    if (it == m_forward_contracts.end()) {
        WalletLogPrintf("Warning: Contract %s not found for vault verification\n", contract_id.GetHex());
        return false;
    }

    ForwardContractRecord& record = it->second;
    const ForwardTerms& terms = record.terms;

    // Parse the transaction to extract vault outpoints
    const Txid txid = tx->GetHash();

    // Check contract lifecycle state
    const ForwardContractState lifecycle = record.DerivedState();
    const bool contract_is_accepted = (lifecycle == ForwardContractState::ACCEPTED);

    // CRITICAL GUARDRAIL: Only process transactions that match record.open_txid unless we explicitly
    // allow discovery (trusted contexts like adaptor.prepare or recovery helpers).
    const bool permit_discovery = allow_open_discovery && contract_is_accepted;
    bool should_update_open_txid = false;
    if (record.open_txid) {
        if (txid.ToUint256() != *record.open_txid) {
            if (permit_discovery) {
                WalletLogPrintf("Forward[%s]: Contract in ACCEPTED state, checking tx %s (stored open_txid=%s differs)\n",
                              contract_id.GetHex(),
                              txid.ToString(),
                              record.open_txid->GetHex());
                should_update_open_txid = true;
            } else {
                // Contract already OPENED - open_txid is authoritative, reject mismatches
                WalletLogPrintf("Forward[%s]: Skipping tx %s (expected open_txid=%s, contract state=%d)\n",
                              contract_id.GetHex(),
                              txid.ToString(),
                              record.open_txid->GetHex(),
                              static_cast<int>(lifecycle));
                return false;
            }
        } else {
            WalletLogPrintf("Forward[%s]: Processing covenant open tx %s (matches expected open_txid)\n",
                          contract_id.GetHex(),
                          txid.ToString());
        }
    } else {
        if (!permit_discovery) {
            WalletLogPrintf("Forward[%s]: open_txid missing, skipping tx %s (discovery disabled)\n",
                            contract_id.GetHex(),
                            txid.ToString());
            return false;
        }
        // open_txid not set - attempting discovery using trusted transaction
        WalletLogPrintf("Forward[%s]: open_txid missing for contract, attempting vault discovery from tx %s\n",
                      contract_id.GetHex(),
                      txid.ToString());
        should_update_open_txid = true;
    }

    // Default asset output value for non-native assets (0.001 BTC = 100k sats)
    constexpr CAmount DEFAULT_ASSET_OUTPUT_VALUE{DEFAULT_REPO_ASSET_OUTPUT_VALUE};

    // Look for outputs that match the expected vault scripts
    std::optional<std::pair<uint32_t, CAmount>> long_vault;
    std::optional<std::pair<uint32_t, CAmount>> short_vault;

    // Calculate expected vault amounts
    const CAmount expected_long = terms.long_party.margin_leg.is_native ?
        static_cast<CAmount>(terms.long_party.margin_leg.units) :
        DEFAULT_ASSET_OUTPUT_VALUE;
    const CAmount expected_short = terms.short_party.margin_leg.is_native ?
        static_cast<CAmount>(terms.short_party.margin_leg.units) :
        DEFAULT_ASSET_OUTPUT_VALUE;

    // Find vault outputs in the transaction
    // Note: We match by amount here. Future enhancement should validate against expected vault scripts.
    for (size_t i = 0; i < tx->vout.size(); ++i) {
        const CTxOut& output = tx->vout[i];

        // Check if this is a taproot output (v1 witness program with 32 bytes)
        int witversion;
        std::vector<unsigned char> witprogram;
        if (output.scriptPubKey.IsWitnessProgram(witversion, witprogram) &&
            witversion == 1 && witprogram.size() == 32) {
            // This is a taproot output
            // Match vaults by amount
            // NOTE: Because we now validate open_txid above, this amount-based matching is safe
            // (deposits can't interfere since they have different txids)
            if (!long_vault && output.nValue == expected_long) {
                long_vault = {static_cast<uint32_t>(i), output.nValue};
                WalletLogPrintf("Forward[%s]: Found long vault candidate at output %u (amount=%s)\n",
                              contract_id.GetHex(), i, FormatMoney(output.nValue));
            } else if (!short_vault && output.nValue == expected_short) {
                short_vault = {static_cast<uint32_t>(i), output.nValue};
                WalletLogPrintf("Forward[%s]: Found short vault candidate at output %u (amount=%s)\n",
                              contract_id.GetHex(), i, FormatMoney(output.nValue));
            }
        }
    }

    // Validate that we found both vaults (if we're processing the open_txid)
    if (record.open_txid && (!long_vault || !short_vault)) {
        WalletLogPrintf("ERROR: Failed to find both vaults in covenant tx %s for contract %s (long=%s, short=%s)\n",
                      txid.ToString(),
                      contract_id.GetHex(),
                      long_vault ? "found" : "MISSING",
                      short_vault ? "found" : "MISSING");
        return false;
    }

    // Persist vault outpoints if found
    bool updated = false;
    const auto persist_vault = [&](std::optional<COutPoint>& slot,
                                   CAmount& slot_value,
                                   const std::optional<std::pair<uint32_t, CAmount>>& located,
                                   const char* label) {
        if (!located) {
            return;
        }
        const COutPoint new_outpoint(txid, located->first);
        const bool changed_outpoint = !slot || slot->hash != new_outpoint.hash || slot->n != new_outpoint.n;
        const bool changed_value = slot_value != located->second;
        if (!changed_outpoint && !changed_value) {
            return;
        }
        const bool replacing = slot.has_value();
        slot = new_outpoint;
        slot_value = located->second;
        updated = true;
        WalletLogPrintf("%s %s vault for contract %s: %s:%d (amount: %s)\n",
                       replacing ? "Updated" : "Persisted",
                       label,
                       contract_id.GetHex(),
                       txid.ToString(),
                       located->first,
                       FormatMoney(located->second));
    };

    persist_vault(record.long_margin_vault, record.long_margin_value, long_vault, "long");
    persist_vault(record.short_margin_vault, record.short_margin_value, short_vault, "short");

    // If we're allowed to update open_txid (ACCEPTED contract with trusted tx)
    // and we successfully found both vaults, update open_txid to this transaction
    if (should_update_open_txid && long_vault && short_vault) {
        if (!record.open_txid || *record.open_txid != txid.ToUint256()) {
            WalletLogPrintf("Forward[%s]: Updating open_txid from %s to %s (found both vaults in ACCEPTED contract)\n",
                          contract_id.GetHex(),
                          record.open_txid ? record.open_txid->GetHex() : "unset",
                          txid.ToString());
            record.open_txid = txid.ToUint256();
            updated = true;
        }
    }

    if (updated) {
        WalletBatch batch(GetDatabase());
        if (!batch.WriteForwardContract(record)) {
            WalletLogPrintf("Warning: failed to persist vault metadata for contract %s\n",
                          contract_id.GetHex());
            return false;
        }
    }

    // Return true if we have both vaults persisted
    return record.long_margin_vault.has_value() && record.short_margin_vault.has_value();
}

std::optional<std::pair<uint256, ForwardSide>> CWallet::FindForwardContractByVault(const COutPoint& prevout) const
{
    AssertLockHeld(cs_wallet);
    for (const auto& [contract_id, record] : m_forward_contracts) {
        if (record.long_margin_vault && *record.long_margin_vault == prevout) {
            return std::make_pair(contract_id, ForwardSide::LONG);
        }
        if (record.short_margin_vault && *record.short_margin_vault == prevout) {
            return std::make_pair(contract_id, ForwardSide::SHORT);
        }
    }
    return std::nullopt;
}

bool CWallet::TransactionSpendsForwardVault(const ForwardContractRecord& record,
                                            const CTransactionRef& tx) const
{
    if (!tx) return false;

    const Txid txid = tx->GetHash();
    WalletLogPrintf("TransactionSpendsForwardVault: checking tx %s for contract %s\n",
                    txid.ToString(), record.contract_id.GetHex());

    // Check if transaction spends margin vaults
    for (const CTxIn& txin : tx->vin) {
        if (record.long_margin_vault && txin.prevout == *record.long_margin_vault) {
            WalletLogPrintf("  -> MATCH: spends long_margin_vault %s:%d\n",
                            record.long_margin_vault->hash.ToString(), record.long_margin_vault->n);
            return true;
        }
        if (record.short_margin_vault && txin.prevout == *record.short_margin_vault) {
            WalletLogPrintf("  -> MATCH: spends short_margin_vault %s:%d\n",
                            record.short_margin_vault->hash.ToString(), record.short_margin_vault->n);
            return true;
        }
    }

    // Check if transaction spends escrow vaults (created by self-delivery)
    // Escrow vaults are indexed in the vault registry by their scriptPubKey
    WalletLogPrintf("  Checking escrow vaults (tx has %d inputs)\n", tx->vin.size());

    for (const CTxIn& txin : tx->vin) {
        WalletLogPrintf("    Input %s:%d\n", txin.prevout.hash.ToString(), txin.prevout.n);

        // Get the previous output
        const CWalletTx* prev_wtx = GetWalletTx(Txid::FromUint256(txin.prevout.hash));
        if (!prev_wtx || txin.prevout.n >= prev_wtx->tx->vout.size()) {
            WalletLogPrintf("      -> prev tx not in wallet or invalid vout\n");
            continue;
        }

        const CTxOut& prev_out = prev_wtx->tx->vout[txin.prevout.n];

        // Check if this is a taproot output (potential escrow vault)
        int witness_version;
        std::vector<unsigned char> witness_program;
        if (prev_out.scriptPubKey.IsWitnessProgram(witness_version, witness_program) &&
            witness_version == 1 && witness_program.size() == 32) {

            WalletLogPrintf("      -> is taproot, checking vault registry\n");

            // Check if this scriptPubKey is a registered vault
            for (auto spk_man : GetAllScriptPubKeyMans()) {
                auto* desc_spkm = dynamic_cast<DescriptorScriptPubKeyMan*>(spk_man);
                if (!desc_spkm) continue;

                // Look up vault by the actual covenant scriptPubKey
                const auto vault_meta = desc_spkm->GetVaultMetadata(prev_out.scriptPubKey);

                if (vault_meta) {
                    WalletLogPrintf("         Found vault: contract=%s, role=%d\n",
                                    vault_meta->contract_id.GetHex(),
                                    static_cast<int>(vault_meta->role));

                    // Check if this vault belongs to this contract and is an escrow vault
                    if (vault_meta->contract_id == record.contract_id &&
                        (vault_meta->role == VaultRole::FORWARD_ESCROW_A ||
                         vault_meta->role == VaultRole::FORWARD_ESCROW_B)) {
                        WalletLogPrintf("  -> MATCH: spends escrow vault for this contract\n");
                        return true;
                    }
                }
            }
        } else {
            WalletLogPrintf("      -> not taproot\n");
        }
    }

    WalletLogPrintf("  -> NO MATCH\n");
    return false;
}

std::unique_ptr<SigningProvider> CWallet::GetSolvingProvider(const CScript& script) const
{
    SignatureData sigdata;
    return GetSolvingProvider(script, sigdata);
}

std::unique_ptr<SigningProvider> CWallet::GetSolvingProvider(const CScript& script, SignatureData& sigdata) const
{
    // Search the cache for relevant SPKMs instead of iterating m_spk_managers
    const auto& it = m_cached_spks.find(script);
    if (it != m_cached_spks.end()) {
        // All spkms for a given script must already be able to make a SigningProvider for the script, so just return the first one.
        Assume(it->second.at(0)->CanProvide(script, sigdata));
        return it->second.at(0)->GetSolvingProvider(script);
    }

    return nullptr;
}

std::vector<WalletDescriptor> CWallet::GetWalletDescriptors(const CScript& script) const
{
    std::vector<WalletDescriptor> descs;
    for (const auto spk_man: GetScriptPubKeyMans(script)) {
        if (const auto desc_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(spk_man)) {
            LOCK(desc_spk_man->cs_desc_man);
            descs.push_back(desc_spk_man->GetWalletDescriptor());
        }
    }
    return descs;
}

LegacyDataSPKM* CWallet::GetLegacyDataSPKM() const
{
    if (IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS)) {
        return nullptr;
    }
    auto it = m_internal_spk_managers.find(OutputType::LEGACY);
    if (it == m_internal_spk_managers.end()) return nullptr;
    return dynamic_cast<LegacyDataSPKM*>(it->second);
}

void CWallet::AddScriptPubKeyMan(const uint256& id, std::unique_ptr<ScriptPubKeyMan> spkm_man)
{
    // Add spkm_man to m_spk_managers before calling any method
    // that might access it.
    const auto& spkm = m_spk_managers[id] = std::move(spkm_man);

    // Update birth time if needed
    MaybeUpdateBirthTime(spkm->GetTimeFirstKey());
}

LegacyDataSPKM* CWallet::GetOrCreateLegacyDataSPKM()
{
    SetupLegacyScriptPubKeyMan();
    return GetLegacyDataSPKM();
}

void CWallet::SetupLegacyScriptPubKeyMan()
{
    if (!m_internal_spk_managers.empty() || !m_external_spk_managers.empty() || !m_spk_managers.empty() || IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS)) {
        return;
    }

    Assert(m_database->Format() == "bdb_ro" || m_database->Format() == "mock");
    std::unique_ptr<ScriptPubKeyMan> spk_manager = std::make_unique<LegacyDataSPKM>(*this);

    for (const auto& type : LEGACY_OUTPUT_TYPES) {
        m_internal_spk_managers[type] = spk_manager.get();
        m_external_spk_managers[type] = spk_manager.get();
    }
    uint256 id = spk_manager->GetID();
    AddScriptPubKeyMan(id, std::move(spk_manager));
}

bool CWallet::WithEncryptionKey(std::function<bool (const CKeyingMaterial&)> cb) const
{
    LOCK(cs_wallet);
    return cb(vMasterKey);
}

bool CWallet::HasEncryptionKeys() const
{
    return !mapMasterKeys.empty();
}

bool CWallet::HaveCryptedKeys() const
{
    for (const auto& spkm : GetAllScriptPubKeyMans()) {
        if (spkm->HaveCryptedKeys()) return true;
    }
    return false;
}

void CWallet::ConnectScriptPubKeyManNotifiers()
{
    for (const auto& spk_man : GetActiveScriptPubKeyMans()) {
        spk_man->NotifyCanGetAddressesChanged.connect(NotifyCanGetAddressesChanged);
        spk_man->NotifyFirstKeyTimeChanged.connect(std::bind(&CWallet::MaybeUpdateBirthTime, this, std::placeholders::_2));
    }
}

DescriptorScriptPubKeyMan& CWallet::LoadDescriptorScriptPubKeyMan(uint256 id, WalletDescriptor& desc)
{
    DescriptorScriptPubKeyMan* spk_manager;
    if (IsWalletFlagSet(WALLET_FLAG_EXTERNAL_SIGNER)) {
        spk_manager = new ExternalSignerScriptPubKeyMan(*this, desc, m_keypool_size);
    } else {
        spk_manager = new DescriptorScriptPubKeyMan(*this, desc, m_keypool_size);
    }
    AddScriptPubKeyMan(id, std::unique_ptr<ScriptPubKeyMan>(spk_manager));
    return *spk_manager;
}

DescriptorScriptPubKeyMan& CWallet::SetupDescriptorScriptPubKeyMan(WalletBatch& batch, const CExtKey& master_key, const OutputType& output_type, bool internal)
{
    AssertLockHeld(cs_wallet);
    auto spk_manager = std::unique_ptr<DescriptorScriptPubKeyMan>(new DescriptorScriptPubKeyMan(*this, m_keypool_size));
    if (IsCrypted()) {
        if (IsLocked()) {
            throw std::runtime_error(std::string(__func__) + ": Wallet is locked, cannot setup new descriptors");
        }
        if (!spk_manager->CheckDecryptionKey(vMasterKey) && !spk_manager->Encrypt(vMasterKey, &batch)) {
            throw std::runtime_error(std::string(__func__) + ": Could not encrypt new descriptors");
        }
    }
    spk_manager->SetupDescriptorGeneration(batch, master_key, output_type, internal);
    DescriptorScriptPubKeyMan* out = spk_manager.get();
    uint256 id = spk_manager->GetID();
    AddScriptPubKeyMan(id, std::move(spk_manager));
    AddActiveScriptPubKeyManWithDb(batch, id, output_type, internal);
    return *out;
}

void CWallet::SetupDescriptorScriptPubKeyMans(WalletBatch& batch, const CExtKey& master_key)
{
    AssertLockHeld(cs_wallet);
    for (bool internal : {false, true}) {
        for (OutputType t : OUTPUT_TYPES) {
            SetupDescriptorScriptPubKeyMan(batch, master_key, t, internal);
        }
    }
}

void CWallet::SetupOwnDescriptorScriptPubKeyMans(WalletBatch& batch)
{
    AssertLockHeld(cs_wallet);
    assert(!IsWalletFlagSet(WALLET_FLAG_EXTERNAL_SIGNER));
    // Make a seed
    CKey seed_key = GenerateRandomKey();
    CPubKey seed = seed_key.GetPubKey();
    assert(seed_key.VerifyPubKey(seed));

    // Get the extended key
    CExtKey master_key;
    master_key.SetSeed(seed_key);

    SetupDescriptorScriptPubKeyMans(batch, master_key);
}

void CWallet::SetupDescriptorScriptPubKeyMans()
{
    AssertLockHeld(cs_wallet);

    if (!IsWalletFlagSet(WALLET_FLAG_EXTERNAL_SIGNER)) {
        if (!RunWithinTxn(GetDatabase(), /*process_desc=*/"setup descriptors", [&](WalletBatch& batch) EXCLUSIVE_LOCKS_REQUIRED(cs_wallet){
            SetupOwnDescriptorScriptPubKeyMans(batch);
            return true;
        })) throw std::runtime_error("Error: cannot process db transaction for descriptors setup");
    } else {
        ExternalSigner signer = ExternalSignerScriptPubKeyMan::GetExternalSigner();

        // TODO: add account parameter
        int account = 0;
        UniValue signer_res = signer.GetDescriptors(account);

        if (!signer_res.isObject()) throw std::runtime_error(std::string(__func__) + ": Unexpected result");

        WalletBatch batch(GetDatabase());
        if (!batch.TxnBegin()) throw std::runtime_error("Error: cannot create db transaction for descriptors import");

        for (bool internal : {false, true}) {
            const UniValue& descriptor_vals = signer_res.find_value(internal ? "internal" : "receive");
            if (!descriptor_vals.isArray()) throw std::runtime_error(std::string(__func__) + ": Unexpected result");
            for (const UniValue& desc_val : descriptor_vals.get_array().getValues()) {
                const std::string& desc_str = desc_val.getValStr();
                FlatSigningProvider keys;
                std::string desc_error;
                auto descs = Parse(desc_str, keys, desc_error, false);
                if (descs.empty()) {
                    throw std::runtime_error(std::string(__func__) + ": Invalid descriptor \"" + desc_str + "\" (" + desc_error + ")");
                }
                auto& desc = descs.at(0);
                if (!desc->GetOutputType()) {
                    continue;
                }
                OutputType t =  *desc->GetOutputType();
                auto spk_manager = std::unique_ptr<ExternalSignerScriptPubKeyMan>(new ExternalSignerScriptPubKeyMan(*this, m_keypool_size));
                spk_manager->SetupDescriptor(batch, std::move(desc));
                uint256 id = spk_manager->GetID();
                AddScriptPubKeyMan(id, std::move(spk_manager));
                AddActiveScriptPubKeyManWithDb(batch, id, t, internal);
            }
        }

        // Ensure imported descriptors are committed to disk
        if (!batch.TxnCommit()) throw std::runtime_error("Error: cannot commit db transaction for descriptors import");
    }
}

void CWallet::AddActiveScriptPubKeyMan(uint256 id, OutputType type, bool internal)
{
    WalletBatch batch(GetDatabase());
    return AddActiveScriptPubKeyManWithDb(batch, id, type, internal);
}

void CWallet::AddActiveScriptPubKeyManWithDb(WalletBatch& batch, uint256 id, OutputType type, bool internal)
{
    if (!batch.WriteActiveScriptPubKeyMan(static_cast<uint8_t>(type), id, internal)) {
        throw std::runtime_error(std::string(__func__) + ": writing active ScriptPubKeyMan id failed");
    }
    LoadActiveScriptPubKeyMan(id, type, internal);
}

void CWallet::LoadActiveScriptPubKeyMan(uint256 id, OutputType type, bool internal)
{
    // Activating ScriptPubKeyManager for a given output and change type is incompatible with legacy wallets.
    // Legacy wallets have only one ScriptPubKeyManager and it's active for all output and change types.
    Assert(IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS));

    WalletLogPrintf("Setting spkMan to active: id = %s, type = %s, internal = %s\n", id.ToString(), FormatOutputType(type), internal ? "true" : "false");
    auto& spk_mans = internal ? m_internal_spk_managers : m_external_spk_managers;
    auto& spk_mans_other = internal ? m_external_spk_managers : m_internal_spk_managers;
    auto spk_man = m_spk_managers.at(id).get();
    spk_mans[type] = spk_man;

    const auto it = spk_mans_other.find(type);
    if (it != spk_mans_other.end() && it->second == spk_man) {
        spk_mans_other.erase(type);
    }

    NotifyCanGetAddressesChanged();
}

void CWallet::DeactivateScriptPubKeyMan(uint256 id, OutputType type, bool internal)
{
    auto spk_man = GetScriptPubKeyMan(type, internal);
    if (spk_man != nullptr && spk_man->GetID() == id) {
        WalletLogPrintf("Deactivate spkMan: id = %s, type = %s, internal = %s\n", id.ToString(), FormatOutputType(type), internal ? "true" : "false");
        WalletBatch batch(GetDatabase());
        if (!batch.EraseActiveScriptPubKeyMan(static_cast<uint8_t>(type), internal)) {
            throw std::runtime_error(std::string(__func__) + ": erasing active ScriptPubKeyMan id failed");
        }

        auto& spk_mans = internal ? m_internal_spk_managers : m_external_spk_managers;
        spk_mans.erase(type);
    }

    NotifyCanGetAddressesChanged();
}

DescriptorScriptPubKeyMan* CWallet::GetDescriptorScriptPubKeyMan(const WalletDescriptor& desc) const
{
    auto spk_man_pair = m_spk_managers.find(desc.id);

    if (spk_man_pair != m_spk_managers.end()) {
        // Try to downcast to DescriptorScriptPubKeyMan then check if the descriptors match
        DescriptorScriptPubKeyMan* spk_manager = dynamic_cast<DescriptorScriptPubKeyMan*>(spk_man_pair->second.get());
        if (spk_manager != nullptr && spk_manager->HasWalletDescriptor(desc)) {
            return spk_manager;
        }
    }

    return nullptr;
}

std::optional<bool> CWallet::IsInternalScriptPubKeyMan(ScriptPubKeyMan* spk_man) const
{
    // only active ScriptPubKeyMan can be internal
    if (!GetActiveScriptPubKeyMans().count(spk_man)) {
        return std::nullopt;
    }

    const auto desc_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(spk_man);
    if (!desc_spk_man) {
        throw std::runtime_error(std::string(__func__) + ": unexpected ScriptPubKeyMan type.");
    }

    LOCK(desc_spk_man->cs_desc_man);
    const auto& type = desc_spk_man->GetWalletDescriptor().descriptor->GetOutputType();
    assert(type.has_value());

    return GetScriptPubKeyMan(*type, /* internal= */ true) == desc_spk_man;
}

util::Result<ScriptPubKeyMan*> CWallet::AddWalletDescriptor(WalletDescriptor& desc, const FlatSigningProvider& signing_provider, const std::string& label, bool internal)
{
    AssertLockHeld(cs_wallet);

    if (!IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS)) {
        WalletLogPrintf("Cannot add WalletDescriptor to a non-descriptor wallet\n");
        return nullptr;
    }

    auto spk_man = GetDescriptorScriptPubKeyMan(desc);
    if (spk_man) {
        WalletLogPrintf("Update existing descriptor: %s\n", desc.descriptor->ToString());
        if (auto spkm_res = spk_man->UpdateWalletDescriptor(desc); !spkm_res) {
            return util::Error{util::ErrorString(spkm_res)};
        }
    } else {
        auto new_spk_man = std::unique_ptr<DescriptorScriptPubKeyMan>(new DescriptorScriptPubKeyMan(*this, desc, m_keypool_size));
        spk_man = new_spk_man.get();

        // Save the descriptor to memory
        uint256 id = new_spk_man->GetID();
        AddScriptPubKeyMan(id, std::move(new_spk_man));
    }

    // Add the private keys to the descriptor
    for (const auto& entry : signing_provider.keys) {
        const CKey& key = entry.second;
        spk_man->AddDescriptorKey(key, key.GetPubKey());
    }

    // Top up key pool, the manager will generate new scriptPubKeys internally
    if (!spk_man->TopUp()) {
        WalletLogPrintf("Could not top up scriptPubKeys\n");
        return nullptr;
    }

    // Apply the label if necessary
    // Note: we disable labels for ranged descriptors
    if (!desc.descriptor->IsRange()) {
        auto script_pub_keys = spk_man->GetScriptPubKeys();
        if (script_pub_keys.empty()) {
            WalletLogPrintf("Could not generate scriptPubKeys (cache is empty)\n");
            return nullptr;
        }

        if (!internal) {
            for (const auto& script : script_pub_keys) {
                CTxDestination dest;
                if (ExtractDestination(script, dest)) {
                    SetAddressBook(dest, label, AddressPurpose::RECEIVE);
                }
            }
        }
    }

    // Save the descriptor to DB
    spk_man->WriteDescriptor();

    return spk_man;
}

bool CWallet::MigrateToSQLite(bilingual_str& error)
{
    AssertLockHeld(cs_wallet);

    WalletLogPrintf("Migrating wallet storage database from BerkeleyDB to SQLite.\n");

    if (m_database->Format() == "sqlite") {
        error = _("Error: This wallet already uses SQLite");
        return false;
    }

    // Get all of the records for DB type migration
    std::unique_ptr<DatabaseBatch> batch = m_database->MakeBatch();
    std::unique_ptr<DatabaseCursor> cursor = batch->GetNewCursor();
    std::vector<std::pair<SerializeData, SerializeData>> records;
    if (!cursor) {
        error = _("Error: Unable to begin reading all records in the database");
        return false;
    }
    DatabaseCursor::Status status = DatabaseCursor::Status::FAIL;
    while (true) {
        DataStream ss_key{};
        DataStream ss_value{};
        status = cursor->Next(ss_key, ss_value);
        if (status != DatabaseCursor::Status::MORE) {
            break;
        }
        SerializeData key(ss_key.begin(), ss_key.end());
        SerializeData value(ss_value.begin(), ss_value.end());
        records.emplace_back(key, value);
    }
    cursor.reset();
    batch.reset();
    if (status != DatabaseCursor::Status::DONE) {
        error = _("Error: Unable to read all records in the database");
        return false;
    }

    // Close this database and delete the file
    fs::path db_path = fs::PathFromString(m_database->Filename());
    m_database->Close();
    fs::remove(db_path);

    // Generate the path for the location of the migrated wallet
    // Wallets that are plain files rather than wallet directories will be migrated to be wallet directories.
    const fs::path wallet_path = fsbridge::AbsPathJoin(GetWalletDir(), fs::PathFromString(m_name));

    // Make new DB
    DatabaseOptions opts;
    opts.require_create = true;
    opts.require_format = DatabaseFormat::SQLITE;
    DatabaseStatus db_status;
    std::unique_ptr<WalletDatabase> new_db = MakeDatabase(wallet_path, opts, db_status, error);
    assert(new_db); // This is to prevent doing anything further with this wallet. The original file was deleted, but a backup exists.
    m_database.reset();
    m_database = std::move(new_db);

    // Write existing records into the new DB
    batch = m_database->MakeBatch();
    bool began = batch->TxnBegin();
    assert(began); // This is a critical error, the new db could not be written to. The original db exists as a backup, but we should not continue execution.
    for (const auto& [key, value] : records) {
        if (!batch->Write(std::span{key}, std::span{value})) {
            batch->TxnAbort();
            m_database->Close();
            fs::remove(m_database->Filename());
            assert(false); // This is a critical error, the new db could not be written to. The original db exists as a backup, but we should not continue execution.
        }
    }
    bool committed = batch->TxnCommit();
    assert(committed); // This is a critical error, the new db could not be written to. The original db exists as a backup, but we should not continue execution.
    return true;
}

std::optional<MigrationData> CWallet::GetDescriptorsForLegacy(bilingual_str& error) const
{
    AssertLockHeld(cs_wallet);

    LegacyDataSPKM* legacy_spkm = GetLegacyDataSPKM();
    if (!Assume(legacy_spkm)) {
        // This shouldn't happen
        error = Untranslated(STR_INTERNAL_BUG("Error: Legacy wallet data missing"));
        return std::nullopt;
    }

    std::optional<MigrationData> res = legacy_spkm->MigrateToDescriptor();
    if (res == std::nullopt) {
        error = _("Error: Unable to produce descriptors for this legacy wallet. Make sure to provide the wallet's passphrase if it is encrypted.");
        return std::nullopt;
    }
    return res;
}

util::Result<void> CWallet::ApplyMigrationData(WalletBatch& local_wallet_batch, MigrationData& data)
{
    AssertLockHeld(cs_wallet);

    LegacyDataSPKM* legacy_spkm = GetLegacyDataSPKM();
    if (!Assume(legacy_spkm)) {
        // This shouldn't happen
        return util::Error{Untranslated(STR_INTERNAL_BUG("Error: Legacy wallet data missing"))};
    }

    // Get all invalid or non-watched scripts that will not be migrated
    std::set<CTxDestination> not_migrated_dests;
    for (const auto& script : legacy_spkm->GetNotMineScriptPubKeys()) {
        CTxDestination dest;
        if (ExtractDestination(script, dest)) not_migrated_dests.emplace(dest);
    }

    // When the legacy wallet has no spendable scripts, the main wallet will be empty, leaving its script cache empty as well.
    // The watch-only and/or solvable wallet(s) will contain the scripts in their respective caches.
    if (!data.desc_spkms.empty()) Assume(!m_cached_spks.empty());
    if (!data.watch_descs.empty()) Assume(!data.watchonly_wallet->m_cached_spks.empty());
    if (!data.solvable_descs.empty()) Assume(!data.solvable_wallet->m_cached_spks.empty());

    for (auto& desc_spkm : data.desc_spkms) {
        if (m_spk_managers.count(desc_spkm->GetID()) > 0) {
            return util::Error{_("Error: Duplicate descriptors created during migration. Your wallet may be corrupted.")};
        }
        uint256 id = desc_spkm->GetID();
        AddScriptPubKeyMan(id, std::move(desc_spkm));
    }

    // Remove the LegacyScriptPubKeyMan from disk
    if (!legacy_spkm->DeleteRecordsWithDB(local_wallet_batch)) {
        return util::Error{_("Error: cannot remove legacy wallet records")};
    }

    // Remove the LegacyScriptPubKeyMan from memory
    m_spk_managers.erase(legacy_spkm->GetID());
    m_external_spk_managers.clear();
    m_internal_spk_managers.clear();

    // Setup new descriptors
    SetWalletFlagWithDB(local_wallet_batch, WALLET_FLAG_DESCRIPTORS);
    if (!IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
        // Use the existing master key if we have it
        if (data.master_key.key.IsValid()) {
            SetupDescriptorScriptPubKeyMans(local_wallet_batch, data.master_key);
        } else {
            // Setup with a new seed if we don't.
            SetupOwnDescriptorScriptPubKeyMans(local_wallet_batch);
        }
    }

    // Get best block locator so that we can copy it to the watchonly and solvables
    CBlockLocator best_block_locator;
    if (!local_wallet_batch.ReadBestBlock(best_block_locator)) {
        return util::Error{_("Error: Unable to read wallet's best block locator record")};
    }

    // Check if the transactions in the wallet are still ours. Either they belong here, or they belong in the watchonly wallet.
    // We need to go through these in the tx insertion order so that lookups to spends works.
    std::vector<Txid> txids_to_delete;
    std::unique_ptr<WalletBatch> watchonly_batch;
    if (data.watchonly_wallet) {
        watchonly_batch = std::make_unique<WalletBatch>(data.watchonly_wallet->GetDatabase());
        if (!watchonly_batch->TxnBegin()) return util::Error{strprintf(_("Error: database transaction cannot be executed for wallet %s"), data.watchonly_wallet->GetName())};
        // Copy the next tx order pos to the watchonly wallet
        LOCK(data.watchonly_wallet->cs_wallet);
        data.watchonly_wallet->nOrderPosNext = nOrderPosNext;
        watchonly_batch->WriteOrderPosNext(data.watchonly_wallet->nOrderPosNext);
        // Write the best block locator to avoid rescanning on reload
        if (!watchonly_batch->WriteBestBlock(best_block_locator)) {
            return util::Error{_("Error: Unable to write watchonly wallet best block locator record")};
        }
    }
    std::unique_ptr<WalletBatch> solvables_batch;
    if (data.solvable_wallet) {
        solvables_batch = std::make_unique<WalletBatch>(data.solvable_wallet->GetDatabase());
        if (!solvables_batch->TxnBegin()) return util::Error{strprintf(_("Error: database transaction cannot be executed for wallet %s"), data.solvable_wallet->GetName())};
        // Write the best block locator to avoid rescanning on reload
        if (!solvables_batch->WriteBestBlock(best_block_locator)) {
            return util::Error{_("Error: Unable to write solvable wallet best block locator record")};
        }
    }
    for (const auto& [_pos, wtx] : wtxOrdered) {
        // Check it is the watchonly wallet's
        // solvable_wallet doesn't need to be checked because transactions for those scripts weren't being watched for
        bool is_mine = IsMine(*wtx->tx) || IsFromMe(*wtx->tx);
        if (data.watchonly_wallet) {
            LOCK(data.watchonly_wallet->cs_wallet);
            if (data.watchonly_wallet->IsMine(*wtx->tx) || data.watchonly_wallet->IsFromMe(*wtx->tx)) {
                // Add to watchonly wallet
                const Txid& hash = wtx->GetHash();
                const CWalletTx& to_copy_wtx = *wtx;
                if (!data.watchonly_wallet->LoadToWallet(hash, [&](CWalletTx& ins_wtx, bool new_tx) EXCLUSIVE_LOCKS_REQUIRED(data.watchonly_wallet->cs_wallet) {
                    if (!new_tx) return false;
                    ins_wtx.SetTx(to_copy_wtx.tx);
                    ins_wtx.CopyFrom(to_copy_wtx);
                    return true;
                })) {
                    return util::Error{strprintf(_("Error: Could not add watchonly tx %s to watchonly wallet"), wtx->GetHash().GetHex())};
                }
                watchonly_batch->WriteTx(data.watchonly_wallet->mapWallet.at(hash));
                // Mark as to remove from the migrated wallet only if it does not also belong to it
                if (!is_mine) {
                    txids_to_delete.push_back(hash);
                }
                continue;
            }
        }
        if (!is_mine) {
            // Both not ours and not in the watchonly wallet
            return util::Error{strprintf(_("Error: Transaction %s in wallet cannot be identified to belong to migrated wallets"), wtx->GetHash().GetHex())};
        }
    }

    // Do the removes
    if (txids_to_delete.size() > 0) {
        if (auto res = RemoveTxs(local_wallet_batch, txids_to_delete); !res) {
            return util::Error{_("Error: Could not delete watchonly transactions. ") + util::ErrorString(res)};
        }
    }

    // Pair external wallets with their corresponding db handler
    std::vector<std::pair<std::shared_ptr<CWallet>, std::unique_ptr<WalletBatch>>> wallets_vec;
    if (data.watchonly_wallet) wallets_vec.emplace_back(data.watchonly_wallet, std::move(watchonly_batch));
    if (data.solvable_wallet) wallets_vec.emplace_back(data.solvable_wallet, std::move(solvables_batch));

    // Write address book entry to disk
    auto func_store_addr = [](WalletBatch& batch, const CTxDestination& dest, const CAddressBookData& entry) {
        auto address{EncodeDestination(dest)};
        if (entry.purpose) batch.WritePurpose(address, PurposeToString(*entry.purpose));
        if (entry.label) batch.WriteName(address, *entry.label);
        for (const auto& [id, request] : entry.receive_requests) {
            batch.WriteAddressReceiveRequest(dest, id, request);
        }
        if (entry.previously_spent) batch.WriteAddressPreviouslySpent(dest, true);
    };

    // Check the address book data in the same way we did for transactions
    std::vector<CTxDestination> dests_to_delete;
    for (const auto& [dest, record] : m_address_book) {
        // Ensure "receive" entries that are no longer part of the original wallet are transferred to another wallet
        // Entries for everything else ("send") will be cloned to all wallets.
        bool require_transfer = record.purpose == AddressPurpose::RECEIVE && !IsMine(dest);
        bool copied = false;
        for (auto& [wallet, batch] : wallets_vec) {
            LOCK(wallet->cs_wallet);
            if (require_transfer && !wallet->IsMine(dest)) continue;

            // Copy the entire address book entry
            wallet->m_address_book[dest] = record;
            func_store_addr(*batch, dest, record);

            copied = true;
            // Only delete 'receive' records that are no longer part of the original wallet
            if (require_transfer) {
                dests_to_delete.push_back(dest);
                break;
            }
        }

        // Fail immediately if we ever found an entry that was ours and cannot be transferred
        // to any of the created wallets (watch-only, solvable).
        // Means that no inferred descriptor maps to the stored entry. Which mustn't happen.
        if (require_transfer && !copied) {

            // Skip invalid/non-watched scripts that will not be migrated
            if (not_migrated_dests.count(dest) > 0) {
                dests_to_delete.push_back(dest);
                continue;
            }

            return util::Error{_("Error: Address book data in wallet cannot be identified to belong to migrated wallets")};
        }
    }

    // Persist external wallets address book entries
    for (auto& [wallet, batch] : wallets_vec) {
        if (!batch->TxnCommit()) {
            return util::Error{strprintf(_("Error: Unable to write data to disk for wallet %s"), wallet->GetName())};
        }
    }

    // Remove the things to delete in this wallet
    if (dests_to_delete.size() > 0) {
        for (const auto& dest : dests_to_delete) {
            if (!DelAddressBookWithDB(local_wallet_batch, dest)) {
                return util::Error{_("Error: Unable to remove watchonly address book data")};
            }
        }
    }

    return {}; // all good
}

bool CWallet::CanGrindR() const
{
    return !IsWalletFlagSet(WALLET_FLAG_EXTERNAL_SIGNER);
}

bool DoMigration(CWallet& wallet, WalletContext& context, bilingual_str& error, MigrationResult& res) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    AssertLockHeld(wallet.cs_wallet);

    // Get all of the descriptors from the legacy wallet
    std::optional<MigrationData> data = wallet.GetDescriptorsForLegacy(error);
    if (data == std::nullopt) return false;

    // Create the watchonly and solvable wallets if necessary
    if (data->watch_descs.size() > 0 || data->solvable_descs.size() > 0) {
        DatabaseOptions options;
        options.require_existing = false;
        options.require_create = true;
        options.require_format = DatabaseFormat::SQLITE;

        WalletContext empty_context;
        empty_context.args = context.args;

        // Make the wallets
        options.create_flags = WALLET_FLAG_DISABLE_PRIVATE_KEYS | WALLET_FLAG_BLANK_WALLET | WALLET_FLAG_DESCRIPTORS;
        if (wallet.IsWalletFlagSet(WALLET_FLAG_AVOID_REUSE)) {
            options.create_flags |= WALLET_FLAG_AVOID_REUSE;
        }
        if (wallet.IsWalletFlagSet(WALLET_FLAG_KEY_ORIGIN_METADATA)) {
            options.create_flags |= WALLET_FLAG_KEY_ORIGIN_METADATA;
        }
        if (data->watch_descs.size() > 0) {
            wallet.WalletLogPrintf("Making a new watchonly wallet containing the watched scripts\n");

            DatabaseStatus status;
            std::vector<bilingual_str> warnings;
            std::string wallet_name = wallet.GetName() + "_watchonly";
            std::unique_ptr<WalletDatabase> database = MakeWalletDatabase(wallet_name, options, status, error);
            if (!database) {
                error = strprintf(_("Wallet file creation failed: %s"), error);
                return false;
            }

            data->watchonly_wallet = CWallet::Create(empty_context, wallet_name, std::move(database), options.create_flags, error, warnings);
            if (!data->watchonly_wallet) {
                error = _("Error: Failed to create new watchonly wallet");
                return false;
            }
            res.watchonly_wallet = data->watchonly_wallet;
            LOCK(data->watchonly_wallet->cs_wallet);

            // Parse the descriptors and add them to the new wallet
            for (const auto& [desc_str, creation_time] : data->watch_descs) {
                // Parse the descriptor
                FlatSigningProvider keys;
                std::string parse_err;
                std::vector<std::unique_ptr<Descriptor>> descs = Parse(desc_str, keys, parse_err, /* require_checksum */ true);
                assert(descs.size() == 1); // It shouldn't be possible to have the LegacyScriptPubKeyMan make an invalid descriptor or a multipath descriptors
                assert(!descs.at(0)->IsRange()); // It shouldn't be possible to have LegacyScriptPubKeyMan make a ranged watchonly descriptor

                // Add to the wallet
                WalletDescriptor w_desc(std::move(descs.at(0)), creation_time, 0, 0, 0);
                if (auto spkm_res = data->watchonly_wallet->AddWalletDescriptor(w_desc, keys, "", false); !spkm_res) {
                    throw std::runtime_error(util::ErrorString(spkm_res).original);
                }
            }

            // Add the wallet to settings
            UpdateWalletSetting(*context.chain, wallet_name, /*load_on_startup=*/true, warnings);
        }
        if (data->solvable_descs.size() > 0) {
            wallet.WalletLogPrintf("Making a new watchonly wallet containing the unwatched solvable scripts\n");

            DatabaseStatus status;
            std::vector<bilingual_str> warnings;
            std::string wallet_name = wallet.GetName() + "_solvables";
            std::unique_ptr<WalletDatabase> database = MakeWalletDatabase(wallet_name, options, status, error);
            if (!database) {
                error = strprintf(_("Wallet file creation failed: %s"), error);
                return false;
            }

            data->solvable_wallet = CWallet::Create(empty_context, wallet_name, std::move(database), options.create_flags, error, warnings);
            if (!data->solvable_wallet) {
                error = _("Error: Failed to create new watchonly wallet");
                return false;
            }
            res.solvables_wallet = data->solvable_wallet;
            LOCK(data->solvable_wallet->cs_wallet);

            // Parse the descriptors and add them to the new wallet
            for (const auto& [desc_str, creation_time] : data->solvable_descs) {
                // Parse the descriptor
                FlatSigningProvider keys;
                std::string parse_err;
                std::vector<std::unique_ptr<Descriptor>> descs = Parse(desc_str, keys, parse_err, /* require_checksum */ true);
                assert(descs.size() == 1); // It shouldn't be possible to have the LegacyScriptPubKeyMan make an invalid descriptor or a multipath descriptors
                assert(!descs.at(0)->IsRange()); // It shouldn't be possible to have LegacyScriptPubKeyMan make a ranged watchonly descriptor

                // Add to the wallet
                WalletDescriptor w_desc(std::move(descs.at(0)), creation_time, 0, 0, 0);
                if (auto spkm_res = data->solvable_wallet->AddWalletDescriptor(w_desc, keys, "", false); !spkm_res) {
                    throw std::runtime_error(util::ErrorString(spkm_res).original);
                }
            }

            // Add the wallet to settings
            UpdateWalletSetting(*context.chain, wallet_name, /*load_on_startup=*/true, warnings);
        }
    }

    // Add the descriptors to wallet, remove LegacyScriptPubKeyMan, and cleanup txs and address book data
    return RunWithinTxn(wallet.GetDatabase(), /*process_desc=*/"apply migration process", [&](WalletBatch& batch) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet){
        if (auto res_migration = wallet.ApplyMigrationData(batch, *data); !res_migration) {
            error = util::ErrorString(res_migration);
            return false;
        }
        wallet.WalletLogPrintf("Wallet migration complete.\n");
        return true;
    });
}

util::Result<MigrationResult> MigrateLegacyToDescriptor(const std::string& wallet_name, const SecureString& passphrase, WalletContext& context)
{
    std::vector<bilingual_str> warnings;
    bilingual_str error;

    // If the wallet is still loaded, unload it so that nothing else tries to use it while we're changing it
    bool was_loaded = false;
    if (auto wallet = GetWallet(context, wallet_name)) {
        if (wallet->IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS)) {
            return util::Error{_("Error: This wallet is already a descriptor wallet")};
        }

        // Flush chain state before unloading wallet
        CBlockLocator locator;
        WITH_LOCK(wallet->cs_wallet, context.chain->findBlock(wallet->GetLastBlockHash(), FoundBlock().locator(locator)));
        if (!locator.IsNull()) wallet->chainStateFlushed(ChainstateRole::NORMAL, locator);

        if (!RemoveWallet(context, wallet, /*load_on_start=*/std::nullopt, warnings)) {
            return util::Error{_("Unable to unload the wallet before migrating")};
        }
        WaitForDeleteWallet(std::move(wallet));
        was_loaded = true;
    } else {
        // Check if the wallet is BDB
        const auto& wallet_path = GetWalletPath(wallet_name);
        if (!wallet_path) {
            return util::Error{util::ErrorString(wallet_path)};
        }
        if (!fs::exists(*wallet_path)) {
            return util::Error{_("Error: Wallet does not exist")};
        }
        if (!IsBDBFile(BDBDataFile(*wallet_path))) {
            return util::Error{_("Error: This wallet is already a descriptor wallet")};
        }
    }

    // Load the wallet but only in the context of this function.
    // No signals should be connected nor should anything else be aware of this wallet
    WalletContext empty_context;
    empty_context.args = context.args;
    DatabaseOptions options;
    options.require_existing = true;
    options.require_format = DatabaseFormat::BERKELEY_RO;
    DatabaseStatus status;
    std::unique_ptr<WalletDatabase> database = MakeWalletDatabase(wallet_name, options, status, error);
    if (!database) {
        return util::Error{Untranslated("Wallet file verification failed.") + Untranslated(" ") + error};
    }

    // Make the local wallet
    std::shared_ptr<CWallet> local_wallet = CWallet::Create(empty_context, wallet_name, std::move(database), options.create_flags, error, warnings);
    if (!local_wallet) {
        return util::Error{Untranslated("Wallet loading failed.") + Untranslated(" ") + error};
    }

    return MigrateLegacyToDescriptor(std::move(local_wallet), passphrase, context, was_loaded);
}

util::Result<MigrationResult> MigrateLegacyToDescriptor(std::shared_ptr<CWallet> local_wallet, const SecureString& passphrase, WalletContext& context, bool was_loaded)
{
    MigrationResult res;
    bilingual_str error;
    std::vector<bilingual_str> warnings;

    DatabaseOptions options;
    options.require_existing = true;
    DatabaseStatus status;

    const std::string wallet_name = local_wallet->GetName();

    // Helper to reload as normal for some of our exit scenarios
    const auto& reload_wallet = [&](std::shared_ptr<CWallet>& to_reload) {
        assert(to_reload.use_count() == 1);
        std::string name = to_reload->GetName();
        to_reload.reset();
        to_reload = LoadWallet(context, name, /*load_on_start=*/std::nullopt, options, status, error, warnings);
        return to_reload != nullptr;
    };

    // Before anything else, check if there is something to migrate.
    if (local_wallet->IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS)) {
        if (was_loaded) {
            reload_wallet(local_wallet);
        }
        return util::Error{_("Error: This wallet is already a descriptor wallet")};
    }

    // Make a backup of the DB
    fs::path this_wallet_dir = fs::absolute(fs::PathFromString(local_wallet->GetDatabase().Filename())).parent_path();
    fs::path backup_filename = fs::PathFromString(strprintf("%s_%d.legacy.bak", (wallet_name.empty() ? "default_wallet" : wallet_name), GetTime()));
    fs::path backup_path = this_wallet_dir / backup_filename;
    if (!local_wallet->BackupWallet(fs::PathToString(backup_path))) {
        if (was_loaded) {
            reload_wallet(local_wallet);
        }
        return util::Error{_("Error: Unable to make a backup of your wallet")};
    }
    res.backup_path = backup_path;

    bool success = false;

    // Unlock the wallet if needed
    if (local_wallet->IsLocked() && !local_wallet->Unlock(passphrase)) {
        if (was_loaded) {
            reload_wallet(local_wallet);
        }
        if (passphrase.find('\0') == std::string::npos) {
            return util::Error{Untranslated("Error: Wallet decryption failed, the wallet passphrase was not provided or was incorrect.")};
        } else {
            return util::Error{Untranslated("Error: Wallet decryption failed, the wallet passphrase entered was incorrect. "
                                            "The passphrase contains a null character (ie - a zero byte). "
                                            "If this passphrase was set with a version of this software prior to 25.0, "
                                            "please try again with only the characters up to — but not including — "
                                            "the first null character.")};
        }
    }

    {
        LOCK(local_wallet->cs_wallet);
        // First change to using SQLite
        if (!local_wallet->MigrateToSQLite(error)) return util::Error{error};

        // Do the migration of keys and scripts for non-empty wallets, and cleanup if it fails
        if (HasLegacyRecords(*local_wallet)) {
            success = DoMigration(*local_wallet, context, error, res);
        } else {
            // Make sure that descriptors flag is actually set
            local_wallet->SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
            success = true;
        }
    }

    // In case of reloading failure, we need to remember the wallet dirs to remove
    // Set is used as it may be populated with the same wallet directory paths multiple times,
    // both before and after reloading. This ensures the set is complete even if one of the wallets
    // fails to reload.
    std::set<fs::path> wallet_dirs;
    if (success) {
        // Migration successful, unload all wallets locally, then reload them.
        // Reload the main wallet
        wallet_dirs.insert(fs::PathFromString(local_wallet->GetDatabase().Filename()).parent_path());
        success = reload_wallet(local_wallet);
        res.wallet = local_wallet;
        res.wallet_name = wallet_name;
        if (success && res.watchonly_wallet) {
            // Reload watchonly
            wallet_dirs.insert(fs::PathFromString(res.watchonly_wallet->GetDatabase().Filename()).parent_path());
            success = reload_wallet(res.watchonly_wallet);
        }
        if (success && res.solvables_wallet) {
            // Reload solvables
            wallet_dirs.insert(fs::PathFromString(res.solvables_wallet->GetDatabase().Filename()).parent_path());
            success = reload_wallet(res.solvables_wallet);
        }
    }
    if (!success) {
        // Migration failed, cleanup
        // Before deleting the wallet's directory, copy the backup file to the top-level wallets dir
        fs::path temp_backup_location = fsbridge::AbsPathJoin(GetWalletDir(), backup_filename);
        fs::copy_file(backup_path, temp_backup_location, fs::copy_options::none);

        // Make list of wallets to cleanup
        std::vector<std::shared_ptr<CWallet>> created_wallets;
        if (local_wallet) created_wallets.push_back(std::move(local_wallet));
        if (res.watchonly_wallet) created_wallets.push_back(std::move(res.watchonly_wallet));
        if (res.solvables_wallet) created_wallets.push_back(std::move(res.solvables_wallet));

        // Get the directories to remove after unloading
        for (std::shared_ptr<CWallet>& w : created_wallets) {
            wallet_dirs.emplace(fs::PathFromString(w->GetDatabase().Filename()).parent_path());
        }

        // Unload the wallets
        for (std::shared_ptr<CWallet>& w : created_wallets) {
            if (w->HaveChain()) {
                // Unloading for wallets that were loaded for normal use
                if (!RemoveWallet(context, w, /*load_on_start=*/false)) {
                    error += _("\nUnable to cleanup failed migration");
                    return util::Error{error};
                }
                WaitForDeleteWallet(std::move(w));
            } else {
                // Unloading for wallets in local context
                assert(w.use_count() == 1);
                w.reset();
            }
        }

        // Delete the wallet directories
        for (const fs::path& dir : wallet_dirs) {
            fs::remove_all(dir);
        }

        // Restore the backup
        // Convert the backup file to the wallet db file by renaming it and moving it into the wallet's directory.
        // Reload it into memory if the wallet was previously loaded.
        bilingual_str restore_error;
        const auto& ptr_wallet = RestoreWallet(context, temp_backup_location, wallet_name, /*load_on_start=*/std::nullopt, status, restore_error, warnings, /*load_after_restore=*/was_loaded);
        if (!restore_error.empty()) {
            error += restore_error + _("\nUnable to restore backup of wallet.");
            return util::Error{error};
        }

        // The wallet directory has been restored, but just in case, copy the previously created backup to the wallet dir
        fs::copy_file(temp_backup_location, backup_path, fs::copy_options::none);
        fs::remove(temp_backup_location);

        // Verify that there is no dangling wallet: when the wallet wasn't loaded before, expect null.
        // This check is performed after restoration to avoid an early error before saving the backup.
        bool wallet_reloaded = ptr_wallet != nullptr;
        assert(was_loaded == wallet_reloaded);

        return util::Error{error};
    }
    return res;
}

void CWallet::CacheNewScriptPubKeys(const std::set<CScript>& spks, ScriptPubKeyMan* spkm)
{
    for (const auto& script : spks) {
        m_cached_spks[script].push_back(spkm);
    }
}

void CWallet::TopUpCallback(const std::set<CScript>& spks, ScriptPubKeyMan* spkm)
{
    // Update scriptPubKey cache
    CacheNewScriptPubKeys(spks, spkm);
}

std::set<CExtPubKey> CWallet::GetActiveHDPubKeys() const
{
    AssertLockHeld(cs_wallet);

    Assert(IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS));

    std::set<CExtPubKey> active_xpubs;
    for (const auto& spkm : GetActiveScriptPubKeyMans()) {
        const DescriptorScriptPubKeyMan* desc_spkm = dynamic_cast<DescriptorScriptPubKeyMan*>(spkm);
        assert(desc_spkm);
        LOCK(desc_spkm->cs_desc_man);
        WalletDescriptor w_desc = desc_spkm->GetWalletDescriptor();

        std::set<CPubKey> desc_pubkeys;
        std::set<CExtPubKey> desc_xpubs;
        w_desc.descriptor->GetPubKeys(desc_pubkeys, desc_xpubs);
        active_xpubs.merge(std::move(desc_xpubs));
    }
    return active_xpubs;
}

std::optional<CKey> CWallet::GetKey(const CKeyID& keyid) const
{
    Assert(IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS));

    for (const auto& spkm : GetAllScriptPubKeyMans()) {
        const DescriptorScriptPubKeyMan* desc_spkm = dynamic_cast<DescriptorScriptPubKeyMan*>(spkm);
        assert(desc_spkm);
        LOCK(desc_spkm->cs_desc_man);
        if (std::optional<CKey> key = desc_spkm->GetKey(keyid)) {
            return key;
        }
    }
    return std::nullopt;
}

CWallet::CWallet(interfaces::Chain* chain, const std::string& name, std::unique_ptr<WalletDatabase> database)
    : m_chain(chain),
      m_name(name),
      m_database(std::move(database))
{
}

CWallet::~CWallet()
{
    // Should not have slots connected at this point.
    assert(NotifyUnload.empty());
}

pricing::PricingContext& CWallet::GetPricingContext() const
{
    std::call_once(m_pricing_context_once, [this]() {
        if (m_pricing_context) {
            return;
        }
        auto ctx = std::make_unique<pricing::PricingContext>(*const_cast<CWallet*>(this));
        ctx->LoadFromDB();
        m_pricing_context = std::move(ctx);
    });
    return *m_pricing_context;
}

} // namespace wallet
