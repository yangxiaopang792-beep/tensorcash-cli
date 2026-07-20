// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <wallet/walletdb.h>

#include <common/system.h>
#include <wallet/vaultregistry.h>
#include <key_io.h>
#include <protocol.h>
#include <script/script.h>
#include <serialize.h>
#include <sync.h>
#include <util/bip32.h>
#include <util/check.h>
#include <util/fs.h>
#include <util/transaction_identifier.h>
#include <util/time.h>
#include <util/translation.h>
#include <wallet/migrate.h>
#include <wallet/sqlite.h>
#include <wallet/wallet.h>

#include <atomic>
#include <optional>
#include <string>

namespace wallet {
namespace DBKeys {
const std::string ACENTRY{"acentry"};
const std::string ACTIVEEXTERNALSPK{"activeexternalspk"};
const std::string ACTIVEINTERNALSPK{"activeinternalspk"};
const std::string BESTBLOCK_NOMERKLE{"bestblock_nomerkle"};
const std::string BESTBLOCK{"bestblock"};
const std::string CRYPTED_KEY{"ckey"};
const std::string CSCRIPT{"cscript"};
const std::string DEFAULTKEY{"defaultkey"};
const std::string DESTDATA{"destdata"};
const std::string FLAGS{"flags"};
const std::string HDCHAIN{"hdchain"};
const std::string KEYMETA{"keymeta"};
const std::string KEY{"key"};
const std::string LOCKED_UTXO{"lockedutxo"};
const std::string MLDSA_KEY{"mlkey"};
const std::string CRYPTED_MLDSA_KEY{"cmlkey"};
const std::string MLDSA_KEYMETA{"mlkeymeta"};
const std::string MLDSA_TAPDATA{"mltapdata"};
const std::string MLDSA_OUTPUT_INDEX{"mloutidx"};
const std::string ASSET_META{"assetmeta"};
const std::string ASSET_DEK{"assetdek"};
const std::string MASTER_KEY{"mkey"};
const std::string MINVERSION{"minversion"};
const std::string NAME{"name"};
const std::string OLD_KEY{"wkey"};
const std::string ORDERPOSNEXT{"orderposnext"};
const std::string POOL{"pool"};
const std::string PURPOSE{"purpose"};
const std::string SETTINGS{"settings"};
const std::string TX{"tx"};
const std::string VERSION{"version"};
const std::string REPO_OFFER{"repooffer"};
const std::string FORWARD_CONTRACT{"forwardcontract"};
const std::string DIFFICULTY_CONTRACT{"diffcontract"};
const std::string OPTION_SERIES{"optseries"};
const std::string SCALAR_NOTE_PAIR{"scalarnotepair"};
const std::string SCALAR_CFD_CONTRACT{"scalarcfdcontract"};
const std::string SPOT_OFFER{"spotoffer"};
const std::string CROSS_CHAIN_RECORD{"xchainrecord"};
const std::string SETTLEMENT_PROFILE{"settlprofile"};
const std::string VAULT_METADATA{"vaultmeta"};
const std::string WALLETDESCRIPTOR{"walletdescriptor"};
const std::string WALLETDESCRIPTORCACHE{"walletdescriptorcache"};
const std::string WALLETDESCRIPTORLHCACHE{"walletdescriptorlhcache"};
const std::string WALLETDESCRIPTORCKEY{"walletdescriptorckey"};
const std::string WALLETDESCRIPTORKEY{"walletdescriptorkey"};
const std::string WATCHMETA{"watchmeta"};
const std::string WATCHS{"watchs"};
const std::unordered_set<std::string> LEGACY_TYPES{CRYPTED_KEY, CSCRIPT, DEFAULTKEY, HDCHAIN, KEYMETA, KEY, OLD_KEY, POOL, WATCHMETA, WATCHS};
} // namespace DBKeys

//
// WalletBatch
//

bool WalletBatch::WriteName(const std::string& strAddress, const std::string& strName)
{
    return WriteIC(std::make_pair(DBKeys::NAME, strAddress), strName);
}

bool WalletBatch::EraseName(const std::string& strAddress)
{
    // This should only be used for sending addresses, never for receiving addresses,
    // receiving addresses must always have an address book entry if they're not change return.
    return EraseIC(std::make_pair(DBKeys::NAME, strAddress));
}

bool WalletBatch::WritePurpose(const std::string& strAddress, const std::string& strPurpose)
{
    return WriteIC(std::make_pair(DBKeys::PURPOSE, strAddress), strPurpose);
}

bool WalletBatch::ErasePurpose(const std::string& strAddress)
{
    return EraseIC(std::make_pair(DBKeys::PURPOSE, strAddress));
}

bool WalletBatch::WriteTx(const CWalletTx& wtx)
{
    return WriteIC(std::make_pair(DBKeys::TX, wtx.GetHash()), wtx);
}

bool WalletBatch::EraseTx(Txid hash)
{
    return EraseIC(std::make_pair(DBKeys::TX, hash.ToUint256()));
}

bool WalletBatch::WriteKeyMetadata(const CKeyMetadata& meta, const CPubKey& pubkey, const bool overwrite)
{
    return WriteIC(std::make_pair(DBKeys::KEYMETA, pubkey), meta, overwrite);
}

bool WalletBatch::WriteKey(const CPubKey& vchPubKey, const CPrivKey& vchPrivKey, const CKeyMetadata& keyMeta)
{
    if (!WriteKeyMetadata(keyMeta, vchPubKey, false)) {
        return false;
    }

    // hash pubkey/privkey to accelerate wallet load
    std::vector<unsigned char> vchKey;
    vchKey.reserve(vchPubKey.size() + vchPrivKey.size());
    vchKey.insert(vchKey.end(), vchPubKey.begin(), vchPubKey.end());
    vchKey.insert(vchKey.end(), vchPrivKey.begin(), vchPrivKey.end());

    return WriteIC(std::make_pair(DBKeys::KEY, vchPubKey), std::make_pair(vchPrivKey, Hash(vchKey)), false);
}

bool WalletBatch::WriteCryptedKey(const CPubKey& vchPubKey,
                                const std::vector<unsigned char>& vchCryptedSecret,
                                const CKeyMetadata &keyMeta)
{
    if (!WriteKeyMetadata(keyMeta, vchPubKey, true)) {
        return false;
    }

    // Compute a checksum of the encrypted key
    uint256 checksum = Hash(vchCryptedSecret);

    const auto key = std::make_pair(DBKeys::CRYPTED_KEY, vchPubKey);
    if (!WriteIC(key, std::make_pair(vchCryptedSecret, checksum), false)) {
        // It may already exist, so try writing just the checksum
        std::vector<unsigned char> val;
        if (!m_batch->Read(key, val)) {
            return false;
        }
        if (!WriteIC(key, std::make_pair(val, checksum), true)) {
            return false;
        }
    }
    EraseIC(std::make_pair(DBKeys::KEY, vchPubKey));
    return true;
}

bool WalletBatch::WriteMLDSAKeyMetadata(const CKeyMetadata& meta, const uint256& pk_hash, const bool overwrite)
{
    return WriteIC(std::make_pair(DBKeys::MLDSA_KEYMETA, pk_hash), meta, overwrite);
}

bool WalletBatch::WriteMLDSAKey(const uint256& pk_hash, const std::vector<uint8_t>& pubkey, const std::vector<uint8_t>& seckey, uint8_t level, const CKeyMetadata& keyMeta)
{
    if (!WriteMLDSAKeyMetadata(keyMeta, pk_hash, false)) {
        return false;
    }

    // Pack ML-DSA key data: level || pubkey_len || pubkey || seckey_len || seckey
    std::vector<unsigned char> vchData;
    vchData.reserve(1 + 4 + pubkey.size() + 4 + seckey.size());

    // Level (parameter set)
    vchData.push_back(level);

    // Public key with length prefix
    uint32_t pk_len = static_cast<uint32_t>(pubkey.size());
    vchData.push_back(static_cast<uint8_t>(pk_len & 0xFF));
    vchData.push_back(static_cast<uint8_t>((pk_len >> 8) & 0xFF));
    vchData.push_back(static_cast<uint8_t>((pk_len >> 16) & 0xFF));
    vchData.push_back(static_cast<uint8_t>((pk_len >> 24) & 0xFF));
    vchData.insert(vchData.end(), pubkey.begin(), pubkey.end());

    // Secret key with length prefix
    uint32_t sk_len = static_cast<uint32_t>(seckey.size());
    vchData.push_back(static_cast<uint8_t>(sk_len & 0xFF));
    vchData.push_back(static_cast<uint8_t>((sk_len >> 8) & 0xFF));
    vchData.push_back(static_cast<uint8_t>((sk_len >> 16) & 0xFF));
    vchData.push_back(static_cast<uint8_t>((sk_len >> 24) & 0xFF));
    vchData.insert(vchData.end(), seckey.begin(), seckey.end());

    // Compute hash for integrity check
    uint256 checksum = Hash(vchData);

    return WriteIC(std::make_pair(DBKeys::MLDSA_KEY, pk_hash), std::make_pair(vchData, checksum), false);
}

bool WalletBatch::WriteCryptedMLDSAKey(const uint256& pk_hash, const std::vector<uint8_t>& pubkey, const std::vector<unsigned char>& vchCryptedSecret, uint8_t level, const CKeyMetadata& keyMeta)
{
    if (!WriteMLDSAKeyMetadata(keyMeta, pk_hash, true)) {
        return false;
    }

    // Pack ML-DSA key data: level || pubkey_len || pubkey || encrypted_seckey
    std::vector<unsigned char> vchData;
    vchData.reserve(1 + 4 + pubkey.size() + vchCryptedSecret.size());

    // Level (parameter set)
    vchData.push_back(level);

    // Public key with length prefix
    uint32_t pk_len = static_cast<uint32_t>(pubkey.size());
    vchData.push_back(static_cast<uint8_t>(pk_len & 0xFF));
    vchData.push_back(static_cast<uint8_t>((pk_len >> 8) & 0xFF));
    vchData.push_back(static_cast<uint8_t>((pk_len >> 16) & 0xFF));
    vchData.push_back(static_cast<uint8_t>((pk_len >> 24) & 0xFF));
    vchData.insert(vchData.end(), pubkey.begin(), pubkey.end());

    // Encrypted secret key (no length needed, it's the rest of the data)
    vchData.insert(vchData.end(), vchCryptedSecret.begin(), vchCryptedSecret.end());

    // Compute checksum of encrypted data
    uint256 checksum = Hash(vchData);

    const auto key = std::make_pair(DBKeys::CRYPTED_MLDSA_KEY, pk_hash);
    if (!WriteIC(key, std::make_pair(vchData, checksum), false)) {
        // It may already exist, so try writing just the checksum
        std::vector<unsigned char> val;
        if (!m_batch->Read(key, val)) {
            return false;
        }
        if (!WriteIC(key, std::make_pair(val, checksum), true)) {
            return false;
        }
    }
    EraseIC(std::make_pair(DBKeys::MLDSA_KEY, pk_hash));
    return true;
}

bool WalletBatch::WriteMLDSATaprootData(const XOnlyPubKey& output_key, const MLDSATaprootMetadata& metadata)
{
    return WriteIC(std::make_pair(DBKeys::MLDSA_TAPDATA, output_key), metadata, true);
}

bool WalletBatch::ReadMLDSATaprootData(const XOnlyPubKey& output_key, MLDSATaprootMetadata& metadata)
{
    return m_batch->Read(std::make_pair(DBKeys::MLDSA_TAPDATA, output_key), metadata);
}

bool WalletBatch::WriteMLDSAOutputIndex(const XOnlyPubKey& output_key, const uint256& pk_hash)
{
    return WriteIC(std::make_pair(DBKeys::MLDSA_OUTPUT_INDEX, output_key), pk_hash, true);
}

bool WalletBatch::ReadMLDSAOutputIndex(const XOnlyPubKey& output_key, uint256& pk_hash)
{
    return m_batch->Read(std::make_pair(DBKeys::MLDSA_OUTPUT_INDEX, output_key), pk_hash);
}

bool WalletBatch::WriteMasterKey(unsigned int nID, const CMasterKey& kMasterKey)
{
    return WriteIC(std::make_pair(DBKeys::MASTER_KEY, nID), kMasterKey, true);
}

bool WalletBatch::EraseMasterKey(unsigned int id)
{
    return EraseIC(std::make_pair(DBKeys::MASTER_KEY, id));
}

bool WalletBatch::WriteWatchOnly(const CScript &dest, const CKeyMetadata& keyMeta)
{
    if (!WriteIC(std::make_pair(DBKeys::WATCHMETA, dest), keyMeta)) {
        return false;
    }
    return WriteIC(std::make_pair(DBKeys::WATCHS, dest), uint8_t{'1'});
}

bool WalletBatch::EraseWatchOnly(const CScript &dest)
{
    if (!EraseIC(std::make_pair(DBKeys::WATCHMETA, dest))) {
        return false;
    }
    return EraseIC(std::make_pair(DBKeys::WATCHS, dest));
}

bool WalletBatch::WriteBestBlock(const CBlockLocator& locator)
{
    WriteIC(DBKeys::BESTBLOCK, CBlockLocator()); // Write empty block locator so versions that require a merkle branch automatically rescan
    return WriteIC(DBKeys::BESTBLOCK_NOMERKLE, locator);
}

bool WalletBatch::ReadBestBlock(CBlockLocator& locator)
{
    if (m_batch->Read(DBKeys::BESTBLOCK, locator) && !locator.vHave.empty()) return true;
    return m_batch->Read(DBKeys::BESTBLOCK_NOMERKLE, locator);
}

bool WalletBatch::IsEncrypted()
{
    DataStream prefix;
    prefix << DBKeys::MASTER_KEY;
    if (auto cursor = m_batch->GetNewPrefixCursor(prefix)) {
        DataStream k, v;
        if (cursor->Next(k, v) == DatabaseCursor::Status::MORE) return true;
    }
    return false;
}

bool WalletBatch::WriteOrderPosNext(int64_t nOrderPosNext)
{
    return WriteIC(DBKeys::ORDERPOSNEXT, nOrderPosNext);
}

bool WalletBatch::WriteMinVersion(int nVersion)
{
    return WriteIC(DBKeys::MINVERSION, nVersion);
}

bool WalletBatch::WriteActiveScriptPubKeyMan(uint8_t type, const uint256& id, bool internal)
{
    std::string key = internal ? DBKeys::ACTIVEINTERNALSPK : DBKeys::ACTIVEEXTERNALSPK;
    return WriteIC(make_pair(key, type), id);
}

bool WalletBatch::EraseActiveScriptPubKeyMan(uint8_t type, bool internal)
{
    const std::string key{internal ? DBKeys::ACTIVEINTERNALSPK : DBKeys::ACTIVEEXTERNALSPK};
    return EraseIC(make_pair(key, type));
}

bool WalletBatch::WriteDescriptorKey(const uint256& desc_id, const CPubKey& pubkey, const CPrivKey& privkey)
{
    // hash pubkey/privkey to accelerate wallet load
    std::vector<unsigned char> key;
    key.reserve(pubkey.size() + privkey.size());
    key.insert(key.end(), pubkey.begin(), pubkey.end());
    key.insert(key.end(), privkey.begin(), privkey.end());

    return WriteIC(std::make_pair(DBKeys::WALLETDESCRIPTORKEY, std::make_pair(desc_id, pubkey)), std::make_pair(privkey, Hash(key)), false);
}

bool WalletBatch::WriteCryptedDescriptorKey(const uint256& desc_id, const CPubKey& pubkey, const std::vector<unsigned char>& secret)
{
    if (!WriteIC(std::make_pair(DBKeys::WALLETDESCRIPTORCKEY, std::make_pair(desc_id, pubkey)), secret, false)) {
        return false;
    }
    EraseIC(std::make_pair(DBKeys::WALLETDESCRIPTORKEY, std::make_pair(desc_id, pubkey)));
    return true;
}

bool WalletBatch::WriteDescriptor(const uint256& desc_id, const WalletDescriptor& descriptor)
{
    return WriteIC(make_pair(DBKeys::WALLETDESCRIPTOR, desc_id), descriptor);
}

bool WalletBatch::WriteDescriptorDerivedCache(const CExtPubKey& xpub, const uint256& desc_id, uint32_t key_exp_index, uint32_t der_index)
{
    std::vector<unsigned char> ser_xpub(BIP32_EXTKEY_SIZE);
    xpub.Encode(ser_xpub.data());
    return WriteIC(std::make_pair(std::make_pair(DBKeys::WALLETDESCRIPTORCACHE, desc_id), std::make_pair(key_exp_index, der_index)), ser_xpub);
}

bool WalletBatch::WriteDescriptorParentCache(const CExtPubKey& xpub, const uint256& desc_id, uint32_t key_exp_index)
{
    std::vector<unsigned char> ser_xpub(BIP32_EXTKEY_SIZE);
    xpub.Encode(ser_xpub.data());
    return WriteIC(std::make_pair(std::make_pair(DBKeys::WALLETDESCRIPTORCACHE, desc_id), key_exp_index), ser_xpub);
}

bool WalletBatch::WriteDescriptorLastHardenedCache(const CExtPubKey& xpub, const uint256& desc_id, uint32_t key_exp_index)
{
    std::vector<unsigned char> ser_xpub(BIP32_EXTKEY_SIZE);
    xpub.Encode(ser_xpub.data());
    return WriteIC(std::make_pair(std::make_pair(DBKeys::WALLETDESCRIPTORLHCACHE, desc_id), key_exp_index), ser_xpub);
}

bool WalletBatch::WriteDescriptorCacheItems(const uint256& desc_id, const DescriptorCache& cache)
{
    for (const auto& parent_xpub_pair : cache.GetCachedParentExtPubKeys()) {
        if (!WriteDescriptorParentCache(parent_xpub_pair.second, desc_id, parent_xpub_pair.first)) {
            return false;
        }
    }
    for (const auto& derived_xpub_map_pair : cache.GetCachedDerivedExtPubKeys()) {
        for (const auto& derived_xpub_pair : derived_xpub_map_pair.second) {
            if (!WriteDescriptorDerivedCache(derived_xpub_pair.second, desc_id, derived_xpub_map_pair.first, derived_xpub_pair.first)) {
                return false;
            }
        }
    }
    for (const auto& lh_xpub_pair : cache.GetCachedLastHardenedExtPubKeys()) {
        if (!WriteDescriptorLastHardenedCache(lh_xpub_pair.second, desc_id, lh_xpub_pair.first)) {
            return false;
        }
    }
    return true;
}

bool WalletBatch::WriteLockedUTXO(const COutPoint& output)
{
    return WriteIC(std::make_pair(DBKeys::LOCKED_UTXO, std::make_pair(output.hash, output.n)), uint8_t{'1'});
}

bool WalletBatch::EraseLockedUTXO(const COutPoint& output)
{
    return EraseIC(std::make_pair(DBKeys::LOCKED_UTXO, std::make_pair(output.hash, output.n)));
}

bool WalletBatch::WriteAssetMetadata(const COutPoint& output, const AssetMetadata& meta)
{
    return WriteIC(std::make_pair(DBKeys::ASSET_META, std::make_pair(output.hash, output.n)), meta);
}

bool WalletBatch::EraseAssetMetadata(const COutPoint& output)
{
    return EraseIC(std::make_pair(DBKeys::ASSET_META, std::make_pair(output.hash, output.n)));
}

bool WalletBatch::WriteRepoOffer(const RepoOfferRecord& record)
{
    return WriteIC(std::make_pair(DBKeys::REPO_OFFER, record.offer_id), record);
}

bool WalletBatch::EraseRepoOffer(const uint256& offer_id)
{
    return EraseIC(std::make_pair(DBKeys::REPO_OFFER, offer_id));
}

bool WalletBatch::WriteSpotOffer(const SpotOfferRecord& record)
{
    return WriteIC(std::make_pair(DBKeys::SPOT_OFFER, record.offer_id), record);
}

bool WalletBatch::EraseSpotOffer(const uint256& offer_id)
{
    return EraseIC(std::make_pair(DBKeys::SPOT_OFFER, offer_id));
}

bool WalletBatch::WriteForwardContract(const ForwardContractRecord& record)
{
    return WriteIC(std::make_pair(DBKeys::FORWARD_CONTRACT, record.contract_id), record);
}

bool WalletBatch::EraseForwardContract(const uint256& contract_id)
{
    return EraseIC(std::make_pair(DBKeys::FORWARD_CONTRACT, contract_id));
}

bool WalletBatch::WriteDifficultyContract(const DifficultyContractRecord& record)
{
    return WriteIC(std::make_pair(DBKeys::DIFFICULTY_CONTRACT, record.contract_id), record);
}

bool WalletBatch::EraseDifficultyContract(const uint256& contract_id)
{
    return EraseIC(std::make_pair(DBKeys::DIFFICULTY_CONTRACT, contract_id));
}

bool WalletBatch::WriteOptionSeries(const OptionSeriesRecord& record)
{
    return WriteIC(std::make_pair(DBKeys::OPTION_SERIES, record.series_id), record);
}

bool WalletBatch::EraseOptionSeries(const uint256& series_id)
{
    return EraseIC(std::make_pair(DBKeys::OPTION_SERIES, series_id));
}

bool WalletBatch::WriteScalarNotePair(const ScalarNotePairRecord& record)
{
    return WriteIC(std::make_pair(DBKeys::SCALAR_NOTE_PAIR, record.pair_id), record);
}

bool WalletBatch::EraseScalarNotePair(const uint256& pair_id)
{
    return EraseIC(std::make_pair(DBKeys::SCALAR_NOTE_PAIR, pair_id));
}

bool WalletBatch::WriteScalarCfdContract(const ScalarCfdContractRecord& record)
{
    return WriteIC(std::make_pair(DBKeys::SCALAR_CFD_CONTRACT, record.contract_id), record);
}

bool WalletBatch::EraseScalarCfdContract(const uint256& contract_id)
{
    return EraseIC(std::make_pair(DBKeys::SCALAR_CFD_CONTRACT, contract_id));
}

bool WalletBatch::WriteCrossChainRecord(const CrossChainRecord& record)
{
    return WriteIC(std::make_pair(DBKeys::CROSS_CHAIN_RECORD, record.swap_id), record);  // string key
}

bool WalletBatch::EraseCrossChainRecord(const std::string& swap_id)
{
    return EraseIC(std::make_pair(DBKeys::CROSS_CHAIN_RECORD, swap_id));  // string key
}

bool WalletBatch::WriteSettlementProfile(const std::string& profile_id, const SettlementProfile& profile)
{
    return WriteIC(std::make_pair(DBKeys::SETTLEMENT_PROFILE, profile_id), profile);
}

bool WalletBatch::EraseSettlementProfile(const std::string& profile_id)
{
    return EraseIC(std::make_pair(DBKeys::SETTLEMENT_PROFILE, profile_id));
}

bool WalletBatch::WriteVaultMetadata(const CScript& script_pubkey, const VaultMetadata& metadata)
{
    return WriteIC(std::make_pair(DBKeys::VAULT_METADATA, script_pubkey), metadata);
}

bool WalletBatch::EraseVaultMetadata(const CScript& script_pubkey)
{
    return EraseIC(std::make_pair(DBKeys::VAULT_METADATA, script_pubkey));
}

bool WalletBatch::WriteAssetDek(const uint256& asset_id, const std::string& dek)
{
    return WriteIC(std::make_pair(DBKeys::ASSET_DEK, asset_id), dek);
}

bool WalletBatch::ReadAssetDek(const uint256& asset_id, std::string& dek)
{
    return m_batch->Read(std::make_pair(DBKeys::ASSET_DEK, asset_id), dek);
}

bool WalletBatch::EraseAssetDek(const uint256& asset_id)
{
    return EraseIC(std::make_pair(DBKeys::ASSET_DEK, asset_id));
}

bool LoadKey(CWallet* pwallet, DataStream& ssKey, DataStream& ssValue, std::string& strErr)
{
    LOCK(pwallet->cs_wallet);
    try {
        CPubKey vchPubKey;
        ssKey >> vchPubKey;
        if (!vchPubKey.IsValid())
        {
            strErr = "Error reading wallet database: CPubKey corrupt";
            return false;
        }
        CKey key;
        CPrivKey pkey;
        uint256 hash;

        ssValue >> pkey;

        // Old wallets store keys as DBKeys::KEY [pubkey] => [privkey]
        // ... which was slow for wallets with lots of keys, because the public key is re-derived from the private key
        // using EC operations as a checksum.
        // Newer wallets store keys as DBKeys::KEY [pubkey] => [privkey][hash(pubkey,privkey)], which is much faster while
        // remaining backwards-compatible.
        try
        {
            ssValue >> hash;
        }
        catch (const std::ios_base::failure&) {}

        bool fSkipCheck = false;

        if (!hash.IsNull())
        {
            // hash pubkey/privkey to accelerate wallet load
            std::vector<unsigned char> vchKey;
            vchKey.reserve(vchPubKey.size() + pkey.size());
            vchKey.insert(vchKey.end(), vchPubKey.begin(), vchPubKey.end());
            vchKey.insert(vchKey.end(), pkey.begin(), pkey.end());

            if (Hash(vchKey) != hash)
            {
                strErr = "Error reading wallet database: CPubKey/CPrivKey corrupt";
                return false;
            }

            fSkipCheck = true;
        }

        if (!key.Load(pkey, vchPubKey, fSkipCheck))
        {
            strErr = "Error reading wallet database: CPrivKey corrupt";
            return false;
        }
        if (!pwallet->GetOrCreateLegacyDataSPKM()->LoadKey(key, vchPubKey))
        {
            strErr = "Error reading wallet database: LegacyDataSPKM::LoadKey failed";
            return false;
        }
    } catch (const std::exception& e) {
        if (strErr.empty()) {
            strErr = e.what();
        }
        return false;
    }
    return true;
}

bool LoadCryptedKey(CWallet* pwallet, DataStream& ssKey, DataStream& ssValue, std::string& strErr)
{
    LOCK(pwallet->cs_wallet);
    try {
        CPubKey vchPubKey;
        ssKey >> vchPubKey;
        if (!vchPubKey.IsValid())
        {
            strErr = "Error reading wallet database: CPubKey corrupt";
            return false;
        }
        std::vector<unsigned char> vchPrivKey;
        ssValue >> vchPrivKey;

        // Get the checksum and check it
        bool checksum_valid = false;
        if (!ssValue.eof()) {
            uint256 checksum;
            ssValue >> checksum;
            if (!(checksum_valid = Hash(vchPrivKey) == checksum)) {
                strErr = "Error reading wallet database: Encrypted key corrupt";
                return false;
            }
        }

        if (!pwallet->GetOrCreateLegacyDataSPKM()->LoadCryptedKey(vchPubKey, vchPrivKey, checksum_valid))
        {
            strErr = "Error reading wallet database: LegacyDataSPKM::LoadCryptedKey failed";
            return false;
        }
    } catch (const std::exception& e) {
        if (strErr.empty()) {
            strErr = e.what();
        }
        return false;
    }
    return true;
}

bool LoadMLDSAKey(CWallet* pwallet, DataStream& ssKey, DataStream& ssValue, std::string& strErr)
{
    LOCK(pwallet->cs_wallet);
    try {
        uint256 pk_hash;
        ssKey >> pk_hash;

        std::vector<unsigned char> vchData;
        uint256 checksum;
        ssValue >> vchData >> checksum;

        // Verify checksum
        if (Hash(vchData) != checksum) {
            strErr = "Error reading wallet database: ML-DSA key checksum mismatch";
            return false;
        }

        // Parse the data: level || pk_len || pubkey || sk_len || seckey
        if (vchData.size() < 9) {  // Min: 1 (level) + 4 (pk_len) + 4 (sk_len)
            strErr = "Error reading wallet database: ML-DSA key data too short";
            return false;
        }

        size_t pos = 0;
        uint8_t level = vchData[pos++];

        // Read public key length (little-endian)
        uint32_t pk_len = static_cast<uint32_t>(vchData[pos]) |
                         (static_cast<uint32_t>(vchData[pos + 1]) << 8) |
                         (static_cast<uint32_t>(vchData[pos + 2]) << 16) |
                         (static_cast<uint32_t>(vchData[pos + 3]) << 24);
        pos += 4;

        if (pos + pk_len + 4 > vchData.size()) {
            strErr = "Error reading wallet database: ML-DSA key public key length invalid";
            return false;
        }

        std::vector<uint8_t> pubkey(vchData.begin() + pos, vchData.begin() + pos + pk_len);
        pos += pk_len;

        // Read secret key length (little-endian)
        uint32_t sk_len = static_cast<uint32_t>(vchData[pos]) |
                         (static_cast<uint32_t>(vchData[pos + 1]) << 8) |
                         (static_cast<uint32_t>(vchData[pos + 2]) << 16) |
                         (static_cast<uint32_t>(vchData[pos + 3]) << 24);
        pos += 4;

        if (pos + sk_len != vchData.size()) {
            strErr = "Error reading wallet database: ML-DSA key secret key length invalid";
            return false;
        }

        // Successfully parsed and validated ML-DSA key
        // Note: Keys are stored for backup/restore but not cached in memory
        // as the current architecture requires manual seckey provision for signing
        pwallet->WalletLogPrintf("Loaded ML-DSA key (level=%d, pk_hash=%s)\n", level, pk_hash.GetHex());

    } catch (const std::exception& e) {
        if (strErr.empty()) {
            strErr = e.what();
        }
        return false;
    }
    return true;
}

bool LoadCryptedMLDSAKey(CWallet* pwallet, DataStream& ssKey, DataStream& ssValue, std::string& strErr)
{
    LOCK(pwallet->cs_wallet);
    try {
        uint256 pk_hash;
        ssKey >> pk_hash;

        std::vector<unsigned char> vchData;
        uint256 checksum;
        ssValue >> vchData >> checksum;

        // Verify checksum
        if (Hash(vchData) != checksum) {
            strErr = "Error reading wallet database: Encrypted ML-DSA key checksum mismatch";
            return false;
        }

        // Parse the encrypted data: level || pk_len || pubkey || encrypted_seckey
        if (vchData.size() < 5) {  // Min: 1 (level) + 4 (pk_len)
            strErr = "Error reading wallet database: Encrypted ML-DSA key data too short";
            return false;
        }

        size_t pos = 0;
        uint8_t level = vchData[pos++];

        // Read public key length (little-endian)
        uint32_t pk_len = static_cast<uint32_t>(vchData[pos]) |
                         (static_cast<uint32_t>(vchData[pos + 1]) << 8) |
                         (static_cast<uint32_t>(vchData[pos + 2]) << 16) |
                         (static_cast<uint32_t>(vchData[pos + 3]) << 24);
        pos += 4;

        if (pos + pk_len > vchData.size()) {
            strErr = "Error reading wallet database: Encrypted ML-DSA key public key length invalid";
            return false;
        }

        std::vector<uint8_t> pubkey(vchData.begin() + pos, vchData.begin() + pos + pk_len);
        pos += pk_len;

        // Remaining data is encrypted secret key
        size_t encrypted_sk_len = vchData.size() - pos;
        if (encrypted_sk_len == 0) {
            strErr = "Error reading wallet database: Encrypted ML-DSA key has no encrypted data";
            return false;
        }

        // Successfully parsed and validated encrypted ML-DSA key
        // Note: Keys are stored for backup/restore but not cached in memory
        // as the current architecture requires manual seckey provision for signing
        pwallet->WalletLogPrintf("Loaded encrypted ML-DSA key (level=%d, pk_hash=%s)\n", level, pk_hash.GetHex());

    } catch (const std::exception& e) {
        if (strErr.empty()) {
            strErr = e.what();
        }
        return false;
    }
    return true;
}

bool LoadEncryptionKey(CWallet* pwallet, DataStream& ssKey, DataStream& ssValue, std::string& strErr)
{
    LOCK(pwallet->cs_wallet);
    try {
        // Master encryption key is loaded into only the wallet and not any of the ScriptPubKeyMans.
        unsigned int nID;
        ssKey >> nID;
        CMasterKey kMasterKey;
        ssValue >> kMasterKey;
        if(pwallet->mapMasterKeys.count(nID) != 0)
        {
            strErr = strprintf("Error reading wallet database: duplicate CMasterKey id %u", nID);
            return false;
        }
        pwallet->mapMasterKeys[nID] = kMasterKey;
        if (pwallet->nMasterKeyMaxID < nID)
            pwallet->nMasterKeyMaxID = nID;

    } catch (const std::exception& e) {
        if (strErr.empty()) {
            strErr = e.what();
        }
        return false;
    }
    return true;
}

bool LoadHDChain(CWallet* pwallet, DataStream& ssValue, std::string& strErr)
{
    LOCK(pwallet->cs_wallet);
    try {
        CHDChain chain;
        ssValue >> chain;
        pwallet->GetOrCreateLegacyDataSPKM()->LoadHDChain(chain);
    } catch (const std::exception& e) {
        if (strErr.empty()) {
            strErr = e.what();
        }
        return false;
    }
    return true;
}

static DBErrors LoadMinVersion(CWallet* pwallet, DatabaseBatch& batch) EXCLUSIVE_LOCKS_REQUIRED(pwallet->cs_wallet)
{
    AssertLockHeld(pwallet->cs_wallet);
    int nMinVersion = 0;
    if (batch.Read(DBKeys::MINVERSION, nMinVersion)) {
        if (nMinVersion > FEATURE_LATEST)
            return DBErrors::TOO_NEW;
        pwallet->LoadMinVersion(nMinVersion);
    }
    return DBErrors::LOAD_OK;
}

static DBErrors LoadWalletFlags(CWallet* pwallet, DatabaseBatch& batch) EXCLUSIVE_LOCKS_REQUIRED(pwallet->cs_wallet)
{
    AssertLockHeld(pwallet->cs_wallet);
    uint64_t flags;
    if (batch.Read(DBKeys::FLAGS, flags)) {
        if (!pwallet->LoadWalletFlags(flags)) {
            pwallet->WalletLogPrintf("Error reading wallet database: Unknown non-tolerable wallet flags found\n");
            return DBErrors::TOO_NEW;
        }
        // All wallets must be descriptor wallets unless opened with a bdb_ro db
        // bdb_ro is only used for legacy to descriptor migration.
        if (pwallet->GetDatabase().Format() != "bdb_ro" && !pwallet->IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS)) {
            return DBErrors::LEGACY_WALLET;
        }
    }
    return DBErrors::LOAD_OK;
}

struct LoadResult
{
    DBErrors m_result{DBErrors::LOAD_OK};
    int m_records{0};
};

using LoadFunc = std::function<DBErrors(CWallet* pwallet, DataStream& key, DataStream& value, std::string& err)>;
static LoadResult LoadRecords(CWallet* pwallet, DatabaseBatch& batch, const std::string& key, DataStream& prefix, LoadFunc load_func)
{
    LoadResult result;
    DataStream ssKey;
    DataStream ssValue{};

    Assume(!prefix.empty());
    std::unique_ptr<DatabaseCursor> cursor = batch.GetNewPrefixCursor(prefix);
    if (!cursor) {
        pwallet->WalletLogPrintf("Error getting database cursor for '%s' records\n", key);
        result.m_result = DBErrors::CORRUPT;
        return result;
    }

    while (true) {
        DatabaseCursor::Status status = cursor->Next(ssKey, ssValue);
        if (status == DatabaseCursor::Status::DONE) {
            break;
        } else if (status == DatabaseCursor::Status::FAIL) {
            pwallet->WalletLogPrintf("Error reading next '%s' record for wallet database\n", key);
            result.m_result = DBErrors::CORRUPT;
            return result;
        }
        std::string type;
        ssKey >> type;
        assert(type == key);
        std::string error;
        DBErrors record_res = load_func(pwallet, ssKey, ssValue, error);
        if (record_res != DBErrors::LOAD_OK) {
            pwallet->WalletLogPrintf("%s\n", error);
        }
        result.m_result = std::max(result.m_result, record_res);
        ++result.m_records;
    }
    return result;
}

static LoadResult LoadRecords(CWallet* pwallet, DatabaseBatch& batch, const std::string& key, LoadFunc load_func)
{
    DataStream prefix;
    prefix << key;
    return LoadRecords(pwallet, batch, key, prefix, load_func);
}

bool HasLegacyRecords(CWallet& wallet)
{
    const auto& batch = wallet.GetDatabase().MakeBatch();
    return HasLegacyRecords(wallet, *batch);
}

bool HasLegacyRecords(CWallet& wallet, DatabaseBatch& batch)
{
    for (const auto& type : DBKeys::LEGACY_TYPES) {
        DataStream key;
        DataStream value{};
        DataStream prefix;

        prefix << type;
        std::unique_ptr<DatabaseCursor> cursor = batch.GetNewPrefixCursor(prefix);
        if (!cursor) {
            // Could only happen on a closed db, which means there is an error in the code flow.
            wallet.WalletLogPrintf("Error getting database cursor for '%s' records", type);
            throw std::runtime_error(strprintf("Error getting database cursor for '%s' records", type));
        }

        DatabaseCursor::Status status = cursor->Next(key, value);
        if (status != DatabaseCursor::Status::DONE) {
            return true;
        }
    }
    return false;
}

static DBErrors LoadLegacyWalletRecords(CWallet* pwallet, DatabaseBatch& batch, int last_client) EXCLUSIVE_LOCKS_REQUIRED(pwallet->cs_wallet)
{
    AssertLockHeld(pwallet->cs_wallet);
    DBErrors result = DBErrors::LOAD_OK;

    // Make sure descriptor wallets don't have any legacy records
    if (pwallet->IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS)) {
        if (HasLegacyRecords(*pwallet, batch)) {
            pwallet->WalletLogPrintf("Error: Unexpected legacy entry found in descriptor wallet %s. The wallet might have been tampered with or created with malicious intent.\n", pwallet->GetName());
            return DBErrors::UNEXPECTED_LEGACY_ENTRY;
        }

        return DBErrors::LOAD_OK;
    }

    // Load HD Chain
    // Note: There should only be one HDCHAIN record with no data following the type
    LoadResult hd_chain_res = LoadRecords(pwallet, batch, DBKeys::HDCHAIN,
        [] (CWallet* pwallet, DataStream& key, DataStream& value, std::string& err) {
        return LoadHDChain(pwallet, value, err) ? DBErrors:: LOAD_OK : DBErrors::CORRUPT;
    });
    result = std::max(result, hd_chain_res.m_result);

    // Load unencrypted keys
    LoadResult key_res = LoadRecords(pwallet, batch, DBKeys::KEY,
        [] (CWallet* pwallet, DataStream& key, DataStream& value, std::string& err) {
        return LoadKey(pwallet, key, value, err) ? DBErrors::LOAD_OK : DBErrors::CORRUPT;
    });
    result = std::max(result, key_res.m_result);

    // Load encrypted keys
    LoadResult ckey_res = LoadRecords(pwallet, batch, DBKeys::CRYPTED_KEY,
        [] (CWallet* pwallet, DataStream& key, DataStream& value, std::string& err) {
        return LoadCryptedKey(pwallet, key, value, err) ? DBErrors::LOAD_OK : DBErrors::CORRUPT;
    });
    result = std::max(result, ckey_res.m_result);

    // Load unencrypted ML-DSA keys
    LoadResult mldsa_key_res = LoadRecords(pwallet, batch, DBKeys::MLDSA_KEY,
        [] (CWallet* pwallet, DataStream& key, DataStream& value, std::string& err) {
        return LoadMLDSAKey(pwallet, key, value, err) ? DBErrors::LOAD_OK : DBErrors::CORRUPT;
    });
    result = std::max(result, mldsa_key_res.m_result);

    // Load encrypted ML-DSA keys
    LoadResult cmldsa_key_res = LoadRecords(pwallet, batch, DBKeys::CRYPTED_MLDSA_KEY,
        [] (CWallet* pwallet, DataStream& key, DataStream& value, std::string& err) {
        return LoadCryptedMLDSAKey(pwallet, key, value, err) ? DBErrors::LOAD_OK : DBErrors::CORRUPT;
    });
    result = std::max(result, cmldsa_key_res.m_result);

    // Load scripts
    LoadResult script_res = LoadRecords(pwallet, batch, DBKeys::CSCRIPT,
        [] (CWallet* pwallet, DataStream& key, DataStream& value, std::string& strErr) {
        uint160 hash;
        key >> hash;
        CScript script;
        value >> script;
        if (!pwallet->GetOrCreateLegacyDataSPKM()->LoadCScript(script))
        {
            strErr = "Error reading wallet database: LegacyDataSPKM::LoadCScript failed";
            return DBErrors::NONCRITICAL_ERROR;
        }
        return DBErrors::LOAD_OK;
    });
    result = std::max(result, script_res.m_result);

    // Check whether rewrite is needed
    if (ckey_res.m_records > 0) {
        // Rewrite encrypted wallets of versions 0.4.0 and 0.5.0rc:
        if (last_client == 40000 || last_client == 50000) result = std::max(result, DBErrors::NEED_REWRITE);
    }

    // Load keymeta
    std::map<uint160, CHDChain> hd_chains;
    LoadResult keymeta_res = LoadRecords(pwallet, batch, DBKeys::KEYMETA,
        [&hd_chains] (CWallet* pwallet, DataStream& key, DataStream& value, std::string& strErr) {
        CPubKey vchPubKey;
        key >> vchPubKey;
        CKeyMetadata keyMeta;
        value >> keyMeta;
        pwallet->GetOrCreateLegacyDataSPKM()->LoadKeyMetadata(vchPubKey.GetID(), keyMeta);

        // Extract some CHDChain info from this metadata if it has any
        if (keyMeta.nVersion >= CKeyMetadata::VERSION_WITH_HDDATA && !keyMeta.hd_seed_id.IsNull() && keyMeta.hdKeypath.size() > 0) {
            // Get the path from the key origin or from the path string
            // Not applicable when path is "s" or "m" as those indicate a seed
            // See https://github.com/bitcoin/bitcoin/pull/12924
            bool internal = false;
            uint32_t index = 0;
            if (keyMeta.hdKeypath != "s" && keyMeta.hdKeypath != "m") {
                std::vector<uint32_t> path;
                if (keyMeta.has_key_origin) {
                    // We have a key origin, so pull it from its path vector
                    path = keyMeta.key_origin.path;
                } else {
                    // No key origin, have to parse the string
                    if (!ParseHDKeypath(keyMeta.hdKeypath, path)) {
                        strErr = "Error reading wallet database: keymeta with invalid HD keypath";
                        return DBErrors::NONCRITICAL_ERROR;
                    }
                }

                // Extract the index and internal from the path
                // Path string is m/0'/k'/i'
                // Path vector is [0', k', i'] (but as ints OR'd with the hardened bit
                // k == 0 for external, 1 for internal. i is the index
                if (path.size() != 3) {
                    strErr = "Error reading wallet database: keymeta found with unexpected path";
                    return DBErrors::NONCRITICAL_ERROR;
                }
                if (path[0] != 0x80000000) {
                    strErr = strprintf("Unexpected path index of 0x%08x (expected 0x80000000) for the element at index 0", path[0]);
                    return DBErrors::NONCRITICAL_ERROR;
                }
                if (path[1] != 0x80000000 && path[1] != (1 | 0x80000000)) {
                    strErr = strprintf("Unexpected path index of 0x%08x (expected 0x80000000 or 0x80000001) for the element at index 1", path[1]);
                    return DBErrors::NONCRITICAL_ERROR;
                }
                if ((path[2] & 0x80000000) == 0) {
                    strErr = strprintf("Unexpected path index of 0x%08x (expected to be greater than or equal to 0x80000000)", path[2]);
                    return DBErrors::NONCRITICAL_ERROR;
                }
                internal = path[1] == (1 | 0x80000000);
                index = path[2] & ~0x80000000;
            }

            // Insert a new CHDChain, or get the one that already exists
            auto [ins, inserted] = hd_chains.emplace(keyMeta.hd_seed_id, CHDChain());
            CHDChain& chain = ins->second;
            if (inserted) {
                // For new chains, we want to default to VERSION_HD_BASE until we see an internal
                chain.nVersion = CHDChain::VERSION_HD_BASE;
                chain.seed_id = keyMeta.hd_seed_id;
            }
            if (internal) {
                chain.nVersion = CHDChain::VERSION_HD_CHAIN_SPLIT;
                chain.nInternalChainCounter = std::max(chain.nInternalChainCounter, index + 1);
            } else {
                chain.nExternalChainCounter = std::max(chain.nExternalChainCounter, index + 1);
            }
        }
        return DBErrors::LOAD_OK;
    });
    result = std::max(result, keymeta_res.m_result);

    // Set inactive chains
    if (!hd_chains.empty()) {
        LegacyDataSPKM* legacy_spkm = pwallet->GetLegacyDataSPKM();
        if (legacy_spkm) {
            for (const auto& [hd_seed_id, chain] : hd_chains) {
                if (hd_seed_id != legacy_spkm->GetHDChain().seed_id) {
                    legacy_spkm->AddInactiveHDChain(chain);
                }
            }
        } else {
            pwallet->WalletLogPrintf("Inactive HD Chains found but no Legacy ScriptPubKeyMan\n");
            result = DBErrors::CORRUPT;
        }
    }

    // Load watchonly scripts
    LoadResult watch_script_res = LoadRecords(pwallet, batch, DBKeys::WATCHS,
        [] (CWallet* pwallet, DataStream& key, DataStream& value, std::string& err) {
        CScript script;
        key >> script;
        uint8_t fYes;
        value >> fYes;
        if (fYes == '1') {
            pwallet->GetOrCreateLegacyDataSPKM()->LoadWatchOnly(script);
        }
        return DBErrors::LOAD_OK;
    });
    result = std::max(result, watch_script_res.m_result);

    // Load watchonly meta
    LoadResult watch_meta_res = LoadRecords(pwallet, batch, DBKeys::WATCHMETA,
        [] (CWallet* pwallet, DataStream& key, DataStream& value, std::string& err) {
        CScript script;
        key >> script;
        CKeyMetadata keyMeta;
        value >> keyMeta;
        pwallet->GetOrCreateLegacyDataSPKM()->LoadScriptMetadata(CScriptID(script), keyMeta);
        return DBErrors::LOAD_OK;
    });
    result = std::max(result, watch_meta_res.m_result);

    // Deal with old "wkey" and "defaultkey" records.
    // These are not actually loaded, but we need to check for them

    // We don't want or need the default key, but if there is one set,
    // we want to make sure that it is valid so that we can detect corruption
    // Note: There should only be one DEFAULTKEY with nothing trailing the type
    LoadResult default_key_res = LoadRecords(pwallet, batch, DBKeys::DEFAULTKEY,
        [] (CWallet* pwallet, DataStream& key, DataStream& value, std::string& err) {
        CPubKey default_pubkey;
        try {
            value >> default_pubkey;
        } catch (const std::exception& e) {
            err = e.what();
            return DBErrors::CORRUPT;
        }
        if (!default_pubkey.IsValid()) {
            err = "Error reading wallet database: Default Key corrupt";
            return DBErrors::CORRUPT;
        }
        return DBErrors::LOAD_OK;
    });
    result = std::max(result, default_key_res.m_result);

    // "wkey" records are unsupported, if we see any, throw an error
    LoadResult wkey_res = LoadRecords(pwallet, batch, DBKeys::OLD_KEY,
        [] (CWallet* pwallet, DataStream& key, DataStream& value, std::string& err) {
        err = "Found unsupported 'wkey' record, try loading with version 0.18";
        return DBErrors::LOAD_FAIL;
    });
    result = std::max(result, wkey_res.m_result);

    if (result <= DBErrors::NONCRITICAL_ERROR) {
        // Only do logging and time first key update if there were no critical errors
        pwallet->WalletLogPrintf("Legacy Wallet Keys: %u plaintext, %u encrypted, %u w/ metadata, %u total.\n",
               key_res.m_records, ckey_res.m_records, keymeta_res.m_records, key_res.m_records + ckey_res.m_records);
    }

    return result;
}

template<typename... Args>
static DataStream PrefixStream(const Args&... args)
{
    DataStream prefix;
    SerializeMany(prefix, args...);
    return prefix;
}

static DBErrors LoadDescriptorWalletRecords(CWallet* pwallet, DatabaseBatch& batch, int last_client) EXCLUSIVE_LOCKS_REQUIRED(pwallet->cs_wallet)
{
    AssertLockHeld(pwallet->cs_wallet);

    // Load descriptor record
    int num_keys = 0;
    int num_ckeys= 0;
    LoadResult desc_res = LoadRecords(pwallet, batch, DBKeys::WALLETDESCRIPTOR,
        [&batch, &num_keys, &num_ckeys, &last_client] (CWallet* pwallet, DataStream& key, DataStream& value, std::string& strErr) {
        DBErrors result = DBErrors::LOAD_OK;

        uint256 id;
        key >> id;
        WalletDescriptor desc;
        try {
            value >> desc;
        } catch (const std::ios_base::failure& e) {
            strErr = strprintf("Error: Unrecognized descriptor found in wallet %s. ", pwallet->GetName());
            strErr += (last_client > CLIENT_VERSION) ? "The wallet might had been created on a newer version. " :
                    "The database might be corrupted or the software version is not compatible with one of your wallet descriptors. ";
            strErr += "Please try running the latest software version";
            // Also include error details
            strErr = strprintf("%s\nDetails: %s", strErr, e.what());
            return DBErrors::UNKNOWN_DESCRIPTOR;
        }
        DescriptorScriptPubKeyMan& spkm = pwallet->LoadDescriptorScriptPubKeyMan(id, desc);

        // Prior to doing anything with this spkm, verify ID compatibility
        if (id != spkm.GetID()) {
            strErr = "The descriptor ID calculated by the wallet differs from the one in DB";
            return DBErrors::CORRUPT;
        }

        DescriptorCache cache;

        // Get key cache for this descriptor
        DataStream prefix = PrefixStream(DBKeys::WALLETDESCRIPTORCACHE, id);
        LoadResult key_cache_res = LoadRecords(pwallet, batch, DBKeys::WALLETDESCRIPTORCACHE, prefix,
            [&id, &cache] (CWallet* pwallet, DataStream& key, DataStream& value, std::string& err) {
            bool parent = true;
            uint256 desc_id;
            uint32_t key_exp_index;
            uint32_t der_index;
            key >> desc_id;
            assert(desc_id == id);
            key >> key_exp_index;

            // if the der_index exists, it's a derived xpub
            try
            {
                key >> der_index;
                parent = false;
            }
            catch (...) {}

            std::vector<unsigned char> ser_xpub(BIP32_EXTKEY_SIZE);
            value >> ser_xpub;
            CExtPubKey xpub;
            xpub.Decode(ser_xpub.data());
            if (parent) {
                cache.CacheParentExtPubKey(key_exp_index, xpub);
            } else {
                cache.CacheDerivedExtPubKey(key_exp_index, der_index, xpub);
            }
            return DBErrors::LOAD_OK;
        });
        result = std::max(result, key_cache_res.m_result);

        // Get last hardened cache for this descriptor
        prefix = PrefixStream(DBKeys::WALLETDESCRIPTORLHCACHE, id);
        LoadResult lh_cache_res = LoadRecords(pwallet, batch, DBKeys::WALLETDESCRIPTORLHCACHE, prefix,
            [&id, &cache] (CWallet* pwallet, DataStream& key, DataStream& value, std::string& err) {
            uint256 desc_id;
            uint32_t key_exp_index;
            key >> desc_id;
            assert(desc_id == id);
            key >> key_exp_index;

            std::vector<unsigned char> ser_xpub(BIP32_EXTKEY_SIZE);
            value >> ser_xpub;
            CExtPubKey xpub;
            xpub.Decode(ser_xpub.data());
            cache.CacheLastHardenedExtPubKey(key_exp_index, xpub);
            return DBErrors::LOAD_OK;
        });
        result = std::max(result, lh_cache_res.m_result);

        // Set the cache for this descriptor
        auto spk_man = (DescriptorScriptPubKeyMan*)pwallet->GetScriptPubKeyMan(id);
        assert(spk_man);
        spk_man->SetCache(cache);

        // Get unencrypted keys
        prefix = PrefixStream(DBKeys::WALLETDESCRIPTORKEY, id);
        LoadResult key_res = LoadRecords(pwallet, batch, DBKeys::WALLETDESCRIPTORKEY, prefix,
            [&id, &spk_man] (CWallet* pwallet, DataStream& key, DataStream& value, std::string& strErr) {
            uint256 desc_id;
            CPubKey pubkey;
            key >> desc_id;
            assert(desc_id == id);
            key >> pubkey;
            if (!pubkey.IsValid())
            {
                strErr = "Error reading wallet database: descriptor unencrypted key CPubKey corrupt";
                return DBErrors::CORRUPT;
            }
            CKey privkey;
            CPrivKey pkey;
            uint256 hash;

            value >> pkey;
            value >> hash;

            // hash pubkey/privkey to accelerate wallet load
            std::vector<unsigned char> to_hash;
            to_hash.reserve(pubkey.size() + pkey.size());
            to_hash.insert(to_hash.end(), pubkey.begin(), pubkey.end());
            to_hash.insert(to_hash.end(), pkey.begin(), pkey.end());

            if (Hash(to_hash) != hash)
            {
                strErr = "Error reading wallet database: descriptor unencrypted key CPubKey/CPrivKey corrupt";
                return DBErrors::CORRUPT;
            }

            if (!privkey.Load(pkey, pubkey, true))
            {
                strErr = "Error reading wallet database: descriptor unencrypted key CPrivKey corrupt";
                return DBErrors::CORRUPT;
            }
            spk_man->AddKey(pubkey.GetID(), privkey);
            return DBErrors::LOAD_OK;
        });
        result = std::max(result, key_res.m_result);
        num_keys = key_res.m_records;

        // Get encrypted keys
        prefix = PrefixStream(DBKeys::WALLETDESCRIPTORCKEY, id);
        LoadResult ckey_res = LoadRecords(pwallet, batch, DBKeys::WALLETDESCRIPTORCKEY, prefix,
            [&id, &spk_man] (CWallet* pwallet, DataStream& key, DataStream& value, std::string& err) {
            uint256 desc_id;
            CPubKey pubkey;
            key >> desc_id;
            assert(desc_id == id);
            key >> pubkey;
            if (!pubkey.IsValid())
            {
                err = "Error reading wallet database: descriptor encrypted key CPubKey corrupt";
                return DBErrors::CORRUPT;
            }
            std::vector<unsigned char> privkey;
            value >> privkey;

            spk_man->AddCryptedKey(pubkey.GetID(), pubkey, privkey);
            return DBErrors::LOAD_OK;
        });
        result = std::max(result, ckey_res.m_result);
        num_ckeys = ckey_res.m_records;

        return result;
    });

    if (desc_res.m_result <= DBErrors::NONCRITICAL_ERROR) {
        // Only log if there are no critical errors
        pwallet->WalletLogPrintf("Descriptors: %u, Descriptor Keys: %u plaintext, %u encrypted, %u total.\n",
               desc_res.m_records, num_keys, num_ckeys, num_keys + num_ckeys);
    }

    return desc_res.m_result;
}

static DBErrors LoadAddressBookRecords(CWallet* pwallet, DatabaseBatch& batch) EXCLUSIVE_LOCKS_REQUIRED(pwallet->cs_wallet)
{
    AssertLockHeld(pwallet->cs_wallet);
    DBErrors result = DBErrors::LOAD_OK;

    // Load name record
    LoadResult name_res = LoadRecords(pwallet, batch, DBKeys::NAME,
        [] (CWallet* pwallet, DataStream& key, DataStream& value, std::string& err) EXCLUSIVE_LOCKS_REQUIRED(pwallet->cs_wallet) {
        std::string strAddress;
        key >> strAddress;
        std::string label;
        value >> label;
        pwallet->m_address_book[DecodeDestination(strAddress)].SetLabel(label);
        return DBErrors::LOAD_OK;
    });
    result = std::max(result, name_res.m_result);

    // Load purpose record
    LoadResult purpose_res = LoadRecords(pwallet, batch, DBKeys::PURPOSE,
        [] (CWallet* pwallet, DataStream& key, DataStream& value, std::string& err) EXCLUSIVE_LOCKS_REQUIRED(pwallet->cs_wallet) {
        std::string strAddress;
        key >> strAddress;
        std::string purpose_str;
        value >> purpose_str;
        std::optional<AddressPurpose> purpose{PurposeFromString(purpose_str)};
        if (!purpose) {
            pwallet->WalletLogPrintf("Warning: nonstandard purpose string '%s' for address '%s'\n", purpose_str, strAddress);
        }
        pwallet->m_address_book[DecodeDestination(strAddress)].purpose = purpose;
        return DBErrors::LOAD_OK;
    });
    result = std::max(result, purpose_res.m_result);

    // Load destination data record
    LoadResult dest_res = LoadRecords(pwallet, batch, DBKeys::DESTDATA,
        [] (CWallet* pwallet, DataStream& key, DataStream& value, std::string& err) EXCLUSIVE_LOCKS_REQUIRED(pwallet->cs_wallet) {
        std::string strAddress, strKey, strValue;
        key >> strAddress;
        key >> strKey;
        value >> strValue;
        const CTxDestination& dest{DecodeDestination(strAddress)};
        if (strKey.compare("used") == 0) {
            // Load "used" key indicating if an IsMine address has
            // previously been spent from with avoid_reuse option enabled.
            // The strValue is not used for anything currently, but could
            // hold more information in the future. Current values are just
            // "1" or "p" for present (which was written prior to
            // f5ba424cd44619d9b9be88b8593d69a7ba96db26).
            pwallet->LoadAddressPreviouslySpent(dest);
        } else if (strKey.starts_with("rr")) {
            // Load "rr##" keys where ## is a decimal number, and strValue
            // is a serialized RecentRequestEntry object.
            pwallet->LoadAddressReceiveRequest(dest, strKey.substr(2), strValue);
        }
        return DBErrors::LOAD_OK;
    });
    result = std::max(result, dest_res.m_result);

    return result;
}

static DBErrors LoadRepoOfferRecords(CWallet* pwallet, DatabaseBatch& batch) EXCLUSIVE_LOCKS_REQUIRED(pwallet->cs_wallet)
{
    AssertLockHeld(pwallet->cs_wallet);
    LoadResult repo_res = LoadRecords(pwallet, batch, DBKeys::REPO_OFFER,
        [] (CWallet* wallet, DataStream& key, DataStream& value, std::string& err) EXCLUSIVE_LOCKS_REQUIRED(wallet->cs_wallet) {
            try {
                uint256 offer_id;
                key >> offer_id;

                RepoOfferRecord record;
                value >> record;

                if (record.offer_id.IsNull()) {
                    record.offer_id = offer_id;
                } else if (record.offer_id != offer_id) {
                    wallet->WalletLogPrintf("Warning: repo offer key (%s) mismatches stored id (%s)\n", offer_id.GetHex(), record.offer_id.GetHex());
                }

                wallet->LoadRepoOffer(record);
                return DBErrors::LOAD_OK;
            } catch (const std::exception& e) {
                err = e.what();
                return DBErrors::CORRUPT;
            }
        });

    return repo_res.m_result;
}

static DBErrors LoadSpotOfferRecords(CWallet* pwallet, DatabaseBatch& batch) EXCLUSIVE_LOCKS_REQUIRED(pwallet->cs_wallet)
{
    AssertLockHeld(pwallet->cs_wallet);
    LoadResult spot_res = LoadRecords(pwallet, batch, DBKeys::SPOT_OFFER,
        [] (CWallet* wallet, DataStream& key, DataStream& value, std::string& err) EXCLUSIVE_LOCKS_REQUIRED(wallet->cs_wallet) {
            try {
                uint256 offer_id;
                key >> offer_id;

                SpotOfferRecord record;
                value >> record;

                if (record.offer_id.IsNull()) {
                    record.offer_id = offer_id;
                } else if (record.offer_id != offer_id) {
                    wallet->WalletLogPrintf("Warning: spot offer key (%s) mismatches stored id (%s)\n", offer_id.GetHex(), record.offer_id.GetHex());
                }

                wallet->LoadSpotOffer(record);
                return DBErrors::LOAD_OK;
            } catch (const std::exception& e) {
                err = e.what();
                return DBErrors::CORRUPT;
            }
        });

    return spot_res.m_result;
}

static DBErrors LoadForwardContractRecords(CWallet* pwallet, DatabaseBatch& batch) EXCLUSIVE_LOCKS_REQUIRED(pwallet->cs_wallet)
{
    AssertLockHeld(pwallet->cs_wallet);
    LoadResult forward_res = LoadRecords(pwallet, batch, DBKeys::FORWARD_CONTRACT,
        [] (CWallet* wallet, DataStream& key, DataStream& value, std::string& err) EXCLUSIVE_LOCKS_REQUIRED(wallet->cs_wallet) {
            try {
                uint256 contract_id;
                key >> contract_id;

                ForwardContractRecord record;
                value >> record;

                if (record.contract_id.IsNull()) {
                    record.contract_id = contract_id;
                } else if (record.contract_id != contract_id) {
                    wallet->WalletLogPrintf("Warning: forward contract key (%s) mismatches stored id (%s)\n", contract_id.GetHex(), record.contract_id.GetHex());
                }

                wallet->LoadForwardContract(record);
                return DBErrors::LOAD_OK;
            } catch (const std::exception& e) {
                err = e.what();
                return DBErrors::CORRUPT;
            }
        });

    return forward_res.m_result;
}

static DBErrors LoadDifficultyContractRecords(CWallet* pwallet, DatabaseBatch& batch) EXCLUSIVE_LOCKS_REQUIRED(pwallet->cs_wallet)
{
    AssertLockHeld(pwallet->cs_wallet);
    LoadResult diff_res = LoadRecords(pwallet, batch, DBKeys::DIFFICULTY_CONTRACT,
        [] (CWallet* wallet, DataStream& key, DataStream& value, std::string& err) EXCLUSIVE_LOCKS_REQUIRED(wallet->cs_wallet) {
            try {
                uint256 contract_id;
                key >> contract_id;

                DifficultyContractRecord record;
                value >> record;

                if (record.contract_id.IsNull()) {
                    record.contract_id = contract_id;
                } else if (record.contract_id != contract_id) {
                    wallet->WalletLogPrintf("Warning: difficulty contract key (%s) mismatches stored id (%s)\n", contract_id.GetHex(), record.contract_id.GetHex());
                }

                wallet->LoadDifficultyContract(record);
                return DBErrors::LOAD_OK;
            } catch (const std::exception& e) {
                err = e.what();
                return DBErrors::CORRUPT;
            }
        });

    return diff_res.m_result;
}

static DBErrors LoadOptionSeriesRecords(CWallet* pwallet, DatabaseBatch& batch) EXCLUSIVE_LOCKS_REQUIRED(pwallet->cs_wallet)
{
    AssertLockHeld(pwallet->cs_wallet);
    LoadResult opt_res = LoadRecords(pwallet, batch, DBKeys::OPTION_SERIES,
        [] (CWallet* wallet, DataStream& key, DataStream& value, std::string& err) EXCLUSIVE_LOCKS_REQUIRED(wallet->cs_wallet) {
            try {
                uint256 series_id;
                key >> series_id;

                OptionSeriesRecord record;
                value >> record;

                // Backfill a null stored id to the DERIVED id (never the raw DB key), then enforce
                // series_id == ComputeOptionSeriesId(terms) == the DB key, plus a well-formed vault set.
                if (record.series_id.IsNull()) record.series_id = ComputeOptionSeriesId(record.terms);
                std::string verr;
                if (!ValidateOptionSeriesRecord(record, &series_id, verr)) {
                    err = strprintf("option series %s integrity check failed: %s", series_id.GetHex(), verr);
                    return DBErrors::CORRUPT;
                }

                wallet->LoadOptionSeries(record);
                return DBErrors::LOAD_OK;
            } catch (const std::exception& e) {
                err = e.what();
                return DBErrors::CORRUPT;
            }
        });

    return opt_res.m_result;
}

static DBErrors LoadScalarNotePairRecords(CWallet* pwallet, DatabaseBatch& batch) EXCLUSIVE_LOCKS_REQUIRED(pwallet->cs_wallet)
{
    AssertLockHeld(pwallet->cs_wallet);
    LoadResult res = LoadRecords(pwallet, batch, DBKeys::SCALAR_NOTE_PAIR,
        [] (CWallet* wallet, DataStream& key, DataStream& value, std::string& err) EXCLUSIVE_LOCKS_REQUIRED(wallet->cs_wallet) {
            try {
                uint256 pair_id;
                key >> pair_id;

                ScalarNotePairRecord record;
                value >> record;

                // Backfill a null stored id to the DERIVED id (never the raw DB key), then enforce
                // pair_id == ComputeScalarNotePairId(terms) == the DB key, plus a well-formed vault set.
                if (record.pair_id.IsNull()) record.pair_id = ComputeScalarNotePairId(record.terms);
                std::string verr;
                if (!ValidateScalarNotePairRecord(record, &pair_id, verr)) {
                    err = strprintf("scalar note pair %s integrity check failed: %s", pair_id.GetHex(), verr);
                    return DBErrors::CORRUPT;
                }

                wallet->LoadScalarNotePair(record);
                return DBErrors::LOAD_OK;
            } catch (const std::exception& e) {
                err = e.what();
                return DBErrors::CORRUPT;
            }
        });

    return res.m_result;
}

static DBErrors LoadScalarCfdContractRecords(CWallet* pwallet, DatabaseBatch& batch) EXCLUSIVE_LOCKS_REQUIRED(pwallet->cs_wallet)
{
    AssertLockHeld(pwallet->cs_wallet);
    LoadResult res = LoadRecords(pwallet, batch, DBKeys::SCALAR_CFD_CONTRACT,
        [] (CWallet* wallet, DataStream& key, DataStream& value, std::string& err) EXCLUSIVE_LOCKS_REQUIRED(wallet->cs_wallet) {
            try {
                uint256 contract_id;
                key >> contract_id;

                ScalarCfdContractRecord record;
                value >> record;

                // contract_id is a pure function of (terms, salt): backfill a null stored id, then run the
                // FULL record integrity gate (DB key == recomputed id, valid terms, NUMS vault internals,
                // valid coop internals, complete Fair-Sign state) — not just id + terms.
                if (record.contract_id.IsNull()) record.contract_id = ComputeScalarCfdContractId(record.terms, record.salt);
                std::string verr;
                if (!ValidateScalarCfdContractRecord(record, &contract_id, verr)) {
                    err = strprintf("scalar CFD contract %s integrity check failed: %s", contract_id.GetHex(), verr);
                    return DBErrors::CORRUPT;
                }

                wallet->LoadScalarCfdContract(record);
                return DBErrors::LOAD_OK;
            } catch (const std::exception& e) {
                err = e.what();
                return DBErrors::CORRUPT;
            }
        });

    return res.m_result;
}

static DBErrors LoadCrossChainRecords(CWallet* pwallet, DatabaseBatch& batch) EXCLUSIVE_LOCKS_REQUIRED(pwallet->cs_wallet)
{
    AssertLockHeld(pwallet->cs_wallet);
    LoadResult xchain_res = LoadRecords(pwallet, batch, DBKeys::CROSS_CHAIN_RECORD,
        [] (CWallet* wallet, DataStream& key, DataStream& value, std::string& err) EXCLUSIVE_LOCKS_REQUIRED(wallet->cs_wallet) {
            try {
                std::string swap_id;
                key >> swap_id;

                CrossChainRecord record;
                value >> record;

                if (record.swap_id.empty()) {
                    record.swap_id = swap_id;
                } else if (record.swap_id != swap_id) {
                    wallet->WalletLogPrintf("Warning: cross-chain record key (%s) mismatches stored id (%s)\n", swap_id, record.swap_id);
                }

                wallet->LoadCrossChainRecord(record);
                return DBErrors::LOAD_OK;
            } catch (const std::exception& e) {
                err = e.what();
                return DBErrors::CORRUPT;
            }
        });

    return xchain_res.m_result;
}

static DBErrors LoadSettlementProfiles(CWallet* pwallet, DatabaseBatch& batch) EXCLUSIVE_LOCKS_REQUIRED(pwallet->cs_wallet)
{
    AssertLockHeld(pwallet->cs_wallet);
    LoadResult profile_res = LoadRecords(pwallet, batch, DBKeys::SETTLEMENT_PROFILE,
        [] (CWallet* wallet, DataStream& key, DataStream& value, std::string& err) EXCLUSIVE_LOCKS_REQUIRED(wallet->cs_wallet) {
            try {
                std::string profile_id;
                key >> profile_id;

                SettlementProfile profile;
                value >> profile;

                wallet->LoadSettlementProfile(profile_id, profile);
                return DBErrors::LOAD_OK;
            } catch (const std::exception& e) {
                err = e.what();
                return DBErrors::CORRUPT;
            }
        });

    return profile_res.m_result;
}

static DBErrors LoadAssetDekRecords(CWallet* pwallet, DatabaseBatch& batch) EXCLUSIVE_LOCKS_REQUIRED(pwallet->cs_wallet)
{
    AssertLockHeld(pwallet->cs_wallet);
    LoadResult dek_res = LoadRecords(pwallet, batch, DBKeys::ASSET_DEK,
        [] (CWallet* wallet, DataStream& key, DataStream& value, std::string& err) EXCLUSIVE_LOCKS_REQUIRED(wallet->cs_wallet) {
            try {
                uint256 asset_id;
                key >> asset_id;

                std::string dek;
                value >> dek;

                if (dek.empty()) {
                    err = strprintf("Empty DEK for asset %s", asset_id.ToString());
                    return DBErrors::CORRUPT;
                }

                wallet->m_asset_deks[asset_id] = dek;
                wallet->WalletLogPrintf("LoadAssetDekRecords: Loaded DEK for asset %s\n", asset_id.ToString());

                return DBErrors::LOAD_OK;
            } catch (const std::exception& e) {
                err = e.what();
                return DBErrors::CORRUPT;
            }
        });

    return dek_res.m_result;
}

static DBErrors LoadVaultMetadataRecords(CWallet* pwallet, DatabaseBatch& batch) EXCLUSIVE_LOCKS_REQUIRED(pwallet->cs_wallet)
{
    AssertLockHeld(pwallet->cs_wallet);
    LoadResult vault_res = LoadRecords(pwallet, batch, DBKeys::VAULT_METADATA,
        [] (CWallet* wallet, DataStream& key, DataStream& value, std::string& err) EXCLUSIVE_LOCKS_REQUIRED(wallet->cs_wallet) {
            try {
                CScript script_pubkey;
                key >> script_pubkey;

                VaultMetadata metadata;
                value >> metadata;

                // Validate metadata before attempting registration
                if (!metadata.Validate()) {
                    err = strprintf("Invalid vault metadata for script %s", HexStr(script_pubkey));
                    return DBErrors::CORRUPT;
                }

                // Try to register vault with all descriptor SPKMs
                // The vault should match with the descriptor that has IsMine for the output
                bool registered = false;
                for (const auto& spk_man_pair : wallet->GetAllScriptPubKeyMans()) {
                    auto* desc_spkm = dynamic_cast<DescriptorScriptPubKeyMan*>(spk_man_pair);
                    if (!desc_spkm) continue;

                    // Directly register in the vault registry without needing base_script
                    // At load time, we skip the m_map_script_pub_keys mapping
                    // and just populate the vault registry
                    if (desc_spkm->LoadVaultFromDB(metadata)) {
                        registered = true;
                        wallet->WalletLogPrintf("LoadVaultMetadataRecords: Registered vault for script %s (contract: %s)\n",
                                              HexStr(script_pubkey),
                                              metadata.contract_id.ToString());
                        break;  // Successfully registered, done
                    }
                }

                if (!registered) {
                    // This is not fatal - vault may belong to a descriptor we don't have keys for
                    wallet->WalletLogPrintf("LoadVaultMetadataRecords: Could not register vault for script %s (no matching descriptor)\n",
                                          HexStr(script_pubkey));
                }

                return DBErrors::LOAD_OK;
            } catch (const std::exception& e) {
                err = e.what();
                return DBErrors::CORRUPT;
            }
        });

    return vault_res.m_result;
}

static DBErrors LoadTxRecords(CWallet* pwallet, DatabaseBatch& batch, std::vector<Txid>& upgraded_txs, bool& any_unordered) EXCLUSIVE_LOCKS_REQUIRED(pwallet->cs_wallet)
{
    AssertLockHeld(pwallet->cs_wallet);
    DBErrors result = DBErrors::LOAD_OK;

    // Load tx record
    any_unordered = false;
    LoadResult tx_res = LoadRecords(pwallet, batch, DBKeys::TX,
        [&any_unordered, &upgraded_txs] (CWallet* pwallet, DataStream& key, DataStream& value, std::string& err) EXCLUSIVE_LOCKS_REQUIRED(pwallet->cs_wallet) {
        DBErrors result = DBErrors::LOAD_OK;
        Txid hash;
        key >> hash;
        // LoadToWallet call below creates a new CWalletTx that fill_wtx
        // callback fills with transaction metadata.
        auto fill_wtx = [&](CWalletTx& wtx, bool new_tx) {
            if(!new_tx) {
                // There's some corruption here since the tx we just tried to load was already in the wallet.
                err = "Error: Corrupt transaction found. This can be fixed by removing transactions from wallet and rescanning.";
                result = DBErrors::CORRUPT;
                return false;
            }
            value >> wtx;
            if (wtx.GetHash() != hash)
                return false;

            // Undo serialize changes in 31600
            if (31404 <= wtx.fTimeReceivedIsTxTime && wtx.fTimeReceivedIsTxTime <= 31703)
            {
                if (!value.empty())
                {
                    uint8_t fTmp;
                    uint8_t fUnused;
                    std::string unused_string;
                    value >> fTmp >> fUnused >> unused_string;
                    pwallet->WalletLogPrintf("LoadWallet() upgrading tx ver=%d %d %s\n",
                                       wtx.fTimeReceivedIsTxTime, fTmp, hash.ToString());
                    wtx.fTimeReceivedIsTxTime = fTmp;
                }
                else
                {
                    pwallet->WalletLogPrintf("LoadWallet() repairing tx ver=%d %s\n", wtx.fTimeReceivedIsTxTime, hash.ToString());
                    wtx.fTimeReceivedIsTxTime = 0;
                }
                upgraded_txs.push_back(hash);
            }

            if (wtx.nOrderPos == -1)
                any_unordered = true;

            return true;
        };
        if (!pwallet->LoadToWallet(hash, fill_wtx)) {
            // Use std::max as fill_wtx may have already set result to CORRUPT
            result = std::max(result, DBErrors::NEED_RESCAN);
        }
        return result;
    });
    result = std::max(result, tx_res.m_result);

    // Load asset metadata records
    LoadResult asset_meta_res = LoadRecords(pwallet, batch, DBKeys::ASSET_META,
        [] (CWallet* pwallet, DataStream& key, DataStream& value, std::string& err) EXCLUSIVE_LOCKS_REQUIRED(pwallet->cs_wallet) {
        Txid hash;
        uint32_t index;
        key >> hash;
        key >> index;
        AssetMetadata meta;
        try {
            value >> meta;
        } catch (const std::exception& e) {
            err = e.what();
            return DBErrors::NONCRITICAL_ERROR;
        }
        pwallet->SetAssetMetadata(COutPoint(hash, index), meta);
        return DBErrors::LOAD_OK;
    });
    result = std::max(result, asset_meta_res.m_result);

    // Load asset DEK records
    LoadResult asset_dek_res = LoadRecords(pwallet, batch, DBKeys::ASSET_DEK,
        [] (CWallet* pwallet, DataStream& key, DataStream& value, std::string& err) EXCLUSIVE_LOCKS_REQUIRED(pwallet->cs_wallet) {
        uint256 asset_id;
        key >> asset_id;
        std::string dek;
        try {
            value >> dek;
        } catch (const std::exception& e) {
            err = e.what();
            return DBErrors::NONCRITICAL_ERROR;
        }
        pwallet->LoadAssetDek(asset_id, dek);
        return DBErrors::LOAD_OK;
    });
    result = std::max(result, asset_dek_res.m_result);

    // Load locked utxo record
    LoadResult locked_utxo_res = LoadRecords(pwallet, batch, DBKeys::LOCKED_UTXO,
        [] (CWallet* pwallet, DataStream& key, DataStream& value, std::string& err) EXCLUSIVE_LOCKS_REQUIRED(pwallet->cs_wallet) {
        Txid hash;
        uint32_t n;
        key >> hash;
        key >> n;
        pwallet->LockCoin(COutPoint(hash, n));
        return DBErrors::LOAD_OK;
    });
    result = std::max(result, locked_utxo_res.m_result);

    // Load orderposnext record
    // Note: There should only be one ORDERPOSNEXT record with nothing trailing the type
    LoadResult order_pos_res = LoadRecords(pwallet, batch, DBKeys::ORDERPOSNEXT,
        [] (CWallet* pwallet, DataStream& key, DataStream& value, std::string& err) EXCLUSIVE_LOCKS_REQUIRED(pwallet->cs_wallet) {
        try {
            value >> pwallet->nOrderPosNext;
        } catch (const std::exception& e) {
            err = e.what();
            return DBErrors::NONCRITICAL_ERROR;
        }
        return DBErrors::LOAD_OK;
    });
    result = std::max(result, order_pos_res.m_result);

    // After loading all tx records, abandon any coinbase that is no longer in the active chain.
    // This could happen during an external wallet load, or if the user replaced the chain data.
    for (auto& [id, wtx] : pwallet->mapWallet) {
        if (wtx.IsCoinBase() && wtx.isInactive()) {
            pwallet->AbandonTransaction(wtx);
        }
    }

    return result;
}

static DBErrors LoadActiveSPKMs(CWallet* pwallet, DatabaseBatch& batch) EXCLUSIVE_LOCKS_REQUIRED(pwallet->cs_wallet)
{
    AssertLockHeld(pwallet->cs_wallet);
    DBErrors result = DBErrors::LOAD_OK;

    // Load spk records
    std::set<std::pair<OutputType, bool>> seen_spks;
    for (const auto& spk_key : {DBKeys::ACTIVEEXTERNALSPK, DBKeys::ACTIVEINTERNALSPK}) {
        LoadResult spkm_res = LoadRecords(pwallet, batch, spk_key,
            [&seen_spks, &spk_key] (CWallet* pwallet, DataStream& key, DataStream& value, std::string& strErr) {
            uint8_t output_type;
            key >> output_type;
            uint256 id;
            value >> id;

            bool internal = spk_key == DBKeys::ACTIVEINTERNALSPK;
            auto [it, insert] = seen_spks.emplace(static_cast<OutputType>(output_type), internal);
            if (!insert) {
                strErr = "Multiple ScriptpubKeyMans specified for a single type";
                return DBErrors::CORRUPT;
            }
            pwallet->LoadActiveScriptPubKeyMan(id, static_cast<OutputType>(output_type), /*internal=*/internal);
            return DBErrors::LOAD_OK;
        });
        result = std::max(result, spkm_res.m_result);
    }
    return result;
}

static DBErrors LoadDecryptionKeys(CWallet* pwallet, DatabaseBatch& batch) EXCLUSIVE_LOCKS_REQUIRED(pwallet->cs_wallet)
{
    AssertLockHeld(pwallet->cs_wallet);

    // Load decryption key (mkey) records
    LoadResult mkey_res = LoadRecords(pwallet, batch, DBKeys::MASTER_KEY,
        [] (CWallet* pwallet, DataStream& key, DataStream& value, std::string& err) {
        if (!LoadEncryptionKey(pwallet, key, value, err)) {
            return DBErrors::CORRUPT;
        }
        return DBErrors::LOAD_OK;
    });
    return mkey_res.m_result;
}

DBErrors WalletBatch::LoadWallet(CWallet* pwallet)
{
    DBErrors result = DBErrors::LOAD_OK;
    bool any_unordered = false;
    std::vector<Txid> upgraded_txs;

    LOCK(pwallet->cs_wallet);

    // Last client version to open this wallet
    int last_client = CLIENT_VERSION;
    bool has_last_client = m_batch->Read(DBKeys::VERSION, last_client);
    pwallet->WalletLogPrintf("Wallet file version = %d, last client version = %d\n", pwallet->GetVersion(), last_client);

    try {
        if ((result = LoadMinVersion(pwallet, *m_batch)) != DBErrors::LOAD_OK) return result;

        // Load wallet flags, so they are known when processing other records.
        // The FLAGS key is absent during wallet creation.
        if ((result = LoadWalletFlags(pwallet, *m_batch)) != DBErrors::LOAD_OK) return result;

#ifndef ENABLE_EXTERNAL_SIGNER
        if (pwallet->IsWalletFlagSet(WALLET_FLAG_EXTERNAL_SIGNER)) {
            pwallet->WalletLogPrintf("Error: External signer wallet being loaded without external signer support compiled\n");
            return DBErrors::EXTERNAL_SIGNER_SUPPORT_REQUIRED;
        }
#endif

        // Load legacy wallet keys
        result = std::max(LoadLegacyWalletRecords(pwallet, *m_batch, last_client), result);

        // Load descriptors
        result = std::max(LoadDescriptorWalletRecords(pwallet, *m_batch, last_client), result);
        // Early return if there are unknown descriptors. Later loading of ACTIVEINTERNALSPK and ACTIVEEXTERNALEXPK
        // may reference the unknown descriptor's ID which can result in a misleading corruption error
        // when in reality the wallet is simply too new.
        if (result == DBErrors::UNKNOWN_DESCRIPTOR) return result;

        // Load address book
        result = std::max(LoadAddressBookRecords(pwallet, *m_batch), result);

        // Load repo offers
        result = std::max(LoadRepoOfferRecords(pwallet, *m_batch), result);
        result = std::max(LoadSpotOfferRecords(pwallet, *m_batch), result);
        result = std::max(LoadForwardContractRecords(pwallet, *m_batch), result);
        result = std::max(LoadDifficultyContractRecords(pwallet, *m_batch), result);
        result = std::max(LoadOptionSeriesRecords(pwallet, *m_batch), result);
        result = std::max(LoadScalarNotePairRecords(pwallet, *m_batch), result);
        result = std::max(LoadScalarCfdContractRecords(pwallet, *m_batch), result);

        // Load cross-chain records and settlement profiles
        result = std::max(LoadCrossChainRecords(pwallet, *m_batch), result);
        result = std::max(LoadSettlementProfiles(pwallet, *m_batch), result);

        // Load vault metadata (Note: vaults will need re-registration via contract rebuilding)
        result = std::max(LoadVaultMetadataRecords(pwallet, *m_batch), result);

        // Load asset DEKs for ICU encryption
        result = std::max(LoadAssetDekRecords(pwallet, *m_batch), result);

        // Load tx records
        result = std::max(LoadTxRecords(pwallet, *m_batch, upgraded_txs, any_unordered), result);

        // Load SPKMs
        result = std::max(LoadActiveSPKMs(pwallet, *m_batch), result);

        // Load decryption keys
        result = std::max(LoadDecryptionKeys(pwallet, *m_batch), result);
    } catch (...) {
        // Exceptions that can be ignored or treated as non-critical are handled by the individual loading functions.
        // Any uncaught exceptions will be caught here and treated as critical.
        result = DBErrors::CORRUPT;
    }

    // Any wallet corruption at all: skip any rewriting or
    // upgrading, we don't want to make it worse.
    if (result != DBErrors::LOAD_OK)
        return result;

    for (const Txid& hash : upgraded_txs)
        WriteTx(pwallet->mapWallet.at(hash));

    if (!has_last_client || last_client != CLIENT_VERSION) // Update
        m_batch->Write(DBKeys::VERSION, CLIENT_VERSION);

    if (any_unordered)
        result = pwallet->ReorderTransactions();

    // Upgrade all of the descriptor caches to cache the last hardened xpub
    // This operation is not atomic, but if it fails, only new entries are added so it is backwards compatible
    try {
        pwallet->UpgradeDescriptorCache();
    } catch (...) {
        result = DBErrors::CORRUPT;
    }

    // Since it was accidentally possible to "encrypt" a wallet with private keys disabled, we should check if this is
    // such a wallet and remove the encryption key records to avoid any future issues.
    // Although wallets without private keys should not have *ckey records, we should double check that.
    // Removing the mkey records is only safe if there are no *ckey records.
    if (pwallet->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS) && pwallet->HasEncryptionKeys() && !pwallet->HaveCryptedKeys()) {
        pwallet->WalletLogPrintf("Detected extraneous encryption keys in this wallet without private keys. Removing extraneous encryption keys.\n");
        for (const auto& [id, _] : pwallet->mapMasterKeys) {
            if (!EraseMasterKey(id)) {
                pwallet->WalletLogPrintf("Error: Unable to remove extraneous encryption key '%u'. Wallet corrupt.\n", id);
                return DBErrors::CORRUPT;
            }
        }
        pwallet->mapMasterKeys.clear();
    }

    return result;
}

static bool RunWithinTxn(WalletBatch& batch, std::string_view process_desc, const std::function<bool(WalletBatch&)>& func)
{
    if (!batch.TxnBegin()) {
        LogDebug(BCLog::WALLETDB, "Error: cannot create db txn for %s\n", process_desc);
        return false;
    }

    // Run procedure
    if (!func(batch)) {
        LogDebug(BCLog::WALLETDB, "Error: %s failed\n", process_desc);
        batch.TxnAbort();
        return false;
    }

    if (!batch.TxnCommit()) {
        LogDebug(BCLog::WALLETDB, "Error: cannot commit db txn for %s\n", process_desc);
        return false;
    }

    // All good
    return true;
}

bool RunWithinTxn(WalletDatabase& database, std::string_view process_desc, const std::function<bool(WalletBatch&)>& func)
{
    WalletBatch batch(database);
    return RunWithinTxn(batch, process_desc, func);
}

bool WalletBatch::WriteAddressPreviouslySpent(const CTxDestination& dest, bool previously_spent)
{
    auto key{std::make_pair(DBKeys::DESTDATA, std::make_pair(EncodeDestination(dest), std::string("used")))};
    return previously_spent ? WriteIC(key, std::string("1")) : EraseIC(key);
}

bool WalletBatch::WriteAddressReceiveRequest(const CTxDestination& dest, const std::string& id, const std::string& receive_request)
{
    return WriteIC(std::make_pair(DBKeys::DESTDATA, std::make_pair(EncodeDestination(dest), "rr" + id)), receive_request);
}

bool WalletBatch::EraseAddressReceiveRequest(const CTxDestination& dest, const std::string& id)
{
    return EraseIC(std::make_pair(DBKeys::DESTDATA, std::make_pair(EncodeDestination(dest), "rr" + id)));
}

bool WalletBatch::EraseAddressData(const CTxDestination& dest)
{
    DataStream prefix;
    prefix << DBKeys::DESTDATA << EncodeDestination(dest);
    return m_batch->ErasePrefix(prefix);
}

bool WalletBatch::WriteWalletFlags(const uint64_t flags)
{
    return WriteIC(DBKeys::FLAGS, flags);
}

bool WalletBatch::EraseRecords(const std::unordered_set<std::string>& types)
{
    return std::all_of(types.begin(), types.end(), [&](const std::string& type) {
        return m_batch->ErasePrefix(DataStream() << type);
    });
}

bool WalletBatch::TxnBegin()
{
    return m_batch->TxnBegin();
}

bool WalletBatch::TxnCommit()
{
    bool res = m_batch->TxnCommit();
    if (res) {
        for (const auto& listener : m_txn_listeners) {
            listener.on_commit();
        }
        // txn finished, clear listeners
        m_txn_listeners.clear();
    }
    return res;
}

bool WalletBatch::TxnAbort()
{
    bool res = m_batch->TxnAbort();
    if (res) {
        for (const auto& listener : m_txn_listeners) {
            listener.on_abort();
        }
        // txn finished, clear listeners
        m_txn_listeners.clear();
    }
    return res;
}

void WalletBatch::RegisterTxnListener(const DbTxnListener& l)
{
    assert(m_batch->HasActiveTxn());
    m_txn_listeners.emplace_back(l);
}

std::unique_ptr<WalletDatabase> MakeDatabase(const fs::path& path, const DatabaseOptions& options, DatabaseStatus& status, bilingual_str& error)
{
    bool exists;
    try {
        exists = fs::symlink_status(path).type() != fs::file_type::not_found;
    } catch (const fs::filesystem_error& e) {
        error = Untranslated(strprintf("Failed to access database path '%s': %s", fs::PathToString(path), e.code().message()));
        status = DatabaseStatus::FAILED_BAD_PATH;
        return nullptr;
    }

    std::optional<DatabaseFormat> format;
    if (exists) {
        if (IsBDBFile(BDBDataFile(path))) {
            format = DatabaseFormat::BERKELEY_RO;
        }
        if (IsSQLiteFile(SQLiteDataFile(path))) {
            if (format) {
                error = Untranslated(strprintf("Failed to load database path '%s'. Data is in ambiguous format.", fs::PathToString(path)));
                status = DatabaseStatus::FAILED_BAD_FORMAT;
                return nullptr;
            }
            format = DatabaseFormat::SQLITE;
        }
    } else if (options.require_existing) {
        error = Untranslated(strprintf("Failed to load database path '%s'. Path does not exist.", fs::PathToString(path)));
        status = DatabaseStatus::FAILED_NOT_FOUND;
        return nullptr;
    }

    if (!format && options.require_existing) {
        error = Untranslated(strprintf("Failed to load database path '%s'. Data is not in recognized format.", fs::PathToString(path)));
        status = DatabaseStatus::FAILED_BAD_FORMAT;
        return nullptr;
    }

    if (format && options.require_create) {
        error = Untranslated(strprintf("Failed to create database path '%s'. Database already exists.", fs::PathToString(path)));
        status = DatabaseStatus::FAILED_ALREADY_EXISTS;
        return nullptr;
    }

    // BERKELEY_RO can only be opened if require_format was set, which only occurs in migration.
    if (format && format == DatabaseFormat::BERKELEY_RO && (!options.require_format || options.require_format != DatabaseFormat::BERKELEY_RO)) {
        error = Untranslated(strprintf("Failed to open database path '%s'. The wallet appears to be a Legacy wallet, please use the wallet migration tool (migratewallet RPC).", fs::PathToString(path)));
        status = DatabaseStatus::FAILED_BAD_FORMAT;
        return nullptr;
    }

    // A db already exists so format is set, but options also specifies the format, so make sure they agree
    if (format && options.require_format && format != options.require_format) {
        error = Untranslated(strprintf("Failed to load database path '%s'. Data is not in required format.", fs::PathToString(path)));
        status = DatabaseStatus::FAILED_BAD_FORMAT;
        return nullptr;
    }

    // Format is not set when a db doesn't already exist, so use the format specified by the options if it is set.
    if (!format && options.require_format) format = options.require_format;

    if (!format) {
        format = DatabaseFormat::SQLITE;
    }

    if (format == DatabaseFormat::SQLITE) {
        return MakeSQLiteDatabase(path, options, status, error);
    }

    if (format == DatabaseFormat::BERKELEY_RO) {
        return MakeBerkeleyRODatabase(path, options, status, error);
    }

    error = Untranslated(STR_INTERNAL_BUG("Could not determine wallet format"));
    status = DatabaseStatus::FAILED_BAD_FORMAT;
    return nullptr;
}
} // namespace wallet
