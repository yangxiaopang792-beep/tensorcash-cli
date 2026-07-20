// Copyright (c) 2019-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <hash.h>
#include <key_io.h>
#include <logging.h>
#include <node/types.h>
#include <outputtype.h>
#include <script/descriptor.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/sign.h>
#include <script/solver.h>
#include <util/bip32.h>
#include <util/check.h>
#include <util/moneystr.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <util/time.h>
#include <util/translation.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/vault_signing.h>
#include <wallet/wallet.h>

#include <utility>
#include <optional>

using common::PSBTError;
using util::ToString;

namespace wallet {

typedef std::vector<unsigned char> valtype;

// Legacy wallet IsMine(). Used only in migration
// DO NOT USE ANYTHING IN THIS NAMESPACE OUTSIDE OF MIGRATION
namespace {

/**
 * This is an enum that tracks the execution context of a script, similar to
 * SigVersion in script/interpreter. It is separate however because we want to
 * distinguish between top-level scriptPubKey execution and P2SH redeemScript
 * execution (a distinction that has no impact on consensus rules).
 */
enum class IsMineSigVersion
{
    TOP = 0,        //!< scriptPubKey execution
    P2SH = 1,       //!< P2SH redeemScript
    WITNESS_V0 = 2, //!< P2WSH witness script execution
};

/**
 * This is an internal representation of isminetype + invalidity.
 * Its order is significant, as we return the max of all explored
 * possibilities.
 */
enum class IsMineResult
{
    NO = 0,         //!< Not ours
    WATCH_ONLY = 1, //!< Included in watch-only balance
    SPENDABLE = 2,  //!< Included in all balances
    INVALID = 3,    //!< Not spendable by anyone (uncompressed pubkey in segwit, P2SH inside P2SH or witness, witness inside witness)
};

bool PermitsUncompressed(IsMineSigVersion sigversion)
{
    return sigversion == IsMineSigVersion::TOP || sigversion == IsMineSigVersion::P2SH;
}

bool HaveKeys(const std::vector<valtype>& pubkeys, const LegacyDataSPKM& keystore)
{
    for (const valtype& pubkey : pubkeys) {
        CKeyID keyID = CPubKey(pubkey).GetID();
        if (!keystore.HaveKey(keyID)) return false;
    }
    return true;
}

//! Recursively solve script and return spendable/watchonly/invalid status.
//!
//! @param keystore            legacy key and script store
//! @param scriptPubKey        script to solve
//! @param sigversion          script type (top-level / redeemscript / witnessscript)
//! @param recurse_scripthash  whether to recurse into nested p2sh and p2wsh
//!                            scripts or simply treat any script that has been
//!                            stored in the keystore as spendable
// NOLINTNEXTLINE(misc-no-recursion)
IsMineResult LegacyWalletIsMineInnerDONOTUSE(const LegacyDataSPKM& keystore, const CScript& scriptPubKey, IsMineSigVersion sigversion, bool recurse_scripthash=true)
{
    IsMineResult ret = IsMineResult::NO;

    std::vector<valtype> vSolutions;
    TxoutType whichType = Solver(scriptPubKey, vSolutions);

    CKeyID keyID;
    switch (whichType) {
    case TxoutType::NONSTANDARD:
    case TxoutType::NULL_DATA:
    case TxoutType::WITNESS_UNKNOWN:
    case TxoutType::WITNESS_V1_TAPROOT:
    case TxoutType::WITNESS_V2_TAPROOT:
        // Witness v2 (ML-DSA post-quantum) outputs
        // Mark as watch-only so wallet tracks them - actual signing uses ML-DSA keys
        // The PSBT signing code will load ML-DSA keys from database when needed
        ret = std::max(ret, IsMineResult::WATCH_ONLY);
        break;
    case TxoutType::ANCHOR:
        break;
    case TxoutType::PUBKEY:
        keyID = CPubKey(vSolutions[0]).GetID();
        if (!PermitsUncompressed(sigversion) && vSolutions[0].size() != 33) {
            return IsMineResult::INVALID;
        }
        if (keystore.HaveKey(keyID)) {
            ret = std::max(ret, IsMineResult::SPENDABLE);
        }
        break;
    case TxoutType::WITNESS_V0_KEYHASH:
    {
        if (sigversion == IsMineSigVersion::WITNESS_V0) {
            // P2WPKH inside P2WSH is invalid.
            return IsMineResult::INVALID;
        }
        if (sigversion == IsMineSigVersion::TOP && !keystore.HaveCScript(CScriptID(CScript() << OP_0 << vSolutions[0]))) {
            // We do not support bare witness outputs unless the P2SH version of it would be
            // acceptable as well. This protects against matching before segwit activates.
            // This also applies to the P2WSH case.
            break;
        }
        ret = std::max(ret, LegacyWalletIsMineInnerDONOTUSE(keystore, GetScriptForDestination(PKHash(uint160(vSolutions[0]))), IsMineSigVersion::WITNESS_V0));
        break;
    }
    case TxoutType::PUBKEYHASH:
        keyID = CKeyID(uint160(vSolutions[0]));
        if (!PermitsUncompressed(sigversion)) {
            CPubKey pubkey;
            if (keystore.GetPubKey(keyID, pubkey) && !pubkey.IsCompressed()) {
                return IsMineResult::INVALID;
            }
        }
        if (keystore.HaveKey(keyID)) {
            ret = std::max(ret, IsMineResult::SPENDABLE);
        }
        break;
    case TxoutType::SCRIPTHASH:
    {
        if (sigversion != IsMineSigVersion::TOP) {
            // P2SH inside P2WSH or P2SH is invalid.
            return IsMineResult::INVALID;
        }
        CScriptID scriptID = CScriptID(uint160(vSolutions[0]));
        CScript subscript;
        if (keystore.GetCScript(scriptID, subscript)) {
            ret = std::max(ret, recurse_scripthash ? LegacyWalletIsMineInnerDONOTUSE(keystore, subscript, IsMineSigVersion::P2SH) : IsMineResult::SPENDABLE);
        }
        break;
    }
    case TxoutType::WITNESS_V0_SCRIPTHASH:
    {
        if (sigversion == IsMineSigVersion::WITNESS_V0) {
            // P2WSH inside P2WSH is invalid.
            return IsMineResult::INVALID;
        }
        if (sigversion == IsMineSigVersion::TOP && !keystore.HaveCScript(CScriptID(CScript() << OP_0 << vSolutions[0]))) {
            break;
        }
        CScriptID scriptID{RIPEMD160(vSolutions[0])};
        CScript subscript;
        if (keystore.GetCScript(scriptID, subscript)) {
            ret = std::max(ret, recurse_scripthash ? LegacyWalletIsMineInnerDONOTUSE(keystore, subscript, IsMineSigVersion::WITNESS_V0) : IsMineResult::SPENDABLE);
        }
        break;
    }

    case TxoutType::MULTISIG:
    {
        // Never treat bare multisig outputs as ours (they can still be made watchonly-though)
        if (sigversion == IsMineSigVersion::TOP) {
            break;
        }

        // Only consider transactions "mine" if we own ALL the
        // keys involved. Multi-signature transactions that are
        // partially owned (somebody else has a key that can spend
        // them) enable spend-out-from-under-you attacks, especially
        // in shared-wallet situations.
        std::vector<valtype> keys(vSolutions.begin()+1, vSolutions.begin()+vSolutions.size()-1);
        if (!PermitsUncompressed(sigversion)) {
            for (size_t i = 0; i < keys.size(); i++) {
                if (keys[i].size() != 33) {
                    return IsMineResult::INVALID;
                }
            }
        }
        if (HaveKeys(keys, keystore)) {
            ret = std::max(ret, IsMineResult::SPENDABLE);
        }
        break;
    }
    } // no default case, so the compiler can warn about missing cases

    if (ret == IsMineResult::NO && keystore.HaveWatchOnly(scriptPubKey)) {
        ret = std::max(ret, IsMineResult::WATCH_ONLY);
    }
    return ret;
}

} // namespace

isminetype LegacyDataSPKM::IsMine(const CScript& script) const
{
    switch (LegacyWalletIsMineInnerDONOTUSE(*this, script, IsMineSigVersion::TOP)) {
    case IsMineResult::INVALID:
    case IsMineResult::NO:
        return ISMINE_NO;
    case IsMineResult::WATCH_ONLY:
        return ISMINE_WATCH_ONLY;
    case IsMineResult::SPENDABLE:
        return ISMINE_SPENDABLE;
    }
    assert(false);
}

bool LegacyDataSPKM::CheckDecryptionKey(const CKeyingMaterial& master_key)
{
    {
        LOCK(cs_KeyStore);
        assert(mapKeys.empty());

        bool keyPass = mapCryptedKeys.empty(); // Always pass when there are no encrypted keys
        bool keyFail = false;
        CryptedKeyMap::const_iterator mi = mapCryptedKeys.begin();
        WalletBatch batch(m_storage.GetDatabase());
        for (; mi != mapCryptedKeys.end(); ++mi)
        {
            const CPubKey &vchPubKey = (*mi).second.first;
            const std::vector<unsigned char> &vchCryptedSecret = (*mi).second.second;
            CKey key;
            if (!DecryptKey(master_key, vchCryptedSecret, vchPubKey, key))
            {
                keyFail = true;
                break;
            }
            keyPass = true;
            if (fDecryptionThoroughlyChecked)
                break;
            else {
                // Rewrite these encrypted keys with checksums
                batch.WriteCryptedKey(vchPubKey, vchCryptedSecret, mapKeyMetadata[vchPubKey.GetID()]);
            }
        }
        if (keyPass && keyFail)
        {
            LogPrintf("The wallet is probably corrupted: Some keys decrypt but not all.\n");
            throw std::runtime_error("Error unlocking wallet: some keys decrypt but not all. Your wallet file may be corrupt.");
        }
        if (keyFail || !keyPass)
            return false;
        fDecryptionThoroughlyChecked = true;
    }
    return true;
}

std::unique_ptr<SigningProvider> LegacyDataSPKM::GetSolvingProvider(const CScript& script) const
{
    return std::make_unique<LegacySigningProvider>(*this);
}

bool LegacyDataSPKM::CanProvide(const CScript& script, SignatureData& sigdata)
{
    IsMineResult ismine = LegacyWalletIsMineInnerDONOTUSE(*this, script, IsMineSigVersion::TOP, /* recurse_scripthash= */ false);
    if (ismine == IsMineResult::SPENDABLE || ismine == IsMineResult::WATCH_ONLY) {
        // If ismine, it means we recognize keys or script ids in the script, or
        // are watching the script itself, and we can at least provide metadata
        // or solving information, even if not able to sign fully.
        return true;
    } else {
        // If, given the stuff in sigdata, we could make a valid signature, then we can provide for this script
        ProduceSignature(*this, DUMMY_SIGNATURE_CREATOR, script, sigdata);
        if (!sigdata.signatures.empty()) {
            // If we could make signatures, make sure we have a private key to actually make a signature
            bool has_privkeys = false;
            for (const auto& key_sig_pair : sigdata.signatures) {
                has_privkeys |= HaveKey(key_sig_pair.first);
            }
            return has_privkeys;
        }
        return false;
    }
}

bool LegacyDataSPKM::LoadKey(const CKey& key, const CPubKey &pubkey)
{
    return AddKeyPubKeyInner(key, pubkey);
}

bool LegacyDataSPKM::LoadCScript(const CScript& redeemScript)
{
    /* A sanity check was added in pull #3843 to avoid adding redeemScripts
     * that never can be redeemed. However, old wallets may still contain
     * these. Do not add them to the wallet and warn. */
    if (redeemScript.size() > MAX_SCRIPT_ELEMENT_SIZE)
    {
        std::string strAddr = EncodeDestination(ScriptHash(redeemScript));
        WalletLogPrintf("%s: Warning: This wallet contains a redeemScript of size %i which exceeds maximum size %i thus can never be redeemed. Do not use address %s.\n", __func__, redeemScript.size(), MAX_SCRIPT_ELEMENT_SIZE, strAddr);
        return true;
    }

    return FillableSigningProvider::AddCScript(redeemScript);
}

void LegacyDataSPKM::LoadKeyMetadata(const CKeyID& keyID, const CKeyMetadata& meta)
{
    LOCK(cs_KeyStore);
    mapKeyMetadata[keyID] = meta;
}

void LegacyDataSPKM::LoadScriptMetadata(const CScriptID& script_id, const CKeyMetadata& meta)
{
    LOCK(cs_KeyStore);
    m_script_metadata[script_id] = meta;
}

bool LegacyDataSPKM::AddKeyPubKeyInner(const CKey& key, const CPubKey& pubkey)
{
    LOCK(cs_KeyStore);
    return FillableSigningProvider::AddKeyPubKey(key, pubkey);
}

bool LegacyDataSPKM::LoadCryptedKey(const CPubKey &vchPubKey, const std::vector<unsigned char> &vchCryptedSecret, bool checksum_valid)
{
    // Set fDecryptionThoroughlyChecked to false when the checksum is invalid
    if (!checksum_valid) {
        fDecryptionThoroughlyChecked = false;
    }

    return AddCryptedKeyInner(vchPubKey, vchCryptedSecret);
}

bool LegacyDataSPKM::AddCryptedKeyInner(const CPubKey &vchPubKey, const std::vector<unsigned char> &vchCryptedSecret)
{
    LOCK(cs_KeyStore);
    assert(mapKeys.empty());

    mapCryptedKeys[vchPubKey.GetID()] = make_pair(vchPubKey, vchCryptedSecret);
    ImplicitlyLearnRelatedKeyScripts(vchPubKey);
    return true;
}

bool LegacyDataSPKM::HaveWatchOnly(const CScript &dest) const
{
    LOCK(cs_KeyStore);
    return setWatchOnly.count(dest) > 0;
}

bool LegacyDataSPKM::LoadWatchOnly(const CScript &dest)
{
    return AddWatchOnlyInMem(dest);
}

static bool ExtractPubKey(const CScript &dest, CPubKey& pubKeyOut)
{
    std::vector<std::vector<unsigned char>> solutions;
    return Solver(dest, solutions) == TxoutType::PUBKEY &&
        (pubKeyOut = CPubKey(solutions[0])).IsFullyValid();
}

bool LegacyDataSPKM::AddWatchOnlyInMem(const CScript &dest)
{
    LOCK(cs_KeyStore);
    setWatchOnly.insert(dest);
    CPubKey pubKey;
    if (ExtractPubKey(dest, pubKey)) {
        mapWatchKeys[pubKey.GetID()] = pubKey;
        ImplicitlyLearnRelatedKeyScripts(pubKey);
    }
    return true;
}

void LegacyDataSPKM::LoadHDChain(const CHDChain& chain)
{
    LOCK(cs_KeyStore);
    m_hd_chain = chain;
}

void LegacyDataSPKM::AddInactiveHDChain(const CHDChain& chain)
{
    LOCK(cs_KeyStore);
    assert(!chain.seed_id.IsNull());
    m_inactive_hd_chains[chain.seed_id] = chain;
}

bool LegacyDataSPKM::HaveKey(const CKeyID &address) const
{
    LOCK(cs_KeyStore);
    if (!m_storage.HasEncryptionKeys()) {
        return FillableSigningProvider::HaveKey(address);
    }
    return mapCryptedKeys.count(address) > 0;
}

bool LegacyDataSPKM::GetKey(const CKeyID &address, CKey& keyOut) const
{
    LOCK(cs_KeyStore);
    if (!m_storage.HasEncryptionKeys()) {
        return FillableSigningProvider::GetKey(address, keyOut);
    }

    CryptedKeyMap::const_iterator mi = mapCryptedKeys.find(address);
    if (mi != mapCryptedKeys.end())
    {
        const CPubKey &vchPubKey = (*mi).second.first;
        const std::vector<unsigned char> &vchCryptedSecret = (*mi).second.second;
        return m_storage.WithEncryptionKey([&](const CKeyingMaterial& encryption_key) {
            return DecryptKey(encryption_key, vchCryptedSecret, vchPubKey, keyOut);
        });
    }
    return false;
}

bool LegacyDataSPKM::GetKeyOrigin(const CKeyID& keyID, KeyOriginInfo& info) const
{
    CKeyMetadata meta;
    {
        LOCK(cs_KeyStore);
        auto it = mapKeyMetadata.find(keyID);
        if (it == mapKeyMetadata.end()) {
            return false;
        }
        meta = it->second;
    }
    if (meta.has_key_origin) {
        std::copy(meta.key_origin.fingerprint, meta.key_origin.fingerprint + 4, info.fingerprint);
        info.path = meta.key_origin.path;
    } else { // Single pubkeys get the master fingerprint of themselves
        std::copy(keyID.begin(), keyID.begin() + 4, info.fingerprint);
    }
    return true;
}

bool LegacyDataSPKM::GetWatchPubKey(const CKeyID &address, CPubKey &pubkey_out) const
{
    LOCK(cs_KeyStore);
    WatchKeyMap::const_iterator it = mapWatchKeys.find(address);
    if (it != mapWatchKeys.end()) {
        pubkey_out = it->second;
        return true;
    }
    return false;
}

bool LegacyDataSPKM::GetPubKey(const CKeyID &address, CPubKey& vchPubKeyOut) const
{
    LOCK(cs_KeyStore);
    if (!m_storage.HasEncryptionKeys()) {
        if (!FillableSigningProvider::GetPubKey(address, vchPubKeyOut)) {
            return GetWatchPubKey(address, vchPubKeyOut);
        }
        return true;
    }

    CryptedKeyMap::const_iterator mi = mapCryptedKeys.find(address);
    if (mi != mapCryptedKeys.end())
    {
        vchPubKeyOut = (*mi).second.first;
        return true;
    }
    // Check for watch-only pubkeys
    return GetWatchPubKey(address, vchPubKeyOut);
}

std::unordered_set<CScript, SaltedSipHasher> LegacyDataSPKM::GetCandidateScriptPubKeys() const
{
    LOCK(cs_KeyStore);
    std::unordered_set<CScript, SaltedSipHasher> candidate_spks;

    // For every private key in the wallet, there should be a P2PK, P2PKH, P2WPKH, and P2SH-P2WPKH
    const auto& add_pubkey = [&candidate_spks](const CPubKey& pub) -> void {
        candidate_spks.insert(GetScriptForRawPubKey(pub));
        candidate_spks.insert(GetScriptForDestination(PKHash(pub)));

        CScript wpkh = GetScriptForDestination(WitnessV0KeyHash(pub));
        candidate_spks.insert(wpkh);
        candidate_spks.insert(GetScriptForDestination(ScriptHash(wpkh)));
    };
    for (const auto& [_, key] : mapKeys) {
        add_pubkey(key.GetPubKey());
    }
    for (const auto& [_, ckeypair] : mapCryptedKeys) {
        add_pubkey(ckeypair.first);
    }

    // mapScripts contains all redeemScripts and witnessScripts. Therefore each script in it has
    // itself, P2SH, P2WSH, and P2SH-P2WSH as a candidate.
    // Invalid scripts such as P2SH-P2SH and P2WSH-P2SH, among others, will be added as candidates.
    // Callers of this function will need to remove such scripts.
    const auto& add_script = [&candidate_spks](const CScript& script) -> void {
        candidate_spks.insert(script);
        candidate_spks.insert(GetScriptForDestination(ScriptHash(script)));

        CScript wsh = GetScriptForDestination(WitnessV0ScriptHash(script));
        candidate_spks.insert(wsh);
        candidate_spks.insert(GetScriptForDestination(ScriptHash(wsh)));
    };
    for (const auto& [_, script] : mapScripts) {
        add_script(script);
    }

    // Although setWatchOnly should only contain output scripts, we will also include each script's
    // P2SH, P2WSH, and P2SH-P2WSH as a precaution.
    for (const auto& script : setWatchOnly) {
        add_script(script);
    }

    return candidate_spks;
}

std::unordered_set<CScript, SaltedSipHasher> LegacyDataSPKM::GetScriptPubKeys() const
{
    // Run IsMine() on each candidate output script. Any script that is not ISMINE_NO is an output
    // script to return.
    // This both filters out things that are not watched by the wallet, and things that are invalid.
    std::unordered_set<CScript, SaltedSipHasher> spks;
    for (const CScript& script : GetCandidateScriptPubKeys()) {
        if (IsMine(script) != ISMINE_NO) {
            spks.insert(script);
        }
    }

    return spks;
}

std::unordered_set<CScript, SaltedSipHasher> LegacyDataSPKM::GetNotMineScriptPubKeys() const
{
    LOCK(cs_KeyStore);
    std::unordered_set<CScript, SaltedSipHasher> spks;
    for (const CScript& script : setWatchOnly) {
        if (IsMine(script) == ISMINE_NO) spks.insert(script);
    }
    return spks;
}

std::optional<MigrationData> LegacyDataSPKM::MigrateToDescriptor()
{
    LOCK(cs_KeyStore);
    if (m_storage.IsLocked()) {
        return std::nullopt;
    }

    MigrationData out;

    std::unordered_set<CScript, SaltedSipHasher> spks{GetScriptPubKeys()};

    // Get all key ids
    std::set<CKeyID> keyids;
    for (const auto& key_pair : mapKeys) {
        keyids.insert(key_pair.first);
    }
    for (const auto& key_pair : mapCryptedKeys) {
        keyids.insert(key_pair.first);
    }

    // Get key metadata and figure out which keys don't have a seed
    // Note that we do not ignore the seeds themselves because they are considered IsMine!
    for (auto keyid_it = keyids.begin(); keyid_it != keyids.end();) {
        const CKeyID& keyid = *keyid_it;
        const auto& it = mapKeyMetadata.find(keyid);
        if (it != mapKeyMetadata.end()) {
            const CKeyMetadata& meta = it->second;
            if (meta.hdKeypath == "s" || meta.hdKeypath == "m") {
                keyid_it++;
                continue;
            }
            if (!meta.hd_seed_id.IsNull() && (m_hd_chain.seed_id == meta.hd_seed_id || m_inactive_hd_chains.count(meta.hd_seed_id) > 0)) {
                keyid_it = keyids.erase(keyid_it);
                continue;
            }
        }
        keyid_it++;
    }

    WalletBatch batch(m_storage.GetDatabase());
    if (!batch.TxnBegin()) {
        LogPrintf("Error generating descriptors for migration, cannot initialize db transaction\n");
        return std::nullopt;
    }

    // keyids is now all non-HD keys. Each key will have its own combo descriptor
    for (const CKeyID& keyid : keyids) {
        CKey key;
        if (!GetKey(keyid, key)) {
            assert(false);
        }

        // Get birthdate from key meta
        uint64_t creation_time = 0;
        const auto& it = mapKeyMetadata.find(keyid);
        if (it != mapKeyMetadata.end()) {
            creation_time = it->second.nCreateTime;
        }

        // Get the key origin
        // Maybe this doesn't matter because floating keys here shouldn't have origins
        KeyOriginInfo info;
        bool has_info = GetKeyOrigin(keyid, info);
        std::string origin_str = has_info ? "[" + HexStr(info.fingerprint) + FormatHDKeypath(info.path) + "]" : "";

        // Construct the combo descriptor
        std::string desc_str = "combo(" + origin_str + HexStr(key.GetPubKey()) + ")";
        FlatSigningProvider keys;
        std::string error;
        std::vector<std::unique_ptr<Descriptor>> descs = Parse(desc_str, keys, error, false);
        CHECK_NONFATAL(descs.size() == 1); // It shouldn't be possible to have an invalid or multipath descriptor
        WalletDescriptor w_desc(std::move(descs.at(0)), creation_time, 0, 0, 0);

        // Make the DescriptorScriptPubKeyMan and get the scriptPubKeys
        auto desc_spk_man = std::make_unique<DescriptorScriptPubKeyMan>(m_storage, w_desc, /*keypool_size=*/0);
        WITH_LOCK(desc_spk_man->cs_desc_man, desc_spk_man->AddDescriptorKeyWithDB(batch, key, key.GetPubKey()));
        desc_spk_man->TopUpWithDB(batch);
        auto desc_spks = desc_spk_man->GetScriptPubKeys();

        // Remove the scriptPubKeys from our current set
        for (const CScript& spk : desc_spks) {
            size_t erased = spks.erase(spk);
            assert(erased == 1);
            assert(IsMine(spk) == ISMINE_SPENDABLE);
        }

        out.desc_spkms.push_back(std::move(desc_spk_man));
    }

    // Handle HD keys by using the CHDChains
    std::vector<CHDChain> chains;
    chains.push_back(m_hd_chain);
    for (const auto& chain_pair : m_inactive_hd_chains) {
        chains.push_back(chain_pair.second);
    }
    for (const CHDChain& chain : chains) {
        for (int i = 0; i < 2; ++i) {
            // Skip if doing internal chain and split chain is not supported
            if (chain.seed_id.IsNull() || (i == 1 && !m_storage.CanSupportFeature(FEATURE_HD_SPLIT))) {
                continue;
            }
            // Get the master xprv
            CKey seed_key;
            if (!GetKey(chain.seed_id, seed_key)) {
                assert(false);
            }
            CExtKey master_key;
            master_key.SetSeed(seed_key);

            // Make the combo descriptor
            std::string xpub = EncodeExtPubKey(master_key.Neuter());
            std::string desc_str = "combo(" + xpub + "/0h/" + ToString(i) + "h/*h)";
            FlatSigningProvider keys;
            std::string error;
            std::vector<std::unique_ptr<Descriptor>> descs = Parse(desc_str, keys, error, false);
            CHECK_NONFATAL(descs.size() == 1); // It shouldn't be possible to have an invalid or multipath descriptor
            uint32_t chain_counter = std::max((i == 1 ? chain.nInternalChainCounter : chain.nExternalChainCounter), (uint32_t)0);
            WalletDescriptor w_desc(std::move(descs.at(0)), 0, 0, chain_counter, 0);

            // Make the DescriptorScriptPubKeyMan and get the scriptPubKeys
            auto desc_spk_man = std::make_unique<DescriptorScriptPubKeyMan>(m_storage, w_desc, /*keypool_size=*/0);
            WITH_LOCK(desc_spk_man->cs_desc_man, desc_spk_man->AddDescriptorKeyWithDB(batch, master_key.key, master_key.key.GetPubKey()));
            desc_spk_man->TopUpWithDB(batch);
            auto desc_spks = desc_spk_man->GetScriptPubKeys();

            // Remove the scriptPubKeys from our current set
            for (const CScript& spk : desc_spks) {
                size_t erased = spks.erase(spk);
                assert(erased == 1);
                assert(IsMine(spk) == ISMINE_SPENDABLE);
            }

            out.desc_spkms.push_back(std::move(desc_spk_man));
        }
    }
    // Add the current master seed to the migration data
    if (!m_hd_chain.seed_id.IsNull()) {
        CKey seed_key;
        if (!GetKey(m_hd_chain.seed_id, seed_key)) {
            assert(false);
        }
        out.master_key.SetSeed(seed_key);
    }

    // Handle the rest of the scriptPubKeys which must be imports and may not have all info
    for (auto it = spks.begin(); it != spks.end();) {
        const CScript& spk = *it;

        // Get birthdate from script meta
        uint64_t creation_time = 0;
        const auto& mit = m_script_metadata.find(CScriptID(spk));
        if (mit != m_script_metadata.end()) {
            creation_time = mit->second.nCreateTime;
        }

        // InferDescriptor as that will get us all the solving info if it is there
        std::unique_ptr<Descriptor> desc = InferDescriptor(spk, *GetSolvingProvider(spk));

        // Past bugs in InferDescriptor have caused it to create descriptors which cannot be re-parsed.
        // Re-parse the descriptors to detect that, and skip any that do not parse.
        {
            std::string desc_str = desc->ToString();
            FlatSigningProvider parsed_keys;
            std::string parse_error;
            std::vector<std::unique_ptr<Descriptor>> parsed_descs = Parse(desc_str, parsed_keys, parse_error);
            if (parsed_descs.empty()) {
                // Remove this scriptPubKey from the set
                it = spks.erase(it);
                continue;
            }
        }

        // Get the private keys for this descriptor
        std::vector<CScript> scripts;
        FlatSigningProvider keys;
        if (!desc->Expand(0, DUMMY_SIGNING_PROVIDER, scripts, keys)) {
            assert(false);
        }
        std::set<CKeyID> privkeyids;
        for (const auto& key_orig_pair : keys.origins) {
            privkeyids.insert(key_orig_pair.first);
        }

        std::vector<CScript> desc_spks;

        // Make the descriptor string with private keys
        std::string desc_str;
        bool watchonly = !desc->ToPrivateString(*this, desc_str);
        if (watchonly && !m_storage.IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
            out.watch_descs.emplace_back(desc->ToString(), creation_time);

            // Get the scriptPubKeys without writing this to the wallet
            FlatSigningProvider provider;
            desc->Expand(0, provider, desc_spks, provider);
        } else {
            // Make the DescriptorScriptPubKeyMan and get the scriptPubKeys
            WalletDescriptor w_desc(std::move(desc), creation_time, 0, 0, 0);
            auto desc_spk_man = std::make_unique<DescriptorScriptPubKeyMan>(m_storage, w_desc, /*keypool_size=*/0);
            for (const auto& keyid : privkeyids) {
                CKey key;
                if (!GetKey(keyid, key)) {
                    continue;
                }
                WITH_LOCK(desc_spk_man->cs_desc_man, desc_spk_man->AddDescriptorKeyWithDB(batch, key, key.GetPubKey()));
            }
            desc_spk_man->TopUpWithDB(batch);
            auto desc_spks_set = desc_spk_man->GetScriptPubKeys();
            desc_spks.insert(desc_spks.end(), desc_spks_set.begin(), desc_spks_set.end());

            out.desc_spkms.push_back(std::move(desc_spk_man));
        }

        // Remove the scriptPubKeys from our current set
        for (const CScript& desc_spk : desc_spks) {
            auto del_it = spks.find(desc_spk);
            assert(del_it != spks.end());
            assert(IsMine(desc_spk) != ISMINE_NO);
            it = spks.erase(del_it);
        }
    }

    // Make sure that we have accounted for all scriptPubKeys
    if (!Assume(spks.empty())) {
        LogPrintf("%s\n", STR_INTERNAL_BUG("Error: Some output scripts were not migrated.\n"));
        return std::nullopt;
    }

    // Legacy wallets can also contain scripts whose P2SH, P2WSH, or P2SH-P2WSH it is not watching for
    // but can provide script data to a PSBT spending them. These "solvable" output scripts will need to
    // be put into the separate "solvables" wallet.
    // These can be detected by going through the entire candidate output scripts, finding the ISMINE_NO scripts,
    // and checking CanProvide() which will dummy sign.
    for (const CScript& script : GetCandidateScriptPubKeys()) {
        // Since we only care about P2SH, P2WSH, and P2SH-P2WSH, filter out any scripts that are not those
        if (!script.IsPayToScriptHash() && !script.IsPayToWitnessScriptHash()) {
            continue;
        }
        if (IsMine(script) != ISMINE_NO) {
            continue;
        }
        SignatureData dummy_sigdata;
        if (!CanProvide(script, dummy_sigdata)) {
            continue;
        }

        // Get birthdate from script meta
        uint64_t creation_time = 0;
        const auto& it = m_script_metadata.find(CScriptID(script));
        if (it != m_script_metadata.end()) {
            creation_time = it->second.nCreateTime;
        }

        // InferDescriptor as that will get us all the solving info if it is there
        std::unique_ptr<Descriptor> desc = InferDescriptor(script, *GetSolvingProvider(script));
        if (!desc->IsSolvable()) {
            // The wallet was able to provide some information, but not enough to make a descriptor that actually
            // contains anything useful. This is probably because the script itself is actually unsignable (e.g. P2WSH-P2WSH).
            continue;
        }

        // Past bugs in InferDescriptor have caused it to create descriptors which cannot be re-parsed
        // Re-parse the descriptors to detect that, and skip any that do not parse.
        {
            std::string desc_str = desc->ToString();
            FlatSigningProvider parsed_keys;
            std::string parse_error;
            std::vector<std::unique_ptr<Descriptor>> parsed_descs = Parse(desc_str, parsed_keys, parse_error, false);
            if (parsed_descs.empty()) {
                continue;
            }
        }

        out.solvable_descs.emplace_back(desc->ToString(), creation_time);
    }

    // Finalize transaction
    if (!batch.TxnCommit()) {
        LogPrintf("Error generating descriptors for migration, cannot commit db transaction\n");
        return std::nullopt;
    }

    return out;
}

bool LegacyDataSPKM::DeleteRecordsWithDB(WalletBatch& batch)
{
    LOCK(cs_KeyStore);
    return batch.EraseRecords(DBKeys::LEGACY_TYPES);
}

util::Result<CTxDestination> DescriptorScriptPubKeyMan::GetNewDestination(const OutputType type)
{
    // Returns true if this descriptor supports getting new addresses. Conditions where we may be unable to fetch them (e.g. locked) are caught later
    if (!CanGetAddresses()) {
        return util::Error{_("No addresses available")};
    }
    {
        LOCK(cs_desc_man);
        assert(m_wallet_descriptor.descriptor->IsSingleType()); // This is a combo descriptor which should not be an active descriptor
        std::optional<OutputType> desc_addr_type = m_wallet_descriptor.descriptor->GetOutputType();
        assert(desc_addr_type);
        if (type != *desc_addr_type) {
            throw std::runtime_error(std::string(__func__) + ": Types are inconsistent. Stored type does not match type of newly generated address");
        }

        TopUp();

        // Get the scriptPubKey from the descriptor
        FlatSigningProvider out_keys;
        std::vector<CScript> scripts_temp;
        if (m_wallet_descriptor.range_end <= m_max_cached_index && !TopUp(1)) {
            // We can't generate anymore keys
            return util::Error{_("Error: Keypool ran out, please call keypoolrefill first")};
        }
        if (!m_wallet_descriptor.descriptor->ExpandFromCache(m_wallet_descriptor.next_index, m_wallet_descriptor.cache, scripts_temp, out_keys)) {
            // We can't generate anymore keys
            return util::Error{_("Error: Keypool ran out, please call keypoolrefill first")};
        }

        CTxDestination dest;
        if (!ExtractDestination(scripts_temp[0], dest)) {
            return util::Error{_("Error: Cannot extract destination from the generated scriptpubkey")}; // shouldn't happen
        }
        m_wallet_descriptor.next_index++;
        WalletBatch(m_storage.GetDatabase()).WriteDescriptor(GetID(), m_wallet_descriptor);
        return dest;
    }
}

isminetype DescriptorScriptPubKeyMan::IsMine(const CScript& script) const
{
    LOCK(cs_desc_man);
    if (m_map_script_pub_keys.count(script) > 0) {
        // Check if this is a registered covenant vault
        // Vaults should be WATCH_ONLY (can sign) but NOT SPENDABLE (not in balance)
        if (m_vault_registry.IsRegistered(script)) {
            return ISMINE_WATCH_ONLY;
        }
        return ISMINE_SPENDABLE;
    }
    return ISMINE_NO;
}

bool DescriptorScriptPubKeyMan::CheckDecryptionKey(const CKeyingMaterial& master_key)
{
    LOCK(cs_desc_man);
    if (!m_map_keys.empty()) {
        return false;
    }

    bool keyPass = m_map_crypted_keys.empty(); // Always pass when there are no encrypted keys
    bool keyFail = false;
    for (const auto& mi : m_map_crypted_keys) {
        const CPubKey &pubkey = mi.second.first;
        const std::vector<unsigned char> &crypted_secret = mi.second.second;
        CKey key;
        if (!DecryptKey(master_key, crypted_secret, pubkey, key)) {
            keyFail = true;
            break;
        }
        keyPass = true;
        if (m_decryption_thoroughly_checked)
            break;
    }
    if (keyPass && keyFail) {
        LogPrintf("The wallet is probably corrupted: Some keys decrypt but not all.\n");
        throw std::runtime_error("Error unlocking wallet: some keys decrypt but not all. Your wallet file may be corrupt.");
    }
    if (keyFail || !keyPass) {
        return false;
    }
    m_decryption_thoroughly_checked = true;
    return true;
}

bool DescriptorScriptPubKeyMan::Encrypt(const CKeyingMaterial& master_key, WalletBatch* batch)
{
    LOCK(cs_desc_man);
    if (!m_map_crypted_keys.empty()) {
        return false;
    }

    for (const KeyMap::value_type& key_in : m_map_keys)
    {
        const CKey &key = key_in.second;
        CPubKey pubkey = key.GetPubKey();
        CKeyingMaterial secret{UCharCast(key.begin()), UCharCast(key.end())};
        std::vector<unsigned char> crypted_secret;
        if (!EncryptSecret(master_key, secret, pubkey.GetHash(), crypted_secret)) {
            return false;
        }
        m_map_crypted_keys[pubkey.GetID()] = make_pair(pubkey, crypted_secret);
        batch->WriteCryptedDescriptorKey(GetID(), pubkey, crypted_secret);
    }
    m_map_keys.clear();
    return true;
}

util::Result<CTxDestination> DescriptorScriptPubKeyMan::GetReservedDestination(const OutputType type, bool internal, int64_t& index)
{
    LOCK(cs_desc_man);
    auto op_dest = GetNewDestination(type);
    index = m_wallet_descriptor.next_index - 1;
    return op_dest;
}

void DescriptorScriptPubKeyMan::ReturnDestination(int64_t index, bool internal, const CTxDestination& addr)
{
    LOCK(cs_desc_man);
    // Only return when the index was the most recent
    if (m_wallet_descriptor.next_index - 1 == index) {
        m_wallet_descriptor.next_index--;
    }
    WalletBatch(m_storage.GetDatabase()).WriteDescriptor(GetID(), m_wallet_descriptor);
    NotifyCanGetAddressesChanged();
}

std::map<CKeyID, CKey> DescriptorScriptPubKeyMan::GetKeys() const
{
    AssertLockHeld(cs_desc_man);
    if (m_storage.HasEncryptionKeys() && !m_storage.IsLocked()) {
        KeyMap keys;
        for (const auto& key_pair : m_map_crypted_keys) {
            const CPubKey& pubkey = key_pair.second.first;
            const std::vector<unsigned char>& crypted_secret = key_pair.second.second;
            CKey key;
            m_storage.WithEncryptionKey([&](const CKeyingMaterial& encryption_key) {
                return DecryptKey(encryption_key, crypted_secret, pubkey, key);
            });
            keys[pubkey.GetID()] = key;
        }
        return keys;
    }
    return m_map_keys;
}

bool DescriptorScriptPubKeyMan::HasPrivKey(const CKeyID& keyid) const
{
    AssertLockHeld(cs_desc_man);
    return m_map_keys.contains(keyid) || m_map_crypted_keys.contains(keyid);
}

std::optional<CKey> DescriptorScriptPubKeyMan::GetKey(const CKeyID& keyid) const
{
    AssertLockHeld(cs_desc_man);
    if (m_storage.HasEncryptionKeys() && !m_storage.IsLocked()) {
        const auto& it = m_map_crypted_keys.find(keyid);
        if (it == m_map_crypted_keys.end()) {
            return std::nullopt;
        }
        const std::vector<unsigned char>& crypted_secret = it->second.second;
        CKey key;
        if (!Assume(m_storage.WithEncryptionKey([&](const CKeyingMaterial& encryption_key) {
            return DecryptKey(encryption_key, crypted_secret, it->second.first, key);
        }))) {
            return std::nullopt;
        }
        return key;
    }
    const auto& it = m_map_keys.find(keyid);
    if (it == m_map_keys.end()) {
        return std::nullopt;
    }
    return it->second;
}

bool DescriptorScriptPubKeyMan::TopUp(unsigned int size)
{
    WalletBatch batch(m_storage.GetDatabase());
    if (!batch.TxnBegin()) return false;
    bool res = TopUpWithDB(batch, size);
    if (!batch.TxnCommit()) throw std::runtime_error(strprintf("Error during descriptors keypool top up. Cannot commit changes for wallet %s", m_storage.GetDisplayName()));
    return res;
}

bool DescriptorScriptPubKeyMan::TopUpWithDB(WalletBatch& batch, unsigned int size)
{
    LOCK(cs_desc_man);
    std::set<CScript> new_spks;
    unsigned int target_size;
    if (size > 0) {
        target_size = size;
    } else {
        target_size = m_keypool_size;
    }

    // Calculate the new range_end
    int32_t new_range_end = std::max(m_wallet_descriptor.next_index + (int32_t)target_size, m_wallet_descriptor.range_end);

    // If the descriptor is not ranged, we actually just want to fill the first cache item
    if (!m_wallet_descriptor.descriptor->IsRange()) {
        new_range_end = 1;
        m_wallet_descriptor.range_end = 1;
        m_wallet_descriptor.range_start = 0;
    }

    FlatSigningProvider provider;
    provider.keys = GetKeys();

    uint256 id = GetID();
    for (int32_t i = m_max_cached_index + 1; i < new_range_end; ++i) {
        FlatSigningProvider out_keys;
        std::vector<CScript> scripts_temp;
        DescriptorCache temp_cache;
        // Maybe we have a cached xpub and we can expand from the cache first
        if (!m_wallet_descriptor.descriptor->ExpandFromCache(i, m_wallet_descriptor.cache, scripts_temp, out_keys)) {
            if (!m_wallet_descriptor.descriptor->Expand(i, provider, scripts_temp, out_keys, &temp_cache)) return false;
        }
        // Add all of the scriptPubKeys to the scriptPubKey set
        new_spks.insert(scripts_temp.begin(), scripts_temp.end());
        for (const CScript& script : scripts_temp) {
            m_map_script_pub_keys[script] = i;
        }
        for (const auto& pk_pair : out_keys.pubkeys) {
            const CPubKey& pubkey = pk_pair.second;
            if (m_map_pubkeys.count(pubkey) != 0) {
                // We don't need to give an error here.
                // It doesn't matter which of many valid indexes the pubkey has, we just need an index where we can derive it and it's private key
                continue;
            }
            m_map_pubkeys[pubkey] = i;
        }
        // Merge and write the cache
        DescriptorCache new_items = m_wallet_descriptor.cache.MergeAndDiff(temp_cache);
        if (!batch.WriteDescriptorCacheItems(id, new_items)) {
            throw std::runtime_error(std::string(__func__) + ": writing cache items failed");
        }
        m_max_cached_index++;
    }
    m_wallet_descriptor.range_end = new_range_end;
    batch.WriteDescriptor(GetID(), m_wallet_descriptor);

    // By this point, the cache size should be the size of the entire range
    assert(m_wallet_descriptor.range_end - 1 == m_max_cached_index);

    m_storage.TopUpCallback(new_spks, this);
    NotifyCanGetAddressesChanged();
    return true;
}

std::vector<WalletDestination> DescriptorScriptPubKeyMan::MarkUnusedAddresses(const CScript& script)
{
    LOCK(cs_desc_man);
    std::vector<WalletDestination> result;
    if (IsMine(script)) {
        int32_t index = m_map_script_pub_keys[script];
        if (index >= m_wallet_descriptor.next_index) {
            WalletLogPrintf("%s: Detected a used keypool item at index %d, mark all keypool items up to this item as used\n", __func__, index);
            auto out_keys = std::make_unique<FlatSigningProvider>();
            std::vector<CScript> scripts_temp;
            while (index >= m_wallet_descriptor.next_index) {
                if (!m_wallet_descriptor.descriptor->ExpandFromCache(m_wallet_descriptor.next_index, m_wallet_descriptor.cache, scripts_temp, *out_keys)) {
                    throw std::runtime_error(std::string(__func__) + ": Unable to expand descriptor from cache");
                }
                CTxDestination dest;
                ExtractDestination(scripts_temp[0], dest);
                result.push_back({dest, std::nullopt});
                m_wallet_descriptor.next_index++;
            }
        }
        if (!TopUp()) {
            WalletLogPrintf("%s: Topping up keypool failed (locked wallet)\n", __func__);
        }
    }

    return result;
}

void DescriptorScriptPubKeyMan::AddDescriptorKey(const CKey& key, const CPubKey &pubkey)
{
    LOCK(cs_desc_man);
    WalletBatch batch(m_storage.GetDatabase());
    if (!AddDescriptorKeyWithDB(batch, key, pubkey)) {
        throw std::runtime_error(std::string(__func__) + ": writing descriptor private key failed");
    }
}

bool DescriptorScriptPubKeyMan::AddDescriptorKeyWithDB(WalletBatch& batch, const CKey& key, const CPubKey &pubkey)
{
    AssertLockHeld(cs_desc_man);
    assert(!m_storage.IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS));

    // Check if provided key already exists
    if (m_map_keys.find(pubkey.GetID()) != m_map_keys.end() ||
        m_map_crypted_keys.find(pubkey.GetID()) != m_map_crypted_keys.end()) {
        return true;
    }

    if (m_storage.HasEncryptionKeys()) {
        if (m_storage.IsLocked()) {
            return false;
        }

        std::vector<unsigned char> crypted_secret;
        CKeyingMaterial secret{UCharCast(key.begin()), UCharCast(key.end())};
        if (!m_storage.WithEncryptionKey([&](const CKeyingMaterial& encryption_key) {
                return EncryptSecret(encryption_key, secret, pubkey.GetHash(), crypted_secret);
            })) {
            return false;
        }

        m_map_crypted_keys[pubkey.GetID()] = make_pair(pubkey, crypted_secret);
        return batch.WriteCryptedDescriptorKey(GetID(), pubkey, crypted_secret);
    } else {
        m_map_keys[pubkey.GetID()] = key;
        return batch.WriteDescriptorKey(GetID(), pubkey, key.GetPrivKey());
    }
}

bool DescriptorScriptPubKeyMan::SetupDescriptorGeneration(WalletBatch& batch, const CExtKey& master_key, OutputType addr_type, bool internal)
{
    LOCK(cs_desc_man);
    assert(m_storage.IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS));

    // Ignore when there is already a descriptor
    if (m_wallet_descriptor.descriptor) {
        return false;
    }

    m_wallet_descriptor = GenerateWalletDescriptor(master_key.Neuter(), addr_type, internal);

    // Store the master private key, and descriptor
    if (!AddDescriptorKeyWithDB(batch, master_key.key, master_key.key.GetPubKey())) {
        throw std::runtime_error(std::string(__func__) + ": writing descriptor master private key failed");
    }
    if (!batch.WriteDescriptor(GetID(), m_wallet_descriptor)) {
        throw std::runtime_error(std::string(__func__) + ": writing descriptor failed");
    }

    // TopUp
    TopUpWithDB(batch);

    m_storage.UnsetBlankWalletFlag(batch);
    return true;
}

bool DescriptorScriptPubKeyMan::IsHDEnabled() const
{
    LOCK(cs_desc_man);
    return m_wallet_descriptor.descriptor->IsRange();
}

bool DescriptorScriptPubKeyMan::CanGetAddresses(bool internal) const
{
    // We can only give out addresses from descriptors that are single type (not combo), ranged,
    // and either have cached keys or can generate more keys (ignoring encryption)
    LOCK(cs_desc_man);
    return m_wallet_descriptor.descriptor->IsSingleType() &&
           m_wallet_descriptor.descriptor->IsRange() &&
           (HavePrivateKeys() || m_wallet_descriptor.next_index < m_wallet_descriptor.range_end);
}

bool DescriptorScriptPubKeyMan::HavePrivateKeys() const
{
    LOCK(cs_desc_man);
    return m_map_keys.size() > 0 || m_map_crypted_keys.size() > 0;
}

bool DescriptorScriptPubKeyMan::HaveCryptedKeys() const
{
    LOCK(cs_desc_man);
    return !m_map_crypted_keys.empty();
}

std::optional<int64_t> DescriptorScriptPubKeyMan::GetOldestKeyPoolTime() const
{
    // This is only used for getwalletinfo output and isn't relevant to descriptor wallets.
    return std::nullopt;
}


unsigned int DescriptorScriptPubKeyMan::GetKeyPoolSize() const
{
    LOCK(cs_desc_man);
    return m_wallet_descriptor.range_end - m_wallet_descriptor.next_index;
}

int64_t DescriptorScriptPubKeyMan::GetTimeFirstKey() const
{
    LOCK(cs_desc_man);
    return m_wallet_descriptor.creation_time;
}

std::unique_ptr<FlatSigningProvider> DescriptorScriptPubKeyMan::GetSigningProvider(const CScript& script,
                                                                                   bool include_private,
                                                                                   const std::set<std::pair<std::vector<unsigned char>, int>>* tap_scripts_filter) const
{
    LOCK(cs_desc_man);

    // Declare variables at function scope to avoid initialization-crossing issues
    std::unique_ptr<FlatSigningProvider> provider;
    std::optional<VaultMetadata> vault_opt;
    int32_t index = 0;
    bool found_in_index = false;

    // Find the index of the script
    auto it = m_map_script_pub_keys.find(script);
    if (it == m_map_script_pub_keys.end()) {
        // FALLBACK: Check vault registry even without index mapping
        // This prevents GetSigningProvider failures when vault scripts arrive before CacheNewScriptPubKeys runs
        vault_opt = m_vault_registry.GetVaultByScript(script);
        if (!vault_opt) {
            // Try lookup by x-only output key for taproot vaults
            if (script.size() == (1 + 1 + XOnlyPubKey::size()) && script[0] == OP_1 && script[1] == XOnlyPubKey::size()) {
                const unsigned char* key_bytes = script.data() + 2;
                XOnlyPubKey output_key(std::span<const unsigned char>(key_bytes, XOnlyPubKey::size()));
                vault_opt = m_vault_registry.GetVaultByOutputKey(output_key);
            }
        }
        if (vault_opt) {
            // Found in vault registry - create minimal provider for vault-only processing
            if (LogAcceptCategory(BCLog::WALLETDB, BCLog::Level::Debug)) {
                WalletLogPrintf("GetSigningProvider: Found script %s in vault registry (no m_map_script_pub_keys entry)\n",
                              HexStr(script));
            }
            provider = std::make_unique<FlatSigningProvider>();
            // Will process vault metadata below
        } else {
            // Not a vault — the common case for any non-vault script. Gated to debug:
            // this fires for nearly every output on every wallet rescan and otherwise
            // floods debug.log.
            if (LogAcceptCategory(BCLog::WALLETDB, BCLog::Level::Debug)) {
                WalletLogPrintf("GetSigningProvider: Script %s is NOT a vault (registry lookup failed)\n",
                              HexStr(script));
            }
            return nullptr;
        }
    } else {
        // Found in index - get normal signing provider
        index = it->second;
        found_in_index = true;

        // Get base provider with keys
        provider = GetSigningProvider(index, include_private);
        if (!provider) {
            return nullptr;
        }
    }

    // If we found the script in the index, check if it's also a vault
    if (found_in_index && !vault_opt) {
        // Check if this is a covenant vault
        vault_opt = m_vault_registry.GetVaultByScript(script);
        if (!vault_opt) {
            // Fallback: if this is a Taproot output, attempt lookup by x-only output key
            if (script.size() == (1 + 1 + XOnlyPubKey::size()) && script[0] == OP_1 && script[1] == XOnlyPubKey::size()) {
                const unsigned char* key_bytes = script.data() + 2;
                XOnlyPubKey output_key(std::span<const unsigned char>(key_bytes, XOnlyPubKey::size()));
                auto by_key = m_vault_registry.GetVaultByOutputKey(output_key);
                if (by_key) {
                    vault_opt = std::move(by_key);
                }
            }
        }

        if (!vault_opt) {
            // Not a vault - check if this is a witness v2 ML-DSA output
            if (script.size() == 34 && script[0] == OP_2 && script[1] == 0x20) {
                // This is witness v2: OP_2 <32 bytes>
                std::vector<unsigned char> output_key_bytes(script.begin() + 2, script.end());
                XOnlyPubKey output_key{output_key_bytes};

                WalletBatch batch(m_storage.GetDatabase());

                // Read the output index to get pk_hash
                uint256 pk_hash;
                if (batch.ReadMLDSAOutputIndex(output_key, pk_hash)) {
                    std::vector<uint8_t> pubkey;
                    std::vector<uint8_t> seckey;
                    uint8_t level = 0;
                    bool have_secret_key = false;

                    if (include_private) {
                        if (m_storage.HasEncryptionKeys()) {
                            std::pair<std::vector<unsigned char>, uint256> encrypted_data;
                            if (batch.ReadFromBatch(std::make_pair(DBKeys::CRYPTED_MLDSA_KEY, pk_hash), encrypted_data)) {
                                const std::vector<unsigned char>& vchData = encrypted_data.first;
                                if (vchData.size() >= 6) {
                                    level = vchData[0];
                                    size_t pos = 1;
                                    uint32_t pubkey_len = 0;
                                    std::memcpy(&pubkey_len, &vchData[pos], sizeof(uint32_t));
                                    pos += sizeof(uint32_t);
                                    if (pos + pubkey_len <= vchData.size()) {
                                        pubkey.assign(vchData.begin() + pos, vchData.begin() + pos + pubkey_len);
                                        pos += pubkey_len;
                                        std::vector<unsigned char> crypted_secret(vchData.begin() + pos, vchData.end());
                                        CKeyingMaterial decrypted;
                                        if (m_storage.WithEncryptionKey([&](const CKeyingMaterial& master_key) {
                                                return DecryptSecret(master_key, crypted_secret, pk_hash, decrypted);
                                            })) {
                                            seckey.assign(decrypted.begin(), decrypted.end());
                                            have_secret_key = true;
                                        }
                                    }
                                }
                            }
                        } else {
                            std::pair<std::vector<unsigned char>, uint256> key_data;
                            if (batch.ReadFromBatch(std::make_pair(DBKeys::MLDSA_KEY, pk_hash), key_data)) {
                                const std::vector<unsigned char>& vchData = key_data.first;
                                if (vchData.size() >= 10) {
                                    level = vchData[0];
                                    size_t pos = 1;
                                    uint32_t pubkey_len = 0;
                                    std::memcpy(&pubkey_len, &vchData[pos], sizeof(uint32_t));
                                    pos += sizeof(uint32_t);
                                    if (pos + pubkey_len + sizeof(uint32_t) <= vchData.size()) {
                                        pubkey.assign(vchData.begin() + pos, vchData.begin() + pos + pubkey_len);
                                        pos += pubkey_len;
                                        uint32_t seckey_len = 0;
                                        std::memcpy(&seckey_len, &vchData[pos], sizeof(uint32_t));
                                        pos += sizeof(uint32_t);
                                        if (pos + seckey_len == vchData.size()) {
                                            seckey.assign(vchData.begin() + pos, vchData.begin() + pos + seckey_len);
                                            have_secret_key = true;
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // Always populate spend data so that size estimation works even without private keys.
                    MLDSATaprootMetadata tap_metadata;
                    if (batch.ReadMLDSATaprootData(output_key, tap_metadata)) {
                        TaprootSpendData spenddata;
                        spenddata.internal_key = tap_metadata.internal_key;
                        spenddata.merkle_root = tap_metadata.merkle_root;

                        std::pair<std::vector<unsigned char>, int> leaf_script{
                            {tap_metadata.tapscript.begin(), tap_metadata.tapscript.end()},
                            0xc0
                        };

                        std::vector<unsigned char> control_block;
                        control_block.push_back(0xc0 | tap_metadata.parity);
                        control_block.insert(control_block.end(),
                                             tap_metadata.internal_key.begin(),
                                             tap_metadata.internal_key.end());

                        spenddata.scripts[leaf_script].insert(control_block);
                        provider->mldsa_taproot_data[output_key] = std::make_pair(spenddata, tap_metadata.parity);
                        WalletLogPrintf("GetSigningProvider: Loaded ML-DSA spend data for witness v2 output %s\n", HexStr(output_key));
                    }

                    if (include_private && have_secret_key && !pubkey.empty() && !seckey.empty()) {
                        CMLDSAKey mldsa_key;
                        mldsa::ParamSet param_set;
                        switch (level) {
                            case 44: param_set = mldsa::ParamSet::MLDSA_44; break;
                            case 65: param_set = mldsa::ParamSet::MLDSA_65; break;
                            case 87: param_set = mldsa::ParamSet::MLDSA_87; break;
                            default: param_set = mldsa::ParamSet::MLDSA_65; break;
                        }

                        if (mldsa_key.SetSecretKey(seckey, param_set) && mldsa_key.SetPublicKey(pubkey)) {
                            provider->mldsa_keys[output_key] = mldsa_key;
                        }
                    }
                }
            }

            if (LogAcceptCategory(BCLog::WALLETDB, BCLog::Level::Debug)) {
                WalletLogPrintf("GetSigningProvider: Script %s is NOT a vault (registry lookup failed)\n", HexStr(script));
            }
            return provider;
        }
    }

    // Process vault metadata if found
    if (!vault_opt) {
        // No vault metadata - return the provider as-is
        return provider;
    }

    const VaultMetadata& vault = *vault_opt;
    const XOnlyPubKey output_key = vault.GetOutputKey();
    const bool filter_active = tap_scripts_filter && !tap_scripts_filter->empty();

    // Apply taproot spend data, filtering if requested
    TaprootSpendData filtered_spenddata = vault.spenddata;
    if (filter_active) {
        // Filter the scripts to only include those in the filter
        for (auto it = filtered_spenddata.scripts.begin(); it != filtered_spenddata.scripts.end(); ) {
            if (tap_scripts_filter->count(it->first) == 0) {
                it = filtered_spenddata.scripts.erase(it);
            } else {
                ++it;
            }
        }
    }

    // Always inject spenddata (filtered or full)
    provider->tr_spenddata[output_key] = filtered_spenddata;

    // Only rebuild tree if no filter (filtered tree would be incomplete)
    if (!filter_active) {
        TaprootBuilder rebuilt_tree = vault.RebuildBuilder();
        if (rebuilt_tree.IsValid() && rebuilt_tree.IsComplete()) {
            provider->tr_trees[output_key] = rebuilt_tree;
        }
    } else {
        provider->tr_trees.erase(output_key);
    }

    // Populate x-only key mappings for signing (only if include_private)
    if (include_private) {
        std::set<std::pair<std::vector<unsigned char>, int>> leaves_with_keys;
        for (size_t i = 0; i < vault.leaves.size(); ++i) {
            const auto& leaf = vault.leaves[i];
            std::pair<std::vector<unsigned char>, int> leaf_key{leaf.script, static_cast<int>(leaf.leaf_version)};
            if (filter_active && tap_scripts_filter->count(leaf_key) == 0) {
                continue;
            }

            // Covenant-only leaves are signatureless (keeper-spendable); there is no key to map.
            if (leaf.IsCovenantOnly()) {
                continue;
            }

            // Try to get the private key for this x-only pubkey
            std::optional<CKey> key_opt = m_vault_registry.GetKeyByXOnly(leaf.signing_key);
            if (!key_opt) {
                CKey fallback_key;
                if (GetKeyByXOnlyLocked(leaf.signing_key, fallback_key)) {
                    key_opt = fallback_key;
                }
            }
            if (key_opt) {
                // X-only keys need to be mapped via their full pubkey keyid
                // Try both parity versions to find the correct one
                for (unsigned char prefix : {0x02, 0x03}) {
                    unsigned char buf[33] = {prefix};
                    std::copy(leaf.signing_key.begin(), leaf.signing_key.end(), buf + 1);
                    CPubKey full_pubkey;
                    full_pubkey.Set(buf, buf + 33);

                    // Verify this is the correct parity by checking if derived xonly matches
                    XOnlyPubKey derived_xonly(full_pubkey);
                    if (derived_xonly == leaf.signing_key) {
                        // Store the key under this keyid and cache direct x-only lookup
                        provider->keys[full_pubkey.GetID()] = *key_opt;
                        provider->tr_xonly_keys[leaf.signing_key] = *key_opt;
                        leaves_with_keys.insert(leaf_key);
                        continue;
                    }
                }
            }
        }

        // When signing, drop taproot leaves we cannot satisfy
        auto spenddata_it = provider->tr_spenddata.find(output_key);
        if (spenddata_it != provider->tr_spenddata.end()) {
            if (!spenddata_it->second.scripts.empty()) {
                for (auto it = spenddata_it->second.scripts.begin(); it != spenddata_it->second.scripts.end(); ) {
                    if (!leaves_with_keys.count(it->first)) {
                        it = spenddata_it->second.scripts.erase(it);
                    } else {
                        ++it;
                    }
                }
            }
            if (spenddata_it->second.scripts.empty()) {
                provider->tr_spenddata.erase(spenddata_it);
                provider->tr_signable_leaves.clear();
            } else {
                provider->tr_signable_leaves = leaves_with_keys;
            }
        } else {
            provider->tr_signable_leaves.clear();
        }
    } else {
        provider->keys.clear();
        provider->tr_xonly_keys.clear();
        provider->tr_signable_leaves.clear();
    }

    return provider;
}

std::unique_ptr<FlatSigningProvider> DescriptorScriptPubKeyMan::GetSigningProvider(const CPubKey& pubkey) const
{
    LOCK(cs_desc_man);

    // Find index of the pubkey
    auto it = m_map_pubkeys.find(pubkey);
    if (it == m_map_pubkeys.end()) {
        return nullptr;
    }
    int32_t index = it->second;

    // Always try to get the signing provider with private keys. This function should only be called during signing anyways
    std::unique_ptr<FlatSigningProvider> out = GetSigningProvider(index, true);
    if (!out->HaveKey(pubkey.GetID())) {
        return nullptr;
    }
    return out;
}

std::unique_ptr<FlatSigningProvider> DescriptorScriptPubKeyMan::GetSigningProvider(int32_t index, bool include_private) const
{
    AssertLockHeld(cs_desc_man);

    std::unique_ptr<FlatSigningProvider> out_keys = std::make_unique<FlatSigningProvider>();

    // Fetch SigningProvider from cache to avoid re-deriving
    auto it = m_map_signing_providers.find(index);
    if (it != m_map_signing_providers.end()) {
        out_keys->Merge(FlatSigningProvider{it->second});
    } else {
        // Get the scripts, keys, and key origins for this script
        std::vector<CScript> scripts_temp;
        if (!m_wallet_descriptor.descriptor->ExpandFromCache(index, m_wallet_descriptor.cache, scripts_temp, *out_keys)) return nullptr;

        // Cache SigningProvider so we don't need to re-derive if we need this SigningProvider again
        m_map_signing_providers[index] = *out_keys;
    }

    if (HavePrivateKeys() && include_private) {
        FlatSigningProvider master_provider;
        master_provider.keys = GetKeys();
        m_wallet_descriptor.descriptor->ExpandPrivate(index, master_provider, *out_keys);
    }

    return out_keys;
}

std::unique_ptr<FlatSigningProvider> DescriptorScriptPubKeyMan::GetSolvingProviderForScript(const CScript& script, bool include_private) const
{
    LOCK(cs_desc_man);
    auto it = m_map_script_pub_keys.find(script);
    if (it == m_map_script_pub_keys.end()) {
        return nullptr;
    }
    return GetSigningProvider(it->second, include_private);
}

std::unique_ptr<SigningProvider> DescriptorScriptPubKeyMan::GetSolvingProvider(const CScript& script) const
{
    return GetSigningProvider(script, false);
}

bool DescriptorScriptPubKeyMan::CanProvide(const CScript& script, SignatureData& sigdata)
{
    return IsMine(script);
}

bool DescriptorScriptPubKeyMan::SignTransaction(CMutableTransaction& tx, const std::map<COutPoint, Coin>& coins, int sighash, std::map<int, bilingual_str>& input_errors) const
{
    struct TaprootLeafRestriction {
        std::set<std::pair<std::vector<unsigned char>, int>> leaves;
        std::map<std::pair<std::vector<unsigned char>, int>,
                 std::set<std::vector<unsigned char>, ShortestVectorFirstComparator>> control_blocks;
    };

    struct CounterpartySigs {
        TaprootLeafRestriction restriction;
        uint256 leaf_hash;
        bool has_leaf_hash{false};
        std::vector<std::pair<XOnlyPubKey, std::vector<unsigned char>>> signatures;
        std::optional<FairSignInputState> state;
        bool keep_existing_witness{false};
    };

    std::map<COutPoint, CounterpartySigs> signing_hints;

    const CWallet* wallet = dynamic_cast<const CWallet*>(&m_storage);
    if (wallet && !tx.vin.empty()) {
        const uint256 txid = tx.GetHash();
        for (size_t idx = 0; idx < tx.vin.size(); ++idx) {
            const CTxIn& txin = tx.vin[idx];
            const auto coin_it = coins.find(txin.prevout);
            if (coin_it == coins.end()) {
                continue;
            }

            FairSignInputState state;
            if (!wallet->GetFairSignInputState(txid, idx, state)) {
                continue;
            }

            if (!state.vault_intent_purpose.has_value()) {
                continue;
            }
            if (state.tapleaf_script.empty() || state.tapleaf_control_block.empty()) {
                continue;
            }

            CounterpartySigs& hints = signing_hints[txin.prevout];

            const bool has_adaptor_secret = state.adaptor_secret.has_value();
            const int leaf_version = static_cast<int>(state.tapleaf_control_block.front() & TAPROOT_LEAF_MASK);
            std::pair<std::vector<unsigned char>, int> leaf_key{state.tapleaf_script, leaf_version};
            hints.restriction.leaves.insert(leaf_key);
            hints.restriction.control_blocks[leaf_key].insert(state.tapleaf_control_block);

            if (state.tapleaf_hash.has_value()) {
                hints.leaf_hash = *state.tapleaf_hash;
                hints.has_leaf_hash = true;
            } else {
                HashWriter hasher{HASHER_TAPLEAF};
                hasher << static_cast<uint8_t>(leaf_version);
                hasher << state.tapleaf_script;
                hints.leaf_hash = hasher.GetSHA256();
                hints.has_leaf_hash = true;
            }

            if (!state.tapleaf_signers.empty() && txin.scriptWitness.stack.size() >= state.tapleaf_signers.size()) {
                const size_t signer_count = state.tapleaf_signers.size();
                const auto& witness_stack = txin.scriptWitness.stack;
                if (witness_stack.size() >= signer_count + 2) {
                    for (size_t signer_idx = 0; signer_idx < signer_count; ++signer_idx) {
                        const auto& sig_bytes = witness_stack[signer_idx];
                        if (sig_bytes.empty()) continue;
                        hints.signatures.emplace_back(state.tapleaf_signers[signer_idx], sig_bytes);
                    }
                }
            }

            // Move state last, after all uses
            hints.state = std::move(state);
            if (has_adaptor_secret) {
                hints.keep_existing_witness = true;
            }
        }
    }

    std::unique_ptr<FlatSigningProvider> keys = std::make_unique<FlatSigningProvider>();
    for (const auto& coin_pair : coins) {
        const COutPoint& prevout = coin_pair.first;
        const CScript& script = coin_pair.second.out.scriptPubKey;

        const CounterpartySigs* hint = nullptr;
        const auto hint_it = signing_hints.find(prevout);
        if (hint_it != signing_hints.end() && !hint_it->second.restriction.leaves.empty()) {
            hint = &hint_it->second;
        }

        std::unique_ptr<FlatSigningProvider> coin_keys = hint ?
            GetSigningProvider(script, /*include_private=*/true, &hint->restriction.leaves) :
            GetSigningProvider(script, /*include_private=*/true);
        if (!coin_keys) {
            continue;
        }

        if (hint) {
            for (auto spend_it = coin_keys->tr_spenddata.begin(); spend_it != coin_keys->tr_spenddata.end(); ) {
                TaprootSpendData& spenddata = spend_it->second;
                for (auto script_it = spenddata.scripts.begin(); script_it != spenddata.scripts.end(); ) {
                    const auto& leaf_key = script_it->first;
                    if (hint->restriction.leaves.count(leaf_key) == 0) {
                        script_it = spenddata.scripts.erase(script_it);
                        continue;
                    }

                    const auto control_filter_it = hint->restriction.control_blocks.find(leaf_key);
                    if (control_filter_it != hint->restriction.control_blocks.end() && !control_filter_it->second.empty()) {
                        auto& control_blocks = script_it->second;
                        for (auto cb_it = control_blocks.begin(); cb_it != control_blocks.end(); ) {
                            if (control_filter_it->second.count(*cb_it) == 0) {
                                cb_it = control_blocks.erase(cb_it);
                            } else {
                                ++cb_it;
                            }
                        }
                        if (control_blocks.empty()) {
                            script_it = spenddata.scripts.erase(script_it);
                            continue;
                        }
                    }

                    ++script_it;
                }

                if (spenddata.scripts.empty()) {
                    spend_it = coin_keys->tr_spenddata.erase(spend_it);
                } else {
                    ++spend_it;
                }
            }

            for (auto it = coin_keys->tr_signable_leaves.begin(); it != coin_keys->tr_signable_leaves.end(); ) {
                if (hint->restriction.leaves.count(*it) == 0) {
                    it = coin_keys->tr_signable_leaves.erase(it);
                } else {
                    ++it;
                }
            }
        }

        keys->Merge(std::move(*coin_keys));
    }

    bool fHashSingle = ((sighash & ~SIGHASH_ANYONECANPAY) == SIGHASH_SINGLE);

    const CTransaction tx_const(tx);
    PrecomputedTransactionData txdata;
    std::vector<CTxOut> spent_outputs;
    for (unsigned int i = 0; i < tx.vin.size(); ++i) {
        const CTxIn& txin = tx.vin[i];
        auto coin = coins.find(txin.prevout);
        if (coin == coins.end() || coin->second.IsSpent()) {
            txdata.Init(tx_const, /*spent_outputs=*/{}, /*force=*/true);
            spent_outputs.clear();
            break;
        }
        spent_outputs.emplace_back(coin->second.out.nValue, coin->second.out.scriptPubKey);
    }
    if (spent_outputs.size() == tx.vin.size()) {
        txdata.Init(tx_const, std::move(spent_outputs), true);
    }

    for (unsigned int i = 0; i < tx.vin.size(); ++i) {
        CTxIn& txin = tx.vin[i];
        auto coin = coins.find(txin.prevout);
        if (coin == coins.end() || coin->second.IsSpent()) {
            input_errors[i] = _("Input not found or already spent");
            continue;
        }
        const CScript& prev_pubkey = coin->second.out.scriptPubKey;
        const CAmount& amount = coin->second.out.nValue;

        SignatureData sigdata = DataFromTransaction(tx, i, coin->second.out);

        const auto hint_it = signing_hints.find(txin.prevout);
        const CounterpartySigs* hint = hint_it != signing_hints.end() ? &hint_it->second : nullptr;
        const bool skip_vault_signing = hint && hint->keep_existing_witness;

        if (skip_vault_signing) {
            // Preserve the cooperative witness produced during adaptor.complete;
            // re-signing would replace the adaptor-derived signature with a fresh one.
            if (hint && hint->state.has_value() && hint->state->tapleaf_hash.has_value()) {
                const FairSignInputState& st = *hint->state;
                ScriptExecutionData execdata;
                execdata.m_annex_init = true;
                execdata.m_annex_present = false;
                execdata.m_codeseparator_pos_init = true;
                execdata.m_codeseparator_pos = 0xFFFFFFFF;
                execdata.m_tapleaf_hash_init = true;
                execdata.m_tapleaf_hash = *st.tapleaf_hash;
                uint256 digest_now;
                if (SignatureHashSchnorr(digest_now,
                                         execdata,
                                         tx_const,
                                         i,
                                         sighash,
                                         SigVersion::TAPSCRIPT,
                                         txdata,
                                         MissingDataBehavior::FAIL)) {
                }
            }
            input_errors.erase(i);
            continue;
        }

        if (!skip_vault_signing && hint && hint->has_leaf_hash) {
            for (const auto& [pubkey, sig] : hint->signatures) {
                sigdata.taproot_script_sigs[{pubkey, hint->leaf_hash}] = sig;
            }
        }

        if (!skip_vault_signing && (!fHashSingle || (i < tx.vout.size()))) {
            ProduceSignature(*keys, MutableTransactionSignatureCreator(tx, i, amount, &txdata, sighash), prev_pubkey, sigdata);
        }

        UpdateInput(txin, sigdata);

        if (amount == MAX_MONEY && !txin.scriptWitness.IsNull()) {
            input_errors[i] = _("Missing amount");
            continue;
        }

        ScriptError serror = SCRIPT_ERR_OK;
        if (!sigdata.complete && !VerifyScript(txin.scriptSig, prev_pubkey, &txin.scriptWitness, STANDARD_SCRIPT_VERIFY_FLAGS, TransactionSignatureChecker(&tx_const, i, amount, txdata, MissingDataBehavior::FAIL), &serror)) {
            if (serror == SCRIPT_ERR_INVALID_STACK_OPERATION) {
                input_errors[i] = Untranslated("Unable to sign input, invalid stack size (possibly missing key)");
            } else if (serror == SCRIPT_ERR_SIG_NULLFAIL) {
                input_errors[i] = Untranslated("CHECK(MULTI)SIG failing with non-zero signature (possibly need more signatures)");
            } else {
                input_errors[i] = Untranslated(ScriptErrorString(serror));
            }
        } else {
            input_errors.erase(i);
        }
    }

    return input_errors.empty();
}

SigningResult DescriptorScriptPubKeyMan::SignMessage(const std::string& message, const PKHash& pkhash, std::string& str_sig) const
{
    std::unique_ptr<FlatSigningProvider> keys = GetSigningProvider(GetScriptForDestination(pkhash), true);
    if (!keys) {
        return SigningResult::PRIVATE_KEY_NOT_AVAILABLE;
    }

    CKey key;
    if (!keys->GetKey(ToKeyID(pkhash), key)) {
        return SigningResult::PRIVATE_KEY_NOT_AVAILABLE;
    }

    if (!MessageSign(key, message, str_sig)) {
        return SigningResult::SIGNING_FAILED;
    }
    return SigningResult::OK;
}

std::optional<PSBTError> DescriptorScriptPubKeyMan::FillPSBT(PartiallySignedTransaction& psbtx, const PrecomputedTransactionData& txdata, int sighash_type, bool sign, bool bip32derivs, int* n_signed, bool finalize) const
{
    if (n_signed) {
        *n_signed = 0;
    }
    for (unsigned int i = 0; i < psbtx.tx->vin.size(); ++i) {
        const CTxIn& txin = psbtx.tx->vin[i];
        PSBTInput& input = psbtx.inputs.at(i);

        if (PSBTInputSigned(input)) {
            continue;
        }

        // Get the Sighash type
        if (sign && input.sighash_type != std::nullopt && *input.sighash_type != sighash_type) {
            return PSBTError::SIGHASH_MISMATCH;
        }

        // Get the scriptPubKey to know which SigningProvider to use
        CScript script;
        if (!input.witness_utxo.IsNull()) {
            script = input.witness_utxo.scriptPubKey;
        } else if (input.non_witness_utxo) {
            if (txin.prevout.n >= input.non_witness_utxo->vout.size()) {
                return PSBTError::MISSING_INPUTS;
            }
            script = input.non_witness_utxo->vout[txin.prevout.n].scriptPubKey;
        } else {
            // There's no UTXO so we can just skip this now
            continue;
        }

        std::unique_ptr<FlatSigningProvider> keys = std::make_unique<FlatSigningProvider>();

        // If the PSBT specifies Taproot BIP32 derivations with explicit leaf hashes,
        // pre-filter any provided tap scripts to only those leaves. This prevents
        // downstream helpers from considering unrelated leaves (e.g. refund paths)
        // when the caller explicitly targeted a single claim/refund leaf.
        if (!input.m_tap_bip32_paths.empty() && !input.m_tap_scripts.empty()) {
            std::set<uint256> allowed_leaf_hashes;
            for (const auto& [xonly, leaf_origin] : input.m_tap_bip32_paths) {
                const auto& leaf_hashes = leaf_origin.first;
                allowed_leaf_hashes.insert(leaf_hashes.begin(), leaf_hashes.end());
            }
            if (!allowed_leaf_hashes.empty()) {
                [[maybe_unused]] size_t before = input.m_tap_scripts.size();
                for (auto it = input.m_tap_scripts.begin(); it != input.m_tap_scripts.end(); ) {
                    const auto& leaf_key = it->first; // (script_bytes, leaf_ver)
                    const auto& script_bytes = leaf_key.first;
                    const int leaf_ver = leaf_key.second;
                    const uint256 leaf_hash = ComputeTapleafHash(leaf_ver,
                        std::span<const unsigned char>(script_bytes.data(), script_bytes.size()));
                    if (allowed_leaf_hashes.count(leaf_hash) == 0) {
                        it = input.m_tap_scripts.erase(it);
                    } else {
                        ++it;
                    }
                }
            }
        }
        std::set<std::pair<std::vector<unsigned char>, int>> tap_scripts_filter;
        const std::set<std::pair<std::vector<unsigned char>, int>>* filter_ptr = nullptr;
        if (!input.m_tap_scripts.empty()) {
            for (const auto& [leaf_key, _] : input.m_tap_scripts) {
                tap_scripts_filter.insert(leaf_key);
            }
            filter_ptr = &tap_scripts_filter;
        }
        std::unique_ptr<FlatSigningProvider> script_keys = GetSigningProvider(script, /*include_private=*/sign, filter_ptr);
        if (script_keys) {
            // Prune PSBT tap scripts to only include leaves we can actually sign
        std::set<std::pair<std::vector<unsigned char>, int>> signable_leaves = script_keys->tr_signable_leaves;
        if (signable_leaves.empty()) {
            for (const auto& [out_key, spenddata] : script_keys->tr_spenddata) {
                for (const auto& [leaf_key, _] : spenddata.scripts) {
                    signable_leaves.insert(leaf_key);
                }
            }
        }
            [[maybe_unused]] bool psbt_pruned = false;
            if (!signable_leaves.empty()) {
                std::map<std::pair<std::vector<unsigned char>, int>, std::set<std::vector<unsigned char>, ShortestVectorFirstComparator>> filtered_map;
                for (auto& [key, control_blocks] : input.m_tap_scripts) {
                    if (signable_leaves.count(key) != 0) {
                        filtered_map.emplace(key, control_blocks);
                    } else {
                        psbt_pruned = true;
                    }
                }
                if (filtered_map.size() != input.m_tap_scripts.size()) {
                    input.m_tap_scripts.swap(filtered_map);
                }
            } else if (!input.m_tap_scripts.empty()) {
                input.m_tap_scripts.clear();
                psbt_pruned = true;
            }
            keys->Merge(std::move(*script_keys));

            // Additional hardening: If PSBT provides Taproot BIP32 derivations with explicit leaf hashes,
            // restrict the assembled spenddata to those leaves even when no m_tap_scripts filter was present.
            if (!input.m_tap_bip32_paths.empty()) {
                std::set<uint256> allowed_leaf_hashes;
                for (const auto& [xonly, leaf_origin] : input.m_tap_bip32_paths) {
                    const auto& leaf_hashes = leaf_origin.first;
                    allowed_leaf_hashes.insert(leaf_hashes.begin(), leaf_hashes.end());
                }
                if (!allowed_leaf_hashes.empty() && !keys->tr_spenddata.empty()) {
                    for (auto spenddata_it = keys->tr_spenddata.begin(); spenddata_it != keys->tr_spenddata.end(); ) {
                        TaprootSpendData& spend = spenddata_it->second;
                        bool pruned = false;
                        for (auto leaf_it = spend.scripts.begin(); leaf_it != spend.scripts.end(); ) {
                            const auto& leaf_key = leaf_it->first; // (script_bytes, leaf_ver)
                            const auto& script_bytes = leaf_key.first;
                            const int leaf_ver = leaf_key.second;
                            const uint256 leaf_hash = ComputeTapleafHash(leaf_ver,
                                std::span<const unsigned char>(script_bytes.data(), script_bytes.size()));
                            if (allowed_leaf_hashes.count(leaf_hash) == 0) {
                                leaf_it = spend.scripts.erase(leaf_it);
                                pruned = true;
                            } else {
                                ++leaf_it;
                            }
                        }
                        if (pruned) {
                            keys->tr_trees.erase(spenddata_it->first);
                        }
                        if (spend.scripts.empty()) {
                            spenddata_it = keys->tr_spenddata.erase(spenddata_it);
                            continue;
                        }
                        ++spenddata_it;
                    }
                    // Also synthesize a minimal PSBT tap_scripts map if it is currently empty to
                    // carry the filter forward to future passes.
                    if (input.m_tap_scripts.empty()) {
                        for (const auto& [out_key, spend] : keys->tr_spenddata) {
                            for (const auto& [leaf_key, blocks] : spend.scripts) {
                                // Add each allowed leaf with its control blocks
                                input.m_tap_scripts[leaf_key].insert(blocks.begin(), blocks.end());
                            }
                        }
                    }
                }
            }

            if (!input.m_tap_scripts.empty() && !keys->tr_spenddata.empty()) {
                for (auto spenddata_it = keys->tr_spenddata.begin(); spenddata_it != keys->tr_spenddata.end(); ) {
                    TaprootSpendData& spenddata = spenddata_it->second;
                    bool pruned = false;
                    for (auto leaf_it = spenddata.scripts.begin(); leaf_it != spenddata.scripts.end(); ) {
                        if (input.m_tap_scripts.count(leaf_it->first) == 0) {
                            leaf_it = spenddata.scripts.erase(leaf_it);
                            pruned = true;
                        } else {
                            ++leaf_it;
                        }
                    }
                    if (pruned) {
                        keys->tr_trees.erase(spenddata_it->first);
                    }
                    if (spenddata.scripts.empty()) {
                        spenddata_it = keys->tr_spenddata.erase(spenddata_it);
                        continue;
                    }
                    ++spenddata_it;
                }
            }
        } else {
            // Maybe there are pubkeys listed that we can sign for
            std::vector<CPubKey> pubkeys;
            pubkeys.reserve(input.hd_keypaths.size() + 2);

            // ECDSA Pubkeys
            for (const auto& [pk, _] : input.hd_keypaths) {
                pubkeys.push_back(pk);
            }

            // Taproot output pubkey
            std::vector<std::vector<unsigned char>> sols;
            if (Solver(script, sols) == TxoutType::WITNESS_V1_TAPROOT) {
                sols[0].insert(sols[0].begin(), 0x02);
                pubkeys.emplace_back(sols[0]);
                sols[0][0] = 0x03;
                pubkeys.emplace_back(sols[0]);
            }

            // Taproot pubkeys
            for (const auto& pk_pair : input.m_tap_bip32_paths) {
                const XOnlyPubKey& pubkey = pk_pair.first;
                for (unsigned char prefix : {0x02, 0x03}) {
                    unsigned char b[33] = {prefix};
                    std::copy(pubkey.begin(), pubkey.end(), b + 1);
                    CPubKey fullpubkey;
                    fullpubkey.Set(b, b + 33);
                    pubkeys.push_back(fullpubkey);
                }
            }

            for (const auto& pubkey : pubkeys) {
                std::unique_ptr<FlatSigningProvider> pk_keys = GetSigningProvider(pubkey);
                if (pk_keys) {
                    keys->Merge(std::move(*pk_keys));
                }
            }
        }

        // CRITICAL: Respect vault signing intent from PSBT proprietary fields
        // If a vault intent is present, filter tr_spenddata AND m_tap_scripts to ONLY the intended leaf
        // This prevents walletprocesspsbt/finalizepsbt from selecting the wrong leaf (e.g. timeout instead of cooperative)
        auto vault_intent = wallet::ExtractVaultIntent(input);
        if (vault_intent) {
            // Filter tr_spenddata to ONLY include scripts matching the vault intent's tapleaf hash
            for (auto spenddata_it = keys->tr_spenddata.begin(); spenddata_it != keys->tr_spenddata.end(); ) {
                TaprootSpendData& spenddata = spenddata_it->second;
                bool pruned = false;

                for (auto leaf_it = spenddata.scripts.begin(); leaf_it != spenddata.scripts.end(); ) {
                    const auto& [script_bytes, leaf_ver] = leaf_it->first;

                    // Compute leaf hash for this script
                    const uint256 leaf_hash = ComputeTapleafHash(leaf_ver,
                        std::span<const unsigned char>(script_bytes.data(), script_bytes.size()));

                    // Keep only if it matches the vault intent's tapleaf hash
                    if (leaf_hash != vault_intent->tapleaf_hash) {
                        leaf_it = spenddata.scripts.erase(leaf_it);
                        pruned = true;
                    } else {
                        ++leaf_it;
                    }
                }

                if (pruned) {
                    keys->tr_trees.erase(spenddata_it->first);
                }

                if (spenddata.scripts.empty()) {
                    spenddata_it = keys->tr_spenddata.erase(spenddata_it);
                } else {
                    ++spenddata_it;
                }
            }

            // ALSO filter the PSBT's m_tap_scripts to prevent finalizepsbt from selecting wrong leaf
            for (auto tap_it = input.m_tap_scripts.begin(); tap_it != input.m_tap_scripts.end(); ) {
                const auto& [script_bytes, leaf_ver] = tap_it->first;

                // Compute leaf hash
                const uint256 leaf_hash = ComputeTapleafHash(leaf_ver,
                    std::span<const unsigned char>(script_bytes.data(), script_bytes.size()));

                if (leaf_hash != vault_intent->tapleaf_hash) {
                    tap_it = input.m_tap_scripts.erase(tap_it);
                } else {
                    ++tap_it;
                }
            }
        }

        // Check if this is an ML-DSA witness v2 input and populate ML-DSA data
        if (script.size() == 34 && script[0] == OP_2 && script[1] == 0x20) {
            // This is a witness v2 output (OP_2 <32 bytes>)
            std::vector<unsigned char> output_key_bytes(script.begin() + 2, script.end());
            XOnlyPubKey output_key{output_key_bytes};

            WalletBatch batch(m_storage.GetDatabase());

            // Read the output index to get pk_hash
            uint256 pk_hash;
            if (batch.ReadMLDSAOutputIndex(output_key, pk_hash)) {
                // Read the ML-DSA key data
                std::vector<uint8_t> pubkey, seckey;
                uint8_t level = 0;

                bool have_key = false;
                if (m_storage.HasEncryptionKeys() && sign) {
                    // Read encrypted key: (vchData, checksum) where vchData = level || pubkey_len || pubkey || encrypted_seckey
                    std::pair<std::vector<unsigned char>, uint256> encrypted_data;
                    if (batch.ReadFromBatch(std::make_pair(DBKeys::CRYPTED_MLDSA_KEY, pk_hash), encrypted_data)) {
                        const std::vector<unsigned char>& vchData = encrypted_data.first;

                        // Deserialize: level || pubkey_len || pubkey || encrypted_seckey
                        if (vchData.size() >= 6) {  // min: 1 byte level + 4 bytes len + 1+ bytes pubkey
                            level = vchData[0];
                            size_t pos = 1;

                            // Read pubkey length (4 bytes little-endian)
                            uint32_t pubkey_len = 0;
                            std::memcpy(&pubkey_len, &vchData[pos], sizeof(uint32_t));
                            pos += sizeof(uint32_t);

                            if (pos + pubkey_len <= vchData.size()) {
                                pubkey.assign(vchData.begin() + pos, vchData.begin() + pos + pubkey_len);
                                pos += pubkey_len;

                                // Rest is encrypted secret key
                                std::vector<unsigned char> crypted_secret(vchData.begin() + pos, vchData.end());

                                // Decrypt secret key
                                CKeyingMaterial decrypted;
                                if (m_storage.WithEncryptionKey([&](const CKeyingMaterial& master_key) {
                                    return DecryptSecret(master_key, crypted_secret, pk_hash, decrypted);
                                })) {
                                    seckey.assign(decrypted.begin(), decrypted.end());
                                    have_key = true;
                                }
                            }
                        }
                    }
                } else if (!m_storage.HasEncryptionKeys()) {
                    // Read unencrypted key: (vchData, checksum) where vchData = level || pubkey_len || pubkey || seckey_len || seckey
                    std::pair<std::vector<unsigned char>, uint256> key_data;
                    if (batch.ReadFromBatch(std::make_pair(DBKeys::MLDSA_KEY, pk_hash), key_data)) {
                        const std::vector<unsigned char>& vchData = key_data.first;

                        // Deserialize: level || pubkey_len || pubkey || seckey_len || seckey
                        if (vchData.size() >= 10) {  // min: 1 + 4 + 1 + 4 + 1
                            level = vchData[0];
                            size_t pos = 1;

                            // Read pubkey length (4 bytes little-endian)
                            uint32_t pubkey_len = 0;
                            std::memcpy(&pubkey_len, &vchData[pos], sizeof(uint32_t));
                            pos += sizeof(uint32_t);

                            if (pos + pubkey_len + sizeof(uint32_t) <= vchData.size()) {
                                pubkey.assign(vchData.begin() + pos, vchData.begin() + pos + pubkey_len);
                                pos += pubkey_len;

                                // Read seckey length (4 bytes little-endian)
                                uint32_t seckey_len = 0;
                                std::memcpy(&seckey_len, &vchData[pos], sizeof(uint32_t));
                                pos += sizeof(uint32_t);

                                if (pos + seckey_len == vchData.size()) {
                                    seckey.assign(vchData.begin() + pos, vchData.begin() + pos + seckey_len);
                                    have_key = true;
                                }
                            }
                        }
                    }
                }

                if (have_key && !pubkey.empty() && !seckey.empty()) {
                    // Reconstruct CMLDSAKey with both public and secret keys
                    CMLDSAKey mldsa_key;
                    mldsa::ParamSet param_set;
                    switch (level) {
                        case 44: param_set = mldsa::ParamSet::MLDSA_44; break;
                        case 65: param_set = mldsa::ParamSet::MLDSA_65; break;
                        case 87: param_set = mldsa::ParamSet::MLDSA_87; break;
                        default: param_set = mldsa::ParamSet::MLDSA_65; break;
                    }

                    if (sign && mldsa_key.SetSecretKey(seckey, param_set) && mldsa_key.SetPublicKey(pubkey)) {
                        keys->mldsa_keys[output_key] = mldsa_key;
                    }
                }

                // Read Taproot metadata
                MLDSATaprootMetadata tap_metadata;
                if (batch.ReadMLDSATaprootData(output_key, tap_metadata)) {
                    TaprootSpendData spenddata;
                    spenddata.internal_key = tap_metadata.internal_key;
                    spenddata.merkle_root = tap_metadata.merkle_root;

                    // Construct control block and add script
                    std::pair<std::vector<unsigned char>, int> leaf_script{
                        {tap_metadata.tapscript.begin(), tap_metadata.tapscript.end()},
                        0xc0  // leaf_version
                    };

                    std::vector<unsigned char> control_block;
                    control_block.push_back(0xc0 | tap_metadata.parity);
                    control_block.insert(control_block.end(),
                                        tap_metadata.internal_key.begin(),
                                        tap_metadata.internal_key.end());

                    spenddata.scripts[leaf_script].insert(control_block);
                    keys->mldsa_taproot_data[output_key] = std::make_pair(spenddata, tap_metadata.parity);
                }
            }
        }

        SignPSBTInput(HidingSigningProvider(keys.get(), /*hide_secret=*/!sign, /*hide_origin=*/!bip32derivs), psbtx, i, &txdata, sighash_type, nullptr, finalize);

        bool signed_one = PSBTInputSigned(input);
        if (n_signed && (signed_one || !sign)) {
            // If sign is false, we assume that we _could_ sign if we get here. This
            // will never have false negatives; it is hard to tell under what i
            // circumstances it could have false positives.
            (*n_signed)++;
        }
    }

    // Fill in the bip32 keypaths and redeemscripts for the outputs so that hardware wallets can identify change
    for (unsigned int i = 0; i < psbtx.tx->vout.size(); ++i) {
        std::unique_ptr<SigningProvider> keys = GetSolvingProvider(psbtx.tx->vout.at(i).scriptPubKey);
        if (!keys) {
            continue;
        }
        UpdatePSBTOutput(HidingSigningProvider(keys.get(), /*hide_secret=*/true, /*hide_origin=*/!bip32derivs), psbtx, i);
    }

    return {};
}

std::unique_ptr<CKeyMetadata> DescriptorScriptPubKeyMan::GetMetadata(const CTxDestination& dest) const
{
    std::unique_ptr<SigningProvider> provider = GetSigningProvider(GetScriptForDestination(dest));
    if (provider) {
        KeyOriginInfo orig;
        CKeyID key_id = GetKeyForDestination(*provider, dest);
        if (provider->GetKeyOrigin(key_id, orig)) {
            LOCK(cs_desc_man);
            std::unique_ptr<CKeyMetadata> meta = std::make_unique<CKeyMetadata>();
            meta->key_origin = orig;
            meta->has_key_origin = true;
            meta->nCreateTime = m_wallet_descriptor.creation_time;
            return meta;
        }
    }
    return nullptr;
}

uint256 DescriptorScriptPubKeyMan::GetID() const
{
    LOCK(cs_desc_man);
    return m_wallet_descriptor.id;
}

void DescriptorScriptPubKeyMan::SetCache(const DescriptorCache& cache)
{
    LOCK(cs_desc_man);
    std::set<CScript> new_spks;
    m_wallet_descriptor.cache = cache;
    for (int32_t i = m_wallet_descriptor.range_start; i < m_wallet_descriptor.range_end; ++i) {
        FlatSigningProvider out_keys;
        std::vector<CScript> scripts_temp;
        if (!m_wallet_descriptor.descriptor->ExpandFromCache(i, m_wallet_descriptor.cache, scripts_temp, out_keys)) {
            throw std::runtime_error("Error: Unable to expand wallet descriptor from cache");
        }
        // Add all of the scriptPubKeys to the scriptPubKey set
        new_spks.insert(scripts_temp.begin(), scripts_temp.end());
        for (const CScript& script : scripts_temp) {
            if (m_map_script_pub_keys.count(script) != 0) {
                throw std::runtime_error(strprintf("Error: Already loaded script at index %d as being at index %d", i, m_map_script_pub_keys[script]));
            }
            m_map_script_pub_keys[script] = i;
        }
        for (const auto& pk_pair : out_keys.pubkeys) {
            const CPubKey& pubkey = pk_pair.second;
            if (m_map_pubkeys.count(pubkey) != 0) {
                // We don't need to give an error here.
                // It doesn't matter which of many valid indexes the pubkey has, we just need an index where we can derive it and it's private key
                continue;
            }
            m_map_pubkeys[pubkey] = i;
        }
        m_max_cached_index++;
    }
    // Make sure the wallet knows about our new spks
    m_storage.TopUpCallback(new_spks, this);
}

bool DescriptorScriptPubKeyMan::RegisterCovenantScript(const CScript& base_script, const CScript& derived_script)
{
    LOCK(cs_desc_man);
    auto it = m_map_script_pub_keys.find(base_script);
    if (it == m_map_script_pub_keys.end()) {
        return false;
    }
    if (m_map_script_pub_keys.count(derived_script) != 0) {
        return true;
    }

    const int32_t index = it->second;
    m_map_script_pub_keys[derived_script] = index;

    std::set<CScript> new_spks{derived_script};
    m_storage.TopUpCallback(new_spks, this);
    return true;
}

bool DescriptorScriptPubKeyMan::RegisterCovenantVault(const CScript& base_script, const VaultMetadata& metadata)
{
    LOCK(cs_desc_man);

    WalletLogPrintf("  Base script: %s\n", HexStr(base_script));
    WalletLogPrintf("  Contract ID: %s\n", metadata.contract_id.ToString());
    WalletLogPrintf("  Role: %d\n", static_cast<int>(metadata.role));

    // 1. Validate metadata
    if (!metadata.Validate()) {
        return false;
    }

    // 2. Get base address index (for solvability, NOT spendability)
    auto it = m_map_script_pub_keys.find(base_script);
    int32_t base_index = 0;
    if (it == m_map_script_pub_keys.end()) {
        WalletLogPrintf("  -> Using placeholder descriptor index 0 for covenant tracking\n");
    } else {
        base_index = it->second;
    }
    WalletLogPrintf("  Base script index: %d\n", base_index);

    // DEBUG: Show ALL addresses in m_map_script_pub_keys
    WalletLogPrintf("  [DEBUG] All addresses in m_map_script_pub_keys (%zu total):\n", m_map_script_pub_keys.size());
    for (const auto& [spk, idx] : m_map_script_pub_keys) {
        WalletLogPrintf("    - Index %d: script=%s\n", idx, HexStr(spk));
    }

    // DEBUG: Verify what key the descriptor actually derives at base_index
    {
        std::vector<CScript> test_scripts;
        FlatSigningProvider test_provider;
        if (m_wallet_descriptor.descriptor->ExpandFromCache(base_index, m_wallet_descriptor.cache, test_scripts, test_provider)) {
            WalletLogPrintf("  [DEBUG] Descriptor at index %d derives:\n", base_index);
            if (!test_scripts.empty()) {
                WalletLogPrintf("    - Script: %s\n", HexStr(test_scripts[0]));
            }
            for (const auto& [keyid, pubkey] : test_provider.pubkeys) {
                XOnlyPubKey xonly(pubkey);
                WalletLogPrintf("    - Pubkey: keyid=%s, xonly=%s\n", HexStr(keyid), HexStr(xonly));
            }
        } else {
            WalletLogPrintf("  [DEBUG] Failed to expand descriptor at index %d\n", base_index);
        }
    }

    // 3. Map covenant script to same index (enables ISMINE_SOLVABLE)
    const CScript& covenant_spk = metadata.GetScriptPubKey();
    m_map_script_pub_keys[covenant_spk] = base_index;
    WalletLogPrintf("  Covenant script: %s (mapped to index %d)\n", HexStr(covenant_spk), base_index);

    // CRITICAL: Mark as solvable but NOT spendable (don't count in balance)
    // This is done by NOT adding to spendable set, only to solvable set

    // 4. Register in vault registry (under same lock)
    if (!m_vault_registry.RegisterVault(metadata)) {
        return false;
    }

    // 5. Cache x-only keys for signing using the descriptor provider.
    std::unique_ptr<FlatSigningProvider> base_provider = GetSigningProvider(base_index, /*include_private=*/true);
    WalletLogPrintf("  HavePrivateKeys=%d, base_provider=%s\n", HavePrivateKeys(), base_provider ? "yes" : "no");
    if (base_provider) {
        WalletLogPrintf("  base_provider keys=%u, scripts=%u\n",
                        (unsigned)base_provider->keys.size(),
                        (unsigned)base_provider->scripts.size());
    }
    WalletLogPrintf("  Caching %zu x-only keys:\n", metadata.leaves.size());

    // DEBUG: Show what keys are in base_provider
    if (base_provider) {
        WalletLogPrintf("  [DEBUG] Keys in base_provider:\n");
        for (const auto& kv : base_provider->keys) {
            const CKey& k = kv.second;
            if (k.IsValid()) {
                XOnlyPubKey xonly(k.GetPubKey());
                WalletLogPrintf("    - KeyID=%s, xonly=%s\n", HexStr(kv.first), HexStr(xonly));
            }
        }
    }

    for (const auto& leaf : metadata.leaves) {
        // Covenant-only leaves are signatureless (keeper-spendable) — no key to cache; skip quietly.
        if (leaf.IsCovenantOnly()) {
            WalletLogPrintf("    Leaf '%s': covenant-only (no signing key)\n", leaf.purpose);
            continue;
        }
        WalletLogPrintf("    Leaf '%s': signing_key=%s\n", leaf.purpose, HexStr(leaf.signing_key));

        bool cached = false;
        if (base_provider) {
            CKey descriptor_key;
            if (base_provider->GetKeyByXOnly(leaf.signing_key, descriptor_key)) {
                m_vault_registry.CacheXOnlyKey(leaf.signing_key, descriptor_key);
                WalletLogPrintf("      ✓ Cached private key via descriptor provider\n");
                cached = true;
            }
        }

        // Descriptor-key scan: iterate through base_provider->keys and match by x-only
        // This is critical because derived child keys live in base_provider->keys,
        // not in the wallet's internal key maps
        if (!cached && base_provider) {
            WalletLogPrintf("      [DEBUG] Scanning %zu keys in base_provider...\n", base_provider->keys.size());
            for (const auto& kv : base_provider->keys) {
                const CKey& k = kv.second;
                if (!k.IsValid()) {
                    WalletLogPrintf("      [DEBUG] Skipping invalid key\n");
                    continue;
                }
                // Compare x-only of the derived full pubkey with leaf.signing_key
                XOnlyPubKey cand_xonly(k.GetPubKey());
                WalletLogPrintf("      [DEBUG] Comparing cand_xonly=%s with leaf=%s\n",
                                HexStr(cand_xonly), HexStr(leaf.signing_key));
                if (cand_xonly == leaf.signing_key) {
                    m_vault_registry.CacheXOnlyKey(leaf.signing_key, k);
                    WalletLogPrintf("      ✓ Cached private key via descriptor key scan\n");
                    cached = true;
                    break;
                }
            }
            if (!cached) {
                WalletLogPrintf("      [DEBUG] No x-only match found in descriptor key scan\n");
            }
        }

            if (!cached) {
                CKey wallet_key;
                if (GetKeyByXOnlyLocked(leaf.signing_key, wallet_key)) {
                    m_vault_registry.CacheXOnlyKey(leaf.signing_key, wallet_key);
                    WalletLogPrintf("      ✓ Cached private key via wallet lookup\n");
                    cached = true;
                }
            }

        if (!cached) {
            WalletLogPrintf("      ✗ Could not find private key for this x-only key\n");
        }
    }

    // 6. Cache script with wallet
    std::set<CScript> new_spks{covenant_spk};
    m_storage.TopUpCallback(new_spks, this);

    // 7. Persist vault metadata to database
    WalletBatch batch(m_storage.GetDatabase());
    if (!batch.WriteVaultMetadata(covenant_spk, metadata)) {
        return false;
    }

    return true;
}

bool DescriptorScriptPubKeyMan::LoadVaultFromDB(const VaultMetadata& metadata)
{
    LOCK(cs_desc_man);

    // 1. Validate metadata
    if (!metadata.Validate()) {
        return false;
    }

    // 2. Register in vault registry
    if (!m_vault_registry.RegisterVault(metadata)) {
        return false;
    }

    // 3. CRITICAL: Add covenant script to m_map_script_pub_keys
    // This is required so GetSigningProvider doesn't return nullptr at line 821
    // We use index 0 as a placeholder since we don't know the original base_script index
    const CScript& covenant_spk = metadata.GetScriptPubKey();
    m_map_script_pub_keys[covenant_spk] = 0;

    // 4. Cache script with wallet
    std::set<CScript> new_spks{covenant_spk};
    m_storage.TopUpCallback(new_spks, this);

    // 5. We don't know the originating descriptor slot here, so defer caching
    // until the vault is referenced through RegisterCovenantVault again.

    return true;
}

std::optional<VaultMetadata> DescriptorScriptPubKeyMan::GetVaultMetadata(const CScript& covenant_spk) const
{
    LOCK(cs_desc_man);
    return m_vault_registry.GetVaultByScript(covenant_spk);
}

bool DescriptorScriptPubKeyMan::IsCovenantVault(const CScript& script) const
{
    LOCK(cs_desc_man);
    return m_vault_registry.IsRegistered(script);
}

bool DescriptorScriptPubKeyMan::GetKeyByXOnly(const XOnlyPubKey& xonly, CKey& key_out) const
{
    LOCK(cs_desc_man);
    return GetKeyByXOnlyLocked(xonly, key_out);
}

bool DescriptorScriptPubKeyMan::GetKeyByXOnlyLocked(const XOnlyPubKey& xonly, CKey& key_out) const
{
    // Check cache first
    auto cached = m_vault_registry.GetKeyByXOnly(xonly);
    if (cached) {
        key_out = *cached;
        return true;
    }

    // For Taproot keys the descriptor machinery stores the child key under
    // Hash160(xonly) rather than Hash160(compressed pubkey). Derive that id
    // and try a lookup before falling back to the generic compressed forms.
    {
        uint160 xonly_hash = Hash160(xonly);
        CKeyID tap_keyid;
        std::copy(xonly_hash.begin(), xonly_hash.end(), tap_keyid.begin());
        auto tap_key = GetKey(tap_keyid);
        if (tap_key.has_value()) {
            key_out = *tap_key;
            m_vault_registry.CacheXOnlyKey(xonly, key_out);
            return true;
        }
    }

    // Try both parity versions (02/03 prefix)
    for (unsigned char prefix : {0x02, 0x03}) {
        unsigned char buf[33] = {prefix};
        std::copy(xonly.begin(), xonly.end(), buf + 1);

        CPubKey full_pubkey;
        full_pubkey.Set(buf, buf + 33);

        CKeyID keyid = full_pubkey.GetID();

        // Try to get the key using the regular GetKey method
        auto key_opt = GetKey(keyid);
        if (key_opt.has_value()) {
            key_out = *key_opt;
            // Cache for future lookups
            m_vault_registry.CacheXOnlyKey(xonly, key_out);
            return true;
        }
    }

    return false;
}

bool DescriptorScriptPubKeyMan::CacheVaultKey(const XOnlyPubKey& xonly, const CKey& key) const
{
    LOCK(cs_desc_man);
    return m_vault_registry.CacheXOnlyKey(xonly, key);
}

bool DescriptorScriptPubKeyMan::AddKey(const CKeyID& key_id, const CKey& key)
{
    LOCK(cs_desc_man);
    m_map_keys[key_id] = key;
    return true;
}

bool DescriptorScriptPubKeyMan::AddCryptedKey(const CKeyID& key_id, const CPubKey& pubkey, const std::vector<unsigned char>& crypted_key)
{
    LOCK(cs_desc_man);
    if (!m_map_keys.empty()) {
        return false;
    }

    m_map_crypted_keys[key_id] = make_pair(pubkey, crypted_key);
    return true;
}

bool DescriptorScriptPubKeyMan::HasWalletDescriptor(const WalletDescriptor& desc) const
{
    LOCK(cs_desc_man);
    return !m_wallet_descriptor.id.IsNull() && !desc.id.IsNull() && m_wallet_descriptor.id == desc.id;
}

void DescriptorScriptPubKeyMan::WriteDescriptor()
{
    LOCK(cs_desc_man);
    WalletBatch batch(m_storage.GetDatabase());
    if (!batch.WriteDescriptor(GetID(), m_wallet_descriptor)) {
        throw std::runtime_error(std::string(__func__) + ": writing descriptor failed");
    }
}

WalletDescriptor DescriptorScriptPubKeyMan::GetWalletDescriptor() const
{
    return m_wallet_descriptor;
}

std::unordered_set<CScript, SaltedSipHasher> DescriptorScriptPubKeyMan::GetScriptPubKeys() const
{
    return GetScriptPubKeys(0);
}

std::unordered_set<CScript, SaltedSipHasher> DescriptorScriptPubKeyMan::GetScriptPubKeys(int32_t minimum_index) const
{
    LOCK(cs_desc_man);
    std::unordered_set<CScript, SaltedSipHasher> script_pub_keys;
    script_pub_keys.reserve(m_map_script_pub_keys.size());

    for (auto const& [script_pub_key, index] : m_map_script_pub_keys) {
        if (index >= minimum_index) script_pub_keys.insert(script_pub_key);
    }
    return script_pub_keys;
}

int32_t DescriptorScriptPubKeyMan::GetEndRange() const
{
    return m_max_cached_index + 1;
}

bool DescriptorScriptPubKeyMan::GetDescriptorString(std::string& out, const bool priv) const
{
    LOCK(cs_desc_man);

    FlatSigningProvider provider;
    provider.keys = GetKeys();

    if (priv) {
        // For the private version, always return the master key to avoid
        // exposing child private keys. The risk implications of exposing child
        // private keys together with the parent xpub may be non-obvious for users.
        return m_wallet_descriptor.descriptor->ToPrivateString(provider, out);
    }

    return m_wallet_descriptor.descriptor->ToNormalizedString(provider, out, &m_wallet_descriptor.cache);
}

void DescriptorScriptPubKeyMan::UpgradeDescriptorCache()
{
    LOCK(cs_desc_man);
    if (m_storage.IsLocked() || m_storage.IsWalletFlagSet(WALLET_FLAG_LAST_HARDENED_XPUB_CACHED)) {
        return;
    }

    // Skip if we have the last hardened xpub cache
    if (m_wallet_descriptor.cache.GetCachedLastHardenedExtPubKeys().size() > 0) {
        return;
    }

    // Expand the descriptor
    FlatSigningProvider provider;
    provider.keys = GetKeys();
    FlatSigningProvider out_keys;
    std::vector<CScript> scripts_temp;
    DescriptorCache temp_cache;
    if (!m_wallet_descriptor.descriptor->Expand(0, provider, scripts_temp, out_keys, &temp_cache)){
        throw std::runtime_error("Unable to expand descriptor");
    }

    // Cache the last hardened xpubs
    DescriptorCache diff = m_wallet_descriptor.cache.MergeAndDiff(temp_cache);
    if (!WalletBatch(m_storage.GetDatabase()).WriteDescriptorCacheItems(GetID(), diff)) {
        throw std::runtime_error(std::string(__func__) + ": writing cache items failed");
    }
}

std::optional<SpkOwner> DescriptorScriptPubKeyMan::GetDescriptorOwnerForScript(const CScript& spk) const
{
    LOCK(cs_desc_man);

    // 0) Pull the exact child index for this spk from the map
    auto it = m_map_script_pub_keys.find(spk);
    if (it == m_map_script_pub_keys.end()) return std::nullopt;
    const int32_t index = it->second;

    // 1) Expand descriptor at that index to get a provider with spend data
    FlatSigningProvider out_keys;
    std::vector<CScript> scripts_temp;
    if (!m_wallet_descriptor.descriptor->ExpandFromCache(index, m_wallet_descriptor.cache, scripts_temp, out_keys)) {
        return std::nullopt;
    }

    // 2) Extract the **output** x-only key from the *input* spk (not from scripts_temp)
    std::vector<std::vector<unsigned char>> solutions;
    if (Solver(spk, solutions) != TxoutType::WITNESS_V1_TAPROOT) return std::nullopt;
    if (solutions.empty() || solutions[0].size() != 32) return std::nullopt;
    const XOnlyPubKey output_key(solutions[0]);

    // 3) Ask spend data for THIS output key
    TaprootSpendData spenddata;
    if (!out_keys.GetTaprootSpendData(output_key, spenddata)) return std::nullopt;
    if (spenddata.internal_key.IsNull()) return std::nullopt;

    // 4) Sanity check: re-tweak internal back to output and verify
    //    Q = lift_x(P) + H_tapTweak(P, merkle_root)*G  (x-only)
    //    Recompute the output key from internal_key + merkle_root and verify it matches
    const uint256* merkle_ptr = spenddata.merkle_root.IsNull() ? nullptr : &spenddata.merkle_root;
    auto tweak_result = spenddata.internal_key.CreateTapTweak(merkle_ptr);
    if (!tweak_result) {
        // Failed to compute taproot tweak
        return std::nullopt;
    }
    const XOnlyPubKey computed_output = tweak_result->first;

    if (computed_output != output_key) {
        // Wrong mapping - internal key doesn't produce the expected output key
        return std::nullopt;
    }

    SpkOwner owner;
    owner.desc_id = GetID();
    owner.index = index;
    owner.internal_xonly = spenddata.internal_key;
    owner.is_watch_only = !HavePrivateKeys();

    // Check if we have the private key for the internal key
    // Construct compressed pubkey from x-only (assume even Y)
    std::array<unsigned char, 33> compressed{};
    compressed[0] = 0x02;
    std::copy(spenddata.internal_key.begin(), spenddata.internal_key.end(), compressed.begin() + 1);
    CPubKey internal_pubkey(compressed.begin(), compressed.end());

    CKeyID internal_keyid = internal_pubkey.GetID();
    owner.has_priv_at_index = HasPrivKey(internal_keyid);

    return owner;
}

bool DescriptorScriptPubKeyMan::EnsurePrivKeyAtIndex(int32_t index)
{
    LOCK(cs_desc_man);

    // If wallet is watch-only or locked, we can't derive keys
    if (!HavePrivateKeys() || m_storage.IsLocked()) {
        return false;
    }

    // If index is beyond our current cache, TopUp to include it
    if (index > m_max_cached_index) {
        // Calculate how many keys we need to generate to reach this index
        int32_t target_size = index + 1 - m_wallet_descriptor.next_index;
        if (target_size > 0) {
            if (!TopUp(target_size)) {
                return false;
            }
        }
    }

    // Now verify the private key exists by expanding the descriptor with private keys
    FlatSigningProvider provider;
    provider.keys = GetKeys();
    FlatSigningProvider out_keys;

    // Expand with private keys (ExpandPrivate returns void, modifies out_keys in place)
    m_wallet_descriptor.descriptor->ExpandPrivate(index, provider, out_keys);

    // Check if we got any keys back
    return !out_keys.keys.empty();
}

std::optional<CKey> DescriptorScriptPubKeyMan::DerivePrivateKeyAtIndex(int32_t index, const XOnlyPubKey& internal_xonly)
{
    LOCK(cs_desc_man);

    // Ensure we have private keys and wallet is unlocked
    if (!HavePrivateKeys() || m_storage.IsLocked()) {
        return std::nullopt;
    }

    // Ensure the index is cached and TopUp if needed
    if (!EnsurePrivKeyAtIndex(index)) {
        return std::nullopt;
    }

    // Get root/master keys for derivation
    FlatSigningProvider root_provider;
    root_provider.keys = GetKeys();

    // Derive child keys at the specific index
    FlatSigningProvider child_provider;
    m_wallet_descriptor.descriptor->ExpandPrivate(index, root_provider, child_provider);

    // Find the internal private key whose x-only pubkey matches
    for (const auto& [keyid, key] : child_provider.keys) {
        CPubKey pub = key.GetPubKey();
        XOnlyPubKey xonly(pub);
        if (xonly == internal_xonly) {
            return key;
        }
    }

    return std::nullopt;
}

util::Result<void> DescriptorScriptPubKeyMan::UpdateWalletDescriptor(WalletDescriptor& descriptor)
{
    LOCK(cs_desc_man);
    std::string error;
    if (!CanUpdateToWalletDescriptor(descriptor, error)) {
        return util::Error{Untranslated(std::move(error))};
    }

    m_map_pubkeys.clear();
    m_map_script_pub_keys.clear();
    m_max_cached_index = -1;
    m_wallet_descriptor = descriptor;

    NotifyFirstKeyTimeChanged(this, m_wallet_descriptor.creation_time);
    return {};
}

bool DescriptorScriptPubKeyMan::CanUpdateToWalletDescriptor(const WalletDescriptor& descriptor, std::string& error)
{
    LOCK(cs_desc_man);
    if (!HasWalletDescriptor(descriptor)) {
        error = "can only update matching descriptor";
        return false;
    }

    if (descriptor.range_start > m_wallet_descriptor.range_start ||
        descriptor.range_end < m_wallet_descriptor.range_end) {
        // Use inclusive range for error
        error = strprintf("new range must include current range = [%d,%d]",
                          m_wallet_descriptor.range_start,
                          m_wallet_descriptor.range_end - 1);
        return false;
    }

    return true;
}
} // namespace wallet
