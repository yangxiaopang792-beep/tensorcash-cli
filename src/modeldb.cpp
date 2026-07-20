#include <common/args.h>
#include <modeldb.h>
#include <leveldb/options.h>
#include <leveldb/write_batch.h>
#include <logging.h>
#include <streams.h>
#include <wallet/rpc/api_model_registration.h>

#include <cstddef>
#include <map>
#include <set>
#include <span>
#include <utility>

namespace {
constexpr uint8_t DB_MODEL_PREFIX{'m'};
constexpr uint8_t DB_DEPOSIT_PREFIX{'d'};
constexpr uint8_t DB_BURN_PREFIX{'b'};
constexpr uint8_t DB_VERIFICATION_PREFIX{'v'};
constexpr uint8_t DB_CHALLENGE_PREFIX{'c'};
constexpr uint8_t DB_CHALLENGE_SCHEDULE_PREFIX{'q'};
constexpr uint8_t DB_BLOCK_MODEL_PREFIX{'x'};
constexpr uint8_t DB_MODEL_BLOCK_PREFIX{'y'};
constexpr uint8_t DB_SYNCED_TIP_PREFIX{'s'};
constexpr uint8_t DB_BLOCK_UNDO_PREFIX{'u'};

// Keep this many trailing per-block undo records on disk. A crash can only rewind
// ModelDB down to the last durably-flushed chainstate height, and an online reorg
// reverts via the block body (not the journal), so undo records far behind the tip
// are never read. The window must exceed the largest gap between chainstate flushes
// (cache-pressure or the >=24h periodic flush) measured in blocks; 50k is generous
// for any real flush cadence while keeping the journal at a few MB.
constexpr int32_t MODELDB_UNDO_KEEP_BLOCKS{50000};

struct ModelKey {
    uint8_t prefix{DB_MODEL_PREFIX};
    uint256 hash;

    ModelKey() = default;
    explicit ModelKey(const uint256& h) : hash(h) {}

    SERIALIZE_METHODS(ModelKey, obj)
    {
        READWRITE(obj.prefix, obj.hash);
    }
};

struct DepositKey {
    uint8_t prefix{DB_DEPOSIT_PREFIX};
    uint256 txid;
    uint32_t vout{0};

    [[maybe_unused]] DepositKey() = default;
    explicit DepositKey(const COutPoint& out) : txid(out.hash), vout(out.n) {}

    SERIALIZE_METHODS(DepositKey, obj)
    {
        READWRITE(obj.prefix, obj.txid, obj.vout);
    }
};

struct BurnKey {
    uint8_t prefix{DB_BURN_PREFIX};
    uint256 txid;
    uint32_t vout{0};

    BurnKey() = default;
    explicit BurnKey(const COutPoint& out) : txid(out.hash), vout(out.n) {}

    SERIALIZE_METHODS(BurnKey, obj)
    {
        READWRITE(obj.prefix, obj.txid, obj.vout);
    }
};

struct VerificationKey {
    uint8_t prefix{DB_VERIFICATION_PREFIX};
    uint32_t height{0};
    uint256 hash;

    VerificationKey() = default;
    VerificationKey(uint32_t h, const uint256& m) : height(h), hash(m) {}

    SERIALIZE_METHODS(VerificationKey, obj)
    {
        READWRITE(obj.prefix, obj.height, obj.hash);
    }
};

struct ChallengeKey {
    uint8_t prefix{DB_CHALLENGE_PREFIX};
    uint256 txid;
    uint32_t vout{0};

    ChallengeKey() = default;
    explicit ChallengeKey(const COutPoint& out) : txid(out.hash), vout(out.n) {}

    SERIALIZE_METHODS(ChallengeKey, obj)
    {
        READWRITE(obj.prefix, obj.txid, obj.vout);
    }
};

struct ChallengeScheduleKey {
    uint8_t prefix{DB_CHALLENGE_SCHEDULE_PREFIX};
    uint32_t height{0};
    uint256 hash;

    ChallengeScheduleKey() = default;
    ChallengeScheduleKey(uint32_t h, const uint256& m) : height(h), hash(m) {}

    SERIALIZE_METHODS(ChallengeScheduleKey, obj)
    {
        READWRITE(obj.prefix, obj.height, obj.hash);
    }
};

struct BlockModelKey {
    uint8_t prefix{DB_BLOCK_MODEL_PREFIX};
    uint256 block_hash;

    BlockModelKey() = default;
    explicit BlockModelKey(const uint256& b) : block_hash(b) {}

    SERIALIZE_METHODS(BlockModelKey, obj)
    {
        READWRITE(obj.prefix, obj.block_hash);
    }
};

struct BlockModelValue {
    uint32_t height{0};
    uint256 model_hash;

    SERIALIZE_METHODS(BlockModelValue, obj)
    {
        READWRITE(obj.height, obj.model_hash);
    }
};

struct ModelBlockKey {
    uint8_t prefix{DB_MODEL_BLOCK_PREFIX};
    uint256 model_hash;
    uint32_t height{0};
    uint256 block_hash;

    ModelBlockKey() = default;
    ModelBlockKey(const uint256& m, uint32_t h, const uint256& b) : model_hash(m), height(h), block_hash(b) {}

    SERIALIZE_METHODS(ModelBlockKey, obj)
    {
        READWRITE(obj.prefix, obj.model_hash, obj.height, obj.block_hash);
    }
};

struct SyncedTipKey {
    uint8_t prefix{DB_SYNCED_TIP_PREFIX};

    SERIALIZE_METHODS(SyncedTipKey, obj)
    {
        READWRITE(obj.prefix);
    }
};

struct SyncedTipValue {
    int32_t height{0};
    uint256 hash{uint256::ZERO};

    SERIALIZE_METHODS(SyncedTipValue, obj)
    {
        READWRITE(obj.height, obj.hash);
    }
};

struct BlockUndoKey {
    uint8_t prefix{DB_BLOCK_UNDO_PREFIX};
    int32_t height{0};

    BlockUndoKey() = default;
    explicit BlockUndoKey(int32_t h) : height(h) {}

    SERIALIZE_METHODS(BlockUndoKey, obj)
    {
        READWRITE(obj.prefix, obj.height);
    }
};

// Opaque pass-through (de)serializer: copies the stream verbatim, no length
// framing. Reading captures a key's whole (already-deobfuscated) value; writing
// re-emits those exact bytes (CDBBatch re-applies value obfuscation on Write).
struct RawSlurp {
    std::vector<unsigned char> bytes;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        if (!bytes.empty()) s.write(std::as_bytes(std::span<const unsigned char>(bytes)));
    }
    template <typename Stream>
    void Unserialize(Stream& s)
    {
        bytes.resize(s.size());
        if (!bytes.empty()) s.read(std::as_writable_bytes(std::span<unsigned char>(bytes)));
    }
};

template <typename T>
std::vector<unsigned char> SerializeToBytes(const T& obj)
{
    DataStream ss;
    ss << obj;
    const auto* p = reinterpret_cast<const unsigned char*>(ss.data());
    return std::vector<unsigned char>(p, p + ss.size());
}

enum class OverlayHit { Miss, Found, Tombstone };

} // namespace

// State buffered between BeginBlock() and CommitBlock()/AbortBlock(). `batch`
// holds the block's forward writes (typed, obfuscated on commit); `overlay` mirrors
// them as plaintext value bytes keyed by raw key bytes so same-block point reads
// see uncommitted writes; `undo` accumulates pre-block values for every first-touched
// key; `captured` dedupes undo capture to the first touch per key.
struct CModelActiveBlock {
    explicit CModelActiveBlock(CDBWrapper& parent) : batch(parent) {}

    CModelBlockUndo undo;
    CDBBatch batch;
    std::set<std::vector<unsigned char>> captured;
    std::map<std::vector<unsigned char>, std::optional<std::vector<unsigned char>>> overlay;

    // Disconnect mode: the staged writes ARE a rollback to a prior state, so no undo
    // is captured; commit erases the disconnected block's undo record and moves the
    // applied-tip marker to the new tip instead of writing a fresh undo record.
    bool is_disconnect{false};
    bool has_new_tip{false};
    int32_t new_tip_height{0};
    uint256 new_tip_hash{uint256::ZERO};
};

namespace {

template <typename K>
void CaptureUndoFirstTouch(CModelActiveBlock& ab, CDBWrapper& db, const K& key,
                           const std::vector<unsigned char>& key_bytes)
{
    if (!ab.captured.insert(key_bytes).second) return; // already captured this block
    CModelUndoEntry entry;
    entry.key = key_bytes;
    RawSlurp prior;
    if (db.Read(key, prior)) {
        entry.had_value = true;
        entry.value = std::move(prior.bytes);
    }
    ab.undo.entries.push_back(std::move(entry));
}

template <typename K, typename V>
bool StageWrite(CModelActiveBlock& ab, CDBWrapper& db, const K& key, const V& value)
{
    std::vector<unsigned char> kb = SerializeToBytes(key);
    if (!ab.is_disconnect) CaptureUndoFirstTouch(ab, db, key, kb);
    ab.batch.Write(key, value);
    ab.overlay[std::move(kb)] = SerializeToBytes(value);
    return true;
}

template <typename K>
bool StageErase(CModelActiveBlock& ab, CDBWrapper& db, const K& key)
{
    std::vector<unsigned char> kb = SerializeToBytes(key);
    if (!ab.is_disconnect) CaptureUndoFirstTouch(ab, db, key, kb);
    ab.batch.Erase(key);
    ab.overlay[std::move(kb)] = std::nullopt;
    return true;
}

template <typename K, typename V>
OverlayHit OverlayRead(const CModelActiveBlock& ab, const K& key, V& value)
{
    auto it = ab.overlay.find(SerializeToBytes(key));
    if (it == ab.overlay.end()) return OverlayHit::Miss;
    if (!it->second.has_value()) return OverlayHit::Tombstone;
    DataStream ss{std::as_bytes(std::span<const unsigned char>(*it->second))};
    value = V{};
    ss >> value;
    return OverlayHit::Found;
}

template <typename K>
OverlayHit OverlayProbe(const CModelActiveBlock& ab, const K& key)
{
    auto it = ab.overlay.find(SerializeToBytes(key));
    if (it == ab.overlay.end()) return OverlayHit::Miss;
    return it->second.has_value() ? OverlayHit::Found : OverlayHit::Tombstone;
}

} // namespace

std::unique_ptr<CModelDB> g_modeldb = nullptr;

CModelDB::CModelDB(const Consensus::Params& consensusParams, size_t cache_size, bool fMemory, bool fWipe)
{
    DBParams params;
    params.cache_bytes = cache_size;
    params.memory_only = fMemory;
    params.wipe_data = fWipe;
    params.path = gArgs.GetDataDirNet() / "modeldb";
    if (gArgs.GetBoolArg("-reindex", false)) {
        fs::remove_all(params.path);
    }
    db = std::make_unique<CDBWrapper>(params);

    if (IsEmpty()) {
        ModelRecord default_record;
        default_record.metadata.model_name = consensusParams.DefaultModelName;
        default_record.metadata.model_commit = consensusParams.DefaultModelCommit;
        default_record.metadata.difficulty = static_cast<int64_t>(consensusParams.ModelDifficultyNormalizer);
        default_record.metadata.cid = consensusParams.DefaultModelCID;
        default_record.status = ModelRegistrationStatus::Registered;
        default_record.deposit_block_hash = consensusParams.hashGenesisBlock;
        default_record.deposit_block_height = 0;
        default_record.commit_block_hash = consensusParams.hashGenesisBlock;
        default_record.commit_block_height = 0;
        default_record.deposit_amount = 0;
        default_record.verification_code = 0;

        const uint256 model_hash = HashSHA256(default_record.metadata.model_name, default_record.metadata.model_commit);
        if (WriteModel(model_hash, default_record)) {
            LogPrintf("[ModelDB] Default model inserted on startup.\n");
        } else {
            LogPrintf("[ModelDB] Failed to write default model.\n");
        }
    }
    LogPrintf("[ModelDB] Initialized database at %s\n", params.path.utf8string());
}

CModelDB::~CModelDB() = default;

bool CModelDB::WriteModel(const uint256& model_hash, const ModelRecord& record, bool overwrite)
{
    if (!overwrite && Exists(model_hash)) {
        LogPrintf("[ModelDB] Error: Attempted to write duplicated model for %s.\n", model_hash.ToString());
        return false;
    }
    // During block connection, stage into the per-block journaled batch (atomic
    // forward-write + undo capture + applied-tip); otherwise fsync directly.
    if (m_active) return StageWrite(*m_active, *db, ModelKey(model_hash), record);
    // Argument-misbinding / durability-hygiene fix: CDBWrapper::Write's 3rd
    // parameter is `fSync`, not an "overwrite" flag (LevelDB always overwrites).
    // It is correct to fsync these infrequent model-state writes rather than leave
    // their durability to an unrelated, accidental flag.
    return db->Write(ModelKey(model_hash), record, /*fSync=*/true);
}

bool CModelDB::ReadModel(const uint256& model_hash, ModelRecord& record) const
{
    if (m_active) {
        switch (OverlayRead(*m_active, ModelKey(model_hash), record)) {
        case OverlayHit::Found: return true;
        case OverlayHit::Tombstone: return false;
        case OverlayHit::Miss: break;
        }
    }
    return db->Read(ModelKey(model_hash), record);
}

bool CModelDB::Exists(const uint256& model_hash) const
{
    if (m_active) {
        switch (OverlayProbe(*m_active, ModelKey(model_hash))) {
        case OverlayHit::Found: return true;
        case OverlayHit::Tombstone: return false;
        case OverlayHit::Miss: break;
        }
    }
    if (IsEmpty()) {
        return false;
    }
    return db->Exists(ModelKey(model_hash));
}

bool CModelDB::Erase(const uint256& model_hash)
{
    if (m_active) return StageErase(*m_active, *db, ModelKey(model_hash));
    return db->Erase(ModelKey(model_hash));
}

// NOTE: iterator-based reads (ForEachModel, GetVerificationSchedule,
// GetChallengeSchedule, GetBlocksForModelFromHeight) deliberately read committed
// leveldb state and do NOT consult the active-block overlay. This is safe under the
// connect/replay ordering: schedule entries are read at the height they fire, which
// is always strictly greater than the height they were written at, so a block never
// iterates schedule rows it staged itself; and the ConnectTip runtime catch-up uses
// ForEachModel only to pick candidates, then re-reads each via the overlay-aware
// point ReadModel before mutating. Only point reads need overlay visibility.
void CModelDB::ForEachModel(const std::function<void(const uint256&, const ModelRecord&)>& callback) const
{
    std::unique_ptr<CDBIterator> it{db->NewIterator()};
    ModelKey seek_key;
    seek_key.hash.SetNull();
    it->Seek(seek_key);
    while (it->Valid()) {
        ModelKey key;
        if (!it->GetKey(key) || key.prefix != DB_MODEL_PREFIX) {
            break;
        }
        ModelRecord rec;
        if (it->GetValue(rec)) {
            callback(key.hash, rec);
        }
        it->Next();
    }
}

bool CModelDB::IsEmpty() const
{
    return db->IsEmpty();
}

bool CModelDB::WriteDepositIndex(const COutPoint& outpoint, const uint256& model_hash)
{
    if (m_active) return StageWrite(*m_active, *db, DepositKey(outpoint), model_hash);
    return db->Write(DepositKey(outpoint), model_hash);
}

bool CModelDB::ReadDepositIndex(const COutPoint& outpoint, uint256& model_hash) const
{
    if (m_active) {
        switch (OverlayRead(*m_active, DepositKey(outpoint), model_hash)) {
        case OverlayHit::Found: return true;
        case OverlayHit::Tombstone: return false;
        case OverlayHit::Miss: break;
        }
    }
    return db->Read(DepositKey(outpoint), model_hash);
}

bool CModelDB::EraseDepositIndex(const COutPoint& outpoint)
{
    if (m_active) return StageErase(*m_active, *db, DepositKey(outpoint));
    return db->Erase(DepositKey(outpoint));
}

std::optional<uint256> CModelDB::LookupModelByDeposit(const COutPoint& outpoint) const
{
    uint256 model_hash;
    if (ReadDepositIndex(outpoint, model_hash)) {
        return model_hash;
    }
    return std::nullopt;
}

bool CModelDB::WriteBurnIndex(const COutPoint& outpoint, const uint256& model_hash)
{
    if (m_active) return StageWrite(*m_active, *db, BurnKey(outpoint), model_hash);
    return db->Write(BurnKey(outpoint), model_hash);
}

bool CModelDB::ReadBurnIndex(const COutPoint& outpoint, uint256& model_hash) const
{
    if (m_active) {
        switch (OverlayRead(*m_active, BurnKey(outpoint), model_hash)) {
        case OverlayHit::Found: return true;
        case OverlayHit::Tombstone: return false;
        case OverlayHit::Miss: break;
        }
    }
    return db->Read(BurnKey(outpoint), model_hash);
}

bool CModelDB::EraseBurnIndex(const COutPoint& outpoint)
{
    if (m_active) return StageErase(*m_active, *db, BurnKey(outpoint));
    return db->Erase(BurnKey(outpoint));
}

std::optional<uint256> CModelDB::LookupModelByBurn(const COutPoint& outpoint) const
{
    uint256 model_hash;
    if (ReadBurnIndex(outpoint, model_hash)) {
        return model_hash;
    }
    return std::nullopt;
}

bool CModelDB::WriteChallengeDepositIndex(const COutPoint& outpoint, const uint256& model_hash)
{
    if (m_active) return StageWrite(*m_active, *db, ChallengeKey(outpoint), model_hash);
    return db->Write(ChallengeKey(outpoint), model_hash, true);
}

bool CModelDB::ReadChallengeDepositIndex(const COutPoint& outpoint, uint256& model_hash) const
{
    if (m_active) {
        switch (OverlayRead(*m_active, ChallengeKey(outpoint), model_hash)) {
        case OverlayHit::Found: return true;
        case OverlayHit::Tombstone: return false;
        case OverlayHit::Miss: break;
        }
    }
    return db->Read(ChallengeKey(outpoint), model_hash);
}

bool CModelDB::EraseChallengeDepositIndex(const COutPoint& outpoint)
{
    if (m_active) return StageErase(*m_active, *db, ChallengeKey(outpoint));
    return db->Erase(ChallengeKey(outpoint));
}

std::optional<uint256> CModelDB::LookupModelByChallengeDeposit(const COutPoint& outpoint) const
{
    uint256 model_hash;
    if (ReadChallengeDepositIndex(outpoint, model_hash)) {
        return model_hash;
    }
    return std::nullopt;
}

bool CModelDB::WriteVerificationSchedule(uint32_t height, const uint256& model_hash, const VerificationValue& value)
{
    if (m_active) return StageWrite(*m_active, *db, VerificationKey(height, model_hash), value);
    return db->Write(VerificationKey(height, model_hash), value, true);
}

bool CModelDB::EraseVerificationSchedule(uint32_t height, const uint256& model_hash)
{
    if (m_active) return StageErase(*m_active, *db, VerificationKey(height, model_hash));
    return db->Erase(VerificationKey(height, model_hash));
}

std::optional<CModelDB::VerificationValue> CModelDB::ReadVerificationSchedule(uint32_t height, const uint256& model_hash) const
{
    if (m_active) {
        VerificationValue value;
        switch (OverlayRead(*m_active, VerificationKey(height, model_hash), value)) {
        case OverlayHit::Found: return value;
        case OverlayHit::Tombstone: return std::nullopt;
        case OverlayHit::Miss: break;
        }
    }
    VerificationValue value;
    if (db->Read(VerificationKey(height, model_hash), value)) {
        return value;
    }
    return std::nullopt;
}

bool CModelDB::UpdateVerificationSchedule(uint32_t height, const uint256& model_hash, const VerificationValue& value)
{
    if (m_active) return StageWrite(*m_active, *db, VerificationKey(height, model_hash), value);
    return db->Write(VerificationKey(height, model_hash), value, true);
}

std::vector<std::pair<uint256, CModelDB::VerificationValue>> CModelDB::GetVerificationSchedule(uint32_t height) const
{
    std::vector<std::pair<uint256, VerificationValue>> results;
    std::unique_ptr<CDBIterator> it{db->NewIterator()};
    VerificationKey seek(height, uint256::ZERO);
    it->Seek(seek);
    while (it->Valid()) {
        VerificationKey key;
        if (!it->GetKey(key) || key.prefix != DB_VERIFICATION_PREFIX || key.height != height) {
            break;
        }
        VerificationValue value;
        if (it->GetValue(value)) {
            results.emplace_back(key.hash, value);
        }
        it->Next();
    }
    return results;
}

bool CModelDB::WriteChallengeSchedule(uint32_t height, const uint256& model_hash, const ChallengeValue& value)
{
    if (m_active) return StageWrite(*m_active, *db, ChallengeScheduleKey(height, model_hash), value);
    return db->Write(ChallengeScheduleKey(height, model_hash), value, true);
}

bool CModelDB::EraseChallengeSchedule(uint32_t height, const uint256& model_hash)
{
    if (m_active) return StageErase(*m_active, *db, ChallengeScheduleKey(height, model_hash));
    return db->Erase(ChallengeScheduleKey(height, model_hash));
}

std::optional<CModelDB::ChallengeValue> CModelDB::ReadChallengeSchedule(uint32_t height, const uint256& model_hash) const
{
    if (m_active) {
        ChallengeValue value;
        switch (OverlayRead(*m_active, ChallengeScheduleKey(height, model_hash), value)) {
        case OverlayHit::Found: return value;
        case OverlayHit::Tombstone: return std::nullopt;
        case OverlayHit::Miss: break;
        }
    }
    ChallengeValue value;
    if (db->Read(ChallengeScheduleKey(height, model_hash), value)) {
        return value;
    }
    return std::nullopt;
}

bool CModelDB::UpdateChallengeSchedule(uint32_t height, const uint256& model_hash, const ChallengeValue& value)
{
    if (m_active) return StageWrite(*m_active, *db, ChallengeScheduleKey(height, model_hash), value);
    return db->Write(ChallengeScheduleKey(height, model_hash), value, true);
}

std::vector<std::pair<uint256, CModelDB::ChallengeValue>> CModelDB::GetChallengeSchedule(uint32_t height) const
{
    std::vector<std::pair<uint256, ChallengeValue>> results;
    std::unique_ptr<CDBIterator> it{db->NewIterator()};
    ChallengeScheduleKey seek(height, uint256::ZERO);
    it->Seek(seek);
    while (it->Valid()) {
        ChallengeScheduleKey key;
        if (!it->GetKey(key) || key.prefix != DB_CHALLENGE_SCHEDULE_PREFIX || key.height != height) {
            break;
        }
        ChallengeValue value;
        if (it->GetValue(value)) {
            results.emplace_back(key.hash, value);
        }
        it->Next();
    }
    return results;
}

bool CModelDB::WriteBlockModelIndex(const uint256& block_hash, uint32_t height, const uint256& model_hash)
{
    // Intentionally NOT routed through the per-block journal: this is non-authoritative
    // index metadata (block_hash -> model, and the model -> blocks reverse index) used
    // only to enumerate candidate blocks for challenge zero-work. It is keyed by
    // block hash, so entries for orphaned blocks are inert (callers filter by the
    // active chain) and it is fully rebuildable from block bodies. Keeping it out of
    // the undo journal avoids journaling churn for a reorg-safe, derived index.
    if (model_hash.IsNull()) {
        return true;
    }
    CDBBatch batch(*db);
    BlockModelValue value;
    value.height = height;
    value.model_hash = model_hash;
    batch.Write(BlockModelKey(block_hash), value);
    batch.Write(ModelBlockKey(model_hash, height, block_hash), uint8_t{1});
    return db->WriteBatch(batch);
}

std::vector<uint256> CModelDB::GetBlocksForModelFromHeight(const uint256& model_hash, uint32_t min_height) const
{
    std::vector<uint256> results;
    std::unique_ptr<CDBIterator> it{db->NewIterator()};
    ModelBlockKey seek(model_hash, 0, uint256::ZERO);
    it->Seek(seek);
    while (it->Valid()) {
        ModelBlockKey key;
        if (!it->GetKey(key) || key.prefix != DB_MODEL_BLOCK_PREFIX || key.model_hash != model_hash) {
            break;
        }
        if (key.height >= min_height) {
            results.push_back(key.block_hash);
        }
        it->Next();
    }
    return results;
}

bool CModelDB::WriteSyncedTip(int height, const uint256& block_hash)
{
    SyncedTipValue value;
    value.height = height;
    value.hash = block_hash;
    return db->Write(SyncedTipKey{}, value, true);
}

bool CModelDB::ReadSyncedTip(int& height, uint256& block_hash) const
{
    SyncedTipValue value;
    if (!db->Read(SyncedTipKey{}, value)) return false;
    height = value.height;
    block_hash = value.hash;
    return true;
}

bool CModelDB::EraseSyncedTip()
{
    return db->Erase(SyncedTipKey{});
}

bool CModelDB::HasActiveBlock() const
{
    return m_active != nullptr;
}

void CModelDB::BeginBlock(int32_t height, const uint256& hash, int32_t parent_height, const uint256& parent_hash)
{
    // A leftover active block means a prior connect neither committed nor aborted;
    // drop its buffered (never-persisted) writes before starting the new one.
    m_active = std::make_unique<CModelActiveBlock>(*db);
    m_active->undo.height = height;
    m_active->undo.hash = hash;
    m_active->undo.parent_height = parent_height;
    m_active->undo.parent_hash = parent_hash;
}

void CModelDB::BeginDisconnect(int32_t disconnected_height, bool has_new_tip, int32_t new_tip_height, const uint256& new_tip_hash)
{
    m_active = std::make_unique<CModelActiveBlock>(*db);
    m_active->is_disconnect = true;
    m_active->undo.height = disconnected_height; // the undo record to erase on commit
    m_active->has_new_tip = has_new_tip;
    m_active->new_tip_height = new_tip_height;
    m_active->new_tip_hash = new_tip_hash;
}

bool CModelDB::ResumeBlock(int32_t height, const uint256& hash, int32_t parent_height, const uint256& parent_hash)
{
    CModelBlockUndo existing;
    if (!db->Read(BlockUndoKey(height), existing) || existing.height != height || existing.hash != hash) {
        // No matching journaled undo for this block: a ModelDB written by a pre-journal
        // binary, or a stale same-height record from another branch. Manufacturing a
        // fresh undo here would be a PARTIAL record (covering only the about-to-be-made
        // repair writes, not the block's original effects) that a later rewind would
        // wrongly trust. Leave the journal inactive: the caller must then DEFER any
        // irreversible catch-up repairs (the next journaled block re-applies them) and
        // only persist the marker — never write un-journaled, irreversible state here.
        return false;
    }
    BeginBlock(height, hash, parent_height, parent_hash);
    // Merge into the existing undo: keys it already covers keep their original
    // pre-block prior value (marked `captured` so a fresh touch does not overwrite it);
    // only newly-touched keys are captured against current state.
    m_active->undo.entries = existing.entries;
    for (const auto& e : existing.entries) {
        m_active->captured.insert(e.key);
    }
    return true;
}

bool CModelDB::CommitBlock()
{
    if (!m_active) return true;
    std::unique_ptr<CModelActiveBlock> ab = std::move(m_active); // clears m_active first

    if (ab->is_disconnect) {
        // Rollback batch: the staged writes already revert the block; just drop its
        // consumed undo record and move the applied-tip marker to the new tip, all in
        // the same fsync'd batch so the disconnect is atomic.
        ab->batch.Erase(BlockUndoKey(ab->undo.height));
        if (ab->has_new_tip) {
            SyncedTipValue tip;
            tip.height = ab->new_tip_height;
            tip.hash = ab->new_tip_hash;
            ab->batch.Write(SyncedTipKey{}, tip);
        } else {
            ab->batch.Erase(SyncedTipKey{});
        }
        if (!db->WriteBatch(ab->batch, /*fSync=*/true)) {
            LogPrintf("[ModelDB] CommitBlock(disconnect): failed to persist at height=%d\n", ab->undo.height);
            return false;
        }
        return true;
    }

    // Forward writes are already staged in ab->batch. Add the undo record and the
    // applied-tip marker, then commit everything as one fsync'd batch so on-disk
    // ModelDB advances to this block atomically (or not at all).
    ab->batch.Write(BlockUndoKey(ab->undo.height), ab->undo);
    SyncedTipValue tip;
    tip.height = ab->undo.height;
    tip.hash = ab->undo.hash;
    ab->batch.Write(SyncedTipKey{}, tip);
    // Compact: drop the undo record that has fallen out of the retention window.
    if (ab->undo.height > MODELDB_UNDO_KEEP_BLOCKS) {
        ab->batch.Erase(BlockUndoKey(ab->undo.height - MODELDB_UNDO_KEEP_BLOCKS));
    }
    if (!db->WriteBatch(ab->batch, /*fSync=*/true)) {
        LogPrintf("[ModelDB] CommitBlock: failed to persist batch at height=%d\n", ab->undo.height);
        return false;
    }
    return true;
}

void CModelDB::AbortBlock()
{
    // Nothing was written to leveldb yet; discarding the in-memory state is enough.
    m_active.reset();
}

bool CModelDB::ReadBlockUndo(int32_t height, CModelBlockUndo& undo) const
{
    return db->Read(BlockUndoKey(height), undo);
}

bool CModelDB::ApplyUndoAndRewindTip(const CModelBlockUndo& undo)
{
    CDBBatch batch(*db);
    // Restore every touched key to its pre-block value (or erase if it did not exist).
    for (const auto& e : undo.entries) {
        RawSlurp key;
        key.bytes = e.key;
        if (e.had_value) {
            RawSlurp value;
            value.bytes = e.value;
            batch.Write(key, value);
        } else {
            batch.Erase(key);
        }
    }
    batch.Erase(BlockUndoKey(undo.height));
    if (undo.parent_height > 0 || !undo.parent_hash.IsNull()) {
        SyncedTipValue tip;
        tip.height = undo.parent_height;
        tip.hash = undo.parent_hash;
        batch.Write(SyncedTipKey{}, tip);
    } else {
        batch.Erase(SyncedTipKey{});
    }
    return db->WriteBatch(batch, /*fSync=*/true);
}
