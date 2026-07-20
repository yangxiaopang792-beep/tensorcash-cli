#include <chainparams.h>
#include <chrono>
#include <common/args.h>
#include <consensus/merkle.h>
#include <interfaces/mining.h>
#include <modeldb.h>
#include <node/context.h>
#include <node/extapi.h>
#include <node/miner.h>
#include <primitives/block.h>
#include <primitives/proofblob.h>
#include <rpc/blockheader_generated.h>
#include <rpc/server_util.h>
#include <thread>
#include <util/signalinterrupt.h>
#include <util/check.h>
#include <validation.h>
#include <validationinterface.h>
#include <verification/quick_verifier.h>

using interfaces::BlockTemplate;
using interfaces::Mining;
using namespace std::chrono;

namespace node {
namespace {
class MiningSubmitStateCatcher final : public CValidationInterface
{
public:
    explicit MiningSubmitStateCatcher(const uint256& hash_in) : m_hash(hash_in) {}

    bool found{false};
    BlockValidationState state;

protected:
    void BlockChecked(const CBlock& block, const BlockValidationState& state_in) override
    {
        if (block.GetHash() != m_hash) {
            return;
        }
        found = true;
        state = state_in;
    }

private:
    uint256 m_hash;
};
} // namespace

uint32_t MaxMiningWorkUnitsFromArgs()
{
    const int64_t value{gArgs.GetIntArg("-maxminingworkunits", DEFAULT_MAX_MINING_WORK_UNITS)};
    if (value < 1) {
        LogPrintf("Warning: -maxminingworkunits=%lld is below the minimum; using 1\n", static_cast<long long>(value));
        return 1;
    }
    return static_cast<uint32_t>(std::min<int64_t>(value, std::numeric_limits<uint32_t>::max()));
}

ExtAPI::ExtAPI(NodeContext& node)
    : m_node{node},
      config{EnvConfig::fromEnvironment("MINER", 6000, 7000)},
      m_broker_mode{gArgs.GetBoolArg("-miningbrokermode", false)},
      context{nullptr},
      jobPush{nullptr},
      solPull{nullptr},
      addressMinerPush{config.getPushAddress()},
      addressMinerPull{config.getPullAddress()},
      waitingApiAnswer{false},
      mining_on{false},
      metrics_{},
      rateLimiter_{120},
      connection_healthy_{true},
      last_send_success_{std::chrono::steady_clock::now()},
      requestTracker{},
      jobThread{},
      solThread{} {
    requestTracker.setMaxOpenRequests(MaxMiningWorkUnitsFromArgs());
    if (m_broker_mode) {
        LogPrintf("ExtAPI initialized in compute-broker mode: sovereign startmining/startminingwithrotation are refused; MINER PUSH/PULL sockets will not be bound. Mining is driven by create_mining_work_unit / submit_mining_response RPCs.\n");
    } else {
        LogPrintf("ExtAPI initialized in sovereign mode with push=%s, pull=%s\n", addressMinerPush, addressMinerPull);
    }
}

bool ExtAPI::EnsureSockets() {
    if (context && jobPush && solPull) {
        return true;
    }
    if (context || jobPush || solPull) {
        LogError("Mining API sockets in inconsistent state (context=%p, jobPush=%p, solPull=%p)\n",
                 (void*)context, (void*)jobPush, (void*)solPull);
        return false;
    }
    if (!Initialize()) {
        LogError("Failed to initialize mining API sockets\n");
        return false;
    }
    return true;
}

bool ExtAPI::Initialize() {
    if (m_broker_mode) {
        // Defense in depth: even if a future code path reaches Initialize,
        // refuse to bind the PUSH/PULL transport in broker mode. Solutions
        // must arrive only via submit_mining_response.
        LogError("ExtAPI::Initialize refused: -miningbrokermode=1; sovereign mining transport is not bound in this mode\n");
        return false;
    }

    try {
        // Validate configuration first
        config = EnvConfig::fromEnvironment("MINER", 6000, 7000);
    } catch (const std::exception& e) {
        LogError("Configuration error: %s\n", e.what());
        return false;
    }

    assert(!context);
    context = zmq_ctx_new();
    if (!context) {
        LogError("Could not create the external API context\n");
        return false;
    }

    assert(!jobPush);
    jobPush = zmq_socket(context, ZMQ_PUSH);
    if (!jobPush) {
        LogError("Could not create the API push socket\n");
        return false;
    }
    
    if (zmq_connect(jobPush, addressMinerPush.c_str()) != 0) {
        LogError("Could not connect the API push socket: %s\n", zmq_strerror(errno));
        zmq_close(jobPush);
        jobPush = nullptr;
        return false;
    }

    assert(!solPull);
    solPull = zmq_socket(context, ZMQ_PULL);
    if (!solPull) {
        LogError("Could not create the API pull socket\n");
        return false;
    }
    
    if (zmq_bind(solPull, addressMinerPull.c_str()) != 0) {
        LogError("Could not bind the API pull socket: %s\n", zmq_strerror(errno));
        zmq_close(solPull);
        solPull = nullptr;
        return false;
    }

    // Set receive timeout so SolutionReceiverLoop can check mining_on periodically
    int recv_timeout = 1000;  // 1 second timeout for responsive shutdown
    zmq_setsockopt(solPull, ZMQ_RCVTIMEO, &recv_timeout, sizeof(recv_timeout));

    LogPrintf("API sockets are connected\n");
    return true;
}

ExtAPI::~ExtAPI() {
    StopMining();
    if (context) {
        int linger = 0;
        if (solPull) {
            zmq_setsockopt(solPull, ZMQ_LINGER, &linger, sizeof(linger));
            zmq_close(solPull);
            solPull = nullptr;
        }
        
        if (jobPush) {
            zmq_setsockopt(jobPush, ZMQ_LINGER, &linger, sizeof(linger));
            zmq_close(jobPush);
            jobPush = nullptr;
        }

        zmq_ctx_term(context);
        context = nullptr;
    }
}

void ExtAPI::checkNetworkHealth() {
    auto now = std::chrono::steady_clock::now();
    if (now - last_send_success_ > PARTITION_TIMEOUT) {
        if (connection_healthy_.exchange(false)) {
            LogError("Network partition detected - no successful sends for %d seconds\n", 
                     std::chrono::duration_cast<std::chrono::seconds>(PARTITION_TIMEOUT).count());
            metrics_.network_errors++;
            
            // Attempt reconnection
            if (jobPush) {
                zmq_disconnect(jobPush, addressMinerPush.c_str());
                zmq_connect(jobPush, addressMinerPush.c_str());
            }
        }
    }
}

void ExtAPI::publishMetrics() const {
        LogPrintf("Mining metrics: received=%lu usable=%lu invalid=%lu duplicate=%lu limited=%lu errors=%lu\n",
             metrics_.solutions_received.load(),
             metrics_.solutions_accepted.load(),
             metrics_.solutions_rejected.load(),
             metrics_.solutions_duplicates.load(),
             metrics_.rate_limited.load(),
             metrics_.network_errors.load());
}

// bool ExtAPI::ValidateMiningResponse(const proof::MiningResponse* resp, CBlock& block) {
//     if (!resp) {
//         LogError("Null mining response\n");
//         return false;
//     }

//     // Validate request ID is within expected range
//     if (resp->req_id() >= MAX_REQUEST_ID) {
//         LogError("Invalid request ID: %u\n", resp->req_id());
//         return false;
//     }

//     // Validate pow_blob_hash
//     if (!resp->pow_blob_hash() || resp->pow_blob_hash()->size() != EXPECTED_HASH_SIZE) {
//         LogError("Invalid PoW blob hash size: %zu\n", 
//                 resp->pow_blob_hash() ? resp->pow_blob_hash()->size() : 0);
//         return false;
//     }

//     // Get the block for this request ID
//     auto blockOpt = requestTracker.getBlockForId(resp->req_id());
//     if (!blockOpt.has_value()) {
//         LogError("No block found for request ID: %u\n", resp->req_id());
//         return false;
//     }

//     block = blockOpt.value();
    
//     // Validate nonce (already bounded by uint32_t)
//     block.nNonce = resp->nonce();
    
//     // Validate adjusted bits (should be validated against consensus rules)
//     block.nAdjBits = resp->adjusted_bits();
//     // TODO: Add consensus validation for nAdjBits here
    
//     // Safe copy with bounds checking
//     std::memcpy(block.hashPoW.begin(), resp->pow_blob_hash()->data(), EXPECTED_HASH_SIZE);
    
//     // Validate PoW blob before filling
//     if (!resp->pow_blob()) {
//         LogError("Missing PoW blob\n");
//         return false;
//     }
    
//     try {
//         block.pow.fillFromFB(resp->pow_blob());
//     } catch (const std::exception& e) {
//         LogError("Failed to fill PoW blob: %s\n", e.what());
//         return false;
//     }
    
//     return true;
// }

ExtAPI::MiningResponseDisposition ExtAPI::ValidateMiningResponse(
    const proof::MiningResponse* resp,
    CBlock& block,
    uint32_t* request_id_out)
{
    if (!resp) {
        LogError("Null mining response\n");
        return MiningResponseDisposition::Invalid;
    }
    
    LogDebug(BCLog::VALIDATION, "=== ValidateMiningResponse DEBUG START ===\n");
    LogDebug(BCLog::VALIDATION, "Request ID: %u\n", resp->req_id());
    LogDebug(BCLog::VALIDATION, "Nonce received: %u (0x%08x)\n", resp->nonce(), resp->nonce());
    LogDebug(BCLog::VALIDATION, "Adjusted bits received: %u (0x%08x)\n", resp->adjusted_bits(), resp->adjusted_bits());
    LogDebug(BCLog::VALIDATION, "Difficulty: %u\n", resp->difficulty());

    // Validate request ID is within expected range
    if (resp->req_id() < 1 || resp->req_id() >= MAX_REQUEST_ID) {
        LogError("Invalid request ID: %u (min: 1, max: %u)\n", resp->req_id(), MAX_REQUEST_ID);
        return MiningResponseDisposition::Invalid;
    }

    // Validate pow_blob_hash
    if (!resp->pow_blob_hash() || resp->pow_blob_hash()->size() != EXPECTED_HASH_SIZE) {
        LogError("Invalid PoW blob hash size: %zu (expected: %zu)\n", 
                 resp->pow_blob_hash() ? resp->pow_blob_hash()->size() : 0,
                 EXPECTED_HASH_SIZE);
        return MiningResponseDisposition::Invalid;
    }
    
    if (LogAcceptCategory(BCLog::VALIDATION, BCLog::Level::Debug)) {
        std::string pow_blob_hash_hex;
        for (size_t i = 0; i < resp->pow_blob_hash()->size(); i++) {
            pow_blob_hash_hex += strprintf("%02x", resp->pow_blob_hash()->data()[i]);
        }
        LogDebug(BCLog::VALIDATION, "PoW blob hash received: %s\n", pow_blob_hash_hex);
    }

    // Get the block for this request ID
    auto lookup = requestTracker.getRequestForSolution(resp->req_id());
    if (lookup.state == RequestTracker::LookupState::Submitted) {
        LogDebug(BCLog::VALIDATION,
                 "Ignoring late duplicate mining solution for request ID: %u\n",
                 resp->req_id());
        return MiningResponseDisposition::Stale;
    }
    if (lookup.state == RequestTracker::LookupState::Missing || !lookup.block.has_value()) {
        LogDebug(BCLog::VALIDATION,
                 "Ignoring mining solution for unknown or expired request ID: %u\n",
                 resp->req_id());
        return MiningResponseDisposition::Stale;
    }

    block = *lookup.block;
    if (request_id_out != nullptr) {
        *request_id_out = resp->req_id();
    }
    
    // Log original block state
    LogDebug(BCLog::VALIDATION, "Original block state:\n");
    LogDebug(BCLog::VALIDATION, "  nVersion: %d (0x%08x)\n", block.nVersion, block.nVersion);
    LogDebug(BCLog::VALIDATION, "  hashPrevBlock: %s\n", block.hashPrevBlock.ToString());
    LogDebug(BCLog::VALIDATION, "  hashMerkleRoot: %s\n", block.hashMerkleRoot.ToString());
    LogDebug(BCLog::VALIDATION, "  nTime: %u (0x%08x)\n", block.nTime, block.nTime);
    LogDebug(BCLog::VALIDATION, "  nBits: %u (0x%08x)\n", block.nBits, block.nBits);
    LogDebug(BCLog::VALIDATION, "  nNonce (before): %u (0x%08x)\n", block.nNonce, block.nNonce);
    LogDebug(BCLog::VALIDATION, "  nAdjBits (before): %u (0x%08x)\n", block.nAdjBits, block.nAdjBits);
    
    // Apply nonce and adjusted bits
    block.nNonce = resp->nonce();
    block.nAdjBits = resp->adjusted_bits();
    
    LogDebug(BCLog::VALIDATION, "After applying response values:\n");
    LogDebug(BCLog::VALIDATION, "  nNonce (after): %u (0x%08x)\n", block.nNonce, block.nNonce);
    LogDebug(BCLog::VALIDATION, "  nAdjBits (after): %u (0x%08x)\n", block.nAdjBits, block.nAdjBits);
    
    // Debug: log the actual header bytes that will be hashed
    if (LogAcceptCategory(BCLog::VALIDATION, BCLog::Level::Debug)) {
        std::vector<unsigned char> header;
        header.resize(80);
        WriteLE32(&header[0], block.nVersion);
        memcpy(&header[4], block.hashPrevBlock.begin(), 32);
        memcpy(&header[36], block.hashMerkleRoot.begin(), 32);
        WriteLE32(&header[68], block.nTime);
        WriteLE32(&header[72], block.nBits);
        WriteLE32(&header[76], block.nNonce);
        std::string header_hex;
        for (size_t i = 0; i < header.size(); i++) {
            header_hex += strprintf("%02x", header[i]);
        }
        LogDebug(BCLog::VALIDATION, "80-byte header hex: %s\n", header_hex);
        uint256 hash_calculated = Hash(header);
        LogDebug(BCLog::VALIDATION, "Hash calculated from header: %s\n", hash_calculated.ToString());
    }
    
    // Validate PoW blob before filling
    if (!resp->pow_blob()) {
        LogError("Missing PoW blob\n");
        return MiningResponseDisposition::Invalid;
    }
    
    LogDebug(BCLog::VALIDATION, "PoW blob present (non-null)\n");
    
    try {
        block.pow.fillFromFB(resp->pow_blob());
        LogDebug(BCLog::VALIDATION, "Successfully filled PoW blob\n");
    } catch (const std::exception& e) {
        LogError("Failed to fill PoW blob: %s\n", e.what());
        return MiningResponseDisposition::Invalid;
    }

    // Generate the hashPoW commitment (Merkle root post-activation)
    {
        ChainstateManager& chainman = EnsureChainman(m_node);
        const CBlockIndex* prev_index = WITH_LOCK(::cs_main, return chainman.m_blockman.LookupBlockIndex(block.hashPrevBlock));
        int height = prev_index ? prev_index->nHeight + 1 : 0;
        bool use_merkle = chainman.GetConsensus().IsVdfSpvActive(height);
        block.hashPoW = block.pow.GetCommitment(use_merkle);
    }
    LogDebug(BCLog::VALIDATION, "  hashPoW (generated from the ProofBlob): %s\n", block.hashPoW.ToString());

    // Update cumulative_tick now that PoW blob is available (tick known).
    // cumulative_tick = prev.cumulative_tick + block.pow.tick
    {
        ChainstateManager& chainman = EnsureChainman(m_node);
        const CBlockIndex* prev_index = WITH_LOCK(::cs_main, return chainman.m_blockman.LookupBlockIndex(block.hashPrevBlock));
        if (prev_index != nullptr) {
            CBlock prev_blk;
            if (chainman.m_blockman.ReadBlock(prev_blk, *prev_index)) {
                uint64_t prev_cum = prev_blk.cumulative_tick;
                block.cumulative_tick = prev_cum + block.pow.tick;
            } else {
                // Fallback: if previous block not readable, at least assign current tick
                block.cumulative_tick = block.pow.tick;
            }
        } else {
            // No previous index (unlikely here) — treat as starting point
            block.cumulative_tick = block.pow.tick;
        }
    }

    LogDebug(BCLog::VALIDATION, "block.pow.GetModelHash(): %s\n", block.pow.GetModelHash().ToString());
    LogDebug(BCLog::VALIDATION, "block.pow.model_identifier: %s\n", block.pow.model_identifier);
    LogDebug(BCLog::VALIDATION, "=== ValidateMiningResponse DEBUG END ===\n");

    return MiningResponseDisposition::Valid;
}

void ExtAPI::JobSchedulerLoop() {
    Mining& miner = EnsureMining(m_node);
    ChainstateManager& chainman = EnsureChainman(m_node);
    
    uint64_t nextSendTime = 0;
    uint64_t lastHealthCheck = 0;
    uint64_t lastMetricsTime = 0;
    CBlock   block;
    uint64_t now = 0;
    
    LogPrintf("Mining JobSchedulerLoop thread was started\n");

    while (mining_on && !chainman.m_interrupt) {
        bool tip_changed = false;
        {
            LOCK(cs_main);
            const CBlockIndex* cur_tip = chainman.ActiveChain().Tip();
            tip_changed = !cur_tip || cur_tip->GetBlockHash() != block.hashPrevBlock;
        }
        if (tip_changed) {
            nextSendTime = 0;
        }

        now = duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
        
        // Health check every minute
        if (now - lastHealthCheck > 60000) {
            int opt = 0;
            size_t opt_len = sizeof(opt);
            if (zmq_getsockopt(jobPush, ZMQ_EVENTS, &opt, &opt_len) < 0) {
                LogError("Socket health check failed\n");
            }
            lastHealthCheck = now;
        }
        
        // Publish metrics every minute
        if (now - lastMetricsTime > 60000) {
            publishMetrics();
            lastMetricsTime = now;
        }
        
        if (now >= nextSendTime) {
            // Get coinbase script - either from callback (rotating) or fixed
            CScript coinbase_script = m_use_callback ? m_get_coinbase_script() : m_coinbase_output_script;

            auto blockTemplate = miner.createNewBlock({ .coinbase_output_script = coinbase_script });
            block = blockTemplate->getBlock();
            block.hashMerkleRoot = BlockMerkleRoot(block);
            SendApiRequest(block);
            nextSendTime = now + DELAY_BETWEEN_MINING_REQUESTS;
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    LogPrintf("Mining JobSchedulerLoop thread was finished\n");
}

void ExtAPI::SolutionReceiverLoop() {
    ChainstateManager& chainman = EnsureChainman(m_node);
    CBlock blockToProcess;
    QuickVerifier quickVerifier;
    LogPrintf("Mining SolutionReceiverLoop thread was started\n");
    while (mining_on.load() && !chainman.m_interrupt) {
        uint32_t request_id = 0;
        if (GetApiAnswer(blockToProcess, false, &request_id)) {
            // V3 prompt binding (TIP-0003): a nonce-bearing v3 proof
            // folds the admission nonce into every u (§7); without the v3
            // context this advisory check would recompute u WITHOUT the nonce
            // and log a false "Quick verification FAILED" for every valid
            // admission-band own-solution. Mirror RunLocalQuick / the submit
            // RPC: height = parent + 1 (dormant at -1 when the parent is
            // unknown), registered difficulty from modeldb.
            const int proof_height = WITH_LOCK(::cs_main, {
                const CBlockIndex* pprev = chainman.m_blockman.LookupBlockIndex(blockToProcess.hashPrevBlock);
                return pprev ? pprev->nHeight + 1 : -1;
            });
            // Parent known => proof_height is the real connect height, so the v3
            // rules below run with the correct (non-dormant) context and the
            // quick verdict faithfully mirrors what ConnectBlock will decide.
            const bool parent_known = proof_height >= 0;
            {
                const auto& pb = blockToProcess.pow;
                int64_t v3_difficulty{0};
                if (pb.version >= 3 && g_modeldb && !pb.model_identifier.empty()) {
                    ModelRecord rec;
                    if (g_modeldb->ReadModel(pb.GetModelHash(), rec)) {
                        v3_difficulty = rec.metadata.difficulty;
                    }
                }
                quickVerifier.SetV3Context(chainman.GetConsensus(), proof_height, v3_difficulty);
            }
            // Run quick verification on the mining solution before submitting
            // Version-keyed: enforces the reuse gate iff pow.version >= REUSE_GATE_VERSION.
            const VerificationResult qvResult = quickVerifier.QuickVerify(blockToProcess.pow);
            if (qvResult != VerificationResult::Quick_OK) {
                LogWarning("Quick verification FAILED for mining solution (result=%d): %s\n",
                           static_cast<int>(qvResult), quickVerifier.GetLastError());
                // Gate (was advisory): a quick-fail is a deterministic, model-free
                // self-consistency reject (bad final hash / sequence / params) that
                // ProcessNewBlock would also reject, so drop the hopeless solution
                // here instead of dispatching it into ProcessNewBlock and the
                // external Quick_Smell verifier — mirroring submit_mining_response's
                // hard gate. Guarded on parent_known: when the parent is UNKNOWN the
                // v3 rules above ran DORMANT (proof_height = -1), so a nonce-bearing
                // build-ahead own solution would false-fail the nonce-less final-hash
                // recomputation here; in that window stay advisory (fall through to
                // ProcessNewBlock, exactly as before) so a valid build-ahead block is
                // never dropped. Build-ahead normally has the parent header known, so
                // this still gates the realistic hopeless-solution cases.
                if (parent_known) {
                    continue;
                }
            } else {
                LogPrintf("Quick verification passed for mining solution\n");
            }

            const uint256 block_hash = blockToProcess.GetHash();
            auto blockPtr = std::make_shared<const CBlock>(std::move(blockToProcess));
            auto sc = std::make_shared<MiningSubmitStateCatcher>(block_hash);
            CHECK_NONFATAL(chainman.m_options.signals)->RegisterSharedValidationInterface(sc);

            bool new_block = false;
            const bool accepted = chainman.ProcessNewBlock(blockPtr, true, true, &new_block);

            CHECK_NONFATAL(chainman.m_options.signals)->UnregisterSharedValidationInterface(sc);

            if (accepted) {
                requestTracker.markSubmitted(request_id);
                if (!new_block) {
                    LogPrintf("Mining solution already known by node: request_id=%u block=%s\n",
                              request_id, block_hash.ToString());
                }
                continue;
            }

            if (!sc->found && chainman.GetConsensus().external_api) {
                requestTracker.markSubmitted(request_id);
                LogPrintf("Mining solution submitted for async full validation: request_id=%u block=%s\n",
                          request_id, block_hash.ToString());
                continue;
            }

            if (sc->found) {
                LogWarning("Mining solution failed local admission: request_id=%u block=%s reason=%s\n",
                           request_id, block_hash.ToString(), sc->state.ToString());
            } else {
                LogWarning("Mining solution was not accepted synchronously: request_id=%u block=%s\n",
                           request_id, block_hash.ToString());
            }
        }
    }
    LogPrintf("Mining SolutionReceiverLoop thread was finished\n");
}

void ExtAPI::SendApiRequest(CBlock& block) {
    if (!EnsureSockets()) {
        LogError("NO API socket\n");
        return;
    }

    // Use new increment method
    uint32_t req_id = requestTracker.incrementAndStore(block);
    
    flatbuffers::FlatBufferBuilder builder;
    // Create reversed vectors for the hashes
    // std::vector<uint8_t> merkle_reversed(block.hashMerkleRoot.begin(), block.hashMerkleRoot.end());
    // std::reverse(merkle_reversed.begin(), merkle_reversed.end());

    // std::vector<uint8_t> prevBlock_reversed(block.hashPrevBlock.begin(), block.hashPrevBlock.end());
    // std::reverse(prevBlock_reversed.begin(), prevBlock_reversed.end());

    // auto merkle_vec = builder.CreateVector(merkle_reversed);
    // auto hashPrevBlock_vec = builder.CreateVector(prevBlock_reversed);    
    auto merkle_vec = builder.CreateVector(block.hashMerkleRoot.begin(), EXPECTED_HASH_SIZE);
    auto hashPrevBlock_vec = builder.CreateVector(block.hashPrevBlock.begin(), EXPECTED_HASH_SIZE);
    LogDebug(BCLog::VALIDATION, "proof::CreateBlockHeader req_id=%u nTime=%u nBits=%u\n", req_id, block.nTime, block.nBits);

    auto header_fb = proof::CreateBlockHeader(builder, req_id, block.nVersion, 
                                            hashPrevBlock_vec, merkle_vec, 
                                            block.nTime, block.nBits);
    builder.Finish(header_fb);
    
    zmq_msg_t request;
    if (zmq_msg_init_size(&request, builder.GetSize()) != 0) {
        LogError("Failed to initialize ZMQ message\n");
        return;
    }
    
    memcpy(zmq_msg_data(&request), builder.GetBufferPointer(), builder.GetSize());
    
    int rc = zmq_sendmsg(jobPush, &request, ZMQ_DONTWAIT);
    zmq_msg_close(&request);
    
    if (rc != -1) {
        last_send_success_ = std::chrono::steady_clock::now();
        connection_healthy_.store(true);
    } else {
        checkNetworkHealth();
        if (errno == EAGAIN) {
            LogPrintf("Mining job queue full, skipping\n");
        } else {
            LogError("zmq_sendmsg error: %s\n", zmq_strerror(errno));
            metrics_.network_errors++;
        }
    }
}

bool ExtAPI::GetApiAnswer(CBlock& block, const bool wait_answer, uint32_t* request_id_out) {
    if (!EnsureSockets()) {
        LogError("NO solPull socket\n");
        return false;
    }

    // Rate limiting check
    if (!rateLimiter_.allowRequest()) {
        metrics_.rate_limited++;
        // Use non-blocking receive to drain excess messages
        zmq_msg_t drain_msg;
        zmq_msg_init(&drain_msg);
        while (zmq_recvmsg(solPull, &drain_msg, ZMQ_DONTWAIT) != -1) {
            zmq_msg_close(&drain_msg);
            zmq_msg_init(&drain_msg);
            metrics_.rate_limited++;
        }
        zmq_msg_close(&drain_msg);
        return false;
    }

    zmq_msg_t reply;
    zmq_msg_init(&reply);
    
    struct MessageGuard {
        zmq_msg_t* msg;
        ~MessageGuard() { if (msg) zmq_msg_close(msg); }
    } guard{&reply};

    try {
        waitingApiAnswer.store(true);
        for (;;) {
            // Receive with timeout (set in Initialize) so loops can stay responsive.
            auto received = zmq_recvmsg(solPull, &reply, 0);
            if (received == -1) {
                if (errno == EAGAIN) {
                    if (wait_answer) {
                        continue;
                    }
                    waitingApiAnswer.store(false);
                    return false;
                }
                LogError("Solution receive error: %s\n", zmq_strerror(errno));
                metrics_.network_errors++;
                waitingApiAnswer.store(false);
                return false;
            }

            LogDebug(BCLog::VALIDATION, "Mining solution received, size: %zu bytes\n", zmq_msg_size(&reply));

            // Increment solutions_received only after successful receive
            metrics_.solutions_received++;

            if (zmq_msg_size(&reply) < sizeof(flatbuffers::uoffset_t)) {
                LogError("Invalid message size\n");
                metrics_.solutions_rejected++;
                waitingApiAnswer.store(false);
                return false;
            }

            auto resp = flatbuffers::GetRoot<proof::MiningResponse>(zmq_msg_data(&reply));
            
            LogDebug(BCLog::VALIDATION, "Solution details: req_id=%u, nonce=%u, adjusted_bits=%u\n",
                    resp->req_id(), resp->nonce(), resp->adjusted_bits());

            const MiningResponseDisposition disposition = ValidateMiningResponse(resp, block, request_id_out);
            if (disposition == MiningResponseDisposition::Stale) {
                metrics_.solutions_duplicates++;
                continue;
            }

            if (disposition == MiningResponseDisposition::Invalid) {
                metrics_.solutions_rejected++;
                waitingApiAnswer.store(false);
                return false;
            }

            metrics_.solutions_accepted++;
            // Use system_clock and convert to seconds (Unix timestamp) for GUI display
            metrics_.last_solution_time = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
            waitingApiAnswer.store(false);
            return true;
        }
        
    } catch (const std::exception& e) {
        LogError("Exception in GetApiAnswer: %s\n", e.what());
        metrics_.network_errors++;
        waitingApiAnswer.store(false);
        return false;
    }
}

UniValue ExtAPI::StartMining(CScript& coinbase_output_script) {
    if (m_broker_mode) {
        return UniValue("Node is running in compute-broker mining mode (-miningbrokermode=1); the sovereign startmining entry point is refused. Use create_mining_work_unit / submit_mining_response.");
    }
    if (mining_on.load()) {
        return UniValue("Mining is started already");
    }

    // Reinitialize ZMQ context/sockets if they were shut down by StopMining.
    if (!context || !jobPush || !solPull) {
        if (!Initialize()) {
            return UniValue("Failed to initialize mining API sockets");
        }
    }

    mining_on.store(true);
    m_use_callback = false;
    m_coinbase_output_script = std::move(coinbase_output_script);

    jobThread = std::thread([this]() {
        this->JobSchedulerLoop();
    });
    solThread = std::thread([this]() {
        this->SolutionReceiverLoop();
    });

    LogPrintf("Mining threads were started\n");
    return UniValue("Mining was started");
}

UniValue ExtAPI::StartMiningWithCallback(std::function<CScript()> get_coinbase_script) {
    if (m_broker_mode) {
        return UniValue("Node is running in compute-broker mining mode (-miningbrokermode=1); the sovereign startminingwithrotation entry point is refused. Use create_mining_work_unit / submit_mining_response.");
    }
    if (mining_on.load()) {
        return UniValue("Mining is started already");
    }

    mining_on.store(true);
    m_use_callback = true;
    m_get_coinbase_script = std::move(get_coinbase_script);

    jobThread = std::thread([this]() {
        this->JobSchedulerLoop();
    });
    solThread = std::thread([this]() {
        this->SolutionReceiverLoop();
    });

    LogPrintf("Mining threads were started with address rotation\n");
    return UniValue("Mining was started with address rotation");
}

UniValue ExtAPI::StopMining() {
    if (!mining_on.load()) {
        return UniValue("Mining is stopped already");
    }

    mining_on.store(false);

    // Threads will exit cleanly:
    // - SolutionReceiverLoop: receive timeout (1s) allows checking mining_on
    // - JobSchedulerLoop: checks mining_on in loop condition
    // ZMQ context stays alive for restart

    if (jobThread.joinable()) jobThread.join();
    if (solThread.joinable()) solThread.join();

    // Fully tear down sockets/context so StartMining can reinitialize cleanly.
    if (context) {
        int linger = 0;
        if (solPull) {
            zmq_setsockopt(solPull, ZMQ_LINGER, &linger, sizeof(linger));
            zmq_close(solPull);
            solPull = nullptr;
        }
        if (jobPush) {
            zmq_setsockopt(jobPush, ZMQ_LINGER, &linger, sizeof(linger));
            zmq_close(jobPush);
            jobPush = nullptr;
        }
        zmq_ctx_term(context);
        context = nullptr;
    }

    LogPrintf("Mining threads were joined\n");
    return UniValue("Mining stopped");
}
}
