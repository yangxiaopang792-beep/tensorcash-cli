// Copyright (c) 2025 The TensorCash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * Mock cosign bridge for C++ unit tests.
 * Implements HWI-style stdio JSON protocol for testing.
 *
 * Usage: mock_cosign_bridge [--fail-ping] [--bad-json] [--error-all]
 */

#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <map>
#include <memory>
#include <vector>
#include <ctime>
#include <cstdlib>
#include <chrono>

#include <univalue.h>

// Command-line flags for controlling mock behavior
static bool g_fail_ping = false;
static bool g_bad_json = false;
static bool g_error_all = false;
static bool g_malformed_response = false;

// Mock Nostr pubkey (64 hex chars, matching secp256k1 x-only pubkey format)
static const std::string MOCK_NOSTR_PUBKEY = "aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233";
static const std::string MOCK_NETWORK = "regtest";

// Bulletin board init state — must call init_bb before discussion commands
static bool g_bb_initialized = false;

// In-memory discussion post storage
struct MockDiscussionPost {
    std::string post_id;
    std::string scope_type;
    std::string scope_id;
    std::string network;
    std::string author_pubkey;
    std::string content;
    int64_t created_at;
    UniValue proof;
};
static std::vector<MockDiscussionPost> g_discussion_posts;

// EPHEMERAL SESSION STORAGE: In-memory only, like Rust bridge
// Sessions persist only while the bridge subprocess is alive.
// When BridgeManager stops the bridge, all sessions are lost.
struct MockSession {
    std::string session_id;
    std::string invite_code;
    std::string sas;
    std::string transport;
    int ttl;
    int64_t created_at;
    int messages_sent{0};
    int messages_received{0};
    bool handshake_complete{false};  // SECURITY: Phase 4 requirement - no send/recv before handshake
};

// Global in-memory session storage (ephemeral)
static std::map<std::string, std::shared_ptr<MockSession>> g_sessions;

std::string GenerateSessionId() {
    std::ostringstream oss;
    // Use time with microsecond precision for better uniqueness
    auto now = std::chrono::high_resolution_clock::now();
    auto nanos = std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
    oss << "mock_session_" << nanos << "_" << (rand() % 10000);
    return oss.str();
}

std::string GenerateInviteCode(const std::string& session_id) {
    // Generate deterministic 5-word code from session_id
    return "apple-banana-cherry-delta-echo";
}

std::string GenerateSAS(const std::string& session_id) {
    return "word1-word2-word3-word4-word5";
}

std::string GenerateSASNumeric(const std::string& session_id) {
    return "123456";
}

UniValue HandleVersion(const UniValue& params) {
    if (g_error_all) {
        UniValue error(UniValue::VOBJ);
        error.pushKV("error", "Forced error");
        return error;
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("api_version", 1);
    result.pushKV("git_commit", "mock-cpp-bridge");

    UniValue flags(UniValue::VARR);
    flags.push_back("noise");
    flags.push_back("spake2");
    result.pushKV("build_flags", flags);

    result.pushKV("bridge_version", "0.1.0-mock-cpp");
    return result;
}

UniValue HandlePing(const UniValue& params) {
    if (g_fail_ping) {
        UniValue error(UniValue::VOBJ);
        error.pushKV("error", "Bridge ping failed (mock)");
        return error;
    }

    if (g_error_all) {
        UniValue error(UniValue::VOBJ);
        error.pushKV("error", "Forced error");
        return error;
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("bridge_alive", true);
    result.pushKV("version", "0.1.0-mock-cpp");

    UniValue transports(UniValue::VARR);
    transports.push_back("ws");
    transports.push_back("nostr");
    result.pushKV("transports", transports);

    result.pushKV("uptime_sec", 42);

    // SECURITY: Only advertise capabilities that are actually implemented.
    // Advertising unimplemented capabilities causes tests to pass incorrectly.
    // DO NOT add capabilities without implementing the corresponding handler.
    UniValue caps(UniValue::VARR);
    caps.push_back("resume");
    caps.push_back("send_multi");
    result.pushKV("capabilities", caps);

    return result;
}

UniValue HandleInit(const UniValue& params) {
    if (g_error_all) {
        UniValue error(UniValue::VOBJ);
        error.pushKV("error", "Forced error");
        return error;
    }

    // Extract parameters
    std::string transport = params.exists("transport") ? params["transport"].get_str() : "auto";
    int ttl = params.exists("ttl") ? params["ttl"].getInt<int>() : 1800;

    // Create session (in-memory only)
    std::string session_id = GenerateSessionId();
    auto session = std::make_shared<MockSession>();
    session->session_id = session_id;
    session->invite_code = GenerateInviteCode(session_id);
    session->sas = GenerateSAS(session_id);
    session->transport = transport;
    session->ttl = ttl;
    session->created_at = std::time(nullptr);

    // Add to in-memory sessions
    g_sessions[session_id] = session;

    // Build response
    UniValue result(UniValue::VOBJ);
    result.pushKV("session_id", session_id);

    std::string invite_link = "cosign:?r=" + session_id.substr(0, 16) + "&t=" + transport + "#c=" + session->invite_code;
    result.pushKV("invite_link", invite_link);
    result.pushKV("invite_code", session->invite_code);
    result.pushKV("qr_data", invite_link);
    result.pushKV("qr_error_correction", "M");
    result.pushKV("sas", session->sas);
    result.pushKV("sas_numeric", GenerateSASNumeric(session_id));
    result.pushKV("transport_selected", transport);

    return result;
}

UniValue HandleJoin(const UniValue& params) {
    if (g_error_all) {
        UniValue error(UniValue::VOBJ);
        error.pushKV("error", "Forced error");
        return error;
    }

    std::string invite_link = params.exists("invite_link") ? params["invite_link"].get_str() : "";

    // Mock: just return a fake session
    std::string session_id = GenerateSessionId();

    UniValue result(UniValue::VOBJ);
    result.pushKV("session_id", session_id);
    result.pushKV("sas", GenerateSAS(session_id));
    result.pushKV("sas_numeric", GenerateSASNumeric(session_id));

    return result;
}

UniValue HandleHandshakeAuto(const UniValue& params) {
    if (g_error_all) {
        UniValue error(UniValue::VOBJ);
        error.pushKV("error", "Forced error");
        return error;
    }

    std::string session_id = params.exists("session_id") ? params["session_id"].get_str() : "";

    // Check in-memory sessions
    auto it = g_sessions.find(session_id);
    if (it == g_sessions.end()) {
        UniValue error(UniValue::VOBJ);
        error.pushKV("error", "Unknown session: " + session_id);
        return error;
    }

    auto session = it->second;

    if (session->handshake_complete) {
        UniValue cached(UniValue::VOBJ);
        cached.pushKV("handshake_complete", true);
        cached.pushKV("sas", session->sas);
        cached.pushKV("sas_numeric", GenerateSASNumeric(session_id));
        cached.pushKV("message", "Handshake already complete; returning cached session state.");
        return cached;
    }

    // Mark handshake as complete (in-memory only)
    session->handshake_complete = true;

    UniValue result(UniValue::VOBJ);
    result.pushKV("handshake_complete", true);
    result.pushKV("sas", session->sas);
    result.pushKV("sas_numeric", GenerateSASNumeric(session_id));
    result.pushKV("message", "Handshake complete! Verify SAS with peer to confirm no MITM.");

    return result;
}

UniValue HandleSend(const UniValue& params) {
    if (g_error_all) {
        UniValue error(UniValue::VOBJ);
        error.pushKV("error", "Forced error");
        return error;
    }

    std::string session_id = params.exists("session_id") ? params["session_id"].get_str() : "";

    // Check in-memory sessions
    auto it = g_sessions.find(session_id);
    if (it == g_sessions.end()) {
        UniValue error(UniValue::VOBJ);
        error.pushKV("error", "Unknown session: " + session_id);
        return error;
    }

    auto session = it->second;

    // SECURITY: Phase 4 enforcement - reject send before handshake completes
    if (!session->handshake_complete) {
        UniValue error(UniValue::VOBJ);
        error.pushKV("error", "COSIGN_HANDSHAKE_REQUIRED: Cannot send before SPAKE2/Noise handshake completes. Use cosign.handshake_auto first.");
        return error;
    }
    session->messages_sent++;

    UniValue result(UniValue::VOBJ);
    result.pushKV("ok", true);
    result.pushKV("seq", session->messages_sent);

    return result;
}

UniValue HandleRecv(const UniValue& params) {
    if (g_error_all) {
        UniValue error(UniValue::VOBJ);
        error.pushKV("error", "Forced error");
        return error;
    }

    std::string session_id = params.exists("session_id") ? params["session_id"].get_str() : "";

    // Check in-memory sessions
    auto it = g_sessions.find(session_id);
    if (it == g_sessions.end()) {
        UniValue error(UniValue::VOBJ);
        error.pushKV("error", "Unknown session: " + session_id);
        return error;
    }

    auto session = it->second;

    // SECURITY: Phase 4 enforcement - reject recv before handshake completes
    if (!session->handshake_complete) {
        UniValue error(UniValue::VOBJ);
        error.pushKV("error", "COSIGN_HANDSHAKE_REQUIRED: Cannot recv before SPAKE2/Noise handshake completes. Use cosign.handshake_auto first.");
        return error;
    }
    session->messages_received++;

    // Mock: return a fake payload
    UniValue payload(UniValue::VOBJ);
    payload.pushKV("type", "mock_response");
    payload.pushKV("data", "test_data");

    UniValue result(UniValue::VOBJ);
    result.pushKV("payload", payload);

    return result;
}

UniValue HandleStatus(const UniValue& params) {
    if (g_error_all) {
        UniValue error(UniValue::VOBJ);
        error.pushKV("error", "Forced error");
        return error;
    }

    std::string session_id = params.exists("session_id") ? params["session_id"].get_str() : "";

    // Check in-memory sessions
    auto it = g_sessions.find(session_id);
    if (it == g_sessions.end()) {
        UniValue error(UniValue::VOBJ);
        error.pushKV("error", "Unknown session: " + session_id);
        return error;
    }

    auto session = it->second;
    int64_t age_sec = std::time(nullptr) - session->created_at;

    UniValue result(UniValue::VOBJ);
    result.pushKV("state", "open");
    result.pushKV("peer_verified", true);
    result.pushKV("messages_sent", session->messages_sent);
    result.pushKV("messages_received", session->messages_received);
    result.pushKV("age_sec", age_sec);
    result.pushKV("ttl_sec", session->ttl);
    result.pushKV("transport", session->transport);

    return result;
}

UniValue HandleClose(const UniValue& params) {
    if (g_error_all) {
        UniValue error(UniValue::VOBJ);
        error.pushKV("error", "Forced error");
        return error;
    }

    std::string session_id = params.exists("session_id") ? params["session_id"].get_str() : "";

    // Remove session from in-memory storage
    g_sessions.erase(session_id);

    UniValue result(UniValue::VOBJ);
    result.pushKV("ok", true);

    return result;
}

UniValue HandleMetrics(const UniValue& params) {
    if (g_error_all) {
        UniValue error(UniValue::VOBJ);
        error.pushKV("error", "Forced error");
        return error;
    }

    // Count in-memory sessions
    UniValue result(UniValue::VOBJ);
    result.pushKV("active_sessions", static_cast<int>(g_sessions.size()));
    result.pushKV("total_messages", 0);
    result.pushKV("bridge_restarts", 0);

    UniValue failures(UniValue::VOBJ);
    failures.pushKV("ws", 0);
    failures.pushKV("nostr", 0);
    result.pushKV("transport_failures", failures);

    result.pushKV("avg_latency_ms", 42);
    result.pushKV("p95_latency_ms", 85);
    result.pushKV("p99_latency_ms", 150);

    // Add bridge_health for M2 tests
    UniValue health(UniValue::VOBJ);
    health.pushKV("health_state", "healthy");
    health.pushKV("restart_count", 0);
    health.pushKV("max_restarts", 5);
    health.pushKV("consecutive_failures", 0);
    health.pushKV("last_successful_ping", static_cast<int64_t>(std::time(nullptr)));
    health.pushKV("seconds_since_last_ping", 0);
    result.pushKV("bridge_health", health);

    return result;
}

UniValue HandleAttest(const UniValue& params) {
    if (g_error_all) {
        UniValue error(UniValue::VOBJ);
        error.pushKV("error", "Forced error");
        return error;
    }

    std::string session_id = params.exists("session_id") ? params["session_id"].get_str() : "";
    std::string address = params.exists("address") ? params["address"].get_str() : "";
    std::string signature = params.exists("signature") ? params["signature"].get_str() : "";

    // Check in-memory sessions
    auto it = g_sessions.find(session_id);
    if (it == g_sessions.end()) {
        UniValue error(UniValue::VOBJ);
        error.pushKV("error", "Unknown session: " + session_id);
        return error;
    }

    // Step 1: Generate challenge (if no signature provided)
    if (signature.empty()) {
        std::string challenge = "cosign|" + session_id + "|test-sas";

        UniValue result(UniValue::VOBJ);
        result.pushKV("challenge", challenge);
        return result;
    }

    // Step 2: Verify signature (mock - always succeeds)
    UniValue result(UniValue::VOBJ);
    result.pushKV("verified", true);

    UniValue peer(UniValue::VOBJ);
    peer.pushKV("address", address);
    result.pushKV("peer", peer);

    return result;
}

UniValue HandleResume(const UniValue& params) {
    if (g_error_all) {
        UniValue error(UniValue::VOBJ);
        error.pushKV("error", "Forced error");
        return error;
    }

    std::string session_id = params.exists("session_id") ? params["session_id"].get_str() : "";
    [[maybe_unused]] int from_seq = params.exists("from_seq") ? params["from_seq"].getInt<int>() : 0;

    // Check in-memory sessions
    auto it = g_sessions.find(session_id);
    if (it == g_sessions.end()) {
        UniValue error(UniValue::VOBJ);
        error.pushKV("error", "Unknown session: " + session_id);
        return error;
    }

    auto session = it->second;

    // Mock: return empty missed_messages array
    UniValue missed_messages(UniValue::VARR);

    int current_seq = std::max(session->messages_sent, session->messages_received);

    UniValue result(UniValue::VOBJ);
    result.pushKV("missed_messages", missed_messages);
    result.pushKV("current_seq", current_seq);
    result.pushKV("buffer_size", 0);
    result.pushKV("recoverable", true);

    return result;
}

// ============================================================================
// BULLETIN BOARD / DISCUSSION HANDLERS
// ============================================================================

UniValue HandleInitBB(const UniValue& params) {
    g_bb_initialized = true;

    UniValue result(UniValue::VOBJ);
    result.pushKV("success", true);
    result.pushKV("pubkey", MOCK_NOSTR_PUBKEY);

    UniValue relays(UniValue::VARR);
    relays.push_back("wss://relay.damus.io");
    result.pushKV("relays", relays);
    result.pushKV("network", MOCK_NETWORK);
    return result;
}

UniValue HandleBBGetPubkey(const UniValue& params) {
    if (!g_bb_initialized) {
        UniValue error(UniValue::VOBJ);
        error.pushKV("error", "Bulletin board not initialized (call init_bb first)");
        return error;
    }
    UniValue result(UniValue::VOBJ);
    result.pushKV("pubkey", MOCK_NOSTR_PUBKEY);
    result.pushKV("network", MOCK_NETWORK);
    return result;
}

static bool IsValidScopeType(const std::string& scope_type) {
    return scope_type == "model_prealert" || scope_type == "model_challenge";
}

static bool IsValidScopeId(const std::string& scope_id) {
    if (scope_id.size() != 64) return false;
    for (char c : scope_id) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
            return false;
    }
    return true;
}

UniValue HandleDiscussionPost(const UniValue& params) {
    if (!g_bb_initialized) {
        UniValue error(UniValue::VOBJ);
        error.pushKV("error", "Bulletin board not initialized (call init_bb first)");
        return error;
    }

    std::string scope_type = params.exists("scope_type") ? params["scope_type"].get_str() : "";
    if (!IsValidScopeType(scope_type)) {
        UniValue error(UniValue::VOBJ);
        error.pushKV("error", "Unsupported discussion scope_type: " + scope_type);
        return error;
    }

    std::string scope_id = params.exists("scope_id") ? params["scope_id"].get_str() : "";
    if (!IsValidScopeId(scope_id)) {
        UniValue error(UniValue::VOBJ);
        error.pushKV("error", "scope_id must be a 64-character hex hash");
        return error;
    }

    std::string content = params.exists("content") ? params["content"].get_str() : "";
    std::string network = params.exists("network") ? params["network"].get_str() : MOCK_NETWORK;

    // Generate a mock post ID
    std::string post_id = "mock_event_" + std::to_string(g_discussion_posts.size() + 1);
    int64_t now = std::time(nullptr);

    MockDiscussionPost post;
    post.post_id = post_id;
    post.scope_type = scope_type;
    post.scope_id = scope_id;
    post.network = network;
    post.author_pubkey = MOCK_NOSTR_PUBKEY;
    post.content = content;
    post.created_at = now;
    if (params.exists("proof") && params["proof"].isObject()) {
        post.proof = params["proof"];
    }

    g_discussion_posts.push_back(post);

    // Return in the format the bridge uses: { success, post: { ... } }
    UniValue post_obj(UniValue::VOBJ);
    post_obj.pushKV("post_id", post_id);
    post_obj.pushKV("scope_type", scope_type);
    post_obj.pushKV("scope_id", scope_id);
    post_obj.pushKV("network", network);
    post_obj.pushKV("author_pubkey", MOCK_NOSTR_PUBKEY);
    post_obj.pushKV("content", content);
    post_obj.pushKV("created_at", now);
    if (params.exists("proof") && params["proof"].isObject()) {
        post_obj.pushKV("proof", params["proof"]);
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("success", true);
    result.pushKV("post", post_obj);
    return result;
}

UniValue HandleDiscussionList(const UniValue& params) {
    if (!g_bb_initialized) {
        UniValue error(UniValue::VOBJ);
        error.pushKV("error", "Bulletin board not initialized (call init_bb first)");
        return error;
    }

    std::string scope_type = params.exists("scope_type") ? params["scope_type"].get_str() : "";
    if (!scope_type.empty() && !IsValidScopeType(scope_type)) {
        UniValue error(UniValue::VOBJ);
        error.pushKV("error", "Unsupported discussion scope_type: " + scope_type);
        return error;
    }

    std::string scope_id = params.exists("scope_id") ? params["scope_id"].get_str() : "";
    if (!scope_id.empty() && !IsValidScopeId(scope_id)) {
        UniValue error(UniValue::VOBJ);
        error.pushKV("error", "scope_id must be a 64-character hex hash");
        return error;
    }
    int limit = params.exists("limit") ? params["limit"].getInt<int>() : 100;

    UniValue posts(UniValue::VARR);
    int count = 0;
    for (const auto& p : g_discussion_posts) {
        if (count >= limit) break;
        if (!scope_type.empty() && p.scope_type != scope_type) continue;
        if (!scope_id.empty() && p.scope_id != scope_id) continue;

        UniValue post_obj(UniValue::VOBJ);
        post_obj.pushKV("post_id", p.post_id);
        post_obj.pushKV("scope_type", p.scope_type);
        post_obj.pushKV("scope_id", p.scope_id);
        post_obj.pushKV("network", p.network);
        post_obj.pushKV("author_pubkey", p.author_pubkey);
        post_obj.pushKV("content", p.content);
        post_obj.pushKV("created_at", p.created_at);
        if (!p.proof.isNull()) {
            post_obj.pushKV("proof", p.proof);
        }
        posts.push_back(post_obj);
        count++;
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("posts", posts);
    return result;
}

int main(int argc, char* argv[]) {
    // Parse command-line flags
    for (int i = 1; i < argc; i++) {
        std::string arg(argv[i]);
        if (arg == "--fail-ping") {
            g_fail_ping = true;
        } else if (arg == "--bad-json") {
            g_bad_json = true;
        } else if (arg == "--error-all") {
            g_error_all = true;
        } else if (arg == "--malformed-response") {
            g_malformed_response = true;
        }
    }

    // PERSISTENT MODE: Keep reading commands from stdin until EOF
    // This matches the Rust bridge behavior and ensures sessions persist
    // across multiple RPC calls within the same subprocess.
    while (true) {
        try {
            // Read JSON command from stdin (HWI-style protocol: one line)
            std::string line;
            if (!std::getline(std::cin, line)) {
                // EOF reached - normal termination
                return 0;
            }

            // Handle test flags that produce invalid responses
            if (g_bad_json) {
                std::cout << "{ this is not valid json" << std::endl;
                std::cout.flush();
                continue;
            }

            if (g_malformed_response) {
                std::cout << "not json at all!" << std::endl;
                std::cout.flush();
                continue;
            }

            // Parse JSON request
            UniValue request;
            if (!request.read(line)) {
                UniValue error(UniValue::VOBJ);
                error.pushKV("error", "Invalid JSON");
                std::cout << error.write() << std::endl;
                std::cout.flush();
                continue;
            }

            if (!request.isObject()) {
                UniValue error(UniValue::VOBJ);
                error.pushKV("error", "Request must be JSON object");
                std::cout << error.write() << std::endl;
                std::cout.flush();
                continue;
            }

            std::string command = request.exists("command") ? request["command"].get_str() : "";
            UniValue params = request.exists("params") ? request["params"] : UniValue(UniValue::VOBJ);

            // Dispatch to handler
            UniValue response;
            if (command == "version") {
                response = HandleVersion(params);
            } else if (command == "ping") {
                response = HandlePing(params);
            } else if (command == "init") {
                response = HandleInit(params);
            } else if (command == "join") {
                response = HandleJoin(params);
            } else if (command == "handshake_auto") {
                response = HandleHandshakeAuto(params);
            } else if (command == "send") {
                response = HandleSend(params);
            } else if (command == "recv") {
                response = HandleRecv(params);
            } else if (command == "status") {
                response = HandleStatus(params);
            } else if (command == "close") {
                response = HandleClose(params);
            } else if (command == "metrics") {
                response = HandleMetrics(params);
            } else if (command == "attest") {
                response = HandleAttest(params);
            } else if (command == "resume") {
                response = HandleResume(params);
            } else if (command == "init_bb") {
                response = HandleInitBB(params);
            } else if (command == "bb_get_pubkey") {
                response = HandleBBGetPubkey(params);
            } else if (command == "discussion_post" || command == "post_discussion") {
                response = HandleDiscussionPost(params);
            } else if (command == "discussion_list" || command == "list_discussion") {
                response = HandleDiscussionList(params);
            } else {
                UniValue error(UniValue::VOBJ);
                error.pushKV("error", "Unknown command: " + command);
                std::cout << error.write() << std::endl;
                std::cout.flush();
                continue;
            }

            // Write response to stdout and flush (critical for stdio protocol)
            std::cout << response.write() << std::endl;
            std::cout.flush();

        } catch (const std::exception& e) {
            UniValue error(UniValue::VOBJ);
            error.pushKV("error", std::string("Exception: ") + e.what());
            std::cout << error.write() << std::endl;
            std::cout.flush();
            // Continue processing commands even after errors
        }
    }

    return 0;
}
