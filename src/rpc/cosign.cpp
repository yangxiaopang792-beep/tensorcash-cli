// Copyright (c) 2025 The TensorCash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <common/args.h>
#include <common/signmessage.h>
#include <common/system.h>
#include <chainparams.h>
#include <rpc/proof_verify.h>
#include <compat/compat.h>
#include <rpc/protocol.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <tinyformat.h>
#include <logging.h>
#include <util/fs.h>
#include <util/subprocess.h>
#include <util/strencodings.h>
#include <util/time.h>
#include <algorithm>
#include <cstdlib>
#include <random.h>
#include <sync.h>

#include <univalue.h>

#include <climits>
#include <chrono>
#include <cstdio>
#include <cerrno>
#include <cstring>
#include <psbt.h>
#include <serialize.h>
#include <streams.h>
#include <script/script.h>
#ifndef WIN32
#include <poll.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>
#ifdef __APPLE__
#include <mach-o/dyld.h>
#endif
#else
#include <windows.h>
#include <io.h>
#endif
#include <memory>
#include <string>
#include <map>
#include <vector>
#include <optional>
#include <thread>
#include <limits>

// Forward declarations
namespace cosign {

static fs::path GetExecutablePathForCosign()
{
#ifdef __APPLE__
    uint32_t size = 0;
    _NSGetExecutablePath(nullptr, &size);
    std::string buf(size, '\0');
    if (_NSGetExecutablePath(buf.data(), &size) == 0) {
        return fs::weakly_canonical(fs::path(buf.c_str()));
    }
#elif defined(__linux__)
    std::vector<char> buf(PATH_MAX);
    ssize_t len = readlink("/proc/self/exe", buf.data(), buf.size() - 1);
    if (len > 0) {
        buf[len] = '\0';
        return fs::weakly_canonical(fs::path(buf.data()));
    }
#elif defined(WIN32)
    char buf[MAX_PATH];
    DWORD len = GetModuleFileNameA(nullptr, buf, MAX_PATH);
    if (len > 0 && len < MAX_PATH) {
        return fs::path(buf);
    }
#endif
    return fs::path();
}

static std::string ResolveBundledCosignBridge()
{
    const fs::path exe_path = GetExecutablePathForCosign();
    if (exe_path.empty()) return {};

    const fs::path exe_dir = exe_path.parent_path();
    const std::vector<fs::path> candidates = {
        exe_dir / "cosign-bridge",
        exe_dir / "cosign-bridge.exe",
        exe_dir.parent_path() / "MacOS" / "cosign-bridge" // bundle structure on macOS
    };

    for (const auto& candidate : candidates) {
        if (!candidate.empty() && fs::exists(candidate)) {
            return fs::PathToString(fs::weakly_canonical(candidate));
        }
    }
    return {};
}

/** Cosign session state (in-memory only, per spec) */
struct SessionState {
    std::string session_id;
    std::string invite_code;
    std::string sas;
    std::string transport;
    int64_t created_at;
    int64_t ttl_sec;
    int messages_sent{0};
    int messages_received{0};
    bool peer_verified{false};
    std::string state; // "open", "closing", "closed", "error"
    bool handshake_complete{false};
    std::string sas_numeric;

    SessionState(const std::string& id, int64_t ttl)
        : session_id(id), created_at(GetTime()), ttl_sec(ttl), state("open") {}

    bool IsExpired() const {
        return (GetTime() - created_at) > ttl_sec;
    }
};

enum class BridgeHealth {
    UNKNOWN,       // Not yet checked
    HEALTHY,       // Bridge responding normally
    RECOVERABLE,   // Exit code 11 (transport down), can retry
    FAILED,        // Exit code 10/12 (bad config/crypto init), no auto-restart
    DEAD           // Exceeded max retries
};

/** Bridge process manager (HWI-style stdio communication) */
class BridgeManager {
private:
    static constexpr int BRIDGE_RESPONSE_TIMEOUT_MS = 30000;
    static constexpr int BRIDGE_POLL_SLICE_MS = 500;
    static constexpr int BRIDGE_SHUTDOWN_TIMEOUT_MS = 2000;
    static constexpr int BRIDGE_KILL_TIMEOUT_MS = 1000;

    mutable Mutex m_mutex;
    std::map<std::string, std::shared_ptr<SessionState>> m_sessions GUARDED_BY(m_mutex);
    mutable std::string m_bridge_path;
    mutable bool m_path_initialized{false};
    int m_restart_count{0};
    int m_max_restarts{5};
    BridgeHealth m_health_state{BridgeHealth::UNKNOWN};
    int64_t m_last_successful_ping{0};
    int64_t m_last_restart_attempt{0};
    int m_consecutive_failures{0};
    std::unique_ptr<subprocess::Popen> m_bridge_process GUARDED_BY(m_mutex);
    // Cached cosign.init_bb parameters from the most recent successful init.
    // When the bridge subprocess is respawned (transport error, timeout, etc.)
    // its in-memory bb_manager is lost; we replay init_bb with these params
    // on the next command so callers don't see "Bulletin board not initialized".
    UniValue m_last_init_bb_params GUARDED_BY(m_mutex){UniValue::VOBJ};
    bool m_have_init_bb_params GUARDED_BY(m_mutex){false};
    bool m_needs_init_bb_replay GUARDED_BY(m_mutex){false};
    // COSIGN_TOR_SOCKS value the current bridge child was spawned with. The
    // child captures its environment at exec() and cannot observe later
    // qputenv() changes, so if it was spawned before TorManager set the Tor
    // env we must respawn it once the value appears. Empty == spawned without
    // a Tor transport.
    std::string m_tor_socks_at_spawn GUARDED_BY(m_mutex);

    void EnsureInitialized() const {
        if (!m_path_initialized) {
            m_bridge_path = gArgs.GetArg("-cosignbridge", "");
            // Support @executable_path token and missing config by falling back to bundled bridge
            auto exe_path = GetExecutablePathForCosign();
            if (!m_bridge_path.empty() && m_bridge_path.rfind("@executable_path", 0) == 0 && !exe_path.empty()) {
                // Strip the "@executable_path" prefix and any leading separator
                // so fs::path / operator doesn't treat it as an absolute path.
                std::string suffix = m_bridge_path.substr(std::string("@executable_path").size());
                while (!suffix.empty() && (suffix[0] == '/' || suffix[0] == '\\')) {
                    suffix.erase(suffix.begin());
                }
                fs::path resolved = exe_path.parent_path() / suffix;
                m_bridge_path = fs::PathToString(fs::weakly_canonical(resolved));
            }
            if (m_bridge_path.empty()) {
                const std::string fallback = ResolveBundledCosignBridge();
                if (!fallback.empty()) {
                    m_bridge_path = fallback;
                }
            }
            m_path_initialized = true;
        }
    }

    void EnsureBridgeProcess() EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    void StopBridgeProcess() EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    void WriteBridgeMessage(const std::string& payload) EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    std::string ReadBridgeMessage(int timeout_ms) EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    bool WaitForBridgeReadable(int timeout_ms) EXCLUSIVE_LOCKS_REQUIRED(m_mutex);

public:
    BridgeManager() = default;
    ~BridgeManager() LOCKS_EXCLUDED(m_mutex) { LOCK(m_mutex); StopBridgeProcess(); }

    bool IsEnabled() const {
        EnsureInitialized();
        return !m_bridge_path.empty();
    }

    std::string GetBridgePath() const {
        EnsureInitialized();
        return m_bridge_path;
    }

    /** Send command to bridge and receive response (persistent stdio protocol) */
    UniValue SendBridgeCommand(const std::string& command, const UniValue& params) LOCKS_EXCLUDED(m_mutex) {
        LOCK(m_mutex);
        if (!IsEnabled()) {
            throw JSONRPCError(RPC_MISC_ERROR, "COSIGN_DISABLED: Bridge not configured (set -cosignbridge)");
        }

        // Build JSON-RPC request for bridge (HWI-style protocol)
        UniValue request(UniValue::VOBJ);
        request.pushKV("command", command);
        request.pushKV("params", params);

        const std::string request_json = request.write();

        // Default timeout for bridge responses
        int response_timeout_ms = BRIDGE_RESPONSE_TIMEOUT_MS;

        // For init with Tor transport, allow time for ADD_ONION + 30s descriptor wait
        if (command == "init" && params.isObject() && params.exists("transport") &&
            params["transport"].get_str() == "tor") {
            response_timeout_ms = std::max<int>(BRIDGE_RESPONSE_TIMEOUT_MS, 60000);
        }

        if (command == "handshake_auto") {
            // For Tor transports, give the bridge longer to accept hidden-service connections
            std::string session_id;
            if (params.isObject() && params.exists("session_id")) {
                session_id = params["session_id"].get_str();
            } else if (params.isArray() && params.size() > 0 && params[0].isStr()) {
                session_id = params[0].get_str();
            }

            if (!session_id.empty()) {
                auto it = m_sessions.find(session_id);
                if (it != m_sessions.end() && it->second && it->second->transport == "tor") {
                    response_timeout_ms = std::max<int>(BRIDGE_RESPONSE_TIMEOUT_MS, 90000);
                }
            }
        }

        int attempts = 0;
        while (attempts < 2) {
            attempts++;
            try {
                EnsureBridgeProcess();

                // After a bridge respawn the new subprocess starts with an empty
                // bulletin-board manager. Transparently replay the most recent
                // successful cosign.init_bb so callers don't see "Bulletin board
                // not initialized" on the next command. The bridge's init_bb is
                // idempotent for the same network (cosign-bridge stdio.rs:427-444).
                if (m_needs_init_bb_replay && m_have_init_bb_params && command != "init_bb") {
                    UniValue init_req(UniValue::VOBJ);
                    init_req.pushKV("command", "init_bb");
                    init_req.pushKV("params", m_last_init_bb_params);
                    const std::string init_json = init_req.write();

                    WriteBridgeMessage(init_json);
                    while (true) {
                        std::string init_line = ReadBridgeMessage(BRIDGE_RESPONSE_TIMEOUT_MS);
                        if (init_line.empty()) {
                            continue;
                        }
                        UniValue init_resp;
                        if (init_resp.read(init_line)) {
                            if (init_resp.isObject() && init_resp.exists("error")) {
                                LogPrintf("cosign-bridge: init_bb replay after respawn failed: %s\n",
                                          init_resp["error"].write().c_str());
                                // Leave the flag set; the next attempt may succeed.
                                // Fall through and let the actual command run — if it
                                // requires bb_manager it will surface a clean error.
                            } else {
                                LogPrintf("cosign-bridge: init_bb replayed successfully after respawn\n");
                                m_needs_init_bb_replay = false;
                            }
                            break;
                        }
                        LogPrintf("cosign-bridge: %s\n", init_line);
                    }
                }

                WriteBridgeMessage(request_json);

                UniValue response;
                while (true) {
                    std::string line = ReadBridgeMessage(response_timeout_ms);
                    if (line.empty()) {
                        continue;
                    }
                    if (response.read(line)) {
                        break;
                    }
                    LogPrintf("cosign-bridge: %s\n", line);
                }

                if (response.isObject() && response.exists("error")) {
                    std::string error_msg = response["error"].isStr() ? response["error"].get_str() : "Unknown bridge error";
                    m_consecutive_failures++;
                    throw JSONRPCError(RPC_MISC_ERROR, "Bridge error: " + error_msg);
                }

                // Cache init_bb params so we can replay them after a future respawn.
                if (command == "init_bb") {
                    m_last_init_bb_params = params;
                    m_have_init_bb_params = true;
                    m_needs_init_bb_replay = false;
                }

                m_consecutive_failures = 0;
                m_restart_count = 0;
                return response;
            } catch (const std::exception& e) {
                m_consecutive_failures++;
                m_restart_count++;
                StopBridgeProcess();
                LogPrintf("cosign-bridge transport error: %s\n", e.what());

                if (attempts >= 2 || m_restart_count > m_max_restarts) {
                    throw JSONRPCError(RPC_MISC_ERROR,
                                       strprintf("Bridge communication failed after %d attempt(s): %s",
                                                 attempts, e.what()));
                }
            }
        }

        throw JSONRPCError(RPC_MISC_ERROR, "Bridge communication failed");
    }

    /** Register a new session */
    void RegisterSession(std::shared_ptr<SessionState> session) LOCKS_EXCLUDED(m_mutex) {
        LOCK(m_mutex);
        m_sessions[session->session_id] = session;
    }

    /** Get session by ID */
    std::shared_ptr<SessionState> GetSession(const std::string& session_id) LOCKS_EXCLUDED(m_mutex) {
        LOCK(m_mutex);
        auto it = m_sessions.find(session_id);
        if (it == m_sessions.end()) {
            return nullptr;
        }
        return it->second;
    }

    /** Remove session */
    void RemoveSession(const std::string& session_id) LOCKS_EXCLUDED(m_mutex) {
        LOCK(m_mutex);
        m_sessions.erase(session_id);
    }

    /** Prune expired sessions (called periodically) */
    void PruneExpiredSessions() LOCKS_EXCLUDED(m_mutex) {
        LOCK(m_mutex);
        std::vector<std::string> to_remove;
        for (const auto& [id, session] : m_sessions) {
            if (session->IsExpired()) {
                to_remove.push_back(id);
            }
        }
        for (const auto& id : to_remove) {
            m_sessions.erase(id);
        }
    }

    /** Get all sessions (for metrics) */
    size_t GetActiveSessionCount() LOCKS_EXCLUDED(m_mutex) {
        LOCK(m_mutex);
        return m_sessions.size();
    }

    /** Get bridge health state */
    BridgeHealth GetHealthState() const LOCKS_EXCLUDED(m_mutex) {
        LOCK(m_mutex);
        return m_health_state;
    }

    /** Perform heartbeat check (ping bridge) */
    bool Heartbeat() LOCKS_EXCLUDED(m_mutex) {
        if (!IsEnabled()) {
            return false;
        }

        try {
            UniValue params(UniValue::VOBJ);
            UniValue response = SendBridgeCommand("ping", params);

            LOCK(m_mutex);
            m_last_successful_ping = GetTime();
            m_health_state = BridgeHealth::HEALTHY;
            m_consecutive_failures = 0;
            m_restart_count = 0; // Reset restart count on successful ping

            return true;
        } catch (const UniValue& obj_error) {
            LOCK(m_mutex);
            m_consecutive_failures++;

            const std::string error_text = obj_error.write();
            LogPrintf("cosign-bridge heartbeat RPC error: %s\n", error_text);

            if (m_consecutive_failures >= 3) {
                if (m_restart_count >= m_max_restarts) {
                    m_health_state = BridgeHealth::DEAD;
                } else {
                    m_health_state = BridgeHealth::RECOVERABLE;
                }
            }

            return false;
        } catch (const std::exception& e) {
            LOCK(m_mutex);
            m_consecutive_failures++;
            LogPrintf("cosign-bridge heartbeat transport error: %s\n", e.what());

            if (m_consecutive_failures >= 3) {
                if (m_restart_count >= m_max_restarts) {
                    m_health_state = BridgeHealth::DEAD;
                } else {
                    m_health_state = BridgeHealth::RECOVERABLE;
                }
            }

            return false;
        }
    }

    /** Get health status for metrics */
    UniValue GetHealthMetrics() const LOCKS_EXCLUDED(m_mutex) {
        LOCK(m_mutex);

        UniValue result(UniValue::VOBJ);

        std::string health_str;
        switch (m_health_state) {
            case BridgeHealth::UNKNOWN: health_str = "unknown"; break;
            case BridgeHealth::HEALTHY: health_str = "healthy"; break;
            case BridgeHealth::RECOVERABLE: health_str = "recoverable"; break;
            case BridgeHealth::FAILED: health_str = "failed"; break;
            case BridgeHealth::DEAD: health_str = "dead"; break;
        }

        result.pushKV("health_state", health_str);
        result.pushKV("restart_count", m_restart_count);
        result.pushKV("max_restarts", m_max_restarts);
        result.pushKV("consecutive_failures", m_consecutive_failures);
        result.pushKV("last_successful_ping", m_last_successful_ping);
        result.pushKV("seconds_since_last_ping", m_last_successful_ping > 0 ? GetTime() - m_last_successful_ping : -1);

        return result;
    }
};

void BridgeManager::EnsureBridgeProcess() {
    // The bridge child inherits its environment at exec() and cannot see later
    // changes. TorManager exports COSIGN_TOR_SOCKS only once Tor is ready, which
    // may be AFTER a cosign RPC has already lazily spawned the bridge. If the
    // value has since appeared (or changed), respawn so the new child gets the
    // Tor transport; init_bb is replayed afterward via m_needs_init_bb_replay.
    const char* tor_socks_c = std::getenv("COSIGN_TOR_SOCKS");
    const std::string tor_socks = tor_socks_c ? tor_socks_c : "";
    if (m_bridge_process) {
        if (tor_socks == m_tor_socks_at_spawn) {
            return;
        }
        LogPrintf("cosign-bridge: COSIGN_TOR_SOCKS changed (\"%s\" -> \"%s\"); respawning bridge to pick up Tor transport\n",
                  m_tor_socks_at_spawn, tor_socks);
        StopBridgeProcess();
        if (m_have_init_bb_params) m_needs_init_bb_replay = true;
    }

    std::vector<std::string> args{GetBridgePath()};
    try {
        m_bridge_process = std::make_unique<subprocess::Popen>(
            args,
            subprocess::input{subprocess::PIPE},
            subprocess::output{subprocess::PIPE},
            subprocess::error{subprocess::STDOUT},
            subprocess::close_fds{true});
        m_tor_socks_at_spawn = tor_socks;
        m_last_restart_attempt = GetTime();
    } catch (const std::exception& e) {
        throw std::runtime_error(strprintf("Failed to start cosign bridge: %s", e.what()));
    }
}

void BridgeManager::StopBridgeProcess() {
    if (!m_bridge_process) {
        return;
    }

#ifndef WIN32
    pid_t child_pid = m_bridge_process->pid();
#endif

    try {
        m_bridge_process->close_stdin();
        m_bridge_process->close_stdout();
        m_bridge_process->close_stderr();
    } catch (...) {
    }

#ifndef WIN32
    if (child_pid > 0) {
        int status = 0;
        const auto wait_with_timeout = [&](int timeout_ms) -> bool {
            const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
            while (true) {
                int ret = waitpid(child_pid, &status, WNOHANG);
                if (ret == child_pid) {
                    return true;
                }
                if (ret == 0) {
                    if (std::chrono::steady_clock::now() >= deadline) {
                        return false;
                    }
                    UninterruptibleSleep(std::chrono::milliseconds{10});
                    continue;
                }
                if (errno == EINTR) {
                    continue;
                }
                return false;
            }
        };

        if (!wait_with_timeout(BRIDGE_SHUTDOWN_TIMEOUT_MS)) {
            kill(child_pid, SIGTERM);
            if (!wait_with_timeout(BRIDGE_KILL_TIMEOUT_MS)) {
                kill(child_pid, SIGKILL);
                waitpid(child_pid, &status, 0);
            }
        }
    }
#else
    try {
        m_bridge_process->wait();
    } catch (...) {
    }
#endif

    m_bridge_process.reset();

    if (!m_sessions.empty()) {
        LogPrintf("cosign-bridge: dropping %u session(s) due to bridge stop/restart (ephemeral sessions)\n", static_cast<unsigned>(m_sessions.size()));
        m_sessions.clear();
    }

    // Mark that the new bridge subprocess will start with no bb_manager.
    // SendBridgeCommand replays the cached cosign.init_bb on the next command
    // so callers don't see "Bulletin board not initialized" after a respawn.
    if (m_have_init_bb_params) {
        m_needs_init_bb_replay = true;
    }
}

void BridgeManager::WriteBridgeMessage(const std::string& payload) {
    if (!m_bridge_process) {
        throw std::runtime_error("Bridge process not running");
    }

    FILE* bridge_stdin = m_bridge_process->stdin_stream();
    if (bridge_stdin == nullptr) {
        throw std::runtime_error("Bridge stdin unavailable");
    }

    if (!payload.empty()) {
        const size_t written = std::fwrite(payload.data(), 1, payload.size(), bridge_stdin);
        if (written != payload.size()) {
            throw std::runtime_error(strprintf("Failed to write to bridge stdin: %s", std::strerror(errno)));
        }
    }

    if (std::fputc('\n', bridge_stdin) == EOF) {
        throw std::runtime_error(strprintf("Failed to write newline to bridge stdin: %s", std::strerror(errno)));
    }

    if (std::fflush(bridge_stdin) != 0) {
        throw std::runtime_error(strprintf("Failed to flush bridge stdin: %s", std::strerror(errno)));
    }
}

std::string BridgeManager::ReadBridgeMessage(int timeout_ms) {
    if (!m_bridge_process) {
        throw std::runtime_error("Bridge process not running");
    }

    FILE* bridge_stdout = m_bridge_process->stdout_stream();
    if (bridge_stdout == nullptr) {
        throw std::runtime_error("Bridge stdout unavailable");
    }

    std::string line;
    char buffer[512];
    const bool finite_timeout = timeout_ms >= 0;
    using SteadyTimePoint = std::chrono::time_point<std::chrono::steady_clock, std::chrono::milliseconds>;
    std::optional<SteadyTimePoint> deadline = finite_timeout
        ? std::optional<SteadyTimePoint>(std::chrono::time_point_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now()) + std::chrono::milliseconds(timeout_ms))
        : std::nullopt;
#ifdef WIN32
    (void)deadline;
#endif

    while (true) {
        if (finite_timeout && std::chrono::time_point_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now()) >= *deadline) {
            throw std::runtime_error("Bridge response timeout");
        }

        int wait_slice = BRIDGE_POLL_SLICE_MS;
        if (finite_timeout) {
            auto now = std::chrono::time_point_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now());
            int remaining = static_cast<int>((*deadline - now).count());
            remaining = std::max(1, remaining);
            wait_slice = std::min(BRIDGE_POLL_SLICE_MS, remaining);
        }

        if (!WaitForBridgeReadable(wait_slice)) {
            continue;
        }

        if (!std::fgets(buffer, sizeof(buffer), bridge_stdout)) {
            if (std::feof(bridge_stdout)) {
                throw std::runtime_error("Bridge closed stdout");
            }
            if (std::ferror(bridge_stdout)) {
                throw std::runtime_error(strprintf("Failed to read from bridge stdout: %s", std::strerror(errno)));
            }
            continue;
        }

        line.append(buffer);
        if (!line.empty() && line.back() == '\n') {
            while (!line.empty() && (line.back() == '\n' || line.back() == '\r')) {
                line.pop_back();
            }
            break;
        }
    }

    return line;
}

bool BridgeManager::WaitForBridgeReadable(int timeout_ms) {
#ifdef WIN32
    if (!m_bridge_process) {
        throw std::runtime_error("Bridge process not running");
    }

    FILE* bridge_stdout = m_bridge_process->stdout_stream();
    if (bridge_stdout == nullptr) {
        throw std::runtime_error("Bridge stdout unavailable");
    }

    HANDLE h = reinterpret_cast<HANDLE>(_get_osfhandle(_fileno(bridge_stdout)));
    if (h == INVALID_HANDLE_VALUE) {
        throw std::runtime_error("Invalid stdout handle for bridge");
    }

    const bool finite_timeout = timeout_ms >= 0;
    const auto deadline = finite_timeout
        ? std::optional<std::chrono::steady_clock::time_point>(
              std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms))
        : std::nullopt;

    while (true) {
        DWORD bytes_available = 0;
        if (PeekNamedPipe(h, nullptr, 0, nullptr, &bytes_available, nullptr)) {
            if (bytes_available > 0) {
                return true;
            }
        } else {
            const DWORD err = GetLastError();
            if (err == ERROR_BROKEN_PIPE || err == ERROR_PIPE_NOT_CONNECTED) {
                throw std::runtime_error("Bridge closed stdout");
            }
            throw std::runtime_error(strprintf("PeekNamedPipe failed for bridge stdout: %lu",
                                               static_cast<unsigned long>(err)));
        }

        if (finite_timeout && std::chrono::steady_clock::now() >= *deadline) {
            return false;
        }

        const auto sleep_for = finite_timeout
            ? std::min<std::chrono::milliseconds>(
                  std::chrono::milliseconds{10},
                  std::max(std::chrono::milliseconds{1},
                           std::chrono::duration_cast<std::chrono::milliseconds>(*deadline - std::chrono::steady_clock::now())))
            : std::chrono::milliseconds{10};
        UninterruptibleSleep(sleep_for);
    }
#else
    if (!m_bridge_process) {
        throw std::runtime_error("Bridge process not running");
    }

    int fd = m_bridge_process->stdout_fd();
    if (fd < 0) {
        throw std::runtime_error("Bridge stdout unavailable");
    }

    while (true) {
        struct pollfd pfd;
        pfd.fd = fd;
        pfd.events = POLLIN;
        pfd.revents = 0;

        int ret = poll(&pfd, 1, timeout_ms);
        if (ret > 0) {
            if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
                throw std::runtime_error("Bridge stdout reported error");
            }
            return (pfd.revents & POLLIN) != 0;
        }
        if (ret == 0) {
            return false;
        }
        if (errno == EINTR) {
            continue;
        }
        throw std::runtime_error(strprintf("poll() failed: %s", std::strerror(errno)));
    }
#endif
}

// Global bridge manager instance
static BridgeManager g_bridge_manager;

} // namespace cosign

// Exported accessors for wallet-layer code (e.g. EthHtlcBackend)
UniValue SendCosignBridgeCommand(const std::string& command, const UniValue& params)
{
    return cosign::g_bridge_manager.SendBridgeCommand(command, params);
}

bool IsCosignBridgeEnabled()
{
    return cosign::g_bridge_manager.IsEnabled();
}

// ============================================================================
// RPC HANDLERS
// ============================================================================

static RPCHelpMan cosign_version()
{
    return RPCHelpMan{"cosign.version",
        "Get cosign bridge version and capabilities.",
        {},
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::NUM, "api_version", "Bridge API version"},
                {RPCResult::Type::STR, "git_commit", "Git commit hash"},
                {RPCResult::Type::ARR, "build_flags", "Enabled features",
                    {
                        {RPCResult::Type::STR, "", "Feature name (e.g., 'noise', 'spake2')"},
                    }
                },
                {RPCResult::Type::STR, "bridge_version", "Bridge binary version"},
            }
        },
        RPCExamples{
            HelpExampleCli("cosign.version", "")
            + HelpExampleRpc("cosign.version", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            if (!cosign::g_bridge_manager.IsEnabled()) {
                throw JSONRPCError(RPC_MISC_ERROR, "COSIGN_DISABLED: Bridge not configured (set -cosignbridge)");
            }

            // Query bridge for actual version info
            UniValue params(UniValue::VOBJ);
            UniValue response = cosign::g_bridge_manager.SendBridgeCommand("version", params);

            // Bridge should return: {api_version, git_commit, build_flags, bridge_version}
            // If bridge doesn't follow protocol, return sensible defaults
            if (!response.isObject()) {
                UniValue fallback(UniValue::VOBJ);
                fallback.pushKV("api_version", 1);
                fallback.pushKV("git_commit", "unknown");
                fallback.pushKV("build_flags", UniValue(UniValue::VARR));
                fallback.pushKV("bridge_version", "unknown");
                return fallback;
            }

            return response;
        }
    };
}

static RPCHelpMan cosign_ping()
{
    return RPCHelpMan{"cosign.ping",
        "Ping the cosign bridge to check if it's alive.",
        {},
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::BOOL, "bridge_alive", "Whether the bridge responded"},
                {RPCResult::Type::STR, "version", "Bridge version"},
                {RPCResult::Type::ARR, "transports", "Available transports",
                    {
                        {RPCResult::Type::STR, "", "Transport name"},
                    }
                },
                {RPCResult::Type::NUM, "uptime_sec", "Bridge uptime in seconds"},
                {RPCResult::Type::ARR, "capabilities", "Bridge capabilities",
                    {
                        {RPCResult::Type::STR, "", "Capability name"},
                    }
                },
            }
        },
        RPCExamples{
            HelpExampleCli("cosign.ping", "")
            + HelpExampleRpc("cosign.ping", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            if (!cosign::g_bridge_manager.IsEnabled()) {
                throw JSONRPCError(RPC_MISC_ERROR, "COSIGN_DISABLED: Bridge not configured");
            }

            // Use Heartbeat() which pings bridge AND updates health metrics
            bool ping_success = cosign::g_bridge_manager.Heartbeat();

            if (ping_success) {
                // Ping succeeded - query bridge for full response
                UniValue params(UniValue::VOBJ);
                try {
                    UniValue response = cosign::g_bridge_manager.SendBridgeCommand("ping", params);

                    // Bridge should return: {bridge_alive, version, transports, uptime_sec, capabilities}
                    if (!response.isObject()) {
                        UniValue fallback(UniValue::VOBJ);
                        fallback.pushKV("bridge_alive", true);
                        fallback.pushKV("version", "unknown");
                        fallback.pushKV("transports", UniValue(UniValue::VARR));
                        fallback.pushKV("uptime_sec", 0);
                        fallback.pushKV("capabilities", UniValue(UniValue::VARR));
                        return fallback;
                    }

                    return response;
                } catch (const std::exception& e) {
                    // Bridge failed - return error
                    UniValue result(UniValue::VOBJ);
                    result.pushKV("bridge_alive", false);
                    result.pushKV("error", std::string(e.what()));
                    return result;
                }
            } else {
                // Heartbeat failed - return error
                UniValue result(UniValue::VOBJ);
                result.pushKV("bridge_alive", false);
                result.pushKV("error", "Bridge heartbeat failed");
                return result;
            }
        }
    };
}

static RPCHelpMan cosign_init()
{
    return RPCHelpMan{"cosign.init",
        "Initialize a new cosign session and return a magic link/code.",
        {
            {"psbt", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Base64-encoded PSBT (optional)"},
            {"context", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Human-readable context label"},
            {"transport", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Transport: auto|websocket|nostr|webrtc|tor|ur (default: auto)"},
            {"ttl", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Session TTL in seconds (default: 1800 = 30 min)"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "session_id", "32-byte session identifier"},
                {RPCResult::Type::STR, "invite_link", "Magic link (cosign:?r=<room>&t=<hint>#c=<code>)"},
                {RPCResult::Type::STR, "invite_code", "5-word mnemonic code"},
                {RPCResult::Type::STR, "qr_data", "QR-friendly URI"},
                {RPCResult::Type::STR, "qr_error_correction", "QR error correction level (M or Q)"},
                {RPCResult::Type::STR, "sas", "5-word SAS for verification"},
                {RPCResult::Type::STR, "sas_numeric", "6-digit numeric SAS"},
                {RPCResult::Type::STR, "transport_selected", "Actual transport used"},
                {RPCResult::Type::STR, "relay_url", /*optional=*/true, "Relay server URL (websocket/nostr transports)"},
                {RPCResult::Type::STR, "transport", /*optional=*/true, "Transport protocol in use"},
            }
        },
        RPCExamples{
            HelpExampleCli("cosign.init", "")
            + HelpExampleCli("cosign.init", "\"\" \"repo-offer\" \"websocket\" 3600")
            + HelpExampleRpc("cosign.init", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            if (!cosign::g_bridge_manager.IsEnabled()) {
                throw JSONRPCError(RPC_MISC_ERROR, "COSIGN_DISABLED: Bridge not configured");
            }

            // Parse arguments
            const std::string psbt = request.params[0].isNull() ? "" : request.params[0].get_str();
            const std::string context = request.params[1].isNull() ? "" : request.params[1].get_str();
            const std::string transport = request.params[2].isNull() ? "auto" : request.params[2].get_str();
            const int64_t ttl = request.params[3].isNull() ? 1800 : request.params[3].getInt<int64_t>();

            if (ttl < 60 || ttl > 86400) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "TTL must be between 60 and 86400 seconds");
            }

            // Send init command to bridge
            UniValue bridge_params(UniValue::VOBJ);
            if (!psbt.empty()) bridge_params.pushKV("psbt", psbt);
            if (!context.empty()) bridge_params.pushKV("context", context);
            bridge_params.pushKV("transport", transport);
            bridge_params.pushKV("ttl", ttl);

            UniValue response = cosign::g_bridge_manager.SendBridgeCommand("init", bridge_params);

            // Bridge should return session_id, invite_link, etc.
            // Extract session_id and register session in our in-memory registry
            if (response.isObject() && response.exists("session_id")) {
                std::string session_id = response["session_id"].get_str();
                auto session = std::make_shared<cosign::SessionState>(session_id, ttl);
                session->transport = transport;

                if (response.exists("invite_code")) {
                    session->invite_code = response["invite_code"].get_str();
                }
                if (response.exists("sas")) {
                    session->sas = response["sas"].get_str();
                }
                if (response.exists("sas_numeric")) {
                    session->sas_numeric = response["sas_numeric"].get_str();
                }

                cosign::g_bridge_manager.RegisterSession(session);
            }

            return response;
        }
    };
}

static RPCHelpMan cosign_join()
{
    return RPCHelpMan{"cosign.join",
        "Join an existing cosign session via invite link or code.",
        {
            {"invite_link", RPCArg::Type::STR, RPCArg::Optional::NO, "Magic link or 5-word code"},
            {"context", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Optional context label"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "session_id", "Joined session ID"},
                {RPCResult::Type::STR, "sas", "5-word SAS for verification"},
                {RPCResult::Type::STR, "sas_numeric", "6-digit numeric SAS"},
                {RPCResult::Type::STR, "transport", /*optional=*/true, "Transport selected by bridge (websocket or tor)"},
                {RPCResult::Type::STR, "relay_url", /*optional=*/true, "Relay URL used for websocket transport"},
            }
        },
        RPCExamples{
            HelpExampleCli("cosign.join", "\"cosign:?r=abc...&t=ws#c=apple-banana-cherry-delta-echo\"")
            + HelpExampleRpc("cosign.join", "\"cosign:?r=abc...#c=...\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            if (!cosign::g_bridge_manager.IsEnabled()) {
                throw JSONRPCError(RPC_MISC_ERROR, "COSIGN_DISABLED: Bridge not configured");
            }

            const std::string invite_link = request.params[0].get_str();
            const std::string context = request.params[1].isNull() ? "" : request.params[1].get_str();

            // Send join command to bridge
            UniValue bridge_params(UniValue::VOBJ);
            bridge_params.pushKV("invite_link", invite_link);
            if (!context.empty()) {
                bridge_params.pushKV("context", context);
            }

            UniValue response = cosign::g_bridge_manager.SendBridgeCommand("join", bridge_params);

            LogPrintf("cosign.join: Got response from bridge, checking for session_id\n");

            // Register joined session in our in-memory registry
            if (response.isObject() && response.exists("session_id")) {
                std::string session_id = response["session_id"].get_str();
                LogPrintf("cosign.join: Registering session %s\n", session_id);
                // Use default TTL since we don't know the original TTL from invite
                auto session = std::make_shared<cosign::SessionState>(session_id, 1800);

                if (response.exists("sas")) {
                    session->sas = response["sas"].get_str();
                }
                if (response.exists("sas_numeric")) {
                    session->sas_numeric = response["sas_numeric"].get_str();
                }

                cosign::g_bridge_manager.RegisterSession(session);
                LogPrintf("cosign.join: Successfully registered session %s with BridgeManager\n", session_id);
            } else {
                LogPrintf("cosign.join: WARNING - response does not contain session_id! Response: %s\n", response.write());
            }

            return response;
        }
    };
}

static RPCHelpMan cosign_attest()
{
    return RPCHelpMan{"cosign.attest",
        "BIP-322 peer attestation (two-step challenge/response flow).\n"
        "\nStep 1: Generate challenge\n"
        "  cosign.attest session_id=<sid> address=<addr>\n"
        "  Returns: {\"challenge\": \"...\"}\n"
        "\nStep 2: Verify signature\n"
        "  First sign challenge: signmessage <address> <challenge>\n"
        "  Then verify: cosign.attest session_id=<sid> address=<addr> signature=<sig>\n"
        "  Returns: {\"verified\": true, \"peer\": {...}}",
        {
            {"session_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Session ID"},
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "Bitcoin address to attest with"},
            {"signature", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Base64 signature (for step 2)"},
        },
        {
            RPCResult{"Step 1 (challenge generation)", RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::STR, "challenge", "Challenge string to sign"},
                }
            },
            RPCResult{"Step 2 (signature verification)", RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::BOOL, "verified", "Whether signature was valid"},
                    {RPCResult::Type::OBJ, "peer", "Verified peer info",
                        {
                            {RPCResult::Type::STR, "address", "Peer's verified address"},
                        }
                    },
                }
            },
        },
        RPCExamples{
            "\nStep 1: Generate challenge\n"
            + HelpExampleCli("cosign.attest", "\"session_abc123\" \"bc1q...\"")
            + "\nStep 2: Sign challenge\n"
            + HelpExampleCli("signmessage", "\"bc1q...\" \"cosign|session_abc123|word1-word2-...\"")
            + "\nStep 3: Verify signature\n"
            + HelpExampleCli("cosign.attest", "\"session_abc123\" \"bc1q...\" \"signature_base64\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            const std::string session_id = request.params[0].get_str();
            const std::string address = request.params[1].get_str();
            const bool has_signature = !request.params[2].isNull();

            auto session = cosign::g_bridge_manager.GetSession(session_id);
            if (!session) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown session_id");
            }

            // Send attest command to bridge
            UniValue bridge_params(UniValue::VOBJ);
            bridge_params.pushKV("session_id", session_id);
            bridge_params.pushKV("address", address);

            if (has_signature) {
                // Step 2: Verify signature
                const std::string signature = request.params[2].get_str();

                // Get challenge from bridge first
                UniValue challenge_response = cosign::g_bridge_manager.SendBridgeCommand("attest", bridge_params);
                if (!challenge_response.exists("challenge")) {
                    throw JSONRPCError(RPC_MISC_ERROR, "Bridge did not return challenge");
                }
                std::string challenge = challenge_response["challenge"].get_str();

                // Verify signature using BIP-322 RPC (matches signmessagebip322)
                JSONRPCRequest verify_request;
                verify_request.context = request.context;
                verify_request.strMethod = "verifymessagebip322";
                verify_request.URI = "/"; // Run against node RPC table, not /wallet/<name>
                verify_request.params = UniValue(UniValue::VARR);
                verify_request.params.push_back(address);
                verify_request.params.push_back(signature);
                verify_request.params.push_back(challenge);

                UniValue verify_result;
                try {
                    verify_result = ::tableRPC.execute(verify_request);
                } catch (const std::exception& e) {
                    throw JSONRPCError(RPC_VERIFY_ERROR,
                        strprintf("COSIGN_PEER_ATTEST_FAIL: BIP-322 verification exception (%s)", e.what()));
                }

                if (!verify_result.isBool() || !verify_result.get_bool()) {
                    throw JSONRPCError(RPC_VERIFY_ERROR, "COSIGN_PEER_ATTEST_FAIL: BIP-322 signature verification failed");
                }

                // Signature is valid - tell bridge to mark peer as verified
                bridge_params.pushKV("signature", signature);
                UniValue response = cosign::g_bridge_manager.SendBridgeCommand("attest", bridge_params);

                // Update local session state
                session->peer_verified = true;

                return response;
            } else {
                // Step 1: Generate challenge
                return cosign::g_bridge_manager.SendBridgeCommand("attest", bridge_params);
            }
        }
    };
}

static RPCHelpMan cosign_close()
{
    return RPCHelpMan{"cosign.close",
        "Close a cosign session and purge its state.",
        {
            {"session_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Session ID to close"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::BOOL, "ok", "Success indicator"},
            }
        },
        RPCExamples{
            HelpExampleCli("cosign.close", "\"abc123...\"")
            + HelpExampleRpc("cosign.close", "\"abc123...\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            const std::string session_id = request.params[0].get_str();

            auto session = cosign::g_bridge_manager.GetSession(session_id);
            if (!session) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown session_id");
            }

            UniValue bridge_params(UniValue::VOBJ);
            bridge_params.pushKV("session_id", session_id);
            cosign::g_bridge_manager.SendBridgeCommand("close", bridge_params);

            session->state = "closed";
            cosign::g_bridge_manager.RemoveSession(session_id);

            UniValue result(UniValue::VOBJ);
            result.pushKV("ok", true);
            return result;
        }
    };
}

static RPCHelpMan cosign_resume()
{
    return RPCHelpMan{"cosign.resume",
        "Resume a dropped session and retrieve missed messages.\n"
        "After connection loss, clients can resume within a 20-minute window to retrieve\n"
        "messages that were sent while disconnected. Messages are buffered up to 256 messages\n"
        "or 5MB, whichever is reached first.",
        {
            {"session_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Session ID to resume"},
            {"from_seq", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Resume from sequence number (default: 0 = all buffered messages)"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::ARR, "missed_messages", "Messages sent during disconnection",
                    {
                        {RPCResult::Type::OBJ, "", "Buffered message",
                            {
                                {RPCResult::Type::NUM, "seq", "Message sequence number"},
                                {RPCResult::Type::NUM, "timestamp", "Unix timestamp when message was sent"},
                                {RPCResult::Type::OBJ_DYN, "payload", "Message payload (structure varies)",
                                    {
                                        {RPCResult::Type::ANY, "", "Arbitrary values"},
                                    }
                                },
                            }
                        },
                    }
                },
                {RPCResult::Type::NUM, "current_seq", "Current sequence number"},
                {RPCResult::Type::NUM, "buffer_size", "Number of messages in buffer"},
                {RPCResult::Type::BOOL, "recoverable", "Whether session is still within recovery window"},
            }
        },
        RPCExamples{
            "\nResume session from last known sequence\n"
            + HelpExampleCli("cosign.resume", "\"abc123...\" 42")
            + "\nResume and get all buffered messages\n"
            + HelpExampleCli("cosign.resume", "\"abc123...\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            const std::string session_id = request.params[0].get_str();
            const uint64_t from_seq = request.params[1].isNull() ? 0 : request.params[1].getInt<uint64_t>();

            auto session = cosign::g_bridge_manager.GetSession(session_id);
            if (!session) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown session_id");
            }

            // Send resume command to bridge
            UniValue bridge_params(UniValue::VOBJ);
            bridge_params.pushKV("session_id", session_id);
            bridge_params.pushKV("from_seq", from_seq);

            UniValue response = cosign::g_bridge_manager.SendBridgeCommand("resume", bridge_params);

            // Bridge should return {missed_messages, current_seq, buffer_size, recoverable}
            return response;
        }
    };
}

static RPCHelpMan cosign_send()
{
    return RPCHelpMan{"cosign.send",
        "Send a JSON payload to the peer via the cosign session.",
        {
            {"session_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Session ID"},
            {"payload", RPCArg::Type::OBJ, RPCArg::Optional::NO, "JSON payload to send", {}, RPCArgOptions{.skip_type_check = true}},
            {"idempotency_key", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Optional idempotency token"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::BOOL, "ok", "Success indicator"},
                {RPCResult::Type::NUM, "seq", "Message sequence number"},
            }
        },
        RPCExamples{
            HelpExampleCli("cosign.send", "\"abc123...\" '{\"type\":\"offer\",\"data\":...}'")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            const std::string session_id = request.params[0].get_str();
            const UniValue& payload = request.params[1].get_obj();
            const std::string idempotency_key = request.params[2].isNull() ? "" : request.params[2].get_str();

            auto session = cosign::g_bridge_manager.GetSession(session_id);
            if (!session) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown session_id");
            }

            // Optionally tamper with ceremony payloads for GUI testing when -ceremonytamper is set.
            // Modes:
            //  - drop_maker_input: On ceremony_ready, remove the first input from the PSBT to trigger immutability check
            //  - underfund_native: On ceremony_ready, reduce the first Taproot (likely covenant) output by 1 sat; if none, reduce first non-zero output
            auto maybe_tamper_payload = [&](const UniValue& original) -> UniValue {
                std::string mode = gArgs.GetArg("-ceremonytamper", "");
                if (mode.empty()) return original; // no tamper

                // Work on a mutable copy
                UniValue mutated = original;

                // Extract type
                std::string type;
                if (original.exists("type") && original.find_value("type").isStr()) {
                    type = original.find_value("type").get_str();
                }

                // Only act on ceremony messages that carry a PSBT
                if ((type == "ceremony_ready" || type == "maker_base_psbt") && original.exists("psbt") && original.find_value("psbt").isStr()) {
                    const std::string psbt_b64 = original.find_value("psbt").get_str();
                    PartiallySignedTransaction psbt;
                    std::string err;
                    if (!DecodeBase64PSBT(psbt, psbt_b64, err) || !psbt.tx || psbt.tx->vin.empty()) {
                        LogPrintf("cosign.send: tamper: failed to decode PSBT or missing tx/inputs (mode=%s, type=%s): %s\n", mode, type, err);
                        return original; // fall back silently
                    }

                    bool changed = false;

                    if (mode == "drop_maker_input" && type == "ceremony_ready") {
                        // Remove the first input and corresponding PSBT input entry
                        psbt.tx->vin.erase(psbt.tx->vin.begin());
                        if (!psbt.inputs.empty()) psbt.inputs.erase(psbt.inputs.begin());
                        changed = true;
                        LogPrintf("cosign.send: tamper applied: drop_maker_input on ceremony_ready (removed first input)\n");
                    } else if (mode == "underfund_native" && (type == "ceremony_ready" || type == "maker_base_psbt")) {
                        // Reduce the first Taproot output by 1 sat if present; else, first non-zero output
                        for (size_t i = 0; i < psbt.tx->vout.size(); ++i) {
                            CTxOut& out = psbt.tx->vout[i];
                            int witversion = 0;
                            std::vector<unsigned char> witprog;
                            bool is_taproot = out.scriptPubKey.IsWitnessProgram(witversion, witprog) && (witversion == 1) && (witprog.size() == 32);
                            if (is_taproot && out.nValue > 0) {
                                out.nValue = out.nValue - 1;
                                changed = true;
                                LogPrintf("cosign.send: tamper applied: underfund_native (taproot output index %u -1sat)\n", (unsigned)i);
                                break;
                            }
                        }
                        if (!changed) {
                            for (size_t i = 0; i < psbt.tx->vout.size(); ++i) {
                                CTxOut& out = psbt.tx->vout[i];
                                if (out.nValue > 0) {
                                    out.nValue = out.nValue - 1;
                                    changed = true;
                                    LogPrintf("cosign.send: tamper applied: underfund_native (fallback output index %u -1sat)\n", (unsigned)i);
                                    break;
                                }
                            }
                        }
                    }

                    if (changed) {
                        DataStream ss{};
                        ss << psbt;
                        const std::string new_b64 = EncodeBase64(ss.str());
                        // Replace the psbt field in the mutated object
                        // pushKV overwrites existing key in UniValue objects
                        mutated.pushKV("psbt", new_b64);
                        return mutated;
                    }
                }

                return original;
            };

            // Send payload via bridge
            UniValue bridge_params(UniValue::VOBJ);
            bridge_params.pushKV("session_id", session_id);
            bridge_params.pushKV("payload", maybe_tamper_payload(payload));
            if (!idempotency_key.empty()) {
                bridge_params.pushKV("idempotency_key", idempotency_key);
            }

            UniValue response = cosign::g_bridge_manager.SendBridgeCommand("send", bridge_params);

            // Update session state
            session->messages_sent++;

            // Bridge should return {ok, seq}
            return response;
        }
    };
}

static RPCHelpMan cosign_recv()
{
    return RPCHelpMan{"cosign.recv",
        "Receive a payload from the peer (blocking or long-poll).",
        {
            {"session_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Session ID"},
            {"timeout_ms", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Timeout in milliseconds (default: 30000)"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::OBJ_DYN, "payload", "Received JSON payload (structure varies)",
                    {
                        {RPCResult::Type::ANY, "", "Arbitrary values (type varies)"},
                    }
                },
            }
        },
        RPCExamples{
            HelpExampleCli("cosign.recv", "\"abc123...\"")
            + HelpExampleCli("cosign.recv", "\"abc123...\" 60000")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            const std::string session_id = request.params[0].get_str();
            const int timeout_ms = request.params[1].isNull() ? 30000 : request.params[1].getInt<int>();

            auto session = cosign::g_bridge_manager.GetSession(session_id);
            if (!session) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown session_id");
            }

            // Receive payload via bridge (blocking with timeout)
            UniValue bridge_params(UniValue::VOBJ);
            bridge_params.pushKV("session_id", session_id);
            bridge_params.pushKV("timeout_ms", timeout_ms);

            UniValue response = cosign::g_bridge_manager.SendBridgeCommand("recv", bridge_params);

            // Update session state
            session->messages_received++;

            // Bridge should return {payload}
            return response;
        }
    };
}

static RPCHelpMan cosign_metrics()
{
    return RPCHelpMan{"cosign.metrics",
        "Get cosign bridge metrics (active sessions, message counts, health).",
        {},
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::NUM, "active_sessions", "Number of active sessions"},
                {RPCResult::Type::NUM, "total_messages", "Total messages sent/received"},
                {RPCResult::Type::NUM, "bridge_restarts", "Bridge restart count (top-level for backward compatibility)"},
                {RPCResult::Type::OBJ, "bridge_health", "Bridge health monitoring",
                    {
                        {RPCResult::Type::STR, "health_state", "Health state: unknown|healthy|recoverable|failed|dead"},
                        {RPCResult::Type::NUM, "restart_count", "Bridge restart attempts"},
                        {RPCResult::Type::NUM, "max_restarts", "Maximum allowed restarts"},
                        {RPCResult::Type::NUM, "consecutive_failures", "Consecutive heartbeat failures"},
                        {RPCResult::Type::NUM, "last_successful_ping", "Unix timestamp of last successful ping"},
                        {RPCResult::Type::NUM, "seconds_since_last_ping", "Seconds since last ping (-1 if never)"},
                    }
                },
                {RPCResult::Type::OBJ, "transport_failures", "Failures by transport",
                    {
                        {RPCResult::Type::NUM, "ws", "WebSocket failures"},
                        {RPCResult::Type::NUM, "nostr", "Nostr failures"},
                    }
                },
                {RPCResult::Type::NUM, "avg_latency_ms", "Average message latency"},
                {RPCResult::Type::NUM, "p95_latency_ms", "P95 latency"},
                {RPCResult::Type::NUM, "p99_latency_ms", "P99 latency"},
            }
        },
        RPCExamples{
            HelpExampleCli("cosign.metrics", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            if (!cosign::g_bridge_manager.IsEnabled()) {
                throw JSONRPCError(RPC_MISC_ERROR, "COSIGN_DISABLED: Bridge not configured");
            }

            UniValue result(UniValue::VOBJ);
            result.pushKV("active_sessions", static_cast<int>(cosign::g_bridge_manager.GetActiveSessionCount()));
            result.pushKV("total_messages", 0);

            // Get bridge health metrics
            UniValue health = cosign::g_bridge_manager.GetHealthMetrics();
            result.pushKV("bridge_health", health);

            // Add bridge_restarts at top level (for backward compatibility with tests)
            result.pushKV("bridge_restarts", health["restart_count"]);

            UniValue failures(UniValue::VOBJ);
            failures.pushKV("ws", 0);
            failures.pushKV("nostr", 0);
            result.pushKV("transport_failures", failures);

            result.pushKV("avg_latency_ms", 0);
            result.pushKV("p95_latency_ms", 0);
            result.pushKV("p99_latency_ms", 0);

            return result;
        }
    };
}

static RPCHelpMan cosign_status()
{
    return RPCHelpMan{"cosign.status",
        "Get runtime status of a cosign session.",
        {
            {"session_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Session ID"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "state", "Session state: open|closing|closed|error"},
                {RPCResult::Type::BOOL, "peer_verified", "Whether peer BIP-322 attestation succeeded"},
                {RPCResult::Type::NUM, "messages_sent", "Messages sent count"},
                {RPCResult::Type::NUM, "messages_received", "Messages received count"},
                {RPCResult::Type::NUM, "age_sec", "Session age in seconds"},
                {RPCResult::Type::NUM, "ttl_sec", "Configured TTL"},
                {RPCResult::Type::STR, "transport", "Active transport"},
            }
        },
        RPCExamples{
            HelpExampleCli("cosign.status", "\"abc123...\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            const std::string session_id = request.params[0].get_str();

            auto session = cosign::g_bridge_manager.GetSession(session_id);
            if (!session) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown session_id");
            }

            UniValue result(UniValue::VOBJ);
            result.pushKV("state", session->state);
            result.pushKV("peer_verified", session->peer_verified);
            result.pushKV("messages_sent", session->messages_sent);
            result.pushKV("messages_received", session->messages_received);
            result.pushKV("age_sec", static_cast<int>(GetTime() - session->created_at));
            result.pushKV("ttl_sec", session->ttl_sec);
            result.pushKV("transport", session->transport);

            return result;
        }
    };
}

static RPCHelpMan cosign_adaptor_roundtrip()
{
    return RPCHelpMan{"cosign.adaptor_roundtrip",
        "Automate complete adaptor signature ceremony over cosign channel (Phase 4 §5.8).\n"
        "\n"
        "This is the PRIMARY ceremony helper that orchestrates all 3 phases:\n"
        "1. PREPARE: Generate nonces/commitments, exchange via cosign\n"
        "2. PARTIAL: Create partial signatures, exchange via cosign\n"
        "3. COMPLETE: Finalize PSBT with adaptor signatures\n"
        "\n"
        "SECURITY: Handshake must be complete before calling (use cosign.handshake_auto first).\n"
        "IMPORTANT: Both parties must call this simultaneously (initiator and responder roles).",
        {
            {"session_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Active cosign session ID (after handshake)"},
            {"psbt", RPCArg::Type::STR, RPCArg::Optional::NO, "Partially Signed Bitcoin Transaction (base64)"},
            {"is_initiator", RPCArg::Type::BOOL, RPCArg::Optional::NO, "Whether this party initiates ceremony"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "psbt", "Completed PSBT with all signatures (base64)"},
                {RPCResult::Type::BOOL, "complete", "Whether ceremony completed successfully"},
                {RPCResult::Type::NUM, "messages_sent", "Number of messages sent"},
                {RPCResult::Type::NUM, "messages_received", "Number of messages received"},
            }
        },
        RPCExamples{
            "\nBorrower (initiator) automates ceremony\n"
            + HelpExampleCli("cosign.adaptor_roundtrip", "\"abc123...\" \"cHNidP8BA...\" true")
            + "\nLender (responder) automates ceremony\n"
            + HelpExampleCli("cosign.adaptor_roundtrip", "\"abc123...\" \"cHNidP8BA...\" false")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            const std::string session_id = request.params[0].get_str();
            const std::string psbt_b64 = request.params[1].get_str();
            // Note: is_initiator could be used for future message ordering logic
            // For now, both parties follow same exchange pattern (send then recv)
            (void)request.params[2].get_bool();  // Acknowledge but don't use yet

            auto session = cosign::g_bridge_manager.GetSession(session_id);
            if (!session) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown session_id");
            }

            int messages_sent = 0;
            int messages_received = 0;

            // =================================================================
            // PHASE 1: PREPARE - Exchange nonce commitments
            // =================================================================

            // Call adaptor.prepare to generate our commitments
            JSONRPCRequest prepare_req;
            prepare_req.context = request.context;
            prepare_req.strMethod = "adaptor.prepare";
            UniValue prepare_params(UniValue::VARR);
            prepare_params.push_back(psbt_b64);
            // Note: musig2_config parameter is optional/omitted - don't pass anything for simple signing
            prepare_req.params = prepare_params;

            UniValue prepare_result = tableRPC.execute(prepare_req);
            std::string psbt_after_prepare = prepare_result["psbt"].get_str();
            UniValue our_commitments = prepare_result["our_commitments"];

            // Exchange commitments via cosign
            {
                // Send our commitments
                JSONRPCRequest send_req;
                send_req.context = request.context;
                send_req.strMethod = "cosign.send";
                UniValue send_params(UniValue::VARR);
                send_params.push_back(session_id);
                UniValue payload(UniValue::VOBJ);
                payload.pushKV("type", "adaptor_commitments");
                payload.pushKV("commitments", our_commitments);
                send_params.push_back(payload);
                send_req.params = send_params;

                tableRPC.execute(send_req);
                messages_sent++;

                // Receive peer commitments
                JSONRPCRequest recv_req;
                recv_req.context = request.context;
                recv_req.strMethod = "cosign.recv";
                UniValue recv_params(UniValue::VARR);
                recv_params.push_back(session_id);
                recv_params.push_back(60000);  // 60s timeout
                recv_req.params = recv_params;

                UniValue recv_result = tableRPC.execute(recv_req);
                messages_received++;

                if (!recv_result["payload"]["commitments"].isArray()) {
                    throw JSONRPCError(RPC_MISC_ERROR, "Invalid commitments from peer");
                }

                UniValue peer_commitments = recv_result["payload"]["commitments"];

                // Call adaptor.prepare again with peer commitments to verify
                JSONRPCRequest prepare2_req;
                prepare2_req.context = request.context;
                prepare2_req.strMethod = "adaptor.prepare";
                UniValue prepare2_params(UniValue::VARR);
                prepare2_params.push_back(psbt_after_prepare);
                prepare2_params.push_back(peer_commitments);
                prepare2_req.params = prepare2_params;

                UniValue prepare2_result = tableRPC.execute(prepare2_req);
                psbt_after_prepare = prepare2_result["psbt"].get_str();
            }

            // =================================================================
            // PHASE 2: PARTIAL - Exchange partial signatures
            // =================================================================

            // Call adaptor.partial to generate our partial signatures
            JSONRPCRequest partial_req;
            partial_req.context = request.context;
            partial_req.strMethod = "adaptor.partial";
            UniValue partial_params(UniValue::VARR);
            partial_params.push_back(psbt_after_prepare);
            partial_params.push_back(UniValue(UniValue::VARR));  // Empty peer_partials initially
            partial_req.params = partial_params;

            UniValue partial_result = tableRPC.execute(partial_req);
            std::string psbt_after_partial = partial_result["psbt"].get_str();
            UniValue our_partials = partial_result["our_partials"];

            // Exchange partial signatures via cosign
            {
                // Send our partial signatures
                JSONRPCRequest send_req;
                send_req.context = request.context;
                send_req.strMethod = "cosign.send";
                UniValue send_params(UniValue::VARR);
                send_params.push_back(session_id);
                UniValue payload(UniValue::VOBJ);
                payload.pushKV("type", "adaptor_partials");
                payload.pushKV("partials", our_partials);
                send_params.push_back(payload);
                send_req.params = send_params;

                tableRPC.execute(send_req);
                messages_sent++;

                // Receive peer partial signatures
                JSONRPCRequest recv_req;
                recv_req.context = request.context;
                recv_req.strMethod = "cosign.recv";
                UniValue recv_params(UniValue::VARR);
                recv_params.push_back(session_id);
                recv_params.push_back(60000);  // 60s timeout
                recv_req.params = recv_params;

                UniValue recv_result = tableRPC.execute(recv_req);
                messages_received++;

                if (!recv_result["payload"]["partials"].isArray()) {
                    throw JSONRPCError(RPC_MISC_ERROR, "Invalid partial signatures from peer");
                }

                UniValue peer_partials = recv_result["payload"]["partials"];

                // Call adaptor.partial again with peer partials to aggregate
                JSONRPCRequest partial2_req;
                partial2_req.context = request.context;
                partial2_req.strMethod = "adaptor.partial";
                UniValue partial2_params(UniValue::VARR);
                partial2_params.push_back(psbt_after_partial);
                partial2_params.push_back(peer_partials);
                partial2_req.params = partial2_params;

                UniValue partial2_result = tableRPC.execute(partial2_req);
                psbt_after_partial = partial2_result["psbt"].get_str();
            }

            // =================================================================
            // PHASE 3: COMPLETE - Finalize with adaptor signatures
            // =================================================================

            // Call adaptor.complete to finalize
            JSONRPCRequest complete_req;
            complete_req.context = request.context;
            complete_req.strMethod = "adaptor.complete";
            UniValue complete_params(UniValue::VARR);
            complete_params.push_back(psbt_after_partial);
            complete_req.params = complete_params;

            UniValue complete_result = tableRPC.execute(complete_req);
            std::string final_psbt = complete_result["psbt"].get_str();
            bool is_complete = complete_result["complete"].get_bool();

            // Return final result
            UniValue result(UniValue::VOBJ);
            result.pushKV("psbt", final_psbt);
            result.pushKV("complete", is_complete);
            result.pushKV("messages_sent", messages_sent);
            result.pushKV("messages_received", messages_received);

            return result;
        }
    };
}

static RPCHelpMan cosign_handshake_auto()
{
    return RPCHelpMan{"cosign.handshake_auto",
        "Automatically complete SPAKE2 + Noise handshake over the established transport.\n"
        "This method handles the entire handshake flow automatically:\n"
        "1. Generate and exchange SPAKE2 messages\n"
        "2. Derive shared secret\n"
        "3. Exchange Noise handshake messages\n"
        "4. Establish encrypted channel\n"
        "\n"
        "After this completes successfully, cosign.send and cosign.recv are enabled.\n"
        "SECURITY: No unencrypted/unauthenticated traffic is allowed (Phase 4 requirement).",
        {
            {"session_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Session ID"},
            {"is_initiator", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED, "Whether this party initiates handshake (default: false for join, true for init)"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::BOOL, "handshake_complete", "Whether handshake completed successfully"},
                {RPCResult::Type::STR, "sas", "5-word SAS for user verification"},
                {RPCResult::Type::STR, "sas_numeric", "6-digit numeric SAS"},
                {RPCResult::Type::STR, "message", "Success message"},
            }
        },
        RPCExamples{
            "\nAfter init (as initiator)\n"
            + HelpExampleCli("cosign.handshake_auto", "\"abc123...\" true")
            + "\nAfter join (as responder)\n"
            + HelpExampleCli("cosign.handshake_auto", "\"abc123...\" false")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            const std::string session_id = request.params[0].get_str();
            const bool is_initiator = request.params[1].isNull() ? false : request.params[1].get_bool();

            auto session = cosign::g_bridge_manager.GetSession(session_id);
            if (!session) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown session_id");
            }

            if (session->handshake_complete) {
                UniValue cached(UniValue::VOBJ);
                cached.pushKV("handshake_complete", true);
                if (!session->sas.empty()) {
                    cached.pushKV("sas", session->sas);
                }
                if (!session->sas_numeric.empty()) {
                    cached.pushKV("sas_numeric", session->sas_numeric);
                }
                cached.pushKV("message", "Handshake already complete; returning cached session state.");
                return cached;
            }

            // Send handshake_auto command to bridge
            UniValue bridge_params(UniValue::VOBJ);
            bridge_params.pushKV("session_id", session_id);
            bridge_params.pushKV("is_initiator", is_initiator);

            UniValue response = cosign::g_bridge_manager.SendBridgeCommand("handshake_auto", bridge_params);

            // Bridge should return {handshake_complete, sas, sas_numeric, message}
            if (response.isObject() && response.exists("handshake_complete") &&
                response["handshake_complete"].isBool() && response["handshake_complete"].get_bool()) {
                session->handshake_complete = true;
                if (response.exists("sas") && response["sas"].isStr()) {
                    session->sas = response["sas"].get_str();
                }
                if (response.exists("sas_numeric") && response["sas_numeric"].isStr()) {
                    session->sas_numeric = response["sas_numeric"].get_str();
                }
            }

            return response;
        }
    };
}

// ============================================================================
// BULLETIN BOARD COMMANDS
// ============================================================================

static RPCHelpMan cosign_init_bb()
{
    return RPCHelpMan{"cosign.init_bb",
        "Initialize bulletin board connection (Nostr relays).\n"
        "Offers will be compartmentalized by the current chain (main/signet/testnet3/regtest).",
        {
            {"relays", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "List of Nostr relay URLs",
                {
                    {"url", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Relay WebSocket URL (wss://...)"},
                }
            },
            {"nostr_key_path", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Path to Nostr key file (default: ~/.tensorcash/nostr_keys)"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::BOOL, "success", "Whether initialization succeeded"},
                {RPCResult::Type::STR_HEX, "pubkey", "Nostr public key (hex)"},
                {RPCResult::Type::ARR, "relays", "Connected relay URLs",
                    {
                        {RPCResult::Type::STR, "", "Relay URL"},
                    }
                },
                {RPCResult::Type::STR, "network", "Bitcoin network (main, signet, testnet3, regtest)"},
            }
        },
        RPCExamples{
            HelpExampleCli("cosign.init_bb", "")
            + HelpExampleCli("cosign.init_bb", "'[\"wss://relay.damus.io\",\"wss://nos.lol\"]'")
            + HelpExampleRpc("cosign.init_bb", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            if (!cosign::g_bridge_manager.IsEnabled()) {
                throw JSONRPCError(RPC_MISC_ERROR, "COSIGN_DISABLED: Bridge not configured");
            }

            // Parse arguments
            UniValue bridge_params(UniValue::VOBJ);

            if (!request.params[0].isNull()) {
                bridge_params.pushKV("relays", request.params[0]);
            }
            if (!request.params[1].isNull()) {
                bridge_params.pushKV("nostr_key_path", request.params[1].get_str());
            }

            // Pass current chain type for offer compartmentalization
            // This ensures regtest/signet/mainnet offers don't mix
            bridge_params.pushKV("network", gArgs.GetChainTypeString());

            UniValue response = cosign::g_bridge_manager.SendBridgeCommand("init_bb", bridge_params);
            return response;
        }
    };
}

static RPCHelpMan cosign_post_offer()
{
    return RPCHelpMan{"cosign.post_offer",
        "Post a trading offer to the bulletin board.",
        {
            {"offer_type", RPCArg::Type::STR, RPCArg::Optional::NO, "Offer type: buy|sell|swap"},
            {"asset_send", RPCArg::Type::STR, RPCArg::Optional::NO, "Asset being sent (e.g., BTC, USD)"},
            {"asset_recv", RPCArg::Type::STR, RPCArg::Optional::NO, "Asset being received"},
            {"amount", RPCArg::Type::NUM, RPCArg::Optional::NO, "Amount of asset_send"},
            {"price", RPCArg::Type::NUM, RPCArg::Optional::NO, "Exchange rate"},
            {"payment_methods", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "Accepted payment methods",
                {
                    {"method", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Payment method"},
                }
            },
            {"regions", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "Allowed regions",
                {
                    {"region", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Region code"},
                }
            },
            {"requires_escrow", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED, "Whether escrow is required (default: false)"},
            {"min_reputation_score", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Minimum reputation score for taker (default: 0)"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::BOOL, "success", "Whether post succeeded"},
                {RPCResult::Type::STR, "offer_id", "UUID of the created offer"},
            }
        },
        RPCExamples{
            HelpExampleCli("cosign.post_offer", "\"sell\" \"BTC\" \"USD\" 0.1 65000")
            + HelpExampleRpc("cosign.post_offer", "\"sell\",\"BTC\",\"USD\",0.1,65000")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            if (!cosign::g_bridge_manager.IsEnabled()) {
                throw JSONRPCError(RPC_MISC_ERROR, "COSIGN_DISABLED: Bridge not configured");
            }

            // Parse arguments
            UniValue bridge_params(UniValue::VOBJ);
            bridge_params.pushKV("offer_type", request.params[0].get_str());
            bridge_params.pushKV("asset_send", request.params[1].get_str());
            bridge_params.pushKV("asset_recv", request.params[2].get_str());
            bridge_params.pushKV("amount", request.params[3].get_real());
            bridge_params.pushKV("price", request.params[4].get_real());

            if (!request.params[5].isNull()) {
                bridge_params.pushKV("payment_methods", request.params[5]);
            }
            if (!request.params[6].isNull()) {
                bridge_params.pushKV("regions", request.params[6]);
            }
            if (!request.params[7].isNull()) {
                bridge_params.pushKV("requires_escrow", request.params[7].get_bool());
            }
            if (!request.params[8].isNull()) {
                bridge_params.pushKV("min_reputation_score", request.params[8].get_real());
            }

            UniValue response = cosign::g_bridge_manager.SendBridgeCommand("post_offer", bridge_params);
            return response;
        }
    };
}

static RPCHelpMan cosign_post_contract_offer()
{
    return RPCHelpMan{"cosign.post_contract_offer",
        "Post a contract offer (repo/forward/spot/option/difficulty) to the bulletin board.",
        {
            {"contract_type", RPCArg::Type::STR, RPCArg::Optional::NO, "Contract type: repo|forward|spot|option|difficulty"},
            {"contract_payload", RPCArg::Type::STR, RPCArg::Optional::NO, "Full contract JSON / term sheet from repo.propose/forward.propose/difficulty term sheet"},
            {"maker_role", RPCArg::Type::STR, RPCArg::Optional::NO, "Maker's role: lender|borrower|long|short|writer|buyer"},
            {"apr", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Annual percentage rate (for display/search)"},
            {"ltv", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Loan-to-value ratio (repo contracts only)"},
            {"tenor_days", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Days until maturity"},
            {"proof_of_funds", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "Array of BIP-322 ownership proofs",
                {
                    {"proof", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                        {
                            {"utxo_ref", RPCArg::Type::STR, RPCArg::Optional::NO, "UTXO reference (txid:vout)"},
                            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "Bitcoin address"},
                            {"message", RPCArg::Type::STR, RPCArg::Optional::NO, "Signed message: TENSORCASH_PROOF:{offer_id}:{role}:{asset_id}"},
                            {"signature", RPCArg::Type::STR, RPCArg::Optional::NO, "BIP-322 signature"},
                            {"asset_units", RPCArg::Type::NUM, RPCArg::Optional::NO, "Asset units in UTXO"},
                            {"asset_id", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Asset ID (hex) - required for multi-asset contracts"},
                        },
                    },
                },
            },
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::BOOL, "success", "Whether post succeeded"},
                {RPCResult::Type::STR, "offer_id", "UUID of the created contract offer"},
            }
        },
        RPCExamples{
            HelpExampleCli("cosign.post_contract_offer", "\"repo\" \"{...contract_json...}\" \"lender\" 5.2 80.0 14")
            + HelpExampleRpc("cosign.post_contract_offer", "\"repo\",\"{...}\",\"lender\",5.2,80.0,14")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            if (!cosign::g_bridge_manager.IsEnabled()) {
                throw JSONRPCError(RPC_MISC_ERROR, "COSIGN_DISABLED: Bridge not configured");
            }

            // Parse arguments
            UniValue bridge_params(UniValue::VOBJ);
            bridge_params.pushKV("contract_type", request.params[0].get_str());
            bridge_params.pushKV("contract_payload", request.params[1].get_str());
            bridge_params.pushKV("maker_role", request.params[2].get_str());

            if (!request.params[3].isNull()) {
                bridge_params.pushKV("apr", request.params[3].get_real());
            }
            if (!request.params[4].isNull()) {
                bridge_params.pushKV("ltv", request.params[4].get_real());
            }
            if (!request.params[5].isNull()) {
                bridge_params.pushKV("tenor_days", request.params[5].getInt<int>());
            }

            // Parse optional proof_of_funds array (params[6])
            if (request.params.size() > 6 && !request.params[6].isNull() && request.params[6].isArray()) {
                const UniValue& proof_array = request.params[6];
                if (proof_array.size() > 0) {
                    bridge_params.pushKV("proof_of_funds", proof_array);
                }
            }

            UniValue response = cosign::g_bridge_manager.SendBridgeCommand("post_contract_offer", bridge_params);
            return response;
        }
    };
}

static RPCHelpMan cosign_list_offers()
{
    return RPCHelpMan{"cosign.list_offers",
        "List available offers from the bulletin board with optional filters.",
        {
            {"offer_type", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Filter by offer type: buy|sell|swap"},
            {"min_amount", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Minimum amount filter"},
            {"max_amount", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Maximum amount filter"},
            {"region", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Filter by region"},
            {"payment_method", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Filter by payment method"},
            {"min_reputation", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Minimum reputation filter"},
            {"force_refresh", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED, "Force refresh from Nostr relays (bypass cache)"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::BOOL, "success", "Whether query succeeded"},
                {RPCResult::Type::ARR, "offers", "List of matching offers",
                    {
                        {RPCResult::Type::OBJ, "", "",
                            {
                                {RPCResult::Type::STR, "id", "Offer ID"},
                                {RPCResult::Type::STR, "offer_type", "buy|sell|swap"},
                                {RPCResult::Type::STR, "asset_send", "Asset being sent"},
                                {RPCResult::Type::STR, "asset_recv", "Asset being received"},
                                {RPCResult::Type::NUM, "amount", "Amount"},
                                {RPCResult::Type::NUM, "price", "Exchange rate"},
                                {RPCResult::Type::STR_HEX, "maker_pubkey", "Maker's Nostr pubkey"},
                                {RPCResult::Type::NUM, "created_at", "Unix timestamp"},
                                {RPCResult::Type::NUM, "expires_at", "Unix timestamp"},
                            }
                        },
                    }
                },
            }
        },
        RPCExamples{
            HelpExampleCli("cosign.list_offers", "")
            + HelpExampleCli("cosign.list_offers", "\"sell\" 0.01 1.0")
            + HelpExampleRpc("cosign.list_offers", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            if (!cosign::g_bridge_manager.IsEnabled()) {
                throw JSONRPCError(RPC_MISC_ERROR, "COSIGN_DISABLED: Bridge not configured");
            }

            // Parse filters
            UniValue bridge_params(UniValue::VOBJ);

            if (!request.params[0].isNull()) {
                bridge_params.pushKV("offer_type", request.params[0].get_str());
            }
            if (!request.params[1].isNull()) {
                bridge_params.pushKV("min_amount", request.params[1].get_real());
            }
            if (!request.params[2].isNull()) {
                bridge_params.pushKV("max_amount", request.params[2].get_real());
            }
            if (!request.params[3].isNull()) {
                bridge_params.pushKV("region", request.params[3].get_str());
            }
            if (!request.params[4].isNull()) {
                bridge_params.pushKV("payment_method", request.params[4].get_str());
            }
            if (!request.params[5].isNull()) {
                bridge_params.pushKV("min_reputation", request.params[5].get_real());
            }
            if (!request.params[6].isNull()) {
                bridge_params.pushKV("force_refresh", request.params[6].get_bool());
            }

            UniValue response = cosign::g_bridge_manager.SendBridgeCommand("list_offers", bridge_params);
            return response;
        }
    };
}

static RPCHelpMan cosign_request_trade()
{
    return RPCHelpMan{"cosign.request_trade",
        "Request to trade on an offer (taker sends DM to maker).",
        {
            {"offer_id", RPCArg::Type::STR, RPCArg::Optional::NO, "Offer ID to request"},
            {"message", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Optional message to maker"},
            {"proof_of_funds", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "Array of BIP-322 ownership proofs for taker's assets",
                {
                    {"proof", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                        {
                            {"utxo_ref", RPCArg::Type::STR, RPCArg::Optional::NO, "UTXO reference (txid:vout)"},
                            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "Bitcoin address"},
                            {"message", RPCArg::Type::STR, RPCArg::Optional::NO, "Signed message: TENSORCASH_PROOF:{offer_id}:{role}:{asset_id}"},
                            {"signature", RPCArg::Type::STR, RPCArg::Optional::NO, "BIP-322 signature"},
                            {"asset_units", RPCArg::Type::NUM, RPCArg::Optional::NO, "Asset units in UTXO"},
                            {"asset_id", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Asset ID (hex) - required for multi-asset contracts"},
                        },
                    },
                },
            },
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::BOOL, "success", "Whether request succeeded"},
                {RPCResult::Type::STR, "request_id", "UUID of the trade request"},
            }
        },
        RPCExamples{
            HelpExampleCli("cosign.request_trade", "\"abc123-def456\"")
            + HelpExampleCli("cosign.request_trade", "\"abc123-def456\" \"Interested in your offer\"")
            + HelpExampleRpc("cosign.request_trade", "\"abc123-def456\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            if (!cosign::g_bridge_manager.IsEnabled()) {
                throw JSONRPCError(RPC_MISC_ERROR, "COSIGN_DISABLED: Bridge not configured");
            }

            // Parse arguments
            UniValue bridge_params(UniValue::VOBJ);
            bridge_params.pushKV("offer_id", request.params[0].get_str());

            if (!request.params[1].isNull()) {
                bridge_params.pushKV("message", request.params[1].get_str());
            }

            // Parse optional proof_of_funds array (params[2])
            if (request.params.size() > 2 && !request.params[2].isNull() && request.params[2].isArray()) {
                const UniValue& proof_array = request.params[2];
                if (proof_array.size() > 0) {
                    bridge_params.pushKV("proof_of_funds", proof_array);
                }
            }

            UniValue response = cosign::g_bridge_manager.SendBridgeCommand("request_trade", bridge_params);
            return response;
        }
    };
}

static RPCHelpMan cosign_list_requests()
{
    return RPCHelpMan{"cosign.list_requests",
        "List pending trade requests (maker checks incoming DMs).",
        {},
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::BOOL, "success", "Whether query succeeded"},
                {RPCResult::Type::ARR, "requests", "List of pending requests",
                    {
                        {RPCResult::Type::OBJ, "", "",
                            {
                                {RPCResult::Type::STR, "id", "Request ID"},
                                {RPCResult::Type::STR, "offer_id", "Offer ID"},
                                {RPCResult::Type::STR_HEX, "taker_pubkey", "Taker's Nostr pubkey"},
                                {RPCResult::Type::NUM, "timestamp", "Unix timestamp"},
                                {RPCResult::Type::STR, "message", "Optional message from taker"},
                                {RPCResult::Type::STR, "status", "pending|accepted|rejected"},
                            }
                        },
                    }
                },
            }
        },
        RPCExamples{
            HelpExampleCli("cosign.list_requests", "")
            + HelpExampleRpc("cosign.list_requests", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            if (!cosign::g_bridge_manager.IsEnabled()) {
                throw JSONRPCError(RPC_MISC_ERROR, "COSIGN_DISABLED: Bridge not configured");
            }

            UniValue bridge_params(UniValue::VOBJ);
            UniValue response = cosign::g_bridge_manager.SendBridgeCommand("list_requests", bridge_params);
            return response;
        }
    };
}

static RPCHelpMan cosign_accept_request()
{
    return RPCHelpMan{"cosign.accept_request",
        "Accept a trade request (maker creates bilateral session and sends invite link to taker).",
        {
            {"request_id", RPCArg::Type::STR, RPCArg::Optional::NO, "Request ID to accept"},
            {"transport", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Transport for bilateral session (default: websocket)"},
            {"ttl", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Session TTL in seconds (default: 1800)"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::BOOL, "success", "Whether accept succeeded"},
                {RPCResult::Type::STR, "invite_link", "Bilateral session invite link (sent to taker via DM)"},
                {RPCResult::Type::STR_HEX, "session_id", "Session ID for bilateral trading"},
            }
        },
        RPCExamples{
            HelpExampleCli("cosign.accept_request", "\"req123-abc456\"")
            + HelpExampleCli("cosign.accept_request", "\"req123-abc456\" \"tor\" 3600")
            + HelpExampleRpc("cosign.accept_request", "\"req123-abc456\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            if (!cosign::g_bridge_manager.IsEnabled()) {
                throw JSONRPCError(RPC_MISC_ERROR, "COSIGN_DISABLED: Bridge not configured");
            }

            // Parse arguments
            UniValue bridge_params(UniValue::VOBJ);
            bridge_params.pushKV("request_id", request.params[0].get_str());

            if (!request.params[1].isNull()) {
                bridge_params.pushKV("transport", request.params[1].get_str());
            }
            if (!request.params[2].isNull()) {
                bridge_params.pushKV("ttl", request.params[2].getInt<int64_t>());
            }

            UniValue response = cosign::g_bridge_manager.SendBridgeCommand("accept_request", bridge_params);

            LogPrintf("cosign.accept_request: Got response from bridge, checking for session_id\n");

            // If successful, register the bilateral session
            if (response.isObject() && response.exists("session_id")) {
                std::string session_id = response["session_id"].get_str();
                LogPrintf("cosign.accept_request: Registering session %s\n", session_id);
                int64_t ttl = request.params[2].isNull() ? 1800 : request.params[2].getInt<int64_t>();
                auto session = std::make_shared<cosign::SessionState>(session_id, ttl);
                session->transport = request.params[1].isNull() ? "websocket" : request.params[1].get_str();
                cosign::g_bridge_manager.RegisterSession(session);
                LogPrintf("cosign.accept_request: Successfully registered session %s with BridgeManager\n", session_id);
            } else {
                LogPrintf("cosign.accept_request: WARNING - response does not contain session_id! Response: %s\n", response.write());
            }

            return response;
        }
    };
}

static RPCHelpMan cosign_reject_request()
{
    return RPCHelpMan{"cosign.reject_request",
        "Reject a trade request (maker sends rejection DM to taker).",
        {
            {"request_id", RPCArg::Type::STR, RPCArg::Optional::NO, "Request ID to reject"},
            {"reason", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Optional rejection reason"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::BOOL, "success", "Whether reject succeeded"},
            }
        },
        RPCExamples{
            HelpExampleCli("cosign.reject_request", "\"req123-abc456\"")
            + HelpExampleCli("cosign.reject_request", "\"req123-abc456\" \"Insufficient reputation\"")
            + HelpExampleRpc("cosign.reject_request", "\"req123-abc456\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            if (!cosign::g_bridge_manager.IsEnabled()) {
                throw JSONRPCError(RPC_MISC_ERROR, "COSIGN_DISABLED: Bridge not configured");
            }

            // Parse arguments
            UniValue bridge_params(UniValue::VOBJ);
            bridge_params.pushKV("request_id", request.params[0].get_str());

            if (!request.params[1].isNull()) {
                bridge_params.pushKV("reason", request.params[1].get_str());
            }

            UniValue response = cosign::g_bridge_manager.SendBridgeCommand("reject_request", bridge_params);
            return response;
        }
    };
}

static RPCHelpMan cosign_delete_offer()
{
    return RPCHelpMan{"cosign.delete_offer",
        "Delete/cancel an offer from the bulletin board (maker only).",
        {
            {"offer_id", RPCArg::Type::STR, RPCArg::Optional::NO, "Offer ID to delete"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::BOOL, "success", "Whether delete succeeded"},
            }
        },
        RPCExamples{
            HelpExampleCli("cosign.delete_offer", "\"offer123-abc456\"")
            + HelpExampleRpc("cosign.delete_offer", "\"offer123-abc456\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            if (!cosign::g_bridge_manager.IsEnabled()) {
                throw JSONRPCError(RPC_MISC_ERROR, "COSIGN_DISABLED: Bridge not configured");
            }

            // Parse arguments
            UniValue bridge_params(UniValue::VOBJ);
            bridge_params.pushKV("offer_id", request.params[0].get_str());

            UniValue response = cosign::g_bridge_manager.SendBridgeCommand("delete_offer", bridge_params);
            return response;
        }
    };
}

// ============================================================================
// CROSS-CHAIN COMMANDS
// ============================================================================

static RPCHelpMan cosign_post_cross_chain_offer()
{
    return RPCHelpMan{"cosign.post_cross_chain_offer",
        "Post a cross-chain settlement offer to the bulletin board.\n"
        "\nValidates the cross_chain_spot_v1 payload (addresses, timeouts, adapter consistency)\n"
        "then posts it as a SpotContract through the existing board path.",
        {
            {"contract_payload", RPCArg::Type::STR, RPCArg::Optional::NO,
                "Cross-chain spot v1 payload JSON (must have schema = \"cross_chain_spot_v1\")"},
            {"proof_of_funds", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "Array of BIP-322 ownership proofs",
                {
                    {"proof", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                        {
                            {"utxo_ref", RPCArg::Type::STR, RPCArg::Optional::NO, "UTXO reference (txid:vout)"},
                            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "Bitcoin address"},
                            {"message", RPCArg::Type::STR, RPCArg::Optional::NO, "Signed message"},
                            {"signature", RPCArg::Type::STR, RPCArg::Optional::NO, "BIP-322 signature"},
                            {"asset_units", RPCArg::Type::NUM, RPCArg::Optional::NO, "Asset units in UTXO"},
                            {"asset_id", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Asset ID (hex)"},
                        },
                    },
                },
            },
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::BOOL, "success", "Whether post succeeded"},
                {RPCResult::Type::STR, "offer_id", "UUID of the created offer"},
                {RPCResult::Type::STR, "schema", "Payload schema identifier"},
                {RPCResult::Type::STR, "external_chain", "External chain (btc|ethereum|tron)"},
                {RPCResult::Type::STR, "adapter", "Adapter kind"},
                {RPCResult::Type::STR, "funding_order", "Funding order (tsc_first|external_first)"},
            }
        },
        RPCExamples{
            HelpExampleCli("cosign.post_cross_chain_offer", "\"{...payload_json...}\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            if (!cosign::g_bridge_manager.IsEnabled()) {
                throw JSONRPCError(RPC_MISC_ERROR, "COSIGN_DISABLED: Bridge not configured");
            }

            UniValue bridge_params(UniValue::VOBJ);
            bridge_params.pushKV("contract_payload", request.params[0].get_str());

            // Optional proof_of_funds
            if (request.params.size() > 1 && !request.params[1].isNull() && request.params[1].isArray()) {
                const UniValue& proof_array = request.params[1];
                if (proof_array.size() > 0) {
                    bridge_params.pushKV("proof_of_funds", proof_array);
                }
            }

            UniValue response = cosign::g_bridge_manager.SendBridgeCommand("post_cross_chain_offer", bridge_params);
            return response;
        }
    };
}

static RPCHelpMan cosign_validate_cross_chain_payload()
{
    return RPCHelpMan{"cosign.validate_cross_chain_payload",
        "Validate a cross-chain spot v1 payload without posting it.\n"
        "\nReturns validation result with detailed error if invalid.\n"
        "Useful for pre-flight checks before submitting an offer.",
        {
            {"contract_payload", RPCArg::Type::STR, RPCArg::Optional::NO,
                "Cross-chain spot v1 payload JSON to validate"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::BOOL, "valid", "Whether payload is valid"},
                {RPCResult::Type::STR, "error", /*optional=*/true, "Validation error message (if invalid)"},
                {RPCResult::Type::STR, "schema", /*optional=*/true, "Schema identifier (if valid)"},
                {RPCResult::Type::STR, "external_chain", /*optional=*/true, "External chain (if valid)"},
            }
        },
        RPCExamples{
            HelpExampleCli("cosign.validate_cross_chain_payload", "\"{...payload_json...}\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            if (!cosign::g_bridge_manager.IsEnabled()) {
                throw JSONRPCError(RPC_MISC_ERROR, "COSIGN_DISABLED: Bridge not configured");
            }

            UniValue bridge_params(UniValue::VOBJ);
            bridge_params.pushKV("contract_payload", request.params[0].get_str());

            UniValue response = cosign::g_bridge_manager.SendBridgeCommand("validate_cross_chain_payload", bridge_params);
            return response;
        }
    };
}

static RPCHelpMan cosign_list_cross_chain_offers()
{
    return RPCHelpMan{"cosign.list_cross_chain_offers",
        "List cross-chain settlement offers from the bulletin board.\n"
        "\nFilters SpotContract offers whose contract_payload contains\n"
        "schema == \"cross_chain_spot_v1\".",
        {
            {"external_chain", RPCArg::Type::STR, RPCArg::Optional::OMITTED,
                "Filter by external chain: btc|ethereum|tron"},
            {"adapter", RPCArg::Type::STR, RPCArg::Optional::OMITTED,
                "Filter by adapter: btc_scriptless_v1|eth_htlc_v1|tron_htlc_v1"},
            {"force_refresh", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED,
                "Re-fetch from Nostr relays first (default: false)"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::BOOL, "success", "Whether listing succeeded"},
                {RPCResult::Type::NUM, "count", "Number of cross-chain offers"},
                {RPCResult::Type::ARR, "offers", "Cross-chain offers",
                    {
                        {RPCResult::Type::OBJ, "", "",
                            {
                                {RPCResult::Type::STR, "offer_id", "Offer UUID"},
                                {RPCResult::Type::STR, "maker_pubkey", "Maker Nostr pubkey"},
                                {RPCResult::Type::STR, "network", "Network"},
                                {RPCResult::Type::OBJ, "cross_chain_payload", "Parsed cross-chain payload",
                                    {
                                        {RPCResult::Type::STR, "schema", "Schema identifier"},
                                        {RPCResult::Type::STR, "funding_order", "Funding order"},
                                    }
                                },
                            }
                        },
                    }
                },
            }
        },
        RPCExamples{
            HelpExampleCli("cosign.list_cross_chain_offers", "")
            + HelpExampleCli("cosign.list_cross_chain_offers", "\"btc\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            if (!cosign::g_bridge_manager.IsEnabled()) {
                throw JSONRPCError(RPC_MISC_ERROR, "COSIGN_DISABLED: Bridge not configured");
            }

            UniValue bridge_params(UniValue::VOBJ);

            if (!request.params[0].isNull()) {
                bridge_params.pushKV("external_chain", request.params[0].get_str());
            }
            if (!request.params[1].isNull()) {
                bridge_params.pushKV("adapter", request.params[1].get_str());
            }
            if (!request.params[2].isNull()) {
                bridge_params.pushKV("force_refresh", request.params[2].get_bool());
            }

            UniValue response = cosign::g_bridge_manager.SendBridgeCommand("list_cross_chain_offers", bridge_params);
            return response;
        }
    };
}

// ============================================================================
// GOVERNANCE COMMANDS
// ============================================================================

static RPCHelpMan cosign_publish_governance()
{
    return RPCHelpMan{"cosign.publish_governance",
        "Publish a governance proposal to the bulletin board.\n"
        "\nSee docs/governance_schema.json for complete proposal structure.",
        {
            {"proposal", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Governance proposal",
                {
                    {"asset_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Asset ID"},
                    {"icu_txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "ICU UTXO transaction ID"},
                    {"icu_vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "ICU UTXO output index"},
                    {"icu_attestation", RPCArg::Type::OBJ, RPCArg::Optional::NO, "BIP-322 attestation",
                        {
                            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "ICU address"},
                            {"message", RPCArg::Type::STR, RPCArg::Optional::NO, "Signed message"},
                            {"signature", RPCArg::Type::STR, RPCArg::Optional::NO, "BIP-322 signature"},
                        },
                    },
                    {"current_policy", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Current policy params",
                        {
                            {"policy_quorum_bps", RPCArg::Type::NUM, RPCArg::Optional::NO, "Quorum in basis points"},
                            {"issuance_cap_units", RPCArg::Type::NUM, RPCArg::Optional::NO, "Issuance cap"},
                            {"policy_epoch", RPCArg::Type::NUM, RPCArg::Optional::NO, "Policy epoch"},
                        },
                    },
                    {"proposed_policy", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Proposed changes",
                        {
                            {"policy_quorum_bps", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "New quorum"},
                            {"issuance_cap_units", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "New cap"},
                        },
                    },
                    {"template_psbt_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "SHA256 of template PSBT"},
                    {"expires_at", RPCArg::Type::NUM, RPCArg::Optional::NO, "Unix timestamp expiry"},
                    {"flow_type", RPCArg::Type::STR, RPCArg::Optional::NO, "\"public\" or \"private\""},
                    {"icu_text", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Governance text (required for public)"},
                    {"canonical_icu_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "SHA256 of ICU text"},
                    {"metadata", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Optional metadata",
                        {
                            {"title", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Proposal title"},
                            {"description", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Description"},
                            {"discussion_url", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Discussion URL"},
                        },
                    },
                },
            },
            {"rate_limit_secs", RPCArg::Type::NUM, RPCArg::Default{3600}, "Rate limit in seconds (default: 3600)"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "proposal_id", "Unique proposal identifier"},
            }
        },
        RPCExamples{
            HelpExampleCli("cosign.publish_governance", "\"{\\\"asset_id\\\":\\\"...\\\", ...}\"")
            + HelpExampleRpc("cosign.publish_governance", "\"{\\\"asset_id\\\":\\\"...\\\", ...}\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            if (!cosign::g_bridge_manager.IsEnabled()) {
                throw JSONRPCError(RPC_MISC_ERROR, "COSIGN_DISABLED: Bridge not configured");
            }

            // SECURITY: Verify BIP-322 attestation BEFORE accepting the proposal
            const UniValue& proposal = request.params[0];

            if (!proposal.exists("icu_attestation") || !proposal["icu_attestation"].isObject()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Missing or invalid icu_attestation");
            }

            const UniValue& attestation = proposal["icu_attestation"];
            if (!attestation.exists("address") || !attestation.exists("signature") || !attestation.exists("message")) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "ICU attestation missing required fields (address, signature, message)");
            }

            std::string address = attestation["address"].get_str();
            std::string signature = attestation["signature"].get_str();
            std::string message = attestation["message"].get_str();

            // Verify expected message format: "TENSORCASH_GOVERNANCE:{proposal_id}"
            if (!proposal.exists("proposal_id")) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Missing proposal_id");
            }
            std::string proposal_id = proposal["proposal_id"].get_str();
            std::string expected_message = "TENSORCASH_GOVERNANCE:" + proposal_id;

            if (message != expected_message) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    strprintf("ICU attestation message mismatch: expected '%s', got '%s'", expected_message, message));
            }

            // Verify BIP-322 signature proves ICU ownership
            JSONRPCRequest verify_request;
            verify_request.context = request.context;
            verify_request.strMethod = "verifymessagebip322";
            verify_request.URI = "/";
            verify_request.params = UniValue(UniValue::VARR);
            verify_request.params.push_back(address);
            verify_request.params.push_back(signature);
            verify_request.params.push_back(message);

            UniValue verify_result;
            try {
                verify_result = ::tableRPC.execute(verify_request);
            } catch (const std::exception& e) {
                throw JSONRPCError(RPC_VERIFY_ERROR,
                    strprintf("BIP-322 verification failed: %s", e.what()));
            }

            if (!verify_result.isBool() || !verify_result.get_bool()) {
                throw JSONRPCError(RPC_VERIFY_ERROR,
                    "BIP-322 signature verification failed: ICU ownership not proven");
            }

            // Verification passed - forward to bridge
            UniValue bridge_params(UniValue::VOBJ);
            bridge_params.pushKV("proposal", request.params[0]);

            if (!request.params[1].isNull()) {
                bridge_params.pushKV("rate_limit_secs", request.params[1].getInt<int>());
            }

            UniValue response = cosign::g_bridge_manager.SendBridgeCommand("publish_governance", bridge_params);
            return response;
        }
    };
}

static RPCHelpMan cosign_list_governance()
{
    return RPCHelpMan{"cosign.list_governance",
        "List governance proposals from the bulletin board.",
        {
            {"asset_id", RPCArg::Type::STR_HEX, RPCArg::Default{""}, "Filter by asset ID (empty = all)"},
            {"include_expired", RPCArg::Type::BOOL, RPCArg::Default{false}, "Include expired proposals"},
        },
        RPCResult{
            RPCResult::Type::ARR, "", "",
            {
                {RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::STR_HEX, "proposal_id", "Proposal ID"},
                    {RPCResult::Type::STR_HEX, "asset_id", "Asset ID"},
                    {RPCResult::Type::STR, "issuer_nostr_pubkey", "Issuer Nostr pubkey"},
                    {RPCResult::Type::NUM, "created_at", "Unix timestamp"},
                    {RPCResult::Type::NUM, "expires_at", "Unix timestamp"},
                    {RPCResult::Type::STR, "flow_type", "\"public\" or \"private\""},
                    {RPCResult::Type::STR, "title", "Proposal title (if set)"},
                    {RPCResult::Type::BOOL, "is_expired", "Whether expired"},
                    {RPCResult::Type::STR, "policy_changes", "Human-readable summary"},
                }},
            }
        },
        RPCExamples{
            HelpExampleCli("cosign.list_governance", "")
            + HelpExampleCli("cosign.list_governance", "\"1234567890abcdef...\"")
            + HelpExampleCli("cosign.list_governance", "\"\" true")
            + HelpExampleRpc("cosign.list_governance", "\"\", false")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            if (!cosign::g_bridge_manager.IsEnabled()) {
                throw JSONRPCError(RPC_MISC_ERROR, "COSIGN_DISABLED: Bridge not configured");
            }

            // Parse arguments
            UniValue bridge_params(UniValue::VOBJ);

            if (!request.params[0].isNull() && !request.params[0].get_str().empty()) {
                bridge_params.pushKV("asset_id", request.params[0].get_str());
            }

            if (!request.params[1].isNull()) {
                bridge_params.pushKV("include_expired", request.params[1].get_bool());
            }

            UniValue response = cosign::g_bridge_manager.SendBridgeCommand("list_governance", bridge_params);

            // Extract proposals array from response object (bridge wraps it due to serde flatten)
            if (response.isObject() && response.exists("proposals")) {
                return response["proposals"];
            }
            return response;
        }
    };
}

static RPCHelpMan cosign_get_governance()
{
    return RPCHelpMan{"cosign.get_governance",
        "Get a specific governance proposal by ID.",
        {
            {"proposal_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Proposal ID"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "proposal_id", "Full governance proposal (see docs/governance_schema.json)"},
            }
        },
        RPCExamples{
            HelpExampleCli("cosign.get_governance", "\"a1b2c3d4e5f6...\"")
            + HelpExampleRpc("cosign.get_governance", "\"a1b2c3d4e5f6...\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            if (!cosign::g_bridge_manager.IsEnabled()) {
                throw JSONRPCError(RPC_MISC_ERROR, "COSIGN_DISABLED: Bridge not configured");
            }

            // Parse arguments
            UniValue bridge_params(UniValue::VOBJ);
            bridge_params.pushKV("proposal_id", request.params[0].get_str());

            UniValue response = cosign::g_bridge_manager.SendBridgeCommand("get_governance", bridge_params);
            return response;
        }
    };
}

static RPCHelpMan cosign_force_refresh_governance()
{
    return RPCHelpMan{"cosign.force_refresh_governance",
        "Force refresh governance proposals from Nostr relays (bypasses 5-minute cache).",
        {},
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::BOOL, "success", "Whether refresh succeeded"},
            }
        },
        RPCExamples{
            HelpExampleCli("cosign.force_refresh_governance", "")
            + HelpExampleRpc("cosign.force_refresh_governance", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            if (!cosign::g_bridge_manager.IsEnabled()) {
                throw JSONRPCError(RPC_MISC_ERROR, "COSIGN_DISABLED: Bridge not configured");
            }

            UniValue bridge_params(UniValue::VOBJ);
            UniValue response = cosign::g_bridge_manager.SendBridgeCommand("force_refresh_governance", bridge_params);
            return response;
        }
    };
}

static RPCHelpMan cosign_publish_ballot()
{
    return RPCHelpMan{"cosign.publish_ballot",
        "Publish a signed ballot (holder's vote) to the bulletin board.\n"
        "Holders call this after signing a governance PSBT with the ballot RPC.",
        {
            {"ballot", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Ballot object",
                {
                    {"proposal_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Proposal ID being voted on"},
                    {"asset_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Asset ID"},
                    {"signed_psbt", RPCArg::Type::STR, RPCArg::Optional::NO, "Signed PSBT with holder's ballot inputs"},
                    {"ballot_units", RPCArg::Type::NUM, RPCArg::Optional::NO, "Voting units contributed"},
                }
            },
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "ballot_id", "Unique ballot identifier"},
                {RPCResult::Type::STR, "nostr_event_id", "Nostr event ID where ballot was published"},
            }
        },
        RPCExamples{
            HelpExampleCli("cosign.publish_ballot", "\"{\\\"proposal_id\\\":\\\"...\\\", \\\"signed_psbt\\\":\\\"...\\\", \\\"ballot_units\\\":100}\"")
            + HelpExampleRpc("cosign.publish_ballot", "\"{\\\"proposal_id\\\":\\\"...\\\", \\\"signed_psbt\\\":\\\"...\\\", \\\"ballot_units\\\":100}\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            if (!cosign::g_bridge_manager.IsEnabled()) {
                throw JSONRPCError(RPC_MISC_ERROR, "COSIGN_DISABLED: Bridge not configured");
            }

            const UniValue& ballot = request.params[0];

            // Validate required fields
            if (!ballot.exists("proposal_id") || !ballot.exists("signed_psbt") || !ballot.exists("ballot_units")) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Ballot missing required fields (proposal_id, signed_psbt, ballot_units)");
            }

            // Forward to bridge
            UniValue bridge_params(UniValue::VOBJ);
            bridge_params.pushKV("ballot", ballot);

            UniValue response = cosign::g_bridge_manager.SendBridgeCommand("publish_ballot", bridge_params);
            return response;
        }
    };
}

static RPCHelpMan cosign_list_ballots()
{
    return RPCHelpMan{"cosign.list_ballots",
        "List ballots (holder votes) for a governance proposal.",
        {
            {"proposal_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Proposal ID to get ballots for"},
        },
        RPCResult{
            RPCResult::Type::ARR, "", "",
            {
                {RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::STR, "proposal_id", "Proposal ID"},
                    {RPCResult::Type::STR, "signed_psbt", "Signed ballot PSBT"},
                    {RPCResult::Type::NUM, "ballot_units", "Voting units"},
                    {RPCResult::Type::NUM, "voter_timestamp", "Unix timestamp when ballot was signed"},
                }},
            }
        },
        RPCExamples{
            HelpExampleCli("cosign.list_ballots", "\"a1b2c3d4e5f6...\"")
            + HelpExampleRpc("cosign.list_ballots", "\"a1b2c3d4e5f6...\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            if (!cosign::g_bridge_manager.IsEnabled()) {
                throw JSONRPCError(RPC_MISC_ERROR, "COSIGN_DISABLED: Bridge not configured");
            }

            UniValue bridge_params(UniValue::VOBJ);
            bridge_params.pushKV("proposal_id", request.params[0].get_str());

            UniValue response = cosign::g_bridge_manager.SendBridgeCommand("list_ballots", bridge_params);
            return response;
        }
    };
}

static RPCHelpMan cosign_request_private_proposal()
{
    return RPCHelpMan{"cosign.request_private_proposal",
        "Request access to a private governance proposal via encrypted DM.\n"
        "\nHolder proves ownership of asset UTXOs via BIP-322 signature,\n"
        "and issuer responds with full proposal details (ICU text, template PSBT) via DM.",
        {
            {"proposal_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Proposal ID"},
            {"asset_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Asset ID"},
            {"issuer_nostr_pubkey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Issuer's Nostr public key"},
            {"holder_nostr_pubkey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Holder's Nostr public key"},
            {"ownership_proof", RPCArg::Type::OBJ, RPCArg::Optional::NO, "BIP-322 ownership proof",
                {
                    {"utxo_ref", RPCArg::Type::STR, RPCArg::Optional::NO, "UTXO reference (txid:vout)"},
                    {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "Bitcoin address"},
                    {"message", RPCArg::Type::STR, RPCArg::Optional::NO, "Message: TENSORCASH_HOLDER:{proposal_id}:{holder_pubkey}"},
                    {"signature", RPCArg::Type::STR, RPCArg::Optional::NO, "BIP-322 signature"},
                    {"asset_units", RPCArg::Type::NUM, RPCArg::Optional::NO, "Asset units in UTXO"},
                },
            },
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "session_id", "Governance session ID"},
                {RPCResult::Type::STR, "status", "Request status"},
                {RPCResult::Type::STR, "message", "Status message"},
            }
        },
        RPCExamples{
            HelpExampleCli("cosign.request_private_proposal", "\"a1b2c3...\" \"def456...\" \"789abc...\" \"{\\\"utxo_ref\\\":\\\"txid:0\\\", ...}\"")
            + HelpExampleRpc("cosign.request_private_proposal", "\"a1b2c3...\", \"def456...\", \"789abc...\", {...}")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            if (!cosign::g_bridge_manager.IsEnabled()) {
                throw JSONRPCError(RPC_MISC_ERROR, "COSIGN_DISABLED: Bridge not configured");
            }

            std::string proposal_id = request.params[0].get_str();
            std::string asset_id = request.params[1].get_str();
            std::string issuer_nostr_pubkey = request.params[2].get_str();
            std::string holder_nostr_pubkey = request.params[3].get_str();
            const UniValue& ownership_proof = request.params[4];

            // Validate ownership proof structure
            if (!ownership_proof.exists("utxo_ref") || !ownership_proof.exists("address") ||
                !ownership_proof.exists("message") || !ownership_proof.exists("signature") ||
                !ownership_proof.exists("asset_units")) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "ownership_proof missing required fields (utxo_ref, address, message, signature, asset_units)");
            }

            // SECURITY: Verify BIP-322 signature BEFORE sending to bridge
            // This prevents unauthorized access to private governance proposals
            std::string address = ownership_proof["address"].get_str();
            std::string message = ownership_proof["message"].get_str();
            std::string signature = ownership_proof["signature"].get_str();

            // Verify message format: TENSORCASH_HOLDER:{proposal_id}:{holder_nostr_pubkey}
            std::string expected_message = "TENSORCASH_HOLDER:" + proposal_id + ":" + holder_nostr_pubkey;
            if (message != expected_message) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    strprintf("Invalid ownership proof message. Expected 'TENSORCASH_HOLDER:%s:%s'", proposal_id, holder_nostr_pubkey));
            }

            // Verify BIP-322 signature using tableRPC
            JSONRPCRequest verify_request;
            verify_request.context = request.context;
            verify_request.strMethod = "verifymessagebip322";
            verify_request.params = UniValue(UniValue::VARR);
            verify_request.params.push_back(address);
            verify_request.params.push_back(signature);
            verify_request.params.push_back(message);

            UniValue verify_result;
            try {
                verify_result = ::tableRPC.execute(verify_request);
            } catch (const std::exception& e) {
                throw JSONRPCError(RPC_VERIFY_ERROR,
                    strprintf("BIP-322 verification failed: %s", e.what()));
            }

            // verifymessagebip322 returns bool
            if (!verify_result.isBool() || !verify_result.get_bool()) {
                throw JSONRPCError(RPC_VERIFY_REJECTED,
                    "BIP-322 signature verification failed. Cannot request private proposal without valid ownership proof.");
            }

            // CRITICAL SECURITY: Verify the UTXO actually holds the asset
            // BIP-322 only proves address ownership, not asset ownership!
            std::string utxo_ref = ownership_proof["utxo_ref"].get_str();
            uint64_t claimed_units = ownership_proof["asset_units"].getInt<uint64_t>();

            // Parse utxo_ref (format: "txid:vout")
            size_t colon_pos = utxo_ref.find(':');
            if (colon_pos == std::string::npos) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid utxo_ref format (expected 'txid:vout')");
            }

            std::string txid_str = utxo_ref.substr(0, colon_pos);
            std::string vout_str = utxo_ref.substr(colon_pos + 1);
            int vout = std::stoi(vout_str);

            // Call listassetutxos to verify UTXO contains the asset
            // (gettxout doesn't return asset data, only BTC value and scriptPubKey)
            JSONRPCRequest listassets_req;
            listassets_req.context = request.context;
            listassets_req.strMethod = "listassetutxos";
            listassets_req.params = UniValue(UniValue::VARR);
            UniValue assets_filter(UniValue::VARR);
            assets_filter.push_back(asset_id);
            listassets_req.params.push_back(assets_filter);

            UniValue utxos_result;
            try {
                utxos_result = ::tableRPC.execute(listassets_req);
            } catch (const std::exception& e) {
                throw JSONRPCError(RPC_VERIFY_ERROR,
                    strprintf("Failed to list asset UTXOs: %s", e.what()));
            }

            // Find the specific UTXO in the list
            bool utxo_found = false;
            uint64_t actual_units = 0;
            std::string actual_address;

            if (utxos_result.isArray()) {
                for (size_t i = 0; i < utxos_result.size(); i++) {
                    const UniValue& utxo = utxos_result[i];
                    if (utxo["txid"].get_str() == txid_str && utxo["vout"].getInt<int>() == vout) {
                        utxo_found = true;
                        actual_units = utxo["asset_units"].getInt<uint64_t>();
                        if (utxo.exists("address")) {
                            actual_address = utxo["address"].get_str();
                        }
                        break;
                    }
                }
            }

            if (!utxo_found) {
                throw JSONRPCError(RPC_VERIFY_REJECTED,
                    strprintf("UTXO %s does not contain asset %s (not found in wallet or spent)", utxo_ref, asset_id));
            }

            // Verify UTXO is at claimed address
            if (!actual_address.empty() && actual_address != address) {
                throw JSONRPCError(RPC_VERIFY_REJECTED,
                    strprintf("UTXO %s is at address %s, not claimed address %s", utxo_ref, actual_address, address));
            }

            // Verify UTXO contains at least the claimed asset units
            if (actual_units < claimed_units) {
                throw JSONRPCError(RPC_VERIFY_REJECTED,
                    strprintf("UTXO %s contains only %d units, but %d units were claimed",
                              utxo_ref, actual_units, claimed_units));
            }

            // All security checks passed - forward to bridge
            UniValue bridge_params(UniValue::VOBJ);
            bridge_params.pushKV("proposal_id", proposal_id);
            bridge_params.pushKV("asset_id", asset_id);
            bridge_params.pushKV("issuer_nostr_pubkey", issuer_nostr_pubkey);
            bridge_params.pushKV("holder_nostr_pubkey", holder_nostr_pubkey);
            bridge_params.pushKV("ownership_proof", ownership_proof);

            UniValue response = cosign::g_bridge_manager.SendBridgeCommand("request_private_proposal", bridge_params);
            return response;
        }
    };
}

static RPCHelpMan cosign_send_governance_ballot_dm()
{
    return RPCHelpMan{"cosign.send_governance_ballot_dm",
        "Submit a signed governance ballot via encrypted DM (private flow).\n"
        "\nUsed instead of cosign.publish_ballot for private governance proposals.",
        {
            {"proposal_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Proposal ID"},
            {"asset_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Asset ID"},
            {"issuer_nostr_pubkey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Issuer's Nostr public key"},
            {"signed_psbt", RPCArg::Type::STR, RPCArg::Optional::NO, "Signed ballot PSBT"},
            {"ballot_units", RPCArg::Type::NUM, RPCArg::Optional::NO, "Voting units"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "ballot_id", "Ballot ID (receipt from issuer)"},
                {RPCResult::Type::NUM, "units_accepted", "Units accepted by issuer"},
                {RPCResult::Type::STR, "status", "Submission status"},
                {RPCResult::Type::OBJ, "quorum_status", "Current quorum status (if available)",
                {
                    {RPCResult::Type::NUM, "total_voted_units", "Total units voted"},
                    {RPCResult::Type::NUM, "settled_supply", "Total settled supply"},
                    {RPCResult::Type::NUM, "quorum_bps", "Quorum threshold (basis points)"},
                    {RPCResult::Type::BOOL, "quorum_reached", "Whether quorum has been reached"},
                }},
            }
        },
        RPCExamples{
            HelpExampleCli("cosign.send_governance_ballot_dm", "\"a1b2c3...\" \"def456...\" \"789abc...\" \"cHNidP8B...\" 1000")
            + HelpExampleRpc("cosign.send_governance_ballot_dm", "\"a1b2c3...\", \"def456...\", \"789abc...\", \"cHNidP8B...\", 1000")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            if (!cosign::g_bridge_manager.IsEnabled()) {
                throw JSONRPCError(RPC_MISC_ERROR, "COSIGN_DISABLED: Bridge not configured");
            }

            std::string proposal_id = request.params[0].get_str();
            std::string asset_id = request.params[1].get_str();
            std::string issuer_nostr_pubkey = request.params[2].get_str();
            std::string signed_psbt = request.params[3].get_str();
            int64_t ballot_units = request.params[4].getInt<int64_t>();

            if (ballot_units <= 0) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "ballot_units must be greater than 0");
            }

            // Forward to bridge
            UniValue bridge_params(UniValue::VOBJ);
            bridge_params.pushKV("proposal_id", proposal_id);
            bridge_params.pushKV("asset_id", asset_id);
            bridge_params.pushKV("issuer_nostr_pubkey", issuer_nostr_pubkey);
            bridge_params.pushKV("signed_psbt", signed_psbt);
            bridge_params.pushKV("ballot_units", ballot_units);

            UniValue response = cosign::g_bridge_manager.SendBridgeCommand("send_governance_ballot_dm", bridge_params);
            return response;
        }
    };
}

// PR3: Issuer-side DM processing
static RPCHelpMan cosign_process_governance_dms()
{
    return RPCHelpMan{"cosign.process_governance_dms",
        "Process incoming governance DMs (access requests, ballots, receipts).\n"
        "\nIssuer-side: Check for holder access requests and verify ownership proofs.\n"
        "Holder-side: Check for proposal responses and ballot receipts.",
        {
            {"since", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Fetch DMs since this timestamp (default: last hour)"},
            {"auto_approve", RPCArg::Type::BOOL, RPCArg::Default{false}, "Automatically send responses to verified holders (default: false, manual approval required)"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::ARR, "access_requests", "Holder requests for private proposals",
                    {
                        {RPCResult::Type::OBJ, "", "",
                            {
                                {RPCResult::Type::STR, "proposal_id", "Proposal ID"},
                                {RPCResult::Type::STR, "asset_id", "Asset ID"},
                                {RPCResult::Type::STR, "holder_nostr_pubkey", "Holder's nostr pubkey"},
                                {RPCResult::Type::STR, "utxo_ref", "UTXO reference (txid:vout)"},
                                {RPCResult::Type::NUM, "asset_units", "Asset units in UTXO"},
                                {RPCResult::Type::BOOL, "ownership_verified", "Whether BIP-322 signature verified"},
                                {RPCResult::Type::STR, "from_pubkey", "Sender's nostr pubkey"},
                            }
                        }
                    }
                },
                {RPCResult::Type::ARR, "proposal_responses", "Issuer responses with full proposal",
                    {
                        {RPCResult::Type::OBJ, "", "",
                            {
                                {RPCResult::Type::STR, "proposal_id", "Proposal ID"},
                                {RPCResult::Type::STR, "icu_text", "Full ICU governance text"},
                                {RPCResult::Type::STR, "template_psbt", "Template PSBT for voting"},
                            }
                        }
                    }
                },
                {RPCResult::Type::ARR, "ballot_dms", "Private ballot submissions",
                    {
                        {RPCResult::Type::OBJ, "", "",
                            {
                                {RPCResult::Type::STR, "proposal_id", "Proposal ID"},
                                {RPCResult::Type::STR, "signed_psbt", "Signed ballot PSBT"},
                                {RPCResult::Type::NUM, "ballot_units", "Voting units"},
                            }
                        }
                    }
                },
                {RPCResult::Type::ARR, "ballot_receipts", "Issuer ballot receipts",
                    {
                        {RPCResult::Type::OBJ, "", "",
                            {
                                {RPCResult::Type::STR, "ballot_id", "Ballot ID"},
                                {RPCResult::Type::NUM, "units_accepted", "Units accepted"},
                                {RPCResult::Type::BOOL, "quorum_reached", "Whether quorum reached"},
                            }
                        }
                    }
                },
            }
        },
        RPCExamples{
            HelpExampleCli("cosign.process_governance_dms", "")
            + HelpExampleRpc("cosign.process_governance_dms", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            if (!cosign::g_bridge_manager.IsEnabled()) {
                throw JSONRPCError(RPC_MISC_ERROR, "COSIGN_DISABLED: Bridge not configured");
            }

            // Get optional 'since' timestamp
            UniValue bridge_params(UniValue::VOBJ);
            if (!request.params[0].isNull()) {
                bridge_params.pushKV("since", request.params[0].getInt<int64_t>());
            }

            // Get optional 'auto_approve' flag (default: false)
            bool auto_approve = false;
            if (request.params.size() > 1 && !request.params[1].isNull()) {
                auto_approve = request.params[1].get_bool();
            }

            // Call bridge to process DMs
            UniValue response = cosign::g_bridge_manager.SendBridgeCommand("process_governance_dms", bridge_params);

            // For access requests, verify BIP-322 signatures on the RPC layer
            if (response.exists("access_requests") && response["access_requests"].isArray()) {
                const UniValue& requests_const = response["access_requests"];
                UniValue verified_requests(UniValue::VARR);

                for (size_t i = 0; i < requests_const.size(); i++) {
                    UniValue req = requests_const[i];  // Make a mutable copy

                    if (req.exists("ownership_proof")) {
                        const UniValue& proof = req["ownership_proof"];
                        if (proof.exists("address") && proof.exists("signature") && proof.exists("message") &&
                            proof.exists("utxo_ref") && proof.exists("asset_units") && req.exists("asset_id")) {

                            std::string address = proof["address"].get_str();
                            std::string signature = proof["signature"].get_str();
                            std::string message = proof["message"].get_str();
                            std::string utxo_ref = proof["utxo_ref"].get_str();
                            uint64_t claimed_units = proof["asset_units"].getInt<uint64_t>();
                            std::string asset_id = req["asset_id"].get_str();

                            // Use shared strict verifier (confirmed UTXOs only + bestblock chain binding)
                            proof_verify::VerifyResult vr = proof_verify::VerifyOwnershipProof(
                                ::tableRPC, request.context,
                                utxo_ref, address, message, signature,
                                asset_id, claimed_units);

                            req.pushKV("ownership_verified", vr.verified);
                            if (!vr.error.empty()) {
                                req.pushKV("verification_error", vr.error);
                            }
                            if (vr.verified) {
                                req.pushKV("verified_asset_units", vr.actual_units);
                            }
                        } else {
                            req.pushKV("ownership_verified", false);
                            req.pushKV("verification_error", "Missing proof fields");
                        }
                    } else {
                        req.pushKV("ownership_verified", false);
                        req.pushKV("verification_error", "No ownership proof provided");
                    }

                    verified_requests.push_back(req);
                }

                // Replace access_requests with verified version
                response.pushKV("access_requests", verified_requests);

                // PR3: Auto-send proposal responses for verified requests (only if auto_approve is enabled)
                UniValue auto_sent(UniValue::VARR);

                if (auto_approve) {
                    LogPrintf("Auto-approve enabled: processing %d verified requests\n", verified_requests.size());
                for (size_t i = 0; i < verified_requests.size(); i++) {
                    const UniValue& req = verified_requests[i];

                    if (!req.exists("ownership_verified") || !req["ownership_verified"].get_bool()) {
                        continue;  // Skip unverified requests
                    }

                    std::string proposal_id = req["proposal_id"].get_str();
                    std::string holder_pubkey = req["holder_nostr_pubkey"].get_str();

                    try {
                        // SECURITY: Fetch private payload from issuer's cache (not Nostr)
                        // For private proposals, sensitive fields are never published to Nostr.
                        // They're cached during publish_governance and retrieved here for verified holders.
                        UniValue bridge_payload_params(UniValue::VOBJ);
                        bridge_payload_params.pushKV("proposal_id", proposal_id);

                        UniValue private_payload;
                        try {
                            private_payload = cosign::g_bridge_manager.SendBridgeCommand("get_private_payload", bridge_payload_params);
                        } catch (const std::exception& e) {
                            LogPrintf("Auto-send skipped for %s: private payload not available (%s)\n",
                                      proposal_id, e.what());
                            continue;
                        }

                        if (private_payload.isNull()) {
                            LogPrintf("Auto-send skipped for %s: private payload returned null\n", proposal_id);
                            continue;
                        }

                        // Validate that payload has substantive content
                        bool has_content = (private_payload.exists("icu_text") && private_payload["icu_text"].isStr() && !private_payload["icu_text"].get_str().empty()) ||
                                          (private_payload.exists("template_psbt") && private_payload["template_psbt"].isStr() && !private_payload["template_psbt"].get_str().empty());

                        if (!has_content) {
                            LogPrintf("Auto-send skipped for %s: private payload exists but contains no icu_text or template_psbt\n", proposal_id);
                            continue;
                        }

                        // Build GovernanceProposalResponse payload from cached private data
                        UniValue response_payload(UniValue::VOBJ);
                        response_payload.pushKV("version", 1);
                        response_payload.pushKV("proposal_id", proposal_id);

                        if (private_payload.exists("icu_text") && private_payload["icu_text"].isStr()) {
                            response_payload.pushKV("icu_text", private_payload["icu_text"].get_str());
                        }
                        if (private_payload.exists("canonical_icu_hash") && private_payload["canonical_icu_hash"].isStr()) {
                            response_payload.pushKV("canonical_icu_hash", private_payload["canonical_icu_hash"].get_str());
                        }
                        if (private_payload.exists("witness_bundle") && private_payload["witness_bundle"].isStr()) {
                            response_payload.pushKV("witness_bundle", private_payload["witness_bundle"].get_str());
                        }
                        if (private_payload.exists("witness_bundle_hash") && private_payload["witness_bundle_hash"].isStr()) {
                            response_payload.pushKV("witness_bundle_hash", private_payload["witness_bundle_hash"].get_str());
                        }
                        if (private_payload.exists("template_psbt") && private_payload["template_psbt"].isStr()) {
                            response_payload.pushKV("template_psbt", private_payload["template_psbt"].get_str());
                        }
                        if (private_payload.exists("template_psbt_hash") && private_payload["template_psbt_hash"].isStr()) {
                            response_payload.pushKV("template_psbt_hash", private_payload["template_psbt_hash"].get_str());
                        }
                        response_payload.pushKV("responded_at", (int64_t)time(nullptr));

                        // Call bridge send_proposal_response command
                        UniValue bridge_params(UniValue::VOBJ);
                        bridge_params.pushKV("holder_nostr_pubkey", holder_pubkey);
                        bridge_params.pushKV("response", response_payload);

                        UniValue send_result = cosign::g_bridge_manager.SendBridgeCommand("send_proposal_response", bridge_params);

                        // Track successful auto-send for audit log
                        UniValue sent_record(UniValue::VOBJ);
                        sent_record.pushKV("proposal_id", proposal_id);
                        sent_record.pushKV("holder_pubkey", holder_pubkey);
                        sent_record.pushKV("event_id", send_result["event_id"].get_str());
                        sent_record.pushKV("sent_at", (int64_t)time(nullptr));
                        auto_sent.push_back(sent_record);

                        LogPrintf("Auto-sent proposal %s to holder %s\n",
                                  proposal_id, holder_pubkey.substr(0, 16));

                    } catch (const std::exception& e) {
                        LogPrintf("Failed to auto-send proposal %s: %s\n", proposal_id, e.what());
                        // Continue processing other requests even if one fails
                    }
                }
                } else {
                    LogPrintf("Auto-approve disabled: manual approval required for %d verified requests\n", verified_requests.size());
                }

                // Add audit log to response
                response.pushKV("auto_sent_responses", auto_sent);
            }

            return response;
        }
    };
}

// PR3: Manual proposal response (issuer approval/denial)
static RPCHelpMan cosign_send_proposal_response_manual()
{
    return RPCHelpMan{"cosign.send_proposal_response_manual",
        "Manually approve or deny a private governance access request.\n"
        "\nIssuer use only. When approve=true, sends full proposal details to verified holder.\n"
        "When approve=false, no response is sent (denial by silence).",
        {
            {"proposal_id", RPCArg::Type::STR, RPCArg::Optional::NO, "Proposal ID to respond to"},
            {"holder_pubkey", RPCArg::Type::STR, RPCArg::Optional::NO, "Holder's nostr pubkey (from access request)"},
            {"approve", RPCArg::Type::BOOL, RPCArg::Default{true}, "Approve (true) or deny (false) the request"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::BOOL, "success", "Whether the operation succeeded"},
                {RPCResult::Type::STR, "action", "Action taken: 'approved' or 'denied'"},
                {RPCResult::Type::STR, "event_id", /*optional=*/true, "Nostr event ID (if approved)"},
                {RPCResult::Type::NUM, "sent_at", /*optional=*/true, "Timestamp when sent (if approved)"},
            }
        },
        RPCExamples{
            HelpExampleCli("cosign.send_proposal_response_manual", "\"prop123...\" \"npub1...\" true")
            + HelpExampleRpc("cosign.send_proposal_response_manual", "\"prop123...\", \"npub1...\", true")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            if (!cosign::g_bridge_manager.IsEnabled()) {
                throw JSONRPCError(RPC_MISC_ERROR, "COSIGN_DISABLED: Bridge not configured");
            }

            // Parse parameters
            std::string proposal_id = request.params[0].get_str();
            std::string holder_pubkey = request.params[1].get_str();
            bool approve = request.params.size() > 2 ? request.params[2].get_bool() : true;

            UniValue result(UniValue::VOBJ);

            // If deny, just return success without sending anything
            if (!approve) {
                result.pushKV("success", true);
                result.pushKV("action", "denied");
                LogPrintf("Manual denial: proposal %s for holder %s\n",
                          proposal_id, holder_pubkey.substr(0, 16));
                return result;
            }

            // Approve: fetch private payload and send to holder
            try {
                // Fetch private payload from issuer's cache
                UniValue bridge_payload_params(UniValue::VOBJ);
                bridge_payload_params.pushKV("proposal_id", proposal_id);

                UniValue private_payload;
                try {
                    private_payload = cosign::g_bridge_manager.SendBridgeCommand("get_private_payload", bridge_payload_params);
                } catch (const std::exception& e) {
                    throw JSONRPCError(RPC_MISC_ERROR, strprintf("Private payload not available: %s", e.what()));
                }

                if (private_payload.isNull()) {
                    throw JSONRPCError(RPC_MISC_ERROR, "Private payload not found for this proposal");
                }

                // Validate that payload has substantive content
                bool has_content = (private_payload.exists("icu_text") && private_payload["icu_text"].isStr() && !private_payload["icu_text"].get_str().empty()) ||
                                  (private_payload.exists("template_psbt") && private_payload["template_psbt"].isStr() && !private_payload["template_psbt"].get_str().empty());

                if (!has_content) {
                    throw JSONRPCError(RPC_MISC_ERROR, "Private payload exists but contains no icu_text or template_psbt");
                }

                // Build GovernanceProposalResponse payload from cached private data
                UniValue response_payload(UniValue::VOBJ);
                response_payload.pushKV("version", 1);
                response_payload.pushKV("proposal_id", proposal_id);

                if (private_payload.exists("icu_text") && private_payload["icu_text"].isStr()) {
                    response_payload.pushKV("icu_text", private_payload["icu_text"].get_str());
                }
                if (private_payload.exists("canonical_icu_hash") && private_payload["canonical_icu_hash"].isStr()) {
                    response_payload.pushKV("canonical_icu_hash", private_payload["canonical_icu_hash"].get_str());
                }
                if (private_payload.exists("witness_bundle") && private_payload["witness_bundle"].isStr()) {
                    response_payload.pushKV("witness_bundle", private_payload["witness_bundle"].get_str());
                }
                if (private_payload.exists("witness_bundle_hash") && private_payload["witness_bundle_hash"].isStr()) {
                    response_payload.pushKV("witness_bundle_hash", private_payload["witness_bundle_hash"].get_str());
                }
                if (private_payload.exists("template_psbt") && private_payload["template_psbt"].isStr()) {
                    response_payload.pushKV("template_psbt", private_payload["template_psbt"].get_str());
                }
                if (private_payload.exists("template_psbt_hash") && private_payload["template_psbt_hash"].isStr()) {
                    response_payload.pushKV("template_psbt_hash", private_payload["template_psbt_hash"].get_str());
                }
                response_payload.pushKV("responded_at", (int64_t)time(nullptr));

                // Call bridge send_proposal_response command
                UniValue bridge_params(UniValue::VOBJ);
                bridge_params.pushKV("holder_nostr_pubkey", holder_pubkey);
                bridge_params.pushKV("response", response_payload);

                UniValue send_result = cosign::g_bridge_manager.SendBridgeCommand("send_proposal_response", bridge_params);

                // Return success with event details
                result.pushKV("success", true);
                result.pushKV("action", "approved");
                result.pushKV("event_id", send_result["event_id"].get_str());
                result.pushKV("sent_at", (int64_t)time(nullptr));

                LogPrintf("Manual approval: sent proposal %s to holder %s\n",
                          proposal_id, holder_pubkey.substr(0, 16));

                return result;

            } catch (const std::exception& e) {
                throw JSONRPCError(RPC_MISC_ERROR, strprintf("Failed to send proposal response: %s", e.what()));
            }
        }
    };
}

// ============================================================================
// ETH ADAPTER COMMANDS
// ============================================================================

static RPCHelpMan cosign_eth_init()
{
    return RPCHelpMan{"cosign.eth_init",
        "Initialize the ETH JSON-RPC client in the cosign bridge.",
        {
            {"rpc_url", RPCArg::Type::STR, RPCArg::Optional::NO, "Ethereum JSON-RPC endpoint URL"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::BOOL, "success", "Whether initialization succeeded"},
            {RPCResult::Type::STR, "rpc_url", "Configured endpoint"},
        }},
        RPCExamples{HelpExampleCli("cosign.eth_init", "\"http://localhost:8545\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            if (!cosign::g_bridge_manager.IsEnabled())
                throw JSONRPCError(RPC_MISC_ERROR, "COSIGN_DISABLED: Bridge not configured");
            UniValue p(UniValue::VOBJ);
            p.pushKV("rpc_url", request.params[0].get_str());
            return cosign::g_bridge_manager.SendBridgeCommand("eth_init", p);
        }
    };
}

static RPCHelpMan cosign_eth_lock_htlc()
{
    return RPCHelpMan{"cosign.eth_lock_htlc",
        "Lock ETH or ERC-20 tokens into the HTLC contract.",
        {
            {"htlc_address", RPCArg::Type::STR, RPCArg::Optional::NO, "HTLC contract address"},
            {"swap_id", RPCArg::Type::STR, RPCArg::Optional::NO, "32-byte swap ID (hex)"},
            {"recipient", RPCArg::Type::STR, RPCArg::Optional::NO, "Recipient address"},
            {"secret_hash", RPCArg::Type::STR, RPCArg::Optional::NO, "sha256(secret) (hex)"},
            {"timelock", RPCArg::Type::NUM, RPCArg::Optional::NO, "Refund-eligible unix timestamp"},
            {"amount_wei", RPCArg::Type::STR, RPCArg::Optional::NO, "Amount in wei (hex)"},
            {"signing_key", RPCArg::Type::STR, RPCArg::Optional::NO, "32-byte private key (hex)"},
            {"token_address", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "ERC-20 token address (null for native ETH)"},
            {"gas_limit", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Gas limit (default 200000)"},
            {"max_fee_gwei", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Max fee in gwei (default 50)"},
            {"max_priority_fee_gwei", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Max priority fee in gwei (default 2)"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::BOOL, "success", "Whether broadcast succeeded"},
            {RPCResult::Type::STR, "tx_hash", "Transaction hash"},
            {RPCResult::Type::STR, "from", "Sender address"},
            {RPCResult::Type::NUM, "nonce", "Transaction nonce"},
        }},
        RPCExamples{HelpExampleCli("cosign.eth_lock_htlc",
            "\"0xHTLC\" \"0xSWAPID\" \"0xRECIPIENT\" \"0xSECRETHASH\" 1234567890 \"0xAMOUNT\" \"0xKEY\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            if (!cosign::g_bridge_manager.IsEnabled())
                throw JSONRPCError(RPC_MISC_ERROR, "COSIGN_DISABLED: Bridge not configured");
            UniValue p(UniValue::VOBJ);
            p.pushKV("htlc_address", request.params[0].get_str());
            p.pushKV("swap_id", request.params[1].get_str());
            p.pushKV("recipient", request.params[2].get_str());
            p.pushKV("secret_hash", request.params[3].get_str());
            p.pushKV("timelock", request.params[4].getInt<int64_t>());
            p.pushKV("amount_wei", request.params[5].get_str());
            p.pushKV("signing_key", request.params[6].get_str());
            if (request.params.size() > 7 && !request.params[7].isNull())
                p.pushKV("token_address", request.params[7].get_str());
            if (request.params.size() > 8 && !request.params[8].isNull())
                p.pushKV("gas_limit", request.params[8].getInt<int64_t>());
            if (request.params.size() > 9 && !request.params[9].isNull())
                p.pushKV("max_fee_gwei", request.params[9].getInt<int64_t>());
            if (request.params.size() > 10 && !request.params[10].isNull())
                p.pushKV("max_priority_fee_gwei", request.params[10].getInt<int64_t>());
            return cosign::g_bridge_manager.SendBridgeCommand("eth_lock_htlc", p);
        }
    };
}

static RPCHelpMan cosign_eth_claim_htlc()
{
    return RPCHelpMan{"cosign.eth_claim_htlc",
        "Claim locked HTLC funds by revealing the secret preimage.",
        {
            {"htlc_address", RPCArg::Type::STR, RPCArg::Optional::NO, "HTLC contract address"},
            {"swap_id", RPCArg::Type::STR, RPCArg::Optional::NO, "32-byte swap ID (hex)"},
            {"secret", RPCArg::Type::STR, RPCArg::Optional::NO, "32-byte secret preimage (hex)"},
            {"signing_key", RPCArg::Type::STR, RPCArg::Optional::NO, "32-byte private key (hex)"},
            {"gas_limit", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Gas limit (default 100000)"},
            {"max_fee_gwei", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Max fee in gwei (default 50)"},
            {"max_priority_fee_gwei", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Max priority fee in gwei (default 2)"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::BOOL, "success", "Whether broadcast succeeded"},
            {RPCResult::Type::STR, "tx_hash", "Transaction hash"},
            {RPCResult::Type::STR, "from", "Sender address"},
            {RPCResult::Type::STR, "secret_revealed", "The revealed secret"},
        }},
        RPCExamples{HelpExampleCli("cosign.eth_claim_htlc",
            "\"0xHTLC\" \"0xSWAPID\" \"0xSECRET\" \"0xKEY\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            if (!cosign::g_bridge_manager.IsEnabled())
                throw JSONRPCError(RPC_MISC_ERROR, "COSIGN_DISABLED: Bridge not configured");
            UniValue p(UniValue::VOBJ);
            p.pushKV("htlc_address", request.params[0].get_str());
            p.pushKV("swap_id", request.params[1].get_str());
            p.pushKV("secret", request.params[2].get_str());
            p.pushKV("signing_key", request.params[3].get_str());
            if (request.params.size() > 4 && !request.params[4].isNull())
                p.pushKV("gas_limit", request.params[4].getInt<int64_t>());
            if (request.params.size() > 5 && !request.params[5].isNull())
                p.pushKV("max_fee_gwei", request.params[5].getInt<int64_t>());
            if (request.params.size() > 6 && !request.params[6].isNull())
                p.pushKV("max_priority_fee_gwei", request.params[6].getInt<int64_t>());
            return cosign::g_bridge_manager.SendBridgeCommand("eth_claim_htlc", p);
        }
    };
}

static RPCHelpMan cosign_eth_refund_htlc()
{
    return RPCHelpMan{"cosign.eth_refund_htlc",
        "Refund locked HTLC funds after timelock expiry.",
        {
            {"htlc_address", RPCArg::Type::STR, RPCArg::Optional::NO, "HTLC contract address"},
            {"swap_id", RPCArg::Type::STR, RPCArg::Optional::NO, "32-byte swap ID (hex)"},
            {"signing_key", RPCArg::Type::STR, RPCArg::Optional::NO, "32-byte private key (hex)"},
            {"gas_limit", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Gas limit (default 100000)"},
            {"max_fee_gwei", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Max fee in gwei (default 50)"},
            {"max_priority_fee_gwei", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Max priority fee in gwei (default 2)"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::BOOL, "success", "Whether broadcast succeeded"},
            {RPCResult::Type::STR, "tx_hash", "Transaction hash"},
            {RPCResult::Type::STR, "from", "Sender address"},
        }},
        RPCExamples{HelpExampleCli("cosign.eth_refund_htlc",
            "\"0xHTLC\" \"0xSWAPID\" \"0xKEY\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            if (!cosign::g_bridge_manager.IsEnabled())
                throw JSONRPCError(RPC_MISC_ERROR, "COSIGN_DISABLED: Bridge not configured");
            UniValue p(UniValue::VOBJ);
            p.pushKV("htlc_address", request.params[0].get_str());
            p.pushKV("swap_id", request.params[1].get_str());
            p.pushKV("signing_key", request.params[2].get_str());
            if (request.params.size() > 3 && !request.params[3].isNull())
                p.pushKV("gas_limit", request.params[3].getInt<int64_t>());
            if (request.params.size() > 4 && !request.params[4].isNull())
                p.pushKV("max_fee_gwei", request.params[4].getInt<int64_t>());
            if (request.params.size() > 5 && !request.params[5].isNull())
                p.pushKV("max_priority_fee_gwei", request.params[5].getInt<int64_t>());
            return cosign::g_bridge_manager.SendBridgeCommand("eth_refund_htlc", p);
        }
    };
}

static RPCHelpMan cosign_eth_get_swap_status()
{
    return RPCHelpMan{"cosign.eth_get_swap_status",
        "Query HTLC swap state and confirmation depth from the Ethereum chain.",
        {
            {"htlc_address", RPCArg::Type::STR, RPCArg::Optional::NO, "HTLC contract address"},
            {"swap_id", RPCArg::Type::STR, RPCArg::Optional::NO, "32-byte swap ID (hex)"},
            {"lock_tx_hash", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Lock tx hash to check confirmations"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::BOOL, "success", "Whether query succeeded"},
            {RPCResult::Type::NUM, "state", "HTLC state: 0=empty, 1=locked, 2=claimed, 3=refunded"},
            {RPCResult::Type::STR, "state_name", "Human-readable state name"},
            {RPCResult::Type::STR, "sender", "Lock sender address"},
            {RPCResult::Type::STR, "recipient", "Lock recipient address"},
            {RPCResult::Type::STR, "token_address", "ERC-20 address or 0x0 for native ETH"},
            {RPCResult::Type::STR, "amount", "Locked amount (hex)"},
            {RPCResult::Type::STR, "secret_hash", "sha256(secret)"},
            {RPCResult::Type::NUM, "timelock", "Refund-eligible timestamp"},
            {RPCResult::Type::NUM, "confirmation_depth", "Confirmations of lock tx (null if not provided)"},
        }},
        RPCExamples{HelpExampleCli("cosign.eth_get_swap_status",
            "\"0xHTLC\" \"0xSWAPID\" \"0xLOCKTXHASH\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            if (!cosign::g_bridge_manager.IsEnabled())
                throw JSONRPCError(RPC_MISC_ERROR, "COSIGN_DISABLED: Bridge not configured");
            UniValue p(UniValue::VOBJ);
            p.pushKV("htlc_address", request.params[0].get_str());
            p.pushKV("swap_id", request.params[1].get_str());
            if (request.params.size() > 2 && !request.params[2].isNull())
                p.pushKV("lock_tx_hash", request.params[2].get_str());
            return cosign::g_bridge_manager.SendBridgeCommand("eth_get_swap_status", p);
        }
    };
}

static RPCHelpMan cosign_eth_verify_attestation()
{
    return RPCHelpMan{"cosign.eth_verify_attestation",
        "Verify an oracle attestation for an HTLC event.",
        {
            {"oracle_pubkey", RPCArg::Type::STR, RPCArg::Optional::NO, "32-byte x-only oracle pubkey (hex)"},
            {"attestation", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Oracle attestation object",
                {
                    {"version", RPCArg::Type::NUM, RPCArg::Optional::NO, "Attestation version"},
                    {"swap_id", RPCArg::Type::STR, RPCArg::Optional::NO, "Swap ID"},
                    {"event_type", RPCArg::Type::STR, RPCArg::Optional::NO, "Event type"},
                    {"tx_hash", RPCArg::Type::STR, RPCArg::Optional::NO, "Transaction hash"},
                    {"block_number", RPCArg::Type::NUM, RPCArg::Optional::NO, "Block number"},
                    {"block_hash", RPCArg::Type::STR, RPCArg::Optional::NO, "Block hash"},
                    {"contract_address", RPCArg::Type::STR, RPCArg::Optional::NO, "Contract address"},
                    {"token_address", RPCArg::Type::STR, RPCArg::Optional::NO, "Token address"},
                    {"amount", RPCArg::Type::STR, RPCArg::Optional::NO, "Amount"},
                    {"recipient", RPCArg::Type::STR, RPCArg::Optional::NO, "Recipient"},
                    {"secret_hash", RPCArg::Type::STR, RPCArg::Optional::NO, "Secret hash"},
                    {"timelock", RPCArg::Type::NUM, RPCArg::Optional::NO, "Timelock"},
                    {"confirmation_depth", RPCArg::Type::NUM, RPCArg::Optional::NO, "Confirmation depth"},
                    {"attested_at", RPCArg::Type::NUM, RPCArg::Optional::NO, "Attestation timestamp"},
                    {"attestation_hash", RPCArg::Type::STR, RPCArg::Optional::NO, "SHA256 of canonical fields"},
                    {"signature", RPCArg::Type::STR, RPCArg::Optional::NO, "Schnorr signature"},
                },
            },
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::BOOL, "valid", "Whether attestation is valid"},
            {RPCResult::Type::STR, "swap_id", "Swap ID from attestation"},
            {RPCResult::Type::NUM, "confirmation_depth", "Confirmation depth"},
        }},
        RPCExamples{HelpExampleCli("cosign.eth_verify_attestation",
            "\"oracle_pubkey_hex\" {attestation_json}")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            if (!cosign::g_bridge_manager.IsEnabled())
                throw JSONRPCError(RPC_MISC_ERROR, "COSIGN_DISABLED: Bridge not configured");
            UniValue p(UniValue::VOBJ);
            p.pushKV("oracle_pubkey", request.params[0].get_str());
            p.pushKV("attestation", request.params[1]);
            return cosign::g_bridge_manager.SendBridgeCommand("eth_verify_attestation", p);
        }
    };
}

// ============================================================================
// DISCUSSION PROOF COMMANDS
// ============================================================================

static RPCHelpMan cosign_verify_discussion_proof()
{
    return RPCHelpMan{"cosign.verify_discussion_proof",
        "Verify a BIP-322 discussion proof using strict rules (confirmed UTXOs, bestblock chain binding).\n"
        "\nMessage format: TENSORCASH_DISCUSS:v1:<network>:<scope_type>:<scope_id>:<nostr_pubkey>:<expiry_height>",
        {
            {"utxo_ref", RPCArg::Type::STR, RPCArg::Optional::NO, "UTXO reference in 'txid:vout' format"},
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "Bitcoin address controlling the UTXO"},
            {"message", RPCArg::Type::STR, RPCArg::Optional::NO, "Signed message (TENSORCASH_DISCUSS:v1:...)"},
            {"signature", RPCArg::Type::STR, RPCArg::Optional::NO, "BIP-322 signature"},
            {"claimed_units", RPCArg::Type::NUM, RPCArg::Optional::NO, "Minimum units the proof must cover"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::BOOL, "verified", "Whether the proof passed all checks"},
                {RPCResult::Type::STR, "error", /*optional=*/true, "Error description if verification failed"},
                {RPCResult::Type::NUM, "actual_units", "Actual units in the UTXO"},
                {RPCResult::Type::STR, "bestblock", "Best block hash at time of verification"},
                {RPCResult::Type::STR, "network", /*optional=*/true, "Extracted network from message"},
                {RPCResult::Type::STR, "scope_type", /*optional=*/true, "Extracted scope type from message"},
                {RPCResult::Type::STR, "scope_id", /*optional=*/true, "Extracted scope ID from message"},
                {RPCResult::Type::STR, "nostr_pubkey", /*optional=*/true, "Extracted Nostr pubkey from message"},
                {RPCResult::Type::NUM, "expiry_height", /*optional=*/true, "Extracted expiry block height from message"},
            }
        },
        RPCExamples{
            HelpExampleCli("cosign.verify_discussion_proof",
                "\"txid:0\" \"addr\" \"TENSORCASH_DISCUSS:v1:regtest:model_prealert:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef:1000\" \"sig\" 10000")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            std::string utxo_ref = request.params[0].get_str();
            std::string address = request.params[1].get_str();
            std::string message = request.params[2].get_str();
            std::string signature = request.params[3].get_str();
            uint64_t claimed_units = request.params[4].getInt<uint64_t>();

            // Parse and validate discussion message format
            std::string network, scope_type, scope_id, nostr_pubkey;
            int expiry_height = 0;
            std::string parse_error = proof_verify::ParseDiscussionProofMessage(
                message, network, scope_type, scope_id, nostr_pubkey, expiry_height);

            UniValue result(UniValue::VOBJ);

            if (!parse_error.empty()) {
                result.pushKV("verified", false);
                result.pushKV("error", "Invalid message format: " + parse_error);
                result.pushKV("actual_units", (uint64_t)0);
                result.pushKV("bestblock", "");
                return result;
            }

            // Check that the claimed network matches the active selected chain.
            std::string active_chain = Params().GetChainTypeString();
            if (network != active_chain) {
                result.pushKV("verified", false);
                result.pushKV("error", strprintf("Network mismatch: message claims '%s' but node is on '%s'", network, active_chain));
                result.pushKV("actual_units", (uint64_t)0);
                result.pushKV("bestblock", "");
                return result;
            }

            // Check expiry against current block height
            JSONRPCRequest height_req;
            height_req.context = request.context;
            height_req.strMethod = "getblockcount";
            height_req.params = UniValue(UniValue::VARR);
            int current_height = 0;
            try {
                UniValue height_result = ::tableRPC.execute(height_req);
                current_height = height_result.getInt<int>();
            } catch (const std::exception& e) {
                result.pushKV("verified", false);
                result.pushKV("error", std::string("Failed to get block height: ") + e.what());
                result.pushKV("actual_units", (uint64_t)0);
                result.pushKV("bestblock", "");
                return result;
            }

            if (current_height >= expiry_height) {
                result.pushKV("verified", false);
                result.pushKV("error", strprintf("Proof expired: current height %d >= expiry %d", current_height, expiry_height));
                result.pushKV("actual_units", (uint64_t)0);
                result.pushKV("bestblock", "");
                return result;
            }

            // Verify the proof using shared strict verifier (native TSC only for V1)
            proof_verify::VerifyResult vr = proof_verify::VerifyOwnershipProof(
                ::tableRPC, request.context,
                utxo_ref, address, message, signature,
                "", // asset_id empty = native TSC
                claimed_units);

            result.pushKV("verified", vr.verified);
            if (!vr.error.empty()) {
                result.pushKV("error", vr.error);
            }
            result.pushKV("actual_units", vr.actual_units);
            result.pushKV("bestblock", vr.bestblock);

            if (vr.verified) {
                result.pushKV("network", network);
                result.pushKV("scope_type", scope_type);
                result.pushKV("scope_id", scope_id);
                result.pushKV("nostr_pubkey", nostr_pubkey);
                result.pushKV("expiry_height", expiry_height);
            }

            return result;
        }
    };
}

// ============================================================================
// DISCUSSION BRIDGE RPC WRAPPERS
// ============================================================================

static RPCHelpMan cosign_discussion_post()
{
    return RPCHelpMan{"cosign.discussion_post",
        "Post a discussion message to a model-scoped thread.\n"
        "\nCreates a BIP-322 proof-of-funds, sends the message to the bridge,\n"
        "which publishes it to Nostr relays as a kind 8322 event.",
        {
            {"scope_type", RPCArg::Type::STR, RPCArg::Optional::NO, "Scope type: \"model_prealert\" or \"model_challenge\""},
            {"scope_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Scope ID: model_hash or challenge_block_hash (64 hex chars)"},
            {"content", RPCArg::Type::STR, RPCArg::Optional::NO, "Message text (max 4096 chars)"},
            {"expiry_blocks", RPCArg::Type::NUM, RPCArg::Default{200}, "Proof expiry in blocks from current height"},
            {"min_stake", RPCArg::Type::NUM, RPCArg::Default{10000}, "Minimum stake in satoshis for proof"},
            {"model_identifier", RPCArg::Type::STR, RPCArg::Default{""}, "Optional model_name@commit_id alias for model_prealert scopes"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "event_id", "Nostr event ID of published post"},
                {RPCResult::Type::STR, "scope_type", "Scope type"},
                {RPCResult::Type::STR_HEX, "scope_id", "Scope ID"},
                {RPCResult::Type::STR, "content", "Message content"},
                {RPCResult::Type::NUM, "created_at", "Unix timestamp"},
                {RPCResult::Type::STR, "model_identifier", /*optional=*/true, "Human-readable model_name@commit_id alias carried with the discussion post"},
            }
        },
        RPCExamples{
            HelpExampleCli("cosign.discussion_post",
                "\"model_prealert\" \"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789\" \"Proposing new model, commits welcome\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            if (!cosign::g_bridge_manager.IsEnabled()) {
                throw JSONRPCError(RPC_MISC_ERROR, "COSIGN_DISABLED: Bridge not configured");
            }

            std::string scope_type = request.params[0].get_str();
            std::string scope_id = request.params[1].get_str();
            std::string content = request.params[2].get_str();
            int expiry_blocks = 200;
            if (!request.params[3].isNull()) {
                expiry_blocks = request.params[3].getInt<int>();
            }
            uint64_t min_stake = 10000;
            if (!request.params[4].isNull()) {
                min_stake = request.params[4].getInt<uint64_t>();
            }
            std::string model_identifier;
            if (request.params.size() > 5 && !request.params[5].isNull()) {
                model_identifier = request.params[5].get_str();
            }

            // Validate scope_type
            if (scope_type != "model_prealert" && scope_type != "model_challenge") {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "scope_type must be \"model_prealert\" or \"model_challenge\"");
            }

            // Validate scope_id is 64 hex chars
            if (scope_id.size() != 64) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "scope_id must be 64 hex characters");
            }

            // Get current height for expiry
            JSONRPCRequest height_req;
            height_req.context = request.context;
            height_req.strMethod = "getblockcount";
            height_req.params = UniValue(UniValue::VARR);
            int current_height = ::tableRPC.execute(height_req).getInt<int>();
            int expiry_height = current_height + expiry_blocks;

            // Get bridge Nostr pubkey (lightweight query, does not reinitialize)
            UniValue nostr_info = cosign::g_bridge_manager.SendBridgeCommand("bb_get_pubkey", UniValue(UniValue::VOBJ));
            std::string nostr_pubkey;
            if (nostr_info.exists("pubkey")) {
                nostr_pubkey = nostr_info["pubkey"].get_str();
            } else {
                throw JSONRPCError(RPC_MISC_ERROR, "Could not get Nostr pubkey from bridge (call cosign.init_bb first)");
            }

            std::string network = Params().GetChainTypeString();

            // Build the canonical discussion message for BIP-322 proof
            std::string proof_message = strprintf("TENSORCASH_DISCUSS:v1:%s:%s:%s:%s:%d",
                network, scope_type, scope_id, nostr_pubkey, expiry_height);

            // Create BIP-322 proof via wallet RPC (signmessagebip322)
            // Get a spendable UTXO and sign
            // We need to use listunspent + signmessagebip322 from the wallet context
            JSONRPCRequest listunspent_req;
            listunspent_req.context = request.context;
            listunspent_req.strMethod = "listunspent";
            listunspent_req.params = UniValue(UniValue::VARR);
            listunspent_req.params.push_back(1); // minconf
            listunspent_req.params.push_back(9999999);

            UniValue unspent = ::tableRPC.execute(listunspent_req);
            if (!unspent.isArray() || unspent.size() == 0) {
                throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "No confirmed UTXOs available for discussion proof");
            }

            // Find a single UTXO that individually meets min_stake.
            // The bridge stores one proof per post, so we need one UTXO >= min_stake.
            // Sort descending by amount to find the largest first.
            UniValue proof_obj(UniValue::VNULL);

            std::vector<size_t> indices;
            for (size_t i = 0; i < unspent.size(); i++) {
                const UniValue& utxo = unspent[i];
                if (!utxo.exists("spendable") || !utxo["spendable"].get_bool()) continue;
                if (!utxo.exists("amount")) continue;
                indices.push_back(i);
            }

            // Sort by amount descending — try largest UTXO first
            std::sort(indices.begin(), indices.end(), [&](size_t a, size_t b) {
                double va = unspent[a]["amount"].get_real();
                double vb = unspent[b]["amount"].get_real();
                return va > vb;
            });

            for (size_t idx : indices) {
                const UniValue& utxo = unspent[idx];
                uint64_t amount_sat = static_cast<uint64_t>(utxo["amount"].get_real() * 1e8);
                if (amount_sat < min_stake) continue; // UTXO too small

                std::string addr = utxo["address"].get_str();
                std::string txid = utxo["txid"].get_str();
                int vout = utxo["vout"].getInt<int>();

                // Sign with BIP-322
                JSONRPCRequest sign_req;
                sign_req.context = request.context;
                sign_req.strMethod = "signmessagebip322";
                sign_req.params = UniValue(UniValue::VARR);
                sign_req.params.push_back(addr);
                sign_req.params.push_back(proof_message);

                std::string signature;
                try {
                    signature = ::tableRPC.execute(sign_req).get_str();
                } catch (...) {
                    continue; // Skip UTXOs we can't sign for
                }

                proof_obj = UniValue(UniValue::VOBJ);
                proof_obj.pushKV("utxo_ref", strprintf("%s:%d", txid, vout));
                proof_obj.pushKV("address", addr);
                proof_obj.pushKV("message", proof_message);
                proof_obj.pushKV("signature", signature);
                proof_obj.pushKV("asset_units", amount_sat);
                break; // Found a valid proof
            }

            if (proof_obj.isNull()) {
                throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS,
                    strprintf("No single UTXO meets minimum stake of %llu sat",
                        (unsigned long long)min_stake));
            }

            // Send to bridge
            UniValue bridge_params(UniValue::VOBJ);
            bridge_params.pushKV("scope_type", scope_type);
            bridge_params.pushKV("scope_id", scope_id);
            bridge_params.pushKV("content", content);
            bridge_params.pushKV("network", network);
            bridge_params.pushKV("proof", proof_obj);
            if (!model_identifier.empty()) {
                bridge_params.pushKV("model_identifier", model_identifier);
            }

            UniValue response = cosign::g_bridge_manager.SendBridgeCommand("discussion_post", bridge_params);

            // Extract fields to match documented schema
            // Bridge returns: { "success": true, "post": { post_id, scope_type, scope_id, content, created_at, ... } }
            UniValue result(UniValue::VOBJ);
            if (response.exists("post") && response["post"].isObject()) {
                const UniValue& post = response["post"];
                result.pushKV("event_id", post.exists("post_id") ? post["post_id"].get_str() : "");
                result.pushKV("scope_type", post.exists("scope_type") ? post["scope_type"].get_str() : scope_type);
                result.pushKV("scope_id", post.exists("scope_id") ? post["scope_id"].get_str() : scope_id);
                result.pushKV("content", post.exists("content") ? post["content"].get_str() : content);
                result.pushKV("created_at", post.exists("created_at") ? post["created_at"].getInt<uint64_t>() : (uint64_t)0);
                if (post.exists("model_identifier") && post["model_identifier"].isStr()) {
                    result.pushKV("model_identifier", post["model_identifier"].get_str());
                }
            } else {
                // Fallback: return what we know
                result.pushKV("event_id", "");
                result.pushKV("scope_type", scope_type);
                result.pushKV("scope_id", scope_id);
                result.pushKV("content", content);
                result.pushKV("created_at", (uint64_t)0);
                if (!model_identifier.empty()) {
                    result.pushKV("model_identifier", model_identifier);
                }
            }
            return result;
        }
    };
}

static RPCHelpMan cosign_discussion_list()
{
    return RPCHelpMan{"cosign.discussion_list",
        "List discussion posts for a model-scoped thread.\n"
        "\nRetrieves posts from the bridge, then verifies each proof locally\n"
        "using strict rules (confirmed UTXOs, bestblock chain binding, BIP-322).",
        {
            {"scope_type", RPCArg::Type::STR, RPCArg::Optional::NO, "Scope type: \"model_prealert\" or \"model_challenge\""},
            {"scope_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Scope ID: model_hash or challenge_block_hash (64 hex chars)"},
            {"since", RPCArg::Type::NUM, RPCArg::Default{0}, "Only return posts after this unix timestamp"},
            {"limit", RPCArg::Type::NUM, RPCArg::Default{100}, "Maximum number of posts to return"},
            {"force_refresh", RPCArg::Type::BOOL, RPCArg::Default{false}, "Force relay re-query (bypass bridge cache)"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::NUM, "current_height", "Current block height"},
                {RPCResult::Type::BOOL, "stale", /*optional=*/true, "Whether cached posts are being returned after a relay refresh failure"},
                {RPCResult::Type::STR, "refresh_error", /*optional=*/true, "Relay refresh failure that caused a stale cached result"},
                {RPCResult::Type::ARR, "posts", "",
                {
                    {RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR, "post_id", "Nostr event ID"},
                        {RPCResult::Type::STR, "author_pubkey", "Author Nostr pubkey"},
                        {RPCResult::Type::STR, "content", "Message text"},
                        {RPCResult::Type::STR, "model_identifier", /*optional=*/true, "Human-readable model_name@commit_id alias carried with the post"},
                        {RPCResult::Type::NUM, "created_at", "Unix timestamp"},
                        {RPCResult::Type::BOOL, "has_proof", "Whether a proof was attached"},
                        {RPCResult::Type::BOOL, "verified", "Whether the proof passed verification"},
                        {RPCResult::Type::STR, "rejected_reason", /*optional=*/true, "Reason proof failed"},
                        {RPCResult::Type::NUM, "verified_units", /*optional=*/true, "Verified stake in satoshis"},
                        {RPCResult::Type::NUM, "expiry_height", /*optional=*/true, "Proof expiry block height"},
                    }},
                }},
            }
        },
        RPCExamples{
            HelpExampleCli("cosign.discussion_list",
                "\"model_prealert\" \"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            if (!cosign::g_bridge_manager.IsEnabled()) {
                throw JSONRPCError(RPC_MISC_ERROR, "COSIGN_DISABLED: Bridge not configured");
            }

            std::string scope_type = request.params[0].get_str();
            std::string scope_id = request.params[1].get_str();
            uint64_t since = 0;
            if (!request.params[2].isNull()) {
                since = request.params[2].getInt<uint64_t>();
            }
            int limit = 100;
            if (!request.params[3].isNull()) {
                limit = request.params[3].getInt<int>();
            }
            bool force_refresh = false;
            if (!request.params[4].isNull()) {
                force_refresh = request.params[4].get_bool();
            }

            // Get current height for expiry checks
            JSONRPCRequest height_req;
            height_req.context = request.context;
            height_req.strMethod = "getblockcount";
            height_req.params = UniValue(UniValue::VARR);
            int current_height = ::tableRPC.execute(height_req).getInt<int>();

            std::string network = Params().GetChainTypeString();

            // Force-refresh from relays if requested (bypasses bridge 25s cache)
            if (force_refresh) {
                UniValue force_params(UniValue::VOBJ);
                force_params.pushKV("scope_type", scope_type);
                force_params.pushKV("scope_id", scope_id);
                if (since > 0) force_params.pushKV("since", since);
                cosign::g_bridge_manager.SendBridgeCommand("force_refresh_discussion", force_params);
            }

            // Fetch from bridge
            UniValue bridge_params(UniValue::VOBJ);
            bridge_params.pushKV("scope_type", scope_type);
            bridge_params.pushKV("scope_id", scope_id);
            if (since > 0) bridge_params.pushKV("since", since);
            if (limit > 0) bridge_params.pushKV("limit", limit);

            UniValue response = cosign::g_bridge_manager.SendBridgeCommand("discussion_list", bridge_params);

            // Extract posts array
            UniValue posts_raw;
            if (response.isObject() && response.exists("posts")) {
                posts_raw = response["posts"];
            } else if (response.isArray()) {
                posts_raw = response;
            } else {
                posts_raw = UniValue(UniValue::VARR);
            }

            // Verify each proof and build annotated result
            UniValue posts_verified(UniValue::VARR);

            for (size_t i = 0; i < posts_raw.size(); i++) {
                const UniValue& post = posts_raw[i];
                UniValue annotated(UniValue::VOBJ);

                annotated.pushKV("post_id", post.exists("post_id") ? post["post_id"].get_str() : "");
                annotated.pushKV("author_pubkey", post.exists("author_pubkey") ? post["author_pubkey"].get_str() : "");
                annotated.pushKV("content", post.exists("content") ? post["content"].get_str() : "");
                if (post.exists("model_identifier") && post["model_identifier"].isStr()) {
                    annotated.pushKV("model_identifier", post["model_identifier"].get_str());
                }
                annotated.pushKV("created_at", post.exists("created_at") ? post["created_at"].getInt<uint64_t>() : (uint64_t)0);

                // Check if proof exists
                bool has_proof = false;
                if (post.exists("proof") && post["proof"].isObject() && !post["proof"].isNull()) {
                    const UniValue& proof = post["proof"];
                    if (proof.exists("utxo_ref") && proof.exists("address") &&
                        proof.exists("message") && proof.exists("signature")) {
                        has_proof = true;
                    }
                }
                // Also check proof_raw (bridge may serialize proof as raw JSON string)
                if (!has_proof && post.exists("proof_raw") && !post["proof_raw"].isNull()) {
                    has_proof = true;
                }

                annotated.pushKV("has_proof", has_proof);

                if (has_proof && post.exists("proof") && post["proof"].isObject()) {
                    const UniValue& proof = post["proof"];
                    std::string utxo_ref = proof.exists("utxo_ref") ? proof["utxo_ref"].get_str() : "";
                    std::string address = proof.exists("address") ? proof["address"].get_str() : "";
                    std::string message = proof.exists("message") ? proof["message"].get_str() : "";
                    std::string signature = proof.exists("signature") ? proof["signature"].get_str() : "";
                    uint64_t claimed_units = proof.exists("asset_units") ? proof["asset_units"].getInt<uint64_t>() : 0;

                    // Parse message to extract expiry and check network
                    std::string msg_network, msg_scope_type, msg_scope_id, msg_nostr_pubkey;
                    int msg_expiry_height = 0;
                    std::string parse_err = proof_verify::ParseDiscussionProofMessage(
                        message, msg_network, msg_scope_type, msg_scope_id, msg_nostr_pubkey, msg_expiry_height);

                    // Extract post's author pubkey for binding check
                    std::string post_author = post.exists("author_pubkey") ? post["author_pubkey"].get_str() : "";

                    if (!parse_err.empty()) {
                        annotated.pushKV("verified", false);
                        annotated.pushKV("rejected_reason", "Bad proof message: " + parse_err);
                    } else if (msg_network != network) {
                        annotated.pushKV("verified", false);
                        annotated.pushKV("rejected_reason", strprintf("Network mismatch: proof says %s, node is %s", msg_network, network));
                    } else if (msg_scope_type != scope_type || msg_scope_id != scope_id) {
                        // Proof is bound to a different thread — possible replay
                        annotated.pushKV("verified", false);
                        annotated.pushKV("rejected_reason", strprintf("Scope mismatch: proof for %s:%s, thread is %s:%s",
                            msg_scope_type, msg_scope_id.substr(0, 16), scope_type, scope_id.substr(0, 16)));
                    } else if (!post_author.empty() && !msg_nostr_pubkey.empty() && post_author != msg_nostr_pubkey) {
                        // Proof was created for a different Nostr identity — possible replay
                        annotated.pushKV("verified", false);
                        annotated.pushKV("rejected_reason", "Author mismatch: proof pubkey does not match post author");
                    } else if (current_height >= msg_expiry_height) {
                        annotated.pushKV("verified", false);
                        annotated.pushKV("rejected_reason", strprintf("Expired: height %d >= expiry %d", current_height, msg_expiry_height));
                        annotated.pushKV("expiry_height", msg_expiry_height);
                    } else {
                        // Full strict verification
                        proof_verify::VerifyResult vr = proof_verify::VerifyOwnershipProof(
                            ::tableRPC, request.context,
                            utxo_ref, address, message, signature,
                            "", // native TSC
                            claimed_units);

                        annotated.pushKV("verified", vr.verified);
                        if (!vr.error.empty()) {
                            annotated.pushKV("rejected_reason", vr.error);
                        }
                        if (vr.verified) {
                            annotated.pushKV("verified_units", vr.actual_units);
                        }
                        annotated.pushKV("expiry_height", msg_expiry_height);
                    }
                } else {
                    annotated.pushKV("verified", false);
                    if (has_proof) {
                        annotated.pushKV("rejected_reason", "Proof present but could not be parsed");
                    } else {
                        annotated.pushKV("rejected_reason", "No proof attached");
                    }
                }

                posts_verified.push_back(annotated);
            }

            UniValue result(UniValue::VOBJ);
            result.pushKV("current_height", current_height);
            if (response.isObject() && response.exists("stale")) {
                result.pushKV("stale", response["stale"].get_bool());
            }
            if (response.isObject() && response.exists("refresh_error") && response["refresh_error"].isStr()) {
                result.pushKV("refresh_error", response["refresh_error"].get_str());
            }
            result.pushKV("posts", posts_verified);
            return result;
        }
    };
}

static RPCHelpMan cosign_discussion_scopes()
{
    return RPCHelpMan{"cosign.discussion_scopes",
        "List active discussion scopes discovered on relays.\n"
        "\nReturns recent model/challenge discussion threads aggregated from relay posts.",
        {
            {"since", RPCArg::Type::NUM, RPCArg::Default{0}, "Only include scopes with posts after this unix timestamp"},
            {"limit", RPCArg::Type::NUM, RPCArg::Default{50}, "Maximum number of scopes to return"},
            {"force_refresh", RPCArg::Type::BOOL, RPCArg::Default{false}, "Force relay re-query before aggregating scopes"},
            {"only_live_verified", RPCArg::Type::BOOL, RPCArg::Default{false}, "Only return scopes that contain at least one verified, unexpired post"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::ARR, "scopes", "",
                {
                    {RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR, "scope_type", "Scope type"},
                        {RPCResult::Type::STR_HEX, "scope_id", "Scope id"},
                        {RPCResult::Type::NUM, "latest_created_at", "Unix timestamp of latest post in this scope"},
                        {RPCResult::Type::NUM, "post_count", "Number of posts observed for this scope"},
                        {RPCResult::Type::STR, "latest_post_id", "Latest Nostr event id"},
                        {RPCResult::Type::STR, "latest_content_preview", "Preview of latest post content"},
                        {RPCResult::Type::STR, "model_identifier", /*optional=*/true, "Human-readable model_name@commit_id alias for the scope when present in discussion relay data"},
                        {RPCResult::Type::BOOL, "has_live_verified_posts", /*optional=*/true, "Whether the scope has at least one verified, unexpired post"},
                        {RPCResult::Type::NUM, "live_verified_post_count", /*optional=*/true, "Number of verified, unexpired posts in the scope"},
                    }},
                }},
            }
        },
        RPCExamples{
            HelpExampleCli("cosign.discussion_scopes", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            if (!cosign::g_bridge_manager.IsEnabled()) {
                throw JSONRPCError(RPC_MISC_ERROR, "COSIGN_DISABLED: Bridge not configured");
            }

            uint64_t since = 0;
            if (!request.params[0].isNull()) {
                since = request.params[0].getInt<uint64_t>();
            }
            int limit = 50;
            if (!request.params[1].isNull()) {
                limit = request.params[1].getInt<int>();
            }
            bool force_refresh = false;
            if (!request.params[2].isNull()) {
                force_refresh = request.params[2].get_bool();
            }
            bool only_live_verified = false;
            if (!request.params[3].isNull()) {
                only_live_verified = request.params[3].get_bool();
            }

            JSONRPCRequest height_req;
            height_req.context = request.context;
            height_req.strMethod = "getblockcount";
            height_req.params = UniValue(UniValue::VARR);
            int current_height = ::tableRPC.execute(height_req).getInt<int>();

            UniValue bridge_params(UniValue::VOBJ);
            if (since > 0) bridge_params.pushKV("since", since);
            if (limit > 0) bridge_params.pushKV("limit", limit);
            bridge_params.pushKV("force_refresh", force_refresh);

            UniValue response = cosign::g_bridge_manager.SendBridgeCommand("discussion_scopes", bridge_params);

            UniValue result(UniValue::VOBJ);
            if (response.isObject() && response.exists("scopes")) {
                UniValue enriched(UniValue::VARR);
                const UniValue& scopes = response["scopes"];
                const std::string network = Params().GetChainTypeString();

                for (size_t i = 0; i < scopes.size(); i++) {
                    const UniValue& scope = scopes[i];
                    if (!scope.isObject() || !scope.exists("scope_type") || !scope.exists("scope_id")) {
                        continue;
                    }

                    const std::string scope_type = scope["scope_type"].get_str();
                    const std::string scope_id = scope["scope_id"].get_str();
                    UniValue annotated = scope;

                    // Only compute per-scope verification state when the live-only filter is requested.
                    if (!only_live_verified) {
                        enriched.push_back(annotated);
                        continue;
                    }

                    UniValue list_params(UniValue::VOBJ);
                    list_params.pushKV("scope_type", scope_type);
                    list_params.pushKV("scope_id", scope_id);
                    list_params.pushKV("limit", 200);
                    if (since > 0) list_params.pushKV("since", since);

                    UniValue raw_scope_posts = cosign::g_bridge_manager.SendBridgeCommand("discussion_list", list_params);

                    int live_verified_post_count = 0;
                    const UniValue posts_raw =
                        raw_scope_posts.isObject() && raw_scope_posts.exists("posts")
                            ? raw_scope_posts["posts"]
                            : UniValue(UniValue::VARR);

                    for (size_t j = 0; j < posts_raw.size(); j++) {
                        const UniValue& post = posts_raw[j];

                        bool has_proof = false;
                        if (post.exists("proof") && post["proof"].isObject() && !post["proof"].isNull()) {
                            const UniValue& proof = post["proof"];
                            if (proof.exists("utxo_ref") && proof.exists("address") &&
                                proof.exists("message") && proof.exists("signature")) {
                                has_proof = true;
                            }
                        }
                        if (!has_proof && post.exists("proof_raw") && !post["proof_raw"].isNull()) {
                            has_proof = true;
                        }
                        if (!(has_proof && post.exists("proof") && post["proof"].isObject())) {
                            continue;
                        }

                        const UniValue& proof = post["proof"];
                        std::string utxo_ref = proof.exists("utxo_ref") ? proof["utxo_ref"].get_str() : "";
                        std::string address = proof.exists("address") ? proof["address"].get_str() : "";
                        std::string message = proof.exists("message") ? proof["message"].get_str() : "";
                        std::string signature = proof.exists("signature") ? proof["signature"].get_str() : "";
                        uint64_t claimed_units = proof.exists("asset_units") ? proof["asset_units"].getInt<uint64_t>() : 0;

                        std::string msg_network, msg_scope_type, msg_scope_id, msg_nostr_pubkey;
                        int msg_expiry_height = 0;
                        std::string parse_err = proof_verify::ParseDiscussionProofMessage(
                            message, msg_network, msg_scope_type, msg_scope_id, msg_nostr_pubkey, msg_expiry_height);
                        std::string post_author = post.exists("author_pubkey") ? post["author_pubkey"].get_str() : "";

                        if (!parse_err.empty()) continue;
                        if (msg_network != network) continue;
                        if (msg_scope_type != scope_type || msg_scope_id != scope_id) continue;
                        if (!post_author.empty() && !msg_nostr_pubkey.empty() && post_author != msg_nostr_pubkey) continue;
                        if (current_height >= msg_expiry_height) continue;

                        proof_verify::VerifyResult vr = proof_verify::VerifyOwnershipProof(
                            ::tableRPC, request.context,
                            utxo_ref, address, message, signature,
                            "",
                            claimed_units);
                        if (vr.verified) {
                            ++live_verified_post_count;
                        }
                    }

                    const bool has_live_verified_posts = live_verified_post_count > 0;
                    if (only_live_verified && !has_live_verified_posts) {
                        continue;
                    }

                    annotated.pushKV("has_live_verified_posts", has_live_verified_posts);
                    annotated.pushKV("live_verified_post_count", live_verified_post_count);
                    enriched.push_back(annotated);
                }

                result.pushKV("scopes", enriched);
            } else {
                result.pushKV("scopes", UniValue(UniValue::VARR));
            }
            return result;
        }
    };
}

// ============================================================================
// REGISTRATION
// ============================================================================

void RegisterCosignRPCCommands(CRPCTable& t)
{
    static const CRPCCommand commands[]{
        {"cosign", &cosign_version},
        {"cosign", &cosign_ping},
        {"cosign", &cosign_init},
        {"cosign", &cosign_join},
        {"cosign", &cosign_handshake_auto},
        {"cosign", &cosign_adaptor_roundtrip},
        {"cosign", &cosign_attest},
        {"cosign", &cosign_send},
        {"cosign", &cosign_recv},
        {"cosign", &cosign_status},
        {"cosign", &cosign_close},
        {"cosign", &cosign_resume},
        {"cosign", &cosign_metrics},

        // Bulletin Board Commands
        {"cosign", &cosign_init_bb},
        {"cosign", &cosign_post_offer},
        {"cosign", &cosign_post_contract_offer},
        {"cosign", &cosign_list_offers},
        {"cosign", &cosign_request_trade},
        {"cosign", &cosign_list_requests},
        {"cosign", &cosign_accept_request},
        {"cosign", &cosign_reject_request},
        {"cosign", &cosign_delete_offer},

        // Cross-chain Commands
        {"cosign", &cosign_post_cross_chain_offer},
        {"cosign", &cosign_validate_cross_chain_payload},
        {"cosign", &cosign_list_cross_chain_offers},

        // ETH Adapter Commands
        {"cosign", &cosign_eth_init},
        {"cosign", &cosign_eth_lock_htlc},
        {"cosign", &cosign_eth_claim_htlc},
        {"cosign", &cosign_eth_refund_htlc},
        {"cosign", &cosign_eth_get_swap_status},
        {"cosign", &cosign_eth_verify_attestation},

        // Governance Commands
        {"cosign", &cosign_publish_governance},
        {"cosign", &cosign_list_governance},
        {"cosign", &cosign_get_governance},
        {"cosign", &cosign_force_refresh_governance},
        {"cosign", &cosign_publish_ballot},
        {"cosign", &cosign_list_ballots},

        // PR3: Private Governance Commands
        {"cosign", &cosign_request_private_proposal},
        {"cosign", &cosign_send_governance_ballot_dm},
        {"cosign", &cosign_process_governance_dms},
        {"cosign", &cosign_send_proposal_response_manual},

        // Discussion Commands
        {"cosign", &cosign_verify_discussion_proof},
        {"cosign", &cosign_discussion_post},
        {"cosign", &cosign_discussion_list},
        {"cosign", &cosign_discussion_scopes},
    };
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
