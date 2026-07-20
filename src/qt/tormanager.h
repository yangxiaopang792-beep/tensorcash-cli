// Copyright (c) 2025 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_QT_TORMANAGER_H
#define BITCOIN_QT_TORMANAGER_H

#include <QObject>
#include <QString>
#include <QProcess>
#include <QFileSystemWatcher>
#include <QTimer>
#include <memory>

namespace fs {
class path;
}

/**
 * @brief Manages a persistent Tor daemon for cosign bridge sessions
 *
 * This class provides:
 * - Idempotent start-once behavior (singleton per application)
 * - Clean teardown on application exit
 * - CookieAuthentication for control port security
 * - Health monitoring and status reporting
 * - Per-GUI instance isolation via deterministic ports
 *
 * The Tor daemon is configured to:
 * - Run under the wallet data directory (.tor/)
 * - Use CookieAuth (no passwords in logs)
 * - Provide SOCKS proxy for cosign-bridge sessions
 * - Support ephemeral hidden services via control port
 */
class TorManager : public QObject
{
    Q_OBJECT

public:
    enum class Status {
        NotStarted,    // Tor has not been initialized
        Starting,      // Tor process is launching
        Ready,         // Tor is running and SOCKS port is ready
        Failed,        // Tor failed to start or crashed
        Stopped        // Tor was stopped cleanly
    };

    static TorManager* instance();
    /** Returns the singleton if it has been created, else nullptr.
     *  Unlike instance(), does NOT construct one — safe to call during
     *  shutdown / from contexts where qApp is being torn down. */
    static TorManager* peek() { return s_instance; }

    /** Static early reaper, callable BEFORE any TorManager instance exists.
     *
     *  The instance reaper in start() runs after the GUI is up — but the
     *  inner P2P listener (CConnman::Init → BindListenPort) binds during
     *  AppInitMain, before TorManager::start() ever runs. If a previous
     *  process exited via _Exit / SIGKILL with tor still attached, those
     *  bind() calls fail with EADDRINUSE and the new process dies before
     *  any wallet UI appears. This static path is safe to call right after
     *  the dataDir is known (post common::InitConfig) and BEFORE
     *  app.requestInitialize(). It does no Qt object construction, no
     *  signals, no qApp interaction — just filesystem + POSIX kill. */
    static void ReapStaleTorEarly(const QString& datadir);

    ~TorManager();

    /**
     * Start the Tor daemon with configuration under dataDir
     *
     * @param dataDir Base data directory (e.g., ~/.bitcoin)
     * @param instanceId Unique ID for this GUI instance (default: 0)
     * @return true if Tor started or was already running
     *
     * This is idempotent - calling start() multiple times is safe.
     * Ports are deterministic: SOCKS = 9150 + (instanceId * 10)
     *                          Control = 9151 + (instanceId * 10)
     */
    bool start(const QString& dataDir, int instanceId = 0);

    /**
     * Stop the Tor daemon cleanly
     */
    void stop();

    /**
     * Check if Tor is running and ready
     */
    bool isReady() const { return m_status == Status::Ready; }

    /**
     * Get current status
     */
    Status status() const { return m_status; }
    QString statusString() const;

    /**
     * Get SOCKS proxy address for cosign-bridge
     * Format: "127.0.0.1:PORT"
     */
    QString socksAddress() const;

    /**
     * Get control port address
     * Format: "127.0.0.1:PORT"
     */
    QString controlAddress() const;

    /**
     * Get base port for hidden services
     * Sessions will use ports starting from this value
     */
    int baseServicePort() const { return m_baseServicePort; }

    /**
     * Get path to Tor data directory
     */
    QString torDataDir() const { return m_torDataDir; }

    /**
     * Set environment variables for cosign-bridge
     * Call this before spawning the bridge process
     */
    void setEnvironmentForBridge();

    /**
     * Get last error message (if status == Failed)
     */
    QString lastError() const { return m_lastError; }

Q_SIGNALS:
    void statusChanged(Status newStatus);
    void ready();
    void failed(const QString& error);

private Q_SLOTS:
    void onProcessStarted();
    void onProcessFinished(int exitCode, QProcess::ExitStatus exitStatus);
    void onProcessError(QProcess::ProcessError error);
    void onProcessReadyReadStdOut();
    void onProcessReadyReadStdErr();
    void onCookieFileChanged(const QString& path);
    void checkSocksPortReady();

private:
    explicit TorManager(QObject* parent = nullptr);

    // Singleton - no copying
    TorManager(const TorManager&) = delete;
    TorManager& operator=(const TorManager&) = delete;

    bool writeTorrc();
    bool createTorDataDir();
    bool waitForCookieFile(int timeoutMs = 10000);
    bool probeSocksPort();
    void setStatus(Status newStatus, const QString& error = QString());

    // Stale-tor reaper: writes tor.pid on spawn, kills any prior tor at startup.
    // Catches the orphan-on-crash case where ~TorManager never runs.
    void reapStaleTor();
    void reapStaleTorFromPidFile();
    void reapStaleTorByArgv();
    bool killTorPid(qint64 pid);
    void writeTorPidFile();
    void removeTorPidFile();

    // Singleton instance
    static TorManager* s_instance;

    // Process management
    QProcess* m_torProcess{nullptr};
    Status m_status{Status::NotStarted};
    QString m_lastError;

    // Configuration
    QString m_dataDir;           // Base data dir (e.g., ~/.bitcoin)
    QString m_torDataDir;        // Tor data dir (e.g., ~/.bitcoin/.tor)
    QString m_torrcPath;         // Path to torrc file
    QString m_torPidPath;        // Path to tor.pid (used by stale-tor reaper)
    int m_instanceId{0};         // GUI instance ID
    int m_socksPort{9150};       // SOCKS proxy port
    int m_controlPort{9151};     // Control port
    int m_baseServicePort{9735}; // Base port for hidden services

    // Monitoring
    QFileSystemWatcher* m_fileWatcher{nullptr};
    QTimer* m_socksProbeTimer{nullptr};
    int m_socksProbeAttempts{0};
    static constexpr int MAX_SOCKS_PROBE_ATTEMPTS = 30; // 30 seconds max
};

#endif // BITCOIN_QT_TORMANAGER_H
