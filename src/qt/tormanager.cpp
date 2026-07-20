// Copyright (c) 2025 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <qt/tormanager.h>

#include <logging.h>
#include <util/fs.h>

#include <QDir>
#include <QFile>
#include <QStandardPaths>
#include <QTcpSocket>
#include <QThread>
#include <QTimer>
#include <QCoreApplication>

#ifndef Q_OS_WIN
#include <cerrno>
#include <csignal>
#include <cstring>
#include <sys/types.h>
#include <unistd.h>
#endif

TorManager* TorManager::s_instance = nullptr;

TorManager* TorManager::instance()
{
    if (!s_instance) {
        s_instance = new TorManager(qApp);
    }
    return s_instance;
}

TorManager::TorManager(QObject* parent)
    : QObject(parent)
{
    LogPrintf("TorManager: Singleton instance created\n");
}

TorManager::~TorManager()
{
    stop();
    LogPrintf("TorManager: Singleton instance destroyed\n");
}

bool TorManager::start(const QString& dataDir, int instanceId)
{
    // Idempotent: if already running or starting, do nothing
    if (m_status == Status::Ready || m_status == Status::Starting) {
        LogPrintf("TorManager: Already running/starting (status=%s)\n",
                 statusString().toStdString().c_str());
        return m_status == Status::Ready;
    }

    m_dataDir = dataDir;
    m_instanceId = instanceId;

    // Calculate deterministic ports based on instance ID
    m_socksPort = 9150 + (instanceId * 10);
    m_controlPort = 9151 + (instanceId * 10);
    m_baseServicePort = 9735 + (instanceId * 100);

    LogPrintf("TorManager: Starting Tor for instance %d (SOCKS=%d, Control=%d, BaseServicePort=%d)\n",
             instanceId, m_socksPort, m_controlPort, m_baseServicePort);

    // Set up paths
    QDir baseDir(dataDir);
    m_torDataDir = baseDir.filePath(".tor");
    m_torrcPath = baseDir.filePath(".tor/torrc");
    m_torPidPath = baseDir.filePath(".tor/tor.pid");

    setStatus(Status::Starting);

    // Create Tor data directory with restrictive permissions
    if (!createTorDataDir()) {
        setStatus(Status::Failed, tr("Failed to create Tor data directory"));
        return false;
    }

    // Reap any tor left behind by a previous launch (crash, _Exit, hard kill).
    reapStaleTor();

    // Write torrc configuration
    if (!writeTorrc()) {
        setStatus(Status::Failed, tr("Failed to write Tor configuration"));
        return false;
    }

    // Initialize file watcher for cookie file
    if (!m_fileWatcher) {
        m_fileWatcher = new QFileSystemWatcher(this);
        connect(m_fileWatcher, &QFileSystemWatcher::fileChanged,
                this, &TorManager::onCookieFileChanged);
    }

    // Watch the control_auth_cookie file directory
    QDir torDataQDir(m_torDataDir);
    m_fileWatcher->addPath(m_torDataDir);

    // Start Tor process
    if (!m_torProcess) {
        m_torProcess = new QProcess(this);
        connect(m_torProcess, &QProcess::started, this, &TorManager::onProcessStarted);
        connect(m_torProcess, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
                this, &TorManager::onProcessFinished);
        connect(m_torProcess, &QProcess::errorOccurred, this, &TorManager::onProcessError);
        connect(m_torProcess, &QProcess::readyReadStandardOutput,
                this, &TorManager::onProcessReadyReadStdOut);
        connect(m_torProcess, &QProcess::readyReadStandardError,
                this, &TorManager::onProcessReadyReadStdErr);
    }

    // Find tor binary — check bundled location first, then PATH
    QString torBinary;

    // 1. Check next to the app executable (macOS: .app/Contents/MacOS/tor,
    //    Linux/Windows: same directory as the executable)
    QString appDir = QCoreApplication::applicationDirPath();
    QString bundledTor = appDir + "/tor";
#ifdef Q_OS_WIN
    bundledTor += ".exe";
#endif
    if (QFile::exists(bundledTor)) {
        torBinary = bundledTor;
    }

    // 2. macOS: also check .app/Contents/Resources/tor
    if (torBinary.isEmpty()) {
        QString resourcesTor = appDir + "/../Resources/tor";
        if (QFile::exists(resourcesTor)) {
            torBinary = resourcesTor;
        }
    }

    // 3. Fall back to system PATH
    if (torBinary.isEmpty()) {
        torBinary = QStandardPaths::findExecutable("tor");
    }

    if (torBinary.isEmpty()) {
        setStatus(Status::Failed, tr("Tor binary not found (checked app bundle and PATH)"));
        return false;
    }

    LogPrintf("TorManager: Using Tor binary: %s\n", torBinary.toStdString());
    LogPrintf("TorManager: Tor config: %s\n", m_torrcPath.toStdString());

    // Start Tor with our config
    QStringList args;
    args << "-f" << m_torrcPath;

    m_torProcess->start(torBinary, args);

    // Wait for process to start
    if (!m_torProcess->waitForStarted(5000)) {
        setStatus(Status::Failed, tr("Tor process failed to start"));
        return false;
    }

    writeTorPidFile();

    // Start probing SOCKS port
    m_socksProbeAttempts = 0;
    if (!m_socksProbeTimer) {
        m_socksProbeTimer = new QTimer(this);
        m_socksProbeTimer->setInterval(1000); // Check every second
        connect(m_socksProbeTimer, &QTimer::timeout, this, &TorManager::checkSocksPortReady);
    }
    m_socksProbeTimer->start();

    return true;
}

void TorManager::stop()
{
    if (m_status == Status::NotStarted || m_status == Status::Stopped) {
        return;
    }

    LogPrintf("TorManager: Stopping Tor daemon\n");

    // Stop monitoring
    if (m_socksProbeTimer) {
        m_socksProbeTimer->stop();
    }

    // Terminate Tor process
    if (m_torProcess && m_torProcess->state() == QProcess::Running) {
        m_torProcess->terminate();

        // Give it 5 seconds to shut down gracefully
        if (!m_torProcess->waitForFinished(5000)) {
            LogPrintf("TorManager: Tor didn't terminate gracefully, killing\n");
            m_torProcess->kill();
            m_torProcess->waitForFinished(2000);
        }
    }

    removeTorPidFile();
    setStatus(Status::Stopped);
}

bool TorManager::createTorDataDir()
{
    QDir dir;
    if (!dir.mkpath(m_torDataDir)) {
        LogPrintf("TorManager: Failed to create directory: %s\n",
                 m_torDataDir.toStdString());
        return false;
    }

    // Set restrictive permissions (700 = rwx------)
    QFile::Permissions perms = QFile::ReadOwner | QFile::WriteOwner | QFile::ExeOwner;
    if (!QFile::setPermissions(m_torDataDir, perms)) {
        LogPrintf("TorManager: Warning - failed to set restrictive permissions on %s\n",
                 m_torDataDir.toStdString());
        // Continue anyway - not fatal on all platforms
    }

    LogPrintf("TorManager: Created Tor data directory: %s\n",
             m_torDataDir.toStdString());
    return true;
}

bool TorManager::writeTorrc()
{
    QString config = QString(
        "# TensorCash Tor Configuration (Instance %1)\n"
        "# Auto-generated - do not edit manually\n"
        "\n"
        "# SOCKS proxy for cosign-bridge\n"
        "SocksPort 127.0.0.1:%2\n"
        "\n"
        "# Control port for ephemeral hidden services\n"
        "ControlPort 127.0.0.1:%3\n"
        "\n"
        "# Use cookie authentication (no passwords in logs)\n"
        "CookieAuthentication 1\n"
        "CookieAuthFileGroupReadable 1\n"
        "\n"
        "# Data directory\n"
        "DataDirectory %4\n"
        "\n"
        "# Logging (notice level; switch to 'info' temporarily for HS debugging)\n"
        "Log notice file %5/tor.log\n"
        "\n"
        "# Disable unnecessary features\n"
        "DisableNetwork 0\n"
        "# ClientOnly 1\n"
        "\n"
        "# Connection limits for resource efficiency\n"
        "ConnLimit 100\n"
        "MaxClientCircuitsPending 32\n"
        "\n"
    ).arg(m_instanceId)
     .arg(m_socksPort)
     .arg(m_controlPort)
     .arg(m_torDataDir)
     .arg(m_torDataDir);

    QFile file(m_torrcPath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        LogPrintf("TorManager: Failed to open torrc for writing: %s\n",
                 m_torrcPath.toStdString());
        return false;
    }

    QTextStream out(&file);
    out << config;
    file.close();

    // Set restrictive permissions on torrc (600 = rw-------)
    QFile::Permissions perms = QFile::ReadOwner | QFile::WriteOwner;
    QFile::setPermissions(m_torrcPath, perms);

    LogPrintf("TorManager: Wrote torrc: %s\n", m_torrcPath.toStdString());
    return true;
}

void TorManager::checkSocksPortReady()
{
    m_socksProbeAttempts++;

    if (m_socksProbeAttempts > MAX_SOCKS_PROBE_ATTEMPTS) {
        m_socksProbeTimer->stop();
        setStatus(Status::Failed, tr("Tor SOCKS port did not become ready after %1 seconds")
                                       .arg(MAX_SOCKS_PROBE_ATTEMPTS));
        return;
    }

    if (probeSocksPort()) {
        m_socksProbeTimer->stop();
        setStatus(Status::Ready);
        LogPrintf("TorManager: Tor is ready (SOCKS port responding)\n");
        Q_EMIT ready();
    }
}

bool TorManager::probeSocksPort()
{
    QTcpSocket socket;
    socket.connectToHost("127.0.0.1", m_socksPort);

    if (socket.waitForConnected(500)) {
        socket.disconnectFromHost();
        if (socket.state() != QAbstractSocket::UnconnectedState) {
            socket.waitForDisconnected(500);
        }
        return true;
    }

    return false;
}

QString TorManager::socksAddress() const
{
    return QString("127.0.0.1:%1").arg(m_socksPort);
}

QString TorManager::controlAddress() const
{
    return QString("127.0.0.1:%1").arg(m_controlPort);
}

void TorManager::setEnvironmentForBridge()
{
    if (m_status != Status::Ready) {
        LogPrintf("TorManager: Warning - setEnvironmentForBridge called but Tor not ready (status=%s)\n",
                 statusString().toStdString());
    }

    qputenv("COSIGN_TOR_SOCKS", socksAddress().toLatin1());
    qputenv("COSIGN_TOR_BASE_PORT", QString::number(m_baseServicePort).toLatin1());
    qputenv("COSIGN_TOR_HS_DIR", m_torDataDir.toLatin1());

    LogPrintf("TorManager: Set environment variables:\n");
    LogPrintf("  COSIGN_TOR_SOCKS=%s\n", socksAddress().toStdString());
    LogPrintf("  COSIGN_TOR_BASE_PORT=%d\n", m_baseServicePort);
    LogPrintf("  COSIGN_TOR_HS_DIR=%s\n", m_torDataDir.toStdString());
}

QString TorManager::statusString() const
{
    switch (m_status) {
        case Status::NotStarted: return tr("Not Started");
        case Status::Starting:   return tr("Starting...");
        case Status::Ready:      return tr("Ready");
        case Status::Failed:     return tr("Failed");
        case Status::Stopped:    return tr("Stopped");
    }
    return tr("Unknown");
}

void TorManager::setStatus(Status newStatus, const QString& error)
{
    if (m_status == newStatus) {
        return;
    }

    Status oldStatus = m_status;
    m_status = newStatus;

    if (!error.isEmpty()) {
        m_lastError = error;
        LogPrintf("TorManager: Status changed: %s -> %s (error: %s)\n",
                 statusString().toStdString(),
                 statusString().toStdString(),
                 error.toStdString());
    } else {
        LogPrintf("TorManager: Status changed: %d -> %d\n",
                 static_cast<int>(oldStatus), static_cast<int>(newStatus));
    }

    Q_EMIT statusChanged(newStatus);

    if (newStatus == Status::Failed) {
        Q_EMIT failed(m_lastError);
    }
}

void TorManager::onProcessStarted()
{
    LogPrintf("TorManager: Tor process started (PID=%lld)\n",
             m_torProcess->processId());
}

void TorManager::onProcessFinished(int exitCode, QProcess::ExitStatus exitStatus)
{
    LogPrintf("TorManager: Tor process finished (exitCode=%d, exitStatus=%d)\n",
             exitCode, static_cast<int>(exitStatus));

    if (m_status == Status::Ready || m_status == Status::Starting) {
        // Unexpected termination - stop probing and fail permanently
        if (m_socksProbeTimer && m_socksProbeTimer->isActive()) {
            m_socksProbeTimer->stop();
            LogPrintf("TorManager: Stopped SOCKS probing due to process exit\n");
        }
        setStatus(Status::Failed, tr("Tor process exited unexpectedly (code %1)").arg(exitCode));
    }
}

void TorManager::onProcessError(QProcess::ProcessError error)
{
    QString errorStr;
    switch (error) {
        case QProcess::FailedToStart:
            errorStr = tr("Tor failed to start");
            break;
        case QProcess::Crashed:
            errorStr = tr("Tor crashed");
            break;
        case QProcess::Timedout:
            errorStr = tr("Tor operation timed out");
            break;
        case QProcess::WriteError:
            errorStr = tr("Error writing to Tor process");
            break;
        case QProcess::ReadError:
            errorStr = tr("Error reading from Tor process");
            break;
        default:
            errorStr = tr("Unknown Tor process error");
            break;
    }

    LogPrintf("TorManager: Process error: %s\n", errorStr.toStdString());

    if (m_status == Status::Starting || m_status == Status::Ready) {
        setStatus(Status::Failed, errorStr);
    }
}

void TorManager::onProcessReadyReadStdOut()
{
    if (!m_torProcess) return;

    QByteArray output = m_torProcess->readAllStandardOutput();
    QString outputStr = QString::fromUtf8(output).trimmed();

    if (!outputStr.isEmpty()) {
        LogPrintf("Tor stdout: %s\n", outputStr.toStdString());
    }
}

void TorManager::onProcessReadyReadStdErr()
{
    if (!m_torProcess) return;

    QByteArray output = m_torProcess->readAllStandardError();
    QString outputStr = QString::fromUtf8(output).trimmed();

    if (!outputStr.isEmpty()) {
        LogPrintf("Tor stderr: %s\n", outputStr.toStdString());

        // Check for common error patterns
        if (outputStr.contains("Address already in use", Qt::CaseInsensitive)) {
            setStatus(Status::Failed, tr("Tor port already in use (another instance running?)"));
        }
    }
}

void TorManager::onCookieFileChanged(const QString& path)
{
    Q_UNUSED(path);
    LogPrintf("TorManager: Cookie file changed, checking SOCKS port...\n");

    // Cookie file was created/modified, Tor might be ready
    if (m_status == Status::Starting) {
        checkSocksPortReady();
    }
}

void TorManager::writeTorPidFile()
{
    if (!m_torProcess || m_torProcess->state() != QProcess::Running) return;
    if (m_torPidPath.isEmpty()) return;

    QFile pidFile(m_torPidPath);
    if (!pidFile.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        LogPrintf("TorManager: Failed to write tor.pid: %s\n",
                  pidFile.errorString().toStdString());
        return;
    }
    pidFile.write(QByteArray::number(static_cast<qint64>(m_torProcess->processId())));
    pidFile.close();

    QFile::Permissions perms = QFile::ReadOwner | QFile::WriteOwner;
    QFile::setPermissions(m_torPidPath, perms);

    LogPrintf("TorManager: Wrote tor.pid: %s pid=%lld\n",
              m_torPidPath.toStdString(),
              static_cast<long long>(m_torProcess->processId()));
}

void TorManager::removeTorPidFile()
{
    if (m_torPidPath.isEmpty()) return;
    QFile::remove(m_torPidPath);
}

namespace {
#ifndef Q_OS_WIN
// Returns true if process `pid`'s argv contains `needle`. False on lookup failure.
bool ProcessArgvContains(qint64 pid, const QString& needle)
{
    QProcess ps;
    ps.start("ps", QStringList() << "-p" << QString::number(pid) << "-o" << "args=");
    if (!ps.waitForFinished(2000)) {
        ps.kill();
        return false;
    }
    return QString::fromUtf8(ps.readAllStandardOutput()).contains(needle);
}
#endif

bool KillTorPidImpl(qint64 pid)
{
#ifndef Q_OS_WIN
    if (kill(static_cast<pid_t>(pid), SIGTERM) != 0) {
        if (errno == ESRCH) return true;  // already dead
        LogPrintf("TorManager: kill(SIGTERM) on pid=%lld failed: %s\n",
                  static_cast<long long>(pid), std::strerror(errno));
        return false;
    }
    for (int i = 0; i < 50; ++i) {
        if (kill(static_cast<pid_t>(pid), 0) != 0 && errno == ESRCH) return true;
        QThread::msleep(100);
    }
    LogPrintf("TorManager: pid=%lld didn't exit on SIGTERM; sending SIGKILL\n",
              static_cast<long long>(pid));
    kill(static_cast<pid_t>(pid), SIGKILL);
    QThread::msleep(200);
    // Verify before claiming success — ignoring SIGKILL's return would let a
    // still-bound process slip past while we delete the only breadcrumb.
    return (kill(static_cast<pid_t>(pid), 0) != 0 && errno == ESRCH);
#else
    Q_UNUSED(pid);
    return false;
#endif
}

void ReapFromPidFileImpl(const QString& tor_pid_path, const QString& torrc_path)
{
    if (tor_pid_path.isEmpty() || !QFile::exists(tor_pid_path)) return;

    QFile pidFile(tor_pid_path);
    if (!pidFile.open(QIODevice::ReadOnly)) {
        LogPrintf("TorManager: Could not open stale tor.pid: %s\n",
                  pidFile.errorString().toStdString());
        return;
    }
    QByteArray content = pidFile.readAll().trimmed();
    pidFile.close();

    bool ok = false;
    qint64 pid = content.toLongLong(&ok);
    if (!ok || pid <= 0) {
        LogPrintf("TorManager: tor.pid is malformed, removing\n");
        QFile::remove(tor_pid_path);
        return;
    }

#ifndef Q_OS_WIN
    if (kill(static_cast<pid_t>(pid), 0) != 0 && errno == ESRCH) {
        LogPrintf("TorManager: tor.pid pid=%lld is not alive, removing file\n",
                  static_cast<long long>(pid));
        QFile::remove(tor_pid_path);
        return;
    }

    if (!ProcessArgvContains(pid, torrc_path)) {
        LogPrintf("TorManager: tor.pid pid=%lld is not our tor (PID recycled?); "
                  "removing file, leaving process alone\n",
                  static_cast<long long>(pid));
        QFile::remove(tor_pid_path);
        return;
    }

    LogPrintf("TorManager: Reaping stale tor pid=%lld (from tor.pid)\n",
              static_cast<long long>(pid));
    if (KillTorPidImpl(pid)) {
        QFile::remove(tor_pid_path);
    } else {
        // Process may still be alive and binding ports. Leave the pid file
        // so the next launch tries again, rather than losing the breadcrumb.
        LogPrintf("TorManager: Failed to reap tor pid=%lld; leaving tor.pid for next attempt\n",
                  static_cast<long long>(pid));
    }
#else
    // Windows: reaper not yet implemented. Remove the file so we don't keep
    // retrying a stale entry that we can't act on.
    LogPrintf("TorManager: tor.pid pid=%lld found; reaper not yet implemented on Windows, removing file\n",
              static_cast<long long>(pid));
    QFile::remove(tor_pid_path);
#endif
}

void ReapByArgvImpl(const QString& torrc_path)
{
#ifndef Q_OS_WIN
    if (torrc_path.isEmpty()) return;

    QProcess ps;
    ps.start("ps", QStringList() << "-ax" << "-o" << "pid=,args=");
    if (!ps.waitForFinished(2000)) {
        ps.kill();
        LogPrintf("TorManager: argv scan timed out; skipping legacy reap\n");
        return;
    }

    // QCoreApplication may not exist yet (early static reap path); use ::getpid().
    const qint64 self_pid = static_cast<qint64>(::getpid());
    const QStringList lines = QString::fromUtf8(ps.readAllStandardOutput())
                                  .split('\n', Qt::SkipEmptyParts);

    for (const QString& line : lines) {
        const QString trimmed = line.trimmed();
        if (!trimmed.contains(torrc_path)) continue;

        const int firstSpace = trimmed.indexOf(' ');
        if (firstSpace <= 0) continue;
        bool ok = false;
        const qint64 pid = trimmed.left(firstSpace).toLongLong(&ok);
        if (!ok || pid <= 0 || pid == self_pid) continue;

        LogPrintf("TorManager: Found orphan tor pid=%lld matching torrc=%s; reaping\n",
                  static_cast<long long>(pid), torrc_path.toStdString());
        if (!KillTorPidImpl(pid)) {
            LogPrintf("TorManager: Could not reap orphan tor pid=%lld\n",
                      static_cast<long long>(pid));
        }
    }
#else
    Q_UNUSED(torrc_path);
#endif
}
}  // namespace

bool TorManager::killTorPid(qint64 pid)
{
    return KillTorPidImpl(pid);
}

void TorManager::reapStaleTor()
{
    // Two paths: our own pid file from a prior launch (fast, validated),
    // and an argv scan that catches orphans from unpatched builds or
    // crashes in the window between waitForStarted() and writeTorPidFile().
    reapStaleTorFromPidFile();
    reapStaleTorByArgv();
}

void TorManager::reapStaleTorFromPidFile()
{
    ReapFromPidFileImpl(m_torPidPath, m_torrcPath);
}

void TorManager::reapStaleTorByArgv()
{
    ReapByArgvImpl(m_torrcPath);
}

void TorManager::ReapStaleTorEarly(const QString& datadir)
{
    if (datadir.isEmpty()) return;
    const QString tor_pid_path = QDir(datadir).filePath(".tor/tor.pid");
    const QString torrc_path = QDir(datadir).filePath(".tor/torrc");
    LogPrintf("TorManager: Early reap pass datadir=%s\n", datadir.toStdString());
    ReapFromPidFileImpl(tor_pid_path, torrc_path);
    ReapByArgvImpl(torrc_path);
}
