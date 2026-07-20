// Copyright (c) 2025 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_QT_BRIDGESESSIONMANAGER_H
#define BITCOIN_QT_BRIDGESESSIONMANAGER_H

#include <QObject>
#include <QMap>
#include <QString>

class WalletModel;

/**
 * @brief Shared model for managing cosign bridge sessions across tabs
 *
 * This class maintains the active session state and provides signals
 * to notify UI components when sessions are created, updated, or closed.
 * It is owned by ExchangeP2PPage and shared with all sub-tabs.
 */
class BridgeSessionManager : public QObject
{
    Q_OBJECT

public:
    enum class SessionPurpose {
        Trade,       // P2P trading (default)
        Contract,    // Financial contract execution
        Governance   // Asset governance voting
    };

    struct SessionInfo {
        QString session_id;
        QString sas;
        QString sas_numeric;
        QString state;
        QString transport;
        QString relay_url;  // For WebSocket transport
        int64_t started_timestamp;
        bool handshake_complete{false};
        bool is_initiator{false};  // true if created via init, false if joined

        // Session purpose and context
        SessionPurpose purpose{SessionPurpose::Trade};
        QString proposal_id;  // For governance sessions
        QString asset_id;     // For governance/contract sessions
        QString contract_id;  // Reference to the contract being negotiated in this session
        QString contract_type;  // Type of contract (repo, forward, option, etc.)
    };

    explicit BridgeSessionManager(WalletModel* walletModel, QObject* parent = nullptr);
    ~BridgeSessionManager();

    // Session management
    void addSession(const SessionInfo& session);
    void updateSession(const QString& session_id, const SessionInfo& session);
    void removeSession(const QString& session_id);
    void updateSessionHandshakeStatus(const QString& session_id, bool complete);

    // Session queries
    QList<SessionInfo> getActiveSessions() const;
    SessionInfo getSession(const QString& session_id) const;
    bool hasSession(const QString& session_id) const;
    int sessionCount() const;

    // Get list of sessions with completed handshakes (for offer sharing)
    QList<SessionInfo> getHandshakeCompleteSessions() const;

Q_SIGNALS:
    void sessionAdded(const QString& session_id);
    void sessionUpdated(const QString& session_id);
    void sessionRemoved(const QString& session_id);
    void sessionsChanged();  // General purpose signal when any change occurs

private:
    WalletModel* walletModel;
    QMap<QString, SessionInfo> sessions;
};

#endif // BITCOIN_QT_BRIDGESESSIONMANAGER_H
