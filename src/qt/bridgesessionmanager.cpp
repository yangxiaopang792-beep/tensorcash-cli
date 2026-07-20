// Copyright (c) 2025 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <qt/bridgesessionmanager.h>
#include <qt/walletmodel.h>

BridgeSessionManager::BridgeSessionManager(WalletModel* walletModel, QObject* parent)
    : QObject(parent),
      walletModel(walletModel)
{
}

BridgeSessionManager::~BridgeSessionManager()
{
}

void BridgeSessionManager::addSession(const SessionInfo& session)
{
    sessions[session.session_id] = session;
    Q_EMIT sessionAdded(session.session_id);
    Q_EMIT sessionsChanged();
}

void BridgeSessionManager::updateSession(const QString& session_id, const SessionInfo& session)
{
    if (sessions.contains(session_id)) {
        sessions[session_id] = session;
        Q_EMIT sessionUpdated(session_id);
        Q_EMIT sessionsChanged();
    }
}

void BridgeSessionManager::removeSession(const QString& session_id)
{
    if (sessions.remove(session_id) > 0) {
        Q_EMIT sessionRemoved(session_id);
        Q_EMIT sessionsChanged();
    }
}

void BridgeSessionManager::updateSessionHandshakeStatus(const QString& session_id, bool complete)
{
    if (sessions.contains(session_id)) {
        sessions[session_id].handshake_complete = complete;
        Q_EMIT sessionUpdated(session_id);
        Q_EMIT sessionsChanged();
    }
}

QList<BridgeSessionManager::SessionInfo> BridgeSessionManager::getActiveSessions() const
{
    return sessions.values();
}

BridgeSessionManager::SessionInfo BridgeSessionManager::getSession(const QString& session_id) const
{
    return sessions.value(session_id);
}

bool BridgeSessionManager::hasSession(const QString& session_id) const
{
    return sessions.contains(session_id);
}

int BridgeSessionManager::sessionCount() const
{
    return sessions.size();
}

QList<BridgeSessionManager::SessionInfo> BridgeSessionManager::getHandshakeCompleteSessions() const
{
    QList<SessionInfo> result;
    for (const SessionInfo& session : sessions.values()) {
        if (session.handshake_complete) {
            result.append(session);
        }
    }
    return result;
}
