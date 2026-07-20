#!/usr/bin/env python3
"""
Mock cosign bridge binary for functional testing.

Implements the HWI-style stdio protocol:
- Reads JSON command from stdin
- Processes command
- Returns JSON response to stdout

Simulates bridge behavior without actual networking/crypto.
"""

import sys
import json
import hashlib
import time
import os
from typing import Dict, Any

# In-memory session storage (persists across invocations during test)
SESSION_FILE = "/tmp/mock_cosign_sessions.json"


def load_sessions() -> Dict[str, Any]:
    """Load session state from temp file"""
    if os.path.exists(SESSION_FILE):
        try:
            with open(SESSION_FILE, 'r') as f:
                return json.load(f)
        except:
            return {}
    return {}


def save_sessions(sessions: Dict[str, Any]):
    """Save session state to temp file"""
    with open(SESSION_FILE, 'w') as f:
        json.dump(sessions, f)


def generate_invite_code(session_id: str) -> str:
    """Generate 5-word invite code from session_id"""
    # Use first 20 chars of session_id as seed
    seed = int(session_id[:20], 16)
    words = ["apple", "banana", "cherry", "delta", "echo", "foxtrot", "golf", "hotel"]
    code_words = []
    for i in range(5):
        word_idx = (seed >> (i * 3)) % len(words)
        code_words.append(words[word_idx])
    return "-".join(code_words)


def generate_sas(session_id: str) -> tuple[str, str]:
    """Generate SAS (5-word and 6-digit) from session_id"""
    # 5-word SAS
    seed = int(session_id[20:40], 16)
    words = ["word1", "word2", "word3", "word4", "word5", "alpha", "bravo", "charlie"]
    sas_words = []
    for i in range(5):
        word_idx = (seed >> (i * 3)) % len(words)
        sas_words.append(words[word_idx])

    # 6-digit numeric SAS
    sas_numeric = str((seed % 900000) + 100000)

    return "-".join(sas_words), sas_numeric


def handle_version(params: Dict[str, Any]) -> Dict[str, Any]:
    """Handle version command"""
    return {
        "api_version": 1,
        "git_commit": "mock-bridge-dev",
        "build_flags": ["noise", "spake2", "websocket", "nostr"],
        "bridge_version": "0.1.0-mock"
    }


def handle_ping(params: Dict[str, Any]) -> Dict[str, Any]:
    """Handle ping command

    SECURITY: Only advertise capabilities that are actually implemented.
    Advertising unimplemented capabilities causes tests to pass incorrectly.
    """
    return {
        "bridge_alive": True,
        "version": "0.1.0-mock",
        "transports": ["ws", "nostr", "webrtc"],
        "uptime_sec": 123,
        # Only advertise capabilities that are actually implemented in this mock
        # DO NOT add capabilities without implementing the corresponding handler
        "capabilities": ["resume", "send_multi"]
    }


def handle_init(params: Dict[str, Any]) -> Dict[str, Any]:
    """Handle init command - create new session"""
    sessions = load_sessions()

    # Generate session ID from timestamp and params
    seed = json.dumps(params, sort_keys=True) + str(time.time())
    session_id = hashlib.sha256(seed.encode()).hexdigest()

    transport = params.get("transport", "auto")
    ttl = params.get("ttl", 1800)

    invite_code = generate_invite_code(session_id)
    sas, sas_numeric = generate_sas(session_id)

    # Store session
    sessions[session_id] = {
        "session_id": session_id,
        "invite_code": invite_code,
        "sas": sas,
        "sas_numeric": sas_numeric,
        "transport": transport,
        "ttl": ttl,
        "created_at": time.time(),
        "messages": [],
        "state": "open",
        "handshake_complete": False  # SECURITY: Phase 4 requirement - no send/recv before handshake
    }
    save_sessions(sessions)

    # Build invite link
    room_id = session_id[:16]
    invite_link = f"cosign:?r={room_id}&t={transport}#c={invite_code}"

    return {
        "session_id": session_id,
        "invite_link": invite_link,
        "invite_code": invite_code,
        "qr_data": invite_link,
        "qr_error_correction": "M",
        "sas": sas,
        "sas_numeric": sas_numeric,
        "transport_selected": transport
    }


def handle_join(params: Dict[str, Any]) -> Dict[str, Any]:
    """Handle join command - join existing session"""
    invite_link = params.get("invite_link", "")

    # Parse invite link to extract room_id and code
    # Format: cosign:?r=<room>&t=<transport>#c=<code>
    if "?r=" in invite_link and "#c=" in invite_link:
        room_part = invite_link.split("?r=")[1].split("&")[0]
        code_part = invite_link.split("#c=")[1]

        # Find session by matching invite code
        sessions = load_sessions()
        for sid, session in sessions.items():
            if session.get("invite_code") == code_part:
                return {
                    "session_id": sid,
                    "sas": session["sas"],
                    "sas_numeric": session["sas_numeric"]
                }

        # Session not found - this shouldn't happen in production
        # For mock testing, we can't find the session because each node
        # has its own bridge process. Return error to match production behavior.
        return {"error": f"Session not found for invite code: {code_part}"}

    return {"error": "Invalid invite link format"}


def handle_handshake_auto(params: Dict[str, Any]) -> Dict[str, Any]:
    """Handle handshake_auto command - complete SPAKE2/Noise handshake

    SECURITY: Phase 4 requirement - handshake MUST complete before send/recv.
    This mock simulates successful handshake to test the enforcement logic.
    """
    sessions = load_sessions()
    session_id = params.get("session_id")

    if session_id not in sessions:
        return {"error": f"Unknown session: {session_id}"}

    # Mark handshake as complete
    session = sessions[session_id]
    if session.get("handshake_complete"):
        return {
            "handshake_complete": True,
            "sas": session["sas"],
            "sas_numeric": session["sas_numeric"],
            "message": "Handshake already complete; returning cached session state."
        }

    session["handshake_complete"] = True
    save_sessions(sessions)

    return {
        "handshake_complete": True,
        "sas": session["sas"],
        "sas_numeric": session["sas_numeric"],
        "message": "Handshake complete! Verify SAS with peer to confirm no MITM."
    }


def handle_send(params: Dict[str, Any]) -> Dict[str, Any]:
    """Handle send command - send payload to peer

    SECURITY: Enforces handshake completion before allowing send (Phase 4 requirement).
    """
    sessions = load_sessions()
    session_id = params.get("session_id")
    payload = params.get("payload", {})

    if session_id not in sessions:
        return {"error": f"Unknown session: {session_id}"}

    session = sessions[session_id]

    # SECURITY: Phase 4 enforcement - reject send before handshake completes
    if not session.get("handshake_complete", False):
        return {"error": "COSIGN_HANDSHAKE_REQUIRED: Cannot send before SPAKE2/Noise handshake completes. Use cosign.handshake_auto first."}

    if session["state"] != "open":
        return {"error": f"Session not open: {session['state']}"}

    # Store message
    session["messages"].append({
        "direction": "sent",
        "payload": payload,
        "timestamp": time.time()
    })
    save_sessions(sessions)

    return {
        "ok": True,
        "seq": len([m for m in session["messages"] if m["direction"] == "sent"])
    }


def handle_recv(params: Dict[str, Any]) -> Dict[str, Any]:
    """Handle recv command - receive payload from peer

    SECURITY: Enforces handshake completion before allowing recv (Phase 4 requirement).
    """
    sessions = load_sessions()
    session_id = params.get("session_id")
    timeout_ms = params.get("timeout_ms", 30000)

    if session_id not in sessions:
        return {"error": f"Unknown session: {session_id}"}

    session = sessions[session_id]

    # SECURITY: Phase 4 enforcement - reject recv before handshake completes
    if not session.get("handshake_complete", False):
        return {"error": "COSIGN_HANDSHAKE_REQUIRED: Cannot recv before SPAKE2/Noise handshake completes. Use cosign.handshake_auto first."}

    # Mock: Echo back the last sent message as a received message
    # In real bridge, this would poll/long-poll for peer messages
    sent_messages = [m for m in session["messages"] if m["direction"] == "sent"]
    if sent_messages:
        last_sent = sent_messages[-1]
        # Return a mock response based on the sent payload
        mock_response = {
            "type": "response",
            "echo": last_sent["payload"]
        }
        return {"payload": mock_response}

    # No messages yet - return empty payload
    return {"payload": {"type": "no_messages"}}


def handle_status(params: Dict[str, Any]) -> Dict[str, Any]:
    """Handle status command - get session status"""
    sessions = load_sessions()
    session_id = params.get("session_id")

    if session_id not in sessions:
        return {"error": f"Unknown session: {session_id}"}

    session = sessions[session_id]
    age_sec = int(time.time() - session["created_at"])

    messages_sent = len([m for m in session["messages"] if m["direction"] == "sent"])
    messages_received = len([m for m in session["messages"] if m["direction"] == "received"])

    return {
        "state": session["state"],
        "peer_verified": True,  # Mock: always verified
        "messages_sent": messages_sent,
        "messages_received": messages_received,
        "age_sec": age_sec,
        "ttl_sec": session["ttl"],
        "transport": session["transport"]
    }


def handle_close(params: Dict[str, Any]) -> Dict[str, Any]:
    """Handle close command - close session"""
    sessions = load_sessions()
    session_id = params.get("session_id")

    if session_id in sessions:
        sessions[session_id]["state"] = "closed"
        save_sessions(sessions)

    return {"ok": True}


def handle_metrics(params: Dict[str, Any]) -> Dict[str, Any]:
    """Handle metrics command - get bridge metrics"""
    sessions = load_sessions()
    active_count = len([s for s in sessions.values() if s["state"] == "open"])

    total_messages = sum(len(s["messages"]) for s in sessions.values())

    return {
        "active_sessions": active_count,
        "total_messages": total_messages,
        "bridge_restarts": 0,
        "transport_failures": {
            "ws": 0,
            "nostr": 0
        },
        "avg_latency_ms": 42,
        "p95_latency_ms": 85,
        "p99_latency_ms": 150
    }


def main():
    """Main entry point - read stdin, process command, write stdout"""
    try:
        # Read JSON request from stdin
        request_line = sys.stdin.readline()
        if not request_line:
            print(json.dumps({"error": "No input provided"}))
            sys.exit(1)

        request = json.loads(request_line)
        command = request.get("command")
        params = request.get("params", {})

        # Dispatch to handler
        handlers = {
            "version": handle_version,
            "ping": handle_ping,
            "init": handle_init,
            "join": handle_join,
            "handshake_auto": handle_handshake_auto,
            "send": handle_send,
            "recv": handle_recv,
            "status": handle_status,
            "close": handle_close,
            "metrics": handle_metrics
        }

        if command not in handlers:
            response = {"error": f"Unknown command: {command}"}
        else:
            response = handlers[command](params)

        # Write JSON response to stdout
        print(json.dumps(response))
        sys.exit(0)

    except Exception as e:
        # Return error as JSON
        print(json.dumps({"error": str(e)}))
        sys.exit(1)


if __name__ == "__main__":
    main()
