# Cosign RPC Unit Tests Plan

## M2 Milestone Completion Status ✓

**All M2 features completed and tested** (October 2025):

### ✓ Implemented Features
1. **Rate Limiting** - 10 messages/second with sliding window algorithm
2. **Bandwidth Caps** - 5MB total session bandwidth limit
3. **BIP-322 Attestation** - `cosign.attest` RPC for peer verification
4. **Bridge Health Monitoring** - Health state tracking with auto-restart
5. **Session Recovery** - `cosign.resume` RPC with 20-minute recovery window

### ✓ Test Coverage
- **C++ Unit Tests**: 40 tests passing (`cosign_tests.cpp`)
  - Bridge configuration & lifecycle
  - Session management
  - RPC validation
  - Rate limiting enforcement
  - Bandwidth cap enforcement
  - BIP-322 attestation flow
  - Bridge health monitoring
  - Session recovery (resume)

- **Python Functional Tests**: 16 tests passing (`feature_fairsign_adaptor.py`)
  - Tests 1-11: Core coordination features
  - Test 12: Rate limiting (10 msg/sec)
  - Test 13: Bandwidth caps (5MB limit)
  - Test 14: BIP-322 peer attestation
  - Test 15: Bridge health monitoring
  - Test 16: Session recovery with message buffering

### Implementation Details
- **Production Bridge**: Rust implementation at `services/core-node/cosign-bridge/`
- **Session State**: File-based persistence at `/tmp/cosign_sessions_rust.json`
- **Message Buffer**: Circular buffer (256 messages, 5MB, 20-minute retention)
- **Health Monitoring**: Auto-restart with max 3 restarts, heartbeat checks

---

## Overview
Unit tests for `src/rpc/cosign.cpp` RPC handlers. The functional tests in `test/functional/feature_fairsign_adaptor.py::test_cosign_coordination()` provide comprehensive end-to-end testing with the production Rust bridge. These unit tests should focus on internal logic and edge cases.

## Test Coverage

### 1. BridgeManager Tests
```cpp
BOOST_AUTO_TEST_SUITE(cosign_bridge_manager_tests)

// Test bridge path configuration
BOOST_AUTO_TEST_CASE(bridge_configuration)
{
    // Test -cosignbridge flag parsing
    // Test IsEnabled() returns false when not configured
    // Test IsEnabled() returns true when path set
    // Test GetBridgePath() returns correct path
}

// Test session registration
BOOST_AUTO_TEST_CASE(session_registration)
{
    // Create session state
    // Register session
    // Verify GetSession() returns same session
    // Verify GetSession() returns nullptr for unknown ID
}

// Test session removal
BOOST_AUTO_TEST_CASE(session_removal)
{
    // Register session
    // Remove session
    // Verify GetSession() returns nullptr after removal
}

// Test session expiration
BOOST_AUTO_TEST_CASE(session_expiration)
{
    // Create expired session (created_at in past)
    // Call PruneExpiredSessions()
    // Verify expired sessions removed
    // Verify non-expired sessions remain
}

// Test active session count
BOOST_AUTO_TEST_CASE(active_session_count)
{
    // Register multiple sessions
    // Verify GetActiveSessionCount() returns correct count
    // Remove one session
    // Verify count decremented
}

BOOST_AUTO_TEST_SUITE_END()
```

### 2. SessionState Tests
```cpp
BOOST_AUTO_TEST_SUITE(cosign_session_state_tests)

// Test session creation
BOOST_AUTO_TEST_CASE(session_creation)
{
    // Create SessionState with ID and TTL
    // Verify session_id set correctly
    // Verify created_at set to current time
    // Verify ttl_sec set correctly
    // Verify state is "open"
}

// Test IsExpired()
BOOST_AUTO_TEST_CASE(is_expired)
{
    // Create session with short TTL
    // Verify IsExpired() returns false initially
    // Sleep for TTL duration
    // Verify IsExpired() returns true after TTL
}

BOOST_AUTO_TEST_SUITE_END()
```

### 3. RPC Handler Input Validation Tests
```cpp
BOOST_AUTO_TEST_SUITE(cosign_rpc_validation_tests)

// Test cosign.init parameter validation
BOOST_AUTO_TEST_CASE(init_ttl_validation)
{
    // Test TTL < 60 throws error
    // Test TTL > 86400 throws error
    // Test valid TTL accepted
}

// Test cosign.send parameter validation
BOOST_AUTO_TEST_CASE(send_parameter_validation)
{
    // Test empty session_id throws error
    // Test invalid session_id throws error
    // Test missing payload throws error
}

// Test cosign.recv parameter validation
BOOST_AUTO_TEST_CASE(recv_parameter_validation)
{
    // Test timeout_ms validation
    // Test negative timeout handled
    // Test zero timeout handled
}

// Test cosign.status on unknown session
BOOST_AUTO_TEST_CASE(status_unknown_session)
{
    // Call cosign.status with non-existent session_id
    // Verify RPC_INVALID_PARAMETER error thrown
}

// Test operations when bridge not configured
BOOST_AUTO_TEST_CASE(bridge_not_configured)
{
    // Configure BridgeManager with empty path
    // Call cosign.version
    // Verify COSIGN_DISABLED error thrown
    // Repeat for other RPCs
}

BOOST_AUTO_TEST_SUITE_END()
```

### 4. Bridge Communication Error Handling Tests
```cpp
BOOST_AUTO_TEST_SUITE(cosign_bridge_error_tests)

// Test bridge process failure
BOOST_AUTO_TEST_CASE(bridge_process_failure)
{
    // Configure bridge path to non-existent binary
    // Call cosign.ping
    // Verify error message contains bridge failure details
}

// Test bridge malformed response
BOOST_AUTO_TEST_CASE(bridge_malformed_response)
{
    // Mock bridge that returns invalid JSON
    // Call cosign.version
    // Verify appropriate error thrown
}

// Test bridge error response
BOOST_AUTO_TEST_CASE(bridge_error_response)
{
    // Mock bridge that returns {"error": "test error"}
    // Call any RPC
    // Verify error propagated to caller
}

// Test retry logic
BOOST_AUTO_TEST_CASE(bridge_retry_logic)
{
    // Mock bridge that fails first N times
    // Verify retry count incremented
    // Verify max retries respected
}

BOOST_AUTO_TEST_SUITE_END()
```

### 5. Thread Safety Tests
```cpp
BOOST_AUTO_TEST_SUITE(cosign_thread_safety_tests)

// Test concurrent session registration
BOOST_AUTO_TEST_CASE(concurrent_registration)
{
    // Spawn multiple threads
    // Each thread registers unique session
    // Verify all sessions registered correctly
    // Verify no data races
}

// Test concurrent session access
BOOST_AUTO_TEST_CASE(concurrent_access)
{
    // Register session
    // Spawn threads that call GetSession() concurrently
    // Verify no crashes or data races
}

// Test concurrent pruning
BOOST_AUTO_TEST_CASE(concurrent_pruning)
{
    // Register sessions
    // Spawn thread that calls PruneExpiredSessions()
    // Spawn threads that access sessions
    // Verify thread-safe operation
}

BOOST_AUTO_TEST_SUITE_END()
```

## Implementation Notes

1. **Mocking**: Use a mock bridge binary for tests that require bridge communication
2. **Isolation**: Each test should clean up sessions to avoid interference
3. **Timing**: Tests involving TTL/expiration should use small values to avoid long test duration
4. **Error Messages**: Verify error messages are informative and follow Bitcoin Core conventions
5. **Security**: Test that sensitive data (session keys, etc.) is not leaked in errors

## Functional Test Coverage (Already Implemented)

The following is already covered by `feature_fairsign_adaptor.py::test_cosign_coordination()`:
- ✓ End-to-end RPC workflow (init → send → recv → close)
- ✓ Bridge version/ping checks
- ✓ Session creation and join via invite link
- ✓ Message exchange
- ✓ Session status queries
- ✓ Metrics collection
- ✓ Fair-Sign ceremony coordination simulation

## Priority

**High Priority (should implement)**:
- Bridge configuration tests
- Session expiration tests
- Parameter validation tests
- Error handling tests

**Medium Priority (nice to have)**:
- Thread safety tests
- Retry logic tests

**Low Priority (covered by functional tests)**:
- End-to-end workflow tests (already in Python)
- Bridge communication tests (use functional tests)
