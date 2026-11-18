import pytest
import sqlite3
import time
import httpx

from backend.safety.guard import (
    SafetyGuard,
    HostNotAllowedError,
    RateLimitExceededError,
    CircuitBreakerOpenError,
    TokenBucketRateLimiter,
    CircuitBreaker,
    safety_guard
)
from backend.safety.audit_log import AuditLogger, GENESIS_HASH

class TestHostAllowlist:
    def test_allowed_local_hosts(self):
        guard = SafetyGuard(allowed_hosts=["localhost", "127.0.0.1"], allowed_ports=[8000, 8001])
        assert guard.validate_url("http://127.0.0.1:8001/api/v1/flights/search") is True
        assert guard.validate_url("http://localhost:8000/webhook/deploy") is True

    def test_rejected_external_hosts(self):
        guard = SafetyGuard(allowed_hosts=["localhost", "127.0.0.1"], allowed_ports=[8000, 8001])
        with pytest.raises(HostNotAllowedError) as exc_info:
            guard.validate_url("https://external-api.attacker.com/v1/leak")
        assert "not in the safe allowlist" in str(exc_info.value)

    def test_rejected_public_ip(self):
        guard = SafetyGuard(allowed_hosts=["localhost", "127.0.0.1"], allowed_ports=[8000, 8001])
        with pytest.raises(HostNotAllowedError):
            guard.validate_url("http://8.8.8.8:8001/api")

    def test_rejected_unauthorized_port(self):
        guard = SafetyGuard(allowed_hosts=["localhost", "127.0.0.1"], allowed_ports=[8000, 8001])
        with pytest.raises(HostNotAllowedError) as exc_info:
            guard.validate_url("http://127.0.0.1:9099/api")
        assert "not in the allowed local port range" in str(exc_info.value)


class TestTokenBucketRateLimiter:
    def test_burst_capacity_and_exhaustion(self):
        limiter = TokenBucketRateLimiter(capacity=5.0, refill_rate=2.0)
        # Should be able to acquire up to capacity
        for _ in range(5):
            assert limiter.acquire(1.0, blocking=False) is True
        # Next immediate request must be throttled
        assert limiter.acquire(1.0, blocking=False) is False

    def test_refill_over_time(self):
        limiter = TokenBucketRateLimiter(capacity=2.0, refill_rate=10.0)
        assert limiter.acquire(2.0, blocking=False) is True
        assert limiter.acquire(1.0, blocking=False) is False
        time.sleep(0.15)  # 0.15s * 10 tokens/s = 1.5 tokens refilled
        assert limiter.acquire(1.0, blocking=False) is True


class TestCircuitBreaker:
    def test_trips_on_consecutive_server_errors(self):
        cb = CircuitBreaker(consecutive_error_threshold=3, recovery_timeout_sec=1.0)
        assert cb.state == CircuitBreaker.STATE_CLOSED

        cb.record_failure(status_code=500, latency_ms=20.0, is_server_error=True)
        cb.check_state()
        cb.record_failure(status_code=502, latency_ms=25.0, is_server_error=True)
        cb.check_state()

        # 3rd consecutive error trips breaker
        cb.record_failure(status_code=503, latency_ms=30.0, is_server_error=True)
        assert cb.state == CircuitBreaker.STATE_OPEN

        with pytest.raises(CircuitBreakerOpenError) as exc:
            cb.check_state()
        assert "Circuit breaker is OPEN" in str(exc.value)

    def test_trips_on_latency_spike(self):
        cb = CircuitBreaker(latency_threshold_ms=100.0, window_size=5)
        for _ in range(5):
            cb.record_failure(status_code=200, latency_ms=250.0, is_server_error=False)
        assert cb.state == CircuitBreaker.STATE_OPEN

    def test_recovery_transition(self):
        cb = CircuitBreaker(consecutive_error_threshold=2, recovery_timeout_sec=0.2)
        cb.record_failure(status_code=500, latency_ms=10.0, is_server_error=True)
        cb.record_failure(status_code=500, latency_ms=10.0, is_server_error=True)
        assert cb.state == CircuitBreaker.STATE_OPEN

        time.sleep(0.25)
        # Check transitions to HALF_OPEN
        cb.check_state()
        assert cb.state == CircuitBreaker.STATE_HALF_OPEN

        # Successful probe recovers to CLOSED
        cb.record_success(latency_ms=15.0)
        assert cb.state == CircuitBreaker.STATE_CLOSED


class TestHashChainedAuditLog:
    def test_audit_log_chaining_and_integrity(self, tmp_path):
        test_db = str(tmp_path / "test_audit.sqlite")
        logger = AuditLogger(db_path=test_db)

        # Log entry 0
        e0 = logger.record(
            method="GET",
            url="http://127.0.0.1:8001/api/v1/flights/search",
            headers={"Authorization": "Bearer token-apex-sub"},
            body=None,
            response_status=200,
            response_body=[{"flight_id": "FL-101"}],
            latency_ms=18.5
        )
        assert e0["entry_index"] == 0
        assert e0["prev_hash"] == GENESIS_HASH

        # Log entry 1
        e1 = logger.record(
            method="POST",
            url="http://127.0.0.1:8001/api/v1/flights/hold",
            headers={"Authorization": "Bearer token-apex-sub"},
            body={"flight_id": "FL-101", "passengers": 1},
            response_status=200,
            response_body={"hold_id": "HLD-TEST-01"},
            latency_ms=22.1
        )
        assert e1["entry_index"] == 1
        assert e1["prev_hash"] == e0["entry_hash"]

        # Verify integrity
        is_valid, msg = logger.verify_integrity()
        assert is_valid is True
        assert "integrity verified" in msg

    def test_tamper_detection(self, tmp_path):
        test_db = str(tmp_path / "test_audit_tamper.sqlite")
        logger = AuditLogger(db_path=test_db)

        # Record 3 events
        logger.record("GET", "http://127.0.0.1:8001/1", response_status=200)
        logger.record("GET", "http://127.0.0.1:8001/2", response_status=200)
        logger.record("GET", "http://127.0.0.1:8001/3", response_status=200)

        # Tamper directly with the SQLite database row (simulate malicious log modification)
        conn = sqlite3.connect(test_db)
        cursor = conn.cursor()
        cursor.execute("UPDATE audit_log SET response_status = 500 WHERE entry_index = 1")
        conn.commit()
        conn.close()

        # Integrity verification must detect the tampering
        is_valid, err_msg = logger.verify_integrity()
        assert is_valid is False
        assert "tampering detected at index 1" in err_msg


class TestSafeRequestDispatcher:
    def test_dispatcher_with_real_target(self):
        with httpx.Client(base_url="http://127.0.0.1:8001", timeout=5.0) as client:
            resp = safety_guard.dispatch_safe_request(
                client=client,
                method="GET",
                url="http://127.0.0.1:8001/health"
            )
            assert resp.status_code == 200
            assert resp.json()["status"] == "healthy"

    def test_dispatcher_blocks_unauthorized_destination(self):
        with httpx.Client(timeout=2.0) as client:
            with pytest.raises(HostNotAllowedError):
                safety_guard.dispatch_safe_request(
                    client=client,
                    method="GET",
                    url="https://api.github.com/zen"
                )
