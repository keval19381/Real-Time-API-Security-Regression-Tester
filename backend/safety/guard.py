import time
import threading
from urllib.parse import urlparse
from typing import List, Optional, Dict, Any, Callable
import httpx

class HostNotAllowedError(Exception):
    """Raised when an outbound test request targets a host not in the safety allowlist."""
    pass

class RateLimitExceededError(Exception):
    """Raised when request volume exceeds token bucket capacity."""
    pass

class CircuitBreakerOpenError(Exception):
    """Raised when the circuit breaker is tripped due to excessive errors or latency."""
    pass


class TokenBucketRateLimiter:
    """
    Thread-safe token bucket rate limiter to prevent denial of service (DoS)
    against target services during active testing.
    """

    def __init__(self, capacity: float = 25.0, refill_rate: float = 15.0):
        self.capacity = float(capacity)
        self.refill_rate = float(refill_rate)  # tokens added per second
        self.tokens = float(capacity)
        self.last_refill = time.time()
        self.lock = threading.Lock()

    def _refill(self):
        now = time.time()
        elapsed = now - self.last_refill
        if elapsed > 0:
            added_tokens = elapsed * self.refill_rate
            self.tokens = min(self.capacity, self.tokens + added_tokens)
            self.last_refill = now

    def acquire(self, tokens: float = 1.0, blocking: bool = False, timeout: float = 2.0) -> bool:
        start_time = time.time()
        with self.lock:
            while True:
                self._refill()
                if self.tokens >= tokens:
                    self.tokens -= tokens
                    return True
                
                if not blocking or (time.time() - start_time) >= timeout:
                    return False
                
                needed = tokens - self.tokens
                sleep_time = min(needed / self.refill_rate, 0.05)
                time.sleep(sleep_time)

    def get_status(self) -> Dict[str, Any]:
        with self.lock:
            self._refill()
            return {
                "capacity": self.capacity,
                "refill_rate_per_sec": self.refill_rate,
                "available_tokens": round(self.tokens, 2)
            }


class CircuitBreaker:
    """
    Adaptive circuit breaker that auto-pauses regression testing when:
    1. Consecutive 5xx server errors exceed threshold (default 3), or
    2. Rolling window error rate exceeds 10%, or
    3. Moving average response latency exceeds 500ms.
    """

    STATE_CLOSED = "CLOSED"       # Normal operations
    STATE_OPEN = "OPEN"           # Tripped; requests blocked to protect target
    STATE_HALF_OPEN = "HALF_OPEN" # Probing recovery

    def __init__(
        self,
        consecutive_error_threshold: int = 3,
        error_rate_threshold: float = 0.10,
        latency_threshold_ms: float = 500.0,
        recovery_timeout_sec: float = 3.0,
        window_size: int = 20
    ):
        self.consecutive_error_threshold = consecutive_error_threshold
        self.error_rate_threshold = error_rate_threshold
        self.latency_threshold_ms = latency_threshold_ms
        self.recovery_timeout_sec = recovery_timeout_sec
        self.window_size = window_size

        self.state = self.STATE_CLOSED
        self.consecutive_errors = 0
        self.window: List[Dict[str, Any]] = []
        self.tripped_at: Optional[float] = None
        self.trip_reason: Optional[str] = None
        self.lock = threading.Lock()

    def check_state(self):
        """Checks if requests are allowed through. Trips or transitions states."""
        with self.lock:
            now = time.time()
            if self.state == self.STATE_OPEN:
                if self.tripped_at and (now - self.tripped_at) >= self.recovery_timeout_sec:
                    self.state = self.STATE_HALF_OPEN
                else:
                    remaining = round(self.recovery_timeout_sec - (now - (self.tripped_at or now)), 2)
                    raise CircuitBreakerOpenError(
                        f"Circuit breaker is OPEN. Target service auto-paused to prevent disruption. "
                        f"Reason: {self.trip_reason}. Cool-down remaining: {max(remaining, 0.1)}s"
                    )

    def record_success(self, latency_ms: float):
        with self.lock:
            self.consecutive_errors = 0
            self._add_to_window(success=True, latency_ms=latency_ms)
            if self.state == self.STATE_HALF_OPEN:
                # Successfully recovered
                self.state = self.STATE_CLOSED
                self.trip_reason = None
                self.tripped_at = None

    def record_failure(self, status_code: int, latency_ms: float, is_server_error: bool = False):
        with self.lock:
            self.consecutive_errors += 1
            self._add_to_window(success=False, latency_ms=latency_ms)

            # Check consecutive 5xx threshold
            if is_server_error and self.consecutive_errors >= self.consecutive_error_threshold:
                self._trip(f"Consecutive 5xx errors reached threshold ({self.consecutive_errors})")
                return

            # Check window error rate
            if len(self.window) >= 5:
                failures = sum(1 for w in self.window if not w["success"])
                error_rate = failures / len(self.window)
                if error_rate > self.error_rate_threshold:
                    self._trip(f"Error rate exceeded threshold: {error_rate*100:.1f}% > {self.error_rate_threshold*100:.1f}%")
                    return

            # Check latency threshold
            avg_latency = sum(w["latency_ms"] for w in self.window) / len(self.window)
            if avg_latency > self.latency_threshold_ms:
                self._trip(f"Moving average latency ({avg_latency:.1f}ms) exceeded safety limit ({self.latency_threshold_ms:.1f}ms)")
                return

            if self.state == self.STATE_HALF_OPEN:
                self._trip("Probe request in HALF_OPEN state failed")

    def _add_to_window(self, success: bool, latency_ms: float):
        self.window.append({"success": success, "latency_ms": latency_ms, "time": time.time()})
        if len(self.window) > self.window_size:
            self.window.pop(0)

    def _trip(self, reason: str):
        self.state = self.STATE_OPEN
        self.tripped_at = time.time()
        self.trip_reason = reason

    def reset(self):
        with self.lock:
            self.state = self.STATE_CLOSED
            self.consecutive_errors = 0
            self.window.clear()
            self.tripped_at = None
            self.trip_reason = None

    def get_status(self) -> Dict[str, Any]:
        with self.lock:
            avg_latency = (sum(w["latency_ms"] for w in self.window) / len(self.window)) if self.window else 0.0
            error_count = sum(1 for w in self.window if not w["success"])
            error_rate = (error_count / len(self.window)) if self.window else 0.0
            return {
                "state": self.state,
                "consecutive_errors": self.consecutive_errors,
                "window_size": len(self.window),
                "error_rate": round(error_rate, 3),
                "moving_avg_latency_ms": round(avg_latency, 2),
                "trip_reason": self.trip_reason
            }


class SafetyGuard:
    """
    Central Safety Controller:
    - Enforces strict local host allowlist
    - Throttles execution via TokenBucketRateLimiter
    - Protects service stability with CircuitBreaker
    - Ensures non-repudiation with append-only hash-chained audit logging
    """

    DEFAULT_ALLOWED_HOSTS = ["localhost", "127.0.0.1", "::1"]
    DEFAULT_ALLOWED_PORTS = [8000, 8001, 8080, 3000, 5000]

    def __init__(
        self,
        allowed_hosts: Optional[List[str]] = None,
        allowed_ports: Optional[List[int]] = None,
        rate_limit_capacity: float = 30.0,
        rate_limit_refill: float = 20.0
    ):
        self.allowed_hosts = set(allowed_hosts or self.DEFAULT_ALLOWED_HOSTS)
        self.allowed_ports = set(allowed_ports or self.DEFAULT_ALLOWED_PORTS)
        self.rate_limiter = TokenBucketRateLimiter(capacity=rate_limit_capacity, refill_rate=rate_limit_refill)
        self.circuit_breaker = CircuitBreaker()
        self.blocked_requests_count = 0

    def validate_url(self, url: str) -> bool:
        """Validates that a URL strictly targets allowed local hosts and ports."""
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        if hostname not in self.allowed_hosts:
            self.blocked_requests_count += 1
            raise HostNotAllowedError(
                f"SAFETY VIOLATION: Host '{hostname}' is not in the safe allowlist {sorted(list(self.allowed_hosts))}. "
                f"DAST engine is strictly confined to local test targets."
            )

        if port not in self.allowed_ports:
            self.blocked_requests_count += 1
            raise HostNotAllowedError(
                f"SAFETY VIOLATION: Port '{port}' is not in the allowed local port range {sorted(list(self.allowed_ports))}."
            )

        return True

    def dispatch_safe_request(
        self,
        client: httpx.Client,
        method: str,
        url: str,
        audit_log_fn: Optional[Callable] = None,
        **kwargs
    ) -> httpx.Response:
        """
        Executes an outbound HTTP request through all safety checks and records audit log.
        """
        # 1. Host allowlist check
        self.validate_url(url)

        # 2. Circuit breaker check
        self.circuit_breaker.check_state()

        # 3. Rate limiter check
        if not self.rate_limiter.acquire(tokens=1.0, blocking=True, timeout=3.0):
            self.blocked_requests_count += 1
            raise RateLimitExceededError("SAFETY VIOLATION: Local rate limit exceeded. Slowing request rate to prevent target disruption.")

        # 4. Dispatch request and measure timing
        start_ts = time.time()
        try:
            response = client.request(method=method, url=url, **kwargs)
            latency_ms = (time.time() - start_ts) * 1000.0

            # 5. Update circuit breaker
            if response.status_code >= 500:
                self.circuit_breaker.record_failure(response.status_code, latency_ms, is_server_error=True)
            elif latency_ms > self.circuit_breaker.latency_threshold_ms:
                self.circuit_breaker.record_failure(response.status_code, latency_ms, is_server_error=False)
            else:
                self.circuit_breaker.record_success(latency_ms)

            # 6. Audit logging callback
            if audit_log_fn:
                audit_log_fn(
                    method=method,
                    url=url,
                    headers=kwargs.get("headers"),
                    body=kwargs.get("json") or kwargs.get("data") or kwargs.get("content"),
                    response_status=response.status_code,
                    response_body=response.text,
                    latency_ms=latency_ms
                )

            return response

        except Exception as exc:
            latency_ms = (time.time() - start_ts) * 1000.0
            self.circuit_breaker.record_failure(status_code=599, latency_ms=latency_ms, is_server_error=True)
            raise exc

    def get_safety_metrics(self) -> Dict[str, Any]:
        return {
            "allowed_hosts": sorted(list(self.allowed_hosts)),
            "allowed_ports": sorted(list(self.allowed_ports)),
            "blocked_requests_count": self.blocked_requests_count,
            "rate_limiter": self.rate_limiter.get_status(),
            "circuit_breaker": self.circuit_breaker.get_status()
        }

safety_guard = SafetyGuard()
