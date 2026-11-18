"""
Safety Layer for Real-Time DAST Regression Tester:
Enforces host allowlists, rate limits, circuit breakers, and append-only hash-chained audit logging.
"""

from backend.safety.guard import SafetyGuard, HostNotAllowedError, RateLimitExceededError, CircuitBreakerOpenError, safety_guard
from backend.safety.audit_log import AuditLogger, audit_logger

__all__ = [
    "SafetyGuard",
    "HostNotAllowedError",
    "RateLimitExceededError",
    "CircuitBreakerOpenError",
    "safety_guard",
    "AuditLogger",
    "audit_logger"
]
