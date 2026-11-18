from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from pydantic import BaseModel
import httpx

from backend.safety.guard import safety_guard
from backend.safety.audit_log import audit_logger
from backend.test_planner import TestCasePlan

class CheckResult(BaseModel):
    check_name: str
    test_id: str
    target_endpoint: str
    method: str
    url: str
    vulnerability_detected: bool
    status_code: int
    expected_status: int
    response_body: Optional[Any] = None
    reproduction_request: Dict[str, Any]
    error_message: Optional[str] = None
    latency_ms: float = 0.0

class BaseCheck(ABC):
    """Abstract base class for all DAST security and logic checks."""

    def __init__(self, name: str, category: str, description: str):
        self.name = name
        self.category = category
        self.description = description

    @abstractmethod
    def run(self, test_case: TestCasePlan, target_base_url: str) -> CheckResult:
        pass
