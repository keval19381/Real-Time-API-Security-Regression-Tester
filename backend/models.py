from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime

class DeploymentWebhookPayload(BaseModel):
    event: str = "deployment"
    service: str = "target_app"
    environment: str = "production"
    version: str
    commit_sha: str
    timestamp: Optional[str] = None
    bundle_url: Optional[str] = None
    openapi_url: Optional[str] = None
    target_base_url: Optional[str] = None
    deployed_by: Optional[str] = "ci-bot"
    notes: Optional[str] = None

class EndpointInventoryItem(BaseModel):
    endpoint_id: str
    method: str
    path: str
    status: str  # 'Active', 'Legacy-unused (zombie)', 'Undocumented (shadow)'
    in_openapi: bool
    in_crawler: bool
    in_traffic: bool
    traffic_count_last_90d: int = 0
    traffic_count_last_30d: int = 0
    last_seen_in_traffic: Optional[str] = None
    allowed_roles: List[str] = Field(default_factory=list)
    parameters: List[Dict[str, Any]] = Field(default_factory=list)
    description: Optional[str] = None
    first_detected: str

class BundleHashInfo(BaseModel):
    bundle_url: str
    file_name: str
    content_hash: str
    detected_endpoints: List[str] = Field(default_factory=list)
    timestamp: str

class DeploymentChangeSummary(BaseModel):
    deploy_id: str
    version: str
    commit_sha: str
    timestamp: str
    bundle_changed: bool
    previous_bundle_hash: Optional[str] = None
    new_bundle_hash: Optional[str] = None
    newly_discovered_routes: List[str] = Field(default_factory=list)
    modified_routes: List[str] = Field(default_factory=list)
    shadow_routes_detected: List[str] = Field(default_factory=list)
    zombie_routes_detected: List[str] = Field(default_factory=list)
    inventory_summary: Dict[str, int] = Field(default_factory=dict)

class TrafficLogEntry(BaseModel):
    timestamp: str
    method: str
    path: str
    status_code: int
    user_id: Optional[str] = None
    agency_id: Optional[str] = None
    role: Optional[str] = None
    ip: Optional[str] = "127.0.0.1"
    response_time_ms: float = 24.5
