import json
import os
import random
import re
from datetime import datetime, timedelta
from typing import Dict, List, Any, Tuple, Optional
from backend.config import backend_settings
from backend.models import TrafficLogEntry

# Regex to normalize dynamic path parameters (e.g. BKG-APEX-9901 -> {booking_id})
BOOKING_ID_REGEX = re.compile(r"/api/v1/bookings/(BKG-[A-Z0-9\-]+)")

def normalize_path(path: str) -> str:
    """Normalizes dynamic path parameters into OpenAPI templated form."""
    clean_path = path.split("?")[0].strip()
    clean_path = BOOKING_ID_REGEX.sub(r"/api/v1/bookings/{booking_id}", clean_path)
    return clean_path

class TrafficLogParser:
    """
    Generates realistic 30-90 day synthetic traffic logs and parses them
    to extract endpoint usage statistics, last seen dates, and role distribution.
    """

    def __init__(self, log_path: str = backend_settings.TRAFFIC_LOGS_PATH):
        self.log_path = log_path

    def generate_synthetic_logs(self, days: int = 90, total_requests: int = 2500) -> str:
        """
        Synthesizes realistic API traffic logs spanning the past `days` (default 90 days).
        Ensures clear distinction between:
          - Active routes (consistently active over last 30-90 days)
          - Shadow routes (/api/v1/promotions/apply - active recently, missing from OpenAPI)
          - Zombie routes (/api/v1/legacy/xml-rates - in OpenAPI, but inactive for > 60 days)
        """
        now = datetime.utcnow()
        entries: List[Dict[str, Any]] = []

        # Route templates with their active timeframes and weight distribution
        active_routes = [
            ("GET", "/api/v1/flights/search", 0.35, (0, days)),
            ("POST", "/api/v1/flights/hold", 0.20, (0, days)),
            ("POST", "/api/v1/bookings", 0.15, (0, days)),
            ("GET", "/api/v1/bookings", 0.08, (0, days)),
            ("GET", "/api/v1/bookings/BKG-APEX-9901", 0.05, (0, days)),
            ("POST", "/api/v1/bookings/BKG-APEX-9901/pay", 0.07, (0, days)),
            ("POST", "/api/v1/bookings/BKG-APEX-9901/cancel", 0.03, (0, days)),
            ("GET", "/api/v1/agency/commissions", 0.03, (0, days)),
        ]

        # Shadow route: Active recently (promotions API launched 25 days ago)
        shadow_routes = [
            ("POST", "/api/v1/promotions/apply", 0.08, (0, 25))
        ]

        # Zombie route: Legacy XML rates only had requests 70-90 days ago, zero in last 60 days
        zombie_routes = [
            ("GET", "/api/v1/legacy/xml-rates?carrier=BA", 0.05, (70, 90))
        ]

        users = [
            ("usr_apex_sub1", "agency_apex", "sub_agent"),
            ("usr_apex_admin1", "agency_apex", "agency_admin"),
            ("usr_global_sub1", "agency_global", "sub_agent"),
            ("usr_global_admin1", "agency_global", "agency_admin")
        ]

        # 1. Generate active route traffic
        for _ in range(int(total_requests * 0.85)):
            method, path_template, _, (min_day, max_day) = random.choice(active_routes)
            day_offset = random.uniform(min_day, max_day)
            entry_time = now - timedelta(days=day_offset, minutes=random.randint(0, 1440))
            user = random.choice(users)
            
            entries.append({
                "timestamp": entry_time.isoformat(),
                "method": method,
                "path": path_template,
                "status_code": 200,
                "user_id": user[0],
                "agency_id": user[1],
                "role": user[2],
                "response_time_ms": round(random.uniform(15.0, 120.0), 2)
            })

        # 2. Generate shadow route traffic (recent 25 days)
        for _ in range(int(total_requests * 0.10)):
            method, path_template, _, (min_day, max_day) = shadow_routes[0]
            day_offset = random.uniform(min_day, max_day)
            entry_time = now - timedelta(days=day_offset, minutes=random.randint(0, 1440))
            user = random.choice(users)
            
            entries.append({
                "timestamp": entry_time.isoformat(),
                "method": method,
                "path": path_template,
                "status_code": 200,
                "user_id": user[0],
                "agency_id": user[1],
                "role": user[2],
                "response_time_ms": round(random.uniform(18.0, 90.0), 2)
            })

        # 3. Generate zombie route traffic (old 70-90 days ago only)
        for _ in range(int(total_requests * 0.05)):
            method, path_template, _, (min_day, max_day) = zombie_routes[0]
            day_offset = random.uniform(min_day, max_day)
            entry_time = now - timedelta(days=day_offset, minutes=random.randint(0, 1440))
            user = random.choice(users)
            
            entries.append({
                "timestamp": entry_time.isoformat(),
                "method": method,
                "path": path_template,
                "status_code": 200,
                "user_id": user[0],
                "agency_id": user[1],
                "role": user[2],
                "response_time_ms": round(random.uniform(60.0, 250.0), 2)
            })

        # Sort chronologically
        entries.sort(key=lambda x: x["timestamp"])

        # Write to JSONL
        with open(self.log_path, "w", encoding="utf-8") as f:
            for entry in entries:
                f.write(json.dumps(entry) + "\n")

        return self.log_path

    def parse_logs(self, log_path: Optional[str] = None) -> Dict[Tuple[str, str], Dict[str, Any]]:
        """
        Parses traffic log entries and aggregates per endpoint (method, normalized_path):
          - total_count
          - count_last_30d
          - count_last_90d
          - last_seen
          - roles seen
          - status codes
        """
        target_path = log_path or self.log_path
        if not os.path.exists(target_path):
            self.generate_synthetic_logs()

        now = datetime.utcnow()
        cutoff_30d = now - timedelta(days=30)
        cutoff_90d = now - timedelta(days=90)

        aggregated: Dict[Tuple[str, str], Dict[str, Any]] = {}

        with open(target_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    method = entry.get("method", "GET").upper()
                    raw_path = entry.get("path", "")
                    normalized_path = normalize_path(raw_path)
                    key = (method, normalized_path)

                    ts_str = entry.get("timestamp")
                    ts = datetime.fromisoformat(ts_str) if ts_str else now
                    role = entry.get("role")
                    status_code = entry.get("status_code", 200)

                    if key not in aggregated:
                        aggregated[key] = {
                            "method": method,
                            "path": normalized_path,
                            "total_count": 0,
                            "count_30d": 0,
                            "count_90d": 0,
                            "last_seen": ts_str,
                            "roles": set(),
                            "status_codes": set()
                        }

                    stats = aggregated[key]
                    stats["total_count"] += 1

                    if ts >= cutoff_90d:
                        stats["count_90d"] += 1
                    if ts >= cutoff_30d:
                        stats["count_30d"] += 1

                    if not stats["last_seen"] or ts_str > stats["last_seen"]:
                        stats["last_seen"] = ts_str

                    if role:
                        stats["roles"].add(role)
                    stats["status_codes"].add(status_code)

                except Exception:
                    continue

        # Convert sets to sorted lists
        for stats in aggregated.values():
            stats["roles"] = sorted(list(stats["roles"]))
            stats["status_codes"] = sorted(list(stats["status_codes"]))

        return aggregated

traffic_parser = TrafficLogParser()
