import sqlite3
import json
from typing import List, Optional, Dict, Any
from datetime import datetime
from backend.config import backend_settings
from backend.models import EndpointInventoryItem, DeploymentChangeSummary

def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(backend_settings.DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_connection()
    cursor = conn.cursor()
    
    # Inventory Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS inventory (
        endpoint_id TEXT PRIMARY KEY,
        method TEXT NOT NULL,
        path TEXT NOT NULL,
        status TEXT NOT NULL,
        in_openapi INTEGER NOT NULL,
        in_crawler INTEGER NOT NULL,
        in_traffic INTEGER NOT NULL,
        traffic_count_last_90d INTEGER DEFAULT 0,
        traffic_count_last_30d INTEGER DEFAULT 0,
        last_seen_in_traffic TEXT,
        allowed_roles TEXT,
        parameters TEXT,
        description TEXT,
        first_detected TEXT NOT NULL,
        UNIQUE(method, path)
    )
    """)

    # Deployments Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS deployments (
        deploy_id TEXT PRIMARY KEY,
        version TEXT NOT NULL,
        commit_sha TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        bundle_changed INTEGER NOT NULL,
        previous_bundle_hash TEXT,
        new_bundle_hash TEXT,
        change_summary_json TEXT NOT NULL
    )
    """)

    # Bundle Hashes History
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS bundle_hashes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        bundle_url TEXT NOT NULL,
        file_name TEXT NOT NULL,
        content_hash TEXT NOT NULL,
        detected_endpoints_json TEXT NOT NULL,
        timestamp TEXT NOT NULL
    )
    """)

    # Graph Storage Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS crawl_graphs (
        graph_id TEXT PRIMARY KEY,
        timestamp TEXT NOT NULL,
        node_count INTEGER NOT NULL,
        edge_count INTEGER NOT NULL,
        graph_data_json TEXT NOT NULL
    )
    """)

    conn.commit()
    conn.close()

def save_inventory_item(item: EndpointInventoryItem):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO inventory (
        endpoint_id, method, path, status, in_openapi, in_crawler, in_traffic,
        traffic_count_last_90d, traffic_count_last_30d, last_seen_in_traffic,
        allowed_roles, parameters, description, first_detected
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(endpoint_id) DO UPDATE SET
        status = excluded.status,
        in_openapi = excluded.in_openapi,
        in_crawler = excluded.in_crawler,
        in_traffic = excluded.in_traffic,
        traffic_count_last_90d = excluded.traffic_count_last_90d,
        traffic_count_last_30d = excluded.traffic_count_last_30d,
        last_seen_in_traffic = excluded.last_seen_in_traffic,
        allowed_roles = excluded.allowed_roles,
        parameters = excluded.parameters,
        description = excluded.description
    """, (
        item.endpoint_id,
        item.method,
        item.path,
        item.status,
        1 if item.in_openapi else 0,
        1 if item.in_crawler else 0,
        1 if item.in_traffic else 0,
        item.traffic_count_last_90d,
        item.traffic_count_last_30d,
        item.last_seen_in_traffic,
        json.dumps(item.allowed_roles),
        json.dumps(item.parameters),
        item.description,
        item.first_detected
    ))
    conn.commit()
    conn.close()

def get_all_inventory() -> List[EndpointInventoryItem]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM inventory ORDER BY path, method")
    rows = cursor.fetchall()
    conn.close()

    items = []
    for row in rows:
        items.append(EndpointInventoryItem(
            endpoint_id=row["endpoint_id"],
            method=row["method"],
            path=row["path"],
            status=row["status"],
            in_openapi=bool(row["in_openapi"]),
            in_crawler=bool(row["in_crawler"]),
            in_traffic=bool(row["in_traffic"]),
            traffic_count_last_90d=row["traffic_count_last_90d"],
            traffic_count_last_30d=row["traffic_count_last_30d"],
            last_seen_in_traffic=row["last_seen_in_traffic"],
            allowed_roles=json.loads(row["allowed_roles"]) if row["allowed_roles"] else [],
            parameters=json.loads(row["parameters"]) if row["parameters"] else [],
            description=row["description"],
            first_detected=row["first_detected"]
        ))
    return items

def save_deployment(summary: DeploymentChangeSummary):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO deployments (
        deploy_id, version, commit_sha, timestamp, bundle_changed,
        previous_bundle_hash, new_bundle_hash, change_summary_json
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        summary.deploy_id,
        summary.version,
        summary.commit_sha,
        summary.timestamp,
        1 if summary.bundle_changed else 0,
        summary.previous_bundle_hash,
        summary.new_bundle_hash,
        json.dumps(summary.model_dump())
    ))
    conn.commit()
    conn.close()

def get_deployments() -> List[Dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM deployments ORDER BY timestamp DESC")
    rows = cursor.fetchall()
    conn.close()
    return [json.loads(r["change_summary_json"]) for r in rows]

def save_crawl_graph(graph_id: str, graph_data: Dict[str, Any]):
    conn = get_connection()
    cursor = conn.cursor()
    node_count = len(graph_data.get("nodes", []))
    edge_count = len(graph_data.get("links", []))
    cursor.execute("""
    INSERT OR REPLACE INTO crawl_graphs (graph_id, timestamp, node_count, edge_count, graph_data_json)
    VALUES (?, ?, ?, ?, ?)
    """, (
        graph_id,
        datetime.utcnow().isoformat(),
        node_count,
        edge_count,
        json.dumps(graph_data)
    ))
    conn.commit()
    conn.close()

def get_latest_crawl_graph() -> Optional[Dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT graph_data_json FROM crawl_graphs ORDER BY timestamp DESC LIMIT 1")
    row = cursor.fetchone()
    conn.close()
    if row:
        return json.loads(row["graph_data_json"])
    return None

def get_latest_bundle_hash() -> Optional[str]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT content_hash FROM bundle_hashes ORDER BY id DESC LIMIT 1")
    row = cursor.fetchone()
    conn.close()
    if row:
        return row["content_hash"]
    return None

def save_bundle_hash(bundle_url: str, file_name: str, content_hash: str, endpoints: List[str]):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO bundle_hashes (bundle_url, file_name, content_hash, detected_endpoints_json, timestamp)
    VALUES (?, ?, ?, ?, ?)
    """, (
        bundle_url,
        file_name,
        content_hash,
        json.dumps(endpoints),
        datetime.utcnow().isoformat()
    ))
    conn.commit()
    conn.close()

# Initialize DB tables on import
init_db()
