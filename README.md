# Real-Time API Security Regression Tester (Agentic DAST)

A fully automated, agentic **Dynamic Application Security Testing (DAST)** platform for a B2B travel booking API — detecting regressions in authorization, business logic, and API hygiene as changes land in CI/CD.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────┐
│          /target_app  (port 8001)                │
│  Mock B2B Travel Booking API (FastAPI)           │
│  2 agencies · 8 users · 4 intentional bugs      │
│  Buggy mode / Fixed mode via /admin/set-mode     │
└───────────────────┬─────────────────────────────┘
                    │  HTTP
┌───────────────────▼─────────────────────────────┐
│          /backend  (port 8000)                   │
│  DAST Engine (FastAPI + SQLite)                  │
│                                                  │
│  Phase 2 — Change Detection & API Inventory      │
│    • JS bundle hash monitor                      │
│    • Playwright multi-role crawler               │
│    • Traffic log parser (30-90d synthetic logs)  │
│    • Endpoint labeling: Active / Shadow / Zombie │
│    • NetworkX workflow topology graph            │
│                                                  │
│  Phase 3 — Safety Layer & Test Planner           │
│    • Host allowlist + token-bucket rate limiter  │
│    • Circuit breaker                             │
│    • SHA-256 hash-chained append-only audit log  │
│    • Prioritized test plan (6 test cases)        │
│                                                  │
│  Phase 4 — Checks, Scoring, Tickets, Retest      │
│    • AccessControlCheck  (BOLA, BFLA)            │
│    • BusinessLogicCheck  (Fare, Refund)          │
│    • InputHandlingCheck  (Shadow endpoint)       │
│    • ApiHygieneCheck     (Zombie endpoint)       │
│    • Verifier (minimal-reproduction evidence)    │
│    • Scorer  (impact formula)                    │
│    • TicketManager (SQLite + tickets.json)       │
│    • Auto-retest & auto-resolve on deploy        │
│                                                  │
│  Phase 5 — Live Dashboard & Telemetry            │
│    • /dashboard — standalone HTML dashboard      │
│    • /ws/events — WebSocket live-push stream     │
│    • Real-time ticket board, inventory table     │
│    • Topology graph, hash-chained audit log      │
└──────────────────────────────────────────────────┘
```

---

## Quick Start

> **Prerequisites:** Python 3.10+, pip

```bash
# 1. Install dependencies
pip install -r requirements.txt
python -m playwright install chromium

# 2. Terminal 1 — start target app
python -m uvicorn target_app.app:app --host 127.0.0.1 --port 8001

# 3. Terminal 2 — start DAST backend
python -m uvicorn backend.app:app --host 127.0.0.1 --port 8000

# 4. Run the end-to-end demo
python demo.py

# 5. Open the live dashboard
# http://127.0.0.1:8000/dashboard
```

---

## Running Tests

```bash
# Full suite (41 tests across all 5 phases)
python -m pytest tests/ -v

# Individual phase suites
python -m pytest tests/test_target_app.py -v    # Phase 1 — 11 tests
python -m pytest tests/test_backend.py -v       # Phase 2 — 9 tests
python -m pytest tests/test_safety.py -v        # Phase 3a — 13 tests
python -m pytest tests/test_planner.py -v       # Phase 3b — 8 tests
python -m pytest tests/test_checks.py -v        # Phase 4a — 6 tests
python -m pytest tests/test_tickets.py -v       # Phase 4b/5 — 7 tests
```

---

## The Four Intentional Bugs (Buggy Mode)

| ID | Type | Endpoint | Fixed Behaviour |
|---|---|---|---|
| BUG-01 | BOLA / IDOR | `GET /api/v1/bookings/{id}` | 403 for cross-agency reads |
| BUG-02 | Client-Trusted Fare | `POST /api/v1/bookings/{id}/pay` | 400 for price < server fare |
| BUG-03 | Double Refund | `POST /api/v1/bookings/{id}/cancel` | 400 on second cancel |
| BUG-04 | BFLA | `GET /api/v1/agency/commissions` | 403 for sub_agent role |

Switch modes at runtime:

```bash
# Enable all bugs
curl -X POST "http://127.0.0.1:8001/admin/set-mode?vulnerable=true"

# Enable all fixes
curl -X POST "http://127.0.0.1:8001/admin/set-mode?vulnerable=false"

# Reset seed data
curl -X POST "http://127.0.0.1:8001/admin/reset-state"
```

---

## Special Endpoints

| Endpoint | Classification | Purpose |
|---|---|---|
| `POST /api/v1/promotions/apply` | **Shadow** | In production code, absent from OpenAPI spec |
| `GET /api/v1/legacy/xml-rates` | **Zombie** | 0 traffic in past 30 days (deprecated) |

---

## Key API Endpoints (Backend)

| Method | Path | Description |
|---|---|---|
| `POST` | `/webhook/deploy` | CI/CD deployment webhook — triggers full change detection |
| `GET` | `/api/inventory` | Classified endpoint inventory (Active / Shadow / Zombie) |
| `GET` | `/api/inventory/summary` | Aggregated inventory metrics |
| `POST` | `/api/pipeline/run` | Execute the full DAST regression pipeline |
| `GET` | `/api/tickets` | All security tickets (CONFIRMED / RESOLVED) |
| `POST` | `/api/tickets/retest` | Auto-retest open tickets; auto-resolve if patched |
| `GET` | `/api/safety/status` | Safety guard metrics (rate limiter, circuit breaker) |
| `GET` | `/api/safety/verify` | Cryptographic audit chain integrity check |
| `WS` | `/ws/events` | WebSocket live-push event stream for dashboard |
| `GET` | `/dashboard` | Standalone live telemetry dashboard |

---

## Pipeline Flow

```
CI/CD Webhook → Bundle Hash Monitor → Playwright Crawler
      ↓
Inventory Reconciliation (OpenAPI + Traffic Logs + Crawler Graph)
      ↓
Test Plan Generation (6 prioritized test cases)
      ↓
Safety-Guarded Check Execution (allowlist + rate limiter + circuit breaker)
      ↓
Minimal Reproduction Verification (evidence collection)
      ↓
Business Impact Scoring (financial + PII + auth + hygiene formula)
      ↓
Ticket Filing → SQLite + tickets.json + WebSocket broadcast
      ↓
Auto-Retest on Deploy → CONFIRMED → RESOLVED (with evidence)
```

---

## Demo Output (Expected)

```
1. Both services healthy
2. Target in VULNERABLE mode
3. Webhook accepted: DEP-XXXXXXXX
   shadow=[POST /api/v1/promotions/apply]
   zombie=[GET /api/v1/legacy/xml-rates]
4. Pipeline: 6 tests, 6 confirmed tickets filed (4x CRITICAL, 2x LOW)
5. Audit chain: 64+ entries verified intact (SHA-256)
6. FIXED mode: 6/6 tickets RESOLVED
7. Dashboard: http://127.0.0.1:8000/dashboard
```

---

## Project Structure

```
.
├── target_app/              # Phase 1 — Vulnerable mock booking API
│   ├── app.py
│   ├── auth.py              # 8 users across 2 agencies
│   ├── config.py            # BUGS_ENABLED / FIXED_MODE toggle
│   ├── database.py          # In-memory seed data
│   ├── models.py
│   └── routes/              # search, hold, book, pay, cancel, admin, legacy, shadow
├── backend/                 # Phases 2–5 — DAST Engine
│   ├── app.py               # FastAPI + WebSocket
│   ├── config.py
│   ├── models.py
│   ├── database.py          # SQLite: backend_inventory.sqlite
│   ├── engine.py            # Pipeline orchestrator
│   ├── test_planner.py      # Prioritized test plan generator
│   ├── verifier.py          # Minimal reproduction verifier
│   ├── scoring.py           # Impact scorer
│   ├── tickets.py           # Ticket lifecycle + auto-retest
│   ├── safety/              # Guard, rate limiter, circuit breaker, audit log
│   ├── checks/              # AccessControl, BusinessLogic, InputHandling, ApiHygiene
│   ├── services/            # BundleMonitor, TrafficParser, Crawler, InventoryManager
│   └── static/
│       └── dashboard.html   # Standalone live dashboard (WebSocket + polling)
├── tests/                   # 41 tests across all phases
├── demo.py                  # End-to-end pipeline demo
├── simulate_deployment.py   # CI/CD webhook simulation script
├── requirements.txt
├── Makefile
└── make.bat
```
