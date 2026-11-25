# CyberShield – An Intelligent Digital Immune System

> **Tagline:** *Detect. Defend. Recover. Evolve.*  
> **Academic Project:** *CyberShield: Design and Development of an Intelligent Digital Immune System for Autonomous Threat Detection and Self-Recovery*

---

## 1. Project Introduction

**CyberShield** is a full-stack Security Operations Center (SOC) prototype demonstrating the principles of a **Digital Immune System (DIS)** inside a safe, locally self-contained Flask + SQLite web application. Inspired by biological adaptive immunity, CyberShield continuously monitors application health, detects anomalous activity through configurable rules, scores risk transparently, isolates simulated threat sources with safeguards, executes simulated self-recovery when services degrade, and preserves incident signatures in historical pattern memory.

### Academic Honesty & Safety Boundaries
- **Monitoring Scope:** Real metrics measure only the local Flask process (uptime, HTTP request/error counts, latency) and SQLite database connectivity (`SELECT 1`). Simulated service/DB states are in-memory flags used for safe failure & recovery demonstrations.
- **Risk Analysis Scope:** Uses an **Explainable Rule-Based Risk Engine** (`ExplainableRuleRiskAnalyzer`) built behind a modular `BaseRiskAnalyzer` interface so an ML model can be plugged in later. It does not falsely claim an ML model is running.
- **Containment Scope:** Automated blocking applies strictly to simulated RFC 5737 test IP identities (`192.0.2.x`, `198.51.100.x`, `203.0.113.x`). No real host firewall or external network changes occur.
- **Immune Memory Scope:** Performs deterministic **Historical Pattern Tracking** to recognize recurring signatures and adjust rule sensitivity weights.

---

## 2. Features & Core Modules

1. **Security Overview Dashboard** — Live SQLite-backed KPIs, system health status (`Healthy`, `Warning`, `Critical`), threat severity distribution, daily incident trends, and system health charts.
2. **System Monitoring** — Distinguishes real Flask/SQLite telemetry from simulated service flags, with manual health snapshots and monitoring event logs.
3. **Intelligent Threat Detection** — Configurable rule thresholds for failed login bursts, suspicious request frequency, repeated IP polling, restricted endpoint probes, and unusual activity patterns with false-alarm prevention for benign/single events.
4. **Explainable Risk Analysis** — 0–100 risk score breakdown across 5 transparent factors with severity classification and recommended responses.
5. **Automated Threat Response** — Temporary simulated IP isolation with RFC 5737 range guardrails, optional human-approval queue, and manual unblock controls.
6. **Self-Recovery Engine** — Simulates API, database pool, and worker failures, restores simulated service states, re-verifies SQLite health, and records recovery duration.
7. **Incident Management** — Searchable, filterable incident table (`New`, `Investigating`, `Resolved`, `False Positive`) and modal inspector with full chronological `IncidentHistory` timeline.
8. **Digital Immune Memory** — Catalogs recurring attack signatures, tracks previous responses, and elevates rule sensitivity weights when patterns repeat.
9. **Security Simulation Lab** — Safe interactive testbed triggering all 7 scenarios and displaying a live 9-stage workflow execution timeline.
10. **Reports & Analytics** — Aggregate analytics charts and one-click CSV report export.

---

## 3. Technology Stack

- **Frontend:** HTML5, CSS3 (glassmorphism dark navy SOC UI), Vanilla JavaScript, offline-bundled Chart.js (`chart.umd.min.js`)
- **Backend:** Python, Flask, Flask-SQLAlchemy, Flask-CORS, Python `logging`
- **Database:** SQLite (`backend/database/cybershield.db`, auto-initialized on startup)

---

## 4. Architecture Workflow

```text
Application Monitoring
        ↓
Event Collection
        ↓
Threat Detection (Configurable Rules + False-Alarm Prevention)
        ↓
Risk Assessment (Explainable 0–100 Rule Scorer)
        ↓
Decision Engine
        ↓
Automated Response (Safeguarded RFC 5737 Simulated IP Blocking)
        ↓
Self-Recovery (Local Simulated Service & DB Pool Restoration)
        ↓
Incident Logging (ThreatIncident + IncidentHistory Audit Trail)
        ↓
Historical Pattern Analysis (Digital Immune Memory)
```

---

## 5. Folder Structure

```text
cybershield/
├── backend/
│   ├── app.py
│   ├── config.py
│   ├── extensions.py
│   ├── requirements.txt
│   ├── database/
│   │   └── init_db.py
│   ├── models/
│   │   ├── blocked_source.py
│   │   ├── incident_history.py
│   │   ├── recovery_action.py
│   │   ├── security_event.py
│   │   ├── security_rule.py
│   │   ├── system_health.py
│   │   └── threat_incident.py
│   ├── routes/
│   │   ├── api.py
│   │   ├── reports.py
│   │   └── simulation.py
│   ├── services/
│   │   ├── immune_memory.py
│   │   ├── monitoring_service.py
│   │   ├── recovery_engine.py
│   │   ├── response_engine.py
│   │   ├── risk_analysis.py
│   │   ├── threat_detection.py
│   │   └── workflow_orchestrator.py
│   └── tests/
│       └── test_cybershield.py
├── frontend/
│   ├── index.html
│   ├── assets/
│   │   └── chart.umd.min.js
│   ├── css/
│   │   └── styles.css
│   └── js/
│       ├── api.js
│       ├── app.js
│       └── charts.js
└── README.md
```

---

## 6. Installation & Execution

### Prerequisites
- Python 3.10+ installed locally

### Install Dependencies
```bash
cd cybershield/backend
pip install -r requirements.txt
```

### Database Setup
No manual SQL setup is needed. On first run, `app.py` automatically creates `backend/database/cybershield.db`, creates all 7 SQLite tables, seeds default `SecurityRule` thresholds, and initializes a clean **Healthy** baseline.

### Run the Application
```bash
cd cybershield/backend
python app.py
```
Then open your browser to:
`http://127.0.0.1:5000`

*(Works completely offline — Chart.js is bundled locally in `frontend/assets/chart.umd.min.js`.)*

### Run Automated Tests
```bash
cd cybershield/backend
python -m unittest discover -s tests -v
```

---

## 7. REST API Documentation

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/health` | Real Flask/SQLite health + simulated service status |
| `GET` | `/api/dashboard` | KPIs, severity distribution, trends, recent events & incidents |
| `GET` | `/api/monitoring` | Real vs simulated telemetry & monitoring event log |
| `GET` | `/api/events` | List analyzed `SecurityEvent` records |
| `GET` | `/api/incidents` | Search & filter `ThreatIncident` records |
| `GET` | `/api/incidents/<id>` | Incident details + chronological `IncidentHistory` |
| `PATCH` | `/api/incidents/<id>` | Update incident status (`New`, `Investigating`, `Resolved`, `False Positive`) |
| `GET` | `/api/blocked-sources` | List active, pending-approval, and past simulated blocks |
| `POST` | `/api/blocked-sources/<id>/unblock` | Manually unblock a simulated IP |
| `POST` | `/api/blocked-sources/<id>/approve` | Approve a pending human-in-the-loop block |
| `GET` | `/api/rules` / `PATCH` `/api/rules/<id>` | View or update detection rule thresholds & safeguards |
| `GET` | `/api/recovery` | Recovery statistics & action history |
| `POST` | `/api/recovery/trigger` | Execute local self-recovery |
| `GET` / `PATCH` | `/api/recovery/settings` | Configure Autonomous Self-Healing Watchdog |
| `POST` | `/api/auth/login` | Monitored login endpoint (demo: `analyst` / `CyberShield@2026`) |
| `GET` | `/api/admin/debug-console` | Monitored restricted endpoint for live unauthorized probe detection |
| `GET` | `/api/records/public` | Monitored sample API endpoint for live polling detection |
| `GET` | `/api/immune-memory` | Recurring signature catalog & adapted rule boosts |
| `POST` | `/api/simulation/failed-logins` | Simulate brute-force login attempts |
| `POST` | `/api/simulation/suspicious-traffic` | Simulate high-frequency request spike |
| `POST` | `/api/simulation/restricted-access` | Simulate restricted endpoint probes |
| `POST` | `/api/simulation/service-failure` | Simulate API service outage |
| `POST` | `/api/simulation/database-failure` | Simulate DB pool outage |
| `POST` | `/api/simulation/excessive-errors` | Simulate HTTP 500 error spike |
| `POST` | `/api/simulation/service-recovery` | Trigger recovery simulation |
| `POST` | `/api/simulation/normal-traffic` | Generate benign traffic (zero false alarms) |
| `POST` | `/api/simulation/reset` | Reset to clean Healthy baseline |
| `GET` | `/api/reports` | Aggregated security & recovery analytics |
| `GET` | `/api/reports/export` | Download CSV report of incidents |

---

## 8. College Presentation Demo Sequence (User Portal + Admin SOC)

Open two browser tabs side by side:
- **Tab 1 (End-User Perspective):** `http://127.0.0.1:5000/` (`student` / `DemoPass@123`)
- **Tab 2 (Admin-Only CyberShield Backend SOC):** `http://127.0.0.1:5000/admin` (`admin` / `AdminShield@2026`)

1. Show Tab 2 (**Admin SOC → Security Overview**) in a **Healthy** baseline (`Reset Baseline` resets anytime).
2. Switch to Tab 1 (**User Portal**) — show a standard user exploring the Digital Immune Systems tabs and signing in cleanly.
3. Sign out in Tab 1 and intentionally submit a **wrong password 5 times**:
   - Attempts 1–4 show only `"Invalid username or password. Please try again."` (no threat telemetry exposed to the user).
   - Attempt 5 locks the user out with a generic security message.
4. Switch to Tab 2 (**Admin SOC**):
   - Show **Security Overview** & **Threat Detection**: CyberShield silently detected the brute-force burst.
   - Show **Risk Analysis**: inspect the explainable 0–100 risk score breakdown.
   - Show **Automated Response**: inspect the temporary simulated block on `192.0.2.100` (and click **Manual Unblock** to restore the user's access).
   - Show **Incident Management**: click **Inspect** to view the full detection reason, automated action, and chronological audit timeline.
5. Open **Simulation Lab** in Tab 2 -> click **Simulate API Failure** -> observe **Critical** status (Tab 1 shows only a user-friendly availability notice), then watch **Autonomous Self-Healing Watchdog** restore **Healthy** status automatically after 6 seconds (or click **Execute Self-Recovery**).

---

## 9. Deploying on Render (Free Web Service)

Render runs a continuous Python process (`gunicorn --workers 1 --threads 4`), allowing SQLite storage and the 6-second Autonomous Self-Healing Watchdog to run properly. Ready-to-use `render.yaml`, `Procfile`, and `requirements.txt` are included.

1. Push the `cybershield` folder to a GitHub repository.
2. Sign in to [Render](https://render.com) and click **New → Blueprint** (or **New → Web Service**).
3. Select your GitHub repository. Render automatically reads `render.yaml`:
   - **Build Command:** `pip install -r backend/requirements.txt`
   - **Start Command:** `gunicorn --chdir backend app:app --workers 1 --threads 4 --bind 0.0.0.0:$PORT`
   - **Health Check Path:** `/api/health`
4. Click **Apply / Create Web Service**. Once live, open `https://<your-service>.onrender.com/` (User Portal) and `https://<your-service>.onrender.com/admin` (Admin SOC Console).

*(Note: Render's free tier spins down after inactivity and uses an ephemeral disk, so SQLite automatically re-seeds the clean Healthy baseline on cold restarts.)*

---

## 10. Known Limitations

- Designed as a single-node local academic prototype using SQLite and Flask's development server; not intended for multi-node high-throughput production deployment without migrating to WSGI (e.g., Gunicorn) and PostgreSQL.
- Anomaly detection and risk scoring are deterministic and rule-based; an ML model is intentionally not claimed until trained on real labeled network telemetry via the `BaseRiskAnalyzer` interface.
- IP blocking and service failures operate strictly on simulated application state for safety during live classroom demonstrations.
