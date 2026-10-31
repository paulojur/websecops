# 🛡️ WebSecOps – Web Application Security Intelligence Platform

🌐 **English** | [Português (BR)](README.pt-BR.md)

![Status](https://img.shields.io/badge/Status-Active%20Development-yellow?style=flat-square)
![Stack](https://img.shields.io/badge/Stack-Next.js%20%7C%20FastAPI%20%7C%20Docker-blue?style=flat-square)

**WebSecOps** is a self-hosted platform for continuous web application security monitoring (AppSec) and DAST (*Dynamic Application Security Testing*). It helps QA and security teams understand what their applications are running, which known vulnerabilities apply, and what to fix first.

It's also built as an **interactive portfolio showcase**. Public visitors get a sandboxed **Demo Mode**, and the real scanning engines stay locked behind an authenticated **Live Mode**.

---

## 🚀 Features

| Feature | Description |
| :--- | :--- |
| 📊 **Executive Dashboard** | Unified risk view: vulnerability score, critical alerts and trends. |
| 🎯 **Target Management** | Register and track monitored URLs (apps, APIs). |
| 🕵️ **Passive Tech-Stack Detection** | Fingerprints servers, frameworks and CMSs from HTTP headers, cookies and HTML, without sending any exploits. |
| 🚨 **CVE Correlation** | Matches detected technologies against the NVD/NIST CVE database. |
| 🧠 **Remediation Engine** | Prioritizes the top 5 most relevant risks, with confidence level (high/low), evidence and mitigation steps. |
| ⚡ **Active DAST** | OWASP ZAP (spider + active scan) and Nuclei templates. |
| 📰 **Threat Intelligence Feed** | Aggregated news and advisories (NVD, CISA, OWASP, HackerNews, Google Security). |
| 📄 **Report Export** | Scan results exportable as PDF. |
| 🌍 **i18n** | Full UI in English and Portuguese (PT-BR). |

### Demo Mode vs. Live Mode

| | Demo Mode (default) | Live Mode |
| :--- | :--- | :--- |
| Access | Any visitor | Requires the Master API Key (`X-API-Key` header) |
| Scan targets | Only a whitelist of intentionally vulnerable test sites (e.g. `demo.testfire.net`, `juice-shop.herokuapp.com`, `scanme.nmap.org`) | Any target |
| Data | Browser local storage | PostgreSQL |

> [!WARNING]
> ZAP and Nuclei perform **active** scans (fuzzing, payload injection). Only scan systems you own or are explicitly authorized to test.

---

## 🏗️ Architecture

Containerized services, orchestrated with Docker Compose:

| Component | Technology | Role |
| :--- | :--- | :--- |
| **Frontend** | Next.js 16, React 19, TailwindCSS 4 | Dashboard, charts, real-time scan logs. Proxies API calls to the backend. |
| **Backend** | Python, FastAPI | REST API, scanner orchestration, CVE correlation, API key auth. |
| **Database** | PostgreSQL 16 | Targets, CVEs, scan history. |
| **Cache/Queue** | Redis | Cache and async scanner results. |
| **Scanners** | OWASP ZAP, Nuclei | Active DAST engines. |
| **Proxy** | Nginx + Let's Encrypt | Reverse proxy, TLS, hardening (`server_tokens off`). |

---

## 🛠️ Running Locally

### Prerequisites
- **Docker Desktop** (Linux containers)
- **Node.js 20+** (to run the frontend natively with hot reload)

### 1. Configure environment
```bash
cp .env.example .env
# Edit .env: set POSTGRES_PASSWORD and ADMIN_API_KEY to strong random values
```

### 2. Start backend services
```bash
docker compose up -d db redis backend
```

### 3. Start the frontend
```bash
cd frontend
npm install
npm run dev
```

Open **http://localhost:3000**.

### Optional: enable ZAP
```bash
docker compose up -d zap
```

### Tests
```bash
cd backend
pytest
```

---

## 🚢 Production Deployment

A single small VM (e.g. a 2 GB droplet) is enough when ZAP is left off:

```bash
cp .env.example .env   # POSTGRES_PASSWORD is mandatory in production
docker compose -f docker-compose.prod.yml up -d --build db redis backend frontend nginx

# Enable ZAP on demand
docker compose -f docker-compose.prod.yml --profile scan up -d zap
```

For HTTPS, run `init-letsencrypt.sh` after pointing your domain to the server.

Health checks:
```bash
docker compose -f docker-compose.prod.yml ps
curl http://localhost:8000/health
```

---

## 📂 Project Structure

```
WebSecOps/
├── backend/
│   ├── app/
│   │   ├── api/endpoints/   # targets, vulnerabilities, zap, nuclei, intelligence, auth
│   │   ├── core/            # config, DB, security (API key, target whitelist)
│   │   ├── models/          # SQLAlchemy models
│   │   ├── scrapers/        # NVD and threat-intel scrapers
│   │   └── services/        # tech detector, ZAP scanner, remediation engine
│   ├── tests/               # pytest
│   └── main.py
├── frontend/
│   ├── app/                 # routes: dashboard, targets, vulns, scans, intelligence
│   ├── components/          # AdminLogin, WelcomeModal
│   └── lib/                 # API client, i18n, PDF export, demo data
├── nginx/                   # reverse proxy config
├── docker-compose.yml       # development
└── docker-compose.prod.yml  # production
```

---

## 🤝 Suggested QA Security Workflow

1. Register the target application.
2. Review detected technologies and correlated CVEs.
3. Write targeted security test cases to validate patches and updates.

---

**Built with a focus on Cyber + Privacy 🔒**
