# WebSecOps Dashboard

A specialized **Web Application Security Monitoring & Intelligence Dashboard** designed for QA Engineers, Security Analysts, and DevSecOps professionals.

## Overview

This project provides a real-time view of the web security landscape by:
1.  **Monitoring Critical Web Vulnerabilities**: Filtering NVD data for XSS, SQLi, CSRF, RCE, etc.
2.  **Aggregating Security Intelligence**: Pulling latest news from OWASP and The Hacker News.
3.  **Visualizing Threat Data**: "SOC-style" dashboard with dark mode and real-time feel.

## Tech Stack

*   **Backend**: Python (FastAPI/Flask), NVD API Integration, RSS Scrapers.
*   **Frontend**: Next.js (React), TailwindCSS, Framer Motion.
*   **Infrastructure**: Docker, Prometheus (optional).

## Features

*   **Web-Centric CVE Filter**: Automatically ignores irrelevant vulnerabilities (e.g., local kernel exploits) to focus on Web App Security.
*   **Intelligence Feed**: Curated news for AppSec.
*   **Cyber Aesthetic**: Designed to look like a modern Security Operations Center (SOC) monitor.

## Getting Started

1.  Start the backend:
    ```bash
    cd backend
    pip install -r requirements.txt
    python main.py
    ```

2.  Start the frontend:
    ```bash
    cd frontend
    npm install
    npm run dev
    ```

## Future Roadmap

*   Integration with OWASP ZAP for active scanning.
*   Webhooks for CI/CD pipeline failures.
*   Dark Web monitoring widgets.
