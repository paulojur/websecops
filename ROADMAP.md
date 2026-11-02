# 🗺️ Roadmap

Planned work for WebSecOps. Items are roughly ordered by priority.

## 🐛 Refinement & Bug Fixing
- [ ] Harden ZAP/Nuclei scan workflows: status polling, timeouts, and error recovery when the scanner is unreachable
- [ ] Consistent API error messages (currently mixed PT/EN in some backend responses)
- [ ] Remove leftover debug scripts from `backend/` (`reproduce_error.py`, `verify_scrapers.py`) or move them into tests

## 🧠 Correlation Improvements
- [ ] Better version matching between detected technologies and CVE CPE ranges
- [ ] Reduce false positives when the detected version is unknown
- [ ] Smarter risk prioritization (CVSS + exploitability signals such as CISA KEV)

## 📄 Reports
- [ ] Richer PDF reports (executive summary, per-finding remediation)
- [ ] Additional export formats (JSON, CSV)

## 🔒 Platform Hardening
- [x] Constant-time API key comparison
- [x] Require explicit database password in production
- [ ] Rate limiting on scan endpoints
- [ ] Move the visitor target whitelist to configuration

## 🧪 Quality
- [ ] Expand backend test coverage (endpoints, security module)
- [ ] Basic CI (lint + tests on push)

## 📚 Documentation
- [x] English README with PT-BR translation
- [ ] Architecture diagram
