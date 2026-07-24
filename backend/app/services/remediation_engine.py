from __future__ import annotations

from typing import Any, Dict, List


class RemediationEngine:
    """
    Small deterministic rule engine for turning scanner findings into analyst
    guidance. It intentionally avoids guessing beyond the available evidence.
    """

    HEADER_RULES = [
        {
            "keys": ["x-frame-options", "content security policy", "frame-ancestors", "clickjacking"],
            "title": "Clickjacking Protection",
            "severity": "MEDIUM",
            "confidence": "HIGH",
            "confidence_reason": "Scanner observed missing or weak headers directly verifiable in the HTTP response.",
            "category": "HTTP Headers",
            "root_cause": "Missing or incomplete browser security headers",
            "why": "Application could be framed by unauthorized origins.",
            "recommendation": "Define Content-Security-Policy with frame-ancestors or use X-Frame-Options for legacy compatibility.",
            "next_step": "Validate which origins need framing access in staging before applying to production.",
            "nginx": "add_header Content-Security-Policy \"frame-ancestors 'self';\" always;",
            "apache": "Header always set Content-Security-Policy \"frame-ancestors 'self';\"",
        },
        {
            "keys": ["strict-transport-security", "hsts"],
            "title": "Enforce HTTPS with HSTS",
            "severity": "MEDIUM",
            "confidence": "HIGH",
            "confidence_reason": "Scanner can directly verify if the HSTS header was published in the HTTPS response.",
            "category": "HTTP Headers",
            "root_cause": "Missing or incomplete browser security headers",
            "why": "Without HSTS, users may be exposed to HTTP downgrade attacks on hostile networks.",
            "recommendation": "Publish Strict-Transport-Security after validating that the entire domain and subdomains work correctly over HTTPS.",
            "next_step": "Confirm all subdomains support HTTPS before using includeSubDomains.",
            "nginx": "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;",
            "apache": "Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains\"",
        },
        {
            "keys": ["x-content-type-options", "mime sniff", "content type options"],
            "title": "Block MIME Sniffing",
            "severity": "LOW",
            "confidence": "HIGH",
            "confidence_reason": "The presence or absence of X-Content-Type-Options is directly verifiable in the HTTP response.",
            "category": "HTTP Headers",
            "root_cause": "Missing or incomplete browser security headers",
            "why": "Browsers may attempt to interpret files as a different MIME type than declared.",
            "recommendation": "Set X-Content-Type-Options to nosniff on all responses.",
            "next_step": "Apply the header and validate endpoints serving static files or uploads.",
            "nginx": "add_header X-Content-Type-Options \"nosniff\" always;",
            "apache": "Header always set X-Content-Type-Options \"nosniff\"",
        },
        {
            "keys": ["referrer-policy", "referrer policy"],
            "title": "Reduce origin leakage via Referer",
            "severity": "LOW",
            "confidence": "HIGH",
            "confidence_reason": "Referrer policy is published in a header and can be verified without inference.",
            "category": "HTTP Headers",
            "root_cause": "Missing or incomplete browser security headers",
            "why": "Internal URLs, parameters, and paths can leak to external sites via the Referer header.",
            "recommendation": "Use a restrictive policy, balancing privacy and compatibility.",
            "next_step": "Validate external authentication flows, payments, and redirects before hardening the policy.",
            "nginx": "add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;",
            "apache": "Header always set Referrer-Policy \"strict-origin-when-cross-origin\"",
        },
        {
            "keys": ["permissions-policy", "feature-policy"],
            "title": "Restrict sensitive browser APIs",
            "severity": "LOW",
            "confidence": "MEDIUM",
            "confidence_reason": "The absence of the header is objective, but the impact depends on the APIs actually used by the application.",
            "category": "HTTP Headers",
            "root_cause": "Missing or incomplete browser security headers",
            "why": "Features like camera, microphone, and geolocation should only be allowed when necessary.",
            "recommendation": "Set Permissions-Policy denying features that the application does not use.",
            "next_step": "Identify which browser APIs are legitimately used before publishing a restrictive policy.",
            "nginx": "add_header Permissions-Policy \"geolocation=(), microphone=(), camera=()\" always;",
            "apache": "Header always set Permissions-Policy \"geolocation=(), microphone=(), camera=()\"",
        },
    ]

    COOKIE_RULES = [
        {
            "keys": ["cookie", "httponly", "secure flag", "samesite"],
            "title": "Harden cookie attributes",
            "severity": "MEDIUM",
            "confidence": "MEDIUM",
            "confidence_reason": "Scanner observed missing attributes, but criticality depends on the cookie type and authentication flow.",
            "category": "Cookies",
            "root_cause": "Session cookies lacking consistent defensive attributes",
            "why": "Cookies without Secure, HttpOnly, and SameSite increase risk of theft, unauthorized sending, or abuse in web attacks.",
            "recommendation": "Configure session cookies with Secure, HttpOnly, and SameSite=Lax or Strict, according to the application flow.",
            "next_step": "Classify which cookies are session/auth related before applying SameSite Strict on flows with federation or external redirects.",
            "nginx": "proxy_cookie_flags ~ secure httponly samesite=lax;",
            "apache": "Header edit* Set-Cookie \"^(.*)$\" \"$1; Secure; HttpOnly; SameSite=Lax\"",
        }
    ]

    BASELINE_RULES = [
        {
            "title": "Apply security headers baseline",
            "severity": "INFO",
            "confidence": "MEDIUM",
            "confidence_reason": "This is a preventive recommendation; needs to be validated against actual application flows.",
            "category": "Hardening",
            "root_cause": "Defensive baseline not fully standardized",
            "evidence": "Preventive recommendation for exposed web applications.",
            "why": "Even without a specific alert, consistent headers reduce the browser's attack surface.",
            "recommendation": "Standardize CSP frame-ancestors, HSTS, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy.",
            "next_step": "Apply first in staging, validate login, embeds, downloads, external integrations, then promote to production.",
            "nginx": "\n".join([
                "add_header Content-Security-Policy \"frame-ancestors 'self';\" always;",
                "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;",
                "add_header X-Content-Type-Options \"nosniff\" always;",
                "add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;",
                "add_header Permissions-Policy \"geolocation=(), microphone=(), camera=()\" always;",
            ]),
            "apache": "\n".join([
                "Header always set Content-Security-Policy \"frame-ancestors 'self';\"",
                "Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains\"",
                "Header always set X-Content-Type-Options \"nosniff\"",
                "Header always set Referrer-Policy \"strict-origin-when-cross-origin\"",
                "Header always set Permissions-Policy \"geolocation=(), microphone=(), camera=()\"",
            ]),
        }
    ]

    def for_alert(self, alert: Dict[str, Any]) -> List[Dict[str, Any]]:
        text = " ".join(
            str(alert.get(field, ""))
            for field in ["alert", "name", "description", "solution", "risk"]
        ).lower()

        matched = []
        for rule in [*self.HEADER_RULES, *self.COOKIE_RULES]:
            if any(key in text for key in rule["keys"]):
                matched.append(self._build(rule, self._alert_evidence(alert), source="ZAP"))

        if alert.get("sourceid") == "static_analysis" or str(alert.get("alert", "")).startswith("CVE-"):
            matched.append(self.for_cve(alert))

        return self._dedupe(matched)

    def for_cve(self, vuln: Dict[str, Any]) -> Dict[str, Any]:
        cve_id = vuln.get("cve_id") or vuln.get("id") or str(vuln.get("alert", "")).split(":")[0]
        severity = (vuln.get("severity") or vuln.get("risk") or "MEDIUM").upper()
        evidence = vuln.get("matched_keyword") or vuln.get("url") or "CVE correlated with detected technology."
        title = f"Update component affected by {cve_id}" if cve_id else "Update vulnerable component"
        confidence, confidence_reason = self._cve_confidence(vuln)

        return self._build(
            {
                "title": title,
                "severity": severity,
                "confidence": confidence,
                "confidence_reason": confidence_reason,
                "category": "CVE",
                "root_cause": "Potentially vulnerable component",
                "why": "The detected technology has a published vulnerability in the CVE database. The exact version must be confirmed before classifying as exploitable.",
                "recommendation": "Confirm the installed version, apply patch or update the affected component, and record evidence of the fixed version.",
                "next_step": "Confirm the actual version on the server or dependency manifest before opening an incident as a confirmed vulnerability.",
                "nginx": "",
                "apache": "",
            },
            evidence,
            source="NVD",
        )

    def baseline(self, technologies: Dict[str, Any] | None = None) -> List[Dict[str, Any]]:
        recommendations = [self._build(rule, rule["evidence"], source="Baseline") for rule in self.BASELINE_RULES]

        tech_names = {name.lower() for name in (technologies or {}).keys()}
        if "nginx" in tech_names:
            recommendations[0]["preferred_server"] = "nginx"
        elif "apache" in tech_names:
            recommendations[0]["preferred_server"] = "apache"

        return recommendations

    def summarize_target(self, correlations: List[Dict[str, Any]]) -> Dict[str, Any]:
        severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0, "UNKNOWN": 0}
        sorted_items = self.prioritize(correlations)
        top_items = sorted_items[:5]
        severity_counts: Dict[str, int] = {}
        for item in correlations:
            severity = str(item.get("severity", "UNKNOWN")).upper()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        return {
            "total": len(correlations),
            "severity_counts": severity_counts,
            "analyst_note": self._analyst_note(len(correlations), top_items),
            "risk_groups": self.group_findings(correlations),
            "top_risks": [
                {
                    "id": item.get("cve_id") or item.get("id"),
                    "severity": item.get("severity", "UNKNOWN"),
                    "score": item.get("score", 0),
                    "confidence": item.get("remediation", {}).get("confidence", "MEDIUM"),
                    "reason": self._correlation_reason(item),
                    "next_step": item.get("remediation", {}).get("next_step"),
                }
                for item in top_items
            ],
        }

    def summarize_alerts(self, alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        remediations = []
        for alert in alerts:
            remediations.extend(alert.get("remediations", []))

        return {
            "total_alerts": len(alerts),
            "risk_groups": self.group_findings(remediations),
            "analyst_note": self._analyst_note(len(alerts), alerts[:5]),
        }

    def prioritize(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0, "UNKNOWN": 0}
        confidence_order = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
        return sorted(
            findings,
            key=lambda item: (
                severity_order.get(str(item.get("severity", "UNKNOWN")).upper(), 0),
                confidence_order.get(str(item.get("remediation", {}).get("confidence", item.get("confidence", "LOW"))).upper(), 1),
                float(item.get("score") or 0),
            ),
            reverse=True,
        )

    def group_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        groups: Dict[str, Dict[str, Any]] = {}
        for item in findings:
            remediation = item.get("remediation", item)
            root_cause = remediation.get("root_cause") or remediation.get("category") or "Others"
            group = groups.setdefault(root_cause, {
                "root_cause": root_cause,
                "count": 0,
                "highest_severity": "INFO",
                "next_step": remediation.get("next_step", "Review evidence and validate impact before prioritizing."),
            })
            group["count"] += 1
            group["highest_severity"] = self._max_severity(group["highest_severity"], remediation.get("severity", item.get("severity", "INFO")))

        return sorted(groups.values(), key=lambda item: item["count"], reverse=True)

    def _build(self, rule: Dict[str, Any], evidence: str, source: str) -> Dict[str, Any]:
        report = (
            f"Risk: {rule['title']}. "
            f"Evidence: {evidence} "
            f"Impact: {rule['why']} "
            f"Recommendation: {rule['recommendation']}"
        )
        return {
            "title": rule["title"],
            "severity": rule["severity"],
            "confidence": rule["confidence"],
            "confidence_reason": rule["confidence_reason"],
            "category": rule["category"],
            "root_cause": rule["root_cause"],
            "evidence": evidence,
            "evidence_items": [
                {
                    "source": source,
                    "detail": evidence,
                }
            ],
            "why_it_matters": rule["why"],
            "recommendation": rule["recommendation"],
            "next_step": rule["next_step"],
            "snippets": {
                "nginx": rule.get("nginx", ""),
                "apache": rule.get("apache", ""),
            },
            "report_sections": {
                "risk": rule["title"],
                "evidence": evidence,
                "impact": rule["why"],
                "recommendation": rule["recommendation"],
                "next_step": rule["next_step"],
            },
            "report_text": report,
        }

    def _alert_evidence(self, alert: Dict[str, Any]) -> str:
        name = alert.get("alert") or alert.get("name") or "Security Alert"
        url = alert.get("url")
        if url:
            return f"{name} observed at {url}."
        return f"{name} returned by the scanner."

    def _correlation_reason(self, item: Dict[str, Any]) -> str:
        keyword = item.get("matched_keyword")
        if keyword:
            return f"Associated because CVE search found a match for '{keyword}'."
        return "Associated based on technologies detected for the target."

    def _cve_confidence(self, vuln: Dict[str, Any]) -> tuple[str, str]:
        keyword = str(vuln.get("matched_keyword") or "")
        if any(char.isdigit() for char in keyword):
            return (
                "MEDIUM",
                "Contains version or family version in the correlation, but still requires confirmation of the installed version on the target.",
            )
        return (
            "LOW",
            "Correlation derived from technology name without confirmed version; treat as a hypothesis until inventory is validated.",
        )

    def _max_severity(self, current: str, candidate: str) -> str:
        severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0, "UNKNOWN": 0}
        current_key = str(current or "INFO").upper()
        candidate_key = str(candidate or "INFO").upper()
        return candidate_key if severity_order.get(candidate_key, 0) > severity_order.get(current_key, 0) else current_key

    def _analyst_note(self, total: int, top_items: List[Dict[str, Any]]) -> str:
        if total == 0:
            return "No findings were correlated at this time. This reduces noise, but does not replace manual review and configuration validation."
        if total > 20:
            return "There are many potential findings. Prioritize root cause groups and confirm versions before opening multiple separate tasks."
        highest = top_items[0].get("severity") if top_items else "INFO"
        return f"Start with the highest severity/confidence items. Highest severity observed in this view: {highest}."

    def _dedupe(self, items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen = set()
        unique = []
        for item in items:
            key = (item["title"], item["category"])
            if key in seen:
                continue
            seen.add(key)
            unique.append(item)
        return unique
