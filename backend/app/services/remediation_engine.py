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
            "title": "Protecao contra clickjacking",
            "severity": "MEDIUM",
            "confidence": "HIGH",
            "category": "HTTP Headers",
            "why": "A aplicacao pode ser renderizada dentro de frames por origens nao autorizadas.",
            "recommendation": "Defina Content-Security-Policy com frame-ancestors ou use X-Frame-Options quando precisar de compatibilidade legada.",
            "nginx": "add_header Content-Security-Policy \"frame-ancestors 'self';\" always;",
            "apache": "Header always set Content-Security-Policy \"frame-ancestors 'self';\"",
        },
        {
            "keys": ["strict-transport-security", "hsts"],
            "title": "Forcar HTTPS com HSTS",
            "severity": "MEDIUM",
            "confidence": "HIGH",
            "category": "HTTP Headers",
            "why": "Sem HSTS, usuarios podem ficar expostos a downgrade para HTTP em redes hostis.",
            "recommendation": "Publique Strict-Transport-Security depois de validar que todo o dominio e subdominios funcionam corretamente em HTTPS.",
            "nginx": "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;",
            "apache": "Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains\"",
        },
        {
            "keys": ["x-content-type-options", "mime sniff", "content type options"],
            "title": "Bloquear MIME sniffing",
            "severity": "LOW",
            "confidence": "HIGH",
            "category": "HTTP Headers",
            "why": "Navegadores podem tentar interpretar arquivos com tipo diferente do declarado.",
            "recommendation": "Defina X-Content-Type-Options como nosniff em todas as respostas.",
            "nginx": "add_header X-Content-Type-Options \"nosniff\" always;",
            "apache": "Header always set X-Content-Type-Options \"nosniff\"",
        },
        {
            "keys": ["referrer-policy", "referrer policy"],
            "title": "Reduzir vazamento de origem via Referer",
            "severity": "LOW",
            "confidence": "HIGH",
            "category": "HTTP Headers",
            "why": "URLs internas, parametros e caminhos podem vazar para sites externos pelo cabecalho Referer.",
            "recommendation": "Use uma politica restritiva, equilibrando privacidade e compatibilidade.",
            "nginx": "add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;",
            "apache": "Header always set Referrer-Policy \"strict-origin-when-cross-origin\"",
        },
        {
            "keys": ["permissions-policy", "feature-policy"],
            "title": "Restringir APIs sensiveis do navegador",
            "severity": "LOW",
            "confidence": "MEDIUM",
            "category": "HTTP Headers",
            "why": "Recursos como camera, microfone e geolocalizacao devem ser liberados apenas quando necessarios.",
            "recommendation": "Defina Permissions-Policy negando recursos que a aplicacao nao utiliza.",
            "nginx": "add_header Permissions-Policy \"geolocation=(), microphone=(), camera=()\" always;",
            "apache": "Header always set Permissions-Policy \"geolocation=(), microphone=(), camera=()\"",
        },
    ]

    COOKIE_RULES = [
        {
            "keys": ["cookie", "httponly", "secure flag", "samesite"],
            "title": "Endurecer atributos de cookies",
            "severity": "MEDIUM",
            "confidence": "MEDIUM",
            "category": "Cookies",
            "why": "Cookies sem Secure, HttpOnly e SameSite aumentam risco de roubo, envio indevido ou abuso em ataques web.",
            "recommendation": "Configure cookies de sessao com Secure, HttpOnly e SameSite=Lax ou Strict, conforme o fluxo da aplicacao.",
            "nginx": "proxy_cookie_flags ~ secure httponly samesite=lax;",
            "apache": "Header edit* Set-Cookie \"^(.*)$\" \"$1; Secure; HttpOnly; SameSite=Lax\"",
        }
    ]

    BASELINE_RULES = [
        {
            "title": "Aplicar baseline de headers de seguranca",
            "severity": "INFO",
            "confidence": "MEDIUM",
            "category": "Hardening",
            "evidence": "Recomendacao preventiva para aplicacoes web expostas.",
            "why": "Mesmo sem alerta especifico, headers consistentes reduzem a superficie de ataque do navegador.",
            "recommendation": "Padronize CSP frame-ancestors, HSTS, X-Content-Type-Options, Referrer-Policy e Permissions-Policy.",
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
                matched.append(self._build(rule, self._alert_evidence(alert)))

        if alert.get("sourceid") == "static_analysis" or str(alert.get("alert", "")).startswith("CVE-"):
            matched.append(self.for_cve(alert))

        return self._dedupe(matched)

    def for_cve(self, vuln: Dict[str, Any]) -> Dict[str, Any]:
        cve_id = vuln.get("cve_id") or vuln.get("id") or str(vuln.get("alert", "")).split(":")[0]
        severity = (vuln.get("severity") or vuln.get("risk") or "MEDIUM").upper()
        evidence = vuln.get("matched_keyword") or vuln.get("url") or "CVE correlacionada com a tecnologia detectada."
        title = f"Atualizar componente afetado por {cve_id}" if cve_id else "Atualizar componente vulneravel"

        return self._build(
            {
                "title": title,
                "severity": severity,
                "confidence": vuln.get("confidence", "MEDIUM"),
                "category": "CVE",
                "why": "A tecnologia detectada possui vulnerabilidade publicada em base de CVEs. A versao exata deve ser confirmada antes de classificar como exploravel.",
                "recommendation": "Confirme a versao instalada, aplique patch ou atualize o componente afetado, e registre evidencia da versao corrigida.",
                "nginx": "",
                "apache": "",
            },
            evidence,
        )

    def baseline(self, technologies: Dict[str, Any] | None = None) -> List[Dict[str, Any]]:
        recommendations = [self._build(rule, rule["evidence"]) for rule in self.BASELINE_RULES]

        tech_names = {name.lower() for name in (technologies or {}).keys()}
        if "nginx" in tech_names:
            recommendations[0]["preferred_server"] = "nginx"
        elif "apache" in tech_names:
            recommendations[0]["preferred_server"] = "apache"

        return recommendations

    def summarize_target(self, correlations: List[Dict[str, Any]]) -> Dict[str, Any]:
        severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0, "UNKNOWN": 0}
        sorted_items = sorted(
            correlations,
            key=lambda item: (
                severity_order.get(str(item.get("severity", "UNKNOWN")).upper(), 0),
                float(item.get("score") or 0),
            ),
            reverse=True,
        )
        top_items = sorted_items[:5]

        return {
            "total": len(correlations),
            "top_risks": [
                {
                    "id": item.get("cve_id") or item.get("id"),
                    "severity": item.get("severity", "UNKNOWN"),
                    "score": item.get("score", 0),
                    "reason": self._correlation_reason(item),
                }
                for item in top_items
            ],
        }

    def _build(self, rule: Dict[str, Any], evidence: str) -> Dict[str, Any]:
        report = (
            f"Risco: {rule['title']}. "
            f"Evidencia: {evidence} "
            f"Impacto: {rule['why']} "
            f"Recomendacao: {rule['recommendation']}"
        )
        return {
            "title": rule["title"],
            "severity": rule["severity"],
            "confidence": rule["confidence"],
            "category": rule["category"],
            "evidence": evidence,
            "why_it_matters": rule["why"],
            "recommendation": rule["recommendation"],
            "snippets": {
                "nginx": rule.get("nginx", ""),
                "apache": rule.get("apache", ""),
            },
            "report_text": report,
        }

    def _alert_evidence(self, alert: Dict[str, Any]) -> str:
        name = alert.get("alert") or alert.get("name") or "Alerta de seguranca"
        url = alert.get("url")
        if url:
            return f"{name} observado em {url}."
        return f"{name} retornado pelo scanner."

    def _correlation_reason(self, item: Dict[str, Any]) -> str:
        keyword = item.get("matched_keyword")
        if keyword:
            return f"Associado porque a busca de CVEs encontrou correspondencia para '{keyword}'."
        return "Associado com base nas tecnologias detectadas para o alvo."

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
