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
            "confidence_reason": "O scanner observou ausencia ou fragilidade em cabecalho diretamente verificavel na resposta HTTP.",
            "category": "HTTP Headers",
            "root_cause": "Headers de navegador ausentes ou incompletos",
            "why": "A aplicacao pode ser renderizada dentro de frames por origens nao autorizadas.",
            "recommendation": "Defina Content-Security-Policy com frame-ancestors ou use X-Frame-Options quando precisar de compatibilidade legada.",
            "next_step": "Validar em ambiente de homologacao quais origens realmente precisam enquadrar a aplicacao antes de aplicar a politica em producao.",
            "nginx": "add_header Content-Security-Policy \"frame-ancestors 'self';\" always;",
            "apache": "Header always set Content-Security-Policy \"frame-ancestors 'self';\"",
        },
        {
            "keys": ["strict-transport-security", "hsts"],
            "title": "Forcar HTTPS com HSTS",
            "severity": "MEDIUM",
            "confidence": "HIGH",
            "confidence_reason": "O scanner consegue verificar diretamente se o cabecalho HSTS foi publicado na resposta HTTPS.",
            "category": "HTTP Headers",
            "root_cause": "Headers de navegador ausentes ou incompletos",
            "why": "Sem HSTS, usuarios podem ficar expostos a downgrade para HTTP em redes hostis.",
            "recommendation": "Publique Strict-Transport-Security depois de validar que todo o dominio e subdominios funcionam corretamente em HTTPS.",
            "next_step": "Confirmar que todos os subdominios suportam HTTPS antes de usar includeSubDomains.",
            "nginx": "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;",
            "apache": "Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains\"",
        },
        {
            "keys": ["x-content-type-options", "mime sniff", "content type options"],
            "title": "Bloquear MIME sniffing",
            "severity": "LOW",
            "confidence": "HIGH",
            "confidence_reason": "A presenca ou ausencia de X-Content-Type-Options e verificavel diretamente na resposta HTTP.",
            "category": "HTTP Headers",
            "root_cause": "Headers de navegador ausentes ou incompletos",
            "why": "Navegadores podem tentar interpretar arquivos com tipo diferente do declarado.",
            "recommendation": "Defina X-Content-Type-Options como nosniff em todas as respostas.",
            "next_step": "Aplicar o header e validar endpoints que servem arquivos estaticos ou uploads.",
            "nginx": "add_header X-Content-Type-Options \"nosniff\" always;",
            "apache": "Header always set X-Content-Type-Options \"nosniff\"",
        },
        {
            "keys": ["referrer-policy", "referrer policy"],
            "title": "Reduzir vazamento de origem via Referer",
            "severity": "LOW",
            "confidence": "HIGH",
            "confidence_reason": "A politica de Referer e publicada em header e pode ser verificada sem inferencia.",
            "category": "HTTP Headers",
            "root_cause": "Headers de navegador ausentes ou incompletos",
            "why": "URLs internas, parametros e caminhos podem vazar para sites externos pelo cabecalho Referer.",
            "recommendation": "Use uma politica restritiva, equilibrando privacidade e compatibilidade.",
            "next_step": "Validar fluxos externos de autenticacao, pagamentos e redirecionamentos antes de endurecer a politica.",
            "nginx": "add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;",
            "apache": "Header always set Referrer-Policy \"strict-origin-when-cross-origin\"",
        },
        {
            "keys": ["permissions-policy", "feature-policy"],
            "title": "Restringir APIs sensiveis do navegador",
            "severity": "LOW",
            "confidence": "MEDIUM",
            "confidence_reason": "A ausencia do header e objetiva, mas o impacto depende das APIs realmente usadas pela aplicacao.",
            "category": "HTTP Headers",
            "root_cause": "Headers de navegador ausentes ou incompletos",
            "why": "Recursos como camera, microfone e geolocalizacao devem ser liberados apenas quando necessarios.",
            "recommendation": "Defina Permissions-Policy negando recursos que a aplicacao nao utiliza.",
            "next_step": "Levantar quais APIs do navegador sao usadas legitimamente antes de publicar uma politica restritiva.",
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
            "confidence_reason": "O scanner observou atributo ausente, mas a criticidade depende do tipo de cookie e do fluxo de autenticacao.",
            "category": "Cookies",
            "root_cause": "Cookies de sessao sem atributos defensivos consistentes",
            "why": "Cookies sem Secure, HttpOnly e SameSite aumentam risco de roubo, envio indevido ou abuso em ataques web.",
            "recommendation": "Configure cookies de sessao com Secure, HttpOnly e SameSite=Lax ou Strict, conforme o fluxo da aplicacao.",
            "next_step": "Classificar quais cookies sao de sessao/autenticacao antes de aplicar SameSite Strict em fluxos com federacao ou redirects externos.",
            "nginx": "proxy_cookie_flags ~ secure httponly samesite=lax;",
            "apache": "Header edit* Set-Cookie \"^(.*)$\" \"$1; Secure; HttpOnly; SameSite=Lax\"",
        }
    ]

    BASELINE_RULES = [
        {
            "title": "Aplicar baseline de headers de seguranca",
            "severity": "INFO",
            "confidence": "MEDIUM",
            "confidence_reason": "E uma recomendacao preventiva; precisa ser validada contra os fluxos reais da aplicacao.",
            "category": "Hardening",
            "root_cause": "Baseline defensivo ainda nao padronizado",
            "evidence": "Recomendacao preventiva para aplicacoes web expostas.",
            "why": "Mesmo sem alerta especifico, headers consistentes reduzem a superficie de ataque do navegador.",
            "recommendation": "Padronize CSP frame-ancestors, HSTS, X-Content-Type-Options, Referrer-Policy e Permissions-Policy.",
            "next_step": "Aplicar primeiro em homologacao, validar login, embeds, downloads, integracoes externas e depois promover para producao.",
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
        evidence = vuln.get("matched_keyword") or vuln.get("url") or "CVE correlacionada com a tecnologia detectada."
        title = f"Atualizar componente afetado por {cve_id}" if cve_id else "Atualizar componente vulneravel"
        confidence, confidence_reason = self._cve_confidence(vuln)

        return self._build(
            {
                "title": title,
                "severity": severity,
                "confidence": confidence,
                "confidence_reason": confidence_reason,
                "category": "CVE",
                "root_cause": "Componente potencialmente vulneravel",
                "why": "A tecnologia detectada possui vulnerabilidade publicada em base de CVEs. A versao exata deve ser confirmada antes de classificar como exploravel.",
                "recommendation": "Confirme a versao instalada, aplique patch ou atualize o componente afetado, e registre evidencia da versao corrigida.",
                "next_step": "Confirmar a versao real no servidor ou manifesto de dependencias antes de abrir incidente como vulnerabilidade confirmada.",
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
            root_cause = remediation.get("root_cause") or remediation.get("category") or "Outros"
            group = groups.setdefault(root_cause, {
                "root_cause": root_cause,
                "count": 0,
                "highest_severity": "INFO",
                "next_step": remediation.get("next_step", "Revisar evidencias e validar impacto antes de priorizar."),
            })
            group["count"] += 1
            group["highest_severity"] = self._max_severity(group["highest_severity"], remediation.get("severity", item.get("severity", "INFO")))

        return sorted(groups.values(), key=lambda item: item["count"], reverse=True)

    def _build(self, rule: Dict[str, Any], evidence: str, source: str) -> Dict[str, Any]:
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

    def _cve_confidence(self, vuln: Dict[str, Any]) -> tuple[str, str]:
        keyword = str(vuln.get("matched_keyword") or "")
        if any(char.isdigit() for char in keyword):
            return (
                "MEDIUM",
                "Ha versao ou familia de versao na correlacao, mas ainda e necessario confirmar a versao instalada no alvo.",
            )
        return (
            "LOW",
            "A correlacao veio do nome da tecnologia sem versao confirmada; trate como hipotese ate validar inventario.",
        )

    def _max_severity(self, current: str, candidate: str) -> str:
        severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0, "UNKNOWN": 0}
        current_key = str(current or "INFO").upper()
        candidate_key = str(candidate or "INFO").upper()
        return candidate_key if severity_order.get(candidate_key, 0) > severity_order.get(current_key, 0) else current_key

    def _analyst_note(self, total: int, top_items: List[Dict[str, Any]]) -> str:
        if total == 0:
            return "Nenhum achado foi correlacionado agora. Isso reduz ruido, mas nao substitui revisao manual e validacao de configuracao."
        if total > 20:
            return "Ha muitos achados potenciais. Priorize os grupos de causa raiz e confirme versoes antes de abrir varias tarefas separadas."
        highest = top_items[0].get("severity") if top_items else "INFO"
        return f"Comece pelos itens de maior severidade/confianca. Maior severidade observada nesta visao: {highest}."

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
