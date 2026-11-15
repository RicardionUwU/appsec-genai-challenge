
"""
AppSec GenAI - Security Policy Engine

Combina los resultados de Semgrep y Ollama
para tomar decisiones de seguridad.

Politica:
- Hallazgo bloqueante de Semgrep: rejected.
- Hallazgo solo de Ollama: review_required.
- Sin hallazgos de ambos: approved.
- Resultados inconsistentes: error (fail-closed).
"""


def normalize_semgrep_finding(finding):
    """Convierte hallazgos de Semgrep al formato del hook."""

    severity_map = {
        "ERROR": "HIGH",
        "WARNING": "MEDIUM",
        "INFO": "LOW",
    }

    rule_id = finding.get("rule_id")
    if not isinstance(rule_id, str) or not rule_id:
        raise ValueError("Hallazgo Semgrep sin regla válida")

    severity = severity_map.get(
        finding.get("severity"), "MEDIUM"
    )

    owasp_categories = finding.get("owasp", [])

    if not isinstance(owasp_categories, list):
        raise ValueError("Categorías OWASP inválidas")

    category = (
        owasp_categories[0]
        if owasp_categories
        else "Unclassified"
    )

    if category == "A03:2021-Injection":
        category = "A03:2021 - Injection"

    line = finding.get("line")
    description = str(finding.get("description") or "")

    if not description:
        raise ValueError("Hallazgo sin descripción")

    if "command-injection" in rule_id.lower():
        recommendation = (
            "Evitar ejecutar comandos arbitrarios. "
            "Utilizar operaciones permitidas y "
            "argumentos explícitos sin shell."
        )
    else:
        recommendation = (
            "Revisar el hallazgo y aplicar la "
            "mitigación correspondiente a la regla."
        )

    return {
        "type": str(
            finding.get("type") or "Security Finding"
        ),
        "owasp": category,
        "severity": severity,
        "description": (
            f"{description} Línea: {line}. "
            f"Regla: {rule_id}"
        ),
        "recommendation": recommendation,
        "source": "semgrep",
        "rule_id": rule_id,
        "line": line,
    }


def decide(semgrep_result: dict, ai_result: dict):
    """Evalúa ambos motores aplicando la política."""

    semgrep_findings = semgrep_result.get("findings")
    ai_findings = ai_result.get("vulnerabilities")
    ai_review = ai_result.get("needs_review")
    ai_status = ai_result.get("status")

    if not all(
        isinstance(items, list)
        for items in (
            semgrep_findings,
            ai_findings,
            ai_review,
        )
    ):
        raise ValueError("Resultados de análisis inválidos")

    if semgrep_result.get("total_findings") != len(
        semgrep_findings
    ):
        raise ValueError("Conteo de Semgrep inconsistente")

    if ai_status == "approved" and (
        ai_findings or ai_review
    ):
        raise ValueError("Aprobación de IA inconsistente")

    if ai_status == "rejected" and not ai_findings:
        raise ValueError("Rechazo de IA sin hallazgos")

    if ai_status == "review_required" and (
        ai_findings or not ai_review
    ):
        raise ValueError("Revisión de IA inconsistente")

    if ai_status not in (
        "approved",
        "rejected",
        "review_required",
    ):
        raise ValueError("Estado de IA desconocido")

    static_findings = [
        normalize_semgrep_finding(f)
        for f in semgrep_findings
    ]

    llm_findings = [
        {**finding, "source": "ollama"}
        for finding in ai_findings + ai_review
    ]

    if static_findings:
        status = "rejected"
        vulnerabilities = static_findings
        needs_review = llm_findings

    elif llm_findings:
        status = "review_required"
        vulnerabilities = []
        needs_review = llm_findings

    else:
        status = "approved"
        vulnerabilities = []
        needs_review = []

    return {
        "status": status,
        "vulnerabilities": vulnerabilities,
        "needs_review": needs_review,
        "semgrep_total": len(static_findings),
        "ollama_total": len(llm_findings),
    }
