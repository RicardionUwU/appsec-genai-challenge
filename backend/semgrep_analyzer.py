
"""
AppSec GenAI - Semgrep Analyzer

Ejecuta Semgrep mediante Docker para analizar
código Python sin ejecutarlo.

Las reglas son controladas por el backend.
"""

import json
import subprocess
import tempfile
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent

RULES_PATH = (
    PROJECT_ROOT / "rules" / "python-security.yaml"
)

SEMGREP_IMAGE = "semgrep/semgrep"

MAX_CODE_BYTES = 90000


def analyze_with_semgrep(filename: str, code: str):
    """
    Analiza código Python con Semgrep.

    Devuelve una lista de hallazgos estructurados.
    Los errores de Semgrep impiden emitir
    una aprobación de seguridad.
    """

    if Path(filename).suffix.lower() != ".py":
        raise ValueError(
            "Este analizador Semgrep solo soporta Python"
        )

    code_bytes = code.encode("utf-8")

    if len(code_bytes) > MAX_CODE_BYTES:
        raise ValueError(
            "El archivo supera el tamaño permitido"
        )

    if not RULES_PATH.is_file():
        raise FileNotFoundError(
            f"No existen las reglas: {RULES_PATH}"
        )

    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)

        source_file = temp_path / "candidate.py"
        source_file.write_bytes(code_bytes)

        command = [
            "docker", "run",
            "--rm",
            "--network", "none",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--memory", "2g",
            "--cpus", "2",
            "-v", f"{temp_path.resolve()}:/src:ro",
            "-v", f"{RULES_PATH.resolve()}:/rules/security.yaml:ro",
            "-w", "/src",
            SEMGREP_IMAGE,
            "semgrep", "scan",
            "--config", "/rules/security.yaml",
            "--json",
            "--metrics", "off",
            "candidate.py",
        ]

        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=240,
            check=False,
            shell=False,
        )

        if process.returncode != 0:
            raise RuntimeError(
                "Semgrep falló: "
                + process.stderr[-1000:]
            )

        result = json.loads(process.stdout)

        if result.get("errors"):
            raise RuntimeError(
                "Semgrep reportó errores de análisis"
            )

        findings = []

        for finding in result.get("results", []):
            extra = finding.get("extra", {})
            start = finding.get("start", {})
            metadata = extra.get("metadata", {})

            findings.append({
                "type": "Potential Command Injection",
                "rule_id": finding.get("check_id"),
                "severity": extra.get("severity"),
                "line": start.get("line"),
                "description": extra.get("message"),
                "owasp": metadata.get("owasp", []),
                "source": "semgrep",
            })

        return {
            "filename": filename,
            "engine": "semgrep",
            "findings": findings,
            "total_findings": len(findings),
        }
