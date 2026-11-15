
import json
import os
import re
import hashlib
from pathlib import Path
from typing import Literal

import httpx
from pydantic import BaseModel, ConfigDict, Field


# ==========================================
# CONFIGURACION DE OLLAMA
# ==========================================

OLLAMA_URL = os.getenv(
    "OLLAMA_URL",
    "http://127.0.0.1:11434/api/chat"
)

OLLAMA_MODEL = os.getenv(
    "OLLAMA_MODEL",
    "qwen2.5-coder:7b"
)

PROMPT_PATH = (
    Path(__file__).parent
    / "prompts"
    / "security_review.txt"
)


# ==========================================
# MODELOS DE VALIDACION
# ==========================================

class Vulnerability(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: str = Field(min_length=1)
    owasp: str = Field(min_length=1)
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    description: str = Field(min_length=1)
    recommendation: str = Field(min_length=1)


class AnalysisResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    vulnerabilities: list[Vulnerability]


# ==========================================
# VALIDACION DE HALLAZGOS
# ==========================================

SQL_INDICATORS = (
    "select ",
    "insert into ",
    "update ",
    "delete from ",
    "sqlite3",
    "sqlalchemy",
    "psycopg",
    "cursor(",
    "executemany(",
    "execute(",
)


def validate_findings(code: str, vulnerabilities: list):
    """
    Clasifica hallazgos que necesitan revision.

    IMPORTANTE:
    Esta es una heuristica inicial, no un
    detector definitivo de SQL Injection.
    """

    validated = []
    needs_review = []

    normalized_code = code.lower()

    for vulnerability in vulnerabilities:
        vuln_type = vulnerability.type.lower()
        description = vulnerability.description.lower()

        is_sqli = (
            "sql injection" in vuln_type
            or "sql injection" in description
        )

        if is_sqli:
            has_sql_evidence = any(
                indicator in normalized_code
                for indicator in SQL_INDICATORS
            )

            if not has_sql_evidence:
                needs_review.append(
                    vulnerability.model_dump()
                )
                continue

        validated.append(
            vulnerability.model_dump()
        )

    return validated, needs_review


# ==========================================
# ANALIZADOR GENAI
# ==========================================

async def analyze_with_ai(filename: str, code: str):
    """
    Analiza el codigo con Ollama.

    Flujo:
    1. Carga el prompt server-side.
    2. Calcula SHA-256 del contenido recibido.
    3. Consulta el LLM.
    4. Valida el formato JSON.
    5. Clasifica hallazgos.
    6. Devuelve el resultado.

    El SHA-256 es informativo por ahora:
    aun no implementa la verificacion
    de integridad del push remoto.
    """

    security_prompt = PROMPT_PATH.read_text(
        encoding="utf-8"
    )

    code_hash = hashlib.sha256(
        code.encode("utf-8")
    ).hexdigest()

    payload = {
        "model": OLLAMA_MODEL,
        "stream": False,
        "format": "json",
        "options": {
            "temperature": 0
        },
        "messages": [
            {
                "role": "system",
                "content": security_prompt
            },
            {
                "role": "user",
                "content": json.dumps(
                    {
                        "filename": filename,
                        "code": code
                    },
                    ensure_ascii=False
                )
            }
        ]
    }

    async with httpx.AsyncClient(
        timeout=180.0
    ) as client:
        response = await client.post(
            OLLAMA_URL,
            json=payload
        )

        response.raise_for_status()

    ollama_response = response.json()

    ai_content = ollama_response[
        "message"
    ]["content"]

    result = AnalysisResult.model_validate_json(
        ai_content
    )

    validated, needs_review = validate_findings(
        code,
        result.vulnerabilities
    )

    if validated:
        status = "rejected"
    elif needs_review:
        status = "review_required"
    else:
        status = "approved"

    return {
        "filename": filename,
        "status": status,
        "sha256": code_hash,
        "model": OLLAMA_MODEL,
        "vulnerabilities": validated,
        "needs_review": needs_review
    }
