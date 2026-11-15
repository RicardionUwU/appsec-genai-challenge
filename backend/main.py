
"""
MercadoLibre AppSec GenAI Challenge

API server-side de análisis de seguridad.

Motores:
- Semgrep (SAST)
- Ollama (LLM)
- Policy Engine (decisiones)
"""

import asyncio
import hashlib
import logging

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from backend.analyzer import analyze_with_ai
from backend.semgrep_analyzer import analyze_with_semgrep
from backend.policy_engine import decide


logger = logging.getLogger(__name__)

app = FastAPI(
    title="AppSec GenAI Security Analyzer",
    description="Análisis híbrido OWASP con Semgrep y Ollama",
    version="1.2.0",
)


class CodeAnalysisRequest(BaseModel):
    filename: str = Field(
        min_length=1,
        max_length=255
    )

    code: str = Field(
        min_length=1,
        max_length=90000
    )


@app.get("/health", tags=["System"])
def health():
    return {"status": "healthy"}


@app.post("/analyze", tags=["Security Analysis"])
async def analyze_code(request: CodeAnalysisRequest):

    try:
        # 1. Calcular huella del contenido recibido
        code_hash = hashlib.sha256(
            request.code.encode("utf-8")
        ).hexdigest()

        # 2. Ejecutar Semgrep sin bloquear
        #    el event loop de FastAPI
        semgrep_result = await asyncio.to_thread(
            analyze_with_semgrep,
            request.filename,
            request.code
        )

        # 3. Ejecutar análisis GenAI
        ai_result = await analyze_with_ai(
            filename=request.filename,
            code=request.code
        )

        if ai_result.get("sha256") != code_hash:
            raise ValueError(
                "Inconsistencia en hash de análisis"
            )

        # 4. Aplicar política de seguridad
        decision = decide(
            semgrep_result,
            ai_result
        )

        # 5. Devolver resultado al hook
        return {
            "filename": request.filename,
            "status": decision["status"],
            "sha256": code_hash,
            "model": ai_result.get("model"),
            "vulnerabilities": decision["vulnerabilities"],
            "needs_review": decision["needs_review"],
            "engines": {
                "semgrep": {
                    "findings": decision["semgrep_total"]
                },
                "ollama": {
                    "findings": decision["ollama_total"]
                }
            }
        }

    except Exception:
        logger.exception(
            "Error durante el análisis de seguridad"
        )

        raise HTTPException(
            status_code=503,
            detail=(
                "No se pudo completar el análisis. "
                "No se emite aprobación de seguridad."
            )
        )
