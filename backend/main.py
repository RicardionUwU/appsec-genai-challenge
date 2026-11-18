
"""
MercadoLibre AppSec GenAI Challenge

API server-side de analisis de seguridad.

Motores:
- Semgrep (SAST)
- Ollama / Qwen2.5-Coder 7B (LLM)
- Policy Engine

Controles:
- Auth0 OAuth 2.0 / OIDC
- JWT Authentication
- RBAC Authorization
- HTTP Security Headers
- SHA-256 Content Integrity
- Signed Analysis Manifests (Ed25519)
- Complete Batch Approval
- Fail-closed Processing

IMPORTANTE:
El cliente Git no es confiable.

La firma del manifiesto demuestra que el
backend firmante aprobo determinados bytes,
pero no demuestra por si sola que representen
todo el commit.

Un verificador remoto independiente debe
comparar el manifiesto con el commit real.
"""

import asyncio
import hashlib
import logging
import os
import re

from pathlib import Path
from typing import Literal

from fastapi import (
    Depends,
    FastAPI,
    HTTPException,
    Request,
)

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    model_validator,
)

from backend.analyzer import (
    OLLAMA_MODEL,
    analyze_with_ai,
)

from backend.semgrep_analyzer import (
    analyze_with_semgrep,
)

from backend.policy_engine import decide

from backend.auth import (
    require_analyze_permission,
    require_review_permission,
)

from backend.attestations import (
    ApprovedAnalysis,
    FileRecord,
    GIT_OID_PATTERN,
    MAX_FILES,
    MAX_FILE_BYTES,
    MAX_TOTAL_BYTES,
    compute_policy_sha256,
    issue_signed_manifest,
    load_signing_private_key,
)


# ==========================================
# LOGGING AND CONFIGURATION
# ==========================================

logger = logging.getLogger(__name__)

APP_ENV = os.getenv(
    "APP_ENV",
    "development",
).strip().lower()

PROJECT_ROOT = (
    Path(__file__).resolve().parent.parent
)


# ==========================================
# FASTAPI APPLICATION
# ==========================================

app = FastAPI(
    title="AppSec GenAI Security Analyzer",
    description=(
        "Analisis hibrido de seguridad OWASP "
        "con Semgrep, Ollama, Auth0 y "
        "manifiestos firmados."
    ),
    version="1.5.0",
)


# ==========================================
# SECURITY HEADERS
# ==========================================

API_CSP = (
    "default-src 'none'; "
    "base-uri 'none'; "
    "frame-ancestors 'none'; "
    "form-action 'none'"
)

# Swagger necesita ciertos recursos
# e inicializacion de JavaScript.
# Esta CSP solo bloquea framing.

SWAGGER_CSP = "frame-ancestors 'none'"

DOCUMENTATION_PATHS = {
    "/docs",
    "/redoc",
    "/docs/oauth2-redirect",
}

SENSITIVE_PATHS = {
    "/analyze",
    "/analyze/batch",
    "/auth/me",
    "/reviews",
}


@app.middleware("http")
async def security_headers_middleware(
    request: Request,
    call_next,
):
    """
    Aplica cabeceras de seguridad.

    HSTS solo bajo HTTPS en produccion.
    """

    response = await call_next(request)

    response.headers[
        "X-Content-Type-Options"
    ] = "nosniff"

    response.headers[
        "X-Frame-Options"
    ] = "DENY"

    response.headers[
        "Referrer-Policy"
    ] = "no-referrer"

    response.headers[
        "Permissions-Policy"
    ] = (
        "camera=(), "
        "microphone=(), "
        "geolocation=(), "
        "payment=()"
    )

    if request.url.path in DOCUMENTATION_PATHS:
        response.headers[
            "Content-Security-Policy"
        ] = SWAGGER_CSP
    else:
        response.headers[
            "Content-Security-Policy"
        ] = API_CSP

    if request.url.path in SENSITIVE_PATHS:
        response.headers[
            "Cache-Control"
        ] = "no-store"

        response.headers[
            "Pragma"
        ] = "no-cache"

    if (
        APP_ENV == "production"
        and request.url.scheme == "https"
    ):
        response.headers[
            "Strict-Transport-Security"
        ] = "max-age=31536000"

    return response


# ==========================================
# EXISTING SINGLE-FILE REQUEST SCHEMA
# ==========================================

class CodeAnalysisRequest(BaseModel):

    filename: str = Field(
        min_length=1,
        max_length=255,
    )

    code: str = Field(
        min_length=1,
        max_length=90000,
    )


# ==========================================
# STRICT BATCH FILE SCHEMA
# ==========================================

class BatchFileInput(BaseModel):

    model_config = ConfigDict(
        extra="forbid",
        strict=True,
    )

    filename: str = Field(
        min_length=1,
        max_length=1024,
    )

    mode: Literal[
        "100644",
        "100755",
    ]

    code: str = Field(
        min_length=1,
        max_length=MAX_FILE_BYTES,
    )

    @model_validator(mode="after")
    def validate_file(self):

        # Reutilizar la politica de rutas
        # canonicas del modulo de firmas.
        #
        # Un filename invalido provoca
        # error de validacion HTTP 422.
        FileRecord(
            path=self.filename,
            mode=self.mode,
            sha256="0" * 64,
        )

        content_bytes = self.code.encode(
            "utf-8"
        )

        if len(content_bytes) > MAX_FILE_BYTES:
            raise ValueError(
                "El archivo excede el "
                "limite de bytes permitido"
            )

        return self


# ==========================================
# STRICT BATCH REQUEST SCHEMA
# ==========================================

class BatchAnalysisRequest(BaseModel):

    model_config = ConfigDict(
        extra="forbid",
        strict=True,
    )

    git_tree_oid: str = Field(
        pattern=GIT_OID_PATTERN,
    )

    parent_oid: str | None = None

    files: list[BatchFileInput] = Field(
        min_length=1,
        max_length=MAX_FILES,
    )

    @model_validator(mode="after")
    def validate_batch(self):

        # ==================================
        # VERIFY GIT IDENTIFIERS FORMAT
        # ==================================

        if self.parent_oid is not None:

            if not re.fullmatch(
                GIT_OID_PATTERN,
                self.parent_oid,
            ):
                raise ValueError(
                    "Git parent OID invalido"
                )

            if (
                len(self.parent_oid)
                != len(self.git_tree_oid)
            ):
                raise ValueError(
                    "Formato Git OID inconsistente"
                )

        # ==================================
        # REJECT DUPLICATE FILE PATHS
        # ==================================

        paths = [
            item.filename.casefold()
            for item in self.files
        ]

        if len(paths) != len(set(paths)):
            raise ValueError(
                "El lote contiene rutas duplicadas"
            )

        # ==================================
        # ENFORCE TOTAL BYTE LIMIT
        # ==================================

        total_bytes = sum(
            len(item.code.encode("utf-8"))
            for item in self.files
        )

        if total_bytes > MAX_TOTAL_BYTES:
            raise ValueError(
                "El lote excede el "
                "limite total de bytes"
            )

        # ==================================
        # SUPPORTED LANGUAGE POLICY
        # ==================================

        # El Semgrep actual solo tiene
        # soporte implementado para Python.
        #
        # Nunca firmar un lenguaje que
        # no haya sido analizado por
        # todos los motores obligatorios.
        for item in self.files:

            extension = Path(
                item.filename
            ).suffix.lower()

            if extension != ".py":
                raise ValueError(
                    "Lenguaje no soportado "
                    "por el analizador actual"
                )

        return self


# ==========================================
# TRUSTED POLICY FINGERPRINT
# ==========================================

TRUSTED_POLICY_PATHS = (
    "backend/main.py",
    "backend/auth.py",
    "backend/attestations.py",
    "backend/analyzer.py",
    "backend/semgrep_analyzer.py",
    "backend/policy_engine.py",
    "backend/prompts/security_review.txt",
    "rules/python-security.yaml",
)


def get_trusted_policy_sha256() -> str:
    """
    Calcula una huella de los controles
    que utiliza el backend.

    Los archivos se leen desde el despliegue
    del servidor, no desde el request.

    En produccion deben proceder de un
    despliegue de confianza e inmutable.
    """

    trusted_files = {}

    for relative_path in TRUSTED_POLICY_PATHS:

        full_path = (
            PROJECT_ROOT / relative_path
        )

        trusted_files[
            relative_path
        ] = full_path.read_bytes()

    return compute_policy_sha256(
        trusted_files
    )


# ==========================================
# HEALTH CHECK
# ==========================================

@app.get(
    "/health",
    tags=["System"],
)
def health():

    return {
        "status": "healthy"
    }


# ==========================================
# AUTHENTICATED USER
# ==========================================

@app.get(
    "/auth/me",
    tags=["Authentication"],
    summary="Validate developer identity",
)
def authenticated_user(
    user: dict = Depends(
        require_analyze_permission
    ),
):
    """
    Requires analyze:code.
    """

    return {
        "authenticated": True,
        "subject": user["sub"],
        "permissions": user.get(
            "permissions", []
        ),
    }


# ==========================================
# SECURITY REVIEW PLACEHOLDER
# ==========================================

@app.post(
    "/reviews",
    tags=["Security Review"],
    summary="Security review - not yet implemented",
    responses={
        501: {
            "description": (
                "Security review workflow "
                "is not implemented yet."
            ),
        },
    },
)
async def create_review(
    user: dict = Depends(
        require_review_permission
    ),
):
    """
    Requires review:findings.

    Intentionally unavailable until
    the review workflow and audit
    controls are implemented.
    """

    raise HTTPException(
        status_code=501,
        detail=(
            "Security review workflow "
            "is not implemented yet. "
            "No approval has been issued."
        ),
    )


# ==========================================
# INTERNAL SECURITY ANALYSIS
# ==========================================

async def evaluate_source_code(
    filename: str,
    code: str,
) -> dict:
    """
    Punto unico de analisis para
    /analyze y /analyze/batch.

    No emite firmas.

    Flujo:
    - Hash del contenido recibido.
    - Semgrep.
    - Ollama.
    - Verificacion de identidad de entrada.
    - Policy Engine.

    Cualquier error se propaga.
    """

    code_hash = hashlib.sha256(
        code.encode("utf-8")
    ).hexdigest()

    # ==================================
    # 1. SEMGREP
    # ==================================

    semgrep_result = await asyncio.to_thread(
        analyze_with_semgrep,
        filename,
        code,
    )

    # ==================================
    # 2. OLLAMA
    # ==================================

    ai_result = await analyze_with_ai(
        filename=filename,
        code=code,
    )

    # ==================================
    # 3. ANALYSIS INTEGRITY
    # ==================================

    if ai_result.get("sha256") != code_hash:
        raise ValueError(
            "Inconsistencia en hash de analisis"
        )

    if ai_result.get("filename") != filename:
        raise ValueError(
            "Inconsistencia en nombre de archivo"
        )

    if ai_result.get("model") != OLLAMA_MODEL:
        raise ValueError(
            "Modelo de analisis inesperado"
        )

    # ==================================
    # 4. POLICY ENGINE
    # ==================================

    decision = decide(
        semgrep_result,
        ai_result,
    )

    status = decision.get("status")

    if status not in {
        "approved",
        "rejected",
        "review_required",
    }:
        raise ValueError(
            "Decision de seguridad invalida"
        )

    # ==================================
    # 5. STRUCTURED RESULT
    # ==================================

    return {
        "filename": filename,
        "status": status,
        "sha256": code_hash,
        "model": ai_result["model"],

        "vulnerabilities": (
            decision["vulnerabilities"]
        ),

        "needs_review": (
            decision["needs_review"]
        ),

        "engines": {
            "semgrep": {
                "findings": (
                    decision["semgrep_total"]
                )
            },

            "ollama": {
                "findings": (
                    decision["ollama_total"]
                )
            },
        },
    }


# ==========================================
# EXISTING SINGLE-FILE ENDPOINT
# ==========================================

@app.post(
    "/analyze",
    tags=["Security Analysis"],
    summary="Analyze source code security",
)
async def analyze_code(
    request: CodeAnalysisRequest,
    user: dict = Depends(
        require_analyze_permission
    ),
):
    """
    Conserva el contrato del hook actual.

    Requires:
    - Valid JWT
    - Allowed OAuth client
    - analyze:code permission

    Nunca emite constancias de lote.
    """

    try:

        return await evaluate_source_code(
            filename=request.filename,
            code=request.code,
        )

    except Exception:

        logger.exception(
            "Error durante el analisis de seguridad"
        )

        raise HTTPException(
            status_code=503,
            detail=(
                "No se pudo completar el analisis. "
                "No se emite aprobacion de seguridad."
            ),
        )


# ==========================================
# SIGNED BATCH ANALYSIS ENDPOINT
# ==========================================

@app.post(
    "/analyze/batch",
    tags=["Security Analysis"],
    summary=(
        "Analyze a Git batch and issue "
        "a signed approval manifest"
    ),
)
async def analyze_batch(
    request: BatchAnalysisRequest,
    user: dict = Depends(
        require_analyze_permission
    ),
):
    """
    Analiza todos los archivos del lote.

    La identidad proviene exclusivamente
    del JWT validado por backend.auth.

    El servidor NO confia en:
    - La decision enviada por un cliente.
    - Un hash aportado por el cliente.
    - La veracidad del Git tree declarado.
    - La cobertura declarada del commit.

    Solo los dos ultimos elementos pueden
    comprobarse completamente contra el
    repositorio remoto real.
    """

    try:

        # ==================================
        # 1. SNAPSHOT OF SERVER POLICY
        # ==================================

        policy_before = (
            get_trusted_policy_sha256()
        )

        results = []
        approved_analyses = []

        # ==================================
        # 2. ANALYZE EVERY FILE
        # ==================================

        for item in request.files:

            result = await evaluate_source_code(
                filename=item.filename,
                code=item.code,
            )

            results.append(result)

            # No fabricar aprobaciones.
            #
            # El estado viene del
            # Policy Engine del servidor.
            if result["status"] == "approved":

                approved_analyses.append(
                    ApprovedAnalysis(
                        path=item.filename,
                        content=item.code.encode(
                            "utf-8"
                        ),
                        mode=item.mode,
                        status="approved",
                    )
                )

        # ==================================
        # 3. COMPLETE BATCH DECISION
        # ==================================

        statuses = {
            item["status"]
            for item in results
        }

        # Rejected tiene precedencia.
        if "rejected" in statuses:
            overall_status = "rejected"

        elif "review_required" in statuses:
            overall_status = "review_required"

        else:
            overall_status = "approved"

        # ==================================
        # 4. NO PARTIAL SIGNATURES
        # ==================================

        if overall_status != "approved":

            return {
                "status": overall_status,
                "attestation": None,
                "files": results,
            }

        if len(approved_analyses) != len(
            request.files
        ):
            raise ValueError(
                "Cobertura del lote inconsistente"
            )

        # ==================================
        # 5. POLICY TOCTOU CHECK
        # ==================================

        policy_after = (
            get_trusted_policy_sha256()
        )

        if policy_before != policy_after:
            raise ValueError(
                "La politica cambio "
                "durante el analisis"
            )

        # ==================================
        # 6. TRUSTED CONFIGURATION
        # ==================================

        repository = os.environ[
            "APPSEC_REPOSITORY"
        ].strip()

        key_id = os.environ[
            "APPSEC_SIGNING_KEY_ID"
        ].strip()

        key_path = Path(
            os.environ[
                "APPSEC_SIGNING_KEY_PATH"
            ]
        )

        private_key = (
            load_signing_private_key(
                key_path
            )
        )

        # ==================================
        # 7. ISSUE SIGNED MANIFEST
        # ==================================

        attestation = issue_signed_manifest(
            subject=user["sub"],
            repository=repository,
            git_tree_oid=request.git_tree_oid,
            parent_oid=request.parent_oid,
            policy_sha256=policy_before,
            model_id=OLLAMA_MODEL,
            analyses=approved_analyses,
            private_key=private_key,
            key_id=key_id,
        )

        # No escribir el JWT, la clave
        # privada ni la firma en logs.
        logger.info(
            "Manifiesto firmado emitido "
            "para %d archivos",
            len(approved_analyses),
        )

        # ==================================
        # 8. API RESPONSE
        # ==================================

        return {
            "status": "approved",
            "attestation": attestation,
            "files": results,
        }

    except Exception:

        logger.exception(
            "Error en el analisis de lote"
        )

        # Fail-closed.
        # No retornar firmas parciales.
        raise HTTPException(
            status_code=503,
            detail=(
                "No se pudo completar el "
                "analisis firmado. "
                "No se emite aprobacion."
            ),
        )
