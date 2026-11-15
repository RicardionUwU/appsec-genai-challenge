
"""
MercadoLibre AppSec GenAI Challenge

API server-side de analisis de seguridad.

Motores:
- Semgrep (SAST)
- Ollama / Qwen2.5-Coder 7B (LLM)
- Policy Engine

Controles de seguridad:
- Auth0 OAuth 2.0 / OIDC
- JWT Authentication
- RBAC Authorization
- Content Security Policy
- HTTP Strict Transport Security
- Clickjacking Protection
- MIME Sniffing Protection
- Referrer Policy
- Permissions Policy
- Cache Control
"""

import asyncio
import hashlib
import logging
import os

from fastapi import (
    Depends,
    FastAPI,
    HTTPException,
    Request,
)

from pydantic import BaseModel, Field

from backend.analyzer import analyze_with_ai
from backend.semgrep_analyzer import analyze_with_semgrep
from backend.policy_engine import decide

from backend.auth import (
    require_analyze_permission,
    require_review_permission,
)


# ==========================================
# LOGGING AND CONFIGURATION
# ==========================================

logger = logging.getLogger(__name__)

APP_ENV = os.getenv(
    "APP_ENV",
    "development"
).strip().lower()


# ==========================================
# FASTAPI APPLICATION
# ==========================================

app = FastAPI(
    title="AppSec GenAI Security Analyzer",
    description=(
        "Analisis hibrido de seguridad OWASP "
        "con Semgrep, Ollama y Auth0."
    ),
    version="1.4.0",
)


# ==========================================
# SECURITY HEADERS CONFIGURATION
# ==========================================

API_CSP = (
    "default-src 'none'; "
    "base-uri 'none'; "
    "frame-ancestors 'none'; "
    "form-action 'none'"
)

# Swagger utiliza recursos externos e
# inicializacion JavaScript inline.
#
# Temporalmente protegemos contra framing.
# Esta no es una CSP completa para Swagger.

SWAGGER_CSP = "frame-ancestors 'none'"

DOCUMENTATION_PATHS = {
    "/docs",
    "/redoc",
    "/docs/oauth2-redirect",
}

SENSITIVE_PATHS = {
    "/analyze",
    "/auth/me",
    "/reviews",
}


# ==========================================
# SECURITY HEADERS MIDDLEWARE
# ==========================================

@app.middleware("http")
async def security_headers_middleware(
    request: Request,
    call_next,
):
    """
    Aplica cabeceras HTTP de seguridad.

    HSTS se habilita exclusivamente cuando
    la aplicacion trabaja bajo HTTPS en
    modo produccion.
    """

    response = await call_next(request)

    # MIME sniffing protection
    response.headers[
        "X-Content-Type-Options"
    ] = "nosniff"

    # Clickjacking protection
    response.headers[
        "X-Frame-Options"
    ] = "DENY"

    # Referrer protection
    response.headers[
        "Referrer-Policy"
    ] = "no-referrer"

    # Browser feature restrictions
    response.headers[
        "Permissions-Policy"
    ] = (
        "camera=(), "
        "microphone=(), "
        "geolocation=(), "
        "payment=()"
    )

    # Content Security Policy
    if request.url.path in DOCUMENTATION_PATHS:
        response.headers[
            "Content-Security-Policy"
        ] = SWAGGER_CSP
    else:
        response.headers[
            "Content-Security-Policy"
        ] = API_CSP

    # Sensitive data cache protection
    if request.url.path in SENSITIVE_PATHS:
        response.headers[
            "Cache-Control"
        ] = "no-store"

        response.headers[
            "Pragma"
        ] = "no-cache"

    # HSTS - HTTPS production only
    if (
        APP_ENV == "production"
        and request.url.scheme == "https"
    ):
        response.headers[
            "Strict-Transport-Security"
        ] = "max-age=31536000"

    return response


# ==========================================
# REQUEST SCHEMA
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
# HEALTH CHECK
# ==========================================

@app.get(
    "/health",
    tags=["System"],
)
def health():
    """
    Public health check.

    Does not disclose configuration,
    credentials or internal components.
    """

    return {
        "status": "healthy"
    }


# ==========================================
# AUTHENTICATION - CURRENT USER
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
    Requires a valid Auth0 access token
    with analyze:code permission.
    """

    return {
        "authenticated": True,
        "subject": user["sub"],
        "permissions": user.get(
            "permissions", []
        ),
    }


# ==========================================
# SECURITY REVIEW - RESERVED ENDPOINT
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
            )
        }
    },
)
async def create_review(
    user: dict = Depends(
        require_review_permission
    ),
):
    """
    Requires review:findings permission.

    The approval workflow is intentionally
    unavailable until server-side review,
    audit logging and integrity validation
    are implemented.

    Never issue an automatic approval.
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
# SECURITY ANALYSIS ENDPOINT
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
    Protected security analysis endpoint.

    Requirements:
    - Valid Auth0 access token
    - Authorized OAuth client
    - analyze:code permission

    Runs:
    - Semgrep
    - Ollama / Qwen 7B
    - Policy Engine

    Fails closed on analysis errors.
    """

    try:

        # ==================================
        # 1. CALCULATE CONTENT HASH
        # ==================================

        code_hash = hashlib.sha256(
            request.code.encode("utf-8")
        ).hexdigest()

        # ==================================
        # 2. SEMGREP STATIC ANALYSIS
        # ==================================

        semgrep_result = await asyncio.to_thread(
            analyze_with_semgrep,
            request.filename,
            request.code,
        )

        # ==================================
        # 3. OLLAMA / QWEN ANALYSIS
        # ==================================

        ai_result = await analyze_with_ai(
            filename=request.filename,
            code=request.code,
        )

        # ==================================
        # 4. ANALYSIS INTEGRITY CHECK
        # ==================================

        if ai_result.get("sha256") != code_hash:
            raise ValueError(
                "Inconsistencia en hash de analisis"
            )

        # ==================================
        # 5. POLICY ENGINE
        # ==================================

        decision = decide(
            semgrep_result,
            ai_result,
        )

        # ==================================
        # 6. STRUCTURED API RESPONSE
        # ==================================

        return {
            "filename": request.filename,
            "status": decision["status"],
            "sha256": code_hash,
            "model": ai_result.get("model"),

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
                }
            }
        }

    except Exception:

        logger.exception(
            "Error durante el analisis de seguridad"
        )

        # Fail-closed:
        # Never issue security approval
        # when analysis fails.

        raise HTTPException(
            status_code=503,
            detail=(
                "No se pudo completar el analisis. "
                "No se emite aprobacion de seguridad."
            ),
        )
