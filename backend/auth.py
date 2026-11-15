
"""
AppSec GenAI - Auth0 Authentication

Validacion de access tokens JWT:
- Firma RS256 mediante JWKS
- Issuer y audience
- Expiracion
- Identidad del desarrollador
- Permisos RBAC
"""

import os

import jwt
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import PyJWKClient


AUTH0_DOMAIN = os.environ["AUTH0_DOMAIN"].strip()
AUTH0_DOMAIN = AUTH0_DOMAIN.removeprefix("https://").rstrip("/")

if (
    not AUTH0_DOMAIN
    or "/" in AUTH0_DOMAIN
    or ":" in AUTH0_DOMAIN
    or AUTH0_DOMAIN.startswith(".")
):
    raise RuntimeError("AUTH0_DOMAIN invalido")

AUTH0_AUDIENCE = os.environ["AUTH0_AUDIENCE"].strip()

if not AUTH0_AUDIENCE:
    raise RuntimeError("AUTH0_AUDIENCE no configurado")

ISSUER = f"https://{AUTH0_DOMAIN}/"
JWKS_URL = f"{ISSUER}.well-known/jwks.json"

security = HTTPBearer(auto_error=False)

jwks_client = PyJWKClient(
    JWKS_URL,
    timeout=5,
)


def unauthorized(message="Invalid access token"):
    return HTTPException(
        status_code=401,
        detail=message,
        headers={"WWW-Authenticate": "Bearer"},
    )


def verify_access_token(
    credentials: HTTPAuthorizationCredentials | None = Depends(security),
):
    if credentials is None:
        raise unauthorized("Bearer token required")

    token = credentials.credentials

    try:
        signing_key = jwks_client.get_signing_key_from_jwt(token)

        payload = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=AUTH0_AUDIENCE,
            issuer=ISSUER,
            leeway=30,
            options={
                "require": [
                    "iss",
                    "sub",
                    "aud",
                    "exp",
                    "iat",
                ]
            },
        )

        subject = payload.get("sub")

        if not isinstance(subject, str) or not subject:
            raise unauthorized("Invalid token subject")

        return payload

    except jwt.PyJWKClientConnectionError:
        raise HTTPException(
            status_code=503,
            detail="Identity provider unavailable",
        )

    except jwt.PyJWTError:
        raise unauthorized()


def require_analyze_permission(
    payload: dict = Depends(verify_access_token),
):
    permissions = payload.get("permissions", [])

    if (
        not isinstance(permissions, list)
        or "analyze:code" not in permissions
    ):
        raise HTTPException(
            status_code=403,
            detail="Insufficient permissions",
        )

    return payload


# ==========================================
# AUTHORIZATION - APPSEC REVIEWER
# ==========================================

def require_review_permission(
    payload: dict = Depends(verify_access_token),
):
    """
    Autoriza exclusivamente usuarios que
    tengan el permiso review:findings.

    El JWT se valida previamente mediante
    verify_access_token.

    Retorna:
        401: Token ausente o invalido.
        403: Permisos insuficientes.
        payload: Usuario autorizado.
    """

    permissions = payload.get("permissions", [])

    if (
        not isinstance(permissions, list)
        or "review:findings" not in permissions
    ):
        raise HTTPException(
            status_code=403,
            detail="Insufficient permissions",
        )

    return payload
