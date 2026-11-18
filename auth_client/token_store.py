
"""
AppSec GenAI - Secure Token Store

Recuperacion de access tokens OAuth desde
Windows Credential Manager.

Controles:
- No almacenar tokens en archivos
- No imprimir credenciales
- Validar formato y expiracion
- No renovar tokens automaticamente
- Fail-closed
"""

import json
import time

import keyring

from auth_client.login import (
    AuthFlowError,
    KEYRING_SERVICE,
    credential_account,
    load_config,
    require_secure_keyring,
)


class TokenUnavailable(Exception):
    """La credencial no esta disponible o es invalida."""


def get_access_token() -> str:
    """
    Recupera el access token de la sesion
    local autenticada con Auth0.

    No devuelve tokens expirados.
    No escribe secretos en stdout.
    """

    try:
        config = load_config()

        # Comprobar almacenamiento seguro.
        require_secure_keyring()

        account = credential_account(config)

        stored = keyring.get_password(
            KEYRING_SERVICE,
            account,
        )

    except (
        AuthFlowError,
        keyring.errors.KeyringError,
    ):
        raise TokenUnavailable(
            "No se pudo acceder al almacen "
            "seguro de credenciales."
        ) from None

    if not stored:
        raise TokenUnavailable(
            "No hay una sesion Auth0 guardada. "
            "Ejecuta: python -m auth_client.login"
        )

    if len(stored) > 32768:
        raise TokenUnavailable(
            "Credencial almacenada invalida."
        )

    try:
        credential = json.loads(stored)
    except (ValueError, TypeError):
        raise TokenUnavailable(
            "Formato de credencial invalido."
        ) from None

    if not isinstance(credential, dict):
        raise TokenUnavailable(
            "Formato de credencial invalido."
        )

    access_token = credential.get(
        "access_token"
    )

    expires_at = credential.get(
        "expires_at"
    )

    # Validar formato basico.
    # La firma del JWT sera comprobada
    # obligatoriamente por FastAPI.
    if (
        not isinstance(access_token, str)
        or not access_token
        or not access_token.isascii()
        or len(access_token) > 16384
        or access_token.count(".") != 2
    ):
        raise TokenUnavailable(
            "Access token almacenado invalido."
        )

    if type(expires_at) is not int:
        raise TokenUnavailable(
            "Expiracion del token invalida."
        )

    # Margen adicional para evitar enviar
    # tokens cercanos a su expiracion.
    if time.time() + 15 >= expires_at:
        raise TokenUnavailable(
            "La sesion Auth0 ha expirado. "
            "Ejecuta: python -m auth_client.login"
        )

    return access_token
