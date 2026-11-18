
"""
AppSec GenAI - Secure Native OAuth Client

Referencias:
- RFC 7636: PKCE
- RFC 8252: OAuth for Native Apps
- RFC 9700: OAuth Security BCP
- OpenID Connect Core
- OWASP ASVS

Controles:
- Authorization Code + PKCE S256
- State y nonce criptograficamente aleatorios
- Callback exclusivo en loopback
- Validacion criptografica del ID token
- Validacion de identidad y permisos por FastAPI
- Windows Credential Manager
- Apertura explicita de Google Chrome
- Fail-closed
"""

import argparse
import base64
import hashlib
import json
import os
import re
import secrets
import socket
import subprocess
import sys
import time

from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit

import httpx
import jwt
import keyring

from dotenv import load_dotenv
from jwt import PyJWKClient


# ==========================================
# CONSTANTES
# ==========================================

ROOT = Path(__file__).resolve().parent.parent

load_dotenv(ROOT / ".env", override=False)

CALLBACK_HOST = "127.0.0.1"
CALLBACK_PORT = 8765
CALLBACK_PATH = "/callback"

REDIRECT_URI = (
    f"http://{CALLBACK_HOST}:"
    f"{CALLBACK_PORT}{CALLBACK_PATH}"
)

API_URL = "http://127.0.0.1:8000"

LOGIN_TIMEOUT = 300
MAX_TOKEN_LIFETIME = 3600
CLOCK_SKEW = 30

KEYRING_SERVICE = "appsec-genai-auth0"

ALLOWED_ALGORITHMS = ["RS256"]


class AuthFlowError(Exception):
    """Error controlado del flujo de autenticacion."""


# ==========================================
# VALIDACION DE CONFIGURACION
# ==========================================

def load_config():

    domain = os.getenv(
        "AUTH0_DOMAIN", ""
    ).strip().lower()

    domain_pattern = (
        r"(?:[a-z0-9]"
        r"(?:[a-z0-9-]{0,61}[a-z0-9])?"
        r"\.)+auth0\.com"
    )

    if not re.fullmatch(domain_pattern, domain):
        raise AuthFlowError(
            "AUTH0_DOMAIN invalido."
        )

    client_id = os.getenv(
        "AUTH0_CLIENT_ID", ""
    ).strip()

    audience = os.getenv(
        "AUTH0_AUDIENCE", ""
    ).strip()

    allowed_clients = {
        value.strip()
        for value in os.getenv(
            "AUTH0_ALLOWED_CLIENT_IDS", ""
        ).split(",")
        if value.strip()
    }

    if (
        not client_id
        or client_id not in allowed_clients
    ):
        raise AuthFlowError(
            "Cliente OAuth no autorizado "
            "en la configuracion local."
        )

    if not audience:
        raise AuthFlowError(
            "AUTH0_AUDIENCE no configurado."
        )

    configured_redirect = os.getenv(
        "AUTH0_REDIRECT_URI",
        REDIRECT_URI,
    ).strip()

    if configured_redirect != REDIRECT_URI:
        raise AuthFlowError(
            "OAuth redirect URI no permitido."
        )

    configured_api = os.getenv(
        "APPSEC_API_URL",
        API_URL,
    ).strip().rstrip("/")

    if configured_api != API_URL:
        raise AuthFlowError(
            "La API local debe utilizar "
            "http://127.0.0.1:8000."
        )

    return {
        "domain": domain,
        "issuer": f"https://{domain}/",
        "client_id": client_id,
        "audience": audience,
        "redirect_uri": REDIRECT_URI,
        "api_url": API_URL,
    }


# ==========================================
# GOOGLE CHROME - WINDOWS
# ==========================================

def find_chrome():
    """
    Localiza Google Chrome en rutas conocidas.

    APPSEC_CHROME_PATH permite indicar
    una ruta explicita si es necesario.

    No utiliza el navegador predeterminado.
    """

    custom_path = os.getenv(
        "APPSEC_CHROME_PATH", ""
    ).strip().strip('"')

    if custom_path:
        candidates = [Path(custom_path)]
    else:
        candidates = []

        for env_name in (
            "PROGRAMFILES",
            "PROGRAMFILES(X86)",
            "LOCALAPPDATA",
        ):
            base = os.getenv(env_name)

            if base:
                candidates.append(
                    Path(base)
                    / "Google"
                    / "Chrome"
                    / "Application"
                    / "chrome.exe"
                )

        candidates.extend([
            Path(
                r"C:\Program Files\Google"
                r"\Chrome\Application\chrome.exe"
            ),
            Path(
                r"C:\Program Files (x86)\Google"
                r"\Chrome\Application\chrome.exe"
            ),
        ])

    for path in candidates:
        if (
            path.is_absolute()
            and path.is_file()
            and path.name.lower() == "chrome.exe"
        ):
            return path

    raise AuthFlowError(
        "Google Chrome no fue encontrado. "
        "Configura APPSEC_CHROME_PATH "
        "con la ruta de chrome.exe."
    )


def open_chrome(authorization_url):
    """
    Ejecuta Chrome directamente.

    No utiliza shell=True.
    No construye comandos de PowerShell.
    No imprime la URL de autorizacion.
    """

    chrome_path = find_chrome()

    parsed = urlsplit(authorization_url)

    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.fragment
    ):
        raise AuthFlowError(
            "URL de autorizacion invalida."
        )

    print("[AUTH] Abriendo Google Chrome...")

    try:
        subprocess.Popen(
            [
                str(chrome_path),
                "--new-window",
                authorization_url,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=False,
        )

    except OSError:
        raise AuthFlowError(
            "No se pudo ejecutar Google Chrome."
        ) from None


# ==========================================
# PKCE S256
# ==========================================

def create_pkce():

    verifier = secrets.token_urlsafe(64)

    digest = hashlib.sha256(
        verifier.encode("ascii")
    ).digest()

    challenge = base64.urlsafe_b64encode(
        digest
    ).decode("ascii").rstrip("=")

    return verifier, challenge


# ==========================================
# AUTHORIZATION REQUEST
# ==========================================

def create_authorization_url(
    config,
    challenge,
    state,
    nonce,
):

    """
    Construye la URL de autorizacion OAuth 2.0.

    Controles:
    - Authorization Code Flow
    - PKCE S256
    - State contra CSRF
    - Nonce para OIDC
    - Audience especifica
    - Reautenticacion mediante Auth0
    """

    params = {
        "response_type": "code",
        "client_id": config["client_id"],
        "redirect_uri": config["redirect_uri"],
        "audience": config["audience"],
        "scope": "openid analyze:code",
        # Solicitar nuevamente autenticacion
        # para evitar reutilizar la sesion
        # anterior del usuario reviewer.
        "prompt": "login",
        # Protecciones OAuth / OIDC
        "state": state,
        "nonce": nonce,
        # PKCE S256
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }

    return (
        config["issuer"]
        + "authorize?"
        + urlencode(params)
    )


# ==========================================
# CALLBACK LOCAL SEGURO
# ==========================================

class SecureCallbackServer(HTTPServer):

    allow_reuse_address = False

    def server_bind(self):

        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            self.socket.setsockopt(
                socket.SOL_SOCKET,
                socket.SO_EXCLUSIVEADDRUSE,
                1,
            )

        super().server_bind()


def receive_code(
    authorization_url,
    expected_state,
    expected_issuer,
):

    result = {}

    class CallbackHandler(BaseHTTPRequestHandler):

        def setup(self):
            # Inicializar primero los atributos
            # internos del socket.
            super().setup()
            # Ahora self.connection ya existe.
            self.connection.settimeout(3)

        def log_message(self, format, *args):
            # No registrar authorization codes.
            pass

        def respond(self, status_code, message):

            body = message.encode("utf-8")

            self.send_response(status_code)

            headers = {
                "Content-Type": (
                    "text/plain; charset=utf-8"
                ),
                "Cache-Control": "no-store",
                "Pragma": "no-cache",
                "Referrer-Policy": "no-referrer",
                "Content-Security-Policy": (
                    "default-src 'none'; "
                    "frame-ancestors 'none'"
                ),
                "X-Frame-Options": "DENY",
                "X-Content-Type-Options": "nosniff",
                "Content-Length": str(len(body)),
                "Connection": "close",
            }

            for name, value in headers.items():
                self.send_header(name, value)

            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):

            hosts = self.headers.get_all(
                "Host", []
            )

            if hosts != [
                f"{CALLBACK_HOST}:{CALLBACK_PORT}"
            ]:
                self.respond(
                    400, "Invalid callback host"
                )
                return

            if len(self.path) > 4096:
                self.respond(
                    414, "Callback too long"
                )
                return

            parsed = urlsplit(self.path)

            if (
                parsed.path != CALLBACK_PATH
                or parsed.fragment
                or parsed.scheme
                or parsed.netloc
            ):
                self.respond(
                    404, "Not found"
                )
                return

            try:
                params = parse_qs(
                    parsed.query,
                    keep_blank_values=True,
                    max_num_fields=16,
                )

            except ValueError:
                self.respond(
                    400, "Invalid callback"
                )
                return

            states = params.get("state", [])

            if (
                len(states) != 1
                or not secrets.compare_digest(
                    states[0],
                    expected_state,
                )
            ):
                self.respond(
                    400, "Invalid OAuth state"
                )
                return

            issuers = params.get("iss", [])

            if (
                len(issuers) > 1
                or (
                    issuers
                    and issuers[0] != expected_issuer
                )
            ):
                self.respond(
                    400, "Invalid issuer"
                )
                return

            if "error" in params:

                result["error"] = (
                    "Authorization rejected by Auth0"
                )

                self.respond(
                    400,
                    "Authentication not completed"
                )
                return

            codes = params.get("code", [])

            if (
                len(codes) != 1
                or not codes[0]
                or len(codes[0]) > 2048
            ):
                self.respond(
                    400,
                    "Invalid authorization code"
                )
                return

            result["code"] = codes[0]

            self.respond(
                200,
                "Authentication callback received. "
                "Return to your terminal."
            )

    try:

        with SecureCallbackServer(
            (CALLBACK_HOST, CALLBACK_PORT),
            CallbackHandler,
        ) as server:

            server.timeout = 0.5

            # Iniciar el servidor ANTES de
            # abrir el navegador.
            open_chrome(authorization_url)

            deadline = (
                time.monotonic() + LOGIN_TIMEOUT
            )

            while (
                "code" not in result
                and "error" not in result
            ):

                if time.monotonic() >= deadline:
                    raise AuthFlowError(
                        "Login timeout."
                    )

                server.handle_request()

    except OSError:
        raise AuthFlowError(
            "Cannot start local OAuth callback server."
        ) from None

    if "error" in result:
        raise AuthFlowError(result["error"])

    return result["code"]


# ==========================================
# TOKEN EXCHANGE
# ==========================================

def exchange_code(
    config,
    code,
    verifier,
):

    token_url = (
        config["issuer"] + "oauth/token"
    )

    data = {
        "grant_type": "authorization_code",
        "client_id": config["client_id"],
        "redirect_uri": config["redirect_uri"],
        "code": code,
        "code_verifier": verifier,
    }

    with httpx.Client(
        timeout=20,
        follow_redirects=False,
        trust_env=False,
    ) as client:

        response = client.post(
            token_url,
            data=data,
        )

    if response.status_code != 200:
        raise AuthFlowError(
            "Auth0 token exchange failed "
            f"(HTTP {response.status_code})."
        )

    try:
        token_data = response.json()

    except ValueError:
        raise AuthFlowError(
            "Invalid Auth0 token response."
        ) from None

    if not isinstance(token_data, dict):
        raise AuthFlowError(
            "Invalid token response format."
        )

    access_token = token_data.get(
        "access_token"
    )

    id_token = token_data.get(
        "id_token"
    )

    token_type = token_data.get(
        "token_type"
    )

    expires_in = token_data.get(
        "expires_in"
    )

    if (
        not isinstance(access_token, str)
        or not access_token
        or len(access_token) > 16384
        or access_token.count(".") != 2
    ):
        raise AuthFlowError(
            "Invalid access token format."
        )

    if (
        not isinstance(id_token, str)
        or not id_token
        or len(id_token) > 16384
        or id_token.count(".") != 2
    ):
        raise AuthFlowError(
            "Missing or invalid OIDC ID token."
        )

    if (
        not isinstance(token_type, str)
        or token_type.lower() != "bearer"
    ):
        raise AuthFlowError(
            "Unexpected token type."
        )

    if (
        type(expires_in) is not int
        or expires_in < 60
        or expires_in > MAX_TOKEN_LIFETIME
    ):
        raise AuthFlowError(
            "Token lifetime exceeds policy. "
            "Configure Auth0 API tokens to "
            "expire within 3600 seconds."
        )

    if "refresh_token" in token_data:
        raise AuthFlowError(
            "Unexpected refresh token returned."
        )

    return access_token, id_token, expires_in


# ==========================================
# VALIDACION CRIPTOGRAFICA DEL ID TOKEN
# ==========================================

def validate_id_token(
    config,
    id_token,
    access_token,
    expected_nonce,
):

    try:

        header = jwt.get_unverified_header(
            id_token
        )

        if header.get("alg") != "RS256":
            raise AuthFlowError(
                "Unexpected JWT algorithm."
            )

        if any(
            field in header
            for field in (
                "jku", "jwk", "x5u", "crit"
            )
        ):
            raise AuthFlowError(
                "Unsupported JWT header."
            )

        kid = header.get("kid")

        if (
            not isinstance(kid, str)
            or not kid
            or len(kid) > 256
        ):
            raise AuthFlowError(
                "Invalid JWT key identifier."
            )

        jwks_client = PyJWKClient(
            config["issuer"]
            + ".well-known/jwks.json",
            timeout=5,
            cache_jwk_set=True,
            lifespan=300,
        )

        signing_key = (
            jwks_client.get_signing_key_from_jwt(
                id_token
            )
        )

        claims = jwt.decode(
            id_token,
            signing_key.key,
            algorithms=ALLOWED_ALGORITHMS,
            audience=config["client_id"],
            issuer=config["issuer"],
            leeway=CLOCK_SKEW,
            options={
                "require": [
                    "iss",
                    "aud",
                    "sub",
                    "exp",
                    "iat",
                    "nonce",
                ]
            },
        )

        nonce = claims.get("nonce")

        if (
            not isinstance(nonce, str)
            or not secrets.compare_digest(
                nonce,
                expected_nonce,
            )
        ):
            raise AuthFlowError(
                "Invalid OIDC nonce."
            )

        subject = claims.get("sub")

        if (
            not isinstance(subject, str)
            or not subject
            or len(subject) > 255
        ):
            raise AuthFlowError(
                "Invalid OIDC subject."
            )

        if subject.endswith("@clients"):
            raise AuthFlowError(
                "Machine identity not allowed."
            )

        azp = claims.get("azp")

        if (
            azp is not None
            and azp != config["client_id"]
        ):
            raise AuthFlowError(
                "Unexpected authorized party."
            )

        audiences = claims.get("aud")

        if (
            isinstance(audiences, list)
            and len(audiences) > 1
            and azp != config["client_id"]
        ):
            raise AuthFlowError(
                "Missing authorized party."
            )

        iat = claims["iat"]
        exp = claims["exp"]

        if (
            type(iat) is not int
            or type(exp) is not int
            or exp <= iat
            or exp - iat > MAX_TOKEN_LIFETIME
        ):
            raise AuthFlowError(
                "Invalid ID token lifetime."
            )

        at_hash = claims.get("at_hash")

        if at_hash is not None:

            digest = hashlib.sha256(
                access_token.encode("ascii")
            ).digest()

            expected_hash = (
                base64.urlsafe_b64encode(
                    digest[:len(digest) // 2]
                )
                .decode("ascii")
                .rstrip("=")
            )

            if (
                not isinstance(at_hash, str)
                or not secrets.compare_digest(
                    at_hash,
                    expected_hash,
                )
            ):
                raise AuthFlowError(
                    "Access token binding failed."
                )

        return claims

    except AuthFlowError:
        raise

    except (
        jwt.PyJWTError,
        ValueError,
        TypeError,
        UnicodeError,
    ):
        raise AuthFlowError(
            "OIDC ID token verification failed."
        ) from None


# ==========================================
# VERIFICACION DE PERMISOS EN FASTAPI
# ==========================================

def validate_with_backend(
    config,
    access_token,
    oidc_subject,
):

    with httpx.Client(
        timeout=20,
        follow_redirects=False,
        trust_env=False,
    ) as client:

        response = client.get(
            config["api_url"] + "/auth/me",
            headers={
                "Authorization": (
                    f"Bearer {access_token}"
                )
            },
        )

    if response.status_code == 401:
        raise AuthFlowError(
            "Access token rejected by FastAPI."
        )

    if response.status_code == 403:
        raise AuthFlowError(
            "User lacks analyze:code permission."
        )

    if response.status_code != 200:
        raise AuthFlowError(
            "FastAPI validation unavailable "
            f"(HTTP {response.status_code})."
        )

    try:
        identity = response.json()

    except ValueError:
        raise AuthFlowError(
            "Invalid FastAPI response."
        ) from None

    if not isinstance(identity, dict):
        raise AuthFlowError(
            "Unexpected API response."
        )

    if identity.get("authenticated") is not True:
        raise AuthFlowError(
            "Authentication not confirmed."
        )

    backend_subject = identity.get("subject")

    if (
        not isinstance(backend_subject, str)
        or not secrets.compare_digest(
            backend_subject,
            oidc_subject,
        )
    ):
        raise AuthFlowError(
            "Token identity mismatch."
        )

    permissions = identity.get("permissions")

    if (
        not isinstance(permissions, list)
        or "analyze:code" not in permissions
    ):
        raise AuthFlowError(
            "Insufficient permissions."
        )

    return identity


# ==========================================
# WINDOWS CREDENTIAL MANAGER
# ==========================================

def credential_account(config):

    return (
        config["domain"]
        + "|"
        + config["client_id"]
        + "|"
        + config["audience"]
    )


def require_secure_keyring():

    if sys.platform != "win32":
        raise AuthFlowError(
            "This client requires Windows "
            "Credential Manager."
        )

    backend = keyring.get_keyring()

    if (
        type(backend).__module__
        != "keyring.backends.Windows"
    ):
        raise AuthFlowError(
            "Secure Windows keyring unavailable."
        )


def save_token(
    config,
    access_token,
    expires_in,
):

    require_secure_keyring()

    account = credential_account(config)

    credential = {
        "access_token": access_token,
        "expires_at": (
            int(time.time())
            + expires_in
            - CLOCK_SKEW
        ),
    }

    keyring.set_password(
        KEYRING_SERVICE,
        account,
        json.dumps(credential),
    )


def logout(config):

    require_secure_keyring()

    account = credential_account(config)

    try:
        keyring.delete_password(
            KEYRING_SERVICE,
            account,
        )

        print(
            "[OK] Local credential deleted."
        )

    except keyring.errors.PasswordDeleteError:
        print(
            "[INFO] No local credential found."
        )


# ==========================================
# FLUJO PRINCIPAL DE LOGIN
# ==========================================

def login():

    config = load_config()

    verifier, challenge = create_pkce()

    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)

    authorization_url = create_authorization_url(
        config,
        challenge,
        state,
        nonce,
    )

    print("[AUTH] OAuth 2.0 Authorization Code")
    print("[AUTH] PKCE S256 enabled")
    print("[AUTH] OIDC nonce validation enabled")
    print("[AUTH] Browser: Google Chrome")

    code = receive_code(
        authorization_url,
        state,
        config["issuer"],
    )

    print("[AUTH] Authorization code received")

    access_token, id_token, expires_in = (
        exchange_code(
            config,
            code,
            verifier,
        )
    )

    print("[AUTH] Validating OIDC ID token")

    claims = validate_id_token(
        config,
        id_token,
        access_token,
        nonce,
    )

    print("[AUTH] Validating API authorization")

    identity = validate_with_backend(
        config,
        access_token,
        claims["sub"],
    )

    # Solo guardar despues de verificar.
    save_token(
        config,
        access_token,
        expires_in,
    )

    print("[OK] Authentication successful")
    print("[OK] OIDC identity validated")
    print("[OK] FastAPI authorization validated")
    print("[OK] Credential stored securely")

    print(
        "[USER] Permissions:",
        ", ".join(identity["permissions"])
    )

    print(
        "[TOKEN] Lifetime:",
        expires_in,
        "seconds"
    )


# ==========================================
# CLI
# ==========================================

def main():

    parser = argparse.ArgumentParser(
        description=(
            "Secure Auth0 login for AppSec GenAI"
        )
    )

    parser.add_argument(
        "action",
        nargs="?",
        choices=["login", "logout"],
        default="login",
    )

    args = parser.parse_args()

    try:

        if args.action == "logout":
            logout(load_config())
        else:
            login()

    except AuthFlowError as exc:

        print(f"[ERROR] {exc}")

        raise SystemExit(1) from None

    except Exception:

        # No mostrar tokens, codigos OAuth
        # ni respuestas sensibles de Auth0.
        print(
            "[ERROR] Secure authentication "
            "could not be completed."
        )

        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
