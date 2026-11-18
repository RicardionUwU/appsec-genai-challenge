
"""
AppSec GenAI - Signed Git Analysis Manifests

Security properties:
- Ed25519 signatures.
- Strict Pydantic validation.
- Deterministic canonical JSON.
- Domain-separated signatures.
- Explicit trusted-key selection.
- Full set of approved analyzed files.
- Git tree and parent commit binding.
- Repository and Auth0 subject binding.
- Policy fingerprint binding.
- Expiration and unique receipt IDs.
- Exact remote-content verification.
- Fail-closed behavior.

TRUST MODEL:
- The developer and local Git repository are untrusted.
- The signing service must control its private key.
- GitHub must independently obtain commit contents.
- The trusted verifier must not come from an
  unreviewed pull-request modification.

IMPORTANT:
This module provides cryptographic primitives.
It does not by itself enforce GitHub branch protection,
prevent all replay, or prove the AI found every issue.
"""

import base64
import hashlib
import json
import os
import re
import time
import uuid

from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Literal, Mapping, Sequence

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)


# ==========================================
# SECURITY CONSTANTS
# ==========================================

SCHEMA_VERSION = 1

MANIFEST_TYPE = "appsec-git-manifest"
MANIFEST_AUDIENCE = "appsec-github-verifier"

PROTECTED_HEADER_TYPE = (
    "appsec-git-manifest-v1"
)

SIGNATURE_DOMAIN = (
    b"APPSEC-GENAI-MANIFEST-V1\x00"
)

MAX_FILES = 128
MAX_FILE_BYTES = 90000
MAX_TOTAL_BYTES = 8_000_000

MAX_TOKEN_BYTES = 200000

MAX_TTL_SECONDS = 86400
CLOCK_SKEW_SECONDS = 60

SHA256_PATTERN = r"^[0-9a-f]{64}$"
GIT_OID_PATTERN = (
    r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$"
)

KID_PATTERN = r"^[A-Za-z0-9_-]{1,64}$"
REPO_PATTERN = (
    r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$"
)

B64URL_PATTERN = re.compile(
    r"^[A-Za-z0-9_-]+$"
)


# ==========================================
# INPUT REPRESENTATION
# ==========================================

@dataclass(frozen=True, slots=True)
class ApprovedAnalysis:
    """
    Resultado interno del backend.

    IMPORTANTE:
    Este objeto debe construirse solamente
    con datos realmente analizados por
    Semgrep, Qwen y el Policy Engine.

    No aceptar objetos ApprovedAnalysis
    directamente desde una solicitud HTTP.
    """

    path: str
    content: bytes
    mode: str
    status: str


# ==========================================
# STRICT DATA MODELS
# ==========================================

class StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        strict=True,
    )


class FileRecord(StrictModel):

    path: str = Field(
        min_length=1,
        max_length=1024,
    )

    mode: Literal[
        "100644",
        "100755",
    ]

    sha256: str = Field(
        pattern=SHA256_PATTERN,
    )

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str):

        if (
            value.startswith("/")
            or "\\" in value
            or ":" in value
            or "//" in value
            or "\x00" in value
        ):
            raise ValueError(
                "Ruta Git invalida"
            )

        if any(
            ord(character) < 32
            or ord(character) == 127
            for character in value
        ):
            raise ValueError(
                "Caracter de control en ruta"
            )

        path = PurePosixPath(value)

        if (
            path.is_absolute()
            or path.as_posix() != value
            or any(
                part in (".", "..", ".git")
                for part in value.split("/")
            )
        ):
            raise ValueError(
                "Ruta Git no canonica"
            )

        return value


class AnalysisManifest(StrictModel):

    version: Literal[1] = SCHEMA_VERSION

    kind: Literal[
        "appsec-git-manifest"
    ] = MANIFEST_TYPE

    audience: Literal[
        "appsec-github-verifier"
    ] = MANIFEST_AUDIENCE

    receipt_id: str = Field(
        pattern=r"^[0-9a-f]{32}$",
    )

    repository: str = Field(
        pattern=REPO_PATTERN,
    )

    subject: str = Field(
        min_length=1,
        max_length=256,
    )

    git_tree_oid: str

    parent_oid: str | None

    policy_sha256: str = Field(
        pattern=SHA256_PATTERN,
    )

    model_id: str = Field(
        min_length=1,
        max_length=128,
    )

    decision: Literal[
        "approved"
    ] = "approved"

    files: list[FileRecord] = Field(
        min_length=1,
        max_length=MAX_FILES,
    )

    issued_at: int
    expires_at: int

    @field_validator("subject", "model_id")
    @classmethod
    def validate_nonblank(cls, value: str):

        if not value.strip():
            raise ValueError(
                "Campo obligatorio vacio"
            )

        return value

    @field_validator("git_tree_oid")
    @classmethod
    def validate_tree_oid(cls, value: str):

        if not re.fullmatch(
            GIT_OID_PATTERN,
            value,
        ):
            raise ValueError(
                "Git tree OID invalido"
            )

        return value

    @field_validator("parent_oid")
    @classmethod
    def validate_parent_oid(
        cls,
        value: str | None,
    ):

        if value is not None and not re.fullmatch(
            GIT_OID_PATTERN,
            value,
        ):
            raise ValueError(
                "Git parent OID invalido"
            )

        return value

    @model_validator(mode="after")
    def validate_manifest(self):

        # Parent y tree deben utilizar
        # el mismo formato de Git OID.
        if (
            self.parent_oid is not None
            and len(self.parent_oid)
            != len(self.git_tree_oid)
        ):
            raise ValueError(
                "Formato Git inconsistente"
            )

        paths = [
            record.path
            for record in self.files
        ]

        # Orden determinista.
        if paths != sorted(paths):
            raise ValueError(
                "Archivos sin orden canonico"
            )

        # Rechazar duplicados exactos y
        # diferencias solo de mayusculas.
        normalized = [
            path.casefold()
            for path in paths
        ]

        if len(normalized) != len(
            set(normalized)
        ):
            raise ValueError(
                "Rutas duplicadas o ambiguas"
            )

        ttl = (
            self.expires_at
            - self.issued_at
        )

        if (
            ttl <= 0
            or ttl > MAX_TTL_SECONDS
        ):
            raise ValueError(
                "Periodo de validez invalido"
            )

        return self


# ==========================================
# CANONICAL SERIALIZATION
# ==========================================

def canonical_json(value: dict) -> bytes:

    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def b64url_encode(value: bytes) -> str:

    return (
        base64.urlsafe_b64encode(value)
        .rstrip(b"=")
        .decode("ascii")
    )


def b64url_decode(value: str) -> bytes:

    if not isinstance(value, str):
        raise ValueError(
            "Base64URL invalido"
        )

    if not B64URL_PATTERN.fullmatch(value):
        raise ValueError(
            "Caracteres Base64URL invalidos"
        )

    padding = "=" * (
        -len(value) % 4
    )

    decoded = base64.b64decode(
        value + padding,
        altchars=b"-_",
        validate=True,
    )

    # Rechaza codificaciones alternativas
    # no canonicas del mismo contenido.
    if b64url_encode(decoded) != value:
        raise ValueError(
            "Base64URL no canonico"
        )

    return decoded


# ==========================================
# POLICY FINGERPRINT
# ==========================================

def compute_policy_sha256(
    trusted_files: Mapping[str, bytes],
) -> str:
    """
    Calcula una huella reproducible de
    las reglas y componentes de seguridad.

    Los archivos deben provenir del despliegue
    del servidor confiable, no de un directorio
    enviado por el desarrollador.
    """

    if not trusted_files:
        raise ValueError(
            "Politica de seguridad vacia"
        )

    digest = hashlib.sha256()

    digest.update(
        b"APPSEC-POLICY-V1\x00"
    )

    for name in sorted(trusted_files):

        content = trusted_files[name]

        if not isinstance(name, str):
            raise ValueError(
                "Nombre de politica invalido"
            )

        if not isinstance(content, bytes):
            raise ValueError(
                "Contenido de politica invalido"
            )

        name_bytes = name.encode("utf-8")

        digest.update(
            len(name_bytes).to_bytes(
                4, "big"
            )
        )

        digest.update(name_bytes)

        digest.update(
            len(content).to_bytes(
                8, "big"
            )
        )

        digest.update(content)

    return digest.hexdigest()


# ==========================================
# SERVER-SIDE FILE RECORDS
# ==========================================

def build_file_records(
    analyses: Sequence[ApprovedAnalysis],
) -> list[FileRecord]:
    """
    Genera hashes sobre los bytes exactos
    recibidos y analizados por el servidor.

    No acepta hashes ni decisiones
    proporcionados directamente por el cliente.
    """

    if not (
        1 <= len(analyses) <= MAX_FILES
    ):
        raise ValueError(
            "Cantidad de archivos invalida"
        )

    records = []
    total_bytes = 0

    for analysis in analyses:

        if not isinstance(
            analysis,
            ApprovedAnalysis,
        ):
            raise TypeError(
                "Registro de analisis invalido"
            )

        if analysis.status != "approved":
            raise ValueError(
                "No se puede firmar un "
                "analisis no aprobado"
            )

        if not isinstance(
            analysis.content,
            bytes,
        ):
            raise ValueError(
                "Contenido no binario"
            )

        if (
            len(analysis.content)
            > MAX_FILE_BYTES
        ):
            raise ValueError(
                "Archivo excede limite"
            )

        total_bytes += len(
            analysis.content
        )

        if total_bytes > MAX_TOTAL_BYTES:
            raise ValueError(
                "Conjunto de archivos demasiado grande"
            )

        records.append(
            FileRecord(
                path=analysis.path,
                mode=analysis.mode,
                sha256=hashlib.sha256(
                    analysis.content
                ).hexdigest(),
            )
        )

    return sorted(
        records,
        key=lambda record: record.path,
    )


# ==========================================
# PRIVATE KEY MANAGEMENT
# ==========================================

def load_signing_private_key(
    path: Path,
) -> Ed25519PrivateKey:
    """
    Carga una clave privada preexistente.

    No genera claves automaticamente.
    No permite ubicarlas dentro de un
    repositorio Git detectado.
    """

    path = Path(path).expanduser()

    if not path.is_absolute():
        raise ValueError(
            "La ruta de la clave debe ser absoluta"
        )

    resolved = path.resolve(
        strict=True
    )

    if not resolved.is_file():
        raise ValueError(
            "La clave no es un archivo"
        )

    # Barrera para evitar almacenar
    # accidentalmente la clave dentro
    # de un repositorio Git.
    for directory in resolved.parents:
        if (
            directory / ".git"
        ).exists():
            raise ValueError(
                "Clave privada dentro de Git"
            )

    private_key = (
        serialization.load_pem_private_key(
            resolved.read_bytes(),
            password=None,
        )
    )

    if not isinstance(
        private_key,
        Ed25519PrivateKey,
    ):
        raise TypeError(
            "Se requiere clave Ed25519"
        )

    return private_key


# ==========================================
# SIGNED MANIFEST ISSUANCE
# ==========================================

def issue_signed_manifest(
    *,
    subject: str,
    repository: str,
    git_tree_oid: str,
    parent_oid: str | None,
    policy_sha256: str,
    model_id: str,
    analyses: Sequence[ApprovedAnalysis],
    private_key: Ed25519PrivateKey,
    key_id: str,
    ttl_seconds: int = MAX_TTL_SECONDS,
) -> str:
    """
    Emite un manifiesto firmado.

    PRECONDICIONES DEL CALLER:
    - Auth0 validado.
    - Subject obtenido del JWT validado.
    - Todos los archivos analizados.
    - Todas las decisiones calculadas
      por el servidor y aprobadas.
    - Repositorio y politica definidos
      por configuracion confiable.

    tree_oid y parent_oid pueden proceder
    del cliente, pero NO deben considerarse
    verificados hasta que GitHub compare
    sus valores con el commit real.
    """

    if not isinstance(
        private_key,
        Ed25519PrivateKey,
    ):
        raise TypeError(
            "Firmante Ed25519 invalido"
        )

    if not re.fullmatch(
        KID_PATTERN,
        key_id,
    ):
        raise ValueError(
            "Identificador de clave invalido"
        )

    if (
        type(ttl_seconds) is not int
        or not (
            1 <= ttl_seconds <= MAX_TTL_SECONDS
        )
    ):
        raise ValueError(
            "TTL invalido"
        )

    records = build_file_records(
        analyses
    )

    now = int(time.time())

    manifest = AnalysisManifest(
        receipt_id=uuid.uuid4().hex,
        repository=repository,
        subject=subject,
        git_tree_oid=git_tree_oid,
        parent_oid=parent_oid,
        policy_sha256=policy_sha256,
        model_id=model_id,
        files=records,
        issued_at=now,
        expires_at=now + ttl_seconds,
    )

    payload = canonical_json(
        manifest.model_dump(
            mode="json"
        )
    )

    protected_header = canonical_json({
        "alg": "EdDSA",
        "typ": PROTECTED_HEADER_TYPE,
        "kid": key_id,
    })

    signing_input = (
        b64url_encode(
            protected_header
        )
        + "."
        + b64url_encode(payload)
    ).encode("ascii")

    signature = private_key.sign(
        SIGNATURE_DOMAIN
        + signing_input
    )

    return (
        signing_input.decode("ascii")
        + "."
        + b64url_encode(signature)
    )


# ==========================================
# INDEPENDENT VERIFICATION
# ==========================================

def verify_signed_manifest(
    token: str,
    *,
    trusted_public_keys: Mapping[
        str,
        Ed25519PublicKey,
    ],
    expected_repository: str,
    expected_tree_oid: str,
    expected_parent_oid: str | None,
    expected_policy_sha256: str,
    expected_files: Mapping[
        str,
        tuple[str, bytes],
    ],
) -> AnalysisManifest:
    """
    Verifica una constancia contra datos
    obtenidos independientemente del commit.

    expected_files:
        {
            "src/app.py": (
                "100644",
                b"contenido REAL de Git"
            )
        }

    CRITICO:
    El verificador debe obtener expected_files,
    expected_tree_oid y expected_parent_oid
    desde el commit remoto verdadero.

    Nunca debe aceptar esos valores desde
    el manifiesto que esta verificando.
    """

    if not isinstance(token, str):
        raise ValueError(
            "Token invalido"
        )

    if len(token) > MAX_TOKEN_BYTES:
        raise ValueError(
            "Token demasiado grande"
        )

    parts = token.split(".")

    if len(parts) != 3:
        raise ValueError(
            "Formato de firma invalido"
        )

    header_bytes = b64url_decode(
        parts[0]
    )

    payload_bytes = b64url_decode(
        parts[1]
    )

    signature = b64url_decode(
        parts[2]
    )

    if len(signature) != 64:
        raise ValueError(
            "Longitud de firma invalida"
        )

    header = json.loads(
        header_bytes
    )

    if not isinstance(header, dict):
        raise ValueError(
            "Header invalido"
        )

    key_id = header.get("kid")

    if (
        not isinstance(key_id, str)
        or not re.fullmatch(
            KID_PATTERN,
            key_id,
        )
    ):
        raise ValueError(
            "Identificador de clave invalido"
        )

    if header != {
        "alg": "EdDSA",
        "typ": PROTECTED_HEADER_TYPE,
        "kid": key_id,
    }:
        raise ValueError(
            "Algoritmo o header no autorizado"
        )

    if canonical_json(
        header
    ) != header_bytes:
        raise ValueError(
            "Header no canonico"
        )

    # La clave se selecciona exclusivamente
    # de una lista confiable del verificador.
    public_key = trusted_public_keys.get(
        key_id
    )

    if not isinstance(
        public_key,
        Ed25519PublicKey,
    ):
        raise ValueError(
            "Clave publica no confiable"
        )

    signing_input = (
        parts[0]
        + "."
        + parts[1]
    ).encode("ascii")

    # Firma invalida: lanza InvalidSignature.
    public_key.verify(
        signature,
        SIGNATURE_DOMAIN
        + signing_input,
    )

    # Solo interpretar el manifiesto
    # DESPUES de verificar la firma.
    manifest = (
        AnalysisManifest.model_validate_json(
            payload_bytes
        )
    )

    if canonical_json(
        manifest.model_dump(
            mode="json"
        )
    ) != payload_bytes:
        raise ValueError(
            "Manifest no canonico"
        )

    # ======================================
    # VERIFY PURPOSE AND REPOSITORY
    # ======================================

    if (
        manifest.repository
        != expected_repository
    ):
        raise ValueError(
            "Repositorio incorrecto"
        )

    if (
        manifest.git_tree_oid
        != expected_tree_oid
    ):
        raise ValueError(
            "Git tree diferente al analizado"
        )

    if (
        manifest.parent_oid
        != expected_parent_oid
    ):
        raise ValueError(
            "Commit padre diferente"
        )

    if (
        manifest.policy_sha256
        != expected_policy_sha256
    ):
        raise ValueError(
            "Version de politica no autorizada"
        )

    # ======================================
    # VERIFY TIME WINDOW
    # ======================================

    now = int(time.time())

    if (
        manifest.issued_at
        > now + CLOCK_SKEW_SECONDS
    ):
        raise ValueError(
            "Constancia emitida en el futuro"
        )

    if manifest.expires_at <= now:
        raise ValueError(
            "Constancia expirada"
        )

    # ======================================
    # RECONSTRUCT REAL FILE RECORDS
    # ======================================

    if not (
        1 <= len(expected_files) <= MAX_FILES
    ):
        raise ValueError(
            "Cantidad remota de archivos invalida"
        )

    actual_records = []
    total_bytes = 0

    for path, (
        mode,
        content,
    ) in expected_files.items():

        if not isinstance(content, bytes):
            raise ValueError(
                "Contenido remoto invalido"
            )

        if len(content) > MAX_FILE_BYTES:
            raise ValueError(
                "Archivo remoto demasiado grande"
            )

        total_bytes += len(content)

        if total_bytes > MAX_TOTAL_BYTES:
            raise ValueError(
                "Contenido remoto demasiado grande"
            )

        actual_records.append(
            FileRecord(
                path=path,
                mode=mode,
                sha256=hashlib.sha256(
                    content
                ).hexdigest(),
            )
        )

    actual_records = sorted(
        actual_records,
        key=lambda record: record.path,
    )

    # Comparacion del CONJUNTO COMPLETO.
    #
    # Detecta:
    # - Archivos agregados sin analizar.
    # - Archivos omitidos.
    # - Contenido modificado.
    # - Cambios de modo.
    # - Rutas diferentes.
    if manifest.files != actual_records:
        raise ValueError(
            "Los archivos remotos no coinciden "
            "con el analisis aprobado"
        )

    return manifest
