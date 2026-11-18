
"""
AppSec GenAI - Independent Git Commit Verifier

Modelo de confianza:
- No confiar en el desarrollador.
- No confiar en el repositorio local.
- Obtener archivos del commit Git real.
- Verificar firmas Ed25519 con claves autorizadas.
- Exigir cobertura completa del codigo Python modificado.
- Rechazar cambios de controles de seguridad protegidos.
- Verificar todos los commits del rango solicitado.
- Fallar de forma segura ante cualquier inconsistencia.

IMPORTANTE:
El verificador debe ejecutarse desde codigo confiable.
La proteccion de ramas de GitHub se configura aparte.
"""

import argparse
import binascii
import re
import subprocess
import sys

from pathlib import Path, PurePosixPath
from typing import Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey,
)

from backend.attestations import (
    MAX_FILE_BYTES,
    MAX_FILES,
    verify_signed_manifest,
)


# ==========================================
# CONSTANTES DE SEGURIDAD
# ==========================================

GIT_OID_RE = re.compile(
    r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z"
)

SHA256_RE = re.compile(
    r"[0-9a-f]{64}\Z"
)

ATTESTATION_PREFIX = "AppSec-Attestation: "

MAX_COMMIT_MESSAGE_BYTES = 250000

# Lenguajes y formatos ejecutables
# que todavia no tienen cobertura
# autorizada en nuestro analizador.
UNSUPPORTED_SOURCE_EXTENSIONS = {
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".go",
    ".java",
    ".rb",
    ".php",
    ".sh",
    ".ps1",
    ".bat",
    ".cmd",
    ".cs",
    ".rs",
    ".kt",
    ".ipynb",
    ".pyd",
    ".so",
    ".dll",
    ".exe",
    ".jar",
    ".wasm",
}

# Estos componentes requieren un flujo
# privilegiado de cambios.
#
# Un developer ordinario no puede
# cambiarlos en el flujo regular.
PROTECTED_PREFIXES = (
    ".github/",
    "rules/",
    "hooks/",
    "scripts/",
    "backend/prompts/",
)

PROTECTED_FILES = {
    ".pre-commit-config.yaml",
    ".gitattributes",
    ".gitmodules",
    ".gitignore",
    "pyproject.toml",
    "poetry.lock",
    "uv.lock",
    "pipfile",
    "pipfile.lock",
    "dockerfile",
    "makefile",
    "backend/auth.py",
    "backend/attestations.py",
    "backend/main.py",
    "backend/analyzer.py",
    "backend/semgrep_analyzer.py",
    "backend/policy_engine.py",
}


class VerificationError(ValueError):
    """Fallo de un control obligatorio de integridad."""


# ==========================================
# OPERACIONES GIT CONFIABLES
# ==========================================

def git(
    repository_path: Path,
    *args: str,
) -> bytes:
    """
    Ejecuta operaciones de lectura Git.

    Nunca utiliza shell=True.
    Nunca ejecuta codigo del commit.
    Nunca hace checkout del contenido.
    """

    try:
        process = subprocess.run(
            [
                "git",
                "-C",
                str(repository_path),
                *args,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            shell=False,
            timeout=30,
        )

    except (
        subprocess.TimeoutExpired,
        OSError,
    ) as exc:
        raise VerificationError(
            "No se pudo completar "
            "una operacion Git"
        ) from exc

    if process.returncode != 0:
        raise VerificationError(
            "Git rechazo una operacion "
            "obligatoria de lectura"
        )

    return process.stdout


def require_oid(value: str) -> str:
    """
    Exige un identificador Git completo.
    """

    if (
        not isinstance(value, str)
        or not GIT_OID_RE.fullmatch(value)
    ):
        raise VerificationError(
            "Git OID invalido"
        )

    return value


def git_text(
    repository_path: Path,
    *args: str,
) -> str:
    """
    Obtiene texto UTF-8 desde Git.
    """

    try:
        return git(
            repository_path,
            *args,
        ).decode(
            "utf-8",
            errors="strict",
        ).strip()

    except UnicodeError as exc:
        raise VerificationError(
            "Salida Git no valida en UTF-8"
        ) from exc


# ==========================================
# IDENTIFICACION DEL COMMIT
# ==========================================

def get_commit_parent(
    repository_path: Path,
    commit_oid: str,
) -> str:
    """
    Acepta commits con exactamente
    un padre.

    Los merges requieren otra politica.
    """

    commit_oid = require_oid(
        commit_oid
    )

    value = git_text(
        repository_path,
        "rev-list",
        "--parents",
        "-n",
        "1",
        commit_oid,
    )

    parts = value.split()

    if (
        len(parts) != 2
        or parts[0] != commit_oid
    ):
        raise VerificationError(
            "Commit raiz o merge "
            "no soportado"
        )

    return require_oid(parts[1])


def get_commit_tree(
    repository_path: Path,
    commit_oid: str,
) -> str:
    """
    Obtiene el arbol del commit real.
    """

    commit_oid = require_oid(
        commit_oid
    )

    tree_oid = git_text(
        repository_path,
        "rev-parse",
        "--verify",
        f"{commit_oid}^{{tree}}",
    )

    return require_oid(tree_oid)


def get_commit_message(
    repository_path: Path,
    commit_oid: str,
) -> str:
    """
    Obtiene el mensaje del commit
    sin ejecutar hooks ni scripts.
    """

    commit_oid = require_oid(
        commit_oid
    )

    raw = git(
        repository_path,
        "log",
        "-1",
        "--format=%B",
        commit_oid,
    )

    if len(raw) > MAX_COMMIT_MESSAGE_BYTES:
        raise VerificationError(
            "Mensaje de commit demasiado grande"
        )

    try:
        return raw.decode(
            "utf-8",
            errors="strict",
        )

    except UnicodeError as exc:
        raise VerificationError(
            "Mensaje de commit invalido"
        ) from exc


# ==========================================
# EXTRAER CONSTANCIA FIRMADA
# ==========================================

def extract_attestation(
    commit_message: str,
) -> str:
    """
    Espera exactamente un trailer:

    AppSec-Attestation: <token>

    El token se verifica posteriormente
    con una clave publica confiable.
    """

    tokens = []

    for line in commit_message.splitlines():

        if line.startswith(
            ATTESTATION_PREFIX
        ):
            tokens.append(
                line[
                    len(ATTESTATION_PREFIX):
                ].strip()
            )

    if len(tokens) != 1:
        raise VerificationError(
            "El commit debe contener "
            "exactamente una constancia AppSec"
        )

    token = tokens[0]

    if (
        not token
        or any(
            character.isspace()
            for character in token
        )
    ):
        raise VerificationError(
            "Constancia AppSec malformada"
        )

    return token


# ==========================================
# DESCUBRIR CAMBIOS DEL COMMIT
# ==========================================

def get_commit_changes(
    repository_path: Path,
    parent_oid: str,
    commit_oid: str,
) -> list[tuple[str, str]]:
    """
    Obtiene cambios directamente de Git.

    --no-renames:
    los renombrados se procesan como
    eliminacion y adicion.

    -z:
    permite rutas con espacios,
    tabulaciones y otros caracteres.
    """

    parent_oid = require_oid(
        parent_oid
    )

    commit_oid = require_oid(
        commit_oid
    )

    raw = git(
        repository_path,
        "diff",
        "--no-ext-diff",
        "--no-renames",
        "--name-status",
        "-z",
        parent_oid,
        commit_oid,
        "--",
    )

    if not raw:
        return []

    if not raw.endswith(b"\x00"):
        raise VerificationError(
            "Salida Git incompleta"
        )

    items = raw[:-1].split(
        b"\x00"
    )

    if len(items) % 2 != 0:
        raise VerificationError(
            "Formato de cambios Git invalido"
        )

    changes = []

    for index in range(
        0,
        len(items),
        2,
    ):
        try:
            status = items[index].decode(
                "ascii",
                errors="strict",
            )

            path = items[
                index + 1
            ].decode(
                "utf-8",
                errors="strict",
            )

        except UnicodeError as exc:
            raise VerificationError(
                "Ruta o estado Git invalido"
            ) from exc

        if status not in {
            "A",
            "M",
            "D",
            "T",
        }:
            raise VerificationError(
                "Estado de cambio Git "
                "no autorizado"
            )

        if not path:
            raise VerificationError(
                "Ruta Git vacia"
            )

        changes.append(
            (status, path)
        )

    return changes


# ==========================================
# POLITICA DE ARCHIVOS PROTEGIDOS
# ==========================================

def is_protected_path(
    path: str,
) -> bool:
    """
    Identifica archivos cuya modificacion
    requiere autorizacion privilegiada.
    """

    normalized = path.casefold()

    if normalized in PROTECTED_FILES:
        return True

    if normalized == ".env":
        return True

    if (
        normalized.startswith(".env.")
        and normalized != ".env.example"
    ):
        return True

    if (
        normalized.startswith("requirements")
        and normalized.endswith(".txt")
    ):
        return True

    return any(
        normalized.startswith(prefix)
        for prefix in PROTECTED_PREFIXES
    )


# ==========================================
# LEER EL BLOB REAL
# ==========================================

def get_remote_file(
    repository_path: Path,
    commit_oid: str,
    path: str,
) -> tuple[str, bytes]:
    """
    Obtiene modo y bytes exactos
    de un archivo del commit.

    No lee el working directory.

    La opcion -r permite encontrar
    archivos dentro de subdirectorios.
    """

    commit_oid = require_oid(
        commit_oid
    )

    raw = git(
        repository_path,
        "ls-tree",
        "-r",
        "-z",
        commit_oid,
        "--",
        path,
    )

    entries = [
        item
        for item in raw.split(b"\x00")
        if item
    ]

    if len(entries) != 1:
        raise VerificationError(
            "Objeto Git ausente o ambiguo"
        )

    try:
        header, listed_path = (
            entries[0].split(
                b"\t",
                1,
            )
        )

        mode, object_type, blob_oid = (
            header.decode("ascii").split()
        )

        listed_path = listed_path.decode(
            "utf-8",
            errors="strict",
        )

    except (
        ValueError,
        UnicodeError,
    ) as exc:
        raise VerificationError(
            "Entrada Git malformada"
        ) from exc

    if listed_path != path:
        raise VerificationError(
            "La ruta Git no coincide"
        )

    if (
        mode not in {
            "100644",
            "100755",
        }
        or object_type != "blob"
        or not GIT_OID_RE.fullmatch(
            blob_oid
        )
    ):
        raise VerificationError(
            "Tipo o modo Git no autorizado"
        )

    size_text = git_text(
        repository_path,
        "cat-file",
        "-s",
        blob_oid,
    )

    try:
        blob_size = int(size_text)

    except ValueError as exc:
        raise VerificationError(
            "Tamano de blob invalido"
        ) from exc

    if (
        blob_size < 0
        or blob_size > MAX_FILE_BYTES
    ):
        raise VerificationError(
            "Archivo Git excede "
            "el limite permitido"
        )

    content = git(
        repository_path,
        "cat-file",
        "blob",
        blob_oid,
    )

    if len(content) != blob_size:
        raise VerificationError(
            "Lectura de blob incompleta"
        )

    return mode, content


# ==========================================
# COBERTURA OBLIGATORIA
# ==========================================

def collect_required_files(
    repository_path: Path,
    commit_oid: str,
    changes: list[tuple[str, str]],
) -> dict[str, tuple[str, bytes]]:
    """
    Reconstruye los archivos que deben
    estar cubiertos por el manifiesto.

    La lista procede exclusivamente
    del commit Git real.
    """

    required = {}

    for status, path in changes:

        if is_protected_path(path):
            raise VerificationError(
                "Modificacion de componente "
                f"protegido: {path}"
            )

        extension = PurePosixPath(
            path
        ).suffix.lower()

        if status == "T":
            raise VerificationError(
                "Cambio de tipo Git "
                "no autorizado"
            )

        if extension in (
            UNSUPPORTED_SOURCE_EXTENSIONS
        ):
            raise VerificationError(
                "Lenguaje ejecutable "
                "sin cobertura AppSec"
            )

        if extension != ".py":
            continue

        if status == "D":
            raise VerificationError(
                "Eliminar Python requiere "
                "revision especial"
            )

        if path in required:
            raise VerificationError(
                "Archivo Git duplicado"
            )

        required[path] = get_remote_file(
            repository_path,
            commit_oid,
            path,
        )

        if len(required) > MAX_FILES:
            raise VerificationError(
                "Demasiados archivos "
                "para el manifiesto"
            )

    return required


# ==========================================
# VERIFICAR UN COMMIT REAL
# ==========================================

def verify_one_commit(
    *,
    repository_path: Path,
    commit_oid: str,
    repository: str,
    trusted_public_keys: Mapping[
        str,
        Ed25519PublicKey,
    ],
    policy_sha256: str,
    model_id: str,
) -> None:
    """
    Verifica un commit completo.

    Compara la constancia firmada
    contra los objetos Git reales.
    """

    commit_oid = require_oid(
        commit_oid
    )

    parent_oid = get_commit_parent(
        repository_path,
        commit_oid,
    )

    tree_oid = get_commit_tree(
        repository_path,
        commit_oid,
    )

    changes = get_commit_changes(
        repository_path,
        parent_oid,
        commit_oid,
    )

    expected_files = collect_required_files(
        repository_path,
        commit_oid,
        changes,
    )

    commit_message = get_commit_message(
        repository_path,
        commit_oid,
    )

    # Los commits exclusivamente documentales
    # no requieren constancia si no modifican
    # codigo ni componentes protegidos.
    if not expected_files:

        if (
            ATTESTATION_PREFIX
            in commit_message
        ):
            raise VerificationError(
                "Constancia inesperada "
                "en commit sin codigo"
            )

        return

    token = extract_attestation(
        commit_message
    )

    # ======================================
    # CRYPTOGRAPHIC VERIFICATION BOUNDARY
    # ======================================

    try:
        manifest = verify_signed_manifest(
            token,
            trusted_public_keys=trusted_public_keys,
            expected_repository=repository,
            expected_tree_oid=tree_oid,
            expected_parent_oid=parent_oid,
            expected_policy_sha256=policy_sha256,
            expected_files=expected_files,
        )

    except (
        ValueError,
        TypeError,
        KeyError,
        InvalidSignature,
        binascii.Error,
    ) as exc:

        # Unificar errores de integridad
        # y firma como VerificationError.
        #
        # La causa original se conserva
        # para diagnostico y pruebas,
        # pero nunca se emite aprobacion.
        raise VerificationError(
            "Constancia invalida o "
            "inconsistente con el commit real"
        ) from exc

    if manifest.model_id != model_id:
        raise VerificationError(
            "Modelo de analisis no autorizado"
        )


# ==========================================
# VERIFICAR TODOS LOS COMMITS
# ==========================================

def verify_commit_range(
    *,
    repository_path: Path,
    base_oid: str,
    head_oid: str,
    repository: str,
    trusted_public_keys: Mapping[
        str,
        Ed25519PublicKey,
    ],
    policy_sha256: str,
    model_id: str,
) -> int:
    """
    Verifica todos los commits
    posteriores a la base confiable.

    No basta con aprobar el ultimo commit.
    """

    repository_path = Path(
        repository_path
    ).resolve()

    base_oid = require_oid(base_oid)
    head_oid = require_oid(head_oid)

    if len(base_oid) != len(head_oid):
        raise VerificationError(
            "Formato Git OID inconsistente"
        )

    # Exigir que la base confiable
    # sea ancestro del HEAD.
    git(
        repository_path,
        "merge-base",
        "--is-ancestor",
        base_oid,
        head_oid,
    )

    raw = git_text(
        repository_path,
        "rev-list",
        "--reverse",
        f"{base_oid}..{head_oid}",
    )

    commits = (
        raw.splitlines()
        if raw
        else []
    )

    if not commits:
        raise VerificationError(
            "No existen commits "
            "para verificar"
        )

    for commit_oid in commits:

        verify_one_commit(
            repository_path=repository_path,
            commit_oid=commit_oid,
            repository=repository,
            trusted_public_keys=(
                trusted_public_keys
            ),
            policy_sha256=policy_sha256,
            model_id=model_id,
        )

    return len(commits)


# ==========================================
# CLAVE PUBLICA CONFIABLE
# ==========================================

def load_trusted_public_key(
    path: Path,
) -> Ed25519PublicKey:
    """
    Carga una clave publica.

    El caller debe proporcionar una ruta
    perteneciente a una fuente confiable.
    """

    content = Path(path).read_bytes()

    key = serialization.load_pem_public_key(
        content
    )

    if not isinstance(
        key,
        Ed25519PublicKey,
    ):
        raise VerificationError(
            "Se requiere clave publica Ed25519"
        )

    return key


# ==========================================
# INTERFAZ CLI
# ==========================================

def main() -> int:

    parser = argparse.ArgumentParser(
        description=(
            "Verify signed AppSec attestations "
            "against a Git commit range"
        ),
    )

    parser.add_argument(
        "--repo-path",
        required=True,
    )

    parser.add_argument(
        "--base",
        required=True,
    )

    parser.add_argument(
        "--head",
        required=True,
    )

    parser.add_argument(
        "--repository",
        required=True,
    )

    parser.add_argument(
        "--public-key",
        required=True,
    )

    parser.add_argument(
        "--kid",
        required=True,
    )

    parser.add_argument(
        "--policy-sha256",
        required=True,
    )

    parser.add_argument(
        "--model",
        required=True,
    )

    args = parser.parse_args()

    try:

        if not SHA256_RE.fullmatch(
            args.policy_sha256
        ):
            raise VerificationError(
                "Huella de politica invalida"
            )

        public_key = load_trusted_public_key(
            Path(args.public_key)
        )

        count = verify_commit_range(
            repository_path=Path(
                args.repo_path
            ),
            base_oid=args.base,
            head_oid=args.head,
            repository=args.repository,
            trusted_public_keys={
                args.kid: public_key,
            },
            policy_sha256=(
                args.policy_sha256
            ),
            model_id=args.model,
        )

        print(
            "[PASS] Integridad Git "
            f"verificada en {count} commit(s)"
        )

        return 0

    except Exception as exc:

        print(
            "[BLOCK] Verificacion AppSec "
            f"rechazada: "
            f"{type(exc).__name__}: {exc}",
            file=sys.stderr,
        )

        return 1


if __name__ == "__main__":
    sys.exit(main())
