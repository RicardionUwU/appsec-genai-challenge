
"""
AppSec GenAI - Git Commit Message Hook

Vincula una constancia de analisis aprobada
al mensaje del commit.

Controles:
- Reutiliza la politica del pre-commit.
- Recalcula el arbol y el padre Git.
- Verifica hashes, rutas y modos del indice.
- Rechaza constancias anteriores o expiradas.
- Rechaza trailers agregados manualmente.
- No acepta resultados parciales.
- Elimina la constancia pendiente al utilizarla.
- Falla de forma segura.

IMPORTANTE:
La verificacion criptografica autoritativa
se realiza independientemente en GitHub.
"""

import hashlib
import json
import os
import sys
import tempfile
import time

from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


from backend.attestations import (
    AnalysisManifest,
    FileRecord,
    b64url_decode,
    canonical_json,
)

from hooks.pre_commit import (
    RECEIPT_PATTERN,
    build_batch_files,
    get_git_context,
    get_pending_receipt_path,
    get_staged_changes,
)


TRAILER = "AppSec-Attestation:"

MAX_MESSAGE_BYTES = 250000
MAX_PENDING_BYTES = 250000

CLOCK_SKEW_SECONDS = 60


# ==========================================
# COMMIT MESSAGE VALIDATION
# ==========================================

def has_attestation_trailer(message: str) -> bool:
    """
    Detecta un trailer existente.

    Nunca sobrescribir una constancia
    introducida manualmente.
    """

    return any(
        line.strip().lower().startswith(
            TRAILER.lower()
        )
        for line in message.splitlines()
    )


def read_commit_message(path: Path) -> str:

    if not path.is_file():
        raise ValueError(
            "Archivo de mensaje Git inexistente"
        )

    if path.stat().st_size > MAX_MESSAGE_BYTES:
        raise ValueError(
            "Mensaje de commit demasiado grande"
        )

    return path.read_text(
        encoding="utf-8"
    )


# ==========================================
# PENDING RECEIPT VALIDATION
# ==========================================

def load_pending_receipt(
    path: Path,
    *,
    tree_oid: str,
    parent_oid: str,
) -> str:
    """
    Recupera la constancia previamente
    almacenada por pre_commit.py.
    """

    if not path.is_file():
        raise ValueError(
            "No existe constancia AppSec pendiente. "
            "Ejecuta nuevamente el pre-commit."
        )

    if path.stat().st_size > MAX_PENDING_BYTES:
        raise ValueError(
            "Constancia pendiente demasiado grande"
        )

    document = json.loads(
        path.read_text(
            encoding="utf-8"
        )
    )

    if not isinstance(document, dict):
        raise ValueError(
            "Constancia pendiente invalida"
        )

    required_keys = {
        "version",
        "git_tree_oid",
        "parent_oid",
        "attestation",
    }

    if set(document) != required_keys:
        raise ValueError(
            "Estructura de constancia inesperada"
        )

    if type(document["version"]) is not int:
        raise ValueError(
            "Version de constancia invalida"
        )

    if document["version"] != 1:
        raise ValueError(
            "Version de constancia no soportada"
        )

    if document["git_tree_oid"] != tree_oid:
        raise ValueError(
            "El arbol Git cambio desde el analisis"
        )

    if document["parent_oid"] != parent_oid:
        raise ValueError(
            "El commit padre cambio desde el analisis"
        )

    receipt = document["attestation"]

    if (
        not isinstance(receipt, str)
        or not RECEIPT_PATTERN.fullmatch(receipt)
    ):
        raise ValueError(
            "Formato de firma invalido"
        )

    return receipt


# ==========================================
# MANIFEST / INDEX CONSISTENCY
# ==========================================

def validate_receipt_context(
    receipt: str,
    files: list[dict],
    tree_oid: str,
    parent_oid: str,
) -> AnalysisManifest:
    """
    Valida la estructura del manifiesto
    frente al indice Git actual.

    ATENCION:
    Esto NO sustituye la verificacion
    Ed25519 independiente de GitHub.
    """

    parts = receipt.split(".")

    if len(parts) != 3:
        raise ValueError(
            "Constancia firmada malformada"
        )

    header_bytes = b64url_decode(
        parts[0]
    )

    payload_bytes = b64url_decode(
        parts[1]
    )

    signature_bytes = b64url_decode(
        parts[2]
    )

    if len(signature_bytes) != 64:
        raise ValueError(
            "Longitud de firma Ed25519 invalida"
        )

    header = json.loads(
        header_bytes
    )

    if not isinstance(header, dict):
        raise ValueError(
            "Header criptografico invalido"
        )

    if (
        header.get("alg") != "EdDSA"
        or header.get("typ")
        != "appsec-git-manifest-v1"
        or not isinstance(
            header.get("kid"),
            str,
        )
        or set(header) != {
            "alg",
            "typ",
            "kid",
        }
    ):
        raise ValueError(
            "Header de firma no autorizado"
        )

    if canonical_json(header) != header_bytes:
        raise ValueError(
            "Header no canonico"
        )

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
            "Manifiesto no canonico"
        )

    if manifest.git_tree_oid != tree_oid:
        raise ValueError(
            "Arbol firmado diferente al staging"
        )

    if manifest.parent_oid != parent_oid:
        raise ValueError(
            "Commit padre firmado diferente"
        )

    now = int(time.time())

    if manifest.issued_at > now + CLOCK_SKEW_SECONDS:
        raise ValueError(
            "Fecha de firma futura"
        )

    if manifest.expires_at <= now:
        raise ValueError(
            "Constancia expirada"
        )

    # Reconstruir hashes sin confiar
    # en el manifiesto recibido.
    actual_files = []

    for item in files:

        actual_files.append(
            FileRecord(
                path=item["filename"],
                mode=item["mode"],
                sha256=hashlib.sha256(
                    item["code"].encode(
                        "utf-8"
                    )
                ).hexdigest(),
            )
        )

    actual_files.sort(
        key=lambda item: item.path
    )

    if manifest.files != actual_files:
        raise ValueError(
            "Cobertura, rutas, modos o hashes "
            "diferentes al analisis aprobado"
        )

    return manifest


# ==========================================
# ATOMIC COMMIT MESSAGE UPDATE
# ==========================================

def append_attestation(
    message_path: Path,
    original_message: str,
    receipt: str,
):
    """
    Incorpora el trailer al mensaje Git
    sin dejar una escritura parcial.
    """

    if has_attestation_trailer(
        original_message
    ):
        raise ValueError(
            "El mensaje ya contiene "
            "una constancia AppSec"
        )

    content = (
        original_message.rstrip("\r\n")
        + "\n\n"
        + TRAILER
        + " "
        + receipt
        + "\n"
    )

    if len(
        content.encode("utf-8")
    ) > MAX_MESSAGE_BYTES:
        raise ValueError(
            "Mensaje final demasiado grande"
        )

    fd, temporary_name = tempfile.mkstemp(
        prefix=".appsec-msg-",
        suffix=".tmp",
        dir=str(message_path.parent),
    )

    temporary_path = Path(
        temporary_name
    )

    try:

        with os.fdopen(
            fd,
            "w",
            encoding="utf-8",
            newline="\n",
        ) as file:

            file.write(content)
            file.flush()
            os.fsync(file.fileno())

        os.replace(
            temporary_path,
            message_path,
        )

    finally:
        temporary_path.unlink(
            missing_ok=True
        )


# ==========================================
# MAIN WORKFLOW
# ==========================================

def main(argv=None) -> int:

    if argv is None:
        argv = sys.argv

    try:

        if len(argv) != 2:
            raise ValueError(
                "Uso: python hooks/commit_msg.py "
                "<ruta-mensaje-git>"
            )

        message_path = Path(
            argv[1]
        ).resolve(strict=True)

        original_message = (
            read_commit_message(
                message_path
            )
        )

        if has_attestation_trailer(
            original_message
        ):
            raise ValueError(
                "El commit ya contiene "
                "una constancia AppSec"
            )

        # Volver a reconstruir el contexto
        # desde Git staging.
        tree_before, parent_before = (
            get_git_context()
        )

        changes = get_staged_changes()

        # Reutiliza la misma politica
        # de archivos protegidos.
        files = build_batch_files(
            changes
        )

        pending_path = (
            get_pending_receipt_path()
        )

        # Commits sin archivos Python:
        # no necesitan una constancia.
        # La politica de archivos protegidos
        # ya se aplico anteriormente.
        if not files:

            if pending_path.exists():
                raise ValueError(
                    "Existe una constancia inesperada "
                    "para un commit sin codigo"
                )

            print(
                "[AppSec] Commit sin cambios "
                "Python sujetos a analisis."
            )

            return 0

        # ==================================
        # REQUIRE AN APPROVED BATCH
        # ==================================

        receipt = load_pending_receipt(
            pending_path,
            tree_oid=tree_before,
            parent_oid=parent_before,
        )

        manifest = validate_receipt_context(
            receipt,
            files,
            tree_before,
            parent_before,
        )

        # ==================================
        # FINAL STAGING CONSISTENCY
        # ==================================

        tree_after, parent_after = (
            get_git_context()
        )

        if (
            tree_after != tree_before
            or parent_after != parent_before
        ):
            raise ValueError(
                "El indice o HEAD cambio "
                "durante commit-msg"
            )

        # ==================================
        # ATTACH SIGNED MANIFEST
        # ==================================

        append_attestation(
            message_path,
            original_message,
            receipt,
        )

        # Evitar reutilizacion accidental
        # de la constancia local pendiente.
        pending_path.unlink(
            missing_ok=True
        )

        print(
            "[PASS] Constancia vinculada "
            "al mensaje del commit"
        )

        print(
            "[AppSec] Archivos firmados:",
            len(manifest.files),
        )

        return 0

    except Exception as exc:

        print(
            "[BLOCK] Commit-msg AppSec: "
            f"{type(exc).__name__}: {exc}",
            file=sys.stderr,
        )

        return 1


if __name__ == "__main__":
    sys.exit(main())
