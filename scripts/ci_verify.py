
"""
AppSec GenAI - Trusted CI Verification Entry Point

Security model:
- Run this file ONLY from trusted base-branch code.
- Never checkout or execute PR-controlled source code.
- Fetch PR Git objects for read-only inspection.
- Trust only the public key in the protected base.
- Reconstruct the signed policy fingerprint.
- Verify every commit in the PR.
- Deny unsupported changes by default.
"""

import ast
import hashlib
import os
import re
import subprocess
import sys

from pathlib import Path, PurePosixPath

from cryptography.hazmat.primitives import serialization

from backend.attestations import compute_policy_sha256

from scripts.verify_commit import (
    VerificationError,
    get_commit_changes,
    get_commit_parent,
    load_trusted_public_key,
    verify_commit_range,
)


ROOT = Path(__file__).resolve().parent.parent

OID_RE = re.compile(
    r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z"
)

ALLOWED_DOC_FILES = {
    "README.md",
    "CHANGELOG.md",
    "CONTRIBUTING.md",
    "LICENSE",
    "LICENSE.md",
}

MAX_PR_COMMITS = 100


def require_oid(value):
    if not OID_RE.fullmatch(value):
        raise VerificationError("Git OID invalido")
    return value


def run_git(*args):
    result = subprocess.run(
        ["git", *args],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        shell=False,
        timeout=120,
    )

    if result.returncode != 0:
        raise VerificationError(
            "Operacion Git de CI fallida"
        )

    return result.stdout.decode(
        "utf-8",
        errors="strict",
    ).strip()


def load_trust():
    """
    La clave proviene del checkout
    de la rama base confiable.
    """

    key_dir = ROOT / ".github" / "appsec" / "keys"

    candidates = list(key_dir.glob("*.pem"))

    if len(candidates) != 1:
        raise VerificationError(
            "CI requiere exactamente una "
            "clave publica autorizada"
        )

    path = candidates[0]

    key = load_trusted_public_key(path)

    raw = key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    kid = (
        "lab-"
        + hashlib.sha256(raw).hexdigest()[:16]
    )

    if path.name != f"{kid}.pem":
        raise VerificationError(
            "Nombre o fingerprint de clave invalido"
        )

    return kid, key


def trusted_policy_sha256():
    """
    Extrae la lista TRUSTED_POLICY_PATHS
    de backend/main.py sin importarlo
    ni ejecutar la aplicacion.

    Los archivos pertenecen al checkout
    de la rama base confiable.
    """

    main_file = ROOT / "backend" / "main.py"

    syntax_tree = ast.parse(
        main_file.read_text(encoding="utf-8")
    )

    declarations = []

    for node in syntax_tree.body:
        if not isinstance(node, ast.Assign):
            continue

        for target in node.targets:
            if (
                isinstance(target, ast.Name)
                and target.id == "TRUSTED_POLICY_PATHS"
            ):
                declarations.append(node.value)

    if len(declarations) != 1:
        raise VerificationError(
            "Lista de politica ausente o ambigua"
        )

    paths = ast.literal_eval(declarations[0])

    if not isinstance(paths, tuple) or not paths:
        raise VerificationError(
            "Lista de politica invalida"
        )

    if len(paths) != len(set(paths)):
        raise VerificationError(
            "Rutas de politica duplicadas"
        )

    trusted_files = {}

    for relative_path in paths:
        if (
            not isinstance(relative_path, str)
            or not re.fullmatch(
                r"[A-Za-z0-9_./-]+",
                relative_path,
            )
            or relative_path.startswith("/")
            or ".." in relative_path.split("/")
        ):
            raise VerificationError(
                "Ruta de politica no confiable"
            )

        full_path = (ROOT / relative_path).resolve()

        if not full_path.is_relative_to(ROOT):
            raise VerificationError(
                "Ruta fuera del directorio confiable"
            )

        trusted_files[relative_path] = (
            full_path.read_bytes()
        )

    return compute_policy_sha256(trusted_files)


def enforce_strict_scope(base_oid, head_oid):
    """
    Control adicional de cobertura.

    Durante esta fase:
    - Python requiere manifiesto firmado.
    - Documentacion permitida no requiere escaneo.
    - Otros archivos requieren revision privilegiada.

    Esto reduce las evasiones mediante
    extensiones que aun no analizamos.
    """

    output = run_git(
        "rev-list",
        "--reverse",
        f"{base_oid}..{head_oid}",
    )

    commits = output.splitlines() if output else []

    if not 1 <= len(commits) <= MAX_PR_COMMITS:
        raise VerificationError(
            "Cantidad de commits fuera de politica"
        )

    for commit_oid in commits:
        commit_oid = require_oid(commit_oid)

        parent_oid = get_commit_parent(
            ROOT,
            commit_oid,
        )

        changes = get_commit_changes(
            ROOT,
            parent_oid,
            commit_oid,
        )

        for status, path in changes:
            if path.endswith(".py"):
                continue

            if path in ALLOWED_DOC_FILES:
                continue

            if (
                path.startswith("docs/")
                and PurePosixPath(path).suffix == ".md"
            ):
                continue

            raise VerificationError(
                "Cambio sin cobertura autorizada: "
                f"{path}"
            )

    return len(commits)


def main():
    try:
        number = int(os.environ["APPSEC_PR_NUMBER"])
        head = require_oid(
            os.environ["APPSEC_PR_SHA"]
        )
        base = require_oid(
            os.environ["APPSEC_BASE_SHA"]
        )
        repository = os.environ[
            "APPSEC_REPOSITORY"
        ]

        if not 1 <= number <= 1000000000:
            raise VerificationError(
                "Numero de PR invalido"
            )

        if not re.fullmatch(
            r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+",
            repository,
        ):
            raise VerificationError(
                "Repositorio invalido"
            )

        # Verificar que el codigo ejecutado
        # realmente es el del commit base.
        checked_out = require_oid(
            run_git("rev-parse", "HEAD")
        )

        if checked_out != base:
            raise VerificationError(
                "El checkout no corresponde a la base"
            )

        # Solo descargamos objetos Git del PR.
        # NO hacemos checkout del codigo aportado.
        run_git(
            "fetch",
            "--no-tags",
            "--force",
            "origin",
            (
                f"+refs/pull/{number}/head:"
                "refs/remotes/origin/appsec-pr"
            ),
        )

        fetched_head = require_oid(
            run_git(
                "rev-parse",
                "refs/remotes/origin/appsec-pr",
            )
        )

        # Si se modifico el PR durante la
        # ejecucion, rechazar y reintentar
        # con un evento de sincronizacion.
        if fetched_head != head:
            raise VerificationError(
                "El HEAD del PR cambio durante CI"
            )

        merge_base = require_oid(
            run_git(
                "merge-base",
                base,
                head,
            )
        )

        kid, public_key = load_trust()

        policy_hash = trusted_policy_sha256()

        count = enforce_strict_scope(
            merge_base,
            head,
        )

        verified = verify_commit_range(
            repository_path=ROOT,
            base_oid=merge_base,
            head_oid=head,
            repository=repository,
            trusted_public_keys={
                kid: public_key
            },
            policy_sha256=policy_hash,
            model_id="qwen2.5-coder:7b",
        )

        if verified != count:
            raise VerificationError(
                "Cobertura de commits inconsistente"
            )

        print(
            "[PASS] CI verifico "
            f"{verified} commit(s) con integridad"
        )

        return 0

    except Exception as exc:
        print(
            "[BLOCK] Integridad remota: "
            f"{type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
