
"""
MercadoLibre AppSec GenAI Challenge
Git Pre-Commit Security Hook

Responsabilidades:
1. Inspeccionar archivos del indice Git.
2. Rechazar modificaciones ordinarias de controles protegidos.
3. Rechazar lenguajes sin cobertura autorizada.
4. Leer los bytes exactos desde Git staging.
5. Recuperar el JWT desde Windows Credential Manager.
6. Enviar el lote a FastAPI /analyze/batch.
7. Comprobar SHA-256, archivos y decisiones.
8. Comprobar que Git staging no haya cambiado.
9. Guardar temporalmente la constancia firmada.
10. Bloquear commits no aprobados.

El hook local no es una frontera de confianza.

La verificacion autoritativa corresponde a GitHub
y a un verificador protegido independiente.
"""

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request

from pathlib import Path


# ==========================================
# PROJECT ROOT
# ==========================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# ==========================================
# AUTH0 TOKEN STORE
# ==========================================

from auth_client.token_store import (
    get_access_token,
    TokenUnavailable,
)


# ==========================================
# CONFIGURATION
# ==========================================

API_BASE_URL = os.getenv(
    "APPSEC_API_URL",
    "http://127.0.0.1:8000",
).strip().rstrip("/")

TRUSTED_API_URL = "http://127.0.0.1:8000"

if API_BASE_URL != TRUSTED_API_URL:
    raise RuntimeError(
        "APPSEC_API_URL no es un destino autorizado"
    )

API_URL = f"{API_BASE_URL}/analyze"
BATCH_API_URL = f"{API_BASE_URL}/analyze/batch"

# El backend de lotes implementa Python
# en esta etapa. No afirmar cobertura JS/TS.
SUPPORTED_EXTENSIONS = (".py",)

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

# Refleja la politica de scripts/verify_commit.py.
# GitHub sera la fuente autoritativa.
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

MAX_FILE_BYTES = 90000
MAX_FILES = 128
MAX_TOTAL_BYTES = 8_000_000

# Tiempo maximo del lote completo.
# Un lote puede ejecutar varios analisis Ollama.
BATCH_REQUEST_TIMEOUT = 900

# Mantener compatibilidad con /analyze.
REQUEST_TIMEOUT = 210

MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_RECEIPT_CHARACTERS = 200000

OID_PATTERN = re.compile(
    r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z"
)

RECEIPT_PATTERN = re.compile(
    r"[A-Za-z0-9_-]+\."
    r"[A-Za-z0-9_-]+\."
    r"[A-Za-z0-9_-]+\Z"
)


# ==========================================
# HTTP SECURITY
# ==========================================

class NoRedirectHandler(
    urllib.request.HTTPRedirectHandler
):
    """
    Prohibe redirecciones HTTP.

    Una solicitud con Bearer token no debe
    reenviarse a destinos inesperados.
    """

    def redirect_request(
        self,
        req,
        fp,
        code,
        msg,
        headers,
        newurl,
    ):
        return None


HTTP_OPENER = urllib.request.build_opener(
    urllib.request.ProxyHandler({}),
    NoRedirectHandler(),
)


# ==========================================
# GIT OPERATIONS
# ==========================================

def git_command(*args):
    """
    Ejecuta Git sin shell.

    Devuelve stdout como bytes.
    """

    result = subprocess.run(
        ["git", *args],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        timeout=30,
    )

    return result.stdout


def git_string(*args):
    """
    Obtiene una respuesta Git en UTF-8.
    """

    return git_command(*args).decode(
        "utf-8",
        errors="strict",
    ).strip()


def get_git_context():
    """
    Obtiene el arbol Git preparado y
    el commit padre propuesto.

    El repositorio debe tener HEAD.

    Estos identificadores proceden del
    entorno local no confiable. GitHub
    debera compararlos posteriormente
    con el commit real.
    """

    parent_oid = git_string(
        "rev-parse",
        "--verify",
        "HEAD",
    )

    # Detectar conflictos de merge sin resolver.
    unmerged = git_command(
        "ls-files",
        "-u",
        "-z",
    )

    if unmerged:
        raise ValueError(
            "Existen conflictos de Git sin resolver"
        )

    tree_oid = git_string(
        "write-tree",
    )

    if not OID_PATTERN.fullmatch(parent_oid):
        raise ValueError(
            "Git HEAD invalido"
        )

    if not OID_PATTERN.fullmatch(tree_oid):
        raise ValueError(
            "Git tree invalido"
        )

    if len(parent_oid) != len(tree_oid):
        raise ValueError(
            "Formatos de Git OID incompatibles"
        )

    return tree_oid, parent_oid


def get_staged_changes():
    """
    Obtiene todos los cambios staged.

    --no-renames convierte renombrados
    en eliminacion y adicion, siguiendo
    el criterio del verificador remoto.

    -z evita ambiguedades en las rutas.
    """

    output = git_command(
        "diff",
        "--cached",
        "--no-renames",
        "--name-status",
        "-z",
        "HEAD",
        "--",
    )

    if not output:
        return []

    if not output.endswith(b"\x00"):
        raise ValueError(
            "Respuesta Git incompleta"
        )

    items = output[:-1].split(b"\x00")

    if len(items) % 2 != 0:
        raise ValueError(
            "Formato Git inesperado"
        )

    changes = []

    for index in range(0, len(items), 2):

        status = items[index].decode(
            "ascii",
            errors="strict",
        )

        filename = items[index + 1].decode(
            "utf-8",
            errors="strict",
        )

        if status not in {
            "A",
            "M",
            "D",
            "T",
        }:
            raise ValueError(
                "Tipo de cambio Git no autorizado"
            )

        if not filename:
            raise ValueError(
                "Ruta Git vacia"
            )

        changes.append(
            (status, filename)
        )

    return changes


def get_staged_files():
    """
    Funcion conservada por compatibilidad.

    Devuelve archivos Python agregados
    o modificados en Git staging.
    """

    return [
        filename
        for status, filename in get_staged_changes()
        if (
            status in {"A", "M"}
            and filename.lower().endswith(
                SUPPORTED_EXTENSIONS
            )
        )
    ]


def get_staged_content(filename):
    """
    Lee los bytes reales del indice Git.

    No lee el working directory.
    """

    raw_content = git_command(
        "show",
        f":0:{filename}",
    )

    if len(raw_content) > MAX_FILE_BYTES:
        raise ValueError(
            f"Archivo demasiado grande: {filename!r}"
        )

    try:
        return raw_content.decode("utf-8")

    except UnicodeDecodeError:
        raise ValueError(
            f"El archivo no es UTF-8: {filename!r}"
        ) from None


def get_staged_mode(filename):
    """
    Obtiene el modo Git desde el indice.

    Solo admite archivos regulares:
    - 100644
    - 100755

    Rechaza symlinks y submodules.
    """

    raw = git_command(
        "ls-files",
        "--stage",
        "-z",
        "--",
        filename,
    )

    entries = [
        item
        for item in raw.split(b"\x00")
        if item
    ]

    if len(entries) != 1:
        raise ValueError(
            f"Entrada Git ambigua: {filename!r}"
        )

    try:
        header, listed_path = (
            entries[0].split(b"\t", 1)
        )

        mode, blob_oid, stage = (
            header.decode("ascii").split()
        )

        real_filename = listed_path.decode(
            "utf-8",
            errors="strict",
        )

    except (
        ValueError,
        UnicodeError,
    ) as exc:
        raise ValueError(
            "Entrada Git malformada"
        ) from exc

    if (
        stage != "0"
        or real_filename != filename
        or mode not in {"100644", "100755"}
        or not OID_PATTERN.fullmatch(blob_oid)
    ):
        raise ValueError(
            f"Modo Git no permitido: {filename!r}"
        )

    return mode


# ==========================================
# SECURITY PATH POLICY
# ==========================================

def is_protected_path(filename):
    """
    Bloquea cambios ordinarios de
    mecanismos de seguridad protegidos.
    """

    path = filename.casefold()

    if path in PROTECTED_FILES:
        return True

    if path == ".env":
        return True

    if (
        path.startswith(".env.")
        and path != ".env.example"
    ):
        return True

    if (
        path.startswith("requirements")
        and path.endswith(".txt")
    ):
        return True

    return any(
        path.startswith(prefix)
        for prefix in PROTECTED_PREFIXES
    )


def build_batch_files(changes):
    """
    Construye la lista de archivos que
    analizara /analyze/batch.

    Bloquea eliminaciones Python,
    cambios protegidos y lenguajes
    que todavia no tienen cobertura.

    La CI reconstruira la lista de
    manera independiente.
    """

    files = []
    total_bytes = 0

    for status, filename in changes:

        if is_protected_path(filename):
            raise ValueError(
                "Cambio en componente protegido: "
                f"{filename!r}. Requiere bootstrap "
                "o revision administrativa."
            )

        extension = Path(filename).suffix.lower()

        if status == "T":
            raise ValueError(
                f"Cambio de tipo Git prohibido: {filename!r}"
            )

        if extension in UNSUPPORTED_SOURCE_EXTENSIONS:
            raise ValueError(
                "Lenguaje ejecutable sin cobertura "
                f"AppSec: {filename!r}"
            )

        if extension != ".py":
            continue

        if status == "D":
            raise ValueError(
                "Eliminacion de archivo Python "
                f"requiere revision: {filename!r}"
            )

        if status not in {"A", "M"}:
            raise ValueError(
                f"Estado Git no autorizado: {status}"
            )

        code = get_staged_content(filename)

        if not code:
            raise ValueError(
                f"Archivo Python vacio: {filename!r}"
            )

        content_size = len(
            code.encode("utf-8")
        )

        total_bytes += content_size

        if total_bytes > MAX_TOTAL_BYTES:
            raise ValueError(
                "El lote excede el limite de bytes"
            )

        if len(files) >= MAX_FILES:
            raise ValueError(
                "Demasiados archivos en el lote"
            )

        files.append({
            "filename": filename,
            "mode": get_staged_mode(filename),
            "code": code,
        })

    # Evitar decisiones basadas en el
    # orden accidental del indice.
    files.sort(
        key=lambda item: item["filename"]
    )

    return files


# ==========================================
# AUTH0 TOKEN
# ==========================================

def obtain_access_token():
    """
    Recupera el JWT desde Windows
    Credential Manager.

    Nunca se imprime ni se guarda
    dentro del repositorio.
    """

    try:
        return get_access_token()

    except TokenUnavailable as exc:
        raise ValueError(
            "Autenticacion Auth0 no disponible. "
            f"{exc}"
        ) from None


# ==========================================
# AUTHENTICATED API REQUEST
# ==========================================

def post_authenticated_json(
    url,
    payload,
    *,
    timeout,
):
    """
    Solicitud JSON con:
    - API autorizada.
    - OAuth Bearer.
    - Sin proxies.
    - Sin redirecciones.
    - Respuesta limitada.
    - Validacion Content-Type.
    """

    raw_payload = json.dumps(
        payload,
        ensure_ascii=False,
    ).encode("utf-8")

    request = urllib.request.Request(
        url,
        data=raw_payload,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        method="POST",
    )

    request.add_unredirected_header(
        "Authorization",
        f"Bearer {obtain_access_token()}",
    )

    try:
        with HTTP_OPENER.open(
            request,
            timeout=timeout,
        ) as response:

            if response.status != 200:
                raise ValueError(
                    "Respuesta HTTP inesperada: "
                    f"{response.status}"
                )

            content_type = (
                response.headers.get(
                    "Content-Type",
                    "",
                ).lower()
            )

            if "application/json" not in content_type:
                raise ValueError(
                    "La API no devolvio JSON"
                )

            raw_response = response.read(
                MAX_RESPONSE_BYTES + 1
            )

            if len(raw_response) > MAX_RESPONSE_BYTES:
                raise ValueError(
                    "Respuesta demasiado grande"
                )

    except urllib.error.HTTPError as exc:

        if exc.code == 401:
            raise ValueError(
                "HTTP 401: JWT invalido o expirado. "
                "Ejecuta python -m auth_client.login"
            ) from None

        if exc.code == 403:
            raise ValueError(
                "HTTP 403: falta permiso analyze:code"
            ) from None

        if exc.code in {301, 302, 303, 307, 308}:
            raise ValueError(
                "Redireccion HTTP bloqueada"
            ) from None

        raise ValueError(
            "FastAPI rechazo la solicitud: "
            f"HTTP {exc.code}"
        ) from None

    try:
        result = json.loads(
            raw_response.decode("utf-8")
        )

    except (
        ValueError,
        UnicodeError,
    ):
        raise ValueError(
            "JSON invalido desde FastAPI"
        ) from None

    if not isinstance(result, dict):
        raise ValueError(
            "FastAPI no devolvio un objeto JSON"
        )

    return result


# ==========================================
# LEGACY SINGLE-FILE API
# ==========================================

def analyze_file(filename, code):
    """
    Compatibilidad con /analyze.

    El flujo principal utiliza /analyze/batch.
    Esta funcion sigue disponible para
    pruebas individuales anteriores.
    """

    result = post_authenticated_json(
        API_URL,
        {
            "filename": filename,
            "code": code,
        },
        timeout=REQUEST_TIMEOUT,
    )

    expected_hash = hashlib.sha256(
        code.encode("utf-8")
    ).hexdigest()

    if result.get("sha256") != expected_hash:
        raise ValueError(
            "SHA-256 de analisis individual invalido"
        )

    if result.get("filename") != filename:
        raise ValueError(
            "Nombre de archivo no coincide"
        )

    return result


# ==========================================
# RESPONSE VALIDATION
# ==========================================

def validate_response(result):
    """
    Conserva la validacion del Policy Engine
    utilizada por el hook anterior.
    """

    status = result.get("status")

    vulnerabilities = result.get(
        "vulnerabilities"
    )

    needs_review = result.get(
        "needs_review"
    )

    if status not in (
        "approved",
        "rejected",
        "review_required",
    ):
        raise ValueError(
            f"Estado de analisis invalido: {status}"
        )

    if not isinstance(vulnerabilities, list):
        raise ValueError(
            "Campo vulnerabilities invalido"
        )

    if not isinstance(needs_review, list):
        raise ValueError(
            "Campo needs_review invalido"
        )

    if status == "approved":

        if vulnerabilities or needs_review:
            raise ValueError(
                "Aprobacion inconsistente"
            )

    elif status == "rejected":

        if not vulnerabilities:
            raise ValueError(
                "Rechazo sin vulnerabilidades"
            )

    elif status == "review_required":

        if vulnerabilities or not needs_review:
            raise ValueError(
                "Revision inconsistente"
            )

    required_fields = (
        "type",
        "owasp",
        "severity",
        "description",
        "recommendation",
    )

    for finding in (
        vulnerabilities + needs_review
    ):
        if not isinstance(finding, dict):
            raise ValueError(
                "Hallazgo invalido"
            )

        for field in required_fields:

            value = finding.get(field)

            if (
                not isinstance(value, str)
                or not value.strip()
            ):
                raise ValueError(
                    f"Hallazgo sin campo valido: {field}"
                )

    return status, vulnerabilities, needs_review


def validate_batch_response(result, files):
    """
    Verifica:
    - Todos los archivos enviados.
    - Ausencia de duplicados.
    - SHA-256 por archivo.
    - Decision global consistente.
    - Firma exclusivamente para approved.
    """

    results = result.get("files")

    if not isinstance(results, list):
        raise ValueError(
            "Respuesta batch sin archivos validos"
        )

    expected = {
        item["filename"]: hashlib.sha256(
            item["code"].encode("utf-8")
        ).hexdigest()
        for item in files
    }

    if len(results) != len(expected):
        raise ValueError(
            "Cobertura de respuesta incompleta"
        )

    observed = set()
    statuses = []

    for item in results:

        if not isinstance(item, dict):
            raise ValueError(
                "Resultado de archivo invalido"
            )

        filename = item.get("filename")

        if (
            not isinstance(filename, str)
            or filename not in expected
            or filename in observed
        ):
            raise ValueError(
                "Archivo inesperado o duplicado"
            )

        observed.add(filename)

        if item.get("sha256") != expected[filename]:
            raise ValueError(
                "SHA-256 inconsistente: "
                f"{filename!r}"
            )

        status, vulnerabilities, needs_review = (
            validate_response(item)
        )

        statuses.append(status)

        print(
            f"\n[SCAN] {filename!r}"
        )

        print(
            "[HASH] SHA-256:",
            item["sha256"]
        )

        if status == "rejected":
            print(
                "[BLOCK] Vulnerabilidades detectadas"
            )

            print_findings(vulnerabilities)

        elif status == "review_required":
            print(
                "[REVIEW] Requiere revision AppSec"
            )

            print_findings(needs_review)

        else:
            print(
                "[OK] Aprobado por el Policy Engine"
            )

    if observed != set(expected):
        raise ValueError(
            "El analisis no cubrio todos los archivos"
        )

    if "rejected" in statuses:
        overall = "rejected"

    elif "review_required" in statuses:
        overall = "review_required"

    else:
        overall = "approved"

    if result.get("status") != overall:
        raise ValueError(
            "Decision global inconsistente"
        )

    attestation = result.get("attestation")

    if overall != "approved":

        if attestation is not None:
            raise ValueError(
                "Constancia emitida sin aprobacion"
            )

        return overall, None

    if (
        not isinstance(attestation, str)
        or not (
            1 <= len(attestation)
            <= MAX_RECEIPT_CHARACTERS
        )
        or not RECEIPT_PATTERN.fullmatch(
            attestation
        )
    ):
        raise ValueError(
            "Constancia aprobada ausente o malformada"
        )

    # Esta validacion local NO sustituye
    # la comprobacion Ed25519 de GitHub.
    return overall, attestation


# ==========================================
# BATCH API
# ==========================================

def analyze_batch(
    files,
    tree_oid,
    parent_oid,
):
    """
    Envia una operacion completa a FastAPI.

    No confia en una decision declarada
    por los archivos del repositorio.
    """

    response = post_authenticated_json(
        BATCH_API_URL,
        {
            "git_tree_oid": tree_oid,
            "parent_oid": parent_oid,
            "files": files,
        },
        timeout=BATCH_REQUEST_TIMEOUT,
    )

    return validate_batch_response(
        response,
        files,
    )


# ==========================================
# FINDINGS PRESENTATION
# ==========================================

def print_findings(findings):
    """
    Conserva la presentacion de
    hallazgos del hook anterior.
    """

    for index, finding in enumerate(
        findings,
        start=1,
    ):
        print(f"\nHallazgo #{index}")
        print("-" * 45)

        print(
            "Tipo:",
            finding["type"]
        )

        print(
            "OWASP:",
            finding["owasp"]
        )

        print(
            "Severidad:",
            finding["severity"]
        )

        print(
            "Descripcion:",
            finding["description"]
        )

        print(
            "Mitigacion:",
            finding["recommendation"]
        )


# ==========================================
# LOCAL RECEIPT TRANSPORT
# ==========================================

def get_pending_receipt_path():
    """
    Devuelve una ubicacion administrada por Git.

    Funciona tambien cuando .git es un
    archivo, como en ciertos worktrees.
    """

    value = git_string(
        "rev-parse",
        "--git-path",
        "appsec-genai/pending.json",
    )

    path = Path(value)

    if not path.is_absolute():
        path = PROJECT_ROOT / path

    return path.resolve()


def clear_pending_receipt():
    """
    Evita reutilizar una constancia
    pendiente de una ejecucion anterior.
    """

    path = get_pending_receipt_path()

    path.unlink(missing_ok=True)


def store_pending_receipt(
    *,
    tree_oid,
    parent_oid,
    receipt,
):
    """
    Guarda una constancia fuera del indice Git.

    El futuro commit-msg la incorporara
    al mensaje del commit solamente si
    el arbol y el padre siguen coincidiendo.

    Nunca guarda el JWT de Auth0.
    """

    destination = get_pending_receipt_path()

    destination.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    data = {
        "version": 1,
        "git_tree_oid": tree_oid,
        "parent_oid": parent_oid,
        "attestation": receipt,
    }

    fd, temporary_name = tempfile.mkstemp(
        prefix=".pending-",
        suffix=".tmp",
        dir=str(destination.parent),
    )

    temporary = Path(temporary_name)

    try:
        with os.fdopen(
            fd,
            "w",
            encoding="utf-8",
        ) as file:
            json.dump(
                data,
                file,
                sort_keys=True,
                separators=(",", ":"),
            )

            file.flush()
            os.fsync(file.fileno())

        os.replace(
            temporary,
            destination,
        )

    finally:
        temporary.unlink(missing_ok=True)


# ==========================================
# MAIN WORKFLOW
# ==========================================

def main():

    print(
        "\n[AppSec GenAI] "
        "Iniciando analisis batch autenticado..."
    )

    try:

        # ==================================
        # 1. DISCARD STALE LOCAL RECEIPTS
        # ==================================

        clear_pending_receipt()

        # ==================================
        # 2. SNAPSHOT OF GIT STAGING
        # ==================================

        tree_before, parent_before = (
            get_git_context()
        )

        changes = get_staged_changes()

        if not changes:
            print(
                "[INFO] No hay cambios staged."
            )
            return 0

        # ==================================
        # 3. CHECK SECURITY SCOPE
        # ==================================

        files = build_batch_files(
            changes
        )

        if not files:
            print(
                "[INFO] Sin cambios Python "
                "que requieran analisis."
            )

            print(
                "[INFO] No se emitio constancia. "
                "La CI verificara el alcance."
            )

            return 0

        print(
            "[INFO] Archivos Python:",
            len(files),
        )

        print(
            "[GIT] Arbol preparado:",
            tree_before,
        )

        # ==================================
        # 4. AUTHENTICATED BATCH ANALYSIS
        # ==================================

        overall, receipt = analyze_batch(
            files,
            tree_before,
            parent_before,
        )

        if overall != "approved":
            print(
                "\n[BLOCK] Commit rechazado "
                "por politica AppSec."
            )
            return 1

        if receipt is None:
            raise ValueError(
                "No se recibio constancia firmada"
            )

        # ==================================
        # 5. GIT TOCTOU CHECK
        # ==================================

        tree_after, parent_after = (
            get_git_context()
        )

        if (
            tree_after != tree_before
            or parent_after != parent_before
        ):
            raise ValueError(
                "Git staging o HEAD cambio "
                "durante el analisis"
            )

        # ==================================
        # 6. STORE SIGNED MANIFEST
        # ==================================

        store_pending_receipt(
            tree_oid=tree_before,
            parent_oid=parent_before,
            receipt=receipt,
        )

        print(
            "[OK] Manifiesto firmado "
            "recibido y almacenado"
        )

        print(
            "[INFO] El hook commit-msg "
            "debera vincularlo al commit"
        )

        print(
            "\n[OK] Analisis batch aprobado. "
            "Control local superado."
        )

        return 0

    # ======================================
    # FAIL-CLOSED ERROR HANDLING
    # ======================================

    except (
        subprocess.CalledProcessError,
        subprocess.TimeoutExpired,
        UnicodeError,
        ValueError,
        KeyError,
        urllib.error.URLError,
        TimeoutError,
        OSError,
    ) as exc:

        print(
            "\n[ERROR] El analisis no pudo "
            f"completarse: {exc}"
        )

        print(
            "[BLOCK] No se permite el commit "
            "sin evaluacion valida."
        )

        return 1


# ==========================================
# ENTRY POINT
# ==========================================

if __name__ == "__main__":
    sys.exit(main())
