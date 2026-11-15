
"""
AppSec GenAI - Git Pre-Commit Hook

Responsabilidades:
1. Obtener archivos preparados en Git staging.
2. Leer el contenido exacto del índice de Git.
3. Enviar código al backend FastAPI.
4. Validar la respuesta del analizador.
5. Bloquear commits vulnerables o no verificados.

Este hook es un control local.
La autenticación e integridad server-side
se implementarán en una siguiente etapa.
"""

import hashlib
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request


# ==========================================
# CONFIGURACION
# ==========================================

API_URL = os.getenv(
    "APPSEC_API_URL",
    "http://127.0.0.1:8000/analyze"
)

SUPPORTED_EXTENSIONS = (
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
)

MAX_FILE_BYTES = 90000

REQUEST_TIMEOUT = 210


# ==========================================
# OPERACIONES GIT
# ==========================================

def git_command(*args):
    """
    Ejecuta Git sin utilizar una shell.

    Devuelve los bytes exactos obtenidos.
    """
    result = subprocess.run(
        ["git", *args],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
    )

    return result.stdout


def get_staged_files():
    """
    Obtiene archivos del staging de Git.

    El formato -z permite procesar rutas
    que contienen espacios.

    ACMR = Added, Copied, Modified, Renamed.
    """
    output = git_command(
        "diff",
        "--cached",
        "--name-only",
        "-z",
        "--diff-filter=ACMR",
    )

    paths = output.decode(
        "utf-8",
        errors="surrogateescape"
    ).split("\0")

    return [
        path
        for path in paths
        if path.lower().endswith(
            SUPPORTED_EXTENSIONS
        )
    ]


def get_staged_content(filename):
    """
    Obtiene el contenido preparado en Git,
    no el contenido del working directory.
    """
    raw_content = git_command(
        "show",
        f":{filename}"
    )

    if len(raw_content) > MAX_FILE_BYTES:
        raise ValueError(
            f"Archivo demasiado grande: {filename}"
        )

    return raw_content.decode("utf-8")


# ==========================================
# COMUNICACION CON FASTAPI
# ==========================================

def analyze_file(filename, code):
    """
    Envía código a la API de análisis.

    Calcula SHA-256 para comprobar que
    el backend analizó el mismo contenido
    recibido desde el staging.
    """
    expected_sha256 = hashlib.sha256(
        code.encode("utf-8")
    ).hexdigest()

    payload = json.dumps({
        "filename": filename,
        "code": code
    }).encode("utf-8")

    request = urllib.request.Request(
        API_URL,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        method="POST"
    )

    with urllib.request.urlopen(
        request,
        timeout=REQUEST_TIMEOUT
    ) as response:
        if response.status != 200:
            raise ValueError(
                f"Respuesta HTTP inesperada: {response.status}"
            )

        result = json.load(response)

    if not isinstance(result, dict):
        raise ValueError(
            "La API no devolvió un objeto JSON"
        )

    received_sha256 = result.get("sha256")

    if received_sha256 != expected_sha256:
        raise ValueError(
            "ERROR DE INTEGRIDAD: "
            "SHA-256 del backend no coincide "
            "con el código enviado"
        )

    if result.get("filename") != filename:
        raise ValueError(
            "El nombre del archivo analizado no coincide"
        )

    return result


# ==========================================
# VALIDACION DE RESULTADOS
# ==========================================

def validate_response(result):
    """
    Comprueba que el backend devuelve
    estados y estructuras consistentes.
    """

    status = result.get("status")

    vulnerabilities = result.get("vulnerabilities")
    needs_review = result.get("needs_review")

    if status not in (
        "approved",
        "rejected",
        "review_required",
    ):
        raise ValueError(
            f"Estado de análisis inválido: {status}"
        )

    if not isinstance(vulnerabilities, list):
        raise ValueError(
            "Campo vulnerabilities inválido"
        )

    if not isinstance(needs_review, list):
        raise ValueError(
            "Campo needs_review inválido"
        )

    if status == "approved":
        if vulnerabilities or needs_review:
            raise ValueError(
                "Aprobación inconsistente con hallazgos"
            )

    elif status == "rejected":
        if not vulnerabilities:
            raise ValueError(
                "Rechazo sin vulnerabilidades"
            )

    elif status == "review_required":
        if vulnerabilities or not needs_review:
            raise ValueError(
                "Estado review_required inconsistente"
            )

    for finding in vulnerabilities + needs_review:
        if not isinstance(finding, dict):
            raise ValueError(
                "Hallazgo con formato inválido"
            )

        required_fields = (
            "type",
            "owasp",
            "severity",
            "description",
            "recommendation",
        )

        for field in required_fields:
            if (
                not isinstance(finding.get(field), str)
                or not finding[field].strip()
            ):
                raise ValueError(
                    f"Hallazgo sin campo válido: {field}"
                )

    return status, vulnerabilities, needs_review


# ==========================================
# PRESENTACION DE HALLAZGOS
# ==========================================

def print_findings(findings):
    """
    Presenta los hallazgos y recomendaciones
    recibidos desde el backend.
    """

    for index, finding in enumerate(findings, start=1):
        print(f"\nHallazgo #{index}")
        print("-" * 45)

        print("Tipo:", finding["type"])
        print("OWASP:", finding["owasp"])
        print("Severidad:", finding["severity"])
        print("Descripción:", finding["description"])
        print("Mitigación:", finding["recommendation"])


# ==========================================
# WORKFLOW PRINCIPAL
# ==========================================

def main():
    print("\n[AppSec GenAI] Iniciando análisis...")

    try:
        staged_files = get_staged_files()

        if not staged_files:
            print(
                "[OK] No hay archivos compatibles "
                "para analizar."
            )
            return 0

        blocked = False

        for filename in staged_files:
            print(f"\n[SCAN] {filename}")

            code = get_staged_content(filename)

            result = analyze_file(
                filename,
                code
            )

            status, vulnerabilities, needs_review = (
                validate_response(result)
            )

            print(
                "[HASH] SHA-256:",
                result["sha256"]
            )

            if status == "rejected":
                blocked = True

                print(
                    "[BLOCK] Vulnerabilidades detectadas"
                )

                print_findings(vulnerabilities)

            elif status == "review_required":
                blocked = True

                print(
                    "[REVIEW] Hallazgos que requieren "
                    "revisión de seguridad"
                )

                print_findings(needs_review)

            elif status == "approved":
                print(
                    "[OK] Sin hallazgos reportados"
                )

        if blocked:
            print(
                "\n[BLOCK] Commit rechazado por AppSec."
            )
            return 1

        print(
            "\n[OK] Análisis completado. "
            "Commit permitido."
        )
        return 0

    except (
        subprocess.CalledProcessError,
        UnicodeError,
        ValueError,
        KeyError,
        urllib.error.URLError,
        TimeoutError,
        OSError,
    ) as exc:
        print(
            f"\n[ERROR] El análisis no pudo "
            f"completarse: {exc}"
        )

        print(
            "[BLOCK] No se permite el commit "
            "sin una evaluación válida."
        )

        return 1


if __name__ == "__main__":
    sys.exit(main())
