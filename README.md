# AppSec GenAI — MercadoLibre Challenge

**Análisis de seguridad de código fuente con GenAI, autenticación OAuth 2.0 y verificación criptográfica de integridad de commits.**

## 1. Descripción

AppSec GenAI es una solución de seguridad integrada con Git que analiza código fuente antes de crear un commit y verifica remotamente la integridad de los commits antes de incorporarlos a una rama protegida.

La solución combina:

- **Semgrep:** análisis estático de patrones de seguridad.
- **Ollama + Qwen2.5-Coder 7B:** análisis de código asistido por un modelo de lenguaje.
- **Policy Engine:** consolidación de hallazgos y aplicación de políticas.
- **FastAPI:** servicio de análisis y firma.
- **Auth0:** autenticación OAuth 2.0 / OpenID Connect y autorización basada en permisos.
- **Ed25519:** emisión de constancias criptográficas.
- **GitHub Actions:** verificación independiente de los commits recibidos.

El objetivo es detectar posibles vulnerabilidades relacionadas con **OWASP Top 10 2021**, explicar los riesgos identificados, ofrecer recomendaciones de mitigación y evitar que la omisión del hook local sea suficiente para eludir la política de integridad.

El proyecto constituye una implementación funcional de laboratorio. No debe interpretarse como una plataforma productiva completamente endurecida.

## 2. Arquitectura

### Flujo de análisis

```text
Developer
    |
    v
Git staging area
    |
    v
pre-commit hook
    |
    | Access token OAuth 2.0
    v
FastAPI - AppSec API
    |
    +----> Semgrep (SAST)
    |
    +----> Ollama / Qwen2.5-Coder 7B
    |
    v
Policy Engine
    |
    +----> rejected
    |
    +----> review_required
    |
    +----> approved
               |
               v
       Ed25519 signed manifest
               |
               v
         commit-msg hook
               |
               v
           Git commit
               |
               v
          Pull Request
               |
               v
         GitHub Actions
               |
               v
      Cryptographic verification
               |
               v
      Required repository check
```

### Componentes principales

| Componente | Responsabilidad |
|---|---|
| `hooks/pre_commit.py` | Recuperar el contenido preparado en Git, obtener la credencial OAuth y solicitar el análisis |
| `hooks/commit_msg.py` | Vincular la constancia AppSec al mensaje del commit |
| `auth_client/login.py` | Autenticación mediante Authorization Code con PKCE |
| `auth_client/token_store.py` | Recuperación y almacenamiento local de credenciales |
| `backend/main.py` | API FastAPI, autorización, análisis y controles HTTP |
| `backend/auth.py` | Validación de JWT y permisos |
| `backend/semgrep_analyzer.py` | Análisis estático con Semgrep |
| `backend/analyzer.py` | Análisis GenAI, fragmentación y validación de hallazgos |
| `backend/prompts/security_review.txt` | Instrucciones de revisión para el modelo |
| `backend/policy_engine.py` | Consolidación de resultados y decisión |
| `backend/attestations.py` | Generación y verificación de constancias Ed25519 |
| `scripts/verify_commit.py` | Comprobaciones criptográficas y de integridad Git |
| `scripts/ci_verify.py` | Verificación desde un contexto de CI |
| `.github/workflows/appsec-integrity.yml` | Automatización de la validación remota |
| `rules/python-security.yaml` | Reglas de seguridad Python |
| `tests/` | Pruebas unitarias y de integración |

### Modelo de despliegue

Actualmente FastAPI, Docker y Ollama funcionan como servicios locales de laboratorio.

El análisis se ejecuta del lado del servicio FastAPI, no mediante instrucciones confiadas al repositorio analizado.

Para una instalación empresarial sería necesario aislar el servidor de análisis, el proceso firmante, las credenciales y la infraestructura de ejecución de las estaciones de trabajo de los desarrolladores.

## 3. Modelo de seguridad

### Autenticación y autorización

El cliente utiliza **OAuth 2.0 Authorization Code con PKCE S256** mediante Auth0.

El backend valida los tokens de acceso mediante claves públicas del proveedor de identidad y comprueba sus propiedades de seguridad, incluyendo firma, emisor, audiencia, vigencia, identidad del cliente autorizado y permisos.

El permiso `analyze:code` permite utilizar los endpoints de análisis.

El permiso `review:findings` está definido para operaciones de revisión de seguridad, pero el workflow funcional del reviewer todavía no forma parte de los entregables completados.

La decisión de autorización corresponde a FastAPI, no al hook ni a una interfaz cliente.

### Política de análisis

Semgrep y Ollama producen resultados independientes. El Policy Engine los combina y establece la decisión.

| Situación | Resultado |
|---|---|
| Semgrep encuentra una vulnerabilidad bloqueante | `rejected` |
| El modelo reporta un hallazgo que requiere validación | `review_required` |
| No se identifican hallazgos bloqueantes ni pendientes | `approved` |
| Un motor falla o la integridad es inconsistente | Error; no se emite aprobación |

Los resultados del LLM se someten a validaciones de estructura, líneas y evidencia.

Una evidencia textualmente presente en el archivo no implica necesariamente que exista una vulnerabilidad explotable. El sistema puede producir falsos positivos y falsos negativos.

### Integridad de los commits

Cuando el análisis cumple la política de aprobación, el servicio puede emitir una constancia firmada con **Ed25519**.

El manifiesto vincula información relevante de la evaluación, incluyendo:

- Identidad del repositorio.
- Árbol Git analizado.
- Commit padre.
- Archivos cubiertos por el análisis.
- Huellas de contenido.
- Identidad de la clave de firma.
- Huella de la política de seguridad.

El hook `commit-msg` incorpora la constancia al mensaje del commit.

GitHub Actions comprueba criptográficamente la constancia y su correspondencia con los objetos Git reales.

Las claves públicas de verificación se publican en `.github/appsec/keys/`.

La clave privada no debe almacenarse en el repositorio.

### Límites de confianza

**El hook local no es una frontera de seguridad confiable.**

Un usuario puede modificarlo, omitirlo o deshabilitarlo. Por ello, la protección principal frente a ese escenario consiste en la verificación remota obligatoria.

Sin embargo, la garantía depende de que:

1. La clave privada y el proceso de firma permanezcan bajo control de una entidad confiable.
2. El verificador y su política no puedan ser alterados por el desarrollador.
3. La protección de ramas se aplique efectivamente.
4. El estado obligatorio de GitHub proceda de una fuente confiable.

En el laboratorio, el servicio firmante se ejecuta localmente. Esto demuestra el mecanismo criptográfico, pero **no equivale al aislamiento de un firmante independiente administrado por un equipo de seguridad**.

La demostración acredita resistencia frente a la omisión del hook local en los escenarios probados; no acredita invulnerabilidad frente a todos los posibles atacantes.

## 4. Categorías OWASP Top 10

La implementación contiene reglas de Semgrep y pruebas para cinco categorías de OWASP Top 10 2021.

| Categoría | Riesgo evaluado | Ejemplo |
|---|---|---|
| A02:2021 — Cryptographic Failures | Uso de mecanismos criptográficos débiles | Hash inseguro para contraseñas |
| A03:2021 — Injection | Ejecución de instrucciones no confiables | `os.system(command)` |
| A05:2021 — Security Misconfiguration | Configuración insegura | Flask en modo debug |
| A08:2021 — Software and Data Integrity Failures | Procesamiento inseguro de datos | `pickle.loads()` sobre datos no confiables |
| A10:2021 — Server-Side Request Forgery | Peticiones a destinos controlados por usuarios | URL suministrada sin validación |

Las pruebas estáticas incluyen ejemplos vulnerables y seguros.

**Importante:** la validación estática de cinco categorías no demuestra por sí sola que el LLM detecte correctamente las cinco. Las capacidades de GenAI deben evaluarse adicionalmente mediante pruebas end-to-end y resultados registrados.

## 5. Instalación

### Requisitos

- Git.
- **Python 3.13**, utilizado en la prueba de instalación reproducible.
- Docker Desktop, para la ejecución de Semgrep.
- Ollama.
- Modelo `qwen2.5-coder:7b`.
- Tenant Auth0 configurado.
- Aplicación Auth0 de tipo Native.
- API Auth0 con audiencia y permisos definidos.
- Clave privada Ed25519 provisionada para el servicio firmante.

### Clonar el repositorio

Desde PowerShell:

```powershell
git clone https://github.com/RicardionUwU/appsec-genai-challenge.git
```

```powershell
cd appsec-genai-challenge
```

### Crear el entorno virtual

```powershell
py -3.13 -m venv .venv
```

### Activar el entorno en PowerShell

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force; .\.venv\Scripts\Activate.ps1
```

La modificación de la política de ejecución se limita a la sesión actual de PowerShell.

### Instalar dependencias

```powershell
python -m pip install -r requirements.txt
```

### Verificar compatibilidad

```powershell
python -m pip check
```

Resultado esperado en una instalación limpia compatible:

```text
No broken requirements found.
```

Las dependencias Python fueron probadas en un entorno limpio con Python 3.13.

Semgrep se ejecuta mediante Docker en esta arquitectura; no es necesario instalar el paquete Python de Semgrep dentro del mismo entorno virtual de FastAPI.

### Instalar el modelo local

```powershell
ollama pull qwen2.5-coder:7b
```

Verificar los modelos disponibles:

```powershell
ollama list
```

El servicio Ollama debe estar disponible en `127.0.0.1:11434`.

### Configurar variables de entorno

Crear `.env` solamente si no existe:

```powershell
if (-not (Test-Path .env)) { Copy-Item .env.example .env } else { Write-Host "[INFO] .env ya existe y no sera sobrescrito" }
```

**Advertencia:** nunca sobrescribir un `.env` previamente configurado con `.env.example`, porque se reemplazarían los valores reales por placeholders.

Editar el archivo `.env` y configurar los parámetros correspondientes.

#### Auth0

| Variable | Descripción |
|---|---|
| `AUTH0_DOMAIN` | Dominio exacto del tenant Auth0, sin `https://` |
| `AUTH0_AUDIENCE` | Identifier de la API Auth0 |
| `AUTH0_CLIENT_ID` | Client ID de la aplicación Native |
| `AUTH0_ALLOWED_CLIENT_IDS` | Lista de clientes OAuth autorizados |
| `AUTH0_REDIRECT_URI` | Callback de Authorization Code + PKCE |

El dominio puede incluir un sufijo regional como `.us.auth0.com`. Debe copiarse exactamente desde la configuración real del tenant.

La audiencia `https://appsec-api.local` es un identificador OAuth; no es una dirección a la que deba enviarse tráfico HTTP.

Para el cliente de desarrollo, configurar el callback:

`http://127.0.0.1:8765/callback`

La API Auth0 debe tener RBAC habilitado e incluir los permisos pertinentes en el access token.

El desarrollador necesita `analyze:code`.

#### Ollama y FastAPI

| Variable | Valor de laboratorio |
|---|---|
| `OLLAMA_URL` | `http://127.0.0.1:11434/api/chat` |
| `OLLAMA_MODEL` | `qwen2.5-coder:7b` |
| `APPSEC_API_URL` | `http://127.0.0.1:8000` |
| `APP_ENV` | `development` |

#### Firma Ed25519

| Variable | Descripción |
|---|---|
| `APPSEC_REPOSITORY` | Identidad del repositorio autorizado |
| `APPSEC_SIGNING_KEY_ID` | Identificador de la clave pública confiable |
| `APPSEC_SIGNING_KEY_PATH` | Ruta absoluta de la clave privada |

La clave pública correspondiente debe estar registrada en `.github/appsec/keys/`.

En una instalación nueva, un administrador debe provisionar el par Ed25519 y registrar su clave pública e identificador en el contexto de confianza apropiado.

No basta con declarar un identificador de clave arbitrario: debe corresponder a la clave real utilizada por el firmante.

**La clave privada no debe distribuirse con el código ni incorporarse a Git.**

En este laboratorio la clave privada se conserva fuera del directorio del repositorio. En un despliegue empresarial se recomienda un servicio de firma aislado o una solución de gestión de claves adecuada.

### Protección de secretos

No incorporar al repositorio:

- `.env` con configuración privada.
- Access tokens o refresh tokens.
- Contraseñas.
- Claves privadas.
- Archivos de credenciales locales.

El archivo `.env.example` contiene únicamente valores de referencia y placeholders.

## 6. Puesta en marcha

### Iniciar servicios

Iniciar Docker Desktop y comprobar que Ollama está disponible.

En una terminal, iniciar FastAPI desde la raíz del repositorio:

```powershell
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --env-file .env
```

En otra terminal, activar el entorno virtual:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force; .\.venv\Scripts\Activate.ps1
```

### Verificar disponibilidad

```powershell
curl.exe -i http://127.0.0.1:8000/health
```

Resultado esperado:

```text
HTTP/1.1 200 OK

{"status":"healthy"}
```

El endpoint `/health` confirma disponibilidad básica. No demuestra por sí solo que Auth0, Docker, Ollama y el firmante estén operativos.

### Autenticarse

```powershell
python -m auth_client.login
```

El cliente inicia el flujo OAuth 2.0 Authorization Code + PKCE.

Después de una autenticación correcta, el cliente valida la identidad y los permisos requeridos para el análisis.

Las credenciales se almacenan mediante el mecanismo local de `keyring`, no en el repositorio.

### Instalar los hooks de Git

```powershell
python -m pre_commit install --hook-type pre-commit --hook-type commit-msg
```

Los hooks configurados en `.pre-commit-config.yaml` son:

- `appsec-genai`
- `appsec-genai-commit-msg`

El primero solicita el análisis y, cuando corresponde, obtiene la constancia.

El segundo incorpora la constancia al mensaje del commit.

### Ejecutar un commit

Preparar únicamente los archivos que se desean incluir:

```powershell
git add -- src/archivo.py
```

Ejecutar el commit normalmente:

```powershell
git commit -m "feat: add analyzed code"
```

El análisis se realiza contra el contenido preparado en Git, no simplemente contra archivos sin guardar en el editor.

Si el resultado es bloqueante o el análisis falla, el hook no concede aprobación.

**No se debe utilizar `SKIP` ni deshabilitar los hooks como procedimiento normal de desarrollo.**

## 7. Ejemplos de detección

### Ejemplo vulnerable — A03:2021 Injection

Archivo de demostración local: `examples/vulnerable.py`.

```python
import os

def execute(command):
    os.system(command)
```

La operación `os.system()` invoca el intérprete de comandos del sistema.

Si recibe datos controlados por un atacante, puede permitir ejecución no autorizada de comandos.

**Resultado estático comprobado:**

```text
TOTAL: 1
RULES: rules.appsec-python-command-injection
```

El ejemplo demuestra un sink inseguro; no incluye por sí solo una fuente explícita de entrada externa.

**Estado de entrega:** este ejemplo se ha probado localmente, pero debe incorporarse al repositorio mediante un procedimiento administrativo controlado antes de considerarlo publicado.

### Ejemplo seguro

Archivo versionado: `examples/secure.py`.

```python
def calculate_total(a: int, b: int) -> int:
    return a + b

def greet_user(name: str) -> str:
    return f"Hola, {name}"
```

**Resultado estático comprobado:**

```text
TOTAL: 0
```

Este archivo sirve como control negativo de detección. No es una corrección directa del ejemplo vulnerable.

### Política para ejemplos intencionalmente vulnerables

Los ejemplos vulnerables son material educativo y deben identificarse claramente como tales.

Su incorporación inicial debe realizarse mediante un proceso administrativo documentado, sin introducir una exclusión general que permita a cualquier desarrollador agregar código vulnerable arbitrario.

Las modificaciones futuras a los ejemplos deben permanecer sujetas a la política de integridad del repositorio.

## 8. Pruebas

### Prueba rápida del analizador

```powershell
python -m unittest discover -s tests -p "test_analyzer_validation.py" -v
```

Esta suite verifica evidencia válida, evidencia inventada, líneas inexistentes, deduplicación y resultados sin hallazgos.

### Pruebas de integridad de commits

```powershell
python -m unittest discover -s tests -p "test_verify_commit.py" -v
```

Se incluyen escenarios de cambios de código, ausencia de constancias, archivos no cubiertos, firmas manipuladas, políticas protegidas y commits válidos.

### Pruebas de integración de hooks

```powershell
python -m unittest discover -s tests -p "test_hook_integration.py" -v
```

Verifican comportamientos de rechazo, integridad del staging y vinculación de constancias.

### Pruebas OWASP con Semgrep

```powershell
python -m unittest discover -s tests -p "test_semgrep_owasp.py" -v
```

Estas pruebas requieren disponibilidad del motor Semgrep y pueden tardar considerablemente más que las pruebas unitarias.

### Suite completa

```powershell
python -m unittest discover -s tests -p "test_*.py" -v
```

Las pruebas de seguridad no sustituyen una evaluación de penetración completa ni garantizan ausencia de vulnerabilidades.

## 9. Evidencias de integridad remota

### Prueba negativa: omisión del hook local

Se creó intencionalmente un commit sin ejecutar los hooks de seguridad locales.

El verificador remoto detectó la ausencia de una constancia AppSec válida y publicó un estado fallido.

**Evidencia:** [Pull Request #1 — Evasión del hook local](https://github.com/RicardionUwU/appsec-genai-challenge/pull/1).

### Prueba positiva: commit analizado y firmado

Se ejecutó el flujo legítimo:

1. Autenticación del desarrollador con Auth0.
2. Análisis del código mediante FastAPI.
3. Evaluación del Policy Engine.
4. Emisión de constancia Ed25519.
5. Incorporación de la constancia al commit.
6. Verificación independiente mediante GitHub Actions.

GitHub mostró que las verificaciones de la prueba positiva fueron exitosas y que el PR podía integrarse.

**Evidencia:** [Pull Request #2 — Commit firmado](https://github.com/RicardionUwU/appsec-genai-challenge/pull/2).

Estas pruebas demuestran el mecanismo ante dos escenarios concretos: commit sin constancia y commit legítimo firmado.

No demuestran que un usuario con control del servidor firmante, de la clave privada o de los mecanismos administrativos del repositorio sea incapaz de alterar el proceso.

## 10. Prompt y protección frente a prompt injection

Las instrucciones del modelo se mantienen en:

`backend/prompts/security_review.txt`

El código enviado por el desarrollador se considera **datos no confiables**, incluso cuando contiene comentarios o cadenas con instrucciones dirigidas al analizador.

Las principales defensas implementadas o previstas incluyen:

- Separación del prompt de revisión respecto al código analizado.
- Solicitud de resultados estructurados.
- Validación de campos y evidencias reportadas.
- Rechazo de evidencias inexistentes o inconsistentes.
- Política conservadora cuando no se puede completar una evaluación confiable.

La validación de evidencias reduce alucinaciones verificables, pero no resuelve por completo la inyección de instrucciones ni garantiza la interpretación correcta del código.

**Estado de validación:** las pruebas adversariales específicas de prompt injection deben completarse y sus resultados documentarse antes de afirmar resistencia comprobada frente a esta técnica.

## 11. Monitoreo de evasiones

La solución dispone de señales que pueden utilizarse para identificar intentos de omitir o manipular las verificaciones de seguridad.

### Señales relevantes

| Señal | Interpretación |
|---|---|
| Commit sin constancia | Posible omisión del hook |
| Firma Ed25519 inválida | Constancia manipulada o clave incorrecta |
| Árbol Git diferente al analizado | Cambio de contenido después del análisis |
| Commit padre diferente | Inconsistencia del contexto Git |
| Política SHA-256 diferente | Cambio de política o inconsistencia de confianza |
| Archivo no cubierto por la constancia | Contenido fuera del alcance analizado |
| Fallo de autenticación | Credencial inválida, vencida o sin permisos |
| Servicio de análisis no disponible | La aprobación no debe emitirse |

### Respuesta

Ante fallos relevantes, el sistema no debe conceder una aprobación automática.

La evidencia se conserva mediante el estado de los checks, sus registros y los eventos del Pull Request.

### Monitoreo recomendado para producción

Se recomienda complementar el laboratorio con:

- Centralización y retención de registros.
- Alertas por fallos repetidos de integridad.
- Monitoreo de modificaciones a workflows y reglas de seguridad.
- Control de acceso administrativo y revisión de excepciones.
- Rotación de claves y procedimientos de respuesta ante compromiso.
- Restricción del emisor autorizado del estado obligatorio.

El repositorio de laboratorio permite demostrar las verificaciones remotas, pero no incluye necesariamente una plataforma completa de observabilidad y alertamiento.

## 12. Limitaciones, escalabilidad y evolución

### Limitaciones actuales

- El modelo se ejecuta localmente mediante Ollama.
- Los tiempos de análisis dependen del hardware disponible.
- Semgrep depende del entorno de ejecución Docker.
- El LLM puede generar falsos positivos y falsos negativos.
- La fragmentación facilita procesar código extenso, pero puede perder contexto entre fragmentos.
- El servicio firmante de laboratorio no está aislado de la estación de desarrollo.
- El flujo funcional de revisión manual todavía no está implementado.
- La interfaz de usuario todavía no está disponible.
- Las pruebas adversariales de prompt injection requieren evidencia adicional.

### Consideraciones de escalabilidad

En un despliegue empresarial se podrían incorporar colas de análisis, control de concurrencia, límites de recursos, caché por hash de contenido y procesamiento distribuido.

Para reducir la fricción sobre el desarrollador, se recomienda analizar solamente los cambios relevantes cuando la política lo permita, reutilizar resultados verificables y comunicar claramente el motivo de cualquier bloqueo.

Las optimizaciones no deben permitir reutilizar aprobaciones para contenido distinto del originalmente analizado.

### Riesgos de configuración remota

El estado obligatorio de GitHub debe asociarse, cuando la plataforma lo permita, con una aplicación emisora confiable.

La opción `Any source` es menos estricta que una fuente identificada y constituye un punto de endurecimiento pendiente.

Las reglas administrativas y los permisos de bypass también forman parte de la frontera de confianza.

### Mejoras futuras

- Flujo completo y auditable para el rol `appsec-reviewer`.
- Interfaz amigable para desarrolladores y revisores.
- Extensión a JavaScript/TypeScript y otros lenguajes.
- Pruebas adversariales ampliadas.
- Métricas de precisión y tiempos de análisis.
- Aislamiento del firmante en infraestructura confiable.
- Controles adicionales de sesión, revocación y protección de credenciales.

## 13. Consideraciones finales

El principio central de este proyecto es:

**No confiar en que el desarrollador ejecute correctamente el hook local.**

La solución combina autenticación, análisis de código, políticas de aprobación y constancias criptográficas verificadas remotamente.

Las demostraciones realizadas muestran que:

- Una evasión concreta del hook local puede detectarse y bloquearse desde GitHub.
- Un commit legítimo puede aprobarse después de un análisis y una verificación de integridad exitosos.

El diseño representa una base técnica para integrar GenAI en controles de AppSec, con limitaciones explícitas sobre el alcance de sus garantías y las mejoras necesarias antes de un despliegue de producción.