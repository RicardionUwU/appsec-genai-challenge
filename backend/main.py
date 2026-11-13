
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(
    title="MercadoLibre AppSec GenAI",
    description="API para análisis de seguridad de código fuente",
    version="1.0.0"
)


class CodeAnalysisRequest(BaseModel):
    filename: str
    code: str


@app.get("/")
def home():
    return {
        "application": "AppSec GenAI",
        "status": "running",
        "message": "Backend funcionando correctamente"
    }


@app.get("/health")
def health():
    return {"status": "healthy"}


@app.post("/analyze")
def analyze_code(request: CodeAnalysisRequest):
    return {
        "filename": request.filename,
        "status": "received",
        "message": "Código recibido correctamente",
        "lines": len(request.code.splitlines())
    }
