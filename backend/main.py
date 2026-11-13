
import httpx

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field, ValidationError

from backend.analyzer import analyze_with_ai


app = FastAPI(
    title="MercadoLibre AppSec GenAI",
    description="AI-Powered Security Code Review",
    version="1.1.0"
)


class CodeAnalysisRequest(BaseModel):
    filename: str = Field(
        min_length=1,
        max_length=255
    )
    code: str = Field(
        min_length=1,
        max_length=100000
    )


@app.get("/")
def home():
    return {
        "application": "AppSec GenAI",
        "status": "running"
    }


@app.get("/health")
def health():
    return {"status": "healthy"}


@app.post("/analyze")
async def analyze_code(request: CodeAnalysisRequest):
    try:
        return await analyze_with_ai(
            filename=request.filename,
            code=request.code
        )

    except (
        httpx.HTTPError,
        ValidationError,
        ValueError,
        KeyError
    ):
        raise HTTPException(
            status_code=503,
            detail=(
                "El análisis de seguridad no pudo "
                "completarse. No se emite aprobación."
            )
        )
