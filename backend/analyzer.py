
import json
import os
from pathlib import Path

import httpx
from pydantic import BaseModel, Field


OLLAMA_URL = os.getenv(
    "OLLAMA_URL",
    "http://127.0.0.1:11434/api/chat"
)

OLLAMA_MODEL = os.getenv(
    "OLLAMA_MODEL",
    "qwen2.5-coder:3b"
)

PROMPT_PATH = (
    Path(__file__).parent
    / "prompts"
    / "security_review.txt"
)


class Vulnerability(BaseModel):
    type: str
    owasp: str
    severity: str
    description: str
    recommendation: str


class AnalysisResult(BaseModel):
    vulnerabilities: list[Vulnerability] = Field(
        default_factory=list
    )


async def analyze_with_ai(filename: str, code: str):
    """
    Envía código al modelo de IA y valida
    la estructura del resultado.
    """

    security_prompt = PROMPT_PATH.read_text(
        encoding="utf-8"
    )

    payload = {
        "model": OLLAMA_MODEL,
        "stream": False,
        "format": "json",
        "options": {
            "temperature": 0
        },
        "messages": [
            {
                "role": "system",
                "content": security_prompt
            },
            {
                "role": "user",
                "content": json.dumps({
                    "filename": filename,
                    "code": code
                })
            }
        ]
    }

    async with httpx.AsyncClient(
        timeout=180.0
    ) as client:
        response = await client.post(
            OLLAMA_URL,
            json=payload
        )
        response.raise_for_status()

    ollama_response = response.json()

    ai_content = ollama_response[
        "message"
    ]["content"]

    result = AnalysisResult.model_validate_json(
        ai_content
    )

    return {
        "filename": filename,
        "status": (
            "rejected"
            if result.vulnerabilities
            else "approved"
        ),
        "vulnerabilities": [
            vulnerability.model_dump()
            for vulnerability in result.vulnerabilities
        ]
    }
