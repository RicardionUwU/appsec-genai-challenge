
"""
Pruebas unitarias del validador de evidencias.

No requieren:
- Auth0
- Ollama
- Docker
- FastAPI
"""

import unittest

from backend.analyzer import (
    Vulnerability,
    validate_findings,
)


def make_finding(
    line=1,
    evidence="os.system(command)",
):
    return Vulnerability(
        type="Command Injection",
        owasp="A03:2021 - Injection",
        severity="HIGH",
        description="Hallazgo de prueba",
        recommendation="Evitar comandos arbitrarios",
        line=line,
        evidence=evidence,
    )


class TestAnalyzerValidation(unittest.TestCase):

    def test_valid_evidence(self):
        result = validate_findings(
            "os.system(command)",
            [make_finding()],
        )

        self.assertEqual(len(result), 1)
        self.assertTrue(
            result[0]["evidence_verified"]
        )

    def test_invented_evidence_rejected(self):
        finding = make_finding(
            evidence="SELECT * FROM users",
        )

        with self.assertRaises(ValueError):
            validate_findings(
                "print(123)",
                [finding],
            )

    def test_nonexistent_line_rejected(self):
        finding = make_finding(line=999)

        with self.assertRaises(ValueError):
            validate_findings(
                "os.system(command)",
                [finding],
            )

    def test_duplicate_findings(self):
        finding = make_finding()

        result = validate_findings(
            "os.system(command)",
            [finding, finding],
        )

        self.assertEqual(len(result), 1)

    def test_no_findings(self):
        result = validate_findings(
            "print('Hello')",
            [],
        )

        self.assertEqual(result, [])


if __name__ == "__main__":
    unittest.main()
