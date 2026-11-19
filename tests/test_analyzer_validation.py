
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

    def test_nonexistent_line_corrected(self):
        finding = make_finding(line=999)
        result = validate_findings('os.system(command)', [finding])
        self.assertEqual(result[0]['line'], 1)
        self.assertTrue(result[0]['line_corrected'])
        self.assertTrue(result[0]['evidence_verified'])

    def test_nonexistent_line_with_invented_evidence_rejected(self):
        finding = make_finding(line=999, evidence='os.system(other)')
        with self.assertRaises(ValueError):
            validate_findings('os.system(command)', [finding])

    def test_ambiguous_line_rejected(self):
        finding = make_finding(line=999)
        code = chr(10).join(['os.system(command)', 'os.system(command)'])
        with self.assertRaises(ValueError):
            validate_findings(code, [finding])

    def test_in_range_mismatched_line_reconciled(self):
        finding = make_finding(line=1)
        code = chr(10).join(['print(123)', 'os.system(command)'])
        result = validate_findings(code, [finding])
        self.assertEqual(result[0]['line'], 2)
        self.assertTrue(result[0]['line_corrected'])

    def test_missing_indentation_reconciled(self):
        src = chr(10).join(['def execute():', '    os.system(command)'])
        result = validate_findings(src, [make_finding(line=2, evidence='os.system(command)')])
        self.assertEqual(result[0]['line'], 2)
        self.assertEqual(result[0]['evidence'], '    os.system(command)')
        self.assertTrue(result[0]['evidence_verified'])
        self.assertTrue(result[0]['line_corrected'])

    def test_missing_indentation_ambiguous_rejected(self):
        src = chr(10).join(['def first():', '    os.system(command)', 'def second():', '    os.system(command)'])
        with self.assertRaises(ValueError):
            validate_findings(src, [make_finding(line=999, evidence='os.system(command)')])

    def test_indentation_does_not_hide_forged_evidence(self):
        with self.assertRaises(ValueError):
            validate_findings('    os.system(command)', [make_finding(line=1, evidence='os.system(other)')])

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
