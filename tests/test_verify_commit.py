
"""
AppSec GenAI - Git Integrity Verification Tests

Pruebas de seguridad sobre commits Git reales.

No requieren:
- Auth0
- Ollama
- Docker
- FastAPI
- GitHub

Validan:
1. Commit firmado correctamente.
2. Constancia ausente.
3. Archivo no cubierto por el manifiesto.
4. Codigo modificado despues de firmar.
5. Cambios adicionales sin aprobacion.
6. Firma criptografica manipulada.
7. Modificacion de controles protegidos.
8. Commit exclusivamente documental.
9. Archivo Python dentro de subdirectorios.
"""

import subprocess
import tempfile
import unittest

from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from backend.attestations import (
    ApprovedAnalysis,
    issue_signed_manifest,
)

from scripts.verify_commit import (
    VerificationError,
    verify_commit_range,
)


class TestCommitIntegrity(unittest.TestCase):

    # ======================================
    # TEST ENVIRONMENT
    # ======================================

    def setUp(self):

        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

        self.repo = Path(self.temp.name)

        # Clave temporal, nunca la real.
        self.key = Ed25519PrivateKey.generate()

        self.policy = "a" * 64
        self.repository = "example/security-demo"
        self.model = "qwen2.5-coder:7b"
        self.kid = "test-key"

        self.git("init", "-q")

        self.git(
            "config",
            "user.name",
            "AppSec Test",
        )

        self.git(
            "config",
            "user.email",
            "appsec@example.invalid",
        )

        # Evitar alteraciones de saltos
        # de linea en Windows.
        self.git(
            "config",
            "core.autocrlf",
            "false",
        )

        self.git(
            "config",
            "core.safecrlf",
            "false",
        )

        # Evitar ejecutar hooks instalados
        # por configuraciones globales
        # durante las pruebas temporales.
        self.git(
            "config",
            "core.hooksPath",
            ".git/no-hooks",
        )

        # Commit base confiable.
        (
            self.repo / "README.md"
        ).write_text(
            "Trusted base\n",
            encoding="utf-8",
        )

        self.git("add", "README.md")

        self.git(
            "commit",
            "-q",
            "-m",
            "Trusted base",
        )

        self.base = self.git(
            "rev-parse",
            "HEAD",
        ).strip()

        self.signed_tree = None

    # ======================================
    # GIT HELPER
    # ======================================

    def git(self, *args):

        process = subprocess.run(
            [
                "git",
                "-C",
                str(self.repo),
                *args,
            ],
            capture_output=True,
            text=True,
            check=True,
            shell=False,
            timeout=30,
        )

        return process.stdout

    # ======================================
    # VERIFIER HELPER
    # ======================================

    def verify(self, head):

        return verify_commit_range(
            repository_path=self.repo,
            base_oid=self.base,
            head_oid=head,
            repository=self.repository,
            trusted_public_keys={
                self.kid: self.key.public_key(),
            },
            policy_sha256=self.policy,
            model_id=self.model,
        )

    # ======================================
    # SIGNED COMMIT FACTORY
    # ======================================

    def signed_commit(
        self,
        *,
        path="app.py",
        add_uncovered_file=False,
        corrupt_signature=False,
        tamper_after_signing=False,
    ):
        """
        Construye escenarios de prueba
        utilizando objetos Git reales.

        Nunca utiliza el repositorio
        principal del challenge.
        """

        content = b"print(123)\n"

        file_path = self.repo / path

        file_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        file_path.write_bytes(content)

        self.git(
            "add",
            "--",
            path,
        )

        # ==================================
        # OPTIONAL UNANALYZED FILE
        # ==================================

        if add_uncovered_file:

            extra = self.repo / "extra.py"

            extra.write_text(
                "print('not analyzed')\n",
                encoding="utf-8",
            )

            self.git(
                "add",
                "--",
                "extra.py",
            )

        # ==================================
        # REAL GIT TREE
        # ==================================

        parent = self.git(
            "rev-parse",
            "HEAD",
        ).strip()

        tree = self.git(
            "write-tree",
        ).strip()

        self.signed_tree = tree

        # ==================================
        # SIGN ONLY THE ANALYZED FILE
        # ==================================

        receipt = issue_signed_manifest(
            subject="auth0|test-developer",
            repository=self.repository,
            git_tree_oid=tree,
            parent_oid=parent,
            policy_sha256=self.policy,
            model_id=self.model,
            analyses=[
                ApprovedAnalysis(
                    path=path,
                    content=content,
                    mode="100644",
                    status="approved",
                ),
            ],
            private_key=self.key,
            key_id=self.kid,
        )

        # ==================================
        # OPTIONAL SIGNATURE TAMPERING
        # ==================================

        if corrupt_signature:

            parts = receipt.split(".")

            signature = parts[2]

            replacement = (
                "A"
                if signature[0] != "A"
                else "B"
            )

            parts[2] = (
                replacement
                + signature[1:]
            )

            receipt = ".".join(parts)

        # ==================================
        # OPTIONAL POST-SIGNING MODIFICATION
        # ==================================

        if tamper_after_signing:

            file_path.write_text(
                "print('modified after approval')\n",
                encoding="utf-8",
            )

            self.git(
                "add",
                "--",
                path,
            )

        # ==================================
        # CREATE ACTUAL COMMIT
        # ==================================

        self.git(
            "commit",
            "-q",
            "-m",
            "Security test",
            "-m",
            "AppSec-Attestation: " + receipt,
        )

        return self.git(
            "rev-parse",
            "HEAD",
        ).strip()

    # ======================================
    # TEST 1 - VALID SIGNED COMMIT
    # ======================================

    def test_valid_signed_commit(self):

        head = self.signed_commit()

        self.assertEqual(
            self.verify(head),
            1,
        )

    # ======================================
    # TEST 2 - MISSING ATTESTATION
    # ======================================

    def test_missing_attestation_rejected(self):

        (
            self.repo / "app.py"
        ).write_text(
            "print('unsigned')\n",
            encoding="utf-8",
        )

        self.git("add", "app.py")

        self.git(
            "commit",
            "-q",
            "-m",
            "Unsigned source code",
        )

        head = self.git(
            "rev-parse",
            "HEAD",
        ).strip()

        with self.assertRaises(
            VerificationError
        ):
            self.verify(head)

    # ======================================
    # TEST 3 - INCOMPLETE COVERAGE
    # ======================================

    def test_uncovered_file_rejected(self):

        head = self.signed_commit(
            add_uncovered_file=True,
        )

        actual_tree = self.git(
            "rev-parse",
            f"{head}^{{tree}}",
        ).strip()

        # El arbol coincide con el firmado.
        self.assertEqual(
            actual_tree,
            self.signed_tree,
        )

        # Pero extra.py no esta incluido
        # en el manifiesto.
        with self.assertRaises(
            VerificationError
        ) as context:
            self.verify(head)

        cause = context.exception.__cause__

        self.assertIsNotNone(cause)

        self.assertIn(
            "Los archivos remotos no coinciden",
            str(cause),
        )

    # ======================================
    # TEST 4 - MODIFICATION AFTER SIGNING
    # ======================================

    def test_modified_tree_rejected(self):

        head = self.signed_commit(
            tamper_after_signing=True,
        )

        actual_tree = self.git(
            "rev-parse",
            f"{head}^{{tree}}",
        ).strip()

        self.assertNotEqual(
            actual_tree,
            self.signed_tree,
        )

        with self.assertRaises(
            VerificationError
        ):
            self.verify(head)

    # ======================================
    # TEST 5 - UNAPPROVED SUBSEQUENT CHANGE
    # ======================================

    def test_changed_code_rejected(self):

        # Primer commit firmado.
        self.signed_commit()

        # Segundo commit sin aprobacion.
        (
            self.repo / "app.py"
        ).write_text(
            "print('unapproved change')\n",
            encoding="utf-8",
        )

        self.git("add", "app.py")

        self.git(
            "commit",
            "-q",
            "-m",
            "Unapproved change",
        )

        head = self.git(
            "rev-parse",
            "HEAD",
        ).strip()

        with self.assertRaises(
            VerificationError
        ):
            self.verify(head)

    # ======================================
    # TEST 6 - TAMPERED ED25519 SIGNATURE
    # ======================================

    def test_tampered_signature_rejected(self):

        head = self.signed_commit(
            corrupt_signature=True,
        )

        with self.assertRaises(
            VerificationError
        ):
            self.verify(head)

    # ======================================
    # TEST 7 - PROTECTED POLICY MODIFICATION
    # ======================================

    def test_protected_policy_rejected(self):

        rules = self.repo / "rules"
        rules.mkdir()

        (
            rules / "python-security.yaml"
        ).write_text(
            "rules: []\n",
            encoding="utf-8",
        )

        self.git(
            "add",
            "rules/python-security.yaml",
        )

        self.git(
            "commit",
            "-q",
            "-m",
            "Tamper with security rules",
        )

        head = self.git(
            "rev-parse",
            "HEAD",
        ).strip()

        with self.assertRaises(
            VerificationError
        ):
            self.verify(head)

    # ======================================
    # TEST 8 - DOCUMENTATION ONLY
    # ======================================

    def test_documentation_only_commit(self):

        (
            self.repo / "README.md"
        ).write_text(
            "Updated documentation\n",
            encoding="utf-8",
        )

        self.git("add", "README.md")

        self.git(
            "commit",
            "-q",
            "-m",
            "Documentation update",
        )

        head = self.git(
            "rev-parse",
            "HEAD",
        ).strip()

        self.assertEqual(
            self.verify(head),
            1,
        )

    # ======================================
    # TEST 9 - NESTED PYTHON FILE
    # ======================================

    def test_nested_python_file(self):

        head = self.signed_commit(
            path="src/app.py",
        )

        self.assertEqual(
            self.verify(head),
            1,
        )


if __name__ == "__main__":
    unittest.main()
