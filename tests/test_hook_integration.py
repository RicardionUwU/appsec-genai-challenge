
"""
AppSec GenAI - Hook Integration Tests

Pruebas de integracion:
- Repositorio Git temporal.
- Constancia Ed25519 temporal.
- Transporte pre-commit -> commit-msg.
- Commit real y verificacion independiente.
- Deteccion de cambios posteriores al analisis.
- Rechazo de constancias ausentes.
- Rechazo de trailers preexistentes.
- Rechazo de componentes protegidos.

No requiere:
- Auth0
- FastAPI
- Ollama
- Docker
- GitHub
"""

import os
import subprocess
import tempfile
import unittest

from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from backend.attestations import (
    ApprovedAnalysis,
    issue_signed_manifest,
)

from hooks import pre_commit
from hooks import commit_msg

from scripts.verify_commit import (
    verify_commit_range,
)


class TestHookIntegration(unittest.TestCase):

    def setUp(self):

        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

        self.repo = Path(self.temp.name)
        self.old_cwd = Path.cwd()

        # Las funciones del hook ejecutan Git
        # en el directorio de trabajo actual.
        os.chdir(self.repo)
        self.addCleanup(os.chdir, self.old_cwd)

        # Evitar que la ruta de almacenamiento
        # apunte al repositorio principal.
        project_patch = patch.object(
            pre_commit,
            "PROJECT_ROOT",
            self.repo,
        )

        project_patch.start()
        self.addCleanup(project_patch.stop)

        self.key = Ed25519PrivateKey.generate()
        self.repository = "example/security-demo"
        self.policy = "a" * 64
        self.kid = "test-key"
        self.model = "qwen2.5-coder:7b"

        self.git("init", "-q")
        self.git("config", "user.name", "AppSec Test")
        self.git(
            "config",
            "user.email",
            "test@example.invalid",
        )

        self.git("config", "core.autocrlf", "false")
        self.git("config", "commit.gpgsign", "false")

        # No ejecutar hooks de Git reales dentro
        # del repositorio temporal.
        self.git(
            "config",
            "core.hooksPath",
            ".git/no-hooks",
        )

        (self.repo / "README.md").write_text(
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
        )

        self.message_path = (
            self.repo / ".git" / "APPSEC_TEST_MSG"
        )

        self.message_path.write_text(
            "Security approved change\n",
            encoding="utf-8",
        )

    def git(self, *args):

        process = subprocess.run(
            ["git", *args],
            cwd=self.repo,
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
            shell=False,
        )

        return process.stdout.strip()

    def prepare_approved_analysis(self):

        content = b"print(123)\n"

        source = self.repo / "src" / "app.py"

        source.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        source.write_bytes(content)

        self.git("add", "src/app.py")

        tree, parent = pre_commit.get_git_context()

        receipt = issue_signed_manifest(
            subject="auth0|test-developer",
            repository=self.repository,
            git_tree_oid=tree,
            parent_oid=parent,
            policy_sha256=self.policy,
            model_id=self.model,
            analyses=[
                ApprovedAnalysis(
                    path="src/app.py",
                    content=content,
                    mode="100644",
                    status="approved",
                )
            ],
            private_key=self.key,
            key_id=self.kid,
        )

        pre_commit.store_pending_receipt(
            tree_oid=tree,
            parent_oid=parent,
            receipt=receipt,
        )

        return tree, parent

    def test_signed_commit_end_to_end(self):

        self.prepare_approved_analysis()

        # commit-msg consume la constancia.
        result = commit_msg.main([
            "commit_msg.py",
            str(self.message_path),
        ])

        self.assertEqual(result, 0)

        message = self.message_path.read_text(
            encoding="utf-8",
        )

        self.assertIn(
            "AppSec-Attestation: ",
            message,
        )

        self.assertFalse(
            pre_commit.get_pending_receipt_path().exists()
        )

        # Construir un commit real utilizando
        # el mensaje que modifico commit-msg.
        self.git(
            "commit",
            "-q",
            "-F",
            str(self.message_path),
        )

        head = self.git(
            "rev-parse",
            "HEAD",
        )

        count = verify_commit_range(
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

        self.assertEqual(count, 1)

    def test_modified_staging_rejected(self):

        self.prepare_approved_analysis()

        source = self.repo / "src" / "app.py"

        source.write_bytes(
            b"print('modified')\n"
        )

        self.git("add", "src/app.py")

        result = commit_msg.main([
            "commit_msg.py",
            str(self.message_path),
        ])

        self.assertEqual(result, 1)

    def test_missing_receipt_rejected(self):

        self.prepare_approved_analysis()

        pre_commit.get_pending_receipt_path().unlink()

        result = commit_msg.main([
            "commit_msg.py",
            str(self.message_path),
        ])

        self.assertEqual(result, 1)

    def test_existing_trailer_rejected(self):

        self.prepare_approved_analysis()

        self.message_path.write_text(
            "Attempt\n\n"
            "AppSec-Attestation: forged\n",
            encoding="utf-8",
        )

        result = commit_msg.main([
            "commit_msg.py",
            str(self.message_path),
        ])

        self.assertEqual(result, 1)

    def test_protected_security_change_rejected(self):

        rules = self.repo / "rules"
        rules.mkdir()

        (rules / "python-security.yaml").write_text(
            "rules: []\n",
            encoding="utf-8",
        )

        self.git(
            "add",
            "rules/python-security.yaml",
        )

        result = commit_msg.main([
            "commit_msg.py",
            str(self.message_path),
        ])

        self.assertEqual(result, 1)


if __name__ == "__main__":
    unittest.main()
