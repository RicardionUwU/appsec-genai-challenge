
import unittest

from backend.semgrep_analyzer import analyze_with_semgrep
from backend.policy_engine import decide


class TestOWASPRules(unittest.TestCase):

    def assert_detected(self, code, rule_id):
        result = analyze_with_semgrep(
            "security_test.py",
            code,
        )

        rule_ids = [
            finding["rule_id"]
            for finding in result["findings"]
        ]

        self.assertTrue(
            any(
                identifier.endswith(rule_id)
                for identifier in rule_ids
            ),
            f"Regla no detectada: {rule_id}",
        )

        return result

    def assert_clean(self, code):
        result = analyze_with_semgrep(
            "security_test.py",
            code,
        )

        self.assertEqual(
            result["total_findings"],
            0,
        )

    # A02 - Cryptographic Failures

    def test_a02_vulnerable(self):
        self.assert_detected(
            "import hashlib\n"
            "def hash_password(password):\n"
            "    return hashlib.md5("
            "password.encode()).hexdigest()\n",
            "appsec-python-weak-password-hash",
        )

    def test_a02_safe(self):
        self.assert_clean(
            "from argon2 import PasswordHasher\n"
            "def hash_password(password):\n"
            "    return PasswordHasher().hash(password)\n"
        )

    # A03 - Injection

    def test_a03_vulnerable(self):
        self.assert_detected(
            "import os\n"
            "def execute(command):\n"
            "    os.system(command)\n",
            "appsec-python-command-injection",
        )

    def test_a03_safe(self):
        self.assert_clean(
            "import subprocess\n"
            "subprocess.run("
            "['echo', 'hello'], "
            "shell=False, check=True)\n"
        )

    # A05 - Security Misconfiguration

    def test_a05_vulnerable(self):
        self.assert_detected(
            "from flask import Flask\n"
            "app = Flask(__name__)\n"
            "app.run(debug=True)\n",
            "appsec-python-flask-debug-enabled",
        )

    def test_a05_safe(self):
        self.assert_clean(
            "from flask import Flask\n"
            "app = Flask(__name__)\n"
            "app.run(debug=False)\n"
        )

    # A08 - Software and Data Integrity Failures

    def test_a08_vulnerable(self):
        self.assert_detected(
            "import pickle\n"
            "from flask import request\n"
            "def load_data():\n"
            "    return pickle.loads(request.get_data())\n",
            "appsec-python-unsafe-deserialization",
        )

    def test_a08_safe(self):
        self.assert_clean(
            "import json\n"
            "from flask import request\n"
            "def load_data():\n"
            "    return json.loads(request.get_data())\n"
        )

    # A10 - Server-Side Request Forgery

    def test_a10_vulnerable(self):
        code = (
            "import requests\n"
            "from flask import request\n"
            "def fetch_url():\n"
            "    return requests.get("
            "request.args.get('url'), timeout=5)\n"
        )

        self.assert_detected(
            code,
            "appsec-python-ssrf-user-url",
        )

    def test_a10_safe(self):
        self.assert_clean(
            "import requests\n"
            "def fetch_safe():\n"
            "    return requests.get("
            "'https://api.example.com/status', "
            "timeout=5)\n"
        )

    # Policy Engine - defensa independiente del LLM

    def test_policy_engine_blocks_ssrf(self):
        code = (
            "import requests\n"
            "from flask import request\n"
            "def fetch_url():\n"
            "    return requests.get("
            "request.args.get('url'), timeout=5)\n"
        )

        static_result = analyze_with_semgrep(
            "security_test.py",
            code,
        )

        ai_result = {
            "status": "approved",
            "vulnerabilities": [],
            "needs_review": [],
        }

        decision = decide(
            static_result,
            ai_result,
        )

        self.assertEqual(
            decision["status"],
            "rejected",
        )


if __name__ == "__main__":
    unittest.main()
