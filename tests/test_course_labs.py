"""Execute credential-free curriculum labs as regression tests."""
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).parents[1]
LABS = [
    "curriculum/shared/foundation_lab.py",
    "curriculum/shared/runtime_security_lab.py",
    "curriculum/roadmap/intermediate/01-agent-memory-security/lab.py",
    "curriculum/roadmap/intermediate/04-secrets-and-credential-security/lab.py",
    "curriculum/roadmap/intermediate/06-network-egress-ssrf-and-external-resource-security/lab.py",
    "curriculum/roadmap/intermediate/07-tool-result-and-output-poisoning/lab.py",
    "curriculum/roadmap/intermediate/09-mcp-security/lab.py",
    "curriculum/roadmap/advanced/08-agent-red-teaming-and-adversarial-evaluation/lab.py",
    "curriculum/roadmap/enterprise/06-agent-security-governance/lab.py",
    "curriculum/roadmap/enterprise/09-production-secure-agent-capstone/lab.py",
]


class CourseLabTests(unittest.TestCase):
    def test_all_credential_free_course_labs(self) -> None:
        for relative in LABS:
            with self.subTest(lab=relative):
                result = subprocess.run([sys.executable, relative], cwd=ROOT, text=True, capture_output=True, check=False)
                self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
