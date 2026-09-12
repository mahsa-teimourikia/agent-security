"""Execute credential-free curriculum labs as regression tests."""
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).parents[1]
LABS = [
    "curriculum/shared/foundation_lab.py",
    "curriculum/shared/runtime_security_lab.py",
    "curriculum/intermediate/08-agent-memory-security/lab.py",
    "curriculum/intermediate/11-secrets-and-credential-security/lab.py",
    "curriculum/intermediate/13-network-egress-ssrf-and-external-resource-security/lab.py",
    "curriculum/intermediate/14-tool-result-and-output-poisoning/lab.py",
    "curriculum/intermediate/16-mcp-security/lab.py",
    "curriculum/advanced/25-agent-red-teaming-and-adversarial-evaluation/lab.py",
    "curriculum/enterprise-agent/33-agent-security-governance/lab.py",
    "curriculum/enterprise-agent/36-production-secure-agent-capstone/lab.py",
]


class CourseLabTests(unittest.TestCase):
    def test_all_credential_free_course_labs(self) -> None:
        for relative in LABS:
            with self.subTest(lab=relative):
                result = subprocess.run([sys.executable, relative], cwd=ROOT, text=True, capture_output=True, check=False)
                self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
