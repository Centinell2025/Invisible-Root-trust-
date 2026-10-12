"""Integrated tests; never invoke the legacy partial generator in isolation."""
import subprocess
import sys
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
def run(name):
    subprocess.run([sys.executable, str(ROOT / "tools" / name)], check=True)

class CaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        run("run_full_case.py")

    def test_generated_case_validates(self):
        run("validate_case.py")

    def test_repeatable_full_generation(self):
        first = (ROOT/"artifacts/custody_manifest.sha256").read_bytes()
        run("run_full_case.py")
        self.assertEqual(first, (ROOT/"artifacts/custody_manifest.sha256").read_bytes())

    def test_student_archive_excludes_source_and_instructor(self):
        run("build_submission.py")
        with zipfile.ZipFile(ROOT/"dist/Invisible-Root-of-Trust-student.zip") as z:
            self.assertFalse(any(
                n.startswith(("tools/", "tests/", "instructor/", ".github/"))
                or "answer_key" in n.lower()
                for n in z.namelist()
            ))

if __name__ == "__main__":
    unittest.main()
