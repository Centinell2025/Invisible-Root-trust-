"""Negative security tests for ZIP integrity and custody."""
import hashlib
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

class ReleaseValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        subprocess.run([sys.executable, str(ROOT/"tools/run_full_case.py")], check=True)
        subprocess.run([sys.executable, str(ROOT/"tools/build_submission.py")], check=True)

    def test_release_validator_accepts_valid_archive(self):
        subprocess.run([sys.executable, str(ROOT/"tools/validate_release.py")], check=True)

    def test_student_archive_excludes_source_and_grading(self):
        archive = ROOT/"dist/Invisible-Root-of-Trust-student.zip"
        with zipfile.ZipFile(archive) as z:
            names = z.namelist()
            self.assertFalse(any(n.startswith(("tools/", "tests/", ".github/", "instructor/")) for n in names))
            self.assertFalse(any("grade_case" in n.lower() for n in names))

    def test_manifest_hashes_are_not_placeholders(self):
        manifest = (ROOT/"artifacts/custody_manifest.sha256").read_text().splitlines()
        self.assertTrue(manifest)
        for line in manifest:
            digest, name = line.split("  ", 1)
            self.assertEqual(hashlib.sha256((ROOT/"artifacts"/name).read_bytes()).hexdigest(), digest)
