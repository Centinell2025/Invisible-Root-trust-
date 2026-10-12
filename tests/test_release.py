"""Release-focused regression tests."""
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

class ReleaseTests(unittest.TestCase):
    def test_student_archive_contains_only_allowlisted_paths(self):
        subprocess.run([sys.executable, str(ROOT/"tools/run_full_case.py")], check=True)
        subprocess.run([sys.executable, str(ROOT/"tools/build_submission.py")], check=True)
        with zipfile.ZipFile(ROOT/"dist/Invisible-Root-of-Trust-student.zip") as z:
            names=z.namelist()
            self.assertTrue(all(n.startswith("artifacts/") or n in {
                "README.md", "questions/INVESTIGATION.md", "questions/ADVANCED_PIVOTS.md",
                "docs/CASE_DESIGN.md", "docs/ADVANCED_ANALYST_GUIDE.md"} for n in names))
            self.assertIn("artifacts/custody_manifest.sha256",names)
    def test_clean_rebuild_discards_stale_artifact(self):
        subprocess.run([sys.executable,str(ROOT/"tools/run_full_case.py")],check=True)
        stale=ROOT/"artifacts/obsolete_debug.txt"
        stale.write_text("not evidence")
        subprocess.run([sys.executable,str(ROOT/"tools/run_full_case.py")],check=True)
        self.assertFalse(stale.exists())
