"""Release regression checks: student ZIP membership and safe rebuild."""
import subprocess
import sys
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCUMENTS = {
    "docs/STUDENT_INCIDENT_BRIEF.md",
    "docs/STUDENT_EVIDENCE_RULES.md",
    "questions/INVESTIGATION.md",
}

class ReleaseTests(unittest.TestCase):
    def test_student_archive_contains_only_allowlisted_paths(self):
        subprocess.run([sys.executable, str(ROOT/"tools/run_full_case.py")], check=True)
        subprocess.run([sys.executable, str(ROOT/"tools/build_submission.py")], check=True)
        archive = ROOT/"dist/Invisible-Root-of-Trust-student.zip"
        with zipfile.ZipFile(archive) as z:
            names = z.namelist()
            self.assertTrue(all(n.startswith("artifacts/") or n in DOCUMENTS for n in names))
            self.assertEqual({n for n in names if not n.startswith("artifacts/")}, DOCUMENTS)
            self.assertIn("artifacts/custody_manifest.sha256", names)
        subprocess.run([sys.executable, str(ROOT/"tools/validate_release.py")], check=True)

    def test_clean_rebuild_discards_stale_artifact(self):
        subprocess.run([sys.executable, str(ROOT/"tools/run_full_case.py")], check=True)
        stale = ROOT/"artifacts/obsolete_debug.txt"
        stale.write_text("not evidence")
        subprocess.run([sys.executable, str(ROOT/"tools/run_full_case.py")], check=True)
        self.assertFalse(stale.exists())
