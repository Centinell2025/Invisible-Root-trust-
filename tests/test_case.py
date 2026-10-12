"""Unit/integration checks; run: python3 -m unittest discover -s tests -v"""
import subprocess,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
class CaseTests(unittest.TestCase):
    def test_generate_and_validate(self):
        subprocess.run([sys.executable,str(ROOT/"tools/generate_case.py")],check=True)
        subprocess.run([sys.executable,str(ROOT/"tools/validate_case.py")],check=True)
    def test_repeatable_generation(self):
        subprocess.run([sys.executable,str(ROOT/"tools/generate_case.py")],check=True)
        first=(ROOT/"artifacts/custody_manifest.sha256").read_bytes()
        subprocess.run([sys.executable,str(ROOT/"tools/generate_case.py")],check=True)
        self.assertEqual(first,(ROOT/"artifacts/custody_manifest.sha256").read_bytes())
    def test_student_archive_excludes_instructor(self):
        subprocess.run([sys.executable,str(ROOT/"tools/generate_case.py")],check=True)
        subprocess.run([sys.executable,str(ROOT/"tools/build_submission.py")],check=True)
        import zipfile
        with zipfile.ZipFile(ROOT/"dist/Invisible-Root-of-Trust-student.zip") as z:
            self.assertFalse(any("instructor" in n.lower() or "answer" in n.lower() for n in z.namelist()))
if __name__=="__main__":unittest.main()
