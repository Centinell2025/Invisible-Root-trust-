import unittest,subprocess,sys,csv,hashlib
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
class GradingTests(unittest.TestCase):
 def test_evidence_consistency(self):
  subprocess.run([sys.executable,str(ROOT/"tools/run_full_case.py")],check=True)
  a=ROOT/"artifacts"
  with (a/"policy_digest_crosscheck.csv").open() as f: rows=list(csv.DictReader(f))
  self.assertTrue(all(hashlib.sha256((a/r["specimen"]).read_bytes()).hexdigest()==r["sha256"] for r in rows))
  subprocess.run([sys.executable,str(ROOT/"tools/validate_case.py")],check=True)
