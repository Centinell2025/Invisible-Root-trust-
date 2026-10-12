import unittest,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
class GradingTests(unittest.TestCase):
 def test_answers_are_reproducible(self):
  subprocess.run([sys.executable,str(ROOT/"tools/run_full_case.py")],check=True)
  from importlib.util import spec_from_file_location,module_from_spec
  spec=spec_from_file_location("grader",ROOT/"tools/grade_case.py");m=module_from_spec(spec);spec.loader.exec_module(m)
  before=m.findings()
  subprocess.run([sys.executable,str(ROOT/"tools/run_full_case.py")],check=True)
  self.assertEqual(before,m.findings())
  self.assertEqual(before["pcap_ip_protocol"],17)
  self.assertEqual(before["change_approved"],"no")
  self.assertTrue(before["crosscheck_digests_valid"])
