import unittest,subprocess,sys,struct,csv,hashlib
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];OUT=ROOT/"artifacts"
class AdvancedTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):subprocess.run([sys.executable,str(ROOT/"tools/run_full_case.py")],check=True)
 def test_binary_specimens_match_ledger(self):
  with (OUT/"policy_digest_crosscheck.csv").open() as f:rows=list(csv.DictReader(f))
  for row in rows:self.assertEqual(hashlib.sha256((OUT/row["specimen"]).read_bytes()).hexdigest(),row["sha256"])
 def test_pcap_header_and_packet(self):
  data=(OUT/"synthetic_telemetry.pcap").read_bytes()
  self.assertEqual(struct.unpack("<I",data[:4])[0],0xa1b2c3d4)
  self.assertEqual(struct.unpack("<I",data[20:24])[0],1)
  incl=struct.unpack("<I",data[32:36])[0]
  self.assertEqual(len(data)-40,incl)
  self.assertEqual(data[40+12:40+14],b"\x08\x00")
  self.assertEqual(data[40+14+9],17)
 def test_manifest_after_full_generation(self):
  subprocess.run([sys.executable,str(ROOT/"tools/validate_case.py")],check=True)
