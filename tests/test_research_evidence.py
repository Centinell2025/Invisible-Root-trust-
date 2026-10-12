"""Consistency tests for additional synthetic investigation streams."""
import csv
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
A = ROOT / "artifacts"

def read(name):
    with (A/name).open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))

class ResearchEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        subprocess.run([sys.executable, str(ROOT/"tools/run_full_case.py")], check=True)

    def test_session_ids_unique(self):
        rows = read("session_lineage.csv")
        self.assertGreaterEqual(len(rows), 8)
        self.assertEqual(len(rows), len({r["session_id"] for r in rows}))

    def test_deployment_has_conflicting_approval_states(self):
        rows = read("deployment_provenance.csv")
        self.assertTrue(any(r["approval"] == "rejected" for r in rows))
        self.assertTrue(any(r["approval"] == "approved" for r in rows))

    def test_missing_acquisition_not_construed_as_negative(self):
        rows = read("acquisition_gaps.csv")
        self.assertTrue(all(r["inference"] == "unknown" for r in rows))
        self.assertTrue(any(r["status"] == "not-collected" for r in rows))
