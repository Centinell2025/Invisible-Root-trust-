"""Tests for uncertainty-aware analysis without leaking case answers."""
import importlib.util
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("scientific_analysis", ROOT/"tools/scientific_analysis.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

class ScientificAnalysisTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        subprocess.run([sys.executable, str(ROOT/"tools/run_full_case.py")], check=True)

    def test_unmapped_clocks_are_not_silently_corrected(self):
        events = MODULE.collect()
        self.assertTrue(events)
        for event in events:
            if event["source_type"] != "journal":
                self.assertIsNone(event["normalized_utc"])
                self.assertEqual(event["normalization_status"], "unknown_clock_offset")

    def test_journal_offset_uses_explicit_convention(self):
        events = [e for e in MODULE.collect() if e["source_type"] == "journal"]
        self.assertTrue(events)
        for event in events:
            self.assertEqual(event["offset_seconds"], 2)
            self.assertIsNotNone(event["normalized_utc"])

    def test_utc_parser_rejects_unlabeled_local_time(self):
        with self.assertRaises(ValueError):
            MODULE.parse_utc("2026-09-17T03:18:00")
