"""Senior scientific forensic quality tests: evidence, question contracts and negative controls.

Engineering pass is not a machine-graded key or an HTB approval.
"""
import importlib.util
import copy
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("scientific_quality_gate", ROOT / "tools" / "scientific_quality_gate.py")
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)

class ScientificInvestigationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        subprocess.run([sys.executable, str(ROOT / "tools" / "run_full_case.py")], check=True)

    def test_complete_30_question_sequence(self):
        self.assertEqual(list(range(1, 31)),
                         GATE.check_question_contracts(GATE.WORKSHEET.read_text(encoding="utf-8")))

    def test_question_count_each_phase(self):
        self.assertEqual(GATE.PHASES, ((1, 5), (6, 9), (10, 14), (15, 20), (21, 25), (26, 30)))

    def test_bad_number_mutation_rejected(self):
        text = GATE.WORKSHEET.read_text(encoding="utf-8").replace("**30 —", "**29 —")
        with self.assertRaisesRegex(ValueError, "30 sequential"):
            GATE.check_question_contracts(text)

    def test_missing_phase_mutation_rejected(self):
        text = GATE.WORKSHEET.read_text(encoding="utf-8").replace("## Phase 6 —", "## Missing final phase —")
        with self.assertRaisesRegex(ValueError, "Six investigative phases"):
            GATE.check_question_contracts(text)

    def test_evidence_gate_passes_without_confusing_simulated_with_real(self):
        result = GATE.check_evidence()
        self.assertEqual(result["questions"], 30)
        self.assertGreaterEqual(result["evidence_files"], 15)
        self.assertEqual(result["packet_count"], 1)

    def test_malformed_capture_rejected(self):
        pcap = bytearray((GATE.EVIDENCE / "synthetic_telemetry.pcap").read_bytes())
        pcap[32:36] = (99999).to_bytes(4, "little")
        with self.assertRaises(ValueError):
            GATE.inspect_pcap(pcap)

    def test_truncated_capture_rejected(self):
        pcap = (GATE.EVIDENCE / "synthetic_telemetry.pcap").read_bytes()[:-2]
        with self.assertRaisesRegex(ValueError, "Truncated"):
            GATE.inspect_pcap(pcap)

    def test_capture_timestamp_belongs_to_case_year(self):
        packet = GATE.inspect_pcap((GATE.EVIDENCE / "synthetic_telemetry.pcap").read_bytes())[0]
        from datetime import datetime, timezone
        self.assertEqual(datetime.fromtimestamp(packet["epoch"], timezone.utc).isoformat(),
                         "2026-09-17T03:17:07+00:00")

    def test_network_sources_do_not_confirm_same_tcp_session(self):
        packet = GATE.inspect_pcap((GATE.EVIDENCE / "synthetic_telemetry.pcap").read_bytes())[0]
        flow = GATE.csv_rows("network_flows.csv")[0]
        self.assertEqual(packet["dst"], flow["dst_ip"])
        self.assertEqual(packet["protocol"], 17)  # UDP
        self.assertEqual(flow["protocol"].upper(), "TCP")
        self.assertNotEqual(packet["protocol"], 6)

    def test_unapproved_ticket_cannot_be_treated_as_approved(self):
        tickets = GATE.csv_rows("change_tickets.csv")
        packages = GATE.csv_rows("deployment_provenance.csv")
        for ticket in tickets:
            if ticket["approved"] == "no":
                self.assertFalse(any(p["ticket"] == ticket["ticket"] and p["approval"] == "approved"
                                     for p in packages))

    def test_mutated_ticket_approval_detected(self):
        original = GATE.csv_rows
        def malicious_rows(name):
            rows = original(name)
            if name == "deployment_provenance.csv":
                rows = copy.deepcopy(rows)
                for record in rows:
                    if record["ticket"] == "CHG-421":
                        record["approval"] = "approved"
                        break
            return rows
        with patch.object(GATE, "csv_rows", side_effect=malicious_rows):
            with self.assertRaisesRegex(ValueError, "Unapproved ticket incorrectly"):
                GATE.check_evidence()

    def test_evidence_gap_is_not_negative_proof(self):
        gaps = GATE.csv_rows("acquisition_gaps.csv")
        self.assertTrue(gaps)
        self.assertTrue(all(g["inference"] == "unknown" for g in gaps))
        self.assertTrue(any(g["collection"] == "firmware" and g["status"] == "not-collected" for g in gaps))

    def test_synthetic_memory_not_advertised_as_real_dump(self):
        blob = (GATE.EVIDENCE / "memory_excerpt.bin").read_bytes()
        self.assertTrue(blob.startswith(b"NRG-SYNTHETIC-MEMORY"))
        self.assertIn("not a real", (ROOT / "docs" / "FORENSIC_LIMITATIONS.md").read_text().lower())

    def test_private_instructor_key_does_not_leak_to_student_archive(self):
        subprocess.run([sys.executable, str(ROOT / "tools" / "build_submission.py")], check=True)
        import zipfile
        archive = ROOT / "dist" / "Invisible-Root-of-Trust-student.zip"
        with zipfile.ZipFile(archive) as z:
            names = z.namelist()
            self.assertIn("questions/INVESTIGATION.md", names)
            self.assertNotIn("docs/ADVANCED_ANALYST_GUIDE.md", names)
            self.assertTrue(all("instructor" not in n.lower() and "answer_key" not in n.lower() for n in names))

    def test_insane_release_is_not_auto_certified(self):
        with self.assertRaisesRegex(ValueError, "INSANE RELEASE BLOCKED"):
            GATE.run("insane")


def _individual_contract_test(number, kind, sources):
    def test(self):
        for name in sources:
            with self.subTest(source=name):
                self.assertTrue((GATE.EVIDENCE / name).is_file(), f"Q{number:02}: missing {name}")
                if name.endswith(".csv"):
                    self.assertTrue(GATE.csv_rows(name), f"Q{number:02}: empty {name}")
        self.assertIn(kind, {"fact", "interpretation", "decision"})
    return test


for qnum, (kind, sources) in GATE.QUESTION_CONTRACTS.items():
    setattr(ScientificInvestigationTests, f"test_q{qnum:02}_evidence_contract",
            _individual_contract_test(qnum, kind, sources))

if __name__ == "__main__":
    unittest.main()
