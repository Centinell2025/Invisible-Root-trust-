"""Adversarial tests for realistic simulated DFIR evidence.

Each negative test must detect an actual evidence inconsistency, rather than
merely proving a file exists. The source generators are not trusted evidence.
"""
import importlib.util
import copy
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("validate_realistic", ROOT / "tools/validate_realistic.py")
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)

class RealisticCaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        subprocess.run([sys.executable, str(ROOT / "tools/run_full_case.py")], check=True)

    def test_full_evidence_chain_passes(self):
        results = VALIDATOR.verify()
        self.assertGreaterEqual(results["packet_total"], 8)
        self.assertGreaterEqual(results["auth_log_lines"], 75)
        self.assertGreaterEqual(results["journal_records"], 60)

    def test_pcap_checksum_mutation_rejected(self):
        packet = bytearray((ROOT / "artifacts" / "edge_sensor_capture.pcap").read_bytes())
        packet[24 + 16 + 14 + 10] ^= 0x80  # corrupt IPv4 header checksum coverage
        with self.assertRaisesRegex(ValueError, "checksum"):
            VALIDATOR.packets_from_pcap(bytes(packet))

    def test_truncated_pcap_rejected(self):
        data = (ROOT / "artifacts" / "edge_sensor_capture.pcap").read_bytes()
        with self.assertRaisesRegex(ValueError, "Truncated"):
            VALIDATOR.packets_from_pcap(data[:-4])

    def test_audit_order_is_chronologically_consistent(self):
        lines = (ROOT / "artifacts" / "auditd_extract.log").read_text(encoding="utf-8").splitlines()
        records = VALIDATOR.validate_audit_order(lines)
        self.assertGreaterEqual(len(records), 38)
        self.assertEqual([s for _,s in records if s in (8101,8104,8105)], [8101,8104,8105])

    def test_audit_serial_inversion_is_rejected(self):
        lines = (ROOT / "artifacts" / "auditd_extract.log").read_text(encoding="utf-8").splitlines()
        lines = list(lines)
        event_indexes = [i for i,x in enumerate(lines) if x.startswith("type=SYSCALL")]
        lines[event_indexes[0]],lines[event_indexes[1]] = lines[event_indexes[1]], lines[event_indexes[0]]
        with self.assertRaisesRegex(ValueError, "timestamp/serial inversion"):
            VALIDATOR.validate_audit_order(lines)

    def test_pcap_contains_two_different_transports(self):
        packets = VALIDATOR.packets_from_pcap(
            (ROOT / "artifacts" / "edge_sensor_capture.pcap").read_bytes())
        self.assertIn(6, {r["protocol"] for r in packets})
        self.assertIn(17, {r["protocol"] for r in packets})

    def test_captured_tcp_bytes_do_not_establish_complete_flow(self):
        results = VALIDATOR.verify()
        self.assertLess(results["captured_outbound_tcp_bytes"], 9821)

    def test_corrupted_measurement_derivation_detected(self):
        old = VALIDATOR.table
        def replaced(name):
            rows = old(name)
            if name == "measurement_derivation.csv":
                rows = copy.deepcopy(rows)
                rows[1]["sha256"] = "0" * 64
            return rows
        with patch.object(VALIDATOR, "table", side_effect=replaced):
            with self.assertRaisesRegex(ValueError, "Observed derivation mismatch"):
                VALIDATOR.verify()

    def test_false_hardware_attestation_claim_rejected(self):
        old = VALIDATOR.table
        def replaced(name):
            rows = old(name)
            if name == "trust_anchor_inventory.csv":
                rows = copy.deepcopy(rows)
                rows[0]["collection_status"] = "collected"
            return rows
        with patch.object(VALIDATOR, "table", side_effect=replaced):
            with self.assertRaisesRegex(ValueError, "verified trust anchor"):
                VALIDATOR.verify()

    def test_process_lineage_mutation_detected(self):
        old = VALIDATOR.table
        def replaced(name):
            rows = old(name)
            if name == "process_lineage.csv":
                rows = copy.deepcopy(rows)
                for row in rows:
                    if row["pid"] == "2904":
                        row["ppid"] = "9999"
            return rows
        with patch.object(VALIDATOR, "table", side_effect=replaced):
            with self.assertRaisesRegex(ValueError, "Service-to-egress"):
                VALIDATOR.verify()

    def test_claims_do_not_prove_hardware_root_compromise(self):
        a = VALIDATOR.table("secure_boot_attestation.csv")
        self.assertTrue(all(r["trust_anchor"] == "none" for r in a))
        t = VALIDATOR.table("trust_anchor_inventory.csv")
        self.assertTrue(all(r["collection_status"] == "not-acquired" for r in t))

    def test_acquisition_register_limits(self):
        sources = VALIDATOR.table("acquisition_register.csv")
        self.assertTrue(all(r["verified_origin"] == "no" for r in sources))
        self.assertTrue(any(r["completeness"] != "complete" for r in sources))

if __name__ == "__main__":
    unittest.main()
