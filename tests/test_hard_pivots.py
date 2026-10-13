"""Hard-tier cross-source case regression tests with adversarial mutations.

A passing test demonstrates that our synthetic data are internally consistent.
It does not replace a non-author blind playtest or certify HTB difficulty.
"""
import copy
import importlib.util
import subprocess
import sys
import unittest
import zipfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("validate_hard_pivots",ROOT/"tools/validate_hard_pivots.py")
VALID=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALID)

class HardPivotTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        subprocess.run([sys.executable,str(ROOT/"tools/run_full_case.py")],check=True)

    def streams(self):
        return {name: VALID.read_stream(name) for name in VALID.FILES}

    def test_four_hard_streams_cross_correlate(self):
        result=VALID.verify()
        self.assertEqual(result["critical_correlations"],4)
        self.assertEqual(result["independently_verified_sources"],0)
        self.assertGreaterEqual(sum(result[x] for x in
            ("identity_events","change_events","firewall_events","service_events")),280)

    def test_duplicate_ids_fail(self):
        x=self.streams()
        x[VALID.FILES[0]].append(copy.deepcopy(x[VALID.FILES[0]][0]))
        with self.assertRaisesRegex(ValueError,"Duplicate Hard evidence"):
            VALID.validate_records(x)

    def test_timestamp_inversion_fails(self):
        x=self.streams()
        x[VALID.FILES[0]][0],x[VALID.FILES[0]][1]=x[VALID.FILES[0]][1],x[VALID.FILES[0]][0]
        with self.assertRaisesRegex(ValueError,"Disordered Hard"):
            VALID.validate_records(x)

    def test_unverified_human_binding_not_attributed(self):
        x=self.streams()
        row=next(r for r in x[VALID.FILES[0]] if r["event_id"]=="IDP-4702")
        row["human_binding"]="verified-person"
        with self.assertRaisesRegex(ValueError,"human attribution"):
            VALID.validate_records(x)

    def test_issued_identity_token_ambiguity_rejected(self):
        x=self.streams()
        row=copy.deepcopy(next(r for r in x[VALID.FILES[0]] if r["event_id"]=="IDP-4702"))
        row["event_id"]="IDP-4702-FAKE"
        x[VALID.FILES[0]].append(row)
        x[VALID.FILES[0]].sort(key=lambda r:(r["utc"],r["event_id"]))
        with self.assertRaisesRegex(ValueError,"pivotal correlation ambiguous"):
            VALID.validate_records(x)

    def test_changed_security_denial_rejected(self):
        x=self.streams()
        row=next(r for r in x[VALID.FILES[1]] if r["event_id"]=="CTRL-2103")
        row["approval"]="approved"
        with self.assertRaisesRegex(ValueError,"Unique rejected change"):
            VALID.validate_records(x)

    def test_fake_approved_ticket_rejected(self):
        x=self.streams()
        row=next(r for r in x[VALID.FILES[1]] if r["event_id"]=="CTRL-2103")
        row["package_id"]="PKG-205"
        with self.assertRaisesRegex(ValueError,"Unique rejected change"):
            VALID.validate_records(x)

    def test_firewall_udp_decoy_not_allowed_to_replace_tcp(self):
        x=self.streams()
        row=next(r for r in x[VALID.FILES[2]] if r["event_id"]=="FW-5031")
        row["protocol"]="UDP"
        with self.assertRaisesRegex(ValueError,"Ambiguous firewall/netflow"):
            VALID.validate_records(x)

    def test_firewall_not_an_exfil_byte_counter(self):
        x=self.streams()
        row=next(r for r in x[VALID.FILES[2]] if r["event_id"]=="FW-5031")
        row["byte_scope"]="full-content-measured"
        with self.assertRaisesRegex(ValueError,"measured network byte coverage"):
            VALID.validate_records(x)

    def test_service_not_authenticated_after_reboot(self):
        x=self.streams()
        row=next(r for r in x[VALID.FILES[3]] if r["event_id"]=="UNIT-3117")
        row["reboot_verified"]="yes"
        with self.assertRaisesRegex(ValueError,"verified origin or reboot"):
            VALID.validate_records(x)

    def test_service_enablement_mutation_rejected(self):
        x=self.streams()
        row=next(r for r in x[VALID.FILES[3]] if r["event_id"]=="UNIT-3117")
        row["event"]="unit-file-read"
        with self.assertRaisesRegex(ValueError,"Ambiguous service enablement"):
            VALID.validate_records(x)

    def test_student_release_has_all_pivots_but_no_answers(self):
        subprocess.run([sys.executable,str(ROOT/"tools/build_submission.py")],check=True)
        with zipfile.ZipFile(ROOT/"dist/Invisible-Root-of-Trust-student.zip") as z:
            for filename in VALID.FILES:
                self.assertIn("artifacts/"+filename,z.namelist())
            self.assertNotIn("tools/generate_hard_pivots.py",z.namelist())
            self.assertNotIn("Sherlock-Questions-PRIVATE.yaml",z.namelist())
            t=z.read("questions/HTB_PLAYER_TASKS.md").decode()
            self.assertIn("**Task 25.**",t)
            self.assertIn("BEACON OF THE EAGLE LLC",z.read("README.txt").decode())

if __name__=="__main__":
    unittest.main()
