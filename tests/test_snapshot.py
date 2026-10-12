"""Tests for realistic *scoped* SQLite and tar forensic specimens."""
import importlib.util
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("validate_snapshot",ROOT/"tools/validate_snapshot.py")
V=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(V)

class SnapshotTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        subprocess.run([sys.executable,str(ROOT/"tools/run_full_case.py")],check=True)

    def test_verified_sqlite_and_tar(self):
        details=V.verify()
        self.assertGreaterEqual(details["events"],1250)
        self.assertGreaterEqual(details["flows"],375)
        self.assertGreaterEqual(details["triage_tar_members"],9)

    def test_database_is_real_sqlite(self):
        db=ROOT/"artifacts/endpoint_telemetry.sqlite3"
        self.assertTrue(db.read_bytes().startswith(b"SQLite format 3\x00"))
        with sqlite3.connect(db) as connection:
            self.assertEqual(connection.execute("PRAGMA integrity_check").fetchone()[0],"ok")
            self.assertGreaterEqual(connection.execute("SELECT count(DISTINCT hostname) FROM host_events").fetchone()[0],5)

    def test_systemd_tar_symlink_retained(self):
        import tarfile
        with tarfile.open(ROOT/"artifacts/offline_gateway_triage.tar","r:") as tar:
            s=tar.getmember("etc/systemd/system/multi-user.target.wants/boot-health-agent.service")
            self.assertTrue(s.issym())
            self.assertEqual(s.linkname,"../boot-health-agent.service")

    def test_boot_observations_do_not_prove_restart(self):
        with sqlite3.connect(ROOT/"artifacts/endpoint_telemetry.sqlite3") as db:
            r=db.execute("SELECT boot_id,independently_verified FROM boot_inventory ORDER BY timestamp_utc").fetchall()
            self.assertEqual(len(r),2)
            self.assertEqual(r[0][0],r[1][0])
            self.assertTrue(all(x[1]==0 for x in r))

    def test_derived_sources_not_false_independent_evidence(self):
        with sqlite3.connect(ROOT/"artifacts/endpoint_telemetry.sqlite3") as db:
            r=db.execute("SELECT collection_method,original_device_verified FROM specimen_inventory").fetchall()
        self.assertTrue(all(method=="deterministic-simulated-export" and verified==0 for method,verified in r))

    def test_tampered_database_detected(self):
        with tempfile.TemporaryDirectory() as t:
            tmp=Path(t)
            src=ROOT/"artifacts"
            for name in ("endpoint_telemetry.sqlite3","policy_baseline.bin","policy_observed.bin",
                         "boot-health-agent.service","edge_sensor_capture.pcap"):
                shutil.copy2(src/name,tmp/name)
            with sqlite3.connect(tmp/"endpoint_telemetry.sqlite3") as db:
                db.execute("UPDATE host_events SET parent_id=9999 WHERE event_id='EVT-0104'")
            with patch.object(V,"OUT",tmp):
                with self.assertRaisesRegex(ValueError,"file-write join"):
                    V.validate_db()

    def test_tampered_tar_specimen_detected(self):
        with tempfile.TemporaryDirectory() as t:
            tmp=Path(t)
            src=ROOT/"artifacts"
            for name in ("offline_gateway_triage.tar","offline_snapshot_scope.csv",
                         "policy_observed.bin","boot-health-agent.service",
                         "auth_syslog.log","auditd_extract.log","journal_extended.jsonl"):
                shutil.copy2(src/name,tmp/name)
            (tmp/"policy_observed.bin").write_bytes(b"altered")
            with patch.object(V,"OUT",tmp):
                with self.assertRaisesRegex(ValueError,"Tar bytes"):
                    V.validate_tar()

    def test_tar_is_scoped_not_firmware_acquisition(self):
        import tarfile
        with tarfile.open(ROOT/"artifacts/offline_gateway_triage.tar","r:") as tar:
            note=tar.extractfile("COLLECTION_SCOPE.txt").read()
            self.assertIn(b"No sector image",note)
            self.assertIn(b"TPM quote",note)

if __name__=="__main__":
    unittest.main()
