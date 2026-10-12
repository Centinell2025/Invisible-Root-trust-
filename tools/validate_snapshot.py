#!/usr/bin/env python3
"""Validate the synthetic SQLite + limited tar forensic acquisitions.

Checks true data joins and tar bytes. A derived SQLite cache is not a second
independent source; a scoped tar is not a full disk image.
"""
import csv
import hashlib
import io
import sqlite3
import sys
import tarfile
from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / "artifacts"

def require(ok, msg):
    if not ok:
        raise ValueError(msg)

def sha(data):
    return hashlib.sha256(data).hexdigest()

def validate_db():
    dbpath=OUT/"endpoint_telemetry.sqlite3"
    require(dbpath.read_bytes().startswith(b"SQLite format 3\x00"), "Invalid SQLite header")
    with sqlite3.connect(f"file:{dbpath.as_posix()}?mode=ro",uri=True) as db:
        require(db.execute("PRAGMA integrity_check").fetchone()[0]=="ok","SQLite integrity failed")
        events=db.execute("SELECT count(*) FROM host_events").fetchone()[0]
        flows=db.execute("SELECT count(*) FROM netflow_sessions").fetchone()[0]
        require(events >= 1250 and flows >= 375, "Insufficient multihost event noise")
        unique=db.execute("SELECT count(DISTINCT event_id) FROM host_events").fetchone()[0]
        require(unique==events,"Duplicate event identities")
        hosts={r[0] for r in db.execute("SELECT DISTINCT hostname FROM host_events")}
        require(len(hosts)>=5,"Multihost event generation missing")
        writes=db.execute("""SELECT timestamp_utc,principal,process_id,parent_id,correlation_ref,object_path
                             FROM host_events WHERE event_kind='file-write'""").fetchall()
        require(len(writes)==1,"Expected a single precise audited-write pivot")
        when,who,pid,ppid,ref,path=writes[0]
        require(when=="2026-09-17T03:12:27Z" and pid==2421 and ppid==2417
                and ref=="AUTH-702" and path=="/etc/secureboot/policy.conf",
                "SQLite file-write join inconsistent with audit source")
        net=db.execute("""SELECT source_ip,source_port,dest_ip,dest_port,protocol,
                                  bytes_out,pid_claim FROM netflow_sessions
                          WHERE session_id='FLOW-99999'""").fetchone()
        require(net==("192.0.2.17",50544,"198.51.100.73",443,"TCP",9821,2904),
                "Deep netflow does not match sampled socket and target flow")
        reboots=db.execute("""SELECT timestamp_utc,boot_id,independently_verified
                              FROM boot_inventory ORDER BY timestamp_utc""").fetchall()
        require(len(reboots)==2 and reboots[0][1]==reboots[1][1]
                and all(row[2]==0 for row in reboots),
                "Unjustified reboot/persistence proof")
        specimens={r[0]:(r[1],r[2],r[3]) for r in db.execute(
            "SELECT specimen,sha256,collection_method,original_device_verified FROM specimen_inventory")}
        for name in ("policy_baseline.bin","policy_observed.bin",
                     "boot-health-agent.service","edge_sensor_capture.pcap"):
            require(name in specimens,"SQLite specimen inventory incomplete")
            hash_value,source,origin=specimens[name]
            require(hash_value==sha((OUT/name).read_bytes()),"SQLite digest mismatch "+name)
            require(source=="deterministic-simulated-export" and origin==0,
                    "Derived specimen misrepresented as authenticated")
    return events, flows

def validate_tar():
    archive=OUT/"offline_gateway_triage.tar"
    expected={
        "etc/secureboot/policy.conf":"policy_observed.bin",
        "etc/systemd/system/boot-health-agent.service":"boot-health-agent.service",
        "var/log/auth.log":"auth_syslog.log",
        "var/log/audit/audit.log":"auditd_extract.log",
        "var/log/journal/export.jsonl":"journal_extended.jsonl",
    }
    with tarfile.open(archive,"r:") as tf:
        members=tf.getmembers()
        names={x.name for x in members}
        require(len(members)==len(names),"Duplicate triage tar entries")
        require(all(not x.name.startswith("/") and ".." not in Path(x.name).parts for x in members),
                "Unsafe archive names")
        for name,source in expected.items():
            require(name in names,"Missing tar acquisition file: "+name)
            member=tf.getmember(name)
            require(member.isfile() and sha(tf.extractfile(member).read())==
                    sha((OUT/source).read_bytes()),"Tar bytes do not equal collected specimen "+name)
        link=tf.getmember("etc/systemd/system/multi-user.target.wants/boot-health-agent.service")
        require(link.issym() and link.linkname=="../boot-health-agent.service",
                "Systemd enabled symlink not faithfully represented")
        note=tf.extractfile("COLLECTION_SCOPE.txt").read()
        require(b"No sector image" in note and b"TPM quote" in note,
                "Missing acquisition-scope warning")
    with (OUT/"offline_snapshot_scope.csv").open(newline="",encoding="utf-8") as f:
        scope=list(csv.DictReader(f))
    require({x["artifact"] for x in scope}=={"offline_gateway_triage.tar",
                                           "endpoint_telemetry.sqlite3"},
            "Scope inventory incomplete")
    require(all(x["origin_verified"]=="no" for x in scope),
            "Simulation incorrectly advertised as real acquisition")
    return len(members)

def verify():
    events,flows=validate_db()
    members=validate_tar()
    return dict(events=events, flows=flows, triage_tar_members=members)

if __name__=="__main__":
    try:
        print("PASS scoped SQLite/tar forensic acquisition:",verify())
    except (OSError,ValueError,KeyError,IndexError,sqlite3.DatabaseError,tarfile.TarError) as e:
        print("FAIL scoped SQLite/tar forensic acquisition:",e,file=sys.stderr)
        sys.exit(1)
