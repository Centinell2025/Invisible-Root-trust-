#!/usr/bin/env python3
"""Generate deterministic SQLite and tar forensic acquisitions (synthetic only).

The fictional enterprise hosts are *not* actual victims. Artifacts resemble
Linux IR investigation materials but are not authentic live disk/TPM captures.
This generator never touches external systems.
"""
import csv
import hashlib
import io
import json
import random
import sqlite3
import tarfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "artifacts"
OUT.mkdir(parents=True, exist_ok=True)
SQLITE = OUT / "endpoint_telemetry.sqlite3"
BASE = datetime(2026, 9, 17, 2, 45, tzinfo=timezone.utc)
RNG = random.Random(2026091701)
HOSTS = ["nrg-gw-07", "nrg-bastion-02", "nrg-idp-01", "nrg-build-03", "nrg-sensor-04"]
SOURCES = ["local-agent", "syslog-export", "audit-extract", "session-replay", "inventory"]
KINDS = ["heartbeat", "package-query", "service-check", "syscall-read", "session-refresh",
         "network-maintenance", "rotate-log", "FIM-scan"]

def iso(ts):
    return ts.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")

def sha(x):
    return hashlib.sha256(x).hexdigest()

def read_rows(filename):
    with (OUT / filename).open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))

if SQLITE.exists():
    SQLITE.unlink()
db = sqlite3.connect(SQLITE)
db.executescript("""
PRAGMA journal_mode=DELETE;
PRAGMA synchronous=OFF;
CREATE TABLE host_events (
  event_id TEXT PRIMARY KEY,
  timestamp_utc TEXT NOT NULL,
  hostname TEXT NOT NULL,
  collector TEXT NOT NULL,
  event_kind TEXT NOT NULL,
  principal TEXT,
  process_id INTEGER,
  parent_id INTEGER,
  correlation_ref TEXT,
  object_path TEXT,
  description TEXT NOT NULL
);
CREATE INDEX idx_host_events_time ON host_events(timestamp_utc,hostname);
CREATE INDEX idx_host_events_refs ON host_events(correlation_ref,hostname);
CREATE INDEX idx_host_events_process ON host_events(hostname,process_id,parent_id);

CREATE TABLE netflow_sessions (
  session_id TEXT PRIMARY KEY,
  first_seen_utc TEXT NOT NULL,
  sensor TEXT NOT NULL,
  source_host TEXT NOT NULL,
  source_ip TEXT NOT NULL,
  source_port INTEGER NOT NULL,
  dest_ip TEXT NOT NULL,
  dest_port INTEGER NOT NULL,
  protocol TEXT NOT NULL,
  bytes_out INTEGER NOT NULL,
  pid_claim INTEGER,
  collector TEXT NOT NULL
);
CREATE INDEX idx_netflow_tuple ON netflow_sessions(source_ip,source_port,dest_ip,dest_port,protocol);

CREATE TABLE boot_inventory (
  sample_id TEXT PRIMARY KEY,
  timestamp_utc TEXT NOT NULL,
  hostname TEXT NOT NULL,
  boot_id TEXT NOT NULL,
  source TEXT NOT NULL,
  independently_verified INTEGER NOT NULL
);
CREATE TABLE specimen_inventory (
  specimen TEXT PRIMARY KEY,
  sha256 TEXT NOT NULL,
  collection_method TEXT NOT NULL,
  original_device_verified INTEGER NOT NULL
);
""")
kind_rows=[]
for i in range(1250):
    t = BASE + timedelta(seconds=RNG.randrange(0, 47*60))
    host = HOSTS[(i*7 + i//17) % len(HOSTS)]
    kind = KINDS[(i * 11 + i//23) % len(KINDS)]
    principal = ["backup", "metrics", "svc-maint", "buildbot", "deploy", "root"][i % 6]
    pid = 4000 + (i * 37) % 1500
    description = f"simulated {kind} on {host}; correlation ambiguous"
    kind_rows.append((f"BG-{i:05d}", iso(t),host,SOURCES[i%len(SOURCES)],kind,
                      principal,pid,1 if i%5==0 else pid-1,None,None,description))
# Pertinent events blend into the background data. They have more than one
# potential join, and no hidden "attacker=yes" answer label.
kind_rows.extend([
    ("EVT-0101","2026-09-17T03:02:10Z","nrg-gw-07","syslog-export","session-accepted","svc-maint",1772,902,"AUTH-701",None,"public-key authentication"),
    ("EVT-0102","2026-09-17T03:05:50Z","nrg-idp-01","identity-export","identity-token-issued","svc-maint",1302,1,"AUTH-702",None,"token issue recorded; human holder unknown"),
    ("EVT-0103","2026-09-17T03:06:12Z","nrg-gw-07","sudo-export","privilege-elevation","svc-maint",2417,1772,"AUTH-702",None,"sudo root session recorded"),
    ("EVT-0104","2026-09-17T03:12:27Z","nrg-gw-07","audit-extract","file-write","root",2421,2417,"AUTH-702","/etc/secureboot/policy.conf","audit serial 8104; write observation"),
    ("EVT-0105","2026-09-17T03:16:40Z","nrg-gw-07","local-agent","unit-start","root",2741,1,"PRC-2741","/etc/systemd/system/boot-health-agent.service","service started; local observation"),
    ("EVT-0106","2026-09-17T03:17:07Z","nrg-gw-07","local-agent","socket-open","root",2904,2741,"PRC-2904",None,"TCP egress process claim"),
    ("EVT-0107","2026-09-17T03:18:00Z","nrg-gw-07","local-software-check","policy-mismatch","root",2917,1,"CLM-005","/etc/secureboot/policy.conf","not a TPM quote"),
])
kind_rows.sort(key=lambda x:(x[1],x[0]))
db.executemany("INSERT INTO host_events VALUES (?,?,?,?,?,?,?,?,?,?,?)",kind_rows)

flows=[]
for i in range(375):
    t=BASE+timedelta(seconds=RNG.randrange(0,47*60))
    src="192.0.2."+str(16+(i%60))
    dst="198.51.100."+str(51+(i%35))
    dst_port=[443,80,53,22,8443][i%5]
    proto="UDP" if dst_port==53 else "TCP"
    flows.append((f"FLOW-{i:05d}",iso(t),"nrg-sensor-04",HOSTS[i%len(HOSTS)],
                  src,40000+i,dst,dst_port,proto,100+i*19,3000+i if i%3 else None,
                  "summarized-flow-export"))
flows.append(("FLOW-99999","2026-09-17T03:17:07Z","nrg-sensor-04","nrg-gw-07",
              "192.0.2.17",50544,"198.51.100.73",443,"TCP",9821,2904,
              "summarized-flow-export"))
flows.append(("FLOW-99998","2026-09-17T03:17:11Z","nrg-sensor-04","nrg-gw-07",
              "192.0.2.17",50545,"198.51.100.91",443,"TCP",314,3007,
              "summarized-flow-export"))
db.executemany("INSERT INTO netflow_sessions VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",flows)

db.executemany("INSERT INTO boot_inventory VALUES (?,?,?,?,?,?)",[
    ("BOOT-01","2026-09-17T02:51:10Z","nrg-gw-07","synthetic-boot-6e21a","local-boot-id-export",0),
    ("BOOT-02","2026-09-17T03:23:12Z","nrg-gw-07","synthetic-boot-6e21a","local-boot-id-export",0),
])
for name in ("policy_baseline.bin","policy_observed.bin",
             "boot-health-agent.service","edge_sensor_capture.pcap"):
    db.execute("INSERT INTO specimen_inventory VALUES (?,?,?,?)",
               (name,sha((OUT / name).read_bytes()),"deterministic-simulated-export",0))
db.commit()
db.execute("VACUUM")
db.close()

# A scoped *tar archive* is an offline lab acquisition from a fictional file
# inventory, not a sector-by-sector disk image. Synthetic boot service and
# policy bytes can be reconciled independently against FIM/SQLite inventories.
def add_file(tf, archive_name, blob):
    ti=tarfile.TarInfo(archive_name)
    ti.size=len(blob)
    ti.mtime=0
    ti.uid=ti.gid=0
    ti.uname=ti.gname=""
    ti.mode=0o644
    tf.addfile(ti,io.BytesIO(blob))

tar_path=OUT / "offline_gateway_triage.tar"
with tarfile.open(tar_path,mode="w",format=tarfile.PAX_FORMAT) as tf:
    add_file(tf,"etc/secureboot/policy.conf",(OUT/"policy_observed.bin").read_bytes())
    add_file(tf,"etc/systemd/system/boot-health-agent.service",(OUT/"boot-health-agent.service").read_bytes())
    add_file(tf,"var/log/auth.log",(OUT/"auth_syslog.log").read_bytes())
    add_file(tf,"var/log/audit/audit.log",(OUT/"auditd_extract.log").read_bytes())
    add_file(tf,"var/log/journal/export.jsonl",(OUT/"journal_extended.jsonl").read_bytes())
    add_file(tf,"etc/apt/apt.conf.d/20auto-upgrades",b'APT::Periodic::Update-Package-Lists "1";\n')
    add_file(tf,"etc/cron.d/monitoring",b"# routine metrics job\n*/15 * * * * root /usr/bin/true\n")
    add_file(tf,"COLLECTION_SCOPE.txt",
             b"SYNTHETIC LAB SNAPSHOT ONLY\nNo sector image, complete RAM dump, firmware extraction, or TPM quote.\n")
    ti=tarfile.TarInfo("etc/systemd/system/multi-user.target.wants/boot-health-agent.service")
    ti.type=tarfile.SYMTYPE
    ti.linkname="../boot-health-agent.service"
    ti.mtime=0
    ti.mode=0o777
    ti.uid=ti.gid=0
    tf.addfile(ti)

# Explicit acquisition scope; a tar archive does not prove that missing files
# were absent from a disk.
scope=[
    ["offline_gateway_triage.tar","selected configuration and log files","limited-file-level-export","no","cannot infer all on-disk persistence"],
    ["endpoint_telemetry.sqlite3","derived multihost events/netflow/boot metadata","deterministic-log-correlation-cache","no","derived fields are not independent corroboration"],
]
with (OUT/"offline_snapshot_scope.csv").open("w",encoding="utf-8",newline="") as f:
    writer=csv.writer(f)
    writer.writerow(["artifact","contents","acquisition","origin_verified","limitation"])
    writer.writerows(scope)

print(f"Generated SQLite correlation cache with {len(kind_rows)} events, {len(flows)} sessions and scoped tar triage.")
