#!/usr/bin/env python3
"""Deterministic synthetic DFIR artifacts. Standard library only. No system modifications."""
from pathlib import Path
import csv, hashlib, json

ROOT=Path(__file__).resolve().parent.parent
OUT=ROOT/"artifacts"
OUT.mkdir(exist_ok=True)
def csvfile(name,fields,rows):
    with (OUT/name).open("w",newline="",encoding="utf-8") as f:
        w=csv.DictWriter(f,fieldnames=fields); w.writeheader(); w.writerows(rows)
def jsonl(name,rows):
    (OUT/name).write_text("".join(json.dumps(x,sort_keys=True)+"\n" for x in rows),encoding="utf-8")
host="nrg-gw-07"
csvfile("secure_boot_attestation.csv",["utc","host","component","expected_digest","observed_digest","status"],[
 {"utc":"2026-09-17T02:55:00Z","host":host,"component":"shim-policy","expected_digest":"a1"*32,"observed_digest":"a1"*32,"status":"match"},
 {"utc":"2026-09-17T03:18:00Z","host":host,"component":"shim-policy","expected_digest":"a1"*32,"observed_digest":"b2"*32,"status":"mismatch"},
 {"utc":"2026-09-17T03:19:00Z","host":host,"component":"kernel-image","expected_digest":"c3"*32,"observed_digest":"c3"*32,"status":"match"}])
csvfile("auth_events.csv",["utc","host","event_id","account","source_ip","action","result"],[
 {"utc":"2026-09-17T03:02:10Z","host":host,"event_id":"AUTH-701","account":"svc-maint","source_ip":"192.0.2.44","action":"ssh-login","result":"success"},
 {"utc":"2026-09-17T03:06:12Z","host":host,"event_id":"AUTH-702","account":"svc-maint","source_ip":"192.0.2.44","action":"sudo-session","result":"success"}])
csvfile("audit_events.csv",["utc","host","sequence","event_id","actor","operation","path"],[
 {"utc":"2026-09-17T03:06:15Z","host":host,"sequence":"8101","event_id":"AUTH-702","actor":"svc-maint","operation":"open","path":"/etc/secureboot/policy.conf"},
 {"utc":"2026-09-17T03:12:27Z","host":host,"sequence":"8104","event_id":"AUTH-702","actor":"svc-maint","operation":"write","path":"/etc/secureboot/policy.conf"},
 {"utc":"2026-09-17T03:13:01Z","host":host,"sequence":"8105","event_id":"AUTH-702","actor":"svc-maint","operation":"close","path":"/etc/secureboot/policy.conf"}])
jsonl("journal_export.jsonl",[
 {"utc":"2026-09-17T03:12:29Z","host":host,"unit":"nrg-update.service","message":"Routine signed update completed","source":"local-service"},
 {"utc":"2026-09-17T03:16:40Z","host":host,"unit":"boot-health-agent.service","message":"boot-health-agent launched","source":"systemd"},
 {"utc":"2026-09-17T03:18:02Z","host":host,"unit":"attestationd.service","message":"measured policy hash differs from baseline","source":"attestation-agent"}])
csvfile("network_flows.csv",["utc","host","dst_ip","dst_port","protocol","bytes_out"],[
 {"utc":"2026-09-17T03:17:07Z","host":host,"dst_ip":"198.51.100.73","dst_port":"443","protocol":"TCP","bytes_out":"9821"}])
csvfile("change_tickets.csv",["ticket","start_utc","end_utc","scope","approved","owner"],[
 {"ticket":"CHG-421","start_utc":"2026-09-17T03:00:00Z","end_utc":"2026-09-17T03:30:00Z","scope":"Firmware maintenance on nrg-gw-07","approved":"no","owner":"Operations"}])
csvfile("firmware_inventory.csv",["utc","host","component","version","scheduled_operation"],[
 {"utc":"2026-09-17T02:50:00Z","host":host,"component":"shim-policy","version":"2.4-approved","scheduled_operation":"none"},
 {"utc":"2026-09-17T03:25:00Z","host":host,"component":"shim-policy","version":"2.4-unverified","scheduled_operation":"none"}])
manifest=[]
for p in sorted(OUT.iterdir()):
    if p.is_file() and p.name!="custody_manifest.sha256":
        manifest.append(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}")
(OUT/"custody_manifest.sha256").write_text("\n".join(manifest)+"\n",encoding="utf-8")
print(f"Generated {len(manifest)} evidence files in {OUT}")
