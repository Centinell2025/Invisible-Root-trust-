#!/usr/bin/env python3
"""Generate deterministic multi-host scientific investigation evidence.
All names, accounts, addresses and events are fictional. No live system access.
"""
import csv
import hashlib
import json
from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / "artifacts"
OUT.mkdir(exist_ok=True)

def emit(name, fields, rows):
    with (OUT/name).open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

hosts = ["nrg-gw-07", "nrg-bastion-02", "nrg-idp-01", "nrg-build-03", "nrg-sensor-04"]
sessions = [
    ("2026-09-17T02:58:03Z","nrg-bastion-02","SES-900","svc-maint","session-open","192.0.2.44","AUTH-701"),
    ("2026-09-17T03:01:55Z","nrg-bastion-02","SES-901","svc-maint","session-accepted","192.0.2.44","AUTH-701"),
    ("2026-09-17T03:03:40Z","nrg-idp-01","SES-902","svc-maint","token-refresh","192.0.2.44","AUTH-702"),
    ("2026-09-17T03:05:50Z","nrg-idp-01","SES-903","svc-maint","token-issued","192.0.2.44","AUTH-702"),
    ("2026-09-17T03:07:19Z","nrg-bastion-02","SES-904","svc-maint","command-channel-open","192.0.2.44","AUTH-702"),
    ("2026-09-17T03:11:58Z","nrg-bastion-02","SES-905","svc-maint","session-heartbeat","192.0.2.44","AUTH-702"),
    ("2026-09-17T03:12:31Z","nrg-bastion-02","SES-906","svc-maint","configuration-write-observed","192.0.2.44","AUTH-702"),
    ("2026-09-17T03:20:22Z","nrg-bastion-02","SES-907","svc-maint","session-close","192.0.2.44","AUTH-702"),
]
emit("session_lineage.csv",["utc","host","session_id","principal","event","source_ip","reference"],[
    dict(zip(["utc","host","session_id","principal","event","source_ip","reference"],x)) for x in sessions
])
ledger = [
    ("2026-09-17T02:54:00Z","nrg-build-03","PKG-201","CHG-419","signed","approved","nrg-build-03"),
    ("2026-09-17T03:04:00Z","nrg-build-03","PKG-202","CHG-421","signed","pending","nrg-gw-07"),
    ("2026-09-17T03:10:00Z","nrg-build-03","PKG-203","CHG-418","signed","approved","nrg-gw-07"),
    ("2026-09-17T03:12:10Z","nrg-build-03","PKG-204","CHG-421","unsigned","rejected","nrg-gw-07"),
    ("2026-09-17T03:15:30Z","nrg-build-03","PKG-205","CHG-419","signed","approved","nrg-build-03"),
]
emit("deployment_provenance.csv",["utc","host","package_id","ticket","signature","approval","target"],[
    dict(zip(["utc","host","package_id","ticket","signature","approval","target"],x)) for x in ledger
])
claims = [
    ("2026-09-17T03:12:29Z","nrg-gw-07","CLM-001","nrg-update.service","signed-maintenance","local-journal","self-reported"),
    ("2026-09-17T03:13:10Z","nrg-build-03","CLM-002","CHG-421","approved-deployment","deployment-ledger","contradicted"),
    ("2026-09-17T03:16:40Z","nrg-gw-07","CLM-003","boot-health-agent.service","service-started","local-journal","self-reported"),
    ("2026-09-17T03:17:07Z","nrg-sensor-04","CLM-004","198.51.100.73","tcp-egress","flow-export","unverified-by-pcap"),
    ("2026-09-17T03:18:02Z","nrg-gw-07","CLM-005","shim-policy","measurement-mismatch","attestation-agent","self-reported"),
]
emit("claim_provenance.csv",["utc","host","claim_id","subject","claim","source","evidence_status"],[
    dict(zip(["utc","host","claim_id","subject","claim","source","evidence_status"],x)) for x in claims
])
# This is a deliberately incomplete acquisition ledger: 'not collected' is not 'absent'.
gaps = [
    ("nrg-gw-07","03:06:15Z","03:12:27Z","audit","sequence-8102-8103","missing-rows","unknown"),
    ("nrg-gw-07","03:12:00Z","03:20:00Z","volatile-memory","full-memory-image","not-collected","unknown"),
    ("nrg-gw-07","03:12:00Z","03:20:00Z","firmware","independent-firmware-image","not-collected","unknown"),
    ("nrg-sensor-04","03:16:00Z","03:19:00Z","network","tcp-session-packets","not-collected","unknown"),
    ("nrg-idp-01","03:00:00Z","03:10:00Z","identity","human-operator-binding","not-collected","unknown"),
]
emit("acquisition_gaps.csv",["host","start_utc_time","end_utc_time","collection","artifact","status","inference"],[
    dict(zip(["host","start_utc_time","end_utc_time","collection","artifact","status","inference"],x)) for x in gaps
])
print("Generated four deterministic research evidence tables")
