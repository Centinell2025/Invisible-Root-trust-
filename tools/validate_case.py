#!/usr/bin/env python3
"""Validate generated synthetic evidence and cross-source invariants."""
from pathlib import Path
import csv, hashlib, json, sys
ROOT=Path(__file__).resolve().parent.parent
OUT=ROOT/"artifacts"
def rows(name):
    with (OUT/name).open(newline="",encoding="utf-8") as f: return list(csv.DictReader(f))
def check(condition,msg):
    if not condition: raise AssertionError(msg)
def main():
    manifest=(OUT/"custody_manifest.sha256").read_text().splitlines()
    expected={}
    for line in manifest:
        digest,filename=line.split("  ",1)
        check(filename not in expected,"duplicate manifest entry")
        check("/" not in filename and "\\" not in filename,"unsafe manifest path")
        expected[filename]=digest
    actual={p.name for p in OUT.iterdir() if p.is_file() and p.name!="custody_manifest.sha256"}
    check(actual==set(expected),"manifest does not cover exact evidence set")
    for name,digest in expected.items():
        check(hashlib.sha256((OUT/name).read_bytes()).hexdigest()==digest,f"hash mismatch: {name}")
    attest=rows("secure_boot_attestation.csv")
    auth=rows("auth_events.csv")
    audit=rows("audit_events.csv")
    flows=rows("network_flows.csv")
    tickets=rows("change_tickets.csv")
    firmware=rows("firmware_inventory.csv")
    journal=[json.loads(s) for s in (OUT/"journal_export.jsonl").read_text().splitlines()]
    check(len(attest)>=3 and any(x["status"]=="mismatch" and x["expected_digest"]!=x["observed_digest"] for x in attest),"missing attestation mismatch")
    check(all(len(x["expected_digest"])==64 and len(x["observed_digest"])==64 for x in attest),"bad digest length")
    check(any(x["action"]=="sudo-session" for x in auth),"no escalation event")
    check(any(x["event_id"]==y["event_id"] for x in audit for y in auth),"no correlated event IDs")
    check(any(int(y["sequence"])-int(x["sequence"])>1 for x,y in zip(audit,audit[1:])),"no audit sequence gap")
    check(any(x["approved"]=="no" for x in tickets),"no unauthorized maintenance record")
    check(any(x["scheduled_operation"]=="none" for x in firmware),"no independent inventory record")
    check(any(x["unit"]=="attestationd.service" for x in journal),"no attestation journal event")
    check(len(flows)>0,"no network evidence")
    for collection in [attest,auth,audit,flows,firmware]:
        check(all(x["utc"].endswith("Z") for x in collection),"non-UTC timestamp")
    print(f"PASS: {len(expected)} artifacts, hashes, and cross-source case invariants")
if __name__=="__main__":
    try: main()
    except (AssertionError,FileNotFoundError,ValueError,KeyError) as exc:
        print(f"FAIL: {exc}",file=sys.stderr);sys.exit(1)
