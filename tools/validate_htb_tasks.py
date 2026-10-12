#!/usr/bin/env python3
"""Validate the *public* 16-task HTB handoff without exposing grading flags.

Final answer correctness and acceptable variants must be tested in a
confidential instructor package; this checker validates coverage and format.
"""
import re
import sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
TASK_FILE=ROOT/"questions/HTB_PLAYER_TASKS.md"
ROOT_README=ROOT/"README.txt"
REVIEW=ROOT/"docs/HTB_REVIEWER_HANDOFF.md"
ART=ROOT/"artifacts"

TASKS={
 1: ("secure_boot_attestation.csv","host"),
 2: ("secure_boot_attestation.csv","UTC"),
 3: ("policy_observed.bin","sha256"),
 4: ("change_tickets.csv","ticket"),
 5: ("audit_events.csv","auth-reference"),
 6: ("auditd_extract.log","pid"),
 7: ("audit_events.csv","audit-serial-range"),
 8: ("deployment_provenance.csv","package"),
 9: ("offline_gateway_triage.tar","systemd-unit"),
10: ("offline_gateway_triage.tar","sha256"),
11: ("process_lineage.csv","parent-pid"),
12: ("edge_sensor_capture.pcap","tcp-source-port"),
13: ("edge_sensor_capture.pcap","tcp-payload-byte-count"),
14: ("endpoint_telemetry.sqlite3","row-count"),
15: ("trust_anchor_inventory.csv","collection-status"),
16: ("trust_anchor_inventory.csv","trust-conclusion"),
}
NUMBERED=re.compile(r"^\*\*Task (\d{2})\.\*\*",re.M)
FORMATS=re.compile(r"^\*\*Answer format:\*\*",re.M)

def check():
    tasks=TASK_FILE.read_text(encoding="utf-8")
    nums=[int(n) for n in NUMBERED.findall(tasks)]
    if nums!=list(range(1,17)):
        raise ValueError("Exact-answer task numbers must be 01–16, unique and sequential")
    if len(FORMATS.findall(tasks))!=16:
        raise ValueError("Each task must contain exactly one answer format")
    if len(TASKS)!=16:
        raise ValueError("Task/source contract incomplete")
    for n,(name,kind) in TASKS.items():
        if not (ART/name).is_file():
            raise ValueError(f"Missing evidence for task {n:02}: {name}")
    if "NOT ESTABLISHED" not in tasks or "human assessed" not in tasks.lower():
        raise ValueError("Science boundary/human research extension not clearly labeled")
    if re.search(r"(?m)^\s*flag\s*:",tasks):
        raise ValueError("Grading flags must never appear in public student task file")
    readme=ROOT_README.read_text(encoding="utf-8")
    if ("BEACON OF THE EAGLE LLC" not in readme or
        "HTB_PLAYER_TASKS.md" not in readme or
        "custody_manifest.sha256" not in readme):
        raise ValueError("Mandatory README has missing author/task/hash instructions")
    handoff=REVIEW.read_text(encoding="utf-8")
    if "Private instructor verification needed" not in handoff:
        raise ValueError("Reviewer handoff fails to disclose private-key blocker")
    print(f"PASS: {len(nums)} sequenced exact-answer task specifications, source coverage, README and authorship")
    print("INSTRUCTOR VALIDATION STILL REQUIRED: exact flags, admissible variants, full writeup and screenshot evidence")

if __name__=="__main__":
    try:check()
    except (OSError,ValueError) as e:
        print("FAIL:",e,file=sys.stderr)
        sys.exit(1)
