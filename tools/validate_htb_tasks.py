#!/usr/bin/env python3
"""Validate the *public* 25-task HTB handoff without exposing grading flags.

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
14: ("clock_calibration.csv","normalized-utc"),
15: ("endpoint_telemetry.sqlite3","event-id"),
16: ("trust_anchor_inventory.csv","collection-status"),
17: ("trust_anchor_inventory.csv","trust-conclusion"),
18: ("idp_session_audit.jsonl","issued-token"),
19: ("change_approval_audit.jsonl","security-denial"),
20: ("file_integrity_timeline.csv","observed-policy-change"),
21: ("firewall_edge_decisions.jsonl","five-tuple-allow"),
22: ("edge_sensor_capture.pcap","cross-product-coverage-gap"),
23: ("session_lineage.csv","command-channel"),
24: ("systemd_lifecycle.jsonl","symlink-enablement"),
25: ("endpoint_telemetry.sqlite3","unverified-boot-sample"),
}
# Hard-tier tasks must require joined *existing evidence categories*.
HARD_SOURCE_CONTRACTS = {
    18: ("auth_events.csv", "session_lineage.csv", "idp_session_audit.jsonl", "process_lineage.csv"),
    19: ("change_tickets.csv", "deployment_provenance.csv", "change_approval_audit.jsonl", "claim_provenance.csv"),
    20: ("audit_events.csv", "file_integrity_timeline.csv", "policy_observed.bin", "measurement_derivation.csv"),
    21: ("socket_observations.csv", "endpoint_telemetry.sqlite3", "edge_sensor_capture.pcap", "firewall_edge_decisions.jsonl"),
    22: ("endpoint_telemetry.sqlite3", "network_flows.csv", "edge_sensor_capture.pcap", "sensor_capture_scope.csv"),
    23: ("session_lineage.csv", "idp_session_audit.jsonl", "auth_events.csv", "audit_events.csv"),
    24: ("systemd_lifecycle.jsonl", "offline_gateway_triage.tar", "systemd_unit_inventory.csv", "file_integrity_timeline.csv"),
    25: ("endpoint_telemetry.sqlite3", "systemd_lifecycle.jsonl", "offline_gateway_triage.tar", "offline_snapshot_scope.csv"),
}

NUMBERED=re.compile(r"^\*\*Task (\d{2})\.\*\*",re.M)
FORMATS=re.compile(r"^\*\*Answer format:\*\*",re.M)

def check():
    tasks=TASK_FILE.read_text(encoding="utf-8")
    nums=[int(n) for n in NUMBERED.findall(tasks)]
    if nums!=list(range(1,26)):
        raise ValueError("Exact-answer task numbers must be 01–25, unique and sequential")
    if len(FORMATS.findall(tasks))!=25:
        raise ValueError("Each task must contain exactly one answer format")
    if len(TASKS)!=25:
        raise ValueError("Task/source contract incomplete")
    for n,(name,kind) in TASKS.items():
        if not (ART/name).is_file():
            raise ValueError(f"Missing evidence for task {n:02}: {name}")
    if set(HARD_SOURCE_CONTRACTS) != set(range(18,26)):
        raise ValueError("Hard-tier 18–25 evidence contracts incomplete")
    for task_number, sources in HARD_SOURCE_CONTRACTS.items():
        if len(set(sources)) < 3:
            raise ValueError(f"Hard task {task_number} is not multi-source")
        for source in sources:
            if not (ART/source).is_file():
                raise ValueError(f"Hard task {task_number} missing supporting source {source}")
    if "NOT ESTABLISHED" not in tasks or "instructor reviewed" not in tasks.lower():
        raise ValueError("Science boundary/human research extension not clearly labeled")
    if re.search(r"(?m)^\s*flag\s*:",tasks):
        raise ValueError("Grading flags must never appear in public student task file")
    readme=ROOT_README.read_text(encoding="utf-8")
    if ("BEACON OF THE EAGLE LLC" not in readme or
        "HTB_PLAYER_TASKS.md" not in readme or
        "custody_manifest.sha256" not in readme):
        raise ValueError("Mandatory README has missing author/task/hash instructions")
    handoff=REVIEW.read_text(encoding="utf-8")
    if ("25 exact-value" not in handoff or
        "independent blind test pending" not in handoff.lower()):
        raise ValueError("Reviewer handoff must disclose private answer key status and independent-testing blocker")
    print(f"PASS: {len(nums)} sequenced exact-answer task specifications, source coverage, README and authorship")
    print("INSTRUCTOR VALIDATION REQUIRED: private 25-task answer key, independent cold solve and full writeup")

if __name__=="__main__":
    try:check()
    except (OSError,ValueError) as e:
        print("FAIL:",e,file=sys.stderr)
        sys.exit(1)
