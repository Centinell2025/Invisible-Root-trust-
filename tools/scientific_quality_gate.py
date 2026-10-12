#!/usr/bin/env python3
"""Scientific question/evidence QA gate for the fictional Invisible Root of Trust case.

This tests investigative answerability, cross-source consistency, uncertainty,
and release structure. It does NOT automatically grade narrative answers or
certify the exercise as HTB Insane.
"""
import argparse
import csv
import hashlib
import ipaddress
import json
import re
import struct
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "artifacts"
WORKSHEET = ROOT / "questions" / "INVESTIGATION.md"

# Each numbered question requires these distinct sources to be available.
# 'interpretation' means a human must evaluate the reasoning; 'fact' means
# the response contains at least one objective, reproducible evidence field.
QUESTION_CONTRACTS = {
     1: ("fact", ("secure_boot_attestation.csv", "journal_export.jsonl")),
     2: ("fact", ("policy_baseline.bin", "policy_observed.bin", "policy_digest_crosscheck.csv", "custody_manifest.sha256")),
     3: ("interpretation", ("audit_events.csv", "secure_boot_attestation.csv", "policy_digest_crosscheck.csv")),
     4: ("fact", ("secure_boot_attestation.csv", "firmware_inventory.csv")),
     5: ("interpretation", ("secure_boot_attestation.csv", "acquisition_gaps.csv", "policy_digest_crosscheck.csv")),
     6: ("fact", ("multi_host_events.csv", "auth_events.csv", "deployment_provenance.csv")),
     7: ("fact", ("audit_events.csv", "policy_digest_crosscheck.csv")),
     8: ("fact", ("change_tickets.csv", "deployment_provenance.csv", "firmware_inventory.csv")),
     9: ("fact", ("network_flows.csv", "synthetic_telemetry.pcap")),
    10: ("fact", ("session_lineage.csv", "auth_events.csv", "multi_host_events.csv")),
    11: ("fact", ("auth_events.csv", "audit_events.csv")),
    12: ("fact", ("audit_events.csv", "acquisition_gaps.csv")),
    13: ("interpretation", ("clock_calibration.csv", "multi_host_events.csv", "journal_export.jsonl")),
    14: ("interpretation", ("audit_events.csv", "journal_export.jsonl", "acquisition_gaps.csv")),
    15: ("fact", ("auth_events.csv", "session_lineage.csv", "acquisition_gaps.csv")),
    16: ("interpretation", ("session_lineage.csv", "auth_events.csv", "multi_host_events.csv")),
    17: ("interpretation", ("session_lineage.csv", "auth_events.csv", "audit_events.csv")),
    18: ("fact", ("journal_export.jsonl", "deployment_provenance.csv", "change_tickets.csv", "firmware_inventory.csv")),
    19: ("fact", ("network_flows.csv", "synthetic_telemetry.pcap")),
    20: ("interpretation", ("journal_export.jsonl", "memory_excerpt.bin", "acquisition_gaps.csv")),
    21: ("interpretation", ("benign_decoys.csv", "deployment_provenance.csv", "journal_export.jsonl")),
    22: ("interpretation", ("audit_events.csv", "change_tickets.csv", "multi_host_events.csv")),
    23: ("interpretation", ("secure_boot_attestation.csv", "acquisition_gaps.csv")),
    24: ("interpretation", ("journal_export.jsonl", "network_flows.csv", "claim_provenance.csv")),
    25: ("interpretation", ("claim_provenance.csv", "clock_calibration.csv", "multi_host_events.csv")),
    26: ("decision", ("audit_events.csv", "secure_boot_attestation.csv", "acquisition_gaps.csv", "change_tickets.csv")),
    27: ("decision", ("session_lineage.csv", "audit_events.csv", "network_flows.csv", "clock_calibration.csv")),
    28: ("decision", ("auth_events.csv", "network_flows.csv", "acquisition_gaps.csv")),
    29: ("decision", ("acquisition_gaps.csv", "secure_boot_attestation.csv", "deployment_provenance.csv")),
    30: ("decision", ("secure_boot_attestation.csv", "audit_events.csv", "acquisition_gaps.csv", "firmware_inventory.csv")),
}
PHASES = ((1, 5), (6, 9), (10, 14), (15, 20), (21, 25), (26, 30))
MANDATORY_COLUMNS = {
    "secure_boot_attestation.csv": {"utc", "host", "component", "expected_digest", "observed_digest", "status"},
    "auth_events.csv": {"utc", "host", "event_id", "account", "source_ip", "action", "result"},
    "audit_events.csv": {"utc", "host", "sequence", "event_id", "actor", "operation", "path"},
    "firmware_inventory.csv": {"utc", "host", "component", "version", "scheduled_operation"},
    "change_tickets.csv": {"ticket", "approved", "start_utc", "end_utc"},
    "deployment_provenance.csv": {"utc", "package_id", "ticket", "signature", "approval", "target"},
    "session_lineage.csv": {"utc", "host", "session_id", "principal", "event", "source_ip", "reference"},
    "multi_host_events.csv": {"utc", "host", "source", "event", "reference"},
    "network_flows.csv": {"utc", "host", "dst_ip", "dst_port", "protocol", "bytes_out"},
    "clock_calibration.csv": {"host", "source", "offset_seconds", "confidence"},
    "acquisition_gaps.csv": {"host", "collection", "artifact", "status", "inference"},
    "claim_provenance.csv": {"utc", "host", "source", "claim", "evidence_status"},
    "benign_decoys.csv": {"utc", "host", "event", "ticket", "assessment"},
    "policy_digest_crosscheck.csv": {"specimen", "sha256", "role"},
}
UTC = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
NUMBERED = re.compile(r"^\*\*(\d{2}) — ", re.MULTILINE)
PHASE = re.compile(r"^## Phase ([1-6]) — ", re.MULTILINE)

def require(condition, message):
    if not condition:
        raise ValueError(message)

def csv_rows(name):
    with (EVIDENCE / name).open(encoding="utf-8", newline="") as f:
        r = csv.DictReader(f)
        require(r.fieldnames is not None, name + ": no header")
        require(MANDATORY_COLUMNS.get(name, set()).issubset(set(r.fieldnames)), name + ": missing mandatory columns")
        result = list(r)
    require(bool(result), name + ": empty stream")
    return result

def iso_utc(s):
    require(bool(UTC.fullmatch(s)), "Unlabelled or invalid UTC timestamp: " + s)
    dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    require(dt.tzinfo is not None, "Timestamp without timezone")
    return dt

def check_question_contracts(text):
    numbers = [int(x) for x in NUMBERED.findall(text)]
    require(numbers == list(range(1, 31)), "Worksheet must contain 30 sequential, nonduplicated question IDs")
    require([int(x) for x in PHASE.findall(text)] == list(range(1, 7)), "Six investigative phases are required")
    require(tuple(sorted(QUESTION_CONTRACTS)) == tuple(range(1, 31)), "Question contract mapping incomplete")
    require(sum(end - start + 1 for start, end in PHASES) == 30, "Phase question counts inconsistent")
    for q, (kind, sources) in QUESTION_CONTRACTS.items():
        require(kind in {"fact", "interpretation", "decision"}, f"Q{q:02} kind invalid")
        require(len(set(sources)) >= 2, f"Q{q:02} must have at least two source candidates")
        for filename in sources:
            require((EVIDENCE / filename).is_file(), f"Q{q:02} missing source {filename}")
    require("NOT ESTABLISHED" in text and "no-go" in text.lower(), "Uncertainty and decision gate language required")
    return numbers

def inspect_pcap(data):
    require(len(data) >= 40, "PCAP too short")
    require(struct.unpack_from("<I", data)[0] == 0xA1B2C3D4, "Wrong PCAP endianness/magic")
    require(struct.unpack_from("<I", data, 20)[0] == 1, "Expected Ethernet link type")
    frames = []
    pos = 24
    while pos < len(data):
        require(len(data) - pos >= 16, "Truncated packet header")
        sec, usec, captured, original = struct.unpack_from("<IIII", data, pos)
        require(0 <= usec < 1000000, "Invalid capture microsecond")
        require(0 < captured <= original <= 65535, "Invalid captured packet lengths")
        pos += 16
        require(pos + captured <= len(data), "Truncated packet data")
        frame = data[pos:pos + captured]
        require(len(frame) >= 34 and frame[12:14] == b"\x08\x00", "Expected Ethernet IPv4 frame")
        ihl = (frame[14] & 15) * 4
        require(ihl >= 20 and len(frame) >= 14 + ihl, "Invalid IPv4 header")
        total_len = struct.unpack_from("!H", frame, 16)[0]
        require(total_len >= ihl and 14 + total_len <= len(frame), "IPv4 length inconsistent")
        frames.append({
            "epoch": sec, "microsecond": usec, "protocol": frame[23],
            "src": str(ipaddress.IPv4Address(frame[26:30])),
            "dst": str(ipaddress.IPv4Address(frame[30:34])),
        })
        pos += captured
    require(pos == len(data), "PCAP trailing data or framing error")
    require(bool(frames), "No captured packets")
    return frames

def check_evidence():
    # Reproducibility of extracted records, not authenticity of original acquisition.
    manifest = (EVIDENCE / "custody_manifest.sha256").read_text(encoding="utf-8").splitlines()
    expected = {}
    for line in manifest:
        h, sep, name = line.partition("  ")
        require(bool(sep) and re.fullmatch("[0-9a-f]{64}", h), "Invalid custody manifest record")
        require(name not in expected and "/" not in name and "\\" not in name, "Duplicate/unsafe evidence path")
        expected[name] = h
    present = {p.name for p in EVIDENCE.iterdir() if p.is_file() and p.name != "custody_manifest.sha256"}
    require(present == set(expected), "Manifest not synchronized with evidence")
    for name, h in expected.items():
        require(hashlib.sha256((EVIDENCE / name).read_bytes()).hexdigest() == h, "Evidence digest mismatch: " + name)

    for name in MANDATORY_COLUMNS:
        rows = csv_rows(name)
        for row in rows:
            if "utc" in row:
                iso_utc(row["utc"])

    att = csv_rows("secure_boot_attestation.csv")
    mismatches = [x for x in att if x["status"] == "mismatch" and x["expected_digest"] != x["observed_digest"]]
    require(len(mismatches) == 1, "Attestation mismatch must be uniquely identifiable")
    require(any(x["status"] == "match" for x in att), "Attestation baseline missing")
    require(iso_utc(mismatches[0]["utc"]) > min(iso_utc(x["utc"]) for x in att), "Anomaly precedes baseline")

    policy = csv_rows("policy_digest_crosscheck.csv")
    require({r["specimen"] for r in policy} == {"policy_baseline.bin", "policy_observed.bin"}, "Incomplete policy ledger")
    for row in policy:
        require(hashlib.sha256((EVIDENCE / row["specimen"]).read_bytes()).hexdigest() == row["sha256"],
                "Policy digest does not match bytes")
    require((EVIDENCE / "policy_baseline.bin").read_bytes() != (EVIDENCE / "policy_observed.bin").read_bytes(),
            "Policy specimens are identical")

    auth = csv_rows("auth_events.csv")
    audit = csv_rows("audit_events.csv")
    multi = csv_rows("multi_host_events.csv")
    sessions = csv_rows("session_lineage.csv")
    require(len({x["session_id"] for x in sessions}) == len(sessions), "Duplicate session IDs")
    auth_refs = {x["event_id"] for x in auth}
    writes = [x for x in audit if x["operation"] == "write"]
    require(len(writes) == 1 and writes[0]["event_id"] in auth_refs, "Write has no corroborated privilege reference")
    require(any(x["reference"] == writes[0]["event_id"] and x["host"] != writes[0]["host"]
                and x["event"] == "configuration-write-observed" for x in multi),
            "No cross-host observation of the configuration write")
    require(any(x["reference"] == writes[0]["event_id"] for x in sessions),
            "No session lineage correlated with the write")
    sequence = sorted(int(x["sequence"]) for x in audit)
    require(len(sequence) == len(set(sequence)), "Repeated audit sequence number")
    require(any(b - a > 1 for a, b in zip(sequence, sequence[1:])), "No demonstrable audit gap")
    gaps = csv_rows("acquisition_gaps.csv")
    require(any(x["collection"] == "audit" and x["status"] == "missing-rows" for x in gaps),
            "Audit gap not documented")
    require(all(x["inference"] == "unknown" for x in gaps),
            "Missing evidence must never be coded as negative evidence")

    ticket = csv_rows("change_tickets.csv")
    deployments = csv_rows("deployment_provenance.csv")
    require(any(x["approved"] == "no" for x in ticket), "No unapproved change")
    require(any(x["approval"] == "rejected" for x in deployments), "No rejected deployment decoy")
    require(any(x["approval"] == "approved" for x in deployments), "No approved deployment decoy")
    for t in ticket:
        if t["approved"] == "no":
            require(not any(x["ticket"] == t["ticket"] and x["approval"] == "approved" for x in deployments),
                    "Unapproved ticket incorrectly has approved deployment")

    clocks = csv_rows("clock_calibration.csv")
    clock_keys = [(x["host"], x["source"]) for x in clocks]
    require(len(clock_keys) == len(set(clock_keys)), "Ambiguous duplicate clock calibrations")
    require(any(x["source"] == "journal" and int(x["offset_seconds"]) != 0 for x in clocks),
            "No journal clock skew test case")
    journal = [json.loads(s) for s in (EVIDENCE / "journal_export.jsonl").read_text(encoding="utf-8").splitlines()]
    require(bool(journal), "Empty journal evidence")
    for j in journal:
        iso_utc(j["utc"])
    require(any(j["unit"] == "nrg-update.service" for j in journal), "No contradicted local benign claim")

    flows = csv_rows("network_flows.csv")
    packets = inspect_pcap((EVIDENCE / "synthetic_telemetry.pcap").read_bytes())
    require(all(iso_utc(f["utc"]) for f in flows), "Invalid flow timestamps")
    require(any(p["dst"] == f["dst_ip"] and p["protocol"] == 17 and f["protocol"].upper() == "TCP"
                for p in packets for f in flows), "No deliberate UDP/TCP corroboration trap")
    require(all(datetime.fromtimestamp(p["epoch"], timezone.utc).year == 2026 for p in packets),
            "Packet date differs from 2026 incident without an explained calibration")
    require(all(int(f["bytes_out"]) >= 0 for f in flows), "Negative flow bytes")
    require(not any(x["collection"] == "firmware" and x["status"] == "collected" for x in gaps),
            "Case limitations unexpectedly changed: review hardware-root trust proposition")

    return {
        "evidence_files": len(expected),
        "packet_count": len(packets),
        "questions": len(QUESTION_CONTRACTS),
        "automatable_fact_questions": sum(1 for kind, _ in QUESTION_CONTRACTS.values() if kind == "fact"),
        "human_review_questions": sum(1 for kind, _ in QUESTION_CONTRACTS.values() if kind != "fact"),
    }

def run(mode="engineering"):
    check_question_contracts(WORKSHEET.read_text(encoding="utf-8"))
    stats = check_evidence()
    if mode == "insane":
        # This must not be allowed to pass purely on self-produced source-code tests.
        blockers = [
            "Private instructor answer key and exact machine-grading contracts not independently verified",
            "No recorded independent cold solve by a non-author investigator",
            "No independently acquired firmware/boot-chain or realistic full-disk/RAM forensic specimen",
            "One-packet UDP PCAP cannot validate the reported TCP conversation",
        ]
        raise ValueError("INSANE RELEASE BLOCKED: " + "; ".join(blockers))
    print("PASS: scientific engineering gate; 30/30 question-source contracts; " + json.dumps(stats, sort_keys=True))
    print("REVIEW REQUIRED: interpreting answers, answer uniqueness, cold solve, and Insane readiness are NOT certified")
    return stats

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--mode", choices=["engineering", "insane"], default="engineering")
    args = p.parse_args()
    try:
        run(args.mode)
    except (OSError, ValueError, KeyError, IndexError, UnicodeError, json.JSONDecodeError, struct.error) as e:
        print("FAIL:", e, file=sys.stderr)
        sys.exit(2)
