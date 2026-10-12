#!/usr/bin/env python3
"""Validate all generated evidence, manifest and essential cross-source facts."""
import csv
import hashlib
import json
import re
import struct
import sys
from datetime import datetime
from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / "artifacts"
HEX = re.compile(r"^[0-9a-f]{64}$")

def require(condition, message):
    if not condition:
        raise ValueError(message)

def rows(name):
    with (OUT/name).open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))

def utc(value):
    require(value.endswith("Z"), "Timestamp not UTC: " + value)
    return datetime.fromisoformat(value.replace("Z", "+00:00"))

def main():
    lines = (OUT/"custody_manifest.sha256").read_text(encoding="utf-8").splitlines()
    expected = {}
    for line in lines:
        digest, sep, name = line.partition("  ")
        require(sep and HEX.fullmatch(digest), "Invalid manifest entry")
        require(name and name not in expected and "/" not in name and "\\" not in name and name not in (".", ".."), "Unsafe manifest name")
        expected[name] = digest
    actual = {p.name for p in OUT.iterdir() if p.is_file() and p.name != "custody_manifest.sha256"}
    require(actual == set(expected), "Manifest inventory mismatch")
    for name, digest in expected.items():
        require(hashlib.sha256((OUT/name).read_bytes()).hexdigest() == digest, "Hash mismatch: " + name)

    att = rows("secure_boot_attestation.csv")
    auth = rows("auth_events.csv")
    audit = rows("audit_events.csv")
    flows = rows("network_flows.csv")
    tickets = rows("change_tickets.csv")
    firmware = rows("firmware_inventory.csv")
    multi = rows("multi_host_events.csv")
    offsets = rows("clock_calibration.csv")
    decoys = rows("benign_decoys.csv")
    ledger = rows("policy_digest_crosscheck.csv")
    journal = [json.loads(line) for line in (OUT/"journal_export.jsonl").read_text().splitlines()]

    for group in (att, auth, audit, flows, firmware, multi, decoys, journal):
        require(group, "Empty evidence stream")
        for row in group:
            utc(row["utc"])
    for row in att:
        require(HEX.fullmatch(row["expected_digest"]) and HEX.fullmatch(row["observed_digest"]), "Invalid attestation digest")
        require((row["status"] == "match") == (row["expected_digest"] == row["observed_digest"]), "Inconsistent attestation status")
    mismatches = [r for r in att if r["status"] == "mismatch"]
    require(len(mismatches) == 1 and mismatches[0]["host"] == "nrg-gw-07", "Unexpected attestation anomaly")
    require(len(auth) >= 2 and any(r["action"] == "sudo-session" for r in auth), "Missing privilege event")
    auth_ids = {r["event_id"] for r in auth}
    writes = [r for r in audit if r["operation"] == "write"]
    require(len(writes) == 1 and writes[0]["event_id"] in auth_ids, "Uncorrelated audit write")
    seq = [int(r["sequence"]) for r in audit]
    require(seq == sorted(set(seq)) and any(b-a > 1 for a,b in zip(seq,seq[1:])), "Audit gap missing or invalid")
    require(any(r["approved"] == "no" for r in tickets), "No unapproved change")
    require(any(r["scheduled_operation"] == "none" for r in firmware), "Missing baseline")
    require(any(r["unit"] == "attestationd.service" for r in journal), "Missing journal attestation")
    require(any(r["event"] == "configuration-write-observed" and r["reference"] == writes[0]["event_id"] for r in multi), "Missing multihost corroboration")
    require(len({r["host"] for r in offsets}) == len(offsets), "Duplicate clock calibration host")
    require(any(r["ticket"] != "CHG-421" for r in decoys), "Missing unrelated maintenance")
    require(len(flows) >= 1 and all(int(r["bytes_out"]) >= 0 for r in flows), "Invalid network flows")
    require({r["specimen"] for r in ledger} == {"policy_baseline.bin", "policy_observed.bin"}, "Incomplete binary ledger")
    for row in ledger:
        require(hashlib.sha256((OUT/row["specimen"]).read_bytes()).hexdigest() == row["sha256"], "Binary ledger mismatch")

    pcap = (OUT/"synthetic_telemetry.pcap").read_bytes()
    require(len(pcap) >= 40 and struct.unpack_from("<I", pcap)[0] == 0xa1b2c3d4, "Invalid PCAP magic")
    require(struct.unpack_from("<I", pcap, 20)[0] == 1, "Unexpected PCAP link type")
    size = struct.unpack_from("<I", pcap, 32)[0]
    require(len(pcap) == 40+size and size >= 34, "Invalid PCAP frame size")
    require(pcap[52:54] == b"\x08\x00" and pcap[63] == 17, "Unexpected PCAP protocol")
    print(f"PASS: {len(expected)} evidence files, hashes and cross-source constraints")

if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, IndexError, struct.error, json.JSONDecodeError) as exc:
        print("FAIL:", exc, file=sys.stderr)
        sys.exit(1)
