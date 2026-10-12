#!/usr/bin/env python3
"""Read-only scientific timeline analysis for synthetic DFIR evidence.

Produces an uncertainty-aware event table, not a verdict or answer key.
Clock offset convention: recorded timestamp = true timestamp + offset.
Confidence labels are qualitative and are NOT probability estimates.
"""
import argparse
import csv
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
A = ROOT / "artifacts"

def parse_utc(s):
    if not s.endswith("Z"):
        raise ValueError("UTC timestamp must end with Z: " + s)
    return datetime.fromisoformat(s.replace("Z", "+00:00"))

def iso(t):
    return t.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")

def read_csv(name):
    with (A / name).open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))

def collect():
    offsets = {(r["host"], r["source"]): int(r["offset_seconds"]) for r in read_csv("clock_calibration.csv")}
    events = []
    streams = [
        ("auth_events.csv", "auth"),
        ("audit_events.csv", "audit"),
        ("secure_boot_attestation.csv", "attestation"),
        ("network_flows.csv", "network"),
        ("multi_host_events.csv", "multi_host"),
        ("firmware_inventory.csv", "firmware"),
    ]
    for filename, category in streams:
        for n, row in enumerate(read_csv(filename), 2):
            events.append({
                "source_file": filename, "source_row": n, "source_type": category,
                "host": row.get("host", ""), "source_clock": "unspecified",
                "observed_utc": row["utc"], "reference": row.get("event_id") or row.get("reference") or "",
            })
    for n, line in enumerate((A / "journal_export.jsonl").read_text(encoding="utf-8").splitlines(), 1):
        row = json.loads(line)
        events.append({
            "source_file": "journal_export.jsonl", "source_row": n, "source_type": "journal",
            "host": row["host"], "source_clock": "journal", "observed_utc": row["utc"],
            "reference": row.get("unit", ""),
        })
    for event in events:
        # Only the journal clock is unambiguously mapped by the supplied
        # calibration. Other streams must not silently inherit host offsets.
        key = (event["host"], event["source_clock"])
        offset = offsets.get(key)
        event["offset_seconds"] = offset
        event["normalized_utc"] = iso(parse_utc(event["observed_utc"]) - timedelta(seconds=offset)) if offset is not None else None
        event["normalization_status"] = "calibrated_assumption" if offset is not None else "unknown_clock_offset"
    return sorted(events, key=lambda e: (e["observed_utc"], e["source_file"], e["source_row"]))

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--output", choices=["json", "csv"], default="json")
    args = p.parse_args()
    events = collect()
    if args.output == "json":
        print(json.dumps({"notice": "Synthetic case; no causality or attacker attribution implied", "events": events}, indent=2))
    else:
        import sys
        writer = csv.DictWriter(sys.stdout, fieldnames=list(events[0]))
        writer.writeheader()
        writer.writerows(events)

if __name__ == "__main__":
    main()
