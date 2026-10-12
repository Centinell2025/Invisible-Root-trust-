#!/usr/bin/env python3
"""Read-only student-facing evidence inventory. Never prints investigation answers."""
import csv
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ART = ROOT / "artifacts"

def inspect(path):
    data = path.read_bytes()
    entry = {
        "file": path.name,
        "size_bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }
    if path.suffix == ".csv":
        with path.open(newline="", encoding="utf-8") as f:
            reader = csv.reader(f)
            header = next(reader, [])
            entry["columns"] = header
            entry["records"] = sum(1 for _ in reader)
    elif path.suffix == ".jsonl":
        entry["records"] = len([x for x in data.splitlines() if x.strip()])
    return entry

def main():
    if not ART.is_dir():
        raise SystemExit("Generate evidence first: python3 tools/run_full_case.py")
    inventory = [
        inspect(p)
        for p in sorted(ART.iterdir())
        if p.is_file() and p.name != "custody_manifest.sha256"
    ]
    print(json.dumps({"synthetic": True, "evidence": inventory}, indent=2))

if __name__ == "__main__":
    main()
