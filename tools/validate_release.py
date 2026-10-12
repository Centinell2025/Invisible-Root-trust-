#!/usr/bin/env python3
"""Independently verify student archive membership, custody and contents."""
import hashlib
import re
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ART = ROOT / "artifacts"
ZIP = ROOT / "dist" / "Invisible-Root-of-Trust-student.zip"
DOCS = {
    "questions/CASE_BRIEFING.md",
    "questions/INVESTIGATION.md",
    "questions/ADVANCED_PIVOTS.md",
    "questions/SENIOR_RESEARCH_CHALLENGES.md",
    "docs/INCIDENT_NARRATIVE.md",
    "docs/SCIENTIFIC_INVESTIGATION_PROTOCOL.md",
    "docs/FORENSIC_LIMITATIONS.md",
}
HEX = re.compile(r"^[a-f0-9]{64}$")

def verify():
    subprocess.run([sys.executable, str(ROOT / "tools" / "validate_case.py")], check=True)
    if not ZIP.is_file():
        raise ValueError("Student archive missing")
    manifest = (ART / "custody_manifest.sha256").read_text(encoding="utf-8").splitlines()
    entries = {}
    for line in manifest:
        digest, sep, filename = line.partition("  ")
        if not sep or not HEX.fullmatch(digest):
            raise ValueError("Malformed custody entry")
        if not filename or "/" in filename or "\\" in filename or filename in entries:
            raise ValueError("Unsafe or duplicate custody filename")
        entries[filename] = digest
    if not entries:
        raise ValueError("No evidence")
    expected = DOCS | {"artifacts/" + n for n in entries} | {"artifacts/custody_manifest.sha256"}
    with zipfile.ZipFile(ZIP) as z:
        members = z.namelist()
        if len(members) != len(set(members)) or set(members) != expected:
            raise ValueError("Archive membership differs from allowlist")
        for name in members:
            if name.startswith("/") or ".." in Path(name).parts:
                raise ValueError("Unsafe archive path")
        for filename, digest in entries.items():
            content = z.read("artifacts/" + filename)
            if hashlib.sha256(content).hexdigest() != digest:
                raise ValueError("Archive hash mismatch: " + filename)
            if content != (ART / filename).read_bytes():
                raise ValueError("Archive evidence differs from generated evidence")
        if z.read("artifacts/custody_manifest.sha256") != (ART / "custody_manifest.sha256").read_bytes():
            raise ValueError("Archive custody manifest mismatch")
        for name in DOCS:
            if z.read(name) != (ROOT / name).read_bytes():
                raise ValueError("Archive documentation mismatch: " + name)
    print("PASS: release archive membership, hashes and provenance verified")

if __name__ == "__main__":
    try:
        verify()
    except (OSError, ValueError, zipfile.BadZipFile, subprocess.CalledProcessError) as e:
        print("FAIL:", e, file=sys.stderr)
        sys.exit(1)
