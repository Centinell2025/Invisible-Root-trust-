#!/usr/bin/env python3
"""Build a reproducible student evidence bundle from allowlisted files."""
from pathlib import Path
import subprocess
import sys
import zipfile

root = Path(__file__).resolve().parents[1]
evidence = root / "artifacts"
destination = root / "dist"
subprocess.run([sys.executable, str(root / "tools" / "validate_case.py")], check=True)
destination.mkdir(exist_ok=True)
documents = (
    "README.md",
    "questions/INVESTIGATION.md",
    "questions/ADVANCED_PIVOTS.md",
    "docs/CASE_DESIGN.md",
    "docs/ADVANCED_ANALYST_GUIDE.md",
)
entries = sorted(p for p in evidence.iterdir() if p.is_file())
if not entries or not (evidence / "custody_manifest.sha256").exists():
    raise SystemExit("Evidence manifest missing")
archive = destination / "Invisible-Root-of-Trust-student.zip"
with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as z:
    for name in documents:
        z.write(root / name, name)
    for p in entries:
        z.write(p, "artifacts/" + p.name)
with zipfile.ZipFile(archive) as z:
    names = z.namelist()
    if any(n.startswith(("tools/", "tests/", ".github/")) for n in names):
        raise SystemExit("Unexpected development file in archive")
print("Created", archive)
