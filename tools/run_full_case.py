#!/usr/bin/env python3
"""Build a clean, deterministic research case and verify all evidence."""
import subprocess
import sys
import shutil
import hashlib
from pathlib import Path

root = Path(__file__).resolve().parents[1]
out = root / "artifacts"
if out.is_symlink():
    raise SystemExit("Refusing to clean symlinked artifacts directory")
if out.exists():
    shutil.rmtree(out)
for script in ("generate_case.py", "generate_advanced.py", "generate_research.py", "generate_realistic.py"):
    subprocess.run([sys.executable, str(root/"tools"/script)], check=True)
files = sorted(p for p in out.iterdir() if p.is_file() and p.name != "custody_manifest.sha256")
(out/"custody_manifest.sha256").write_text(
    "".join(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n" for p in files),
    encoding="utf-8"
)
subprocess.run([sys.executable, str(root/"tools/validate_case.py")], check=True)
subprocess.run([sys.executable, str(root/"tools/scientific_quality_gate.py")], check=True)
print("Full synthetic research case generated and validated.")
