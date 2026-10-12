#!/usr/bin/env python3
"""Create a student-only ZIP from deterministic generated artifacts."""
from pathlib import Path
import zipfile
ROOT=Path(__file__).resolve().parent.parent
ART=ROOT/"artifacts"
OUT=ROOT/"dist"
OUT.mkdir(exist_ok=True)
required=["README.md","questions/INVESTIGATION.md","docs/CASE_DESIGN.md"]
evidence=sorted(p for p in ART.iterdir() if p.is_file())
if not evidence or not (ART/"custody_manifest.sha256").exists():
    raise SystemExit("Generate and validate artifacts first")
target=OUT/"Invisible-Root-of-Trust-student.zip"
with zipfile.ZipFile(target,"w",compression=zipfile.ZIP_DEFLATED) as z:
    for name in required:z.write(ROOT/name,name)
    for path in evidence:z.write(path,"artifacts/"+path.name)
print(f"Created {target} ({target.stat().st_size} bytes)")
