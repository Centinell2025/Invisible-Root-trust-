#!/usr/bin/env python3
"""Build a clean, deterministic case and verify the resulting evidence."""
import subprocess,sys,shutil
from pathlib import Path
root=Path(__file__).resolve().parents[1]
out=root/"artifacts"
if out.is_symlink():raise SystemExit("Refusing to clean symlinked artifacts directory")
if out.exists():shutil.rmtree(out)
for script in ["generate_case.py","generate_advanced.py","validate_case.py"]:
 subprocess.run([sys.executable,str(root/"tools"/script)],check=True)
print("Full synthetic case generated and validated.")
