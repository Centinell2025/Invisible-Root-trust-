#!/usr/bin/env python3
"""Generate all evidence in a known order and validate."""
import subprocess,sys
from pathlib import Path
root=Path(__file__).resolve().parents[1]
for script in ["generate_case.py","generate_advanced.py","validate_case.py"]:
 subprocess.run([sys.executable,str(root/"tools"/script)],check=True)
print("Full case generated and validated.")
