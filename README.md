# Invisible Root of Trust
**Hack The Box Sherlock candidate | Advanced defensive DFIR | Target difficulty: Insane**

## Briefing
At 03:18 UTC, fictional Northstar Research Group received an attestation discrepancy for Linux gateway `nrg-gw-07`. Investigate the relationship between identity activity, maintenance authorization, local audit records, binary policy specimens, clock skew and conflicting network observations.

All entities, evidence and indicators are synthetic. The specimens do not demonstrate a real UEFI bootkit or memory compromise.

## Build and verify
Requires Python 3.10+ (standard library only):
```bash
python3 tools/run_full_case.py
python3 -m unittest discover -s tests -v
python3 tools/build_submission.py
```
Evidence appears in `artifacts/`, and the student-only archive appears in `dist/`. Verify integrity using `cd artifacts && sha256sum -c custody_manifest.sha256`.

## Student materials
- [Investigation worksheet](questions/INVESTIGATION.md)
- [Advanced evidence pivots](questions/ADVANCED_PIVOTS.md)
- [Advanced analyst guidance](docs/ADVANCED_ANALYST_GUIDE.md)
- [Case design and limitations](docs/CASE_DESIGN.md)

## Internal development
This public repository contains development code. It is **not a confidential challenge distribution**: Git history may reveal removed files, and generator scripts inherently disclose clues. Distribute only the reviewed student ZIP to learners, and host instructor solutions in a separate private repository. Do not submit before independent playtesting, answer uniqueness review, and evidence quality verification.

Copyright (c) 2026 Centinell Suite Defense. Educational use only.
