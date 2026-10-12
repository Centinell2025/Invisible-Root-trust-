# Invisible Root of Trust
**Hack The Box Sherlock candidate | Advanced defensive DFIR | Target difficulty: Insane**

## Briefing
At 03:18 UTC, a fully fictional enterprise-lab environment received a *local software* policy discrepancy for Linux gateway `nrg-gw-07`. Investigate the relationship between identity activity, maintenance authorization, local audit records, binary policy specimens, clock skew and conflicting network observations.

Prepared by Centinell Suite Defense. All events, people, hosts and indicators are synthetic: no actual organization is named as a victim. The new realistic evidence includes syslog/auditd-style exports, FIM, processes, unit inventory and a partial valid TCP/UDP sensor PCAP. These specimens do not demonstrate a real UEFI bootkit, verified TPM quote, memory compromise or data exfiltration.

## Build and verify
Requires Python 3.10+ (standard library only):
```bash
python3 tools/run_full_case.py
python3 tools/validate_realistic.py
python3 tools/validate_snapshot.py
python3 -m unittest discover -s tests -v
python3 tools/build_submission.py
```
Evidence appears in `artifacts/`, and the student-only archive appears in `dist/`. Verify integrity using `cd artifacts && sha256sum -c custody_manifest.sha256`.

## Expanded forensic acquisitions
The generated package now includes a five-host SQLite correlation cache (`endpoint_telemetry.sqlite3`, over 1,200 synthetic host events and 370 synthetic flow records) and a scoped Linux TAR triage (`offline_gateway_triage.tar`) with unit files, a service enablement symlink, and selected logs. **The TAR is not a sector disk image, the SQLite database is derived rather than an independent witness, and no real company is a victim.** See [architecture and provenance](docs/ARCHITECTURE_AND_PROVENANCE.md) and [the Insane readiness audit](docs/INSANE_READINESS_AUDIT_2026-10-12.md).

## Student materials (reviewed ZIP allowlist)
- [Student incident briefing](docs/STUDENT_INCIDENT_BRIEF.md)
- [Evidence handling rules](docs/STUDENT_EVIDENCE_RULES.md)
- [16 precise platform task milestones](questions/HTB_PLAYER_TASKS.md)
- [30-question advanced investigation worksheet](questions/INVESTIGATION.md)

The required `README.txt`, these four student documents and the generated forensic artifacts go into the student ZIP. Other documents in this public development repository include instructor-style commentary, advanced pivots, scientific testing criteria or explicit evidence limitations that may reveal investigative findings. **Do not supply the entire public GitHub repository or its history as the student challenge.**

## Scientific test and acceptance
```bash
python3 tools/run_full_case.py
python3 tools/scientific_quality_gate.py
python3 tools/validate_realistic.py
python3 -m unittest discover -s tests -v
python3 tools/build_submission.py
python3 tools/validate_release.py
```
The `--mode insane` scientific gate deliberately blocks a release claim until private answer verification, independent cold solving and realistic evidence requirements are met. See [Scientific Test Protocol](docs/SCIENTIFIC_TEST_PROTOCOL.md).

## Internal development
This public repository contains development code. It is **not a confidential challenge distribution**: Git history may reveal removed files, and generator scripts inherently disclose clues. Distribute only the reviewed student ZIP to learners, and host instructor solutions in a separate private repository. Do not submit before independent playtesting, answer uniqueness review, and evidence quality verification.

Copyright (c) 2026 Centinell Suite Defense. Educational use only.

---

> **SELLO DE AUTORÍA | BEACON OF THE EAGLE LLC**  
> **Centinell Suite Defense — Digital Forensics & Incident Response Research**  
> © 2026 Beacon of the Eagle LLC. Original educational laboratory. All incident evidence and entities are simulated.  
> *Corporate attribution only; this mark does not imply external certification or that Beacon was an incident victim.*
