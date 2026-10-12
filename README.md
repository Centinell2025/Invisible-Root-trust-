# Invisible Root of Trust

**HTB Sherlock candidate | Advanced DFIR | Target difficulty: Insane**

## Incident briefing
At 03:18 UTC, the fictional Northstar Research Group received a boot-attestation mismatch alert for Linux gateway `nrg-gw-07`. The event conflicts with the maintenance ledger and local journal. Investigate authentication, file audit, attestation, network and change-management evidence to reconstruct the event.

All company names, identities and events are fictional. No executable malware or real bootkit is distributed.

## Getting started
Requires Python 3.10+ (standard library only):

```bash
python3 tools/generate_case.py
cd artifacts
sha256sum -c custody_manifest.sha256
```

Then open [the investigation worksheet](questions/INVESTIGATION.md) with 30 forensic investigation questions. Use the [case design](docs/CASE_DESIGN.md) to understand artifact limitations, not for answer values.

## Evidence generated
- `secure_boot_attestation.csv` — simulated measured boot discrepancy
- `auth_events.csv` — account logins and privilege events
- `audit_events.csv` — audited configuration changes with sequence gaps
- `journal_export.jsonl` — service and attestation events
- `network_flows.csv` — synthetic egress metadata
- `change_tickets.csv` — approved or rejected maintenance windows
- `firmware_inventory.csv` — baseline versions
- `custody_manifest.sha256` — generated artifact hashes

## Investigation goals
Identify the trust discrepancy, connect the privileged session with changes, validate conflicting sources, assess the limits of persistence claims, reconstruct the timeline, and specify safe containment and recovery.

## Publication and readiness
This repository contains a **starter case**, not yet a completed or independently playtested HTB Insane Sherlock. Actual platform submission requires richer forensic evidence, exact machine-gradable answers, instructor walkthrough, QA tests and review. The instructor answer key must be maintained privately, outside this public repository.

Copyright (c) 2026 Centinell Suite Defense. Training/evaluation use only.
