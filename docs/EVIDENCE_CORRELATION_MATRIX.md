# Evidence correlation matrix — student worksheet

**Scenario:** Northstar Research Group, gateway `nrg-gw-07`. All observations are simulated.

| Hypothesis | Primary evidence | Independent simulated corroboration | Potential contradiction | What remains unknown |
|---|---|---|---|---|
| Privileged account activity preceded the change | `auth_events.csv` | `multi_host_events.csv` | Account identity does not establish operator identity | Credential ownership and session attribution |
| Boot-policy configuration was altered | `audit_events.csv` | `policy_baseline.bin`, `policy_observed.bin` | Local service claims routine update | Whether any firmware executable changed |
| Maintenance was authorized | `change_tickets.csv` | `firmware_inventory.csv` | Nearby benign maintenance records may distract | Completeness of change approval records |
| Boot attestation differs | `secure_boot_attestation.csv` | `journal_export.jsonl` | Both streams are synthetic and not independent trusted attestations | Hardware-backed attestation |
| Outbound traffic occurred | `network_flows.csv` | `synthetic_telemetry.pcap` | Flow is TCP; sample PCAP is UDP and cannot confirm that flow | Packet capture of the alleged TCP session |
| Exact ordering can be established | Source timestamps | `clock_calibration.csv` | Offsets and uncertainty affect ordering | Ground-truth clock synchronization |

## Analyst method
1. Record each observation with source, event ID, timestamp and its clock domain.
2. Distinguish observations from interpretations and identify conflicting sources.
3. Calculate normalized times where offsets are available, preserving uncertainty.
4. Reject conclusions that require missing evidence.
5. Provide an alternative explanation and state what collection could falsify it.

This matrix is a guide to evidence types, **not** an answer key. It intentionally does not identify final conclusions.
