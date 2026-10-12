# Architecture and provenance of a synthetic Linux DFIR case

**Copyright and authorship:** Centinell Suite Defense. All hostnames, accounts, activities, addresses and case events are fabricated; this is not a reported breach of any company.

## Five-system laboratory topology

```mermaid
flowchart LR
    U["Simulated admin origin
192.0.2.44"] -->|Authentication evidence| B["Bastion
nrg-bastion-02"]
    B -.->|Session identifiers (not proof of same operator)| G["Research gateway
nrg-gw-07 / 192.0.2.17"]
    I["Identity provider
nrg-idp-01"] -.->|Token logs| B
    C["Build/change service
nrg-build-03"] -.->|Package/approval records| G
    G -->|Recorded outbound network tuple| S["Network sensor
nrg-sensor-04"]
    S -->|Synthetic partial packet capture| D["Documentation destination
198.51.100.73"]
    G --> L["Host-local evidence:
auth/audit/journal
processes/systemd/FIM"]
    L --> Q["SQLite analytical cache
derived, not independent"]
    S --> Q
    C --> Q
```

Solid edges indicate a modeled collection or activity relationship. Dashed edges are *hypotheses or joined labels* requiring investigation; they must not be read as confirmed malicious actions.

## Trust boundary and collection scope

| Collection | Source type | Supported analysis | Does **not** prove |
|---|---|---|---|
| `secure_boot_attestation.csv` + `measurement_derivation.csv` | Local software SHA-256 check | A repeatable difference between mock policy specimens | TPM quote validation, UEFI code execution, firmware implant |
| `policy_*.bin` | Reproducible specimen bytes | Actual byte comparison and hash consistency | Original production acquisition |
| `auth_syslog.log` + `auditd_extract.log` | Simulated Linux log export | Session, privilege, syscall/sequence pivots | Full original kernel logs, a named human attacker |
| `process_lineage.csv` + `socket_observations.csv` | Sampled host-local telemetry | Local process ancestry and network tuple | Process integrity or exfiltration intent |
| `endpoint_telemetry.sqlite3` | **Derived** analytical cache | Multihost SQL correlation, background and distracting events | Independent corroboration of the input evidence |
| `offline_gateway_triage.tar` | **Scoped** simulated Linux file export | Read-only tar inspection, unit symlink, specimen and log hashes | Complete sector image, absence of uncollected files, persistence over reboot |
| `edge_sensor_capture.pcap` | Partial simulated sensor capture | TCP flags/handshake, packet/flow matching, checksum verification | Complete session, authentic TLS, full flow export, data theft |
| `synthetic_telemetry.pcap` | Legacy single-packet UDP specimen | Negative control for transport correlation | Corroboration of the reported TCP flow |
| `trust_anchor_inventory.csv` | Missing collection inventory | Identification of TPM/EFI/firmware acquisition requirements | Confirmation or refutation of hardware-root compromise |

## Senior investigation logic

Analysts are expected to test **which evidence is independent**, reconcile clock offsets only within each stated source, and prove which propositions can be verified:

- **P1:** A local policy specimen changed relative to its reference. This is testable with multiple hash-linked file representations.
- **P2:** Unauthorized boot-chain code executed. Not established by the distributed collection.
- **P3:** The platform hardware root of trust was subverted. Not established without independently verified hardware attestation/firmware collection.
- **P4:** A process communicated on the reported TCP tuple. Short packet and socket samples corroborate limited connectivity, but not a complete flow or malicious purpose.
- **P5:** A service persisted across reboot. The TAR and local metadata permit examination of a possible enabled unit, not proof of execution after an independently observed reboot.

**The lab deliberately distinguishes what was recorded, what can be inferred, and what an IT incident commander may responsibly authorize.**

## Reproducibility

Run `python3 tools/run_full_case.py`, `python3 tools/validate_realistic.py`, `python3 tools/validate_snapshot.py`, `python3 -m unittest discover -s tests -v`, `python3 tools/build_submission.py`, then `python3 tools/validate_release.py`.

Do not distribute this development document as an answer key, or give blind-solvers access to the Git history; the reviewed student ZIP is the only intended challenge package.
