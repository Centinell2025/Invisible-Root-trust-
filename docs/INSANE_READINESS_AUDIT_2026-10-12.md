# Insane-readiness forensic QA — 12 October 2026

**Project:** Invisible Root of Trust (NRG-IR-2026-0917)  
**Author:** Centinell Suite Defense | **Exercise:** Fully synthetic, no company depicted as a real victim  
**Target:** HTB Sherlock, intended Insane difficulty | **Readiness:** Engineering verified, difficulty/acceptance not verified

## Verified CI results

[Successful forensic QA run prior to student artifact publishing](https://github.com/Centinell2025/Invisible-Root-trust-/actions/runs/38312009086).

| Measured gate | Observed |
|---|---:|
| Python unittest suite | **73 tests passed** |
| Scientific question–source mappings | **30/30** |
| Verified generated evidence files (excluding SHA manifest) | **32** |
| Linux auth/syslog lines | **83** |
| auditd-like lines | **41** |
| Extended journal records | **68** |
| Off-host synthetic edge-sensor packets | **8** |
| TCP packets associated with the short test conversation | **5** |
| Outbound TCP application-like bytes present in capture | **53** |
| Outbound byte count asserted by the *separate* flow record | **9,821** |
| Indexed simulated acquisition sources | **5** |

**Interpretation:** The captured TCP exchange validates a limited five-tuple and handshake but does **not** account for the flow-export total, authenticated TLS, exfiltration, or packet provenance. The original single-UDP `synthetic_telemetry.pcap` remains an additional negative-control specimen; it is not part of the correlated TCP conversation. Conflicting sources are designed to test careful reasoning, not to secretly declare an attack.

## Realism improvements delivered

- `measurement_derivation.csv` links the baseline and changed *software* measurements to real SHA-256 values computed from the bundled policy specimens. No TPM-backed evidence is claimed.
- `trust_anchor_inventory.csv` explicitly records **uncollected** TPM quote, EFI variable export and independent firmware image. A reported mismatch is not evidence that the root of trust was subverted.
- `file_integrity_timeline.csv`, `systemd_unit_inventory.csv` and `boot-health-agent.service` make file paths, service metadata and exact specimen hashes inspectable.
- `process_lineage.csv` and `socket_observations.csv` connect sampled process ancestry with a TCP socket, but local telemetry remains a local observation, not authenticated independent evidence.
- `auth_syslog.log`, `auditd_extract.log` and `journal_extended.jsonl` contain background activity and Linux-shaped events; there is a controlled suspicious subset to investigate.
- `edge_sensor_capture.pcap` contains Ethernet/IPv4/TCP/UDP frames with validated checksums, a TCP handshake, limited application-like data and background decoys.
- `acquisition_register.csv` describes collection source, scope and limitations. All `verified_origin` fields remain **no**, correctly reflecting a simulation.

## QA controls and negative tests

`tools/validate_realistic.py` verifies actual packet bytes and checksums, TCP flags, policy-to-measurement hash consistency, file-integrity links, unit metadata, process/service/network relationships, source boundaries, and background records.

`tests/test_realistic.py` additionally rejects a corrupted checksum, a truncated PCAP, falsified measurement derivation, fabricated TPM collection and altered process parenthood. Other regression suites check the 30 numbered questions, contradictory change approvals, incomplete evidence and student archive membership.

The student ZIP is built by `tools/build_submission.py` and rechecked by `tools/validate_release.py`. CI publishes that reviewed archive only after successful build and release checks.

## Critical scientific limitations still open

1. **No verified root-of-trust hardware acquisition.** Software SHA-256 policy measurements do not prove firmware execution, platform reset-chain integrity, or TPM quote authenticity.
2. **No realistic full-memory or offline-disk forensic acquisition.** The memory specimen is synthetic. The systemd unit can be inspected, but complete on-disk persistence and survival after a reboot have not been proved.
3. **Partial network coverage.** The packet capture corroborates limited TCP connectivity; it does not establish the full reported flow, any remote command, malicious intent, or data theft.
4. **Assessment answerability not proved.** The 30 source-mapping contracts establish possible inputs; they do not grade 30 complete answers. All final reasoning prompts still need human review.
5. **No private, verified instructor key or independent cold solve.** This public development repository exposes generator logic and should not be distributed to blind-solve participants. Send the student ZIP only.
6. **Insane challenge complexity has not been externally measured.** A passing CI run is not an HTB difficulty classification, approval, or payment agreement.

## Required independent acceptance experiment

Give the reviewed student ZIP to **two** analysts with no exposure to code or commit history. Collect their timed solution records, commands, citations, disagreements, unsupported inferences, and final decision memos. At minimum:

- Every objective answer must be unambiguous and verifiable from bytes and event records.
- Reconcile source-clock corrections and demonstrate why uncalibrated event order does not prove causality.
- Explain the exact limits of the software-policy, TCP-connection, persistence and identity findings.
- Produce a defensible organizational restoration decision with independently testable validation gates.
- Rewrite any question that competent independent analysts reasonably answer differently.
- Keep the canonical solution and grading answers in an instructor-only private location.

**Decision:** The current build meets its automated engineering and evidence-consistency gates. **Do not submit or advertise it as a finished $1,000/Insane Sherlock until the human answer, cold-solve, realism and HTB-specific gates are satisfied.**
