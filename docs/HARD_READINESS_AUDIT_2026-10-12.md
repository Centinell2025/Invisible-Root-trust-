# Hard-readiness forensic QA — 12 October 2026

**Project:** Invisible Root of Trust (NRG-IR-2026-0917)  
**Author:** Centinell Suite Defense | **Exercise:** Fully synthetic, no company depicted as a real victim  
**Target:** HTB Sherlock, proposed Hard difficulty | **Readiness:** Engineering verified, final category and acceptance subject to HTB evaluation

## Verified CI results

[Latest successful 97-test Hard build and student archive](https://github.com/Centinell2025/Invisible-Root-trust-/actions/runs/38325750148).

| Measured gate | Observed |
|---|---:|
| Python unittest suite | **97 tests passed in current Hard CI** |
| Scientific question–source mappings | **30/30** |
| Verified generated evidence files (excluding SHA manifest) | **39** |
| Linux auth/syslog lines | **83** |
| auditd-like lines | **41** |
| Extended journal records | **68** |
| Off-host synthetic edge-sensor packets | **8** |
| TCP packets associated with the short test conversation | **5** |
| Outbound TCP application-like bytes present in capture | **53** |
| Outbound byte count asserted by the *separate* flow record | **9,821** |
| Indexed simulated acquisition sources | **9** |
| Derived SQLite event records across five hosts | **1,257** |
| Derived SQLite flow entries | **377** |
| Scoped TAR file and symlink entries | **9** |

**Interpretation:** The captured TCP exchange validates a limited five-tuple and handshake but does **not** account for the flow-export total, authenticated TLS, exfiltration, or packet provenance. The original single-UDP `synthetic_telemetry.pcap` remains an additional negative-control specimen; it is not part of the correlated TCP conversation. Conflicting sources are designed to test careful reasoning, not to secretly declare an attack.

## Realism improvements delivered

- `measurement_derivation.csv` links the baseline and changed *software* measurements to real SHA-256 values computed from the bundled policy specimens. No TPM-backed evidence is claimed.
- `trust_anchor_inventory.csv` explicitly records **uncollected** TPM quote, EFI variable export and independent firmware image. A reported mismatch is not evidence that the root of trust was subverted.
- `file_integrity_timeline.csv`, `systemd_unit_inventory.csv` and `boot-health-agent.service` make file paths, service metadata and exact specimen hashes inspectable.
- `process_lineage.csv` and `socket_observations.csv` connect sampled process ancestry with a TCP socket, but local telemetry remains a local observation, not authenticated independent evidence.
- `auth_syslog.log`, `auditd_extract.log` and `journal_extended.jsonl` contain background activity and Linux-shaped events; there is a controlled suspicious subset to investigate.
- `edge_sensor_capture.pcap` contains Ethernet/IPv4/TCP/UDP frames with validated checksums, a TCP handshake, limited application-like data and background decoys.
- `acquisition_register.csv` describes collection source, scope and limitations. All `verified_origin` fields remain **no**, correctly reflecting a simulation.
- `endpoint_telemetry.sqlite3` adds a queryable five-host analytical cache with 1,257 rows and 377 flow records. It is **derived**, not an independent second witness.
- `offline_gateway_triage.tar` supplies an offline **file-level** acquisition, including FIM-correlated policy bytes, the unit file, its enablement symlink and selected Linux logs. It is **not** a sector-level disk image.
- `tools/validate_snapshot.py` validates actual SQL joins, boot identity limitations, tar entry hashes and the scope disclaimer. `tests/test_snapshot.py` adds database and TAR tampering negative controls.

## Hard investigation extension — four new evidence sources

- `idp_session_audit.jsonl`: 59 events, including identity-token issuance, refresh/expiry activity and service-account decoys.
- `change_approval_audit.jsonl`: 73 records; distinguishes security rejection from package quarantine and earlier pending approvals.
- `firewall_edge_decisions.jsonl`: 91 synthetic firewall decisions, including a protocol-matched TCP allow, a denied decoy and a misleading UDP lookalike.
- `systemd_lifecycle.jsonl`: 67 service observations; distinguishes enablement symlink from locally asserted starts and *unverified* reboot persistence.

Together these include **276 background events**, explicitly registered as simulated, incomplete and unauthenticated; they add forensic discrimination but are not independent real production witnesses. The updated `tools/validate_hard_pivots.py` and 12 additional regression tests enforce cross-source consistency and reject fabricated attribution, approval, protocol and reboot claims. The student release contains 25 exact-answer checkpoints, with eight new multi-artifact Hard stages and 30 research prompts for instructor grading.

## QA controls and negative tests

`tools/validate_realistic.py` verifies actual packet bytes and checksums, TCP flags, policy-to-measurement hash consistency, file-integrity links, unit metadata, process/service/network relationships, source boundaries, and background records.

`tests/test_realistic.py` additionally rejects a corrupted checksum, a truncated PCAP, falsified measurement derivation, fabricated TPM collection and altered process parenthood. Other regression suites check the 30 numbered questions, contradictory change approvals, incomplete evidence and student archive membership.

The student ZIP is built by `tools/build_submission.py` and rechecked by `tools/validate_release.py`. CI publishes that reviewed archive only after successful build and release checks.

## Critical scientific limitations still open

1. **No verified root-of-trust hardware acquisition.** Software SHA-256 policy measurements do not prove firmware execution, platform reset-chain integrity, or TPM quote authenticity.
2. **No verified full-memory or sector-level offline-disk acquisition.** There is a realistic *scoped TAR* and SQLite cache, not a complete disk/RAM image. The unit file and enablement symlink can be inspected, but all-disk persistence and execution after a verified reboot are not proved.
3. **Partial network coverage.** The packet capture corroborates limited TCP connectivity; it does not establish the full reported flow, any remote command, malicious intent, or data theft.
4. **Assessment answerability not proved.** The 30 source-mapping contracts establish possible inputs; they do not grade 30 complete answers. All final reasoning prompts still need human review.
5. **Current confidential 25-answer solutions and screenshots assembled; independent cold solve pending.** The reviewer-only ZIP contains an answer YAML, intended write-up and terminal screenshots. That is not a substitute for an independent non-author playtest. Public development code exposes generator logic: send testers only the student ZIP.
6. **Hard difficulty has not been externally measured.** HTB describes a Hard Sherlock as an advanced, multi-stage investigation taking up to about two days depending on analyst experience. A passing CI run is not independent evidence of that difficulty or HTB approval.

## Practical Hard classification rationale

The scenario requires Linux DFIR, multihost identity correlation, exact UTC/source-clock reconciliation, forensic data-integrity checks, SQL filtering, systemd persistence analysis and partial network packet interpretation. The expanded **25 exact-value questions** add eight multi-source Hard investigation gates; the original 17 offer a graded baseline but include straightforward artifact lookups, so Hard is a **requested category**, not a measured result. Preserve the 30-question extended investigation for deeper professional learning; do not imply those open-ended prompts are automatically graded on HTB.

## Required independent acceptance experiment

Give the reviewed student ZIP to **two** analysts with no exposure to code or commit history. Collect their timed solution records, commands, citations, disagreements, unsupported inferences, and final decision memos. At minimum:

- Every objective answer must be unambiguous and verifiable from bytes and event records.
- Reconcile source-clock corrections and demonstrate why uncalibrated event order does not prove causality.
- Explain the exact limits of the software-policy, TCP-connection, persistence and identity findings.
- Produce a defensible organizational restoration decision with independently testable validation gates.
- Rewrite any question that competent independent analysts reasonably answer differently.
- Keep the canonical solution and grading answers in an instructor-only private location.

**Decision:** The current build meets its automated engineering and evidence-consistency gates. **Target Hard, not Insane.** External cold solves, final task calibration and HTB review remain necessary before claiming Hard acceptance. Official Hard compensation is $650 base plus a possible $150 quality bonus (up to $800); neither acceptance nor payment is guaranteed.
