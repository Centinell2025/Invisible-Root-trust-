# Root of Trust — The Decision Point
**Case:** NRG-IR-2026-0917 | **Fictional scientific DFIR exercise** | **Role:** Principal Incident Investigator

## The question that changes the investigation
**Was the system's root of trust actually compromised, or did an unauthorized configuration change and contradictory telemetry create the appearance of a deeper attack?**

At 03:18 UTC, the monitoring team receives a measured-boot policy discrepancy from `nrg-gw-07`. Operations attributes the alarm to scheduled maintenance. Security finds privileged account activity, an audit write to boot-policy configuration, missing audit sequence values, and a change request that exists but is not approved. A later flow export suggests outbound traffic, yet the available packet specimen does not match the flow's transport protocol.

Leadership asks for a binary verdict before authorizing service restoration. Your obligation is to challenge that framing. A trustworthy answer may be **confirmed**, **refuted**, or **not determinable from the supplied evidence**, depending on the precise proposition being tested.

## Three distinct propositions
**P1 — Configuration integrity:** Was a boot-related configuration specimen altered relative to the recorded baseline? This can be evaluated from audit records, policy specimens, digests, and deployment provenance.

**P2 — Boot-chain integrity:** Did the platform execute unauthorized code in a protected boot stage? A configuration discrepancy or local attestation-agent message does not establish this. Identify what independent measurement, signature validation, boot-event sequence, or firmware acquisition would be needed.

**P3 — Root-of-trust integrity:** Was the hardware-anchored mechanism used to protect, detect, or recover firmware itself subverted? Do not conflate P1, P2 and P3. No hardware-backed attestation or independently acquired firmware image is included in this synthetic dataset.

## Investigative acts

### Act I — The authorized change that was not
Reconstruct the maintenance claim using `change_tickets.csv`, `deployment_provenance.csv`, `firmware_inventory.csv` and the journal. Distinguish a signed package, an approved change, a staged package, and verified execution. State whether any one record alone authorizes a configuration write.

### Act II — Who held the session?
Join `session_lineage.csv`, `auth_events.csv`, `audit_events.csv` and `multi_host_events.csv` by their recorded identifiers. Explain the limitations of service-account attribution. Treat missing audit sequence numbers as missing observations, not evidence of deliberate deletion.

### Act III — The clock cannot testify alone
Use `clock_calibration.csv` and `tools/scientific_analysis.py` in the development environment if available. Define your offset convention and report which event orderings are conditional. The provided offsets do not include error bounds; do not claim millisecond-level causality or apply host-wide offsets to unspecified source clocks.

### Act IV — The packet that looks familiar
Compare `network_flows.csv` with `synthetic_telemetry.pcap`. Determine whether packet-to-flow attribution is technically defensible. A common destination address is not a shared five-tuple, and bytes-out metadata is not proof of exfiltration.

### Act V — The trust boundary
Assess what `secure_boot_attestation.csv`, the policy binary specimens and `claim_provenance.csv` establish. Separate local telemetry from hardware-rooted evidence. Explain how a compromised host could influence its own logs without claiming such tampering actually occurred.

### Act VI — The decision under uncertainty
Prepare a concise incident-command recommendation: what is safe to preserve, what should be isolated, what trusted evidence should be collected next, and what validation would be required before restoration.

## Required final submission
1. **Claim-evidence matrix:** P1, P2 and P3, each with supporting observations, contradictory records, dependencies, missing sources and an explicit status.
2. **Timeline:** original source time, any justified normalization, uncertainty statement and event reference.
3. **Hypothesis comparison:** unauthorized local configuration change; authorized-but-misrecorded maintenance; deeper boot-chain persistence; telemetry/clock artifact. Do not assign numerical probabilities without a defensible statistical model.
4. **Discriminating tests:** for each unresolved hypothesis, specify a realistic acquisition or verification that could change the finding.
5. **Decision memo:** no more than 400 words; state what is known, what is unknown and whether the available evidence permits a definitive root-of-trust compromise finding.

## Evidence standard
Every material claim must identify a file and row, event ID, or byte offset. No answer is awarded for asserting a bootkit, firmware infection, exfiltration, or operator identity without proof. Explain uncertainty rather than masking it.

## Scope and safety
All names, hosts, IPs, and evidence are synthetic. The memory excerpt is not a forensic RAM image; the sample PCAP is a minimal UDP packet; policy binaries are mock specimens. This is an advanced reasoning exercise, not a demonstration of actual firmware compromise.

## Reference framework
NIST SP 800-193, *Platform Firmware Resiliency Guidelines*, distinguishes firmware protection, detection and recovery. Use those distinctions to avoid treating a local integrity alarm as proof that a hardware root of trust has failed.
https://doi.org/10.6028/NIST.SP.800-193
