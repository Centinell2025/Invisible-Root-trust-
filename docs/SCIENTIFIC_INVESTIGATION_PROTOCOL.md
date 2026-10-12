# Scientific investigation protocol — senior research track
**Case:** NRG-IR-2026-0917 | **Mode:** Synthetic DFIR research | **Status:** Methodology, not proof of compromise

## Research question
Can the observations distinguish an unauthorized boot-policy change from an actual compromise of a hardware-rooted boot trust chain, while controlling for telemetry dependence, clock uncertainty and alternative causes?

## Competing hypotheses
- **H1:** An unauthorized privileged session altered a local boot-policy configuration; the attestation discrepancy followed, but no firmware execution is established.
- **H2:** An authorized or benign process caused the discrepancy, and the ticket/journal disagreement reflects incomplete change management.
- **H3:** A deeper persistence mechanism affected the trust chain; this is a hypothesis requiring additional acquisition and trusted measurements, not a fact established by the provided artifacts.
- **H4:** Some apparent correlations are artifacts of logging, clock offset, duplicated telemetry or incomplete collection.

Do not treat these as exhaustive or equally likely. No priors or likelihoods have been supplied; numerical posterior probabilities would be invented.

## Measurement model
Let observed timestamp be `t_obs = t_true + delta_source + epsilon`, where `delta_source` is clock bias and `epsilon` captures measurement and timestamp uncertainty. The calibration file provides selected *offset estimates*, not validated uncertainty intervals. Never assign zero error merely because an offset is present. An ordering is robust only if it survives plausible clock-error bounds; absent those bounds, report conditional ordering.

## Evidence dependence
The journal and attestation streams are simulated and may share a common generating process. Counting them as two independent confirmations would overstate confidence. Build a provenance/dependence graph before drawing conclusions. A shared destination IP does not make a UDP packet evidence of a separate TCP session.

## Falsification plan
| Claim | Observation that would strengthen it | Observation that could weaken it |
|---|---|---|
| Unauthorized policy change | Independent file acquisition, authenticated session recording, approved baseline comparison | Verified authorized deployment and matching change approvals |
| Firmware persistence | Hardware-backed measured boot, firmware image acquisition and reproducible diff, trusted signatures | Clean independently attested firmware and an explanation confined to configuration |
| Data exfiltration | Complete session capture, endpoint process/socket mapping, destination evidence | Flow export error or unrelated traffic; no matching session |
| Human attribution | Identity provider records plus strong authentication/session binding | Shared or compromised service credentials |

## Advanced analyst requirements
1. Write a falsifiable hypothesis and identify the minimum evidence that would discriminate it from alternatives.
2. Construct an event provenance graph with primary sources, derived sources and common-cause dependencies.
3. Normalize timestamps only when the relevant source clock is identified; mark others unknown.
4. Test the robustness of event ordering under clock error and missing audit records.
5. Distinguish measurement discrepancy, configuration tampering, boot-chain execution and firmware persistence as separate propositions.
6. Assess how an incomplete capture affects sensitivity, specificity and false-positive risk; do not invent rates.
7. Maintain a claim-evidence ledger with exact references, contradictions, uncertainty and collection gaps.
8. Deliver a conditional recovery recommendation based on trust in the acquisition source.

## Scoring design for a future instructor key
Each graded question must have a unique expected value or an explicitly defined finite set, a deterministic extraction procedure, at least one source citation, and documented tolerance for time offsets or alternate representations. Open-ended interpretation belongs in instructor-reviewed questions, not strict string grading.

## Limitations
The distributed memory excerpt is not a RAM acquisition. The policy binaries are mock specimens. The minimal PCAP is UDP and cannot validate the separate TCP flow. The supplied offset estimates lack error bars. These limitations are central to the exercise and must remain visible to learners.
