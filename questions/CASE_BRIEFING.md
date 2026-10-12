# Investigator assignment — NRG-IR-2026-0917

**Role:** Senior DFIR investigator  
**Environment:** Fictional Northstar Research Group  
**Affected asset:** `nrg-gw-07`  
**Incident window:** 17 September 2026, approximately 02:50–03:25 UTC

## Initial report
The operations team says a scheduled update explains the measured-boot discrepancy. The security desk notes a privileged service-account session, an unapproved change record, incomplete audit sequencing and network telemetry that does not agree with the packet specimen.

You have been asked to decide whether the gateway can be trusted, **without presuming that the alert is evidence of a firmware implant**.

## Investigation stages
**Stage 1 — Validate the evidence.** Confirm hashes and inventory. Note the provenance and limits of each synthetic stream.

**Stage 2 — Reconstruct access.** Identify the remote account, privilege activity, host references and missing audit sequences. Do not equate account use with human attribution.

**Stage 3 — Challenge the maintenance explanation.** Reconcile the local journal, change ticket, firmware inventory and observed binary policy specimens.

**Stage 4 — Reconcile clocks and network observations.** Document offset assumptions. Compare packet transport details against the separate flow record without claiming they are the same session.

**Stage 5 — Deliver a defensible verdict.** Separate confirmed observations from hypotheses, identify missing acquisition sources and propose proportionate containment and trusted recovery.

## Evidence citation convention
For each significant finding, provide `filename | row/event ID or byte offset | original UTC timestamp | normalized UTC timestamp (if justified) | confidence | limitation`. If a field is absent, say so instead of inventing it.

## Success criteria
A successful investigation reconstructs the supported event sequence and explicitly rejects unsupported claims. A high-confidence conclusion must be based on evidence, not the scenario title.
