# Analyst Investigation — Invisible Root of Trust

**Case:** NRG-IR-2026-0917 | **Audience:** Senior DFIR / incident response | **Classification:** Fictional training evidence

## Mission

**Was the system's root of trust compromised, or did an unauthorized configuration change and contradictory records create the appearance of a deeper attack?**

Your task is not to find an answer the story suggests. Your task is to build a defensible answer from the supplied evidence, determine which claims remain unresolved, and recommend what an IT organization must do before returning the affected gateway to service.

The 30 questions are ordered as a scientific investigation: **WHAT → WHERE → WHEN → WHO → HOW → WHY / FOR WHAT PURPOSE → WHAT SHOULD THE ORGANIZATION DO?**

### Analyst evidence standard

For every answer, provide: **finding → exact file and record/ID/byte offset → original UTC timestamp, where available → independent corroboration, if available → uncertainty or counterexample → practical significance**.

Two copies or restatements of one source do not constitute independent corroboration. A hash-matching evidence package establishes consistency of the provided files, *not* authenticity of the underlying event. Never fill collection gaps with invented observations. Use **NOT ESTABLISHED** when the evidence cannot support a conclusion and specify what acquisition would resolve it. Clock calibration values are estimates without supplied error bounds; do not assert a precise causal ordering from timestamps alone.

---

## Phase 1 — WHAT happened? Define the observable event. (01–05)

**Investigation objective:** Separate a recorded measurement discrepancy from demonstrated unauthorized execution or compromise of a hardware root of trust.

**01 — WHAT is the initial anomaly?** Identify the affected hostname, measurement component, first recorded mismatch, expected digest, observed digest and the source reporting the mismatch. What exactly has been *observed*, rather than inferred?  
**Deliverable:** An evidence tuple with source classification.

**02 — WHAT differs in the policy specimens?** Independently hash `policy_baseline.bin` and `policy_observed.bin`, compare them byte by byte, and reconcile the values with `policy_digest_crosscheck.csv` and `custody_manifest.sha256`. Why does file integrity not prove trustworthy acquisition?  
**Deliverable:** Verified hashes, changed byte range, provenance limitation.

**03 — WHAT changed, and WHAT has not been shown to change?** Distinguish the audited configuration path, the mock binary policy specimens, the reported measured component, executed boot code and firmware itself. Which equivalences are evidence-backed and which are assumptions?  
**Deliverable:** Five-row claim/evidence table.

**04 — WHAT was the last documented baseline?** Identify the earlier matching measurement and the inventory's reference status. Why is "last recorded match" not necessarily "last uncompromised moment"?  
**Deliverable:** Referenced baseline and its evidentiary limitation.

**05 — WHAT must be proved for three distinct findings?** Define separate testable claims for (P1) policy/configuration alteration, (P2) unauthorized boot-chain execution and (P3) compromise of hardware-anchored root of trust. What decisive evidence is missing for each?  
**Deliverable:** Three-proposition proof matrix.

## Phase 2 — WHERE did activity cross system and trust boundaries? (06–09)

**Investigation objective:** Establish where observations originated and where the suspected effect occurred, rather than treating labels as proof.

**06 — WHERE was access recorded?** Locate the gateway, bastion, identity-provider and build-system observations. Which are host-local statements and which come from another recording system?  
**Deliverable:** Host/source/provenance map.

**07 — WHERE did the audited write occur?** Provide the exact path, host, operation and correlated identifier. Is it demonstrated that this path is equivalent to protected firmware storage or a root-of-trust primitive?  
**Deliverable:** Write record plus trust-boundary classification.

**08 — WHERE was software deployment authorized or rejected?** Compare the change ticket, target host, package signatures, approval states and firmware inventory. Explain why signed, approved, deployed and executed are not interchangeable.  
**Deliverable:** Authorization-versus-execution matrix.

**09 — WHERE is the reported network activity, and WHERE is its independent packet evidence?** Identify flow destination and transport; inspect *all* supplied capture specimens, their provenance, timestamps, five-tuples and available connection identifiers. Which packets, if any, can be attributed to the recorded flow and what coverage gaps remain?  
**Deliverable:** Flow-to-packet correlation verdict with missing fields.

## Phase 3 — WHEN did events occur? Reconcile time and missing observations. (10–14)

**Investigation objective:** Construct an auditable timeline while preserving clock and collection uncertainty.

**10 — WHEN was the earliest recorded candidate access?** Correlate `session_lineage.csv`, `auth_events.csv`, `multi_host_events.csv` and the SQLite host-event cache. Distinguish earliest observed time from proven initiation time; explain why a derived SQLite cache is not a new independent witness.  
**Deliverable:** Chronology with timestamps, hosts and event IDs.

**11 — WHEN was privileged activity recorded?** Identify login, elevation, audit open, write and close, with exact identifiers. Which intervals are merely differences between source timestamps?  
**Deliverable:** Linked sequence and clock caveats.

**12 — WHEN do the missing audit records belong?** Identify the absent sequence numbers and bounding events. What cannot be inferred about activity during that interval?  
**Deliverable:** Gap analysis with at least two possible explanations.

**13 — WHEN do events occur after defensible clock correction?** Read `clock_calibration.csv`; apply corrections only to explicitly matched source clocks. Which orderings remain uncertain without error intervals?  
**Deliverable:** Raw-versus-adjusted timeline; unknown offsets marked unknown.

**14 — WHEN could persistence first have been introduced, and WHEN was it proven?** Compare the policy change, service activity, installation metadata in the scoped offline tar, SQLite boot-inventory records and collection gaps. Does a unit-file symlink by itself demonstrate execution or survival across a later boot?  
**Deliverable:** Earliest candidate opportunity and explicit persistence status.

## Phase 4 — WHO acted, and HOW was the apparent change performed? (15–20)

**Investigation objective:** Reconstruct a testable mechanism without confusing a credential, a person, a process and an attacker.

**15 — WHO is the recorded principal?** Identify the service account, source IP and session references. What is known about the principal, and what remains unknown about a human operator?  
**Deliverable:** Identity/attribution statement.

**16 — HOW do the identity, bastion and gateway events connect?** Produce a reproducible cross-host timeline joining `idp_session_audit.jsonl`, `session_lineage.csv`, gateway authentication, `process_lineage.csv` and the SQLite cache. Demonstrate why token issuance, token refresh, a command channel and a privileged file write are different events. Which references survive all joins, which fail, and why does a service token not identify a human actor? Cite exact rows and acquisition scopes.  
**Deliverable:** Correlation graph with each edge marked observed, inferred or unsupported.

**17 — HOW could an unauthorized policy change have occurred?** Reconstruct access, parent/child process ancestry, privilege escalation and audited write from `auth_syslog.log`, `auditd_extract.log`, the process inventory and the SQLite event cache. Which specific relationships are independently observed and which remain local telemetry claims?  
**Deliverable:** Mechanism chain and missing execution detail.

**18 — HOW credible is the local "routine signed update" statement?** Compare the gateway-local journal claim with `change_approval_audit.jsonl`, signed and unsigned packages, change tickets and `deployment_provenance.csv`. Identify the last security rejection before quarantine, distinguish authorization from installation and execution, and state what evidence would independently resolve the contradictory claims. Do not treat matching ticket labels as cryptographic provenance.  
**Deliverable:** Contradiction analysis and deployment confidence.

**19 — HOW can misleading telemetry imitate a deeper attack?** Independently parse both PCAPs, the SQL `netflow_sessions` table, `socket_observations.csv` and `firewall_edge_decisions.jsonl`. Join the entire five-tuple and process lineage, discriminate the UDP lookalike from the TCP session, count payload bytes and compute the mismatch with the flow summary. Explain why a matching firewall ALLOW and an exporter byte counter are not independent proof of content, complete coverage or exfiltration.  
**Deliverable:** Protocol-level falsification test and verdict.

**20 — HOW could persistence arise, and what is *actually* evidenced?** Inspect `offline_gateway_triage.tar` safely; reconcile exact service bytes and enablement symlink with `systemd_lifecycle.jsonl`, FIM, process lineage and two SQLite boot snapshots. Construct a state diagram with **installed → enabled → started-asserted → executed → survived verified reboot** and label each arrow observed, locally asserted or unproved. Why do equal synthetic boot IDs and the TAR's normalized metadata not establish reboot survival?  
**Deliverable:** Persistence claim with required verification steps.

## Phase 5 — WHY did the discrepancy arise, and FOR WHAT PURPOSE? (21–25)

**Investigation objective:** Evaluate competing explanations without inventing motive, certainty or a malicious actor.

**21 — WHY might a legitimate maintenance explanation fit part of the evidence?** Investigate at least three competing stories—authorized deployment, mistaken privileged maintenance, unauthorized configuration modification. Use the IdP token/event chain, independent change-control state and approved decoy packages; for each story identify two supportive facts, two contradictions and one missing discriminator. Do not label an account holder or attack group.  
**Deliverable:** Hypothesis H1 with supporting and contradicting sources.

**22 — WHY is an unauthorized configuration modification a plausible explanation rather than an established verdict?** Cite the strongest evidence, identify any competing authorized-change explanation, and name the precise point beyond which the claim becomes speculative. What independent evidence would reverse your conclusion?  
**Deliverable:** Hypothesis H2 and falsification condition.

**23 — WHY is actual root-of-trust compromise a separate hypothesis?** Identify what hardware-backed attestation, trusted boot measurements, independent firmware imaging and recovery validation would be required. Which of those are absent?  
**Deliverable:** Hypothesis H3 and evidence acquisition plan.

**24 — FOR WHAT PURPOSE could the observed service and egress have been used?** Develop at least three testable hypotheses: service health telemetry, unauthorized remote control and data transfer. Correlate `systemd_lifecycle.jsonl`, TCP socket/process ancestry, the edge firewall decision, limited packets and the source-defined capture window. Specify what additional full-session or endpoint evidence would *falsify* each hypothesis and explain why the packet sample cannot authenticate the actual payload purpose.  
**Deliverable:** Intent-versus-observation table, without invented attacker motives.

**25 — WHY might the entire chain appear more conclusive than it is?** Build a provenance dependency graph for the SQLite cache, TAR copy, local software digest, IdP export, firewall decision, change ledger and journal claims. Rank each witness by acquisition scope and `verified_origin`; distinguish **logically distinct modeled sources** from truly independently authenticated acquisitions. Identify three double-counting traps, two important missing-collection windows and at least two examples where a confident causal inference is invalid.  
**Deliverable:** Dependency graph and uncertainty summary.

## Phase 6 — WHAT SHOULD IT DECIDE? Build an actionable and defensible verdict. (26–30)

**Investigation objective:** Deliver a decision an IT organization can act upon, with evidence thresholds and an accountable restoration plan.

**26 — WHAT is proved, plausible, contradicted or unknown?** Classify at minimum: recorded configuration modification, unauthorized approval, unauthorized boot-code execution, firmware compromise, persistence, exfiltration and human attribution. Every status must cite an exact artifact or explicitly note missing evidence.  
**Deliverable:** Executive claim-evidence-status matrix.

**27 — WHAT is the minimal supported incident chronology?** Reconstruct a source-attributed chain from identity token and bastion channel through denied change, privilege escalation, audited write, FIM mutation, service unit observation, firewall ALLOW, partial TCP egress and software measurement alarm. Preserve raw timestamps and corrected times only where an appropriate calibration exists. Highlight contradictory ordering, audit serial gaps, clock error bounds, derived-source reuse and links that cannot be proven causal.  
**Deliverable:** One-page incident timeline with evidence references.

**28 — WHAT must the organization do immediately, and WHY?** Recommend proportionate containment that limits further access/egress while protecting volatile and durable evidence. Identify business continuity trade-offs and preservation priorities.  
**Deliverable:** Ordered incident-response actions with owner, reason and prerequisite.

**29 — WHAT independent tests would change the verdict?** Prioritize trusted firmware/boot-chain attestation, offline configuration and disk examination, authenticated change-approval records, endpoint-to-network session correlation and human-identity binding. Which exact result would confirm, weaken or leave each hypothesis unresolved?  
**Deliverable:** Verification plan with explicit pass/fail/indeterminate conditions.

**30 — WHAT is the final recommendation to the IT incident commander?** In no more than 400 words, answer: **Was the hardware root of trust shown compromised? What actually happened? Why does it matter? What remains unproved? Is service restoration supportable on the current evidence? What must occur before trust can be re-established?** Name limitations and explain the confidence basis; do not supply unsupported percentages or ATT&CK technique assertions.  
**Deliverable:** A concrete go / no-go / conditional-go decision memo, with assumptions and verification gates.

---

## Required final investigation package

| Output | Minimum acceptance criterion |
|---|---|
| Evidence integrity | Hash verification and acquisition-versus-integrity distinction |
| Multihost timeline | Exact source references; time uncertainty explicitly preserved |
| Causal/identity graph | All links typed as observed, inferred or unproven |
| Hypothesis matrix | Competing hypotheses with falsifying/discriminating tests |
| Trust-boundary verdict | Separate findings for policy, boot chain and hardware root of trust |
| IT action plan | Containment, evidence preservation, independent verification, recovery and ownership |
| Executive decision memo | Specific restoration gate and explicit limitations |

### Investigator grading principles

- **No credit for a confident but unsupported conclusion.** Correctly identifying an unknown can be the highest-quality answer.
- **No inference of firmware bootkit, attacker identity or data exfiltration from a service name, log label or IP address alone.**
- **No uncalibrated clock corrections or false claims of independent evidence.**
- **No claims that SHA-256 validation proves an originally collected image authentic.**
- **Final recommendations must connect observations to practical actions and clear release criteria.**

> **Submission status:** This is an instructor-assessed scientific worksheet. Converting it to a machine-graded Sherlock requires a separately verified private answer key, exact answer contracts, and an independent cold-solve. The simulated evidence does not establish real firmware compromise.
