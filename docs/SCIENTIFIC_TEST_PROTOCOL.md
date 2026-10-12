# Scientific QA and senior challenge acceptance protocol
**Case:** NRG-IR-2026-0917 | **Exercise:** Invisible Root of Trust | **Status:** In development

## Why this test exists
A mature incident response Sherlock does not pass because its files exist, its SHA-256 checksums match, or its story sounds technical. It passes only when a skilled analyst can work from documented evidence to a reproducible conclusion and a practical decision for an IT organization.

This protocol tests three **different** concepts:
1. **Engineering validity:** Are artifacts reproducible, parsable, mutually consistent where required, and intentionally contradictory where the case design requires it?
2. **Scientific answerability:** Can a non-author independently resolve what is determinable and justify what is not, using exact evidence, provenance and alternate hypotheses?
3. **Business decision readiness:** Can the final analysis justify containment, independent trust verification and a restoration decision without claiming unsupported firmware compromise?

A passing automated engineering test does not establish items 2 or 3. A passing research report does not make this an automatically graded HTB Sherlock.

## Automated engineering gates

Run locally from the repository root:

```bash
python3 tools/run_full_case.py
python3 -m unittest discover -s tests -v
python3 tools/build_submission.py
python3 tools/validate_release.py
python3 tools/scientific_quality_gate.py --mode insane
```

The last command is **expected to block** release until external evidence, instructor grading contracts and independent cold-solve requirements are satisfied; an ordinary nonzero exit status is not a defect in this protective gate.

The automated tests must verify:
- Exactly **30 unique, sequentially numbered questions** organized into six investigation phases.
- A minimum of two *candidate* evidence sources associated with each question. Distinct filenames are **not** necessarily independent sources.
- Integrity and exhaustive inventory consistency of the synthetic case files.
- A real byte-level difference between policy specimens, their cryptographically correct hashes, the derived software measurement and file-integrity timeline, while requiring that all hardware-attestation fields remain unverified.
- Authentication, privileged session, audited write, cross-host reference and audit gap correlations.
- Signed/approved/rejected deployment differences and lack of an approved deployment for an unapproved change ticket.
- Explicit source-clock uncertainty; timestamps without a justified calibration cannot silently be normalized.
- Syntactically valid Ethernet/IPv4 packet capture with the **correct 2026 incident date**.
- Separate the legacy UDP-only packet from the partial **TCP handshake, sample payload and UDP lookalike** in the additional edge-sensor PCAP. Validate actual on-wire checksums, endpoints and capture completeness. No source alone proves exfiltration.
- A student's ZIP that contains the investigative brief and artifacts but excludes development and instructor-only material.
- **Negative controls:** malformed or truncated PCAP, invalid IPv4/TCP/UDP checksums, tampered policy hash derivation, false TPM-attestation claim, broken process lineage, altered change approval, missing phase and duplicate question number must be rejected.

## Research examination — what to evaluate in each phase

| Phase | Questions | Scientific task | Common invalid answer |
|---|---|---|---|
| WHAT | 01–05 | Identify measured vs. actually proved state | A local mismatch proves firmware execution |
| WHERE | 06–09 | Localize trust and capture boundaries | Same destination IP means same session |
| WHEN | 10–14 | Build qualified timeline and account for gaps | An uncalibrated earlier log proves causation |
| WHO & HOW | 15–20 | Reconstruct identity, mechanism and persistence limits | A service account proves human attribution |
| WHY & PURPOSE | 21–25 | Falsify alternative hypotheses and separate intent from facts | Correlated labels prove attacker intent |
| IT DECISION | 26–30 | Produce claim ledger, containment plan and revalidation gates | Replace one service, claim system is trusted |

## Senior scientific grading rubric (instructor evaluated)

Score each dimension from **0 to 20**, for **100 possible points**:

| Dimension | Maximum | Award credit for |
|---|---:|---|
| Evidence provenance and repeatability | 20 | Exact file/row/hash/byte citations, chain-of-custody qualifications, reproducible processing |
| Cross-host reconstruction and timing | 20 | Correct link semantics, offset limitations, missing-data treatment, unsupported causal-edge labels |
| Hypothesis falsification and uncertainty | 20 | Competing explanations, discriminating tests, non-independence analysis, proportionate confidence |
| Trust-boundary and network precision | 20 | Correct distinction among policy, boot chain and hardware trust; protocol-level correlation; no invented exfiltration |
| Business response and executive reasoning | 20 | Actionable containment, realistic acquisition priorities, owner/sequence, go/no-go conditions and limitations |

**Proposed senior pass threshold:** 85/100 with no critical errors and an acceptable response to Q30. This is an internal training target, **not** an official HTB requirement or a verified difficulty percentile.

### Disqualifying errors regardless of points
- Declaring the hardware root of trust compromised based only on mock binaries or local journal/attestation-agent logs.
- Claiming a UDP packet validates a TCP transfer.
- Calling an absent memory/firmware image proof that persistence is absent.
- Treating matching synthetic hashes as proof that original evidence was collected authentically.
- Restoring production service solely because a suspicious service was removed.
- Naming an attacker or a human operator without corroborated identity context.

## Independent cold-solve protocol

Before release, give the **student ZIP only** to at least two investigators who have never seen the generators, commit history or instructor reasoning. They must:

1. Verify the file inventory and complete questions 01–30 without assistance.
2. Supply evidence references for each affirmative finding and explicit uncertainty for unsupported claims.
3. Document time spent, ambiguous wording, missing evidence, divergent answers and any unintended shortcuts.
4. Present a 400-word executive decision memo for an IT incident commander.
5. Explain whether the offered evidence supports **P1** (configuration alteration), **P2** (unauthorized boot-chain execution), **P3** (hardware root-of-trust compromise), separately.

The instructor must reconcile disagreements and **repair artifacts/questions** when different answers follow reasonably from the same data. The challenge should not demand a single numeric/string answer for an open-ended proposition.

## HTB-specific release blocker

An HTB Sherlock typically needs discrete, verifiable answer fields; this public research worksheet contains compound and narrative questions. Before submission, create a separate precisely graded set with an instructor-only key, including exact values, supported equivalent answers and proof locations. Keep the complete solution out of the public repository and its history.

The following remain **open**:
- No independent, documented cold-solve result has been collected.
- No privately verified grading key covering 30 final answers exists in the repository.
- The policy specimens are mock data; no trustworthy firmware acquisition or hardware attestation is distributed.
- The memory excerpt is not a forensic RAM image.
- The legacy single UDP packet does not corroborate TCP; the new eight-packet edge-sensor sample supports only a limited TCP connection and not the full byte count, authentic TLS, payload purpose or exfiltration.

**Release policy:** Passing the engineering gate permits continued development and reproducible distribution for testing. It does **not** authorize calling the lab Insane or promising HTB acceptance.
