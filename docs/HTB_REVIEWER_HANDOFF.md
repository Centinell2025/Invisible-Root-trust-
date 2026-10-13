# Reviewer Handoff — Invisible Root of Trust
**Publisher:** Beacon of the Eagle LLC  
**Research brand:** Centinell Suite Defense  
**Case ID:** NRG-IR-2026-0917 · **Submitted track:** Hack The Box Sherlock candidate  
**Intended category:** DFIR / Linux / Incident Response · **Target:** Hard (proposed; subject to HTB review)  
**Status:** Technical candidate; formal HTB acceptance, difficulty and quality bonus are **not** established.

## 1. What the reviewer receives

The verified **student-only ZIP** is published after successful GitHub Actions validation. It contains:

- `README.txt` — mandatory safety notice, free-tool instructions, evidence-validation commands and Beacon authorship.
- `docs/STUDENT_INCIDENT_BRIEF.md` — spoiler-free fictional incident and tasking.
- `docs/STUDENT_EVIDENCE_RULES.md` — measurement, attribution, uncertainty and chain-of-custody standards.
- `questions/HTB_PLAYER_TASKS.md` — **25 exact-value, progressively staged** player tasks with unambiguous output formats.
- `questions/INVESTIGATION.md` — **30 analytical research questions**, a separate instructor-assessed extension rather than 30 automatically scored flags.
- `artifacts/` — all 39 evidence files plus `custody_manifest.sha256`, including SQLite, packet captures, hash-linked specimen bytes, Linux-style logs and a scoped TAR.

The *public development repository* contains generator logic and discussions. **Do not use the repository or its commit history for a blind playtest.** Provide the reviewed ZIP exclusively.

## 2. Five-host architecture

See [ARCHITECTURE_AND_PROVENANCE.md](ARCHITECTURE_AND_PROVENANCE.md). The fictional systems and training-relevant services are:

| Host | Simulated role | Evidence and processes worth reviewing |
|---|---|---|
| `nrg-gw-07` | Linux research gateway | `sshd`, `sudo`, `nrg-policy-sync`, `attestationd`, `boot-health-agent.service`, outbound client and local FIM |
| `nrg-bastion-02` | Session broker / bastion | VPN/session acceptance and remote session references |
| `nrg-idp-01` | Identity provider | Service-principal token events; no verified human identity binding |
| `nrg-build-03` | Package/change system | Signed, pending, approved and rejected package records |
| `nrg-sensor-04` | Network sensor | Partial packet capture, reported flow totals and collection limitations |

Important fictional principals include `svc-maint` (service account); background `backup`, `metrics`, `buildbot`, `deploy` and `root` accounts. These are not actual employees or externally identifiable individuals.

## 3. Technical methodology and supported findings

The participant must validate the SHA-256 custody manifest, reconstruct the recorded access/change sequence, compare package approval with execution claims, inspect file and process lineage, evaluate packet/flow coverage, normalize timestamps **only where justified**, and separate:

- **P1** — observable local software policy-specimen change.
- **P2** — unverified unauthorized execution in a protected boot stage.
- **P3** — unverified hardware-root-of-trust compromise.

The measurements in this lab are explicitly **local software SHA-256 values**, not TPM quotes, hardware firmware digests or proof of an actual bootkit. The ZIP contains **no malware**, no live credentials and no exfiltrated customer data. Network ranges `192.0.2.0/24` and `198.51.100.0/24` are documentation-only addresses.

## 4. Tools, rights, provenance

Investigation requires only free/open-source capabilities: Python 3 standard library, SQLite CLI or DB Browser for SQLite, tar utilities, `sha256sum`, and Wireshark/tshark where available.

**CVE utilization:** No real CVE, exploit or vulnerable commercial target is used to create this simulated exercise. **Malware specimens:** None; no malware password-protected archive is needed. **PII/PCI:** No real PII or cardholder records are used; all identifiers, timestamps, source IPs, user accounts and scenarios are fabricated for educational purposes. **External copyrighted content:** Not intentionally bundled; release QA should still check intellectual-property provenance before commercial submission.

A matching manifest authenticates the **delivered bytes**, not an independent historical collection from production infrastructure. The SQLite database is a derived analytic cache. The TAR is a selective export, not a full disk image. The capture is partial and cannot substantiate a complete session or data loss.

## 5. Reproduce the candidate

```bash
python3 tools/run_full_case.py
python3 tools/validate_realistic.py
python3 tools/validate_snapshot.py
python3 tools/scientific_quality_gate.py
python3 -m unittest discover -s tests -v
python3 tools/build_submission.py
python3 tools/validate_release.py
```

CI also checks syntax, rebuilds evidence after mutation tests, hashes every artifact and publishes the verified **student** ZIP as `invisible-root-of-trust-student`. Never publish a private instructor key, full solution or internal reviewer ZIP as a public CI artifact.

## 6. Examination / approval criteria

| Criterion | Minimum proof expected | Current status |
|---|---|---|
| User can start without the repository | README, included tasks, evidence, safe free-tool examples | Built into student ZIP |
| Answers reproducible from artifact bytes | Reproduce all 25 exact tasks against the current ZIP | **25/25 reproduced from the current student ZIP in a confidential reviewer package; independent blind test pending** |
| Grading compatible with official HTB question YAML | Exact `flag` values, formatting and acceptable variants | **Current 25-flag YAML assembled and author-verified, held outside public repository; HTB approval pending** |
| Full intended walkthrough | Step-by-step proof path for 25 tasks aligned to HTB Sherlock template | **Current 25-question private writeup complete; independent assessment pending** |
| Screenshot proof of each answer | Terminal evidence and exact commands covering the current questions | **25 actual Xterm screenshots and read-only replay commands in confidential examiner package; independent verification pending** |
| Scenario, host/process/service/account/CVE/PII description | Clear scope and technical details | This handoff + architecture diagram |
| Evidence integrity | SHA-256 inventory, reproducible build and CI | **97 automated tests passed in CI; 39 synthetic evidence files hash-verified** |
| Realism and playability | Two blind attempts and ambiguity reconciliation | **Not independently validated** |
| Hard difficulty | Advanced multi-source investigation and observed time-to-solve (HTB suggests up to 2 days) | **Not independently established** |

The 30-question research worksheet remains instructor-assessed and is intentionally not machine-graded; HTB's platform should receive the 25 discrete task fields and a **separately confidential** human-reviewed incident conclusion. Editors may choose to revise the number and difficulty after cold-solve results.

## 7. Reviewer feedback requested

Please assess evidence realism, task wording and ambiguity, whether the incidental data produce meaningful forensic discrimination, coverage of an expert Linux DFIR workflow, and whether the experience meets the **Hard** difficulty requirements. Record any expected answer variants and unintended shortcuts.

An excellent review should not be obtained by hiding limitations or claiming software measurements prove a hardware root-of-trust failure. The scientific objective is knowing both **what can be proved and what cannot**.

## 8. Author attribution

> **BEACON OF THE EAGLE LLC**  
> **CENTINELL SUITE DEFENSE**  
> **ORIGINAL DIGITAL FORENSICS RESEARCH & TRAINING — 2026**

This is an authorship imprint, **not** an HTB endorsement, external certification or identification of a real incident victim.

## Official references

- [HTB Sherlock requirements](https://help.hackthebox.com/en/articles/8463668-sherlocks-submission-requirements)
- [Official Sherlock question/writeup templates](https://github.com/hackthebox/public-templates/tree/master/Sherlock)
- [HTB Sherlock submission process](https://www.hackthebox.com/blog/sherlock-submission-process)

**Important:** Never mark a missing private key, complete screenshot walkthrough or cold-solve as done merely because GitHub Actions passed. These are independent examiner sign-off gates.
