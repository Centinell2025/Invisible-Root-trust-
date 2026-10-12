INVISIBLE ROOT OF TRUST — INVESTIGATION PACKAGE
Case NRG-IR-2026-0917 | Fictional DFIR training laboratory
Publisher: BEACON OF THE EAGLE LLC
Research brand: CENTINELL SUITE DEFENSE
Copyright (c) 2026 Beacon of the Eagle LLC

READ THIS FILE FIRST
====================
Mission: Investigate a reported gateway integrity discrepancy and determine
which trust claims can be established using the supplied evidence. Present
a defensible restoration decision, not merely a list of suspicious strings.

This package is entirely synthetic. It contains NO live malware, production
customer records, genuine keys, actual incident victim, actual firmware
image, complete disk image, or trustworthy hardware-backed TPM quote.
Treat all binary/log/PCAP files as untrusted input. Use a dedicated VM and
do not execute unknown material extracted from the evidence archive.

PACKAGE CONTENTS
================
- docs/STUDENT_INCIDENT_BRIEF.md : your assignment and scenario
- docs/STUDENT_EVIDENCE_RULES.md : what qualifies as a defensible conclusion
- questions/HTB_PLAYER_TASKS.md : 16 objective, single-answer HTB task milestones
- questions/INVESTIGATION.md : 30-question instructor-reviewed research extension
- artifacts/ : simulated forensic evidence, including:
    custody_manifest.sha256         -- SHA-256 inventory
    endpoint_telemetry.sqlite3      -- derived SQL event/flow cache
    offline_gateway_triage.tar      -- scoped Linux file-level collection
    auth_syslog.log, auditd_extract.log, journal_extended.jsonl
    edge_sensor_capture.pcap, synthetic_telemetry.pcap
    policy_baseline.bin, policy_observed.bin
    supplementary CSVs, service unit and metadata

FREE TOOLS
==========
Required: Python 3 (stdlib), text editor, archive extractor.
Recommended: sqlite3 CLI, sha256sum, tar, Wireshark/tshark.
All tools may be free or open source; no subscription or paid trial needed.
Kali/Ubuntu examples below. On Windows use Python, DB Browser for SQLite
and Wireshark, or analyze in a Linux VM.

SAFE FIRST STEPS — KALI/UBUNTU
===============================
1. Extract the ZIP into a new directory (do not run any contained binaries).
2. Read docs/STUDENT_INCIDENT_BRIEF.md and questions/HTB_PLAYER_TASKS.md.
   The 30-question INVESTIGATION.md is a deeper, narrative research extension.
3. From the extracted package root, verify the artifact inventory:
       cd artifacts
       sha256sum -c custody_manifest.sha256
       cd ..
   Report any mismatches before analyzing.
4. Inspect the SQLite schema without modifying the database:
       sqlite3 'file:artifacts/endpoint_telemetry.sqlite3?mode=ro' '.tables'
       sqlite3 'file:artifacts/endpoint_telemetry.sqlite3?mode=ro' '.schema'
5. List the scoped TAR safely, without extracting or running its contents:
       tar -tf artifacts/offline_gateway_triage.tar
6. Inspect capture metadata (no traffic replay):
       capinfos artifacts/edge_sensor_capture.pcap
       tshark -r artifacts/edge_sensor_capture.pcap -c 10
   If those tools are unavailable, Wireshark's File > Open also works.
7. Compare the policy specimens using local SHA-256 utilities:
       sha256sum artifacts/policy_baseline.bin artifacts/policy_observed.bin
8. Continue through the 16 HTB tasks in order. For each answer, cite the source filename,
   specific record/row/offset and original UTC timestamp if present.

SAFETY AND PROVENANCE
=====================
The SQLite database is a derived analysis cache, NOT independent proof that
its underlying records are authentic. The TAR is a selective *file-level*
triage, NOT a full-disk forensic image. Packet captures are partial.
A local software hash discrepancy is NOT a validated TPM quote or proof
that the platform firmware root of trust has been compromised.

DO NOT automatically apply clock corrections to sources that lack an
explicit calibration and error bound. Do not assign a named human attacker
from a service account. Do not infer exfiltration solely from byte counts.
Use NOT ESTABLISHED where evidence is insufficient, and state the acquisition
that would resolve the issue.

WHAT TO DELIVER
===============
- SHA-256/inventory verification notes
- Exact-value answers to the 16 HTB tasks (on the platform, if supplied)
- Artifact-cited responses to the optional 30-question research extension
- Multihost event timeline, including uncertainty
- Observed/inferred/unknown claim matrix and competing hypotheses
- Practical containment, recovery and independent revalidation gates
- Executive decision memo: GO / NO-GO / CONDITIONAL-GO

If working within HTB, submit answers in the HTB Sherlock task fields
using the formatting requested there. The research worksheet is an
instructor-reviewed extension; not every question has a single exact string.

AUTHORSHIP SEAL
===============
BEACON OF THE EAGLE LLC
CENTINELL SUITE DEFENSE
ORIGINAL DIGITAL FORENSICS RESEARCH & TRAINING — 2026
Corporate authorship, not an external certification or an actual incident.
