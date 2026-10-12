# Hack The Box Player Tasks — Invisible Root of Trust
**Author:** Centinell Suite Defense · Beacon of the Eagle LLC  
**Case:** NRG-IR-2026-0917 · **Data:** fully synthetic DFIR artifacts

## Before starting
Read `README.txt`, verify `artifacts/custody_manifest.sha256`, and use a safe investigation VM. These tasks are designed as **single-value, evidence-checkable milestones**. The separate `questions/INVESTIGATION.md` contains the advanced **30-question research extension**, including interpretive questions assessed by an instructor rather than automated flags.

Use only the supplied artifacts. Preserve capitalization, timestamp precision, paths, identifiers and hex digits as requested. A derived SQLite cache is not independent corroboration of its input data.

## Stage I — Establish observable integrity

**Task 01.** What is the exact hostname of the gateway with the first reported local policy-measurement discrepancy?  
**Answer format:** hostname, lowercase (example: `host-01`).

**Task 02.** At what exact UTC timestamp does the first `shim-policy` measurement mismatch occur in the attestation export?  
**Answer format:** `YYYY-MM-DDTHH:MM:SSZ`.

**Task 03.** Compute the SHA-256 of the observed policy binary from its actual bytes. What is the resulting digest?  
**Answer format:** exactly 64 lowercase hexadecimal characters, no prefix.

## Stage II — Reconstruct privileged change and approval

**Task 04.** Which change ticket covering the affected gateway's maintenance window was **not approved**?  
**Answer format:** `CHG-NNN`.

**Task 05.** Which audit-linked authentication reference identifies the privileged session associated with the recorded policy write?  
**Answer format:** `AUTH-NNN`.

**Task 06.** By correlating the Linux audit extract with the process lineage, which process ID performed the observed write on the policy path?  
**Answer format:** decimal PID.

**Task 07.** Which **two consecutive audit serial numbers** are missing between the recorded `open` and `write` observations in the simplified audit table?  
**Answer format:** `NNNN-NNNN` (ascending order, hyphen-separated).

**Task 08.** In the deployment provenance ledger, what is the package ID of the gateway-targeted **unsigned, rejected** deployment associated with the unapproved ticket?  
**Answer format:** `PKG-NNN`.

## Stage III — Investigate the service and file-level snapshot

**Task 09.** Which systemd unit is represented by the service specimen and the matching enablement symlink in the scoped offline TAR?  
**Answer format:** unit basename, including `.service`.

**Task 10.** Compute the SHA-256 of the service unit file bytes in the offline TAR; what is its digest? Cross-check the FIM entry.  
**Answer format:** 64 lowercase hexadecimal characters.

**Task 11.** Which PID is recorded as the parent of the sampled outbound network client process in `process_lineage.csv`? Match the client with the socket observation.  
**Answer format:** decimal PID.

## Stage IV — Correlate sampled network traffic

**Task 12.** What client-side TCP source port identifies the socket and partial edge-sensor TCP conversation associated with the gateway's reported destination?  
**Answer format:** decimal port.

**Task 13.** How many outbound **TCP application-payload bytes** from that five-tuple are actually present in the **partial** `edge_sensor_capture.pcap`? Count TCP payload bytes only; exclude Ethernet/IP/TCP headers, ACK-only packets, and UDP traffic.  
**Answer format:** decimal byte count.

## Stage V — Scientific trust finding

**Task 14.** How many `host_events` records are in the provided read-only SQLite analysis cache?  
**Answer format:** decimal row count.

**Task 15.** What is the exact `collection_status` value for `TPM2-quote` in `trust_anchor_inventory.csv`?  
**Answer format:** value copied exactly from the CSV, including hyphen if present.

**Task 16.** Based **only on the distributed evidence**, which finding correctly describes whether a hardware-root-of-trust compromise has been **proven**?  
**Answer format:** `ESTABLISHED` or `NOT ESTABLISHED` (uppercase, with space if applicable). Explain your reasoning separately in the research memo.

## Scientific completion task (human assessed; not an HTB exact flag)
In the extended worksheet, prepare a defensible incident memo: **WHAT happened, WHERE, WHEN, WHO is actually known, HOW the observations are linked, WHY alternative explanations remain, and WHAT an IT organization must verify before restoration**. A local policy mismatch does not, by itself, establish firmware takeover, operator identity or exfiltration.

**No answers or solution logic are provided in this student task sheet.**
