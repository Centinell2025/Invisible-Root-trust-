# Case design and forensic limitations
## Fictional environment
Fully fictional enterprise training laboratory authored by Centinell Suite Defense, **not an account of an actual victim company**; isolated research gateway `nrg-gw-07`; accounts, endpoints, and IP addresses are fabricated. The two external IPs use IANA documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`).

## Incident hypothesis
A simulated maintenance account writes a boot policy configuration without approval, a service follows, and a measurement mismatch plus egress triggers investigation. The investigator must avoid assuming a policy hash mismatch proves firmware execution or an actual UEFI rootkit.

## Independence / confidence
The synthetic attestation CSV, system journal, authentication records, audit events, network metadata, and change ledger are separate *simulated data streams*, not cryptographically independent instruments. They teach corroboration rather than provide real-world proof.

## Containment
Isolate the affected host logically, capture volatile state if operationally safe, preserve original evidence, validate known-good recovery images and attestation baselines, rotate potentially exposed credentials, and monitor for recurrence. Do not trust a compromised machine's own claims of recovery.

## Future development before HTB submission
**Completed:** derive software policy measurement SHA-256 digests directly from reproducible mock files; add noisy syslog/auditd-like logs, FIM, process lineage, systemd unit, acquisition register, and valid limited TCP/UDP sensor samples with checksum validation. **Still needed:** realistic independently analyzable disk/firmware/memory acquisitions, event timing error bounds, richer decoys, precise machine-gradable question contracts, peer cold solves, private instructor solutions and human review of ambiguity. Do not represent this starter scaffold as an actual verified boot compromise.
