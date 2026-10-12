# Case design and forensic limitations
## Fictional environment
Northstar Research Group; isolated research gateway `nrg-gw-07`; accounts, endpoints, and IP addresses are fabricated. The two external IPs use IANA documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`).

## Incident hypothesis
A simulated maintenance account writes a boot policy configuration without approval, a service follows, and a measurement mismatch plus egress triggers investigation. The investigator must avoid assuming a policy hash mismatch proves firmware execution or an actual UEFI rootkit.

## Independence / confidence
The synthetic attestation CSV, system journal, authentication records, audit events, network metadata, and change ledger are separate *simulated data streams*, not cryptographically independent instruments. They teach corroboration rather than provide real-world proof.

## Containment
Isolate the affected host logically, capture volatile state if operationally safe, preserve original evidence, validate known-good recovery images and attestation baselines, rotate potentially exposed credentials, and monitor for recurrence. Do not trust a compromised machine's own claims of recovery.

## Future development before HTB submission
Replace toy repeated digests with realistic fixed-size cryptographic digests generated from reproducible mock files; add memory/firmware image simulators with parsers, signed-and-invalid artifact specimens, timestamps with documented offset/skew, obfuscated false leads, precise machine-gradable questions, peer playtests, a complete instructor solution kept private, and automated quality tests. Do not represent this starter scaffold as an actual verified boot compromise.
