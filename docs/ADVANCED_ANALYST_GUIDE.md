# Advanced analyst guidance
## Evidence handling
Run `python3 tools/run_full_case.py` to generate both basic and advanced evidence. Verify `sha256sum -c artifacts/custody_manifest.sha256`. Generated binaries are synthetic *specimens*, not actual UEFI images or RAM acquisitions.

## Investigation pivots
- Compare `policy_baseline.bin` and `policy_observed.bin` bytewise; verify both digests in `policy_digest_crosscheck.csv`.
- Correlate `multi_host_events.csv` with local `auth_events.csv` and `audit_events.csv`; distinguish independent host records from local self-reporting.
- Apply clock offsets from `clock_calibration.csv` before asserting ordering to the second. Offset conventions: corrected UTC = recorded UTC minus offset.
- Use `benign_decoys.csv` to separate unrelated authorized maintenance from the suspect change.
- Parse `synthetic_telemetry.pcap` using Wireshark/tshark or a PCAP parser. It contains a single benign UDP frame to documentation addresses. It does **not** substantiate the TCP 443 flow in `network_flows.csv`; that discrepancy is intentional and must be reported.
- The memory excerpt is a deterministic teaching sample and cannot prove actual runtime memory persistence.

## Interpretive limits
A simulated policy mismatch and journal entry do not prove a real UEFI implant. High-confidence findings require stronger provenance, trusted acquisition, firmware measurements and independent collection. A defensible answer may be 'insufficient evidence.'
