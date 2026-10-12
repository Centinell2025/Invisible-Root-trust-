# Evidence provenance and limits
This challenge is a **synthetic forensic exercise**, not a firmware acquisition. The policy binaries are invented text-like specimens; memory_excerpt.bin is not a valid raw RAM dump and must not be described as Volatility-compatible. The PCAP is a one-packet UDP sample, not a reconstructed TCP conversation. The discrepancy with TCP flow metadata is deliberate and cannot prove exfiltration.

## Claims requiring additional evidence
- Actual UEFI persistence: trusted firmware dump, verified boot chain, measured boot evidence and signatures.
- Network exfiltration: correlated full packet capture, endpoint socket telemetry and collection provenance.
- Attacker identity: corroborated authentication context and host compromise analysis.
- Timeline certainty: trusted clock synchronization records and timestamp error bounds.

## Responsible investigator conclusion
A mismatched simulated boot policy and suspicious service are indicators warranting investigation. They do not establish a bootkit, malicious actor identity, or confirmed data loss. Findings must distinguish observation, inference, and unknown.
