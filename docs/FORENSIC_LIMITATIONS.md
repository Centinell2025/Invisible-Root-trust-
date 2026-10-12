# Evidence provenance and limits
This challenge is a **synthetic forensic exercise**, not a firmware acquisition. The binary specimens support an explicitly documented **local software SHA-256 measurement** that has no hardware trust anchor. They are not UEFI images. `memory_excerpt.bin` is not a valid raw RAM dump and must not be described as Volatility-compatible. There are two packet specimens: `synthetic_telemetry.pcap` is a deliberately partial **single UDP packet**, while `edge_sensor_capture.pcap` contains an eight-packet, checksum-valid TCP/UDP synthetic sensor sample with an observable three-way handshake, a small amount of TCP application-like data and benign lookalikes. The partial TCP data corroborates a connection tuple but does **not** establish the reported flow byte total, authentic TLS, data exfiltration or a complete session. The UDP packet alone cannot corroborate the TCP flow.

## Claims requiring additional evidence
- Actual UEFI persistence: trusted firmware dump, verified boot chain, measured boot evidence and signatures.
- Network exfiltration: correlated full packet capture, endpoint socket telemetry and collection provenance.
- Attacker identity: corroborated authentication context and host compromise analysis.
- Timeline certainty: trusted clock synchronization records and timestamp error bounds.

## Responsible investigator conclusion
A mismatched simulated boot policy and suspicious service are indicators warranting investigation. They do not establish a bootkit, malicious actor identity, or confirmed data loss. Findings must distinguish observation, inference, and unknown.
