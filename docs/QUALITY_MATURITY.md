# Maturity review — release candidate criteria

## Technical changes
- Use the full-case generator in all tests; the legacy basic generator must not overwrite the manifest during integrated validation.
- Require exact evidence inventory and SHA-256 equality, rather than checking only presence.
- Check timestamps are parseable UTC, unique audit sequences, correlated identity and write references, binary digests, and PCAP structure.
- Reject contradictory attestation match/mismatch flags and malformed network counters.

## Known open blockers
1. The public Git history previously contained answer derivation logic. Deleting a file does not erase commit history.
2. The memory excerpt is not a real forensic RAM image, and the policy specimens are mock bytes.
3. The single-packet UDP PCAP cannot confirm the separate TCP flow metadata.
4. A private instructor key, precise grading contract, and independent cold solve are still missing.
5. CI must pass before release; no assertion of passing CI should be made without seeing the run.

## Acceptance threshold
Only mark ready when every prompt has a unique verified answer and source reference, independent solvers can finish without hints, the ZIP has passed strict release validation, and the content meets HTB's current submission terms.
