# Evaluation rubric for independent playtesting
**This is not an official HTB rubric.**
- Evidence provenance and SHA-256 verification: 15 points
- Cross-host identity and privilege correlation: 20 points
- Timestamp skew correction and uncertainty: 15 points
- Boot-policy binary analysis and hash crosscheck: 20 points
- Network-flow / PCAP discrepancy recognition: 10 points
- Alternative hypotheses and explicit limits: 10 points
- Containment and trusted recovery strategy: 10 points
Total 100 points. Target for cold-solve: require defensible written reasoning, not just filenames. Do not equate high score or high question count with HTB Insane acceptance.

## Separation
The internal grader `tools/grade_case.py` calculates answer fields. It is intentionally excluded from the student archive by an allowlist. Keep any expanded instructor walkthrough and canonical answers in a private repository.
