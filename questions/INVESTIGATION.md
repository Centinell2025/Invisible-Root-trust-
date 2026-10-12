# Analyst investigation — Invisible Root of Trust
Use exact UTC timestamps, filenames, IDs and hashes from generated evidence. Cite at least two independent sources for conclusions wherever possible.

1. Which hostname is the subject of the attestation alert?
2. What is the first UTC time when the recorded boot measurement differs from its approved reference?
3. Which measurement component differs at that time?
4. Which change ticket covers the same window, and is it approved?
5. What source confirms whether a legitimate scheduled firmware operation occurred?
6. Which user first initiated an interactive session during the anomalous window?
7. Which source IP is associated with that session?
8. Which privilege escalation event precedes the trust measurement change?
9. What exact path is named by the audit record for the unauthorized write?
10. What event identifier ties that write to the suspicious session?
11. Which neighboring audit sequence values are absent?
12. What evidence prevents treating the absent audit rows as proof of no activity?
13. What service label appears in the journal after the unauthorized change?
14. Does the service entry by itself prove execution of a real bootkit? Explain.
15. Which destination is contacted after the service starts?
16. What is the first flow timestamp for that destination?
17. Which log claims a benign update, and what independent record contradicts it?
18. What is the last clearly trustworthy observation before the change?
19. What is the earliest supported moment of potential persistence?
20. State the minimal event sequence from session establishment through egress.
21. Identify two artifacts whose clocks should be reconciled before reporting exact causality.
22. Which records are observations versus assumptions or vendor-style labels?
23. What SHA-256 validation step would establish local artifact integrity after generation?
24. What containment action preserves forensic value while limiting simulated egress?
25. What recovery step would re-establish boot trust more reliably than deleting a suspicious service?
26. Name one alternative hypothesis consistent with only a subset of the evidence.
27. Which evidence rules out that alternative?
28. Which missing collection would most improve confidence about on-disk persistence?
29. Write a concise finding with confidence level and explicit limitations.
30. Which ATT&CK techniques can be *hypothesized* and which cannot be established from this evidence alone?

> This is an analyst worksheet, not a platform-ready machine-graded answer set. Every question should be converted into a precisely graded prompt after review.
