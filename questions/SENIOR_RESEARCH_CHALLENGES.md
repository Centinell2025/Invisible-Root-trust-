# Senior scientific investigation — research challenges
All evidence is synthetic. Use source references and distinguish what is proven from what is merely plausible.

## Track A — identity and session lineage
1. Determine which session references connect the bastion and identity provider to the gateway privilege event. Explain why shared account labels alone are not proof of a single human operator.
2. Find the earliest recorded session event associated with the service account and report its clock-domain limitation.
3. Identify the earliest independently logged observation of a configuration write and compare it with the gateway audit write. Can their order be proven without uncertainty bounds?
4. Determine which session events could be benign background activity and specify a testable criterion for excluding them.
5. Explain which missing identity artifact would allow stronger attribution than a service-account name.

## Track B — deployment provenance
6. Identify all package records targeting the affected gateway and classify each by signature and approval status.
7. Explain why a signed package is not automatically an authorized deployment.
8. Determine whether the deployment ledger supports the local journal's routine signed-update claim.
9. Find the package associated with a rejected change and explain what additional host evidence would prove installation.
10. Distinguish staged, signed, approved and executed states using only recorded fields.

## Track C — causal reconstruction
11. Construct a provenance graph linking session activity, privileged access, policy modification, service launch, attestation and network metadata.
12. Mark each edge as observed, inferred or unsupported; explain which edges cannot be promoted to causal links.
13. Compare the source timestamps across at least three hosts; identify where the supplied clock calibration is insufficient.
14. Evaluate whether the missing audit sequence could hide a second write, while explaining why this is not established.
15. Provide two competing causal explanations for the measured-policy mismatch and identify a discriminating acquisition.

## Track D — contradictory network evidence
16. Compare the transport protocol in the network-flow record with the PCAP specimen and determine whether they represent the same verified session.
17. Explain why the shared destination address is insufficient for packet-to-flow attribution.
18. Specify the minimum packet and endpoint process metadata needed to substantiate the alleged outbound connection.
19. Identify which claims about exfiltration remain unsupported and why byte counts alone cannot establish data theft.
20. Design a reproducible test that would falsify the interpretation that the UDP sample corroborates TCP egress.

## Track E — scientific inference and decision
21. Create a claim-evidence table for unauthorized change, persistence, firmware execution and exfiltration.
22. Identify at least three evidence sources with potential common-cause dependence.
23. Explain how incomplete collection changes confidence without assigning invented probabilities.
24. Recommend an evidence-preserving containment sequence with explicit operational assumptions.
25. State the strongest defensible finding and at least three conclusions that cannot be drawn from this dataset.

> These are instructor-reviewed research prompts. They are not yet machine-gradable HTB questions; a private key and verified answer contract are still required.
