# INVISIBLE ROOT OF TRUST — Incident narrative
**Case ID:** NRG-IR-2026-0917 | **Classification:** Fictional training case | **Target audience:** Senior DFIR / Blue Team

## The call at 03:18 UTC
At 03:18 UTC on 17 September 2026, Northstar Research Group's monitoring desk received a measured-boot policy discrepancy from `nrg-gw-07`, a Linux gateway that brokers research network connectivity. The alarm was initially assigned low confidence: a maintenance window appeared in the change system, and a local service reported a routine signed update. Within minutes, however, the change ledger showed the relevant request had **not** been approved.

The first response team faced an uncomfortable problem. A service account had established a remote session and elevated privileges shortly before the discrepancy. An audit record pointed to a boot-policy configuration write, but neighboring audit sequence numbers were absent. Another host reported observing a related configuration change. The local journal claimed routine maintenance, while the independent inventory did not record a scheduled firmware operation.

A network-flow record then appeared to show outbound TCP traffic after a new service launched. A separate packet-capture specimen appeared to involve the same destination, but its actual transport protocol differed. Neither record alone proves exfiltration, and the capture must not be used to validate a TCP conversation it does not contain.

## The mandate
You are the lead incident investigator. Management wants a decisive answer before the gateway is restored to service: **Was the root of trust compromised, or did an unauthorized configuration change and inconsistent telemetry merely create the appearance of a deeper compromise?**

Your job is not to confirm the most alarming explanation. It is to establish which events are supported, which interpretations remain plausible, and where the evidence is too weak to decide. An inaccurate declaration of a firmware bootkit could trigger unnecessary fleet-wide recovery; a careless dismissal could return a compromised gateway to production.

## Investigative tensions
- **Authority versus activity:** A change ticket exists within the event window, but existence is not approval.
- **Identity versus attribution:** The account associated with the privileged session is known; the human or process controlling its credentials is not.
- **Continuity versus missing data:** Audit sequence gaps are evidence of incomplete visibility, not proof of either malicious deletion or inactivity.
- **Measurement versus execution:** A mismatched simulated policy measurement does not demonstrate that untrusted firmware executed.
- **Corroboration versus repetition:** Two simulated sources can agree while sharing the same underlying assumptions or clock problems.
- **Network metadata versus packets:** A TCP flow record cannot be validated by an unrelated UDP packet solely because a destination address matches.

## Deliverables to the incident commander
1. A defensible timeline that identifies source clocks and uncertainty.
2. A chain of observations connecting access, privilege use, configuration changes and the later alarm.
3. A table separating established facts, reasonable inferences, competing hypotheses and unknowns.
4. An evidence-based assessment of whether persistence, firmware compromise or data exfiltration can actually be concluded.
5. A preservation-first containment and recovery recommendation, including what new collection would change your confidence.

## Evidence boundaries
This case is entirely simulated. Policy binary specimens are illustrative, the memory excerpt is not a full RAM acquisition, and the packet capture is a minimal UDP sample. The challenge does **not** establish a real bootkit, hardware-backed attestation, or verified data theft. Avoid treating narrative urgency as proof.

## Investigator's closing standard
Every material claim must identify its supporting artifact and limitations. Strong investigators know not only how to connect evidence, but when the evidence does not permit a conclusion.
