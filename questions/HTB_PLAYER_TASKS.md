# Invisible Root of Trust — Hard Sherlock Investigation
**Original research:** Centinell Suite Defense · **Publisher:** Beacon of the Eagle LLC  
**Case ID:** NRG-IR-2026-0917 · **Proposed HTB difficulty:** Hard (subject to external review)  
**Safety:** All hosts, people, identities, companies, addresses and events are fictitious.

## Mission and rules of proof

A Linux network gateway reportedly failed a local policy-integrity check during a disputed maintenance interval. Three stories compete: authorized change, unauthorized local modification, or compromise of the machine's root of trust. Your investigation must discover **what the evidence actually proves**, rather than assume the most dramatic explanation is correct.

**Do not analyze this case only by keyword searches.** The required technical workflow includes SHA-256 byte verification, timestamp correction within the appropriate source, joined identity and privilege records, signed/unsigned change state, service and process lineage, a read-only SQLite query, systemd symlink inspection, and genuine parsing of a partial network PCAP.

Begin with `README.txt` and `docs/STUDENT_INCIDENT_BRIEF.md`. Verify `artifacts/custody_manifest.sha256`. Use only the student ZIP; avoid the public generator repository and do not execute binaries from evidence. All sources are *simulations*, and the derived SQLite cache does **not** provide independent corroboration of its input logs.

Every task has **one exact, machine-readable result**. A reasoned supporting explanation is requested for the human-assessed extension. A negative finding means the supplied collection does not establish the proposition; it is not evidence of absolute absence.

## Stage I — Establish the integrity boundary

**Task 01.** Use the local measurement report, file-integrity observations and host inventory to distinguish the affected gateway from unrelated background hosts. Which exact hostname carries the `shim-policy` divergence?  
**Answer format:** hostname, lowercase.

**Task 02.** Recompute the observed specimen digest and compare the *first differing* software measurement with earlier matching observations. At what exact UTC instant did the measurement collector report the first divergence? Do not substitute the earlier file-write time.  
**Answer format:** `YYYY-MM-DDTHH:MM:SSZ`.

**Task 03.** Hash the observed policy specimen's actual **bytes**, reconcile the result with the offline TAR copy, the measurement derivation and the local FIM change. Which 64-character digest identifies the changed specimen? A copied claim alone is not a valid investigative method.  
**Answer format:** exactly 64 lowercase hexadecimal characters.

## Stage II — Reconstruct authentication, authorization and the write

**Task 04.** Separate an approved decoy deployment from the maintenance action affecting the compromised-integrity gateway. Correlate the applicable ticket interval, change owner, deployment approval state and local write observation. Which ticket remained **unapproved**?  
**Answer format:** `CHG-NNN`.

**Task 05.** Trace a service principal across host authentication, privileged session creation, audit write and process lineage. Which exact authentication reference **joins the sudo execution to the file write**? An account name alone cannot identify the human operator.  
**Answer format:** `AUTH-NNN`.

**Task 06.** Using the Linux audit serial, privilege reference, process parent/child relationship and the derived SQLite event, identify the **actual recorded writer process**, not its `sudo` parent or the later integrity checker.  
**Answer format:** decimal PID.

**Task 07.** Inspect both the simplified audit table and the raw auditd-style source. Between the policy file's `open` and `write` events, which **two consecutive audit serials are absent** from the supplied collection? Do not infer that absence means the records were erased.  
**Answer format:** `NNNN-NNNN`, ascending.

**Task 08.** Cross-check the denied ticket, deployment-signature status, build-system entries and the administrative approval trail. Which package was **unsigned, rejected and targeted to the affected gateway**? Distinguish it from a signed but pending package and an unrelated approved package.  
**Answer format:** `PKG-NNN`.

## Stage III — Investigate local execution and potential persistence

**Task 09.** From the scoped Linux TAR, follow the systemd `multi-user.target.wants` link to its underlying unit, compare the service inventory, then identify the locally observed process family. Which exact unit name is implicated? The link is evidence of enablement, **not** proof of persistence across a verified reboot.  
**Answer format:** unit basename including `.service`.

**Task 10.** Obtain the **unit file bytes from inside the TAR**, calculate their SHA-256, and reconcile the value with the standalone service specimen, FIM record and SQLite inventory. Which digest identifies that exact file?  
**Answer format:** 64 lowercase hexadecimal characters.

**Task 11.** Work backwards from the gateway's recorded TCP socket through the sampled `curl` process and its parent process. Which PID is the **direct parent of the client**, rather than the socket client itself? Cross-check its command line against the systemd unit.  
**Answer format:** decimal PID.

## Stage IV — Separate packets, sessions and claims

**Task 12.** Join the socket's process PID to the SQL flow's five-tuple and verify the TCP handshake using the edge-sensor PCAP. Reject the lookalike UDP record with the same destination and the unrelated client-port sample. What source port identifies the gateway's TCP connection?  
**Answer format:** decimal port.

**Task 13.** Decode the **actual TCP payload lengths** in the edge capture for that specific outbound five-tuple. Count application-like bytes only, excluding layer-2/3/4 headers, SYN/ACK-only packets, reverse traffic and the UDP decoy. What is the observed byte total?  
**Answer format:** decimal number of bytes. Never claim this total proves exfiltration.

## Stage V — Normalize time and state what is knowable

**Task 14.** Identify the bastion's relevant VPN `session-accepted` entry by matching it to the gateway's earlier authenticated maintenance session. Apply **only that VPN source's** clock calibration, using `recorded UTC = actual UTC + offset`. What is its normalized UTC timestamp? Do not apply the gateway journal's offset to VPN events.  
**Answer format:** `YYYY-MM-DDTHH:MM:SSZ`.

**Task 15.** Find the unique `file-write` row inside the **read-only derived SQL cache** that agrees simultaneously with the path, privilege reference, process ancestry and raw audit observation. What is the row's `event_id`?  
**Answer format:** `EVT-NNNN`.

**Task 16.** Inventory the missing **independently verifiable trust-anchor acquisition** needed to substantiate any claim about a real TPM-rooted compromise. What exact `collection_status` is recorded for the TPM2 quote?  
**Answer format:** the exact status token from the acquisition inventory.

**Task 17.** After checking the policy hashes, local software measurement method, missing hardware acquisition and the scope of the offline file-level export, has a **hardware-root-of-trust compromise** been proven by the provided collection?  
**Answer format:** `ESTABLISHED` or `NOT ESTABLISHED`. This is a proof-standard decision, not a speculation about motive.

## Stage VI — Hard investigation: privileged identity and competing changes

**Task 18.** The privileged write follows a service-account authentication reference, but several token records are unrelated or represent refresh/expiry activity. Join the gateway's *writer reference* to the bastion/IdP session and select the **issued** identity-token event for that exact session. What is its identity audit `event_id`? Do not treat that service token as attribution to a named person.  
**Answer format:** `IDP-NNNN`.

**Task 19.** A local maintenance claim says the change was approved. Independently examine the change-ticket state, build-system package provenance and change-control events. Which **specific security-rejection event** occurred immediately before the unsigned package was rejected/quarantined? Exclude the pending check and subsequent quarantine event.  
**Answer format:** `CTRL-NNNN`.

## Stage VII — Hard investigation: integrity and traffic evidence

**Task 20.** Reconstruct the policy mutation from the audited writer process through the offline specimen bytes, reported measurement and local FIM timeline. Identify the **first FIM event marking the modified policy**, not the baseline, later service-unit specimen or routine APT change.  
**Answer format:** `FIM-NNNN`.

**Task 21.** The firewall stream has numerous decoy allows and a UDP lookalike. Rebuild the TCP five-tuple from the client PID/socket, the SQL flow and PCAP handshake, then identify the **matching allowed edge-firewall decision**. Which decision event is it?  
**Answer format:** `FW-NNNN`.

**Task 22.** The summarized flow attributes more outbound bytes to the relevant TCP connection than the partial edge PCAP actually contains. Compute the **numeric difference between the two reported measures** after protocol- and direction-correct filtering. This quantity is an *observation gap between data products*, not proof that the difference was transmitted or stolen.  
**Answer format:** decimal byte difference.

**Task 23.** Walk backward from the write-process privilege reference through the bastion session history and the corresponding IdP token. Which bastion **command-channel-open** session ID is associated with that reference? Distinguish it from session acceptance, the later heartbeat and configuration-write observations. A matching reference does not by itself prove who used the channel.  
**Answer format:** `SES-NNN`.

## Stage VIII — Hard investigation: persistence and recovery limitations

**Task 24.** Inspect the scoped systemd files in the TAR, verify the service's FIM event and compare the unit lifecycle with its local process entry. What is the **file-inventory event ID** that specifically records the enablement symlink? Distinguish file-level enablement from local claims that a service started.  
**Answer format:** `UNIT-NNNN`.

**Task 25.** Compare both sampled gateway boot IDs in the SQLite inventory with the service's reported enablement/start and later collection time. Which **later boot inventory sample ID** shows the same, *unverified*, boot identity? Explain why this is insufficient to prove service execution after a trusted reboot.  
**Answer format:** `BOOT-NN`.

## Final senior incident response exercise — instructor reviewed, not an exact flag

Use `questions/INVESTIGATION.md` to prepare a forensic case report with an evidence-cited timeline and a 400–700 word executive memorandum. Explicitly answer **WHAT, WHY, FOR WHAT PURPOSE (if provable), HOW, WHEN, WHERE and by WHOM (if actually attributable)**. Separate observations from hypotheses; challenge the local maintenance explanation, account for source-clock uncertainty and missing collection windows, and propose a defensible **NO-GO / CONDITIONAL-GO / GO** restoration plan with independent validation criteria.

You receive no credit for invented actor identity, invented exfiltration, invented firmware compromise, claims of independently verified sources, or treating the derived SQL cache as new ground truth.

**The 25 exact-value tasks are intended for HTB-style grading. The 30-question research extension is independently human-assessed. Neither the task sheet nor this ZIP contains the instructor answers.**
