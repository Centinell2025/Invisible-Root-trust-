# Release gate — Invisible Root of Trust
**Do not label this candidate HTB-ready solely because automated checks pass.**

## Automated gate
Run these commands from the repository root:
```bash
python3 tools/run_full_case.py
python3 -m unittest discover -s tests -v
python3 tools/build_submission.py
python3 tools/validate_release.py
```
The final command independently checks exact ZIP membership, hashes, manifest fidelity, and document bytes. It is not a substitute for a cold-solve playtest.

## Human gate
- [ ] An investigator completes a cold solve using only the student ZIP
- [ ] Each graded question has a unique artifact-supported answer
- [ ] Instructor walkthrough is kept outside the public repository
- [ ] No grading answers can be recovered from public Git history or distributed files
- [ ] Time-skew, network contradictions, and uncertainty are explained correctly
- [ ] All artifacts are explicitly described as synthetic
- [ ] Submission requirements confirmed with HTB

## Known limitations
Current memory specimen is not a real RAM capture. Current PCAP is a minimal UDP packet, not proof of the reported TCP flow. Simulated measured-boot records do not prove an actual UEFI compromise. These limitations must not be disguised as confirmed attacker activity.
