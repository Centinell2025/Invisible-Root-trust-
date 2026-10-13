# HTB Sherlock release gate
- [x] Fictional defensive-only scenario
- [x] Deterministic evidence generator
- [x] Student investigation worksheet
- [x] SHA-256 manifest generator
- [x] Evidence integrity and consistency validator (CI passed with 97 tests on 2026-10-12)
- [x] Student ZIP packaging script (CI builds and validates its contents)
- [x] CI workflow definition (verified successful; artifact published from successful push run)
- [ ] Trusted firmware/TPM, memory or full disk acquisitions (current files are realistic **simulations**; TCP partial capture and TAR file triage are validated)
- [x] Limited benign background noise, SQLite event cache and time-offset reconciliation logic (error bounds still unavailable)
- [x] 25 exact-answer HTB tasks, eight requiring multi-source correlation; all 25 reproduced in a confidential, author-verified 25-answer YAML and writeup; independent cold solve remains pending (30 additional questions are research extension)
- [x] Confidential instructor walkthrough, answer YAML, demonstrations and evidence-to-answer mapping prepared outside public repository
- [ ] Independent cold-solve playtest with difficulty measurement
- [ ] Confirm current HTB submission requirements, licensing and approval
Target difficulty is **Hard**. Do not advertise acceptance or independent Hard validation before completion of blind-solve evaluation and HTB review.
