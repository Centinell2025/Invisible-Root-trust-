# Release QA protocol
1. Run `python3 tools/run_full_case.py`.
2. Run `python3 -m unittest discover -s tests -v`.
3. Run `python3 tools/validate_realistic.py` and `python3 tools/scientific_quality_gate.py` for deterministic structural and evidence validation.
4. Run `python3 tools/build_submission.py`.
5. Inspect ZIP members and contents manually to ensure no grader, solutions, or instructor-only files.
6. Have an independent investigator solve from the ZIP without access to this repository.
7. Confirm each graded prompt has exactly one answer and trace it to artifact/offset/event ID.
8. Record playtest duration, misleading clues, contradictions and required changes.
9. Do not submit until the release checklist is fully satisfied.

**Caution:** This repository is public; historic commits and generators can reveal the case design. The private grading key and human cold-solve evidence do not exist yet in the repository. Use only the reviewed student ZIP for a blind test. Current artifacts remain simulated.
