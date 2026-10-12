# Release QA protocol
1. Run `python3 tools/run_full_case.py`.
2. Run `python3 -m unittest discover -s tests -v`.
3. Run `python3 tools/grade_case.py --verify` (internal only).
4. Run `python3 tools/build_submission.py`.
5. Inspect ZIP members and contents manually to ensure no grader, solutions, or instructor-only files.
6. Have an independent investigator solve from the ZIP without access to this repository.
7. Confirm each graded prompt has exactly one answer and trace it to artifact/offset/event ID.
8. Record playtest duration, misleading clues, contradictions and required changes.
9. Do not submit until the release checklist is fully satisfied.

**Caution:** The repository is public. The grader source exposes answer derivation and therefore should be moved to a private instructor repository before publishing a final student-facing challenge. Current artifacts remain illustrative.
