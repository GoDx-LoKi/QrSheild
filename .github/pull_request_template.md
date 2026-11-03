## Summary
Briefly describe the changes introduced in this pull request and link any related issue(s).

## Type of Change
- [ ] Bug fix (non-breaking fix to decoder, OCR, analyzer, UI, or CLI)
- [ ] Security rule / analyzer update (requires `docs/SPEC_TRACE.md` & `docs/TUNING_DISCLOSURE.md` update)
- [ ] Documentation or benchmark tooling improvement
- [ ] Test / verification harness improvement

## Verification & Safety Checklist
- [ ] **Non-Execution Invariant Preserved**: No payload is opened, fetched, resolved, dialed, or executed.
- [ ] **Zero Benchmark Leakage**: No rules, lexicons, or brand lists were tuned on `qrs_bench_ind/splits/test_locked/` (`N01`–`N40`, `T09`–`T28`).
- [ ] **Unit & Regression Tests Added**: New behavior is covered by tests under `source/tests/`.
- [ ] **Traceability Updated**: Ran `python3 tools/generate_spec_trace.py` (`0` orphan rules).
- [ ] **Full Verification Gate Passed**: Ran `make verify` locally and confirmed exit code `0`.
