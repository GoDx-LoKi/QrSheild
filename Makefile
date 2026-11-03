export PYTHONDONTWRITEBYTECODE := 1

.PHONY: all verify clean-tree test mutation provenance spec-trace security independent-validation

all: verify

verify: clean-tree test mutation provenance spec-trace security independent-validation clean-tree
	@echo "=================================================================="
	@echo "QRShield 1.0.0: ALL VERIFICATION GATES PASSED (0)"
	@echo "=================================================================="

clean-tree:
	python3 tools/verify_clean_tree.py --clean

test:
	python3 tools/run_coverage.py

mutation:
	python3 tools/run_mutation.py

provenance:
	python3 tools/check_label_provenance.py

spec-trace:
	python3 tools/generate_spec_trace.py

security:
	python3 tools/run_static_security.py

independent-validation:
	python3 tools/independent_validation.py
