"""Machine-readable exports (JSON / CSV). Inputs are already redacted at the source."""
from __future__ import annotations

import csv
import io
import json
from typing import Any

FINDING_COLUMNS = ["analysis_id", "layer", "family", "indicator_id", "severity", "confidence", "source", "mismatch_type",
                   "title", "observation", "expected", "payload_field", "context_attribute", "provenance", "independent_group"]


def to_json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, indent=2, ensure_ascii=False, sort_keys=False).encode("utf-8")


def finding_rows(result: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for key in ("payload_findings", "context_findings", "action_findings", "threat_intel_findings"):
        for e in result.get(key, []):
            rows.append({"analysis_id": result["analysis_id"], **{c: e.get(c) for c in FINDING_COLUMNS if c != "analysis_id"}})
    return rows


def findings_csv(result: dict[str, Any]) -> bytes:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=FINDING_COLUMNS, extrasaction="ignore")
    w.writeheader()
    for r in finding_rows(result):
        w.writerow(r)
    return buf.getvalue().encode("utf-8")
