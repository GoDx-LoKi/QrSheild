"""Self-contained offline HTML report generator.

All charts are rendered as inline SVG. No CDN, no external JavaScript.
The generated HTML is usable offline from any browser.
"""
from __future__ import annotations

import html
from pathlib import Path
from typing import Any

from qrshield_core.models import LEVEL_LABELS, AssessmentLevel


def _label(level: str | None) -> str:
    if level is None:
        return "—"
    try:
        return LEVEL_LABELS[AssessmentLevel(level)]
    except (ValueError, KeyError):
        return str(level)


def _pct(n: int | None, total: int) -> str:
    if n is None or total == 0:
        return "—"
    return f"{n} ({100 * n / total:.1f}%)"


def _h(text: Any) -> str:
    return html.escape(str(text))


COLOURS = [
    "#4f8ef7", "#f7924f", "#4fdb96", "#f74f7a", "#a04ff7",
    "#f7e94f", "#4fc3f7", "#f7a84f",
]

LEVEL_COLOURS = {
    "no_material_concern": "#22c55e",
    "needs_verification": "#f59e0b",
    "high_concern": "#ef4444",
    "harmful_corroborated": "#7c3aed",
    "not_assessed": "#6b7280",
}


def _bar_chart_svg(labels: list[str], values: list[int], colours: list[str] | None = None,
                   width: int = 560, bar_h: int = 28, gap: int = 8) -> str:
    if not labels:
        return "<p><em>No data.</em></p>"
    if colours is None:
        colours = [COLOURS[i % len(COLOURS)] for i in range(len(labels))]
    max_v = max(values) if values else 1
    chart_w = width - 160
    rows = []
    for i, (lbl, val, col) in enumerate(zip(labels, values, colours)):
        y = i * (bar_h + gap)
        bar_w = max(2, int(chart_w * val / max_v)) if max_v > 0 else 0
        rows.append(
            f'<g transform="translate(0,{y})">'
            f'<rect x="0" y="0" width="{bar_w}" height="{bar_h}" fill="{col}" rx="3"/>'
            f'<text x="{bar_w + 6}" y="{bar_h // 2 + 5}" font-size="12" fill="#e2e8f0">{_h(val)}</text>'
            f'<text x="-4" y="{bar_h // 2 + 5}" text-anchor="end" font-size="12" fill="#94a3b8">{_h(lbl[:28])}</text>'
            f'</g>'
        )
    chart_h = len(labels) * (bar_h + gap)
    svg = (
        f'<svg viewBox="-160 0 {width} {chart_h}" width="{width}" height="{chart_h}" '
        f'xmlns="http://www.w3.org/2000/svg" style="overflow:visible">'
        + "".join(rows) + "</svg>"
    )
    return svg


def _pipeline_chart(pipeline: dict[str, int]) -> str:
    stages = [
        ("Images total", pipeline.get("images_total", 0)),
        ("QR decoded", pipeline.get("qr_decode_success", 0)),
        ("OCR ok", pipeline.get("ocr_ok", 0)),
        ("Context available", pipeline.get("context_available", 0)),
        ("Analysis complete", pipeline.get("analysis_complete", 0)),
    ]
    labels = [s[0] for s in stages]
    vals = [s[1] for s in stages]
    return _bar_chart_svg(labels, vals)


CSS = """
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0 }
body { font-family: system-ui, -apple-system, 'Segoe UI', sans-serif;
       background: #0f172a; color: #e2e8f0; line-height: 1.55; padding: 2rem; }
.page { max-width: 960px; margin: 0 auto; }
h1 { font-size: 1.8rem; font-weight: 700; color: #f8fafc; margin-bottom: .5rem; }
h2 { font-size: 1.25rem; color: #94a3b8; margin: 2rem 0 .75rem; border-bottom: 1px solid #1e293b; padding-bottom: .4rem; }
h3 { font-size: 1rem; color: #cbd5e1; margin: 1.25rem 0 .5rem; }
.meta { font-size: .8rem; color: #64748b; margin-bottom: 1.5rem; }
.cards { display: flex; flex-wrap: wrap; gap: 1rem; margin: 1rem 0; }
.card { background: #1e293b; border-radius: .75rem; padding: 1.25rem 1.5rem;
        flex: 1 1 180px; min-width: 150px; }
.card .num { font-size: 2rem; font-weight: 700; color: #4f8ef7; }
.card .lbl { font-size: .8rem; color: #94a3b8; margin-top: .25rem; }
table { width: 100%; border-collapse: collapse; margin: .75rem 0; font-size: .85rem; }
th { text-align: left; padding: .5rem .75rem; background: #1e293b; color: #94a3b8;
     border-bottom: 1px solid #334155; font-weight: 600; }
td { padding: .45rem .75rem; border-bottom: 1px solid #1e293b; color: #cbd5e1; }
tr:hover td { background: #1e293b88; }
.level-no_material_concern { color: #22c55e; font-weight: 600; }
.level-needs_verification { color: #f59e0b; font-weight: 600; }
.level-high_concern { color: #ef4444; font-weight: 600; }
.level-harmful_corroborated { color: #a855f7; font-weight: 600; }
.ok { color: #22c55e; }
.warn { color: #f59e0b; }
.err { color: #ef4444; }
.chart-box { background: #1e293b; border-radius: .75rem; padding: 1.5rem; margin: .75rem 0; }
.scope { background: #1e293b; border-left: 4px solid #4f8ef7; padding: .75rem 1rem;
         border-radius: 0 .5rem .5rem 0; font-size: .85rem; color: #94a3b8; margin: 1rem 0; }
code { background: #334155; border-radius: .25rem; padding: .1em .35em; font-size: .85em; }
"""


def _page(title: str, body: str) -> str:
    return (
        "<!doctype html>\n<html lang=\"en\">\n"
        f"<head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        f"<title>{_h(title)} \u00b7 QRShield Research</title>"
        f"<style>{CSS}</style></head>\n"
        f"<body><div class=\"page\">{body}</div></body></html>"
    )


def _cards(*items: tuple[str, Any]) -> str:
    return '<div class="cards">' + "".join(
        f'<div class="card"><div class="num">{_h(v)}</div><div class="lbl">{_h(l)}</div></div>'
        for l, v in items
    ) + "</div>"


def _table(headers: list[str], rows: list[list[Any]]) -> str:
    head = "<tr>" + "".join(f"<th>{_h(h)}</th>" for h in headers) + "</tr>"
    body = "".join(
        "<tr>" + "".join(f"<td>{_h(c)}</td>" for c in row) + "</tr>"
        for row in rows
    )
    return f"<table><thead>{head}</thead><tbody>{body}</tbody></table>"


def generate_base_html(
    run_manifest: dict[str, Any],
    results: list[dict[str, Any]],
    metrics: dict[str, Any],
) -> str:
    """Generate self-contained HTML for the base suite report."""
    run_id = run_manifest.get("run_id", "")
    p = metrics.get("pipeline", {})
    pt = metrics.get("payload_type", {})
    asmt = metrics.get("assessment", {})
    ind = metrics.get("indicators", {})
    div = metrics.get("diversity_and_clustering", {})
    fail = metrics.get("failures", {})

    body = (
        f'<h1>QRShield Research \u2014 Base Test</h1>'
        f'<div class="meta">Run <code>{_h(run_id)}</code> \u00b7 Dataset: '
        f'<code>{_h(run_manifest.get("dataset_root", ""))}</code> \u00b7 '
        f'Threat intelligence: <strong>disabled</strong></div>'
        f'<div class="scope">Threat intelligence was disabled for this run. '
        f'All OCR candidates were auto-accepted (no manual filtering). '
        f'Ground truth was loaded after predictions were frozen.</div>'
    )

    body += "<h2>Summary</h2>" + _cards(
        ("Total images", p.get("images_total", 0)),
        ("Evaluable", p.get("images_evaluable", 0)),
        ("Failures", p.get("images_failed", 0)),
        ("QR decoded", p.get("qr_decode_success", 0)),
        ("OCR ok", p.get("ocr_ok", 0)),
        ("Context incomplete", p.get("context_incomplete_count", 0)),
    )

    body += '<div class="chart-box"><h3>Pipeline stages</h3>' + _pipeline_chart(p) + "</div>"

    pt_dist = pt.get("predicted_distribution", {})
    if pt_dist:
        body += '<div class="chart-box"><h3>Payload type distribution (predicted syntax)</h3>'
        labels = list(pt_dist.keys())
        values = [pt_dist[k] for k in labels]
        body += _bar_chart_svg(labels, values) + "</div>"

    lvl_dist = asmt.get("level_distribution", {})
    if lvl_dist:
        body += '<div class="chart-box"><h3>Assessment level distribution</h3>'
        labels = list(lvl_dist.keys())
        values = [lvl_dist[k] for k in labels]
        colours = [LEVEL_COLOURS.get(l, "#4f8ef7") for l in labels]
        body += _bar_chart_svg(labels, values, colours) + "</div>"

    # Payload type classification: syntax vs purpose (P1 #4)
    enc = pt.get("encoded_syntax", {})
    purp = pt.get("scenario_purpose", {})
    n_eval = pt.get("evaluable_with_gt", 0)
    body += "<h2>Payload type classification (Encoded Syntax vs. Scenario Purpose)</h2>"
    body += _table(
        ["Measure", "Count / Rate"],
        [
            ["Evaluable with ground truth", n_eval],
            ["Encoded payload syntax agreement", f"{enc.get('agreement', pt.get('agreement', 0))} ({(enc.get('agreement_rate') or pt.get('agreement_rate') or 0) * 100:.2f}%)"],
            ["Scenario purpose vs. syntax agreement", f"{pt.get('agreement', 0)} ({(pt.get('agreement_rate') or 0) * 100:.2f}%)"],
            ["HTTP payment portal scenarios (encoded=url, purpose=payment)", purp.get("http_payment_portal_count", 0)],
            ["Purpose-aware classification agreement", f"{purp.get('purpose_aware_agreement', pt.get('agreement', 0))} ({(purp.get('purpose_aware_agreement_rate') or pt.get('agreement_rate') or 0) * 100:.2f}%)"],
        ]
    )

    # Assessment agreement: Adjudicated Ordinal vs Accepted-Set (P1 #6)
    n_asmt = asmt.get("evaluable_with_gt", 0)
    body += "<h2>Assessment agreement (Adjudicated Ordinal vs. Accepted-Set Compatibility)</h2>"
    body += _table(
        ["Metric", "Count / Rate", "95% Wilson CI", "95% Cluster-Bootstrap CI"],
        [
            [
                "Adjudicated 1-to-1 ordinal agreement",
                f"{asmt.get('adjudicated_ordinal_agreement', asmt.get('agreement', 0))} / {asmt.get('adjudicated_evaluable', n_asmt)} "
                f"({(asmt.get('adjudicated_ordinal_agreement_rate') if asmt.get('adjudicated_ordinal_agreement_rate') is not None else (asmt.get('agreement_rate') or 0)) * 100:.2f}%)",
                str(div.get("wilson_95_ci_adjudicated", "—")),
                str(div.get("cluster_bootstrap_95_ci_adjudicated", "—")),
            ],
            [
                "Accepted-set compatibility agreement",
                f"{asmt.get('accepted_set_agreement', asmt.get('agreement', 0))} / {n_asmt} "
                f"({(asmt.get('accepted_set_agreement_rate') if asmt.get('accepted_set_agreement_rate') is not None else (asmt.get('agreement_rate') or 0)) * 100:.2f}%)",
                str(div.get("wilson_95_ci_accepted_set", "—")),
                str(div.get("cluster_bootstrap_95_ci_accepted_set", "—")),
            ],
        ]
    )

    # Expected category vs predicted ordinal level cross-tabulation
    xtab = asmt.get("expected_category_vs_predicted_level", {})
    if xtab:
        body += "<h3>ScenarioForge category vs. predicted assessment level</h3>"
        lvl_cols = ["no_material_concern", "needs_verification", "high_concern", "harmful_corroborated"]
        body += _table(
            ["Expected Category", *lvl_cols, "Total"],
            [[cat, *[row.get(c, 0) for c in lvl_cols], sum(row.values())] for cat, row in xtab.items()]
        )

    # Indicator evaluation table (P0 #2)
    if ind:
        body += "<h2>Indicator-level evaluation</h2>"
        body += _table(
            ["Measure", "Value"],
            [
                ["Indicator-evaluable scenarios", ind.get("evaluable", 0)],
                ["Exact indicator-set match", f"{ind.get('exact_indicator_match', 0)} ({(ind.get('exact_indicator_match_rate') or 0) * 100:.2f}%)"],
                ["Missing key indicators", ind.get("missing_key_indicators", 0)],
                ["Unexpected indicators", ind.get("unexpected_indicators", 0)],
                ["ScenarioForge template tag contradictions", ind.get("semantic_tag_contradictions", 0)],
            ]
        )

    # Per-payload type table
    per_pt = asmt.get("per_payload_type", {})
    if per_pt:
        body += "<h3>Per payload type assessment</h3>"
        body += _table(
            ["Payload type", "Evaluable", "Adjudicated ordinal match", "Accepted-set match"],
            [
                [pt_name, v.get("total", 0), v.get("adjudicated_ordinal_agreement", v.get("agreement", 0)), v.get("accepted_set_agreement", v.get("agreement", 0))]
                for pt_name, v in per_pt.items()
            ]
        )

    body += "<h2>Failure analysis</h2>"
    body += _table(["Failure code", "Count"], list((fail.get("by_code") or {}).items()))

    body += "<h2>Per-image results (first 200)</h2>"
    subset = results[:200]
    body += _table(
        ["ID", "Evaluable", "QR", "OCR", "Payload type", "Assessment", "Confidence"],
        [
            [
                r.get("item_id", ""),
                "\u2713" if r.get("evaluable") else f"\u2717 {r.get('failure_code', '')}",
                "\u2713" if r.get("qr_decode_success") else "\u2717",
                r.get("ocr_status", ""),
                r.get("payload_type", "—"),
                _label(r.get("assessment_level")),
                r.get("assessment_confidence", "—"),
            ]
            for r in subset
        ]
    )

    return _page(f"Base Test \u2014 {run_id}", body)


def generate_counterfactual_html(
    run_manifest: dict[str, Any],
    results: list[dict[str, Any]],
    metrics: dict[str, Any],
) -> str:
    """Generate self-contained HTML for the counterfactual suite report."""
    run_id = run_manifest.get("run_id", "")
    s = metrics.get("summary", {})

    body = (
        f'<h1>QRShield Research \u2014 Counterfactual Test</h1>'
        f'<div class="meta">Run <code>{_h(run_id)}</code></div>'
    )

    body += "<h2>Directional summary (Rule Activation vs. Final Ordinal Level)</h2>" + _cards(
        ("Directional pairs", s.get("total_pairs", 0)),
        ("Evaluable pairs", s.get("evaluable_pairs", 0)),
        ("Indicator/rule changed", s.get("indicator_changed_pairs", 0)),
        ("Level moved (expected dir.)", s.get("correct_direction", 0)),
        ("Sub-threshold indicator change", s.get("sub_threshold_indicator_change_only", 0)),
        ("Opposite direction", s.get("opposite_direction", 0)),
    )

    direction_data = {
        "correct_direction": s.get("correct_direction", 0),
        "indistinguishable": s.get("indistinguishable", 0),
        "opposite_direction": s.get("opposite_direction", 0),
        "not_evaluable": s.get("not_evaluable", 0),
    }
    body += '<div class="chart-box"><h3>Directional response distribution</h3>'
    body += _bar_chart_svg(list(direction_data.keys()), list(direction_data.values()),
                           ["#22c55e", "#f59e0b", "#ef4444", "#6b7280"])
    body += "</div>"

    nc = metrics.get("negative_controls", {})
    body += "<h2>Negative controls (no_change)</h2>" + _table(
        ["Measure", "Count"],
        [
            ["Control pairs", nc.get("total_pairs", 0)],
            ["Evaluable controls", nc.get("evaluable_pairs", 0)],
            ["Assessment stable", nc.get("assessment_stable", 0)],
            ["Assessment changed", nc.get("assessment_changed", 0)],
            ["Assessment stability rate", f"{nc.get('assessment_stability_rate') * 100:.1f}%" if nc.get("assessment_stability_rate") is not None else "—"],
            ["Finding stable", nc.get("finding_stable", 0)],
            ["Finding stability rate", f"{nc.get('finding_stability_rate') * 100:.1f}%" if nc.get("finding_stability_rate") is not None else "—"],
        ],
    )

    pairs = metrics.get("pairs", [])
    body += "<h2>Pair results</h2>"
    body += _table(
        ["Pair", "Payload", "Changed factor", "Expected dir.", "Level A", "Level B", "Indicator changed", "Status"],
        [
            [
                p.get("pair_id", ""),
                p.get("payload_type", "—"),
                p.get("changed_factor", "—"),
                p.get("expected_direction", "—"),
                _label(p.get("level_a")),
                _label(p.get("level_b")),
                "Yes" if p.get("indicator_changed") else "No",
                p.get("status", "—"),
            ]
            for p in pairs
        ]
    )

    return _page(f"Counterfactual Test \u2014 {run_id}", body)


def generate_robustness_html(
    run_manifest: dict[str, Any],
    results: list[dict[str, Any]],
    metrics: dict[str, Any],
) -> str:
    """Generate self-contained HTML for the robustness suite report."""
    run_id = run_manifest.get("run_id", "")
    s = metrics.get("summary", {})

    body = (
        f'<h1>QRShield Research \u2014 Robustness Test</h1>'
        f'<div class="meta">Run <code>{_h(run_id)}</code></div>'
    )

    body += "<h2>Summary</h2>" + _cards(
        ("Total variants", s.get("total_variants", 0)),
        ("QR retained", f"{s.get('qr_retained', 0)} ({(s.get('qr_retention_rate') or 0) * 100:.1f}%)"),
        ("OCR retained", f"{s.get('ocr_retained', 0)} ({(s.get('ocr_retention_rate') or 0) * 100:.1f}%)"),
        ("Compared to base", s.get("assessment_compared", 0)),
        ("Retained (conditional)", f"{s.get('assessment_retained', 0)} ({(s.get('assessment_retention_rate') or 0) * 100:.1f}%)"),
        ("Retained (all decoded)", f"{s.get('all_decoded_retained', 0)} / {s.get('all_decoded_compared', 0)}"),
        ("OCR-failure downgrades", s.get("ocr_failure_assessment_drops", 0)),
        ("Missing base links", s.get("missing_base_links_count", 0)),
    )

    by_trans = metrics.get("by_transformation", {}) or metrics.get("by_variant", {})
    if by_trans:
        body += "<h2>By transformation</h2>"
        body += _table(
            ["Transformation", "Total", "QR ok", "OCR ok", "Compared", "Assessment retained"],
            [[t_id, v.get("total"), v.get("qr_ok", 0), v.get("ocr_ok", 0), v.get("assessment_compared", 0), v.get("assessment_retained", 0)]
             for t_id, v in by_trans.items()]
        )

    by_pt = metrics.get("by_payload_type", {})
    if by_pt:
        body += "<h2>By payload type</h2>"
        body += _table(
            ["Type", "Total", "QR ok", "OCR ok", "Compared", "Assessment retained"],
            [[pt, v.get("total"), v.get("qr_ok", 0), v.get("ocr_ok", 0), v.get("assessment_compared", 0), v.get("assessment_retained", 0)]
             for pt, v in by_pt.items()]
        )

    return _page(f"Robustness Test \u2014 {run_id}", body)


def generate_overall_html(
    run_manifest: dict[str, Any],
    suite_metrics: dict[str, dict[str, Any]],
) -> str:
    """Generate combined overall HTML for an 'all' run."""
    run_id = run_manifest.get("run_id", "")
    base_m = suite_metrics.get("base", {})
    cf_m = suite_metrics.get("counterfactual", {})
    rob_m = suite_metrics.get("robustness", {})

    base_p = base_m.get("pipeline", {})
    cf_s = cf_m.get("summary", {})
    rob_s = rob_m.get("summary", {})

    body = (
        f'<h1>QRShield Research \u2014 Overall Report</h1>'
        f'<div class="meta">Run <code>{_h(run_id)}</code> \u00b7 '
        f'Dataset: <code>{_h(run_manifest.get("dataset_root", ""))}</code></div>'
        f'<div class="scope">Threat intelligence: <strong>disabled</strong> \u00b7 '
        f'OCR: local provider, all candidates auto-accepted \u00b7 '
        f'Ground truth loaded after predictions were frozen.</div>'
    )

    body += "<h2>Dataset</h2>" + _cards(
        ("Base images", base_p.get("images_total", 0)),
        ("Counterfactual images", cf_s.get("total_images", 0)),
        ("Directional pairs", cf_s.get("total_pairs", 0)),
        ("Negative controls", cf_m.get("negative_controls", {}).get("total_pairs", 0)),
        ("Robustness variants", rob_s.get("total_variants", 0)),
        ("Grand total", (base_p.get("images_total", 0) + cf_s.get("total_images", 0) + rob_s.get("total_variants", 0))),
    )

    body += "<h2>1. Base Test</h2>"
    body += _cards(
        ("Evaluable", base_p.get("images_evaluable", 0)),
        ("Encoded syntax match", base_m.get("payload_type", {}).get("encoded_syntax", {}).get("agreement", base_m.get("payload_type", {}).get("agreement", 0))),
        ("Scenario purpose match", base_m.get("payload_type", {}).get("agreement", 0)),
        ("Adjudicated ordinal match", base_m.get("assessment", {}).get("adjudicated_ordinal_agreement", base_m.get("assessment", {}).get("agreement", 0))),
        ("Accepted-set match", base_m.get("assessment", {}).get("accepted_set_agreement", base_m.get("assessment", {}).get("agreement", 0))),
        ("Indicators evaluable", base_m.get("indicators", {}).get("evaluable", 0)),
    )

    body += "<h2>2. Counterfactual Test</h2>"
    body += _cards(
        ("Directional pairs", cf_s.get("total_pairs", 0)),
        ("Indicator changed", cf_s.get("indicator_changed_pairs", 0)),
        ("Level moved (expected)", cf_s.get("correct_direction", 0)),
        ("Opposite direction", cf_s.get("opposite_direction", 0)),
        ("Negative controls", cf_m.get("negative_controls", {}).get("total_pairs", 0)),
        ("Control stability", f"{(cf_m.get('negative_controls', {}).get('assessment_stability_rate') or 0) * 100:.1f}%"),
    )

    body += "<h2>3. Robustness Test</h2>"
    body += _cards(
        ("QR retention", f"{(rob_s.get('qr_retention_rate') or 0) * 100:.1f}%"),
        ("OCR retention", f"{(rob_s.get('ocr_retention_rate') or 0) * 100:.1f}%"),
        ("Compared to base", rob_s.get("assessment_compared", 0)),
        ("Retention (conditional)", f"{(rob_s.get('assessment_retention_rate') or 0) * 100:.1f}%"),
        ("Retention (all decoded)", f"{(rob_s.get('all_decoded_retention_rate') or 0) * 100:.1f}%"),
        ("OCR-failure downgrades", rob_s.get("ocr_failure_assessment_drops", 0)),
    )

    body += "<h2>4. Reproducibility</h2>"
    body += (
        f'<p><strong>QRShield version:</strong> {_h(run_manifest.get("qrshield_version", "—"))} \u00b7 '
        f'<strong>Dataset hash:</strong> <code>{_h(run_manifest.get("dataset_manifest_hash", "—"))}</code></p>'
    )

    return _page(f"Overall Report \u2014 {run_id}", body)


def write_html_report(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
