"""Evidence grouping: correlated observations are counted once.

Findings are grouped by evidence *family* and, inside a family, by *independent group*. Within a group only the
strongest indicator of each distinct id counts, so several correlated URL properties (HTTP + raw IP + lookalike +
query parameters) form one 'destination anomaly' instead of several independent pieces of evidence.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..models import CONF_ORDER, SEVERITY_ORDER, Confidence, Evidence, Family, Severity

_BY_ORDER = {v: k for k, v in SEVERITY_ORDER.items()}


def effective_severity(e: Evidence) -> Severity:
    """Low-confidence findings never count above 'weak'."""
    if e.confidence is Confidence.LOW and SEVERITY_ORDER[e.severity] > SEVERITY_ORDER[Severity.WEAK]:
        return Severity.WEAK
    return e.severity


@dataclass
class EvidenceGroup:
    family: Family
    strength: Severity
    indicator_ids: list[str] = field(default_factory=list)
    subgroups: dict[str, dict] = field(default_factory=dict)
    layers: list[str] = field(default_factory=list)
    bumped: bool = False
    summary: str = ""


def group_evidence(findings: list[Evidence], *, bump_threshold: int = 3) -> list[EvidenceGroup]:
    fam: dict[Family, dict[str, dict[str, Severity]]] = {}
    layers: dict[Family, set[str]] = {}
    for e in findings:
        sub = fam.setdefault(e.family, {}).setdefault(e.independent_group, {})
        sev = effective_severity(e)
        if e.indicator_id not in sub or SEVERITY_ORDER[sev] > SEVERITY_ORDER[sub[e.indicator_id]]:
            sub[e.indicator_id] = sev
        layers.setdefault(e.family, set()).add(e.layer)
    groups: list[EvidenceGroup] = []
    for family, subs in fam.items():
        sub_out: dict[str, dict] = {}
        fam_strength = Severity.INFO
        bumped_any = False
        for name, ind in subs.items():
            smax = max(ind.values(), key=lambda s: SEVERITY_ORDER[s])
            n_weak_plus = sum(1 for s in ind.values() if SEVERITY_ORDER[s] >= SEVERITY_ORDER[Severity.WEAK])
            bumped = smax is Severity.WEAK and n_weak_plus >= bump_threshold
            strength = Severity.MEANINGFUL if bumped else smax
            bumped_any = bumped_any or bumped
            sub_out[name] = {"indicators": sorted(ind), "strength": strength.value, "bumped": bumped}
            if SEVERITY_ORDER[strength] > SEVERITY_ORDER[fam_strength]:
                fam_strength = strength
        ids = sorted({i for ind in subs.values() for i in ind})
        note = " (raised from weak: several distinct weak indicators in one group)" if bumped_any else ""
        groups.append(EvidenceGroup(family, fam_strength, ids, sub_out, sorted(layers[family]), bumped_any,
                                    f"{family.value}: {fam_strength.value}{note}"))
    groups.sort(key=lambda g: (-SEVERITY_ORDER[g.strength], g.family.value))
    return groups
