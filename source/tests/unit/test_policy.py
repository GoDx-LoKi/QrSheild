import itertools

import pytest

from qrshield_core.action.sensitivity import assess_action
from qrshield_core.analyzers import analyze_payload_security
from qrshield_core.decision.policy import TISummary, decide
from qrshield_core.evidence.grouping import EvidenceGroup, group_evidence
from qrshield_core.models import AssessmentLevel as L, Confidence, Family, Sensitivity as Sn, Severity as S, Source


def ev(reg, rid, **kw):
    return reg.make(rid, "obs", source=Source.QR_PAYLOAD, **kw)


def G(family, strength, ids=None):
    return EvidenceGroup(family, strength, indicator_ids=ids or [])


# ---------------------------------------------------------------- action sensitivity
@pytest.mark.parametrize("raw,ctype,level", [
    ("upi://pay?pa=a@b&pn=X", None, Sn.HIGH), ("https://a.example/menu", None, Sn.LOW), ("https://a.example/login", None, Sn.MEDIUM),
    ("https://a.example/login", "bank", Sn.HIGH), ("https://a.example/app.apk", None, Sn.HIGH), ("javascript:alert(1)", None, Sn.HIGH),
    ("WIFI:T:WPA;S:G;P:x;;", None, Sn.MEDIUM), ("BEGIN:VCARD\nFN:A\nEND:VCARD", None, Sn.MEDIUM), ("SMSTO:+910000000011:hi", None, Sn.MEDIUM),
    ("SMSTO:+910000000011:Send OTP now", None, Sn.HIGH), ("sgnl://linkdevice?uuid=1&pub_key=2", None, Sn.HIGH), ("tg://resolve?domain=x", None, Sn.LOW),
    ("customapp://open", None, Sn.MEDIUM), ("Table 12", None, Sn.LOW), ("tel:+910000000099", None, Sn.MEDIUM),
])
def test_action_sensitivity(norm, deps, raw, ctype, level):
    p = norm(raw)
    assert assess_action(p, None, analyze_payload_security(p, deps), [], ctype, deps).level is level


def test_wifi_becomes_high_only_when_context_conflicts(norm, deps, reg):
    p = norm("WIFI:T:nopass;S:x;;")
    conflict = [reg.make("CTX-006", "o", source=Source.ENTITY_MATCHER)]
    assert assess_action(p, None, [], conflict, None, deps).level is Sn.HIGH
    assert assess_action(p, None, [], [], None, deps).level is Sn.MEDIUM


# ---------------------------------------------------------------- grouping
def test_correlated_indicators_count_once(reg):
    f = [ev(reg, "URL-001"), ev(reg, "URL-018"), ev(reg, "URL-011"), ev(reg, "URL-006")]
    g = group_evidence(f)
    assert len(g) == 1 and g[0].family is Family.DESTINATION and g[0].strength is S.MEANINGFUL


def test_three_distinct_weak_indicators_in_one_group_are_raised_to_meaningful_only(reg):
    g = group_evidence([ev(reg, "URL-001"), ev(reg, "URL-006"), ev(reg, "URL-011")])
    assert g[0].strength is S.MEANINGFUL and g[0].bumped
    g2 = group_evidence([ev(reg, "URL-001"), ev(reg, "URL-006")])
    assert g2[0].strength is S.WEAK and not g2[0].bumped


def test_duplicate_indicator_ids_do_not_inflate(reg):
    g = group_evidence([ev(reg, "URL-001", payload_field=f"body.url[{i}]") for i in range(5)])
    assert g[0].strength is S.WEAK and g[0].indicator_ids == ["URL-001"]


def test_low_confidence_findings_never_count_above_weak(reg):
    g = group_evidence([ev(reg, "CTX-002", confidence=Confidence.LOW)])
    assert g[0].strength is S.WEAK


# ---------------------------------------------------------------- decision policy
def d(groups, sens=Sn.MEDIUM, ti=None, **kw):
    kw = {"context_confidence": Confidence.HIGH, "context_needed": True, "parse_ok": True, **kw}
    return decide(groups, sens, ti, **kw)


def test_no_evidence_is_no_material_concern():
    assert d([]).level is L.NO_MATERIAL_CONCERN


def test_single_weak_never_escalates_even_with_high_sensitivity():
    assert d([G(Family.DESTINATION, S.WEAK)], Sn.HIGH).level is L.NO_MATERIAL_CONCERN


def test_two_weak_families_need_verification():
    assert d([G(Family.DESTINATION, S.WEAK), G(Family.IDENTITY, S.WEAK)]).level is L.NEEDS_VERIFICATION


def test_single_meaningful_mismatch_needs_verification_even_with_high_sensitivity():
    assert d([G(Family.IDENTITY, S.MEANINGFUL)], Sn.HIGH).level is L.NEEDS_VERIFICATION


def test_two_meaningful_families_plus_high_sensitivity_is_high_concern():
    assert d([G(Family.IDENTITY, S.MEANINGFUL), G(Family.DESTINATION, S.MEANINGFUL)], Sn.HIGH).level is L.HIGH_CONCERN
    assert d([G(Family.IDENTITY, S.MEANINGFUL), G(Family.DESTINATION, S.MEANINGFUL)], Sn.MEDIUM).level is L.NEEDS_VERIFICATION


def test_three_families_with_at_least_one_meaningful_is_high_concern():
    assert d([G(Family.IDENTITY, S.MEANINGFUL), G(Family.DESTINATION, S.WEAK), G(Family.TRANSACTION, S.WEAK)], Sn.LOW).level is L.HIGH_CONCERN
    assert d([G(Family.IDENTITY, S.WEAK), G(Family.DESTINATION, S.WEAK), G(Family.TRANSACTION, S.WEAK)], Sn.LOW).level is L.NEEDS_VERIFICATION


def test_strong_plus_high_sensitivity_is_high_concern_strong_alone_is_not():
    assert d([G(Family.COMMUNICATION, S.STRONG)], Sn.HIGH).level is L.HIGH_CONCERN
    assert d([G(Family.COMMUNICATION, S.STRONG), G(Family.DESTINATION, S.WEAK)], Sn.LOW).level is L.HIGH_CONCERN
    assert d([G(Family.COMMUNICATION, S.STRONG)], Sn.MEDIUM).level is L.NEEDS_VERIFICATION


def test_action_and_external_groups_are_not_anomalies():
    assert d([G(Family.ACTION, S.STRONG), G(Family.EXTERNAL_CORROBORATION, S.STRONG)], Sn.HIGH).level is L.NO_MATERIAL_CONCERN


def test_harmful_requires_external_corroboration_and_local_high_concern():
    high = [G(Family.IDENTITY, S.MEANINGFUL), G(Family.DESTINATION, S.MEANINGFUL)]
    assert d(high, Sn.HIGH, TISummary(queried=True, confirmed=True)).level is L.HARMFUL_CORROBORATED
    assert d(high, Sn.HIGH).level is L.HIGH_CONCERN                                               # same local evidence, no external
    assert d([G(Family.IDENTITY, S.MEANINGFUL)], Sn.HIGH, TISummary(queried=True, confirmed=True)).level is L.HIGH_CONCERN   # not harmful


def test_unavailable_or_clean_threat_intel_never_changes_level():
    base = [G(Family.IDENTITY, S.MEANINGFUL)]
    for ti in (None, TISummary(), TISummary(queried=True), TISummary(queried=False, statuses=["unavailable"])):
        assert d(base, Sn.MEDIUM, ti).level is L.NEEDS_VERIFICATION
        assert d([], Sn.MEDIUM, ti).level is L.NO_MATERIAL_CONCERN


def test_mixed_external_result_only_lifts_a_clean_assessment_to_verification():
    assert d([], Sn.LOW, TISummary(queried=True, suspicious=True)).level is L.NEEDS_VERIFICATION
    assert d([G(Family.IDENTITY, S.MEANINGFUL)], Sn.LOW, TISummary(queried=True, suspicious=True)).level is L.NEEDS_VERIFICATION


@pytest.mark.parametrize("fam,sev", list(itertools.product([f for f in Family if f not in (Family.ACTION, Family.EXTERNAL_CORROBORATION)], [S.WEAK, S.MEANINGFUL])))
def test_no_single_family_can_reach_harmful_without_external_evidence(fam, sev):
    for sens in Sn:
        assert d([G(fam, sev)], sens).level in (L.NO_MATERIAL_CONCERN, L.NEEDS_VERIFICATION)


def test_confidence_reflects_evidence_completeness_not_probability():
    assert d([], context_confidence=None).confidence is Confidence.LOW
    assert d([], context_confidence=Confidence.LOW).confidence is Confidence.LOW
    assert d([], context_confidence=Confidence.MEDIUM).confidence is Confidence.MEDIUM
    assert d([], context_confidence=Confidence.HIGH).confidence is Confidence.HIGH
    assert d([], context_confidence=Confidence.HIGH, parse_ok=False).confidence is Confidence.LOW
    assert d([], context_confidence=None, context_needed=False).confidence is Confidence.MEDIUM


def test_confidence_boost_on_strong_or_ti_confirmed_with_medium_context():
    # Medium context confidence + HIGH_CONCERN + strong indicator -> bumped to HIGH confidence
    res_strong = d([G(Family.COMMUNICATION, S.STRONG)], Sn.HIGH, context_confidence=Confidence.MEDIUM)
    assert res_strong.level is L.HIGH_CONCERN and res_strong.confidence is Confidence.HIGH
    # Medium context confidence + HIGH_CONCERN without strong indicator or TI -> stays MEDIUM confidence
    res_r2 = d([G(Family.IDENTITY, S.MEANINGFUL), G(Family.DESTINATION, S.MEANINGFUL)], Sn.HIGH, context_confidence=Confidence.MEDIUM)
    assert res_r2.level is L.HIGH_CONCERN and res_r2.confidence is Confidence.MEDIUM
    # Medium context confidence + NEEDS_VERIFICATION + strong indicator -> stays MEDIUM confidence (since level < HIGH_CONCERN)
    res_nv = d([G(Family.COMMUNICATION, S.STRONG)], Sn.MEDIUM, context_confidence=Confidence.MEDIUM)
    assert res_nv.level is L.NEEDS_VERIFICATION and res_nv.confidence is Confidence.MEDIUM
    # Low context confidence + HIGH_CONCERN + strong indicator -> stays LOW confidence
    res_low = d([G(Family.COMMUNICATION, S.STRONG)], Sn.HIGH, context_confidence=Confidence.LOW)
    assert res_low.level is L.HIGH_CONCERN and res_low.confidence is Confidence.LOW


def test_calibrated_r0_to_r0e_and_context_gates():
    # R0: PAY-002 weak + HIGH sensitivity + context_ready -> NEEDS_VERIFICATION
    assert d([G(Family.TRANSACTION, S.WEAK, ["PAY-002"])], Sn.HIGH).level is L.NEEDS_VERIFICATION
    # R0 disabled when context_confidence is LOW or parse_ok is False
    assert d([G(Family.TRANSACTION, S.WEAK, ["PAY-002"])], Sn.HIGH, context_confidence=Confidence.LOW).level is L.NO_MATERIAL_CONCERN
    assert d([G(Family.TRANSACTION, S.WEAK, ["PAY-002"])], Sn.HIGH, parse_ok=False).level is L.NO_MATERIAL_CONCERN
    # R0 active when context_needed=False even if context_confidence=None
    assert d([G(Family.TRANSACTION, S.WEAK, ["PAY-002"])], Sn.HIGH, context_needed=False, context_confidence=None).level is L.NEEDS_VERIFICATION

    # R0a and R0b: DL-002 weak on HIGH and MEDIUM sensitivity
    assert d([G(Family.APPLICATION, S.WEAK, ["DL-002"])], Sn.HIGH).level is L.NEEDS_VERIFICATION
    assert d([G(Family.APPLICATION, S.WEAK, ["DL-002"])], Sn.MEDIUM).level is L.NEEDS_VERIFICATION
    assert d([G(Family.APPLICATION, S.WEAK, ["DL-002"])], Sn.LOW).level is L.NO_MATERIAL_CONCERN

    # R0c: WIFI-001 weak on MEDIUM sensitivity
    assert d([G(Family.NETWORK, S.WEAK, ["WIFI-001"])], Sn.MEDIUM).level is L.NEEDS_VERIFICATION
    assert d([G(Family.NETWORK, S.WEAK, ["WIFI-001"])], Sn.LOW).level is L.NO_MATERIAL_CONCERN

    # R0d: URL-003 discarded when ocr_status == "no_text" and context_confidence is None
    assert d(
        [G(Family.DESTINATION, S.WEAK, ["URL-003"])], Sn.LOW,
        has_org_context=False, ocr_status="no_text", context_confidence=None,
    ).level is L.NO_MATERIAL_CONCERN
    assert d(
        [G(Family.DESTINATION, S.WEAK, ["URL-003"])], Sn.LOW,
        has_org_context=False, ocr_status="ok", context_confidence=None,
    ).level is L.NEEDS_VERIFICATION
    assert d(
        [G(Family.DESTINATION, S.WEAK, ["URL-003"])], Sn.LOW,
        has_org_context=False, ocr_status="no_text", context_confidence=Confidence.LOW,
    ).level is L.NEEDS_VERIFICATION
    # R0d disabled when parse_ok is False
    assert d(
        [G(Family.DESTINATION, S.WEAK, ["URL-011"])], Sn.LOW,
        has_org_context=False, parse_ok=False,
    ).level is L.NO_MATERIAL_CONCERN

    # R0e: email with ocr_status == "no_text"
    assert d([], Sn.LOW, ocr_status="no_text", payload_type="email").level is L.NEEDS_VERIFICATION
    assert d([], Sn.LOW, ocr_status="no_text", payload_type="email", parse_ok=False).level is L.NO_MATERIAL_CONCERN


def test_policy_trace_explains_the_decision():
    r = d([G(Family.IDENTITY, S.MEANINGFUL), G(Family.DESTINATION, S.MEANINGFUL)], Sn.HIGH)
    assert r.trace and r.trace[0].startswith("R2") and r.basis["independent_anomaly_families"] == 2
