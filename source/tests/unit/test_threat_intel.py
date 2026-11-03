import httpx
import pytest

from qrshield_core.models import ThreatIntelStatus as T
from qrshield_core.normalizer.normalize import normalize
from qrshield_core.threat_intel.base import MockThreatIntelProvider, ResultCache, ThreatIntelPolicy, classify_stats
from qrshield_core.threat_intel.service import ThreatIntelService, candidate_urls, to_evidence
from qrshield_core.threat_intel.virustotal import VirusTotalProvider


def report(m, s=0, h=60, u=10):
    return {"data": {"attributes": {"last_analysis_stats": {"malicious": m, "suspicious": s, "harmless": h, "undetected": u}}}}


def vt(handler, **kw):
    seen = []

    def wrapped(req):
        seen.append(req)
        return handler(req)
    p = VirusTotalProvider("KEY123", client=httpx.Client(transport=httpx.MockTransport(wrapped)), **kw)
    p.seen = seen
    return p


@pytest.mark.parametrize("stats,status", [
    ({"malicious": 7}, T.CONFIRMED_MALICIOUS_EVIDENCE), ({"malicious": 3}, T.CONFIRMED_MALICIOUS_EVIDENCE), ({"malicious": 1}, T.SUSPICIOUS_MIXED),
    ({"suspicious": 2}, T.SUSPICIOUS_MIXED), ({"harmless": 60, "undetected": 10}, T.NO_KNOWN_MALICIOUS_REPORT), ({}, T.NO_RESULT),
])
def test_stats_classification_one_detection_is_never_malicious(stats, status):
    assert classify_stats(stats, 3) is status


@pytest.mark.parametrize("code,status", [(404, T.NO_RESULT), (401, T.AUTH_FAILURE), (403, T.AUTH_FAILURE), (429, T.RATE_LIMITED), (500, T.UNAVAILABLE), (503, T.UNAVAILABLE)])
def test_vt_http_statuses_map_to_distinct_non_verdict_states(code, status):
    assert vt(lambda r: httpx.Response(code, json={})).lookup("https://a.example/").status is status


def test_vt_success_paths():
    assert vt(lambda r: httpx.Response(200, json=report(7))).lookup("https://a.example/").status is T.CONFIRMED_MALICIOUS_EVIDENCE
    assert vt(lambda r: httpx.Response(200, json=report(0))).lookup("https://a.example/").status is T.NO_KNOWN_MALICIOUS_REPORT


def test_vt_failures_are_unavailable_not_malicious():
    def boom(r): raise httpx.ConnectError("down")
    def slow(r): raise httpx.ReadTimeout("slow")
    assert vt(boom).lookup("https://a.example/").status is T.UNAVAILABLE and "timed out" in vt(slow).lookup("https://a.example/").message
    assert vt(lambda r: httpx.Response(200, json={"oops": 1})).lookup("https://a.example/").status is T.UNAVAILABLE      # malformed body
    assert vt(lambda r: httpx.Response(200, content=b"<html>")).lookup("https://a.example/").status is T.UNAVAILABLE      # not JSON


def test_vt_without_key_makes_no_request():
    p = VirusTotalProvider("")
    r = p.lookup("https://a.example/")
    assert r.status is T.UNAVAILABLE and "VIRUSTOTAL_API_KEY" in r.message and p.configured()[0] is False


def test_vt_contacts_only_virustotal_with_key_in_header_only():
    p = vt(lambda r: httpx.Response(200, json=report(0)))
    p.lookup("https://a.example/path")
    req = p.seen[0]
    assert req.url.host == "www.virustotal.com" and req.headers["x-apikey"] == "KEY123" and "KEY123" not in str(req.url)
    assert req.method == "GET" and req.url.path.startswith("/api/v3/urls/")


def test_vt_scan_is_explicit_post_then_poll():
    calls = []

    def h(req):
        calls.append((req.method, req.url.path))
        if req.method == "POST":
            return httpx.Response(200, json={"data": {"id": "ana-1"}})
        return httpx.Response(200, json={"data": {"attributes": {"status": "completed", "stats": {"malicious": 5, "harmless": 50}}}})
    r = vt(h).submit_scan("https://a.example/")
    assert r.status is T.CONFIRMED_MALICIOUS_EVIDENCE and r.query_type == "scan" and calls[0][0] == "POST"
    pending = vt(lambda q: httpx.Response(200, json={"data": {"id": "x", "attributes": {"status": "queued", "stats": {}}}})).submit_scan("https://a.example/")
    assert pending.status is T.NO_RESULT


def test_vt_cache_prevents_repeat_requests(tmp_path):
    p = vt(lambda r: httpx.Response(200, json=report(0)), cache=ResultCache(tmp_path))
    first, second = p.lookup("https://a.example/x"), p.lookup("https://a.example/x")
    assert not first.cached and second.cached and len(p.seen) == 1
    assert list(tmp_path.glob("*.json")) and "a.example" not in "".join(f.read_text() for f in tmp_path.glob("*.json")).split('"url"')[0]


# ---------------------------------------------------------------- privacy gate
@pytest.mark.parametrize("url,allowed", [
    ("https://abcshop.example/menu", True), ("http://abcshop.example/x", True),
    ("http://localhost/x", False), ("http://10.0.0.5/x", False), ("http://169.254.169.254/latest/meta-data", False), ("http://intranet/x", False),
    ("http://203.0.113.45/pay", False), ("https://user:pw@evil.example/", False), ("ftp://a.example/f", False), ("javascript:alert(1)", False), ("bit.ly/abc", False),
    ("https://a.example/?token=abc", False), ("https://a.example/?email=a@b.example", False), ("https://a.example/o?id=1234567890123", False),
])
def test_privacy_gate(ref, url, allowed):
    cands = candidate_urls(normalize(url, ref))            # URLs without a host are never even candidates for external lookup
    sent = bool(cands) and ThreatIntelPolicy(ref).check(cands[0].parsed)[0]
    assert sent is allowed


def test_override_lifts_soft_blocks_only(ref):
    pol = ThreatIntelPolicy(ref)
    soft = candidate_urls(normalize("https://a.example/?token=abc", ref))[0].parsed
    hard = candidate_urls(normalize("http://localhost/x", ref))[0].parsed
    userinfo = candidate_urls(normalize("https://u:p@a.example/", ref))[0].parsed
    assert pol.check(soft, override=True)[0] and not pol.check(hard, override=True)[0] and not pol.check(userinfo, override=True)[0]


def test_payment_auxiliary_url_is_a_soft_block(ref):
    c = candidate_urls(normalize("upi://pay?pa=a@b&pn=X&url=https://pay.example/r", ref))[0]
    pol = ThreatIntelPolicy(ref)
    assert c.from_payment and not pol.check(c.parsed, from_payment=True)[0] and pol.check(c.parsed, from_payment=True, override=True)[0]


# ---------------------------------------------------------------- service
def test_service_modes_and_states(ref, reg):
    p = normalize("https://abcshop.example/x", ref)
    pol = ThreatIntelPolicy(ref)
    mock = MockThreatIntelProvider(default={"malicious": 7, "harmless": 50})
    svc = ThreatIntelService(mock, pol)
    off = svc.query(p, mode="off")
    assert off[0].status is T.NOT_QUERIED and not mock.calls                       # nothing sent unless requested
    assert svc.query(p, mode="lookup")[0].status is T.CONFIRMED_MALICIOUS_EVIDENCE and mock.calls == [("lookup", "https://abcshop.example/x")]
    assert svc.query(p, mode="scan")[0].query_type == "scan"
    none = ThreatIntelService(None, pol).query(p, mode="lookup")[0]
    assert none.status is T.UNAVAILABLE and "local analysis only" in none.message
    nokey = ThreatIntelService(VirusTotalProvider(""), pol).query(p, mode="lookup")[0]
    assert nokey.status is T.UNAVAILABLE
    blocked = ThreatIntelService(mock, pol).query(normalize("http://localhost/x", ref), mode="lookup")[0]
    assert blocked.status is T.NOT_QUERIED and len(mock.calls) == 2                    # private host never reached the provider
    assert {e.indicator_id for e in to_evidence(svc.query(p, mode="lookup"), reg)} == {"TI-001"}


def test_every_status_has_a_rule(reg):
    from qrshield_core.threat_intel.base import ThreatIntelResult
    for s in T:
        e = to_evidence([ThreatIntelResult("p", "lookup", "u", s, "m")], reg)[0]
        assert e.family.value == "EXTERNAL_CORROBORATION" and e.layer == "external"
