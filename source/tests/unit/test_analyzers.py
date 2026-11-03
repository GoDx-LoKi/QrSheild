import pytest

from qrshield_core.analyzers import analyze_payload_security
from qrshield_core.models import Severity as S
from tests.conftest import ids


def run(norm, deps, raw):
    return analyze_payload_security(norm(raw), deps)


# ---------------------------------------------------------------- URL
def test_url_https_clean_has_no_findings(norm, deps):
    assert ids(run(norm, deps, "https://abcshop.example/menu")) == set()


def test_url_http_is_weak_not_more(norm, deps):
    ev = run(norm, deps, "http://abcshop.example/offers")
    assert [(e.indicator_id, e.severity) for e in ev] == [("URL-001", S.WEAK)]


@pytest.mark.parametrize("raw,expected", [
    ("http://203.0.113.45/pay", {"URL-018", "URL-001", "URL-011"}), ("http://93.184.216.34/x", {"URL-002", "URL-001"}),
    ("http://2130706433/x", {"URL-019", "URL-001"}), ("https://bit.ly/3xYz", {"URL-003"}), ("https://qrco.de/abc", {"URL-003"}),
    ("https://paypa1.com/signin", {"URL-004", "URL-011"}), ("https://paypa1l.com/", {"URL-004"}),
    ("https://paypal-secure-login.example/", {"URL-005"}), ("https://paypal.com.evil.example/", {"URL-005"}),
    ("https://user:pw@evil.example/", {"URL-007"}), ("javascript:alert(1)", {"URL-013"}), ("https://a.example:8443/x", {"URL-014"}),
    ("https://a.b.c.d.e.example/", {"URL-010"}), ("https://x.example/?next=https://evil.example", {"URL-016"}),
])
def test_url_indicators(norm, deps, raw, expected):
    assert expected <= ids(run(norm, deps, raw))


def test_official_brand_domain_is_not_flagged(norm, deps):
    assert not ids(run(norm, deps, "https://www.paypal.com/signin")) & {"URL-004", "URL-005"}
    assert not ids(run(norm, deps, "https://login.microsoft.com/")) & {"URL-004", "URL-005"}


def test_sensitive_parameter_is_observation_not_verdict(norm, deps):
    ev = run(norm, deps, "https://abcshop.example/receipt?token=abc123")
    assert ids(ev) == {"URL-006"} and ev[0].severity is S.WEAK and "abc123" not in ev[0].observation


def test_url_many_params_and_long_url(norm, deps):
    assert "URL-012" in ids(run(norm, deps, "https://a.example/?" + "&".join(f"p{i}=1" for i in range(14))))
    assert "URL-017" in ids(run(norm, deps, "https://a.example/" + "x" * 1100))


# ---------------------------------------------------------------- Wi-Fi
def test_wifi(norm, deps):
    assert ids(run(norm, deps, "WIFI:T:WPA;S:Guest;P:pw;;")) == {"WIFI-004"}
    assert ids(run(norm, deps, "WIFI:T:nopass;S:Guest;;")) == {"WIFI-001"}
    assert ids(run(norm, deps, "WIFI:T:WEP;S:Guest;P:12345;;")) == {"WIFI-002", "WIFI-004"}
    assert "WIFI-003" in ids(run(norm, deps, "WIFI:T:WPA;S:Guest;P:x;H:true;;"))
    assert "WIFI-005" in ids(run(norm, deps, "WIFI:T:WPA;S:" + "A" * 40 + ";P:x;;"))


def test_wifi_password_never_in_observation(norm, deps):
    for e in run(norm, deps, "WIFI:T:WPA;S:Guest;P:Sup3rSecret!;;"):
        assert "Sup3rSecret" not in e.observation


# ---------------------------------------------------------------- payment
def test_payment_clean_static_code(norm, deps):
    assert ids(run(norm, deps, "upi://pay?pa=shop@okicici&pn=Shop")) == {"PAY-001", "PAY-011"}


def test_payment_amount_rules(norm, deps):
    assert {"PAY-004", "PAY-003"} <= ids(run(norm, deps, "upi://pay?pa=shop@okicici&pn=Shop&am=15000&cu=INR"))
    assert "PAY-003" not in ids(run(norm, deps, "upi://pay?pa=shop@okicici&pn=Shop&am=850&cu=INR"))
    assert "PAY-010" in ids(run(norm, deps, "upi://pay?pa=shop@okicici&pn=Shop&am=-5"))


def test_payment_structure_and_ancillary(norm, deps):
    ev = ids(run(norm, deps, "upi://pay?pa=bad&pn=Shop&am=1&x=2&url=http://pay.example/r"))
    assert {"PAY-007", "PAY-006", "PAY-005", "URL-001"} <= ev
    assert "PAY-002" in ids(run(norm, deps, "upi://pay?pa=shop@okicici"))


def test_payment_malformed_is_reported_not_guessed(norm, deps):
    assert "TXT-006" in ids(run(norm, deps, "upi://pay?pn=NoAddress"))


# ---------------------------------------------------------------- contact / sms / email / deep link / text
def test_contact(norm, deps):
    ok = run(norm, deps, "BEGIN:VCARD\nFN:A\nORG:ABC Infotech Pvt Ltd\nEMAIL:support@abc.example\nURL:https://abc.example\nEND:VCARD")
    assert not ids(ok) & {"CON-001", "CON-002", "CON-003"}
    assert "CON-004" in ids(run(norm, deps, "MECARD:N:A;ORG:ABC;EMAIL:x@gmail.com;;"))
    bad = ids(run(norm, deps, "BEGIN:VCARD\nFN:A\nORG:ABC Infotech\nEMAIL:a@other.example\nURL:https://another.example\nEND:VCARD"))
    assert {"CON-001", "CON-002", "CON-003"} <= bad


def test_sms_sensitive_requests(norm, deps):
    assert "COM-001" in ids(run(norm, deps, "SMSTO:+910000000022:Send OTP to complete verification"))
    assert "COM-003" in ids(run(norm, deps, "SMSTO:+910000000022:Reply with your Aadhaar and date of birth"))
    assert "COM-002" in ids(run(norm, deps, "SMSTO:+910000000022:Reply PAY 5000 to confirm"))
    assert ids(run(norm, deps, "SMSTO:+910000000022:URGENT reply YES within 24 hours")) >= {"COM-004"}
    assert "SMS-002" in ids(run(norm, deps, "sms:+910000000022,+910000000023?body=hi"))
    assert "SMS-001" in ids(run(norm, deps, "SMSTO:abc:hi"))


@pytest.mark.parametrize("text", ["Please do not share your OTP with anyone", "Never send your PIN to anyone", "Don't give your password to staff",
                                  "I would like to book a table for two"])
def test_negated_or_benign_text_is_not_a_request(norm, deps, text):
    """Regression: the negation guard once sliced one character too far and flagged warnings as requests."""
    assert not ids(run(norm, deps, f"SMSTO:+910000000011:{text}")) & {"COM-001", "COM-002", "COM-003"}


def test_sms_links_are_analyzed_statically(norm, deps):
    assert "URL-003" in ids(run(norm, deps, "SMSTO:+910000000011:See https://bit.ly/abc"))


def test_email(norm, deps):
    assert "COM-001" in ids(run(norm, deps, "mailto:billing@abc.example?subject=Verify&body=Please%20reply%20with%20your%20password%20and%20card%20number"))
    assert "EML-001" in ids(run(norm, deps, "mailto:a@b.example?bcc=c@d.example"))
    assert "EML-002" in ids(run(norm, deps, "mailto:x@gmail.com"))
    assert "EML-003" in ids(run(norm, deps, "mailto:help@paypa1.com"))
    assert "EML-004" in ids(run(norm, deps, "mailto:not-an-email"))


def test_deeplink(norm, deps):
    ev = ids(run(norm, deps, "unknownbank://recover?token=XYZ&device=new"))
    assert {"DL-001", "DL-002", "DL-003"} <= ev
    sig = ids(run(norm, deps, "sgnl://linkdevice?uuid=EXAMPLE&pub_key=EXAMPLE"))
    assert {"DL-007", "DL-002"} <= sig and "DL-001" not in sig
    assert "DL-006" in ids(run(norm, deps, "otpauth://totp/Ex:a?secret=ABC")) and "DL-005" in ids(run(norm, deps, "intent://x#Intent;scheme=a;package=com.a.b;S.browser_fallback_url=https%3A%2F%2Fx.example;end"))
    assert ids(run(norm, deps, "tg://resolve?domain=chan")) == {"DL-007"}


def test_plain_text(norm, deps):
    assert ids(run(norm, deps, "Table 12")) == {"TXT-004"}
    assert "TXT-001" in ids(run(norm, deps, "pay\u202e now"))
    assert "TXT-005" in ids(run(norm, deps, "tel:+910000000099"))
    assert "TXT-002" in ids(run(norm, deps, "Visit https://bit.ly/abc for details")) and "URL-003" in ids(run(norm, deps, "Visit https://bit.ly/abc"))


def test_every_emitted_rule_is_registered_and_traceable(norm, deps, reg):
    samples = ["http://203.0.113.45/pay?token=1", "WIFI:T:nopass;S:x;;", "upi://pay?pa=a@b&url=http://x.example", "SMSTO:+91000000001:Send OTP",
               "mailto:a@b.example?body=password", "unknownbank://recover?token=1", "Table 12"]
    for raw in samples:
        for e in analyze_payload_security(norm(raw), deps):
            r = reg.get(e.indicator_id)
            assert e.rationale == r.rationale and e.family is r.family and e.title == r.title
