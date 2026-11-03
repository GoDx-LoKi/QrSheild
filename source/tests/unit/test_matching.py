import pytest

from qrshield_core.matching.domains import edit_distance, phones_equal, registrable_domain, skeleton, split_host
from qrshield_core.models import MatchResult as M


@pytest.mark.parametrize("a,b,expected", [
    ("Sunrise Hotel", "Sunrise Hotel", M.MATCH), ("Sunrise Hotel", "SUNRISE  HOTEL!", M.MATCH),
    ("Sunrise Hotel", "Sunrise Hospitality Pvt Ltd", M.LIKELY_MATCH), ("ABC", "ABC Infotech Pvt. Ltd.", M.LIKELY_MATCH),
    ("Sunrise Hotel", "ABC Trading", M.MISMATCH), ("Sunrise Hotel", "Sunrise Beach Resort", M.LIKELY_MATCH),
    ("Sunrise Palace Hotel", "Sunrise Beach Resort", M.UNCERTAIN), ("Sunrise Hotel", "Sunr1se Hotel", M.UNCERTAIN),
    ("Sunrise Hotel", "ExamplePay Merchant Services", M.UNCERTAIN), ("", "ABC", M.INSUFFICIENT_CONTEXT), ("Sunrise Hotel", None, M.INSUFFICIENT_CONTEXT),
    # Generic-only and legal-only comparisons (both sides generic or one side generic + one side distinctive)
    ("Hotel", "Resort Hotel", M.UNCERTAIN), ("Hotel", "Sunrise Hotel", M.UNCERTAIN), ("Sunrise Hotel", "Hotel", M.UNCERTAIN),
    ("Hotel", "Clinic", M.MISMATCH), ("Sunrise Hotel", "Clinic", M.MISMATCH), ("Pvt Ltd", "Inc", M.INSUFFICIENT_CONTEXT),
    # Acronym comparisons (distinctive non-generic tokens)
    ("NTR", "Northstar Timber Rail", M.UNCERTAIN), ("Northstar Timber Rail", "NTR", M.UNCERTAIN),
    # Spacing ignored
    ("Sun Rise", "Sunrise", M.LIKELY_MATCH),
])
def test_compare_names(matcher, a, b, expected):
    assert matcher.compare_names(a, b).result is expected


def test_processor_hint_only_attached_when_relevant(matcher):
    assert matcher.compare_names("Sunrise Hotel", "ExamplePay Merchant Services").exception_hint
    assert matcher.compare_names("Sunrise Hotel", "ABC Trading").exception_hint is None


@pytest.mark.parametrize("org,host,expected", [
    ("ABC Shop", "abcshop.example", M.LIKELY_MATCH), ("ABC Infotech", "abc.example", M.LIKELY_MATCH),
    ("ABC Bank", "abcbank-verify.example", M.UNCERTAIN), ("ABC Bank", "abcbank.example.verify-account.example", M.MISMATCH),
    ("ABC Shop", "totally-different.example", M.MISMATCH), ("ABC Shop", "203.0.113.45", M.UNCERTAIN),
    ("", "x.example", M.INSUFFICIENT_CONTEXT), ("ABC Shop", "", M.INSUFFICIENT_CONTEXT),
    ("Pvt Ltd", "abc.example", M.INSUFFICIENT_CONTEXT),
    # Acronym + group descriptor domain vs single-token or non-matching initials
    ("Harborview Bistro", "hb-group.example", M.LIKELY_MATCH),
    ("Harborview", "hb-group.example", M.MISMATCH),
    ("Harborview Bistro", "hbgroup.example", M.MISMATCH),
    # Fuzzy domain match (>= 0.85 ratio) and substring match
    ("SunriseHtl", "sunriseht1.example", M.UNCERTAIN),
    ("Hotel", "hote1.example", M.MISMATCH),
    ("Greenfield", "mygreenfieldportal.example", M.UNCERTAIN),
])
def test_org_domain_relation(matcher, org, host, expected):
    assert matcher.org_domain_relation(org, host).result is expected


@pytest.mark.parametrize("org,ssid,expected", [
    ("Sunrise Hotel", "Sunrise_Guest", M.LIKELY_MATCH), ("Greenfield University", "GreenfieldGuest", M.LIKELY_MATCH),
    ("Hotel", "Hotel_Guest", M.LIKELY_MATCH), ("Hotel", "Airport_Guest", M.MISMATCH),
    ("Greenfield University", "CityCafe_Free", M.MISMATCH), ("Greenfield University", "random-public", M.MISMATCH),
    ("Greenfield University", "Guest WiFi", M.UNCERTAIN),
    ("", "Guest WiFi", M.INSUFFICIENT_CONTEXT), ("Greenfield University", "", M.INSUFFICIENT_CONTEXT),
    ("Pvt Ltd", "Guest WiFi", M.INSUFFICIENT_CONTEXT),
])
def test_ssid_relation(matcher, org, ssid, expected):
    assert matcher.ssid_relation(org, ssid).result is expected


def test_known_brand_ambiguity_regression(matcher):
    """'ABC Shop' must not resolve to 'ABC Bank': generic words are ignored by name matching, so lookup must veto contradictions."""
    assert matcher.known_brand("ABC Shop").name == "ABC Shop"
    assert matcher.known_brand("ABC Bank").name == "ABC Bank"
    assert matcher.known_brand("ABC Infotech") is None and matcher.known_brand("ABC") is None
    assert matcher.known_brand("Sunrise Hospitality Pvt Ltd").name == "Sunrise Hotel"      # via alias


def test_official_domain_includes_subdomains(matcher):
    b = matcher.known_brand("ABC Bank")
    assert matcher.is_official_domain(b, "abcbank.example") and matcher.is_official_domain(b, "secure.abcbank.example")
    assert not matcher.is_official_domain(b, "abcbank-verify.example")


def test_domain_helpers():
    assert registrable_domain("a.b.example.co.in") == "example.co.in" and registrable_domain("www.paypal.com") == "paypal.com"
    assert split_host("x.y.z.example").subdomains == ["x", "y"] and split_host("x.y.z.example").sld == "z"
    assert skeleton("paypa1") == skeleton("paypal") and skeleton("rnicrosoft") == skeleton("microsoft")
    assert edit_distance("kitten", "sitting") == 3
    assert phones_equal("+91 00000 00033", "00000-00033") and not phones_equal("+910000000033", "+910000000044") and not phones_equal("123", "123")
