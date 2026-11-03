import pytest

from qrshield_core.models import PayloadType as T
from qrshield_core.normalizer.normalize import crc16_ccitt


def test_crc16_matches_reference_check_value():
    assert crc16_ccitt("123456789") == "29B1"          # CRC-16/CCITT-FALSE check value


@pytest.mark.parametrize("raw,ptype", [
    ("https://abcshop.example/menu", T.URL), ("http://203.0.113.45/pay", T.URL), ("javascript:alert(1)", T.URL), ("bit.ly/3xYz", T.URL),
    ("WIFI:T:WPA;S:Cafe;P:x;;", T.WIFI), ("upi://pay?pa=a@b&pn=X", T.PAYMENT), ("bitcoin:bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", T.PAYMENT),
    ("phonepe://pay?pa=a@ybl&pn=X", T.PAYMENT), ("BEGIN:VCARD\nFN:A\nEND:VCARD", T.CONTACT), ("MECARD:N:A,B;;", T.CONTACT),
    ("SMSTO:+910000000001:hi", T.SMS), ("sms:+910000000001?body=hi", T.SMS), ("mailto:a@b.example", T.EMAIL), ("MATMSG:TO:a@b.example;SUB:s;BODY:b;;", T.EMAIL),
    ("sgnl://linkdevice?uuid=1&pub_key=2", T.DEEP_LINK), ("unknownbank://recover?token=1", T.DEEP_LINK), ("otpauth://totp/x?secret=ABC", T.DEEP_LINK),
    ("intent://x#Intent;scheme=a;package=com.a.b;end", T.DEEP_LINK), ("Table 12", T.PLAIN_TEXT), ("tel:+910000000099", T.PLAIN_TEXT), ("", T.PLAIN_TEXT),
    ("notes.pdf", T.PLAIN_TEXT),
])
def test_classification(norm, raw, ptype):
    assert norm(raw).type is ptype


def test_bare_domain_is_url_without_assumed_scheme(norm):
    p = norm("bit.ly/3xYz")
    assert p.normalized_fields["scheme_missing"] and p.normalized_fields["scheme"] == ""


def test_url_special_hosts(norm):
    assert norm("http://203.0.113.45/x").normalized_fields["special_host"]            # documentation range
    assert norm("http://localhost:8080/x").normalized_fields["special_host"]
    assert norm("http://2130706433/x").normalized_fields["obfuscated_ip"]
    assert norm("http://0x7f.1/x").normalized_fields["obfuscated_ip"]
    assert not norm("http://93.184.216.34/x").normalized_fields["special_host"]


def test_url_idn_and_mixed_script(norm):
    f = norm("https://\u0430pple.com/login").normalized_fields       # Cyrillic a
    assert f["punycode"] and f["mixed_script"]


def test_url_query_values_redacted_but_names_kept(norm):
    f = norm("https://a.example/p?token=SECRET123&x=1").normalized_fields
    assert f["query"]["token"] == ["[REDACTED]"] and f["query"]["x"] == ["1"] and "SECRET123" not in f["url_redacted"]


def test_wifi_parse_escapes_and_password_not_stored(norm):
    p = norm("WIFI:T:WPA;S:My\\;Net;P:pa\\;ss;H:true;;")
    f = p.normalized_fields
    assert f["ssid"] == "My;Net" and f["hidden"] and f["password_present"] and "password" not in f
    assert "pa" not in p.raw_redacted.replace("password", "") or "[REDACTED]" in p.raw_redacted
    assert "ss;" not in p.raw_redacted


def test_wifi_open_and_missing_ssid(norm):
    assert norm("WIFI:T:nopass;S:Guest;;").normalized_fields["auth_type"] == "open"
    bad = norm("WIFI:T:WPA;P:x;;")
    assert not bad.parse_ok and bad.notes


def test_upi_fields(norm):
    f = norm("upi://pay?pa=shop@okicici&pn=Sunrise%20Hotel&am=850.00&cu=INR&tn=Room&tr=T1&mc=5812").normalized_fields
    assert (f["recipient"], f["payee_name"], f["amount"], f["currency"], f["rail"]) == ("shop@okicici", "Sunrise Hotel", "850", "INR", "UPI")
    assert f["amount_fixed"] and f["recipient_format_valid"]


def test_upi_invalid_amount_and_missing_address(norm):
    assert norm("upi://pay?pa=a@b&am=abc").normalized_fields["amount_valid"] is False
    assert not norm("upi://pay?pn=NoAddress").parse_ok


def _emv(valid=True):
    core = "0002010102112628" "0010A000000524" "0110shop@icici" "5204" "5812" "5303" "356" "5913SUNRISE HOTEL" "6304"
    return core + (crc16_ccitt(core) if valid else "0000")


def test_emv_crc_valid_and_invalid(norm):
    assert norm(_emv()).normalized_fields["crc_valid"] is True
    bad = norm(_emv(False))
    assert bad.normalized_fields["crc_valid"] is False and bad.normalized_fields["payee_name"] == "SUNRISE HOTEL"


def test_malformed_emv_is_payment_not_plain_text(norm):
    p = norm("000201010211" + "2699broken-payload-xx")
    assert p.type is T.PAYMENT and not p.parse_ok            # a possibly tampered payment is never downgraded to text


def test_vcard_and_mecard(norm):
    v = norm("BEGIN:VCARD\nFN:A B\nORG:ABC Infotech\nTEL:+910000000001\nEMAIL:x@abc.example\nURL:https://abc.example\nNOTE:hi\nEND:VCARD").normalized_fields
    assert v["organization"] == "ABC Infotech" and v["email_domains"] == ["abc.example"] and v["websites_parsed"][0]["host"] == "abc.example"
    m = norm("MECARD:N:Doe,John;ORG:ABC;TEL:+910000000002;EMAIL:j@abc.example;;").normalized_fields
    assert m["name"] == "John Doe" and m["organization"] == "ABC"


@pytest.mark.parametrize("raw,rec,body", [
    ("SMSTO:+910000000011:Send OTP now", ["+910000000011"], "Send OTP now"),
    ("sms:+910000000011?body=Hello%20there", ["+910000000011"], "Hello there"),
    ("sms:+910000000011,+910000000012?body=hi", ["+910000000011", "+910000000012"], "hi"),
])
def test_sms_forms(norm, raw, rec, body):
    f = norm(raw).normalized_fields
    assert f["recipients"] == rec and body.split()[0] in f["body"]


def test_sms_otp_digits_redacted(norm):
    assert "839123" not in norm("SMSTO:+910000000011:Send OTP 839123 now").normalized_fields["body"]


def test_email_forms(norm):
    f = norm("mailto:a@b.example,c@d.example?subject=Hi&cc=e@f.example&bcc=g@h.example&body=Yo").normalized_fields
    assert f["to"] == ["a@b.example", "c@d.example"] and f["bcc"] == ["g@h.example"] and f["subject"] == "Hi"
    m = norm("MATMSG:TO:a@b.example;SUB:s;BODY:b;;").normalized_fields
    assert m["to"] == ["a@b.example"] and m["subject"] == "s"


def test_deeplink_operations(norm):
    assert norm("sgnl://linkdevice?uuid=EX&pub_key=EX").normalized_fields["operation"] == "device_linking"
    assert norm("unknownbank://recover?token=XYZ&device=new").normalized_fields["operations"][0] == "account_recovery"
    assert norm("tg://resolve?domain=chan").normalized_fields["operation"] == "content"
    d = norm("tg://login?token=SECRET").normalized_fields
    assert d["operation"] == "authentication" and d["params"]["token"] == ["[REDACTED]"]
    assert norm("otpauth://totp/Ex:alice?secret=ABC").normalized_fields["operation"] == "auth_secret"
    i = norm("intent://x#Intent;scheme=abc;package=com.a.b;S.browser_fallback_url=https%3A%2F%2Fx.example;end").normalized_fields
    assert i["package"] == "com.a.b" and i["fallback_url"] == "https://x.example"


def test_plain_text_and_tel(norm):
    t = norm("tel:+910000000099")
    assert t.type is T.PLAIN_TEXT and t.action == "initiate_call"
    h = norm("pay\u202e now\u200b").normalized_fields
    assert h["has_hidden_chars"]


@pytest.mark.parametrize("raw", ["http://[::1", "WIFI:", "BEGIN:VCARD", "SMSTO:", "mailto:", "upi://", "://", "\x00\x01\x02", "A" * 5000,
                                 "http://" + "a." * 300 + "com", "{{7*7}}", "'; DROP TABLE users;--", "<img src=x onerror=alert(1)>"])
def test_malformed_input_never_raises(norm, raw):
    p = norm(raw)
    assert p.type in T and isinstance(p.normalized_fields, dict)


def test_sms_percent_encoded_body_is_decoded_before_security_analysis(norm, deps):
    from qrshield_core.analyzers import analyze_payload_security
    p = norm("SMSTO:+910000000022:Enter%20OTP%20to%20complete%20payment")
    assert p.normalized_fields["body"] == "Enter OTP to complete payment"
    assert "COM-001" in {e.indicator_id for e in analyze_payload_security(p, deps)}

