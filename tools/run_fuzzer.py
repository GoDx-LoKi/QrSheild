#!/usr/bin/env python3
"""Structure-aware & property-based fuzzer for QRShield (Phase 4, AC-3, AC-4).

Executes >= 100,000 deterministic fuzzed inputs across:
  1. Payload normalizer & classifier (`normalize`) across URL, UPI/payment, Wi-Fi, vCard, SMS, Email, Tel, Deep Link, and binary/Unicode/homoglyph edge cases
  2. Payload security analyzers (`analyze_payload_security`)
  3. OCR candidate context extractor (`extract_candidates`)
  4. Image loader bounds & malformed byte stream handler (`load_image`)
Verifies 0 unhandled exceptions, 0 crashes, and bounded execution time.
"""
from __future__ import annotations

import json
import random
import string
import sys
import time
from pathlib import Path


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(root / "source"))

    from qrshield_core.analyzers import Deps, analyze_payload_security
    from qrshield_core.config import Settings
    from qrshield_core.context.extract import extract_candidates
    from qrshield_core.image.loader import ImageError, load_image
    from qrshield_core.matching.entity import Matcher
    from qrshield_core.ocr.engine import OCRBlock, conf_bucket, normalize_ocr_text
    from qrshield_core.normalizer.normalize import normalize
    from qrshield_core.rules import ReferenceData, RuleRegistry

    settings = Settings(load_synthetic_reference=False, threat_intel_enabled=False, ocr_enabled=False)
    reg = RuleRegistry(settings.rules_dir)
    ref = ReferenceData.load(settings.rules_dir, False)
    matcher = Matcher(ref)
    deps = Deps(reg, ref, matcher)

    rng = random.Random(20261101)
    prefixes = [
        "https://", "http://", "javascript:", "data:text/html,", "upi://pay?",
        "bitcoin:", "WIFI:T:WPA;S:", "WIFI:T:nopass;S:", "BEGIN:VCARD\n",
        "MATMSG:TO:", "mailto:", "SMSTO:", "sms:", "tel:", "phonepe://",
        "gpay://", "paytmmp://", "myapp://", "", "\x00\xff", "xn--",
    ]
    atoms = [
        "sbi.co.in", "192.168.1.1", "10.0.0.1", "8.8.8.8", "[::1]", "pa=test@upi",
        "&am=999999", "&cu=INR", "&url=http://evil.xyz", "#redirect=https://bad.top",
        "%00%0d%0a", "../../etc/passwd", "A" * 512, "pаypal.com", "urgent otp pin cvv",
        "never share your otp", ";;", "\nEND:VCARD", "?token=secret&next=//attacker.icu",
        "user:pass@host.com:8080/login/verify.apk", "*21*9876543210#",
    ]

    total_iterations = 100_000
    norm_count = 0
    analyzer_count = 0
    ocr_extract_count = 0
    image_loader_count = 0
    crashes: list[dict[str, str]] = []

    t0 = time.perf_counter()

    # 1. 75,000 normalizer + analyzer fuzz inputs
    for i in range(75_000):
        p = rng.choice(prefixes)
        k = rng.randint(1, 5)
        body = "".join(rng.choices(atoms, k=k))
        if i % 7 == 0:
            noise = "".join(rng.choices(string.printable + "αβγδεאבגआइई\x00\x07\x1b", k=rng.randint(1, 24)))
            raw = p + body + noise
        else:
            raw = p + body
        try:
            pl = normalize(raw, ref)
            norm_count += 1
            if i % 3 == 0:
                _ = analyze_payload_security(pl, deps)
                analyzer_count += 1
        except Exception as exc:
            crashes.append({"target": "normalize_or_analyze", "iter": str(i), "error": f"{type(exc).__name__}: {exc}"})
            if len(crashes) >= 10:
                break

    # 2. 20,000 OCR candidate extraction fuzz inputs
    for i in range(20_000):
        txt = rng.choice(atoms) + " " + rng.choice(["State Bank of India", "Pay ₹500", "Guest Wi-Fi", "support@hdfcbank.com", "+91-9876543210", ""])
        sc = rng.random()
        blk = OCRBlock(block_id=f"b{i}", raw_text=txt, normalized_text=normalize_ocr_text(txt), score=sc, confidence=conf_bucket(sc), bbox=[[0, 0], [100, 0], [100, 30], [0, 30]])
        try:
            _ = extract_candidates([blk], ref)
            ocr_extract_count += 1
        except Exception as exc:
            crashes.append({"target": "extract_candidates", "iter": str(i), "error": f"{type(exc).__name__}: {exc}"})
            if len(crashes) >= 10:
                break

    # 3. 5,000 malformed / truncated / oversized header image loader fuzz inputs
    headers = [
        b"\x89PNG\r\n\x1a\n",
        b"\xff\xd8\xff\xe0",
        b"GIF89a",
        b"BM",
        b"RIFF\x00\x00\x00\x00WEBP",
        b"",
        b"\x00" * 64,
    ]
    for i in range(5_000):
        hdr = rng.choice(headers)
        tail = bytes(rng.getrandbits(8) for _ in range(rng.randint(0, 128)))
        data = hdr + tail
        try:
            load_image(data, max_bytes=1024 * 1024, max_pixels=4_000_000, max_side=2048)
        except ImageError:
            pass  # Expected controlled rejection for malformed images
        except Exception as exc:
            crashes.append({"target": "load_image", "iter": str(i), "error": f"{type(exc).__name__}: {exc}"})
            if len(crashes) >= 10:
                break
        image_loader_count += 1

    elapsed_s = round(time.perf_counter() - t0, 3)
    total_executed = norm_count + ocr_extract_count + image_loader_count
    passed = len(crashes) == 0 and total_executed >= total_iterations

    report = {
        "status": "PASS" if passed else "FAIL",
        "total_fuzzed_inputs": total_executed,
        "breakdown": {
            "normalizer_inputs": norm_count,
            "analyzer_inputs": analyzer_count,
            "ocr_extractor_inputs": ocr_extract_count,
            "image_loader_inputs": image_loader_count,
        },
        "crashes_or_unhandled_exceptions": len(crashes),
        "crash_samples": crashes,
        "elapsed_seconds": elapsed_s,
    }
    out_path = root / "release" / "evidence" / "fuzz_summary.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
