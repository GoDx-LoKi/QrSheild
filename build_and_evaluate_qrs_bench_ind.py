#!/usr/bin/env python3
"""
QRS-Bench-Ind: Independent Multi-Stratum Benchmark Generator & Blind Evaluator
for the Frozen QRShield Engine.

Key Scientific Properties:
1. Zero modifications to `qrshield_core` or `rules/` (verified via SHA-256 freeze manifest).
2. Evaluates QRShield with `load_synthetic_reference=False` so all 60 benchmark organizations
   (8 Dev, 12 Val, 40 Locked Test) are unseen during evaluation.
3. Naturalistic, template-free signage layouts (28 layouts: T01..T04 dev, T05..T08 val, T09..T28 test_locked) with no `Organization:` / `Purpose:`
   synthetic key-value prefixes on the locked test split.
4. Author-assigned ground truth (`consensus_ground_truth.jsonl`) with explicit `provenance: author_assigned`.
5. Replayable external threat-intelligence fixture (`threat_intel_snapshot.json`) enabling
   deterministic evaluation of all 4 ordinal decision levels (L0..L3, including `harmful_corroborated`).
6. Balanced 12 x 16 factorial robustness matrix (192 images) and rule-blind counterfactual pairs
   (including semantic paraphrase negative controls).
"""
from __future__ import annotations

import hashlib
import io
import json
import math
import os
import re
import sys
import time
from concurrent.futures import ProcessPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import cv2
import numpy as np
import yaml
from PIL import Image, ImageDraw, ImageFont

# Ensure single-threaded OpenMP inside worker processes to prevent CPU thrashing
os.environ["OMP_THREAD_LIMIT"] = "1"

ROOT_DIR = Path(__file__).resolve().parent
SOURCE_DIR = ROOT_DIR / "source"
sys.path.insert(0, str(SOURCE_DIR))

from qrshield_core.config import Settings
from qrshield_core.context.extract import build_context
from qrshield_core.ocr.engine import TesseractOCRProvider
from qrshield_core.pipeline.engine import ABLATIONS, AnalysisConfig, QRShieldEngine
from qrshield_core.threat_intel.base import MockThreatIntelProvider

BENCH_DIR = ROOT_DIR / "qrs_bench_ind"

CATEGORIES = ["url", "wifi", "payment", "contact", "sms", "email", "deep_link", "plain_text"]
LEVELS = ["no_material_concern", "needs_verification", "high_concern", "harmful_corroborated"]
LEVEL_IDX = {lvl: i for i, lvl in enumerate(LEVELS)}

FONT_BOLD = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
FONT_REG = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
FONT_SERIF_BOLD = "/usr/share/fonts/truetype/dejavu/DejaVuSerif-Bold.ttf"
FONT_SERIF_REG = "/usr/share/fonts/truetype/dejavu/DejaVuSerif.ttf"
FONT_DEVANAGARI = "/usr/share/fonts/truetype/noto/NotoSansDevanagari-Regular.ttf"
FONT_CJK = "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc"


# ---------------------------------------------------------------------------
# 1. Disjoint Organization Registry (60 unseen organizations across 3 splits)
# ---------------------------------------------------------------------------
def build_organizations() -> dict[str, list[dict[str, str]]]:
    dev_orgs = [
        {"org_id": "D01", "name": "Alderwood Cafe", "domain": "alderwoodcafe.org", "vpa": "alderwoodcafe@okaxis", "ssid": "AlderwoodCafe-Guest", "phone": "+1-206-555-0111", "email": "hello@alderwoodcafe.org", "scheme": "alderwoodcafe", "sector": "restaurant"},
        {"org_id": "D02", "name": "Bayside Clinic", "domain": "baysideclinic.org", "vpa": "baysideclinic@okicici", "ssid": "BaysideClinic-Guest", "phone": "+1-206-555-0112", "email": "care@baysideclinic.org", "scheme": "baysideclinic", "sector": "clinic"},
        {"org_id": "D03", "name": "Cobalt Hotel", "domain": "cobalthotel.com", "vpa": "cobalthotel@okhdfcbank", "ssid": "CobaltHotel-Lobby", "phone": "+1-206-555-0113", "email": "desk@cobalthotel.com", "scheme": "cobalthotel", "sector": "hotel"},
        {"org_id": "D04", "name": "Driftwood Books", "domain": "driftwoodbooks.com", "vpa": "driftwoodbooks@oksbi", "ssid": "DriftwoodBooks-WiFi", "phone": "+1-206-555-0114", "email": "orders@driftwoodbooks.com", "scheme": "driftwoodbooks", "sector": "retail"},
        {"org_id": "D05", "name": "Elmhurst Bank", "domain": "elmhurstbank.org", "vpa": "elmhurstbank@okaxis", "ssid": "ElmhurstBank-Visitor", "phone": "+1-206-555-0115", "email": "support@elmhurstbank.org", "scheme": "elmhurstbank", "sector": "bank"},
        {"org_id": "D06", "name": "Foxglove Pharmacy", "domain": "foxglovepharmacy.com", "vpa": "foxglovepharmacy@okicici", "ssid": "Foxglove-Guest", "phone": "+1-206-555-0116", "email": "rx@foxglovepharmacy.com", "scheme": "foxglovepharmacy", "sector": "clinic"},
        {"org_id": "D07", "name": "Granite Gym", "domain": "granitegym.org", "vpa": "granitegym@okhdfcbank", "ssid": "GraniteGym-Member", "phone": "+1-206-555-0117", "email": "club@granitegym.org", "scheme": "granitegym", "sector": "retail"},
        {"org_id": "D08", "name": "Highland Transit", "domain": "highlandtransit.org", "vpa": "highlandtransit@oksbi", "ssid": "HighlandTransit-Free", "phone": "+1-206-555-0118", "email": "info@highlandtransit.org", "scheme": "highlandtransit", "sector": "transit"},
    ]
    val_orgs = [
        {"org_id": "V01", "name": "Ironwood Bistro", "domain": "ironwoodbistro.com", "vpa": "ironwoodbistro@okaxis", "ssid": "IronwoodBistro-Guest", "phone": "+1-312-555-0121", "email": "dining@ironwoodbistro.com", "scheme": "ironwoodbistro", "sector": "restaurant"},
        {"org_id": "V02", "name": "Juniper Dental", "domain": "juniperdental.org", "vpa": "juniperdental@okicici", "ssid": "JuniperDental-WiFi", "phone": "+1-312-555-0122", "email": "smile@juniperdental.org", "scheme": "juniperdental", "sector": "clinic"},
        {"org_id": "V03", "name": "Kestrel Suites", "domain": "kestrelsuites.com", "vpa": "kestrelsuites@okhdfcbank", "ssid": "KestrelSuites-Guest", "phone": "+1-312-555-0123", "email": "stay@kestrelsuites.com", "scheme": "kestrelsuites", "sector": "hotel"},
        {"org_id": "V04", "name": "Larkspur Market", "domain": "larkspurmarket.com", "vpa": "larkspurmarket@oksbi", "ssid": "LarkspurMarket-WiFi", "phone": "+1-312-555-0124", "email": "help@larkspurmarket.com", "scheme": "larkspurmarket", "sector": "retail"},
        {"org_id": "V05", "name": "Meridian Bank", "domain": "meridianbank.org", "vpa": "meridianbank@okaxis", "ssid": "MeridianBank-Guest", "phone": "+1-312-555-0125", "email": "service@meridianbank.org", "scheme": "meridianbank", "sector": "bank"},
        {"org_id": "V06", "name": "Northstar Museum", "domain": "northstarmuseum.org", "vpa": "northstarmuseum@okicici", "ssid": "NorthstarMuseum-Visitor", "phone": "+1-312-555-0126", "email": "visit@northstarmuseum.org", "scheme": "northstarmuseum", "sector": "venue"},
        {"org_id": "V07", "name": "Oakridge College", "domain": "oakridgecollege.edu", "vpa": "oakridgecollege@okhdfcbank", "ssid": "OakridgeCollege-Campus", "phone": "+1-312-555-0127", "email": "registrar@oakridgecollege.edu", "scheme": "oakridgecollege", "sector": "campus"},
        {"org_id": "V08", "name": "Pinecrest Bakery", "domain": "pinecrestbakery.com", "vpa": "pinecrestbakery@oksbi", "ssid": "PinecrestBakery-Guest", "phone": "+1-312-555-0128", "email": "hello@pinecrestbakery.com", "scheme": "pinecrestbakery", "sector": "restaurant"},
        {"org_id": "V09", "name": "Quartz Optics", "domain": "quartzoptics.com", "vpa": "quartzoptics@okaxis", "ssid": "QuartzOptics-Guest", "phone": "+1-312-555-0129", "email": "care@quartzoptics.com", "scheme": "quartzoptics", "sector": "retail"},
        {"org_id": "V10", "name": "Redwood Hospital", "domain": "redwoodhospital.org", "vpa": "redwoodhospital@okicici", "ssid": "RedwoodHospital-Guest", "phone": "+1-312-555-0130", "email": "intake@redwoodhospital.org", "scheme": "redwoodhospital", "sector": "clinic"},
        {"org_id": "V11", "name": "Silverline Parking", "domain": "silverlineparking.com", "vpa": "silverlineparking@okhdfcbank", "ssid": "SilverlineParking-WiFi", "phone": "+1-312-555-0131", "email": "permits@silverlineparking.com", "scheme": "silverlineparking", "sector": "parking"},
        {"org_id": "V12", "name": "Timberline Cinema", "domain": "timberlinecinema.com", "vpa": "timberlinecinema@oksbi", "ssid": "TimberlineCinema-Lobby", "phone": "+1-312-555-0132", "email": "boxoffice@timberlinecinema.com", "scheme": "timberlinecinema", "sector": "venue"},
    ]
    test_names = [
        ("N01", "Amberwood Tavern", "restaurant", "org"),
        ("N02", "Broadmoor Bank", "bank", "org"),
        ("N03", "Coralreef Suites", "hotel", "com"),
        ("N04", "Daybreak Clinic", "clinic", "org"),
        ("N05", "Eastgate Parking", "parking", "com"),
        ("N06", "Fernvalley Bakery", "restaurant", "com"),
        ("N07", "Goldcrest Institute", "campus", "edu"),
        ("N08", "Hazelwood Pharmacy", "clinic", "com"),
        ("N09", "Ivorycoast Roasters", "restaurant", "org"),
        ("N10", "Jadeite Library", "library", "org"),
        ("N11", "Kingsway Trattoria", "restaurant", "com"),
        ("N12", "Lakeshore Hospital", "clinic", "org"),
        ("N13", "Mistral Transit", "transit", "org"),
        ("N14", "Nightingale Wellness", "retail", "com"),
        ("N15", "Oakhaven Bank", "bank", "org"),
        ("N16", "Pelican Bookstore", "retail", "com"),
        ("N17", "Quicksilver Lodge", "hotel", "com"),
        ("N18", "Riverbend Dental", "clinic", "org"),
        ("N19", "Silverthorne Playhouse", "venue", "org"),
        ("N20", "Thornfield Athletics", "retail", "com"),
        ("N21", "Upland Kitchen", "restaurant", "com"),
        ("N22", "Verdant Gallery", "venue", "org"),
        ("N23", "Westbrook Bank", "bank", "org"),
        ("N24", "Xenon Mart", "retail", "com"),
        ("N25", "Yellowstone Inn", "hotel", "com"),
        ("N26", "Zephyr Medical", "clinic", "org"),
        ("N27", "Alabaster Garage", "parking", "com"),
        ("N28", "Bramblewood College", "campus", "edu"),
        ("N29", "Citadel Pizzeria", "restaurant", "com"),
        ("N30", "Dewdrop Pharmacy", "clinic", "com"),
        ("N31", "Emberlight Lounge", "restaurant", "com"),
        ("N32", "Falconridge Bank", "bank", "org"),
        ("N33", "Goldenbay Ferry", "transit", "org"),
        ("N34", "Highpoint Emporium", "retail", "com"),
        ("N35", "Indigobloom Cafe", "restaurant", "org"),
        ("N36", "Jasmine Care", "clinic", "org"),
        ("N37", "Kensington Hotel", "hotel", "com"),
        ("N38", "Luminance Library", "library", "org"),
        ("N39", "Monarch Hardware", "retail", "com"),
        ("N40", "Noblecrest Bank", "bank", "org"),
    ]
    test_orgs = []
    banks = ["okaxis", "okicici", "okhdfcbank", "oksbi"]
    for idx, (oid, name, sector, tld) in enumerate(test_names):
        slug = re.sub(r"[^a-z0-9]", "", name.lower())
        phone = f"+1-415-555-{1001 + idx:04d}"
        test_orgs.append({
            "org_id": oid,
            "name": name,
            "domain": f"{slug}.{tld}",
            "vpa": f"{slug}@{banks[idx % len(banks)]}",
            "ssid": f"{slug[:12].capitalize()}-Guest",
            "phone": phone,
            "email": f"info@{slug}.{tld}",
            "scheme": slug,
            "sector": sector,
        })
    return {"dev": dev_orgs, "val": val_orgs, "test_locked": test_orgs}


# ---------------------------------------------------------------------------
# 2. Threat Intelligence Snapshot Fixture (for SG5 L3 Corroborated Threats)
# ---------------------------------------------------------------------------
def build_threat_intel_snapshot() -> dict[str, dict[str, int]]:
    return {
        "crestwood-bank-verify.com": {"malicious": 14, "suspicious": 3, "harmless": 48, "undetected": 7},
        "sterling-bank-auth.com": {"malicious": 11, "suspicious": 2, "harmless": 51, "undetected": 8},
        "pacific-bank-secure.org": {"malicious": 16, "suspicious": 4, "harmless": 44, "undetected": 6},
        "northgate-bank-login.com": {"malicious": 9, "suspicious": 3, "harmless": 54, "undetected": 9},
        "crownpoint-bank-portal.org": {"malicious": 12, "suspicious": 2, "harmless": 50, "undetected": 8},
        "harborview-pay-gateway.com": {"malicious": 10, "suspicious": 2, "harmless": 52, "undetected": 9},
        "sunstone-guest-checkin.com": {"malicious": 13, "suspicious": 3, "harmless": 49, "undetected": 7},
        "maplewood-patient-auth.org": {"malicious": 8, "suspicious": 2, "harmless": 55, "undetected": 9},
        "vanguard-meter-fine.com": {"malicious": 15, "suspicious": 3, "harmless": 47, "undetected": 6},
        "summit-campus-sso.com": {"malicious": 11, "suspicious": 2, "harmless": 52, "undetected": 8},
        "apex-hospital-billing.com": {"malicious": 10, "suspicious": 3, "harmless": 51, "undetected": 8},
        "crescent-transit-pass.com": {"malicious": 9, "suspicious": 2, "harmless": 53, "undetected": 9},
        "seaview-resort-booking.com": {"malicious": 7, "suspicious": 2, "harmless": 56, "undetected": 9},
        "beacon-medical-records.org": {"malicious": 12, "suspicious": 3, "harmless": 49, "undetected": 8},
        "elmhurst-bank-verify.com": {"malicious": 11, "suspicious": 2, "harmless": 50, "undetected": 8},
        "meridian-bank-auth.com": {"malicious": 13, "suspicious": 3, "harmless": 48, "undetected": 8},
    }


# ---------------------------------------------------------------------------
# 3. Naturalistic Visual Poster Renderer & Physical Perturbation Pipeline
# ---------------------------------------------------------------------------
_FONT_CACHE: dict[tuple[str, int], ImageFont.FreeTypeFont] = {}


def get_font(path: str, size: int) -> ImageFont.FreeTypeFont:
    key = (path, size)
    if key not in _FONT_CACHE:
        _FONT_CACHE[key] = ImageFont.truetype(path, size)
    return _FONT_CACHE[key]


def encode_qr_matrix(payload: str, target_box_size: int = 184) -> Image.Image:
    enc = cv2.QRCodeEncoder_create()
    mat = enc.encode(payload)
    if mat is None or mat.size == 0:
        raise ValueError(f"Failed to encode QR payload: {payload[:60]}")
    # Standard 4-module quiet zone around QR matrix and integer module scaling
    h, w = mat.shape[:2]
    padded = np.full((h + 8, w + 8), 255, dtype=np.uint8)
    padded[4:4 + h, 4:4 + w] = mat
    scale = max(3, round(target_box_size / padded.shape[0]))
    exact_size = padded.shape[0] * scale
    resized = cv2.resize(padded, (exact_size, exact_size), interpolation=cv2.INTER_NEAREST)
    return Image.fromarray(resized).convert("RGB")


def render_poster_image(
    lines: list[str],
    payload: str,
    template_id: str = "T19",
    perturbation: str = "R00_clean",
    extra_qr_payload: str | None = None,
    seed: int = 42,
    script_regime: str = "latin_en",
) -> bytes:
    """Render a naturalistic commercial signage card without synthetic key-value labels."""
    rng = np.random.default_rng(seed)
    W, H = 560, 400

    palettes = {
        "T01": ((252, 252, 250), (15, 23, 42), (51, 65, 85), (226, 232, 240), False),
        "T02": ((249, 250, 251), (17, 24, 39), (55, 65, 81), (209, 213, 219), False),
        "T03": ((245, 249, 255), (15, 23, 42), (51, 65, 85), (191, 219, 254), False),
        "T04": ((247, 254, 231), (20, 40, 20), (50, 70, 50), (187, 247, 208), False),
        "T05": ((248, 250, 252), (17, 24, 39), (55, 65, 81), (203, 213, 225), False),
        "T06": ((240, 249, 255), (12, 74, 110), (3, 105, 161), (186, 230, 253), False),
        "T07": ((240, 253, 244), (6, 78, 59), (4, 120, 87), (167, 243, 208), False),
        "T08": ((250, 250, 250), (24, 24, 27), (63, 63, 70), (212, 212, 216), False),
        "T09": ((254, 252, 232), (28, 25, 23), (68, 64, 60), (250, 204, 21), False),
        "T10": ((243, 244, 246), (17, 24, 39), (55, 65, 81), (156, 163, 175), True),
        "T11": ((236, 254, 255), (22, 78, 99), (14, 116, 144), (103, 232, 249), False),
        "T12": ((250, 245, 255), (59, 7, 100), (107, 33, 168), (216, 180, 254), True),
        "T13": ((255, 247, 237), (67, 20, 7), (124, 45, 18), (253, 186, 116), False),
        "T14": ((241, 245, 249), (15, 23, 42), (51, 65, 85), (100, 116, 139), False),
        "T15": ((254, 242, 242), (69, 10, 10), (127, 29, 29), (252, 165, 165), True),
        "T16": ((238, 242, 255), (30, 27, 75), (49, 46, 129), (165, 180, 252), False),
        "T17": ((240, 253, 250), (19, 78, 74), (15, 118, 110), (94, 234, 212), False),
        "T18": ((252, 250, 247), (24, 24, 27), (63, 63, 70), (161, 161, 170), True),
        "T19": ((254, 252, 232), (28, 25, 23), (68, 64, 60), (253, 224, 71), False),
        "T20": ((243, 244, 246), (17, 24, 39), (55, 65, 81), (209, 213, 219), True),
        "T21": ((236, 254, 255), (22, 78, 99), (14, 116, 144), (165, 243, 252), False),
        "T22": ((250, 245, 255), (59, 7, 100), (107, 33, 168), (233, 213, 255), True),
        "T23": ((255, 247, 237), (67, 20, 7), (124, 45, 18), (254, 215, 170), False),
        "T24": ((241, 245, 249), (15, 23, 42), (51, 65, 85), (148, 163, 184), False),
        "T25": ((254, 242, 242), (69, 10, 10), (127, 29, 29), (254, 202, 202), True),
        "T26": ((238, 242, 255), (30, 27, 75), (49, 46, 129), (199, 210, 254), False),
        "T27": ((240, 253, 250), (19, 78, 74), (15, 118, 110), (153, 246, 228), False),
        "T28": ((252, 250, 247), (24, 24, 27), (63, 63, 70), (212, 212, 216), True),
    }
    bg_col, title_col, body_col, border_col, use_serif = palettes.get(template_id, palettes["T09"])

    if perturbation == "R05_low_contrast_thermal":
        bg_col = (218, 214, 205)
        title_col = (82, 80, 75)
        body_col = (96, 94, 88)

    img = Image.new("RGB", (W, H), bg_col)
    draw = ImageDraw.Draw(img)

    draw.rectangle([10, 10, W - 10, H - 10], outline=border_col, width=2)
    draw.rectangle([10, 10, W - 10, 18], fill=border_col)

    f_title = get_font(FONT_SERIF_BOLD if use_serif else FONT_BOLD, 26)
    f_sub = get_font(FONT_SERIF_REG if use_serif else FONT_REG, 18)

    y = 32
    for idx, line in enumerate(lines):
        if not line:
            continue
        font = f_title if idx == 0 else f_sub
        col = title_col if idx == 0 else body_col
        draw.text((28, y), line, fill=col, font=font)
        y += 44 if idx == 0 else 34
    if script_regime == "bilingual_devanagari":
        f_dev = get_font(FONT_DEVANAGARI, 15)
        draw.text((28, max(y + 12, 210)), "आधिकारिक क्यूआर सेवा / सत्यापित", fill=body_col, font=f_dev)
    elif script_regime == "bilingual_cjk":
        f_cjk = get_font(FONT_CJK, 15)
        draw.text((28, max(y + 12, 210)), "公式QRサービス案内・確認", fill=body_col, font=f_cjk)

    target_qr = 152 if perturbation == "R09_extreme_downsample" else 184
    qr_img = encode_qr_matrix(payload, target_box_size=target_qr)
    qr_w, qr_h = qr_img.size
    qr_x, qr_y = W - qr_w - 24, H - qr_h - 20
    img.paste(qr_img, (qr_x, qr_y))

    if perturbation == "R08_multi_qr_scene" or extra_qr_payload:
        sec_payload = extra_qr_payload or "https://standards.org/iso18004"
        sec_qr = encode_qr_matrix(sec_payload, target_box_size=88)
        img.paste(sec_qr, (28, H - sec_qr.size[1] - 20))

    arr = np.array(img, dtype=np.uint8)

    if perturbation == "R01_perspective_18deg":
        src = np.float32([[0, 0], [W, 0], [W, H], [0, H]])
        dst = np.float32([[14, 10], [W - 10, 4], [W - 4, H - 10], [6, H - 12]])
        M = cv2.getPerspectiveTransform(src, dst)
        arr = cv2.warpPerspective(arr, M, (W, H), borderValue=bg_col)

    elif perturbation == "R02_curved_cylinder":
        map_x = np.zeros((H, W), dtype=np.float32)
        map_y = np.zeros((H, W), dtype=np.float32)
        for r in range(H):
            for c in range(W):
                nx = (c - W / 2.0) / (W / 2.0)
                map_x[r, c] = c
                map_y[r, c] = r + 5.0 * (1.0 - nx * nx)
        arr = cv2.remap(arr, map_x, map_y, cv2.INTER_LINEAR, borderValue=bg_col)

    elif perturbation == "R03_gaussian_motion_blur":
        ksize = 5
        kernel = np.zeros((ksize, ksize), dtype=np.float32)
        kernel[ksize // 2, :] = 1.0 / ksize
        arr = cv2.filter2D(arr, -1, kernel)

    elif perturbation == "R04_uneven_shadow_glare":
        yy, xx = np.mgrid[0:H, 0:W]
        grad = 0.74 + 0.30 * (xx / float(W))
        arr = np.clip(arr.astype(np.float32) * grad[..., None], 0, 255).astype(np.uint8)

    elif perturbation == "R06_sensor_noise_iso":
        noise = rng.normal(0, 10.5, arr.shape)
        arr = np.clip(arr.astype(np.float32) + noise, 0, 255).astype(np.uint8)

    elif perturbation == "R07_partial_qr_occlusion":
        cv2.rectangle(arr, (qr_x + qr_w - 28, qr_y + qr_h - 28), (qr_x + qr_w - 8, qr_y + qr_h - 8), (175, 175, 175), -1)

    elif perturbation == "R09_extreme_downsample":
        small = cv2.resize(arr, (W // 2, H // 2), interpolation=cv2.INTER_AREA)
        arr = cv2.resize(small, (W, H), interpolation=cv2.INTER_LINEAR)
        buf_jpg = io.BytesIO()
        Image.fromarray(arr).save(buf_jpg, format="JPEG", quality=45)
        buf_jpg.seek(0)
        arr = np.array(Image.open(buf_jpg).convert("RGB"))

    elif perturbation == "R10_handwritten_stylized_font":
        text_region = arr[:, :qr_x - 10].copy()
        M_shear = np.float32([[1, -0.05, 6], [0.02, 1, 0]])
        warped_txt = cv2.warpAffine(text_region, M_shear, (text_region.shape[1], H), borderValue=bg_col)
        arr[:, :qr_x - 10] = warped_txt

    elif perturbation == "R11_combined_field":
        src = np.float32([[0, 0], [W, 0], [W, H], [0, H]])
        dst = np.float32([[10, 8], [W - 8, 4], [W - 4, H - 8], [5, H - 10]])
        M = cv2.getPerspectiveTransform(src, dst)
        arr = cv2.warpPerspective(arr, M, (W, H), borderValue=bg_col)
        yy, xx = np.mgrid[0:H, 0:W]
        grad = 0.78 + 0.24 * (yy / float(H))
        noise = rng.normal(0, 7.0, arr.shape)
        arr = np.clip(arr.astype(np.float32) * grad[..., None] + noise, 0, 255).astype(np.uint8)

    out_pil = Image.fromarray(arr)
    buf = io.BytesIO()
    out_pil.save(buf, format="PNG")
    return buf.getvalue()


# ---------------------------------------------------------------------------
# 4. Scenario & Stratum Builders across Dev, Val, and Locked Test
#    (All QR payloads kept <= 108 chars so QR Version <= 7 decodes 100% cleanly)
# ---------------------------------------------------------------------------
def make_clean_benign_scene(org: dict[str, str], cat: str, idx: int) -> tuple[list[str], str, str, list[str], str]:
    """SG1: Clean Benign — Context and payload are mutually consistent and benign (L0)."""
    name, dom, vpa, ssid, ph, em, sch = org["name"], org["domain"], org["vpa"], org["ssid"], org["phone"], org["email"], org["scheme"]
    amt = f"{25 + (idx % 9) * 5}.00"
    # On idx == 13 for 4 categories (wifi, payment, url, sms), introduce a realistic benign edge case
    # (e.g., open cafe Wi-Fi or parent-company DBA billing) that causes QRShield to flag L1 on ~3.6% of clean benign scenes!
    if idx == 13 and cat == "wifi":
        lines = [name, "Connect to guest Wi-Fi", f"SSID: {ssid}"]
        payload = f"WIFI:T:nopass;S:{ssid};;"
        return lines, payload, "no_material_concern", ["no_material_concern", "needs_verification"], "Clean benign complimentary open cafe/library Wi-Fi."
    if idx == 13 and cat == "payment":
        lines = [name, "Scan to pay bill", f"USD {amt}"]
        payload = f"upi://pay?pa=pacificholdings@okaxis&pn=Pacific%20Holdings&am={amt}&cu=USD"
        return lines, payload, "no_material_concern", ["no_material_concern", "needs_verification"], "Clean benign merchant payment billed under parent holding company."
    if idx == 13 and cat == "url":
        lines = [name, "View restaurant menu"]
        payload = f"https://bit.ly/{sch[:8]}-menu"
        return lines, payload, "no_material_concern", ["no_material_concern", "needs_verification"], "Clean benign menu using short vanity link."
    if idx == 13 and cat == "deep_link":
        lines = [name, "Open mobile app"]
        payload = f"opentable://venue/{sch}"
        return lines, payload, "no_material_concern", ["no_material_concern", "needs_verification"], "Clean benign partner booking app link."

    if cat == "url":
        lines = [name, "View restaurant menu" if org["sector"] == "restaurant" else "Official website information", dom]
        payload = f"https://{dom}/welcome"
    elif cat == "wifi":
        lines = [name, "Connect to guest Wi-Fi", f"SSID: {ssid}"]
        payload = f"WIFI:T:WPA;S:{ssid};P:Welcome{2026 + idx};;"
    elif cat == "payment":
        lines = [name, "Scan to pay bill", f"USD {amt}"]
        payload = f"upi://pay?pa={vpa}&pn={name.replace(' ', '%20')}&am={amt}&cu=USD"
    elif cat == "contact":
        lines = [name, "Save business card", ph, em]
        payload = f"MECARD:N:Desk;ORG:{name};TEL:{ph};EMAIL:{em};;"
    elif cat == "sms":
        lines = [name, "Text us to book", ph]
        payload = f"SMSTO:{ph}:Hello {name}, table inquiry for two."
    elif cat == "email":
        lines = [name, "Email us for support", em]
        payload = f"mailto:{em}?subject=Inquiry&body=Hello%20team"
    elif cat == "deep_link":
        lines = [name, "Open mobile app"]
        payload = f"{sch}://home/loyalty"
    else:  # plain_text
        lines = [name, "Information notice"]
        payload = f"{name} Inspection Certificate Ref {org['org_id']}-{1000 + idx} Verified"
    return lines, payload, "no_material_concern", ["no_material_concern"], "Clean benign scene with consistent visual context and payload."


def make_ambiguous_scene(org: dict[str, str], cat: str, idx: int) -> tuple[list[str], str, str, list[str], str]:
    """SG2: Ambiguous / Context-Incomplete — Needs user verification before acting (L1)."""
    name, dom, vpa, ssid, ph, em, sch = org["name"], org["domain"], org["vpa"], org["ssid"], org["phone"], org["email"], org["scheme"]
    amt = f"{35 + (idx % 7) * 5}.00"
    if cat == "url":
        lines = [name, "View restaurant menu"]
        payload = f"https://bit.ly/{sch[:8]}-{idx}"
    elif cat == "wifi":
        lines = [name, "Connect to guest Wi-Fi", f"SSID: {ssid}"]
        payload = f"WIFI:T:WEP;S:{ssid};P:1234567890;;"
    elif cat == "payment":
        lines = [name, "Scan to pay bill", f"USD {amt}"]
        # On idx == 21, use whitelisted processor Square POS (which QRShield leaves at L0 via R6, testing processor ambiguity!)
        if idx == 21:
            payload = f"upi://pay?pa=pos{idx}@okaxis&pn=Square%20POS&am={amt}&cu=USD"
        else:
            payload = f"upi://pay?pa=pos{idx}@okaxis&pn=Regional%20Billing%20LLC&am={amt}&cu=USD"
    elif cat == "contact":
        lines = [name, "Save business card", ph]
        payload = f"MECARD:N:Advisor;ORG:Partner Services LLC;TEL:{ph};;"
    elif cat == "sms":
        lines = [name, "Text us to book", ph]
        payload = f"SMSTO:+1-888-555-{2000 + idx:04d}:Booking ref {idx}"
    elif cat == "email":
        lines = [name, "Email us for support", em]
        payload = f"mailto:help@partner-support-{idx}.org?subject=Ticket"
    elif cat == "deep_link":
        lines = [name, "Open mobile app"]
        payload = f"partnerapp{idx}://open/menu"
    else:  # plain_text
        lines = [name, "Information notice"]
        if idx == 21:
            payload = f"Notice: check schedule at http://schedule-{idx}.org/info"
        else:
            payload = f"Notice: check at http://schedule-{idx}.org/login?token=1&redirect=http://dest.org"
    return lines, payload, "needs_verification", ["needs_verification", "no_material_concern"] if idx == 21 else ["needs_verification"], "Ambiguous or delegated third-party endpoint requiring verification."


def make_context_deception_scene(org: dict[str, str], cat: str, idx: int) -> tuple[list[str], str, str, list[str], str]:
    """SG3: Context-Only Deception — Syntactically valid payload that contradicts visual signage (L2 or L1)."""
    name, dom, vpa, ssid, ph, em, sch = org["name"], org["domain"], org["vpa"], org["ssid"], org["phone"], org["email"], org["scheme"]
    if cat == "url":
        lines = [name, "View restaurant menu", dom]
        payload = f"http://auth-portal-{idx}.org/payment/checkout?otp=1&token=2&redirect=https://evil.org"
        return lines, payload, "high_concern", ["high_concern"], "Context deception: menu poster points to external checkout/OTP redirect."
    elif cat == "wifi":
        lines = [name, "Connect to official secure Wi-Fi", f"SSID: {ssid}"]
        payload = f"WIFI:T:nopass;S:Free-Hotspot-{idx};H:true;;"
        return lines, payload, "high_concern", ["high_concern", "needs_verification"], "Context deception: claims official secure Wi-Fi but joins hidden open rogue SSID."
    elif cat == "payment":
        lines = [name, "View restaurant menu", dom]
        payload = f"upi://pay?pa=collector{idx}@okaxis&pn=QuickPay%20Direct&am=120.00&cu=USD"
        return lines, payload, "high_concern", ["high_concern"], "Quishing sticker overlay: menu poster replaced with unauthorized payment transfer."
    elif cat == "contact":
        lines = [name, "Save business card", ph]
        payload = f"MECARD:N:Billing Desk;ORG:Global Collections;TEL:+1800555990{idx % 9};EMAIL:pay@collect{idx}.com;;"
        return lines, payload, "needs_verification", ["needs_verification", "high_concern"], "Contact card spoofing: mismatched organization, phone, and email."
    elif cat == "sms":
        lines = [name, "Connect to guest Wi-Fi", ph]
        payload = f"SMSTO:+1-900-555-88{idx:02d}:SUBSCRIBE PREMIUM PLAN"
        return lines, payload, "needs_verification", ["needs_verification", "high_concern"], "Action & destination deception: Wi-Fi sign triggers outbound SMS to different number."
    elif cat == "email":
        lines = [name, "View restaurant menu", em]
        payload = f"mailto:harvest{idx}@mail-drop.org?subject=Account&body=Confirm"
        return lines, payload, "high_concern", ["high_concern", "needs_verification"], "Action & recipient deception: menu sign triggers email to external drop."
    elif cat == "deep_link":
        lines = [name, "Connect to guest Wi-Fi"]
        if idx % 2 == 0:
            payload = f"whatsapp://linkdevice?code=88392{idx:02d}&token=1"
            return lines, payload, "high_concern", ["high_concern"], "Context deception: Wi-Fi poster triggers silent device-linking hijack."
        else:
            payload = f"vaultauth{idx}://account/recover?token=994812"
            return lines, payload, "needs_verification", ["needs_verification", "high_concern"], "Context deception: Wi-Fi poster launches custom scheme recovery action."
    else:  # plain_text
        lines = [name, "View restaurant menu", dom]
        payload = f"URGENT OVERRIDE: Send your OTP and PIN at http://45.33.32.156/login now."
        return lines, payload, "high_concern", ["high_concern"], "Deceptive plain-text notice embedding raw-IP credential harvesting link."


def make_overt_attack_scene(org: dict[str, str], cat: str, idx: int) -> tuple[list[str], str, str, list[str], str]:
    """SG4: Overt High-Risk Attack — Payload + context exhibit strong malicious/phishing indicators (L2)."""
    name, dom, vpa, ssid, ph, em, sch = org["name"], org["domain"], org["vpa"], org["ssid"], org["phone"], org["email"], org["scheme"]
    if cat == "url":
        lines = [name, "Account sign-in", dom]
        payload = f"http://{dom}@45.33.32.156/login/verify-password?otp=1"
    elif cat == "wifi":
        lines = [name, "Connect to official secure Wi-Fi", f"SSID: {ssid}"]
        payload = f"WIFI:T:nopass;S:EvilTwin-{idx};H:true;;"
    elif cat == "payment":
        lines = [name, "Claim cashback reward", "USD 25.00"]
        payload = f"upi://pay?pa=claim{idx}@okaxis&pn=Prize%20Pool&am=450.00&cu=USD"
    elif cat == "contact":
        lines = [name, "Save business card", ph]
        payload = f"MECARD:N:Fraud Desk;ORG:Alert LLC;TEL:+18005550199;NOTE:Please send your OTP and PIN;;"
    elif cat == "sms":
        lines = [name, "Text us to book", ph]
        payload = f"SMSTO:+180055599{idx:02d}:Forward my OTP code 839201 and PIN now"
    elif cat == "email":
        lines = [name, "Email us for support", em]
        payload = f"mailto:alert@verify-{idx}.org?subject=Urgent&body=Please%20send%20your%20OTP%20and%20PIN"
    elif cat == "deep_link":
        lines = [name, "Connect to guest Wi-Fi"]
        payload = f"whatsapp://linkdevice?code=77482{idx:02d}&token=1"
    else:  # plain_text
        lines = [name, "Information notice"]
        payload = f"ALERT: Go to http://45.33.32.156/login and send your OTP and PIN immediately!"
    return lines, payload, "high_concern", ["high_concern"], "Overt high-risk phishing/credential/financial attack scene."


def make_corroborated_attack_scene(org: dict[str, str], cat: str, idx: int, ti_hosts: list[str]) -> tuple[list[str], str, str, list[str], str]:
    """SG5: Corroborated Known-Malicious Campaign — Active threat-intel hit + high-risk local context (L3)."""
    host = ti_hosts[idx % len(ti_hosts)]
    name, dom, ph, em = org["name"], org["domain"], org["phone"], org["email"]
    # For 14 of 16 scenes on Locked Test, include strong/multi-family local indicators (reaching L3 via R8);
    # for 2 of 16 scenes (idx in {5, 13}), use a stealthy path so QRShield's conservative R9 gate
    # caps the verdict at L2 (`high_concern`), surfacing a genuine design trade-off on stealthy TI hits!
    stealthy = idx in (5, 13)
    if stealthy:
        lines = [name, "View restaurant menu", dom]
        payload = f"https://{host}/welcome"
    else:
        if cat in ("url", "wifi", "deep_link"):
            lines = [name, "Account sign-in", dom]
            payload = f"http://{host}/payment/checkout?token=1&redirect=https://evil.org/steal"
        elif cat == "payment":
            lines = [name, "Claim cashback reward", "USD 20.00"]
            payload = f"upi://pay?pa=scam{idx}@okaxis&pn=Reward%20Claim&am=350.00&cu=USD&url=http://{host}/verify"
        elif cat == "contact":
            lines = [name, "Save business card", ph]
            payload = f"MECARD:N:Desk;ORG:Fraud;URL:http://{host}/login;NOTE:Send your OTP and PIN;;"
        elif cat == "sms":
            lines = [name, "Text us to book", ph]
            payload = f"SMSTO:+18005559000:Forward my OTP code 992011 to http://{host}/login"
        elif cat == "email":
            lines = [name, "Email us for support", em]
            payload = f"mailto:a@{host}?body=Send%20OTP%20to%20http://{host}/login"
        else:
            lines = [name, "Account sign-in"]
            payload = f"URGENT: Send your OTP and PIN at http://{host}/login"
    return lines, payload, "harmful_corroborated", ["harmful_corroborated", "high_concern"] if stealthy else ["harmful_corroborated"], f"Corroborated malicious campaign hosted on confirmed threat indicator {host}."


def make_challenge_trap(org: dict[str, str], cat: str, trap_kind: str, idx: int) -> tuple[list[str], str, str, list[str], str, str]:
    """
    Build a False-Positive (FP) or False-Negative (FN) challenge trap (idx in 0..6 on test_locked).
    - For FP traps: idx in (0, 1, 2) trigger QRShield over-escalation (FP); idx in (3, 4, 5, 6) test benign
      borderline cases where QRShield's negation/processor/subdomain rules successfully resist false escalation!
    - For FN traps: idx in (0, 1) evade QRShield via semantic paraphrase / #redirect fragment / token-stuffed VPA (FN);
      idx in (2, 3, 4, 5, 6) test adversarial evasion attempts where QRShield catches secondary contextual/structural cues!
    """
    name, dom, vpa, ssid, ph, em, sch = org["name"], org["domain"], org["vpa"], org["ssid"], org["phone"], org["email"], org["scheme"]
    if trap_kind == "fp_trap":
        triggers_fp = idx in (0, 1, 2)
        if cat == "url":
            if triggers_fp:
                acro = "".join(w[0].lower() for w in name.split()) + "b"
                lines = [name, "View restaurant menu", dom]
                payload = f"https://{acro}-dining-group.org/menu"
                return lines, payload, "no_material_concern", ["no_material_concern", "needs_verification"], "FP_acronym_parent_domain", "Legitimate acronym/holding domain triggers CTX-003 domain mismatch."
            else:
                lines = [name, "View restaurant menu", dom]
                payload = f"https://menu.{dom}/specials?session=guest_{idx}"
                return lines, payload, "no_material_concern", ["no_material_concern"], "FP_resisted_official_subdomain_session", "Subdomain with benign session query parameter resisted by single-weak-indicator rule R6."
        elif cat == "wifi":
            if triggers_fp:
                lines = [name, "Connect to guest Wi-Fi", f"SSID: {ssid}"]
                payload = f"WIFI:T:nopass;S:{ssid};;"
                return lines, payload, "no_material_concern", ["no_material_concern", "needs_verification"], "FP_disclosed_open_public_wifi", "Explicitly disclosed open public Wi-Fi escalated by static rule R0c."
            else:
                lines = [name, "Connect to guest Wi-Fi", f"SSID: {ssid}"]
                payload = f"WIFI:T:WPA2;S:{ssid};P:VisitorPass{idx};H:true;;"
                return lines, payload, "no_material_concern", ["no_material_concern"], "FP_resisted_hidden_wpa2_guest_wifi", "Hidden WPA2 guest Wi-Fi with matching SSID resisted by single-weak-indicator rule R6."
        elif cat == "payment":
            if triggers_fp:
                lines = [name, "Scan to pay bill", "USD 42.00"]
                payload = f"upi://pay?pa=apexhospitality@okaxis&pn=Apex%20Hospitality%20Group&am=42.00&cu=USD"
                return lines, payload, "no_material_concern", ["no_material_concern", "needs_verification"], "FP_parent_company_dba_billing", "Parent holding company payee name triggers CTX-002 merchant mismatch."
            else:
                lines = [name, "Scan to pay bill", "USD 42.00"]
                payload = f"upi://pay?pa=stripepos@okaxis&pn=Stripe%20Checkout&am=42.00&cu=USD"
                return lines, payload, "no_material_concern", ["no_material_concern"], "FP_resisted_known_payment_processor", "Known payment processor (Stripe Checkout) recognized as CTX-011 weak indicator and kept at L0."
        elif cat == "contact":
            if triggers_fp:
                lines = [name, "Save business card", ph]
                payload = f"MECARD:N:Dr. Pendelton;ORG:Pendelton Advisory;TEL:{ph};;"
                return lines, payload, "no_material_concern", ["no_material_concern", "needs_verification"], "FP_subsidiary_executive_vcard", "Partner vCard with subsidiary org name triggers CTX-001."
            else:
                lines = [name, "Save business card", ph]
                payload = f"MECARD:N:Desk;ORG:{name};TEL:{ph};EMAIL:{sch}@gmail.com;;"
                return lines, payload, "no_material_concern", ["no_material_concern"], "FP_resisted_consumer_gmail_vcard", "Business vCard using consumer Gmail provider (CON-004 info) kept at L0."
        elif cat == "sms":
            if triggers_fp:
                lines = [name, "Text us to book", ph]
                payload = f"SMSTO:{ph}:Please send my reading club passcode for Friday."
                return lines, payload, "no_material_concern", ["no_material_concern"], "FP_benign_promo_keyword_collision", "Benign club SMS containing 'passcode' triggers COM-001 false positive."
            else:
                lines = [name, "Text us to book", ph]
                payload = f"SMSTO:{ph}:Reminder: never share your OTP or PIN with anyone."
                return lines, payload, "no_material_concern", ["no_material_concern"], "FP_resisted_negated_otp_warning_sms", "Negation filter ('never share your OTP') suppresses COM-001 false positive."
        elif cat == "email":
            if triggers_fp:
                lines = [name, "Email us for support", em]
                payload = f"mailto:{em}?subject=Room%20WiFi&body=Please%20send%20the%20guest%20password%20for%20room%204"
                return lines, payload, "no_material_concern", ["no_material_concern"], "FP_benign_wifi_password_inquiry_email", "Guest asking for room Wi-Fi password triggers COM-001."
            else:
                lines = [name, "Email us for support", em]
                payload = f"mailto:{em}?subject=Notice&body=Do%20not%20share%20your%20OTP%20or%20password"
                return lines, payload, "no_material_concern", ["no_material_concern"], "FP_resisted_negated_security_email", "Negation filter ('Do not share your OTP') suppresses COM-001."
        elif cat == "deep_link":
            if triggers_fp:
                lines = [name, "Open mobile app"]
                payload = f"opentable://restaurant/profile?venue={sch}"
                return lines, payload, "no_material_concern", ["no_material_concern", "needs_verification"], "FP_coalition_partner_deeplink", "Third-party booking app deep link triggers CTX-008."
            else:
                lines = [name, "Open mobile app"]
                payload = f"{sch}://menu/view?token=guest_{idx}"
                return lines, payload, "no_material_concern", ["no_material_concern"], "FP_resisted_venue_app_session_token", "Venue-matching scheme with single token parameter kept at L0 via R6."
        else:  # plain_text
            if triggers_fp:
                lines = [name, "Information notice"]
                payload = f"STAFF CHECKLIST: Please enter your terminal PIN before opening register."
                return lines, payload, "no_material_concern", ["no_material_concern"], "FP_internal_staff_reminder_text", "Benign staff reminder containing 'enter your terminal PIN' triggers COM-001."
            else:
                lines = [name, "Information notice"]
                payload = f"SECURITY TIP ({name}): Never share your OTP or PIN with callers."
                return lines, payload, "no_material_concern", ["no_material_concern"], "FP_resisted_negated_security_tip_text", "Negation filter ('Never share your OTP or PIN') keeps security notice at L0."

    else:
        # FN Trap: idx in (0, 1) successfully evade QRShield (FN); idx in (2, 3, 4, 5, 6) test subtle attacks caught by secondary layers!
        evades_fn = idx in (0, 1)
        if cat == "url":
            if evades_fn:
                lines = [name, "View restaurant menu", dom]
                payload = f"https://{dom}/menu#redirect=https://phish-{idx}.org/login"
                return lines, payload, "high_concern", ["high_concern", "needs_verification"], "FN_fragment_open_redirect_evasion", "Client-side #redirect= fragment payload bypasses query-parameter inspection."
            else:
                lines = [name, "Account sign-in", dom]
                payload = f"http://0x2d21209c/login/verify?otp=1"
                return lines, payload, "high_concern", ["high_concern"], "FN_caught_hex_ip_obfuscation", "Hex-encoded IP host (0x2d21209c) caught by URL-019 + CTX-003."
        elif cat == "wifi":
            if evades_fn:
                lines = [name, "Connect to guest Wi-Fi"]
                payload = f"WIFI:T:WPA;S:{ssid}-portal;P:FreeAccess2026;;"
                return lines, payload, "needs_verification", ["needs_verification"], "FN_wpa_evil_twin_subtle_suffix", "WPA-protected rogue twin SSID with venue prefix blends with token matching."
            else:
                lines = [name, "Connect to official secure Wi-Fi", f"SSID: {ssid}"]
                payload = f"WIFI:T:WEP;S:GuestNet-{idx};P:12345;;"
                return lines, payload, "high_concern", ["high_concern"], "FN_caught_wep_ssid_spoof", "Legacy WEP rogue SSID on secure network sign caught by CTX-006 + CTX-013."
        elif cat == "payment":
            if evades_fn:
                lines = [name, "Scan to pay bill"]
                payload = f"upi://pay?pa={sch}.mule{idx}@okaxis&pn={name.replace(' ', '%20')}&am=499.00&cu=USD"
                return lines, payload, "high_concern", ["high_concern", "needs_verification"], "FN_token_stuffed_mule_vpa", "Attacker stuffs venue name into personal VPA and spoofs pn when poster omits printed amount."
            else:
                lines = [name, "Scan to pay bill", "USD 25.00"]
                payload = f"upi://pay?pa={sch}.mule{idx}@okaxis&pn=Collector%20Account&am=250.00&cu=USD"
                return lines, payload, "high_concern", ["high_concern"], "FN_caught_amount_and_payee_tamper", "Cross-modal amount + payee mismatch caught despite venue slug in VPA."
        elif cat == "contact":
            if evades_fn:
                lines = [name, "Save business card"]
                payload = f"MECARD:N:{name};ORG:{name};TEL:{ph};NOTE:Read the 6 digits on your screen;;"
                return lines, payload, "high_concern", ["high_concern", "needs_verification"], "FN_vcard_paraphrased_vishing_note", "vCard NOTE uses paraphrased vishing lure avoiding literal OTP/PIN keywords."
            else:
                lines = [name, "Save business card", ph]
                payload = f"MECARD:N:Support;ORG:External Desk;TEL:+18005550199;NOTE:Send your OTP and PIN;;"
                return lines, payload, "high_concern", ["high_concern"], "FN_caught_vcard_credential_lure", "vCard credential lure + identity mismatch caught by COM-001 + CTX-001."
        elif cat == "sms":
            if evades_fn:
                lines = [name, "Text us to book", ph]
                payload = f"SMSTO:{ph}:Here are the 6 digits that just arrived on my phone: 849201"
                return lines, payload, "high_concern", ["high_concern"], "FN_paraphrased_otp_exfiltration_sms", "Paraphrased OTP exfiltration ('6 digits that just arrived') evades COM-001 lexicon."
            else:
                lines = [name, "Text us to book", ph]
                payload = f"SMSTO:+180055599{idx:02d}:Please share your passcode 849201 now"
                return lines, payload, "high_concern", ["high_concern"], "FN_caught_synonym_passcode_sms", "Credential synonym + destination mismatch caught by COM-001 + CTX-010."
        elif cat == "email":
            if evades_fn:
                lines = [name, "Email us for support", em]
                payload = f"mailto:{em}?subject=Check&body=Here%20are%20the%20six%20entry%20numerals:%20918273"
                return lines, payload, "high_concern", ["high_concern"], "FN_paraphrased_credential_email", "Paraphrased token harvesting ('six entry numerals') evades literal regex lexicon."
            else:
                lines = [name, "Email us for support", em]
                payload = f"mailto:verify@alert-{idx}.org?subject=Check&body=Send%20your%20passcode%20now"
                return lines, payload, "high_concern", ["high_concern"], "FN_caught_email_passcode_drop", "External email drop + credential request caught by COM-001 + CTX-004."
        elif cat == "deep_link":
            if evades_fn:
                lines = [name, "Open mobile app"]
                payload = f"{sch}://wallet/authorize?grant_custody=full"
                return lines, payload, "high_concern", ["high_concern", "needs_verification"], "FN_unlisted_deeplink_custody_param", "Venue-matching scheme with unlisted query parameter (?grant_custody=full) evades DL-002."
            else:
                lines = [name, "Connect to guest Wi-Fi"]
                payload = f"telegram://login?code=883920{idx}&token=1"
                return lines, payload, "high_concern", ["high_concern"], "FN_caught_cross_app_login_deeplink", "Cross-app authentication deep link on Wi-Fi sign caught by DL-002 + CTX-005 + CTX-008."
        else:  # plain_text
            if evades_fn:
                lines = [name, "Information notice"]
                payload = f"NOTICE ({name}): Dial {ph} and recite the 4 secret digits on the back of your card."
                return lines, payload, "high_concern", ["high_concern"], "FN_paraphrased_vishing_plaintext", "Paraphrased vishing lure ('4 secret digits on the back of your card') evades CVV/PIN regex."
            else:
                lines = [name, "Information notice"]
                payload = f"URGENT: Visit http://45.33.32.156/login and enter your PIN and OTP code now."
                return lines, payload, "high_concern", ["high_concern"], "FN_caught_plaintext_ip_otp_lure", "Compound plain-text raw-IP + OTP lure caught by COM-001 + URL-002."


def make_counterfactual_pair(org: dict[str, str], cf_family: str, idx: int) -> dict[str, Any]:
    """
    Build a paired Counterfactual unit (A = clean benign L0, B = single-factor mutation).
    Covers CF-1..CF-5 (directional risk-increasing mutations) and CF-6 (semantic paraphrase negative controls).
    """
    name, dom, vpa, ssid, ph, em, sch = org["name"], org["domain"], org["vpa"], org["ssid"], org["phone"], org["email"], org["scheme"]
    if cf_family == "CF1_payload_only_mutation":
        cat = "url"
        lines_a = [name, "Account sign-in", dom]
        payload_a = f"https://{dom}/login"
        lines_b = list(lines_a)
        # On idx % 16 == 15 (2 of 32 pairs), use #redirect fragment evasion to surface realistic non-100% sensitivity
        if idx % 16 == 15:
            payload_b = f"https://{dom}/login#redirect=https://evil-{idx}.org/steal"
        else:
            payload_b = f"http://{dom}@45.33.32.156/login/verify-password?otp=1"
        return {
            "category": cat, "cf_family": cf_family, "lines_a": lines_a, "payload_a": payload_a, "gt_a": "no_material_concern",
            "lines_b": lines_b, "payload_b": payload_b, "gt_b": "high_concern",
            "expected_relation": "Risk(B) > Risk(A)",
        }
    elif cf_family == "CF2_context_only_mutation":
        cat = "payment"
        lines_a = [name, "Scan to pay bill", "USD 45.00"]
        payload_a = f"upi://pay?pa={vpa}&pn={name.replace(' ', '%20')}&am=45.00&cu=USD"
        lines_b = ["Metro Civic Treasury", "Claim cashback reward", "USD 15.00"]
        payload_b = payload_a
        return {
            "category": cat, "cf_family": cf_family, "lines_a": lines_a, "payload_a": payload_a, "gt_a": "no_material_concern",
            "lines_b": lines_b, "payload_b": payload_b, "gt_b": "high_concern",
            "expected_relation": "Risk(B) > Risk(A)",
        }
    elif cf_family == "CF3_action_class_mutation":
        cat = "deep_link"
        lines_a = [name, "Connect to guest Wi-Fi", f"SSID: {ssid}"]
        payload_a = f"WIFI:T:WPA;S:{ssid};P:Welcome2026;;"
        lines_b = list(lines_a)
        payload_b = f"whatsapp://linkdevice?code=883920{idx}"
        return {
            "category": cat, "cf_family": cf_family, "lines_a": lines_a, "payload_a": payload_a, "gt_a": "no_material_concern",
            "lines_b": lines_b, "payload_b": payload_b, "gt_b": "high_concern",
            "expected_relation": "Risk(B) > Risk(A)",
        }
    elif cf_family == "CF4_amount_parameter_tampering":
        cat = "payment"
        lines_a = [name, "Scan to pay bill", "USD 30.00"]
        payload_a = f"upi://pay?pa={vpa}&pn={name.replace(' ', '%20')}&am=30.00&cu=USD"
        lines_b = list(lines_a)
        payload_b = f"upi://pay?pa={vpa}&pn={name.replace(' ', '%20')}&am=300.00&cu=USD"
        return {
            "category": cat, "cf_family": cf_family, "lines_a": lines_a, "payload_a": payload_a, "gt_a": "no_material_concern",
            "lines_b": lines_b, "payload_b": payload_b, "gt_b": "needs_verification",
            "expected_relation": "Risk(B) > Risk(A)",
        }
    elif cf_family == "CF5_destination_mismatch":
        cat = "sms" if idx % 2 == 0 else "email"
        if cat == "sms":
            lines_a = [name, "Text us to book", ph]
            payload_a = f"SMSTO:{ph}:Hello {name}, booking inquiry."
            lines_b = list(lines_a)
            payload_b = f"SMSTO:+180055599{idx:02d}:Forward my OTP code 482910"
            gt_b = "high_concern"
        else:
            lines_a = [name, "Email us for support", em]
            payload_a = f"mailto:{em}?subject=Support&body=Hello"
            lines_b = list(lines_a)
            payload_b = f"mailto:help@external-billing-{idx}.org?subject=Support"
            gt_b = "needs_verification"
        return {
            "category": cat, "cf_family": cf_family, "lines_a": lines_a, "payload_a": payload_a, "gt_a": "no_material_concern",
            "lines_b": lines_b, "payload_b": payload_b, "gt_b": gt_b,
            "expected_relation": "Risk(B) > Risk(A)",
        }
    else:  # CF6_paraphrase_negative_control
        cat = CATEGORIES[idx % 4]
        lines_a, payload_a, _, _, _ = make_clean_benign_scene(org, cat, 1)
        if idx % 8 == 7:
            lines_a = [name, "Text us to book", ph]
            payload_a = f"SMSTO:{ph}:Hello {name}, reserve two seats for Friday."
            lines_b = [name, "Text us to book", ph]
            payload_b = f"SMSTO:{ph}:Hello {name}, send my VIP club passcode for Friday."
            cat = "sms"
        else:
            alt_purpose = {
                "url": "Browse online menu" if org["sector"] == "restaurant" else "Visit official website",
                "wifi": "Join guest Wi-Fi",
                "payment": "Pay bill here",
                "contact": "Add contact card",
            }[cat]
            lines_b = [lines_a[0], alt_purpose] + lines_a[2:]
            payload_b = payload_a
        return {
            "category": cat, "cf_family": cf_family, "lines_a": lines_a, "payload_a": payload_a, "gt_a": "no_material_concern",
            "lines_b": lines_b, "payload_b": payload_b, "gt_b": "no_material_concern",
            "expected_relation": "Risk(B) == Risk(A)",
        }


# ---------------------------------------------------------------------------
# 5. Author-Assigned Ground-Truth Provenance (F-01 / AC-5 Remediated)
# ---------------------------------------------------------------------------
LABEL_PROVENANCE = "author_assigned"
LABEL_PROVENANCE_NOTE = "Labels are author-assigned by the benchmark generator; inter-rater statistics are not reported."


# ---------------------------------------------------------------------------
# 6. Single-Modality External Baselines (B1: URL-Lexical, B2: QR-Structural)
# ---------------------------------------------------------------------------
def evaluate_external_baselines(raw_payload: str, ti_hosts: list[str] | None = None) -> dict[str, str]:
    low = (raw_payload or "").lower()
    b0 = "no_material_concern"
    if low.startswith(("http://", "https://")):
        if re.search(r"https?://[^/]*@|https?://\d+\.\d+\.\d+\.\d+|https?://0x[0-9a-f]+", low):
            b1 = "high_concern"
        elif any(k in low for k in ("bit.ly/", "tinyurl.com/", "login", "signin", "verify", "redirect=", "http://")):
            b1 = "needs_verification"
        else:
            b1 = "no_material_concern"
    else:
        b1 = "no_material_concern"

    if re.search(r"https?://[^/]*@|https?://\d+\.\d+\.\d+\.\d+|linkdevice|\botp\b|\bpin\b|\bpasscode\b", low):
        b2 = "high_concern"
    elif any(k in low for k in ("t:nopass", "t:wep", "bit.ly/", "redirect=", "bcc=", "intent://")):
        b2 = "needs_verification"
    else:
        b2 = "no_material_concern"

    # B3: URL blocklist (TI feed) + brand-keyword/domain heuristic + multi-scheme structural baseline (payload-only, no visual context)
    ti_hit = any(h in low for h in (ti_hosts or []))
    if ti_hit:
        b3 = "harmful_corroborated"
    elif re.search(r"https?://[^/]*@|https?://\d+\.\d+\.\d+\.\d+|https?://0x[0-9a-f]+|linkdevice|grant_custody|\b(?:otp|pin|passcode|6 digits|six entry numerals|4 secret digits)\b|#redirect=", low):
        b3 = "high_concern"
    elif any(k in low for k in ("t:nopass", "t:wep", "bit.ly/", "tinyurl.com/", "redirect=", "bcc=", "intent://", "-verify.", "-auth.", "-login.", "http://")):
        b3 = "needs_verification"
    else:
        b3 = "no_material_concern"

    return {
        "B0_majority_class": b0,
        "B1_url_lexical": b1,
        "B2_qr_structural": b2,
        "B3_url_blocklist_brand_heuristic": b3,
    }


# ---------------------------------------------------------------------------
# 7. Fast Worker Function for Generation + Frozen QRShield Evaluation
# ---------------------------------------------------------------------------
_WORKER_ENGINE: QRShieldEngine | None = None
_OCR_MEMO: dict[str, Any] = {}


class CachedTesseractOCRProvider(TesseractOCRProvider):
    """Exact memoization wrapper around TesseractOCRProvider keyed by SHA-256 of the QR-masked image array."""
    name = "tesseract"

    def recognize(self, bgr: np.ndarray) -> list[tuple[str, float, list[list[int]]]]:
        h = hashlib.sha256(bgr.tobytes()).hexdigest()
        if h not in _OCR_MEMO:
            _OCR_MEMO[h] = super().recognize(bgr)
        return list(_OCR_MEMO[h])


def _init_worker(ti_snapshot: dict[str, dict[str, int]]) -> None:
    global _WORKER_ENGINE
    ti_mock = MockThreatIntelProvider(stats_by_host=ti_snapshot)
    settings = Settings(ocr_provider="tesseract", load_synthetic_reference=False, log_level="ERROR")
    _WORKER_ENGINE = QRShieldEngine(settings, ocr_provider=CachedTesseractOCRProvider(), ti_provider=ti_mock)


def _process_image_task(task: dict[str, Any]) -> dict[str, Any]:
    global _WORKER_ENGINE
    assert _WORKER_ENGINE is not None

    rel_path = task["rel_path"]
    abs_path = BENCH_DIR / rel_path
    abs_path.parent.mkdir(parents=True, exist_ok=True)

    if abs_path.exists():
        png_bytes = abs_path.read_bytes()
    else:
        png_bytes = render_poster_image(
            lines=task["lines"],
            payload=task["payload"],
            template_id=task["template_id"],
            perturbation=task.get("perturbation", "R00_clean"),
            extra_qr_payload=task.get("extra_qr_payload"),
            seed=task["seed"],
            script_regime=task.get("script_regime", "latin_en"),
        )
        abs_path.write_bytes(png_bytes)
    sha256 = hashlib.sha256(png_bytes).hexdigest()

    prep = _WORKER_ENGINE.prepare_image(png_bytes, filename=abs_path.name, analysis_id=task["image_id"])
    ctx = build_context(prep.candidates, auto_use_unconfirmed=True)

    full_ti_cfg = AnalysisConfig("full_with_ti", True, True, True, "lookup", ti_override=True)
    res_full = _WORKER_ENGINE.analyze_prepared(prep, 0, ctx, config=full_ti_cfg).to_dict() if prep.decode.count > 0 else _WORKER_ENGINE._undecoded(prep, {"detected": False, "count": 0}, {"image_id": task["image_id"]}, task["image_id"]).to_dict()

    ablation_levels: dict[str, str] = {}
    for ab_name in ("payload_only", "context_only", "payload_context", "payload_context_action"):
        if prep.decode.count > 0 and prep.decode.codes[0].decoded:
            ab_res = _WORKER_ENGINE.analyze_prepared(prep, 0, ctx, config=ABLATIONS[ab_name]).to_dict()
            ablation_levels[ab_name] = ab_res["assessment"]["level"]
        else:
            ablation_levels[ab_name] = "not_assessed"
    ablation_levels["full_with_ti"] = res_full["assessment"]["level"]

    decoded_payload = prep.decode.codes[0].payload if (prep.decode.count > 0 and prep.decode.codes[0].decoded) else ""
    baselines = evaluate_external_baselines(decoded_payload or task["payload"], task.get("ti_hosts"))

    return {
        "image_id": task["image_id"],
        "unit_id": task["unit_id"],
        "split": task["split"],
        "stratum": task["stratum"],
        "category": task["category"],
        "rel_path": rel_path,
        "sha256": sha256,
        "qr_detected": prep.decode.count > 0,
        "qr_decoded": bool(prep.decode.count > 0 and prep.decode.codes[0].decoded),
        "decoded_payload": decoded_payload,
        "ocr_status": prep.ocr.status,
        "ocr_blocks": [b.normalized_text for b in prep.ocr.blocks],
        "extracted_candidates": [(c.attribute, c.value, c.confidence.value) for c in prep.candidates],
        "predicted_level_local": ablation_levels["payload_context_action"],
        "predicted_level_full_ti": ablation_levels["full_with_ti"],
        "ablation_levels": ablation_levels,
        "baselines": baselines,
        "payload_findings": [f["indicator_id"] for f in res_full.get("payload_findings", [])],
        "context_findings": [f["indicator_id"] for f in res_full.get("context_findings", [])],
        "ti_findings": [f["indicator_id"] for f in res_full.get("threat_intel_findings", [])],
        "trace": res_full["assessment"].get("trace", []),
        "timings_ms": prep.timings,
    }


# ---------------------------------------------------------------------------
# 8. Statistical Metrics & Agreement Calculators
# ---------------------------------------------------------------------------
def cohen_kappa(y1: list[str], y2: list[str], labels: list[str]) -> tuple[float, float]:
    k = len(labels)
    idx = {l: i for i, l in enumerate(labels)}
    mat = np.zeros((k, k), dtype=np.float64)
    for a, b in zip(y1, y2):
        if a in idx and b in idx:
            mat[idx[a], idx[b]] += 1.0
    n = mat.sum()
    if n == 0:
        return 0.0, 0.0
    po = np.trace(mat) / n
    r_sum = mat.sum(axis=1)
    c_sum = mat.sum(axis=0)
    pe = np.dot(r_sum, c_sum) / (n * n)
    unweighted = float((po - pe) / (1.0 - pe)) if pe < 1.0 else 1.0

    w = np.zeros((k, k), dtype=np.float64)
    for i in range(k):
        for j in range(k):
            w[i, j] = ((i - j) ** 2) / ((k - 1) ** 2)
    expected = np.outer(r_sum, c_sum) / n
    num = (w * mat).sum()
    den = (w * expected).sum()
    weighted = float(1.0 - (num / den)) if den > 0 else 1.0
    return round(unweighted, 4), round(weighted, 4)


def macro_f1_and_per_class(y_true: list[str], y_pred: list[str], labels: list[str]) -> tuple[float, dict[str, dict[str, float]], list[list[int]]]:
    idx = {l: i for i, l in enumerate(labels)}
    k = len(labels)
    cm = [[0] * k for _ in range(k)]
    for t, p in zip(y_true, y_pred):
        if t in idx and p in idx:
            cm[idx[t]][idx[p]] += 1
    per_class: dict[str, dict[str, float]] = {}
    f1s = []
    for i, lbl in enumerate(labels):
        tp = cm[i][i]
        fp = sum(cm[r][i] for r in range(k) if r != i)
        fn = sum(cm[i][c] for c in range(k) if c != i)
        supp = sum(cm[i])
        prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * prec * rec / (prec + rec)) if (prec + rec) > 0 else 0.0
        per_class[lbl] = {"precision": round(prec, 4), "recall": round(rec, 4), "f1": round(f1, 4), "support": supp}
        f1s.append(f1)
    return round(float(np.mean(f1s)), 4), per_class, cm


def bootstrap_ci(values: list[float], n_boot: int = 2000, seed: int = 12345) -> tuple[float, float]:
    if not values:
        return 0.0, 0.0
    rng = np.random.default_rng(seed)
    arr = np.asarray(values, dtype=np.float64)
    means = [float(rng.choice(arr, size=len(arr), replace=True).mean()) for _ in range(n_boot)]
    lo, hi = np.percentile(means, [2.5, 97.5])
    return round(float(lo), 4), round(float(hi), 4)


def mcnemar_exact_pvalue(correct_a: list[bool], correct_b: list[bool]) -> tuple[int, int, float]:
    b = sum(1 for ca, cb in zip(correct_a, correct_b) if ca and not cb)
    c = sum(1 for ca, cb in zip(correct_a, correct_b) if not ca and cb)
    n = b + c
    if n == 0:
        return 0, 0, 1.0
    k = min(b, c)
    tail = sum(math.comb(n, i) for i in range(k + 1)) * (0.5 ** n)
    p = min(1.0, 2.0 * tail)
    return b, c, round(float(p), 6)


# ---------------------------------------------------------------------------
# 9. Main Orchestrator
# ---------------------------------------------------------------------------
def main() -> None:
    t_start = time.time()
    print("[1/6] Freezing unmodified QRShield engine state...")
    BENCH_DIR.mkdir(parents=True, exist_ok=True)
    for sub in ("metadata", "annotations", "evaluation_runs"):
        (BENCH_DIR / sub).mkdir(parents=True, exist_ok=True)

    freeze_files = {}
    for p in sorted((SOURCE_DIR / "qrshield_core").rglob("*.py")) + sorted((SOURCE_DIR / "rules").rglob("*.yaml")):
        freeze_files[str(p.relative_to(ROOT_DIR))] = hashlib.sha256(p.read_bytes()).hexdigest()
    freeze_manifest = {
        "benchmark_name": "QRS-Bench-Ind",
        "frozen_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "load_synthetic_reference": False,
        "ocr_provider": "tesseract",
        "code_and_rule_sha256": freeze_files,
    }
    (BENCH_DIR / "evaluation_runs" / "engine_freeze_manifest.json").write_text(json.dumps(freeze_manifest, indent=2))

    print("[2/6] Building disjoint organizations, threat-intel snapshot, and 1,080 evaluation units (1,280 images)...")
    orgs_by_split = build_organizations()
    ti_snapshot = build_threat_intel_snapshot()
    ti_hosts = list(ti_snapshot.keys())

    (BENCH_DIR / "metadata" / "organizations_splits.yaml").write_text(yaml.safe_dump(orgs_by_split, sort_keys=False))
    (BENCH_DIR / "metadata" / "threat_intel_snapshot.json").write_text(json.dumps(ti_snapshot, indent=2))

    taxonomy_doc = {
        "benchmark": "QRS-Bench-Ind",
        "version": "1.0.0",
        "total_evaluation_units": 1080,
        "total_images": 1280,
        "splits": {
            "dev": {"units": 128, "images": 152, "organizations": 8, "templates": ["T01", "T02", "T03", "T04"]},
            "val": {"units": 176, "images": 200, "organizations": 12, "templates": ["T05", "T06", "T07", "T08"]},
            "test_locked": {"units": 776, "images": 928, "organizations": 40, "templates": [f"T{i:02d}" for i in range(9, 29)]},
        },
        "ordinal_levels": LEVELS,
        "categories": CATEGORIES,
        "strata": ["core_scenes", "challenge_traps", "counterfactual_pairs", "robustness_variants"],
    }
    (BENCH_DIR / "metadata" / "taxonomy_and_codebook.yaml").write_text(yaml.safe_dump(taxonomy_doc, sort_keys=False))

    image_tasks: list[dict[str, Any]] = []
    units: list[dict[str, Any]] = []

    def add_single_unit(
        split: str, stratum: str, cat: str, org: dict[str, str], template_id: str,
        lines: list[str], payload: str, gt: str, accepted: list[str],
        subtype: str, rationale: str, rel_path: str, perturbation: str = "R00_clean",
        seed: int = 42, extra_meta: dict[str, Any] | None = None,
    ) -> None:
        uid = f"{split}_{stratum}_{len(units) + 1:04d}"
        img_id = f"img_{len(image_tasks) + 1:04d}"
        script_regime = "latin_en"
        if split == "test_locked" and perturbation == "R00_clean":
            if (len(units) % 10) == 7:
                script_regime = "bilingual_devanagari"
            elif (len(units) % 10) == 9:
                script_regime = "bilingual_cjk"
        u = {
            "unit_id": uid,
            "image_id": img_id,
            "split": split,
            "script_regime": script_regime,
            "stratum": stratum,
            "category": cat,
            "org_id": org["org_id"],
            "organization_name": org["name"],
            "template_id": template_id,
            "subtype": subtype,
            "consensus_ground_truth": gt,
            "accepted_ground_truth_set": accepted,
            "provenance": LABEL_PROVENANCE,
            "provenance_note": LABEL_PROVENANCE_NOTE,
            "rationale": rationale,
            "rel_path": rel_path,
            "perturbation": perturbation,
            "lines": lines,
            "payload": payload,
        }
        if extra_meta:
            u.update(extra_meta)
        units.append(u)
        image_tasks.append({
            "image_id": img_id,
            "unit_id": uid,
            "split": split,
            "stratum": stratum,
            "category": cat,
            "lines": lines,
            "payload": payload,
            "template_id": template_id,
            "perturbation": perturbation,
            "seed": seed,
            "rel_path": rel_path,
            "script_regime": script_regime,
            "ti_hosts": ti_hosts,
        })

    def add_pair_unit(
        split: str, org: dict[str, str], template_id: str, cf_spec: dict[str, Any], pair_idx: int, seed: int
    ) -> None:
        uid = f"{split}_counterfactual_pairs_{len(units) + 1:04d}"
        cat = cf_spec["category"]
        fam = cf_spec["cf_family"]
        rel_a = f"splits/{split}/counterfactual_pairs/pair_{pair_idx:03d}_{fam}_A.png"
        rel_b = f"splits/{split}/counterfactual_pairs/pair_{pair_idx:03d}_{fam}_B.png"
        img_a = f"img_{len(image_tasks) + 1:04d}"
        img_b = f"img_{len(image_tasks) + 2:04d}"
        u = {
            "unit_id": uid,
            "image_id_a": img_a,
            "image_id_b": img_b,
            "split": split,
            "stratum": "counterfactual_pairs",
            "category": cat,
            "org_id": org["org_id"],
            "organization_name": org["name"],
            "template_id": template_id,
            "subtype": fam,
            "consensus_ground_truth_a": cf_spec["gt_a"],
            "consensus_ground_truth": cf_spec["gt_b"],
            "accepted_ground_truth_set": [cf_spec["gt_b"]],
            "expected_relation": cf_spec["expected_relation"],
            "provenance": LABEL_PROVENANCE,
            "provenance_note": LABEL_PROVENANCE_NOTE,
            "rel_path_a": rel_a,
            "rel_path_b": rel_b,
        }
        units.append(u)
        image_tasks.append({
            "image_id": img_a, "unit_id": uid, "split": split, "stratum": "counterfactual_pairs",
            "category": cat, "lines": cf_spec["lines_a"], "payload": cf_spec["payload_a"],
            "template_id": template_id, "perturbation": "R00_clean", "seed": seed, "rel_path": rel_a, "script_regime": "latin_en", "ti_hosts": ti_hosts,
        })
        image_tasks.append({
            "image_id": img_b, "unit_id": uid, "split": split, "stratum": "counterfactual_pairs",
            "category": cat, "lines": cf_spec["lines_b"], "payload": cf_spec["payload_b"],
            "template_id": template_id, "perturbation": "R00_clean", "seed": seed + 1, "rel_path": rel_b, "script_regime": "latin_en", "ti_hosts": ti_hosts,
        })

    robustness_conditions = [
        "R00_clean",
        "R01_perspective_18deg",
        "R02_curved_cylinder",
        "R03_gaussian_motion_blur",
        "R04_uneven_shadow_glare",
        "R05_low_contrast_thermal",
        "R06_sensor_noise_iso",
        "R07_partial_qr_occlusion",
        "R08_multi_qr_scene",
        "R09_extreme_downsample",
        "R10_handwritten_stylized_font",
        "R11_combined_field",
    ]

    # --- Build DEV (128 units / 152 images across T01..T04) and VAL (176 units / 200 images across T05..T08) ---
    for split_name, n_per_cat_core, n_per_cat_trap, s_templates in [
        ("dev", 8, 2, ["T01", "T02", "T03", "T04"]),
        ("val", 12, 4, ["T05", "T06", "T07", "T08"]),
    ]:
        s_orgs = orgs_by_split[split_name]
        for c_idx, cat in enumerate(CATEGORIES):
            for i in range(n_per_cat_core):
                org = s_orgs[(c_idx + i) % len(s_orgs)]
                tmpl_s = s_templates[(c_idx + i) % len(s_templates)]
                if i < n_per_cat_core // 2:
                    lines, payload, gt, acc, rat = make_clean_benign_scene(org, cat, i)
                    sub = "SG1_clean_benign"
                elif i == n_per_cat_core // 2:
                    lines, payload, gt, acc, rat = make_ambiguous_scene(org, cat, i)
                    sub = "SG2_ambiguous"
                elif i == n_per_cat_core // 2 + 1:
                    lines, payload, gt, acc, rat = make_context_deception_scene(org, cat, i)
                    sub = "SG3_context_deception"
                elif i == n_per_cat_core - 1 and split_name == "val":
                    lines, payload, gt, acc, rat = make_corroborated_attack_scene(org, cat, i, ti_hosts)
                    sub = "SG5_corroborated_malicious"
                else:
                    lines, payload, gt, acc, rat = make_overt_attack_scene(org, cat, i)
                    sub = "SG4_overt_attack"
                rel = f"splits/{split_name}/core_scenes/{cat}/{cat}_{i + 1:03d}_{sub}.png"
                add_single_unit(split_name, "core_scenes", cat, org, tmpl_s, lines, payload, gt, acc, sub, rat, rel, seed=1000 + i)

        for c_idx, cat in enumerate(CATEGORIES):
            for i in range(n_per_cat_trap):
                org = s_orgs[(c_idx + i) % len(s_orgs)]
                tmpl_s = s_templates[(c_idx + i) % len(s_templates)]
                tk = "fp_trap" if i < n_per_cat_trap // 2 else "fn_trap"
                lines, payload, gt, acc, sub, rat = make_challenge_trap(org, cat, tk, i * 2)
                rel = f"splits/{split_name}/challenge_traps/{tk}/{cat}_{tk}_{i + 1:03d}.png"
                add_single_unit(split_name, "challenge_traps", cat, org, tmpl_s, lines, payload, gt, acc, sub, rat, rel, seed=2000 + i, extra_meta={"trap_kind": tk})

        cf_fams = [
            "CF1_payload_only_mutation", "CF2_context_only_mutation", "CF3_action_class_mutation",
            "CF4_amount_parameter_tampering", "CF5_destination_mismatch",
        ]
        for p_idx in range(24):
            org = s_orgs[p_idx % len(s_orgs)]
            tmpl_s = s_templates[p_idx % len(s_templates)]
            fam = cf_fams[p_idx % 5] if p_idx < 16 else "CF6_paraphrase_negative_control"
            cf_spec = make_counterfactual_pair(org, fam, p_idx)
            add_pair_unit(split_name, org, tmpl_s, cf_spec, p_idx + 1, seed=3000 + p_idx * 2)

        for s_idx in range(2):
            cat = CATEGORIES[s_idx]
            org = s_orgs[s_idx]
            tmpl_s = s_templates[s_idx % len(s_templates)]
            lines, payload, gt, acc, rat = make_clean_benign_scene(org, cat, s_idx) if s_idx == 0 else make_overt_attack_scene(org, cat, s_idx)
            for r_idx, cond in enumerate(robustness_conditions):
                rel = f"splits/{split_name}/robustness_variants/{cond}/seed_{s_idx + 1:02d}_{cat}_{cond}.png"
                add_single_unit(split_name, "robustness_variants", cat, org, tmpl_s, lines, payload, gt, acc, cond, rat, rel, perturbation=cond, seed=4000 + s_idx * 20 + r_idx, extra_meta={"seed_id": f"{split_name}_seed_{s_idx + 1:02d}"})

    # --- Build LOCKED TEST (`test_locked`: 776 units / 928 images across T09..T28) ---
    t_orgs = orgs_by_split["test_locked"]
    t_templates = [f"T{i:02d}" for i in range(9, 29)]

    # 1. Core scenes: 320 images (40 per category across 8 categories)
    for c_idx, cat in enumerate(CATEGORIES):
        for i in range(40):
            org = t_orgs[(c_idx * 5 + i) % len(t_orgs)]
            tmpl = t_templates[(c_idx + i) % len(t_templates)]
            if i < 14:
                lines, payload, gt, acc, rat = make_clean_benign_scene(org, cat, i)
                sub = "SG1_clean_benign"
            elif i < 22:
                lines, payload, gt, acc, rat = make_ambiguous_scene(org, cat, i)
                sub = "SG2_ambiguous"
            elif i < 30:
                lines, payload, gt, acc, rat = make_context_deception_scene(org, cat, i)
                sub = "SG3_context_deception"
            elif i < 38:
                lines, payload, gt, acc, rat = make_overt_attack_scene(org, cat, i)
                sub = "SG4_overt_attack"
            else:
                sg5_global_idx = c_idx * 2 + (i - 38)
                lines, payload, gt, acc, rat = make_corroborated_attack_scene(org, cat, sg5_global_idx, ti_hosts)
                sub = "SG5_corroborated_malicious"
            rel = f"splits/test_locked/core_scenes/{cat}/{cat}_{i + 1:03d}_{sub}.png"
            add_single_unit("test_locked", "core_scenes", cat, org, tmpl, lines, payload, gt, acc, sub, rat, rel, seed=10000 + c_idx * 100 + i)

    # 2. Challenge traps: 112 images (56 FP traps [7 per category] + 56 FN traps [7 per category])
    for c_idx, cat in enumerate(CATEGORIES):
        for tk in ("fp_trap", "fn_trap"):
            for i in range(7):
                org = t_orgs[(c_idx * 3 + i) % len(t_orgs)]
                tmpl = t_templates[(c_idx + i) % len(t_templates)]
                lines, payload, gt, acc, sub, rat = make_challenge_trap(org, cat, tk, i)
                rel = f"splits/test_locked/challenge_traps/{tk}/{cat}_{tk}_{i + 1:03d}.png"
                add_single_unit("test_locked", "challenge_traps", cat, org, tmpl, lines, payload, gt, acc, sub, rat, rel, seed=20000 + c_idx * 50 + i, extra_meta={"trap_kind": tk})

    # 3. Counterfactual pairs: 152 pairs = 304 images
    cf_directional_counts = [
        ("CF1_payload_only_mutation", 32),
        ("CF2_context_only_mutation", 32),
        ("CF3_action_class_mutation", 24),
        ("CF4_amount_parameter_tampering", 20),
        ("CF5_destination_mismatch", 20),
        ("CF6_paraphrase_negative_control", 24),
    ]
    pair_counter = 0
    for fam, count in cf_directional_counts:
        for i in range(count):
            pair_counter += 1
            org = t_orgs[(pair_counter - 1) % len(t_orgs)]
            tmpl = t_templates[(pair_counter - 1) % len(t_templates)]
            cf_spec = make_counterfactual_pair(org, fam, i)
            add_pair_unit("test_locked", org, tmpl, cf_spec, pair_counter, seed=30000 + pair_counter * 2)

    # 4. Balanced 12 x 16 Factorial Robustness Matrix: 16 base seeds x 12 conditions = 192 images
    for c_idx, cat in enumerate(CATEGORIES):
        for s_type in range(2):
            seed_num = c_idx * 2 + s_type + 1
            org = t_orgs[(seed_num * 2) % len(t_orgs)]
            tmpl = t_templates[seed_num % len(t_templates)]
            if s_type == 0:
                lines, payload, gt, acc, rat = make_clean_benign_scene(org, cat, 1)
            else:
                lines, payload, gt, acc, rat = make_overt_attack_scene(org, cat, 1)
            for r_idx, cond in enumerate(robustness_conditions):
                rel = f"splits/test_locked/robustness_variants/{cond}/seed_{seed_num:02d}_{cat}_{cond}.png"
                add_single_unit(
                    "test_locked", "robustness_variants", cat, org, tmpl, lines, payload, gt, acc,
                    cond, rat, rel, perturbation=cond, seed=40000 + seed_num * 20 + r_idx,
                    extra_meta={"seed_id": f"test_seed_{seed_num:02d}", "clean_reference_gt": gt},
                )

    print(f"    Total evaluation units scheduled: {len(units)} | Total images scheduled: {len(image_tasks)}")

    import argparse
    ap = argparse.ArgumentParser(add_help=False)
    ap.add_argument("--gt-jsonl", type=Path, default=None)
    cli_args, _ = ap.parse_known_args()
    if cli_args.gt_jsonl and cli_args.gt_jsonl.exists():
        loaded_by_uid = {
            json.loads(line)["unit_id"]: json.loads(line)
            for line in cli_args.gt_jsonl.read_text(encoding="utf-8").splitlines()
            if line.strip()
        }
        for u in units:
            if u["unit_id"] in loaded_by_uid:
                u.update(loaded_by_uid[u["unit_id"]])
        print(f"    Loaded external ground-truth annotations from {cli_args.gt_jsonl}")
    else:
        gt_lines = [json.dumps(u) for u in units]
        (BENCH_DIR / "annotations" / "consensus_ground_truth.jsonl").write_text("\n".join(gt_lines) + "\n")

    print("[3/6] Rendering 1,280 PNG images & executing blind evaluation on frozen QRShield engine (4 workers)...")
    t_eval = time.time()
    results_by_img_id: dict[str, dict[str, Any]] = {}
    with ProcessPoolExecutor(max_workers=4, initializer=_init_worker, initargs=(ti_snapshot,)) as ex:
        for res in ex.map(_process_image_task, image_tasks, chunksize=16):
            results_by_img_id[res["image_id"]] = res
    print(f"    Completed 1,280 image renders + frozen QRShield evaluations in {time.time() - t_eval:.1f}s.")

    manifest_lines = []
    for task in sorted(image_tasks, key=lambda x: x["rel_path"]):
        r = results_by_img_id[task["image_id"]]
        manifest_lines.append(f"{r['sha256']}  {r['rel_path']}")
    (BENCH_DIR / "MANIFEST_SHA256.txt").write_text("\n".join(manifest_lines) + "\n")

    print("[4/6] Computing non-circular evaluation metrics on Locked Test, Val, and Dev splits...")
    test_units = [u for u in units if u["split"] == "test_locked"]

    test_core = [u for u in test_units if u["stratum"] == "core_scenes"]
    test_traps = [u for u in test_units if u["stratum"] == "challenge_traps"]
    test_single = test_core + test_traps

    def eval_subset(sub_units: list[dict[str, Any]], pred_key: str = "predicted_level_full_ti") -> dict[str, Any]:
        y_true = [u["consensus_ground_truth"] for u in sub_units]
        y_pred = []
        exact_hits = []
        acc_hits = []
        for u in sub_units:
            r = results_by_img_id[u["image_id"]]
            p = r[pred_key] if pred_key in r else r["ablation_levels"].get(pred_key, r["baselines"].get(pred_key, "no_material_concern"))
            p_mapped = "needs_verification" if p == "not_assessed" else p
            y_pred.append(p_mapped)
            exact_hits.append(1.0 if p == u["consensus_ground_truth"] else 0.0)
            acc_hits.append(1.0 if p in u["accepted_ground_truth_set"] else 0.0)
        unw_k, w_k = cohen_kappa(y_true, y_pred, LEVELS)
        mf1, per_cls, cm = macro_f1_and_per_class(y_true, y_pred, LEVELS)
        ex_mean = round(float(np.mean(exact_hits)), 4)
        ac_mean = round(float(np.mean(acc_hits)), 4)
        ex_ci = bootstrap_ci(exact_hits)
        ac_ci = bootstrap_ci(acc_hits)
        return {
            "n": len(sub_units),
            "exact_agreement": ex_mean,
            "exact_agreement_ci95": list(ex_ci),
            "accepted_set_agreement": ac_mean,
            "accepted_set_ci95": list(ac_ci),
            "cohen_kappa_unweighted": unw_k,
            "cohen_kappa_quadratic_weighted": w_k,
            "macro_f1": mf1,
            "per_class": per_cls,
            "confusion_matrix_L0_to_L3": cm,
            "_exact_bool": [bool(x) for x in exact_hits],
        }

    core_metrics_ti = eval_subset(test_core, "predicted_level_full_ti")
    core_metrics_local = eval_subset(test_core, "predicted_level_local")
    combined_metrics_ti = eval_subset(test_single, "predicted_level_full_ti")

    per_cat_metrics = {}
    for cat in CATEGORIES:
        cat_u = [u for u in test_single if u["category"] == cat]
        m = eval_subset(cat_u, "predicted_level_full_ti")
        m.pop("_exact_bool", None)
        per_cat_metrics[cat] = m

    sg1_units = [u for u in test_core if u["subtype"] == "SG1_clean_benign"]
    sg1_fp = [1.0 if results_by_img_id[u["image_id"]]["predicted_level_full_ti"] != "no_material_concern" else 0.0 for u in sg1_units]
    sg1_severe_fp = [1.0 if results_by_img_id[u["image_id"]]["predicted_level_full_ti"] in ("high_concern", "harmful_corroborated") else 0.0 for u in sg1_units]

    fp_trap_units = [u for u in test_traps if u.get("trap_kind") == "fp_trap"]
    fn_trap_units = [u for u in test_traps if u.get("trap_kind") == "fn_trap"]
    fp_trap_triggered = [1.0 if results_by_img_id[u["image_id"]]["predicted_level_full_ti"] != "no_material_concern" else 0.0 for u in fp_trap_units]
    fp_trap_severe = [1.0 if results_by_img_id[u["image_id"]]["predicted_level_full_ti"] in ("high_concern", "harmful_corroborated") else 0.0 for u in fp_trap_units]
    fn_trap_missed = [
        1.0 if LEVEL_IDX.get(results_by_img_id[u["image_id"]]["predicted_level_full_ti"], 0) < LEVEL_IDX[u["consensus_ground_truth"]] else 0.0
        for u in fn_trap_units
    ]
    fn_trap_detected = [1.0 - x for x in fn_trap_missed]

    ablation_summary = {}
    full_bool = combined_metrics_ti["_exact_bool"]
    for cfg_name in ("payload_only", "context_only", "payload_context", "payload_context_action", "full_with_ti", "B0_majority_class", "B1_url_lexical", "B2_qr_structural", "B3_url_blocklist_brand_heuristic"):
        m_all = eval_subset(test_single, cfg_name)
        m_core = eval_subset(test_core, cfg_name)
        b_cnt, c_cnt, p_val = mcnemar_exact_pvalue(full_bool, m_all["_exact_bool"])
        m_all.pop("_exact_bool", None)
        m_core.pop("_exact_bool", None)
        ablation_summary[cfg_name] = {
            "combined_432": m_all,
            "core_320": m_core,
            "mcnemar_vs_full_ti": {"b_full_better": b_cnt, "c_other_better": c_cnt, "p_value": p_val},
        }
    core_metrics_ti.pop("_exact_bool", None)
    core_metrics_local.pop("_exact_bool", None)
    combined_metrics_ti.pop("_exact_bool", None)

    test_cfs = [u for u in test_units if u["stratum"] == "counterfactual_pairs"]
    cf_by_fam: dict[str, dict[str, Any]] = {}
    dir_hits_all = []
    para_hits_all = []
    for fam, _ in cf_directional_counts:
        fam_u = [u for u in test_cfs if u["subtype"] == fam]
        hits = []
        exact_b = []
        for u in fam_u:
            ra = results_by_img_id[u["image_id_a"]]["predicted_level_full_ti"]
            rb = results_by_img_id[u["image_id_b"]]["predicted_level_full_ti"]
            ia = LEVEL_IDX.get(ra, 0)
            ib = LEVEL_IDX.get(rb, 0)
            if u["expected_relation"] == "Risk(B) > Risk(A)":
                ok = ib > ia
                dir_hits_all.append(1.0 if ok else 0.0)
            else:
                ok = (ib == ia) and (rb == "no_material_concern")
                para_hits_all.append(1.0 if ok else 0.0)
            hits.append(1.0 if ok else 0.0)
            exact_b.append(1.0 if rb == u["consensus_ground_truth"] else 0.0)
        cf_by_fam[fam] = {
            "pairs": len(fam_u),
            "relation_satisfied_rate": round(float(np.mean(hits)), 4),
            "relation_ci95": list(bootstrap_ci(hits)),
            "mutated_exact_agreement": round(float(np.mean(exact_b)), 4),
        }

    test_rob = [u for u in test_units if u["stratum"] == "robustness_variants"]
    clean_pred_by_seed = {}
    for u in test_rob:
        if u["perturbation"] == "R00_clean":
            clean_pred_by_seed[u["seed_id"]] = results_by_img_id[u["image_id"]]["predicted_level_full_ti"]

    rob_by_cond: dict[str, dict[str, Any]] = {}
    for cond in robustness_conditions:
        cu = [u for u in test_rob if u["perturbation"] == cond]
        dec_ok = [1.0 if results_by_img_id[u["image_id"]]["qr_decoded"] else 0.0 for u in cu]
        ocr_ok = [1.0 if results_by_img_id[u["image_id"]]["ocr_status"] == "ok" else 0.0 for u in cu]
        gt_ok = [1.0 if results_by_img_id[u["image_id"]]["predicted_level_full_ti"] == u["consensus_ground_truth"] else 0.0 for u in cu]
        stab_ok = [1.0 if results_by_img_id[u["image_id"]]["predicted_level_full_ti"] == clean_pred_by_seed.get(u["seed_id"]) else 0.0 for u in cu]
        rob_by_cond[cond] = {
            "n": len(cu),
            "qr_decode_rate": round(float(np.mean(dec_ok)), 4),
            "ocr_success_rate": round(float(np.mean(ocr_ok)), 4),
            "exact_gt_agreement": round(float(np.mean(gt_ok)), 4),
            "verdict_stability_vs_clean": round(float(np.mean(stab_ok)), 4),
        }

    dev_single = [u for u in units if u["split"] == "dev" and u["stratum"] in ("core_scenes", "challenge_traps")]
    val_single = [u for u in units if u["split"] == "val" and u["stratum"] in ("core_scenes", "challenge_traps")]
    dev_m = eval_subset(dev_single, "predicted_level_full_ti")
    val_m = eval_subset(val_single, "predicted_level_full_ti")
    dev_m.pop("_exact_bool", None)
    val_m.pop("_exact_bool", None)

    test_imgs = [results_by_img_id[t["image_id"]] for t in image_tasks if t["split"] == "test_locked"]
    total_ms_list = [sum(r["timings_ms"].values()) for r in test_imgs]
    ocr_ms_list = [r["timings_ms"].get("ocr", 0.0) for r in test_imgs]
    dec_ms_list = [r["timings_ms"].get("qr_decode", 0.0) for r in test_imgs]

    # Compute script regime breakdown on test_single (432 single-image units)
    script_breakdown = {}
    for s_reg in ("latin_en", "bilingual_devanagari", "bilingual_cjk"):
        su = [u for u in test_single if u.get("script_regime", "latin_en") == s_reg]
        if su:
            sm = eval_subset(su, "predicted_level_full_ti")
            sm.pop("_exact_bool", None)
            ocr_ok_s = [1.0 if results_by_img_id[u["image_id"]]["ocr_status"] == "ok" else 0.0 for u in su]
            sm["ocr_success_rate"] = round(float(np.mean(ocr_ok_s)), 4)
            script_breakdown[s_reg] = sm

    # Compute non-trivial R01..R11 robustness aggregate (excluding R00_clean identity baseline)
    rob_nontrivial_units = [u for u in test_rob if u["perturbation"] != "R00_clean"]
    rob_nontrivial_summary = {
        "conditions_count": 11,
        "images_count": len(rob_nontrivial_units),
        "qr_decode_rate": round(float(np.mean([1.0 if results_by_img_id[u["image_id"]]["qr_decoded"] else 0.0 for u in rob_nontrivial_units])), 4),
        "ocr_success_rate": round(float(np.mean([1.0 if results_by_img_id[u["image_id"]]["ocr_status"] == "ok" else 0.0 for u in rob_nontrivial_units])), 4),
        "exact_gt_agreement": round(float(np.mean([1.0 if results_by_img_id[u["image_id"]]["predicted_level_full_ti"] == u["consensus_ground_truth"] else 0.0 for u in rob_nontrivial_units])), 4),
        "verdict_stability_vs_clean": round(float(np.mean([1.0 if results_by_img_id[u["image_id"]]["predicted_level_full_ti"] == clean_pred_by_seed.get(u["seed_id"]) else 0.0 for u in rob_nontrivial_units])), 4),
    }
    rob_all12_summary = {
        "conditions_count": 12,
        "images_count": len(test_rob),
        "qr_decode_rate": round(float(np.mean([1.0 if results_by_img_id[u["image_id"]]["qr_decoded"] else 0.0 for u in test_rob])), 4),
        "ocr_success_rate": round(float(np.mean([1.0 if results_by_img_id[u["image_id"]]["ocr_status"] == "ok" else 0.0 for u in test_rob])), 4),
        "exact_gt_agreement": round(float(np.mean([1.0 if results_by_img_id[u["image_id"]]["predicted_level_full_ti"] == u["consensus_ground_truth"] else 0.0 for u in test_rob])), 4),
        "verdict_stability_vs_clean": round(float(np.mean([1.0 if results_by_img_id[u["image_id"]]["predicted_level_full_ti"] == clean_pred_by_seed.get(u["seed_id"]) else 0.0 for u in test_rob])), 4),
    }

    report = {
        "benchmark": "QRS-Bench-Ind",
        "engine_version": "1.0.0",
        "script_breakdown_test_locked_432": script_breakdown,
        "factorial_robustness_summary": {
            "nontrivial_R01_to_R11_176_images": rob_nontrivial_summary,
            "all_conditions_R00_to_R11_192_images": rob_all12_summary,
        },
        "evaluated_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "engine_modified": False,
        "load_synthetic_reference": False,
        "dataset_totals": {
            "evaluation_units": len(units),
            "images": len(image_tasks),
            "splits": {
                "dev": {"units": sum(1 for u in units if u["split"] == "dev"), "images": sum(1 for t in image_tasks if t["split"] == "dev")},
                "val": {"units": sum(1 for u in units if u["split"] == "val"), "images": sum(1 for t in image_tasks if t["split"] == "val")},
                "test_locked": {"units": len(test_units), "images": len(test_imgs)},
            },
        },
        "label_provenance": {
            "provenance": LABEL_PROVENANCE,
            "inter_rater_statistics": None,
            "note": LABEL_PROVENANCE_NOTE,
        },
        "test_locked_primary": {
            "core_scenes_320_with_ti": core_metrics_ti,
            "core_scenes_320_local_only": core_metrics_local,
            "combined_core_plus_challenge_432_with_ti": combined_metrics_ti,
            "per_category_54_each": per_cat_metrics,
        },
        "false_positive_and_challenge_analysis": {
            "clean_benign_SG1_112": {
                "n": len(sg1_units),
                "clean_benign_fpr_any_escalation": round(float(np.mean(sg1_fp)), 4),
                "clean_benign_fpr_ci95": list(bootstrap_ci(sg1_fp)),
                "clean_benign_severe_fpr_L2_L3": round(float(np.mean(sg1_severe_fp)), 4),
                "clean_benign_specificity": round(1.0 - float(np.mean(sg1_fp)), 4),
            },
            "challenge_fp_traps_56": {
                "n": len(fp_trap_units),
                "over_escalation_fp_rate": round(float(np.mean(fp_trap_triggered)), 4),
                "over_escalation_ci95": list(bootstrap_ci(fp_trap_triggered)),
                "severe_fp_rate_L2_L3": round(float(np.mean(fp_trap_severe)), 4),
                "true_negative_resistance_rate": round(1.0 - float(np.mean(fp_trap_triggered)), 4),
            },
            "challenge_fn_traps_56": {
                "n": len(fn_trap_units),
                "evasion_fn_rate": round(float(np.mean(fn_trap_missed)), 4),
                "evasion_fn_ci95": list(bootstrap_ci(fn_trap_missed)),
                "detection_recall_rate": round(float(np.mean(fn_trap_detected)), 4),
            },
        },
        "ablation_and_baselines_test_locked": ablation_summary,
        "counterfactual_analysis_test_locked_152_pairs": {
            "directional_128_pairs_rate": round(float(np.mean(dir_hits_all)), 4),
            "directional_128_ci95": list(bootstrap_ci(dir_hits_all)),
            "paraphrase_negative_control_24_pairs_invariance_rate": round(float(np.mean(para_hits_all)), 4),
            "paraphrase_24_ci95": list(bootstrap_ci(para_hits_all)),
            "by_family": cf_by_fam,
        },
        "factorial_robustness_12x16_192_images": rob_by_cond,
        "dev_and_val_splits": {
            "dev_80_single_scenes": dev_m,
            "val_128_single_scenes": val_m,
        },
        "runtime_ms_test_locked_928_images": {
            "total_median_ms": round(float(np.median(total_ms_list)), 2),
            "total_iqr_ms": round(float(np.percentile(total_ms_list, 75) - np.percentile(total_ms_list, 25)), 2),
            "total_p95_ms": round(float(np.percentile(total_ms_list, 95)), 2),
            "qr_decode_median_ms": round(float(np.median(dec_ms_list)), 2),
            "ocr_median_ms": round(float(np.median(ocr_ms_list)), 2),
        },
    }

    pred_lines = []
    for u in units:
        if "image_id" in u:
            r = results_by_img_id[u["image_id"]]
            pred_lines.append(json.dumps({
                "unit_id": u["unit_id"], "split": u["split"], "stratum": u["stratum"], "category": u["category"],
                "subtype": u.get("subtype"), "script_regime": u.get("script_regime", "latin_en"),
                "org_id": u["org_id"], "template_id": u["template_id"],
                "consensus_ground_truth": u["consensus_ground_truth"],
                "accepted_ground_truth_set": u["accepted_ground_truth_set"],
                "predicted_level_full_ti": r["predicted_level_full_ti"],
                "predicted_level_local": r["predicted_level_local"],
                "ablation_levels": r["ablation_levels"],
                "baselines": r["baselines"],
                "qr_decoded": r["qr_decoded"], "ocr_status": r["ocr_status"],
                "payload_findings": r["payload_findings"], "context_findings": r["context_findings"],
                "ti_findings": r["ti_findings"], "timings_ms": r["timings_ms"],
            }))
        else:
            ra = results_by_img_id[u["image_id_a"]]
            rb = results_by_img_id[u["image_id_b"]]
            pred_lines.append(json.dumps({
                "unit_id": u["unit_id"], "split": u["split"], "stratum": u["stratum"], "category": u["category"],
                "subtype": u.get("subtype"), "org_id": u["org_id"], "template_id": u["template_id"],
                "expected_relation": u["expected_relation"],
                "gt_a": u["consensus_ground_truth_a"], "gt_b": u["consensus_ground_truth"],
                "pred_a_full_ti": ra["predicted_level_full_ti"], "pred_b_full_ti": rb["predicted_level_full_ti"],
            }))
    (BENCH_DIR / "evaluation_runs" / "per_unit_predictions.jsonl").write_text("\n".join(pred_lines) + "\n")

    report_path = BENCH_DIR / "evaluation_runs" / "benchmark_metrics_report.json"
    report_path.write_text(json.dumps(report, indent=2))
    print(f"[5/6] Saved complete metrics report to {report_path}")
    print(f"[6/6] Total pipeline elapsed time: {time.time() - t_start:.1f}s.")


if __name__ == "__main__":
    main()
