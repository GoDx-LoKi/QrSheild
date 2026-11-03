"""Local OCR (PaddleOCR and Tesseract). No cloud OCR and no network fallback service.

OCR output is *evidence*, not truth: every block keeps raw text, normalised text, confidence, bounding box and
provenance. When OCR is unavailable the result says so explicitly and the pipeline falls back to manual context
(OCR failure is never a security verdict).
"""
from __future__ import annotations

import os
import re
import shutil
import time
import unicodedata
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

import numpy as np

from ..models import Confidence
from ..rules import ReferenceData

_CURRENCY = r"(?:₹|rs\.?|inr|\$|usd|€|eur|£|gbp)"
AMOUNT_RE = re.compile(rf"(?i)(?:{_CURRENCY}\s*\d[\d,]*(?:\.\d{{1,2}})?|\d[\d,]*(?:\.\d{{1,2}})?\s*(?:/-|{_CURRENCY}(?![a-z])))")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
PHONE_RE = re.compile(r"(?<![\w.])\+?\d[\d\s().-]{7,16}\d(?![\w])")
DOMAIN_RE = re.compile(r"(?i)\b(?:https?://)?(?:www\.)?[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?!txt\b|pdf\b|png\b|jpg\b)[a-z]{2,24}(?:/\S*)?")
NETWORK_RE = re.compile(r"(?i)\b(?:wi-?\s?fi|ssid|network|password)\b")
INSTRUCTION_WORDS = {"scan", "qr", "code", "to", "pay", "welcome", "thank", "thanks", "you", "please", "here", "now",
                     "open", "hours", "the", "and", "for", "your", "our", "with", "via", "use", "using"}
_EXPLICIT_LABEL_PREFIX_RE = re.compile(
    r"(?i)^\s*(?:organization|organisation|merchant|business|venue|company|purpose|amount|"
    r"official\s+domain|website|site|web\s+address|contact\s+email|email|email\s+address|"
    r"displayed\s+phone|contact\s+phone|phone|telephone|tel|network|ssid|wi[- ]?fi\s+network|network\s+name)\s*[:\-]"
)
_PURPOSE_VERB_LEAD_RE = re.compile(
    r"(?i)^\s*(?:connect\s+to|scan\s+to|view\s+|open\s+|save\s+|text\s+us|email\s+us|claim\s+|join\s+|account\s+sign)"
)
_SYNTHETIC_WATERMARK_RE = re.compile(r"(?i)^\s*synthetic\s+test\s+scenario\s*$")


def conf_bucket(score: float) -> Confidence:
    return Confidence.HIGH if score >= 0.90 else Confidence.MEDIUM if score >= 0.62 else Confidence.LOW


def normalize_ocr_text(raw: str) -> str:
    """Normalise obvious OCR artefacts without destroying the raw text (kept separately).

    Digit/letter confusions (0/O, 1/l, 5/S) are only corrected inside predominantly alphabetic words; tokens that look
    like numbers, e-mail addresses or domains are left alone.
    """
    s = unicodedata.normalize("NFKC", raw or "")
    s = re.sub(r"[\u200b-\u200f\ufeff]", "", s)
    s = re.sub(r"\s+", " ", s).strip()
    # Normalise common OCR artefacts on blurred/noisy Wi-Fi signage ('Wii' -> 'Wi-Fi', 'SSDD-' -> 'SSID:')
    s = re.sub(r"(?i)^\s*[‘'\"`]*SS[I1lD]{2}\s*[-:]\s*", "SSID: ", s)
    s = re.sub(r"(?i)\b(?:Wi[- ]?i|Wii)\b", "Wi-Fi", s)

    def fix(tok: str) -> str:
        if "@" in tok or "." in tok.strip(".,") or "/" in tok or sum(c.isdigit() for c in tok) == 0:
            return tok
        letters = sum(c.isalpha() for c in tok)
        digits = sum(c.isdigit() for c in tok)
        if letters < 3 or digits > letters / 2:
            return tok
        upper = sum(c.isupper() for c in tok) >= letters / 2
        table = {"0": "O" if upper else "o", "1": "I" if upper else "l", "5": "S" if upper else "s"}
        return "".join(table.get(c, c) for c in tok)

    return " ".join(fix(t) for t in s.split(" "))


@dataclass
class OCRBlock:
    block_id: str
    raw_text: str
    normalized_text: str
    score: float
    confidence: Confidence
    bbox: list[list[int]]
    candidate_type: str = "other"
    source: str = "ocr"


@dataclass
class OCRResult:
    status: str                      # ok | no_text | unavailable | disabled | failed
    message: str
    engine: str
    blocks: list[OCRBlock] = field(default_factory=list)
    duration_ms: float = 0.0
    engine_version: str | None = None
    config: dict[str, Any] = field(default_factory=dict)
    masked_qr_regions: int = 0


class OCRProvider(ABC):
    name = "abstract"
    version: str | None = None
    config: dict[str, Any] = {}

    @abstractmethod
    def available(self) -> tuple[bool, str]: ...

    @abstractmethod
    def recognize(self, bgr: np.ndarray) -> list[tuple[str, float, list[list[int]]]]: ...


def parse_paddle_result(res: Any) -> list[tuple[str, float, list[list[int]]]]:
    """Parse PaddleOCR output (3.x `predict()` dict-like results and legacy 2.x nested lists)."""
    out: list[tuple[str, float, list[list[int]]]] = []
    if res is None:
        return out
    items = res if isinstance(res, (list, tuple)) else [res]
    for r in items:
        if r is None:
            continue
        if hasattr(r, "get") or isinstance(r, dict):                       # 3.x
            d = r.get("res", r) if hasattr(r, "get") else r
            texts = d.get("rec_texts") if hasattr(d, "get") else None
            if texts is None:
                continue
            scores = list(d.get("rec_scores", []))
            polys = d.get("rec_polys")
            if polys is None:
                polys = d.get("dt_polys", [])
            for i, t in enumerate(texts):
                if not str(t).strip():
                    continue
                poly = np.asarray(polys[i]).reshape(-1, 2) if i < len(polys) else np.zeros((4, 2))
                out.append((str(t), float(scores[i]) if i < len(scores) else 0.0, np.rint(poly).astype(int).tolist()))
        elif isinstance(r, (list, tuple)):                                   # 2.x: [[poly, (text, score)], ...]
            for line in r:
                try:
                    poly, (text, score) = line[0], line[1]
                except (TypeError, ValueError, IndexError):
                    continue
                if str(text).strip():
                    out.append((str(text), float(score), np.rint(np.asarray(poly).reshape(-1, 2)).astype(int).tolist()))
    return out


class PaddleOCRProvider(OCRProvider):
    """PaddleOCR with local inference. Model files are downloaded once on first use (or pre-baked in Docker)."""

    name = "paddleocr"

    def __init__(self, lang: str = "en"):
        self.lang = lang
        self._ocr: Any = None
        self._error: str | None = None
        self.config = {"lang": lang, "doc_orientation_classify": False, "doc_unwarping": False, "textline_orientation": False}

    def _ensure(self) -> None:
        if self._ocr is not None or self._error:
            return
        os.environ.setdefault("PADDLE_PDX_DISABLE_MODEL_SOURCE_CHECK", "True")
        os.environ.setdefault("FLAGS_use_mkldnn", "0")
        os.environ.setdefault("PADDLE_PDX_ENABLE_MKLDNN_BYDEFAULT", "0")
        try:
            import paddleocr  # noqa: WPS433 (lazy import: heavy)
            self.version = getattr(paddleocr, "__version__", None)
            try:
                self._ocr = paddleocr.PaddleOCR(lang=self.lang, use_doc_orientation_classify=False,
                                                use_doc_unwarping=False, use_textline_orientation=False,
                                                enable_mkldnn=False)
            except TypeError:
                try:
                    self._ocr = paddleocr.PaddleOCR(lang=self.lang, use_doc_orientation_classify=False,
                                                    use_doc_unwarping=False, use_textline_orientation=False)
                except (TypeError, ValueError):   # legacy 2.x signature
                    self._ocr = paddleocr.PaddleOCR(use_angle_cls=True, lang=self.lang, show_log=False)
            except ValueError:
                self._ocr = paddleocr.PaddleOCR(use_angle_cls=True, lang=self.lang, show_log=False)
        except Exception as exc:               # missing package, missing/blocked model download, etc.
            self._error = f"{type(exc).__name__}: {str(exc)[:300]}"

    def available(self) -> tuple[bool, str]:
        self._ensure()
        return (self._ocr is not None, self._error or "")

    def recognize(self, bgr: np.ndarray) -> list[tuple[str, float, list[list[int]]]]:
        self._ensure()
        if self._ocr is None:
            raise RuntimeError(self._error or "PaddleOCR is not initialised")
        if hasattr(self._ocr, "predict"):
            return parse_paddle_result(self._ocr.predict(bgr))
        return parse_paddle_result(self._ocr.ocr(bgr, cls=True))


class TesseractOCRProvider(OCRProvider):
    """Local Tesseract OCR provider (via pytesseract) for portable CPU environments.

    Groups word-level detections into line-level blocks with confidence scores and
    4-point bounding polygons matching the OCRProvider interface. Includes a secondary
    illumination-normalised + denoised pass when shadow/glare/noise degrades the primary scan.
    """

    name = "tesseract"

    def __init__(self, lang: str = "eng", psm: int = 6):
        self.lang = lang
        self.psm = psm
        self._pytesseract: Any = None
        self._error: str | None = None
        self.config = {"lang": lang, "psm": psm}

    def _ensure(self) -> None:
        if self._pytesseract is not None or self._error:
            return
        try:
            import pytesseract  # noqa: WPS433
            if shutil.which("tesseract") is None:
                self._error = "FileNotFoundError: tesseract binary not found on PATH"
                return
            ver = pytesseract.get_tesseract_version()
            self.version = str(ver)
            self._pytesseract = pytesseract
        except Exception as exc:
            self._error = f"{type(exc).__name__}: {str(exc)[:300]}"

    def available(self) -> tuple[bool, str]:
        self._ensure()
        return (self._pytesseract is not None, self._error or "")

    def _run_tesseract_data(self, img_input: np.ndarray) -> list[tuple[str, float, list[list[int]]]]:
        data = self._pytesseract.image_to_data(
            img_input, lang=self.lang, config=f"--psm {self.psm}", output_type=self._pytesseract.Output.DICT
        )
        lines: dict[tuple[int, int, int], dict[str, Any]] = {}
        n = len(data.get("text", []))
        for i in range(n):
            txt = str(data["text"][i] or "").strip()
            if not txt:
                continue
            try:
                conf = float(data["conf"][i])
            except (TypeError, ValueError):
                conf = -1.0
            if conf < 0:
                continue
            key = (int(data["block_num"][i]), int(data["par_num"][i]), int(data["line_num"][i]))
            x, y, w, h = int(data["left"][i]), int(data["top"][i]), int(data["width"][i]), int(data["height"][i])
            entry = lines.setdefault(key, {"words": [], "confs": [], "x0": x, "y0": y, "x1": x + w, "y1": y + h})
            entry["words"].append(txt)
            entry["confs"].append(max(0.0, min(1.0, conf / 100.0)))
            entry["x0"] = min(entry["x0"], x)
            entry["y0"] = min(entry["y0"], y)
            entry["x1"] = max(entry["x1"], x + w)
            entry["y1"] = max(entry["y1"], y + h)
        out: list[tuple[str, float, list[list[int]]]] = []
        for entry in lines.values():
            line_text = " ".join(entry["words"]).strip()
            if not line_text:
                continue
            avg_score = float(sum(entry["confs"]) / len(entry["confs"])) if entry["confs"] else 0.0
            x0, y0, x1, y1 = entry["x0"], entry["y0"], entry["x1"], entry["y1"]
            bbox = [[x0, y0], [x1, y0], [x1, y1], [x0, y1]]
            out.append((line_text, round(avg_score, 4), bbox))
        return out

    @staticmethod
    def _pass_quality(blocks: list[tuple[str, float, list[list[int]]]]) -> tuple[int, float]:
        valid = [
            score for txt, score, _ in blocks
            if any(len(w) >= 4 for w in re.findall(r"[A-Za-z0-9]+", txt))
        ]
        if not valid:
            return 0, 0.0
        return len(valid), float(sum(valid) / len(valid))

    def recognize(self, bgr: np.ndarray) -> list[tuple[str, float, list[list[int]]]]:
        self._ensure()
        if self._pytesseract is None:
            raise RuntimeError(self._error or "Tesseract OCR is not initialised")
        import cv2  # noqa: WPS433
        rgb = cv2.cvtColor(bgr, cv2.COLOR_BGR2RGB)
        primary = self._run_tesseract_data(rgb)
        n_valid, mean_conf = self._pass_quality(primary)
        # Weakness 11: When shadow/glare/noise degrades primary OCR, run an illumination-normalised + denoised fallback pass
        if n_valid < 2 or mean_conf < 0.72:
            gray = cv2.cvtColor(bgr, cv2.COLOR_BGR2GRAY) if bgr.ndim == 3 else bgr
            bg = cv2.GaussianBlur(gray, (0, 0), sigmaX=35, sigmaY=35)
            norm = cv2.divide(gray, bg, scale=255)
            denoised = cv2.fastNlMeansDenoising(norm, None, h=12, templateWindowSize=7, searchWindowSize=21)
            _, bw = cv2.threshold(denoised, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
            secondary = self._run_tesseract_data(bw)
            if self._pass_quality(secondary) > (n_valid, mean_conf):
                return secondary
        return primary


def create_ocr_provider(provider_name: str = "paddleocr") -> OCRProvider | None:
    """Instantiate an OCRProvider by name ('paddleocr', 'tesseract', 'auto', or 'none')."""
    choice = (provider_name or "paddleocr").strip().lower()
    if choice in ("none", "off", "disabled"):
        return None
    if choice == "tesseract":
        return TesseractOCRProvider()
    if choice == "auto":
        paddle = PaddleOCRProvider()
        ok, _ = paddle.available()
        if ok:
            return paddle
        tess = TesseractOCRProvider()
        ok_t, _ = tess.available()
        return tess if ok_t else paddle
    return PaddleOCRProvider()


class StaticOCRProvider(OCRProvider):
    """TEST DOUBLE returning pre-defined blocks. Never used by the application unless explicitly injected."""

    name = "static-test-double"

    def __init__(self, blocks: list[tuple[str, float, list[list[int]]]]):
        self._blocks = blocks

    def available(self) -> tuple[bool, str]:
        return True, ""

    def recognize(self, bgr: np.ndarray) -> list[tuple[str, float, list[list[int]]]]:
        return list(self._blocks)


def classify_block_type(text: str, ref: ReferenceData) -> str:
    t = text.strip()
    low = t.lower()
    if _SYNTHETIC_WATERMARK_RE.match(t):
        return "other"
    if re.match(r"(?i)^\s*purpose\s*[:\-]", t):
        return "purpose"
    if re.match(r"(?i)^\s*(?:contact\s+email|email|email\s+address)\s*[:\-]", t):
        return "email"
    if re.match(r"(?i)^\s*(?:displayed\s+phone|contact\s+phone|phone|telephone|tel)\s*[:\-]", t):
        return "phone"
    if re.match(r"(?i)^\s*(?:official\s+domain|website|site|web\s+address)\s*[:\-]", t):
        return "domain"
    if re.match(r"(?i)^\s*amount\s*[:\-]", t):
        return "amount"
    if re.match(r"(?i)^\s*(?:network|ssid|wi[- ]?fi\s+network|network\s+name)\s*[:\-]", t):
        return "network"
    if re.match(r"(?i)^\s*(?:organization|organisation|merchant|business|venue|company|operated\s+by|a\s+unit\s+of|parent|subsidiary\s+of|dba)\s*[:\-]", t):
        return "organization"
    if EMAIL_RE.search(t):
        return "email"
    if AMOUNT_RE.search(t) and len(re.sub(r"[^A-Za-z]", "", re.sub(_CURRENCY, "", t, flags=re.I))) <= 6:
        return "amount"
    digits = re.sub(r"\D", "", t)
    if PHONE_RE.search(t) and len(digits) >= 8 and sum(c.isalpha() for c in t) <= 6:
        return "phone"
    if DOMAIN_RE.search(t) and " " not in t.strip() and "." in t:
        return "domain"
    for p in ref.purposes:
        if any(re.search(rf"\b{re.escape(k)}\b", low) for k in p["keywords"]):
            return "purpose"
    if _PURPOSE_VERB_LEAD_RE.match(t):
        return "purpose"
    if NETWORK_RE.search(t):
        return "network"
    words = re.findall(r"[A-Za-z][A-Za-z'&.-]*", t)
    letters = sum(c.isalpha() for c in t)
    if 2 <= len(t) <= 60 and letters >= 0.5 * len(t) and 1 <= len(words) <= 7 \
            and not _EXPLICIT_LABEL_PREFIX_RE.match(t) \
            and not all(w.lower() in INSTRUCTION_WORDS for w in words):
        return "organization"
    return "other"


def run_ocr(provider: OCRProvider | None, bgr: np.ndarray, ref: ReferenceData, *, enabled: bool = True,
            qr_boxes: list[list[list[int]]] | None = None) -> OCRResult:
    """Run OCR over the image with the QR symbol(s) masked out, and classify the resulting blocks."""
    name = provider.name if provider else "none"
    if not enabled or provider is None:
        return OCRResult("disabled", "OCR is disabled; enter context manually.", name)
    ok, why = provider.available()
    if not ok:
        return OCRResult("unavailable", f"OCR engine unavailable ({why}). Context extraction unavailable; enter context manually.",
                         name, engine_version=provider.version, config=provider.config)
    img = bgr.copy()
    masked = 0
    for box in qr_boxes or []:
        pts = np.asarray(box, dtype=float)
        c = pts.mean(axis=0)
        grown = (pts - c) * 1.18 + c
        x0, y0 = np.maximum(grown.min(axis=0), 0).astype(int)
        x1, y1 = grown.max(axis=0).astype(int)
        img[y0:y1, x0:x1] = 255
        masked += 1
    t0 = time.perf_counter()
    try:
        raw_blocks = provider.recognize(img)
    except Exception as exc:
        return OCRResult("failed", f"OCR failed ({type(exc).__name__}). Context extraction unavailable; enter context manually.",
                         name, engine_version=provider.version, config=provider.config, masked_qr_regions=masked)
    dur = round((time.perf_counter() - t0) * 1000, 1)
    blocks: list[OCRBlock] = []
    for i, (text, score, bbox) in enumerate(raw_blocks):
        norm = normalize_ocr_text(text)
        blocks.append(OCRBlock(f"b{i + 1}", text, norm, round(score, 3), conf_bucket(score), bbox,
                               classify_block_type(norm, ref)))
    status = "ok" if blocks else "no_text"
    msg = f"{len(blocks)} text block(s) recognised." if blocks else "No text was recognised in the image."
    return OCRResult(status, msg, name, blocks, dur, provider.version, provider.config, masked)
