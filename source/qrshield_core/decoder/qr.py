"""QR detection and decoding. Decoded content is DATA: it is never opened, resolved or executed.

OpenCV's QRCodeDetector is the primary decoder. A second OpenCV detector (ArUco-based) and the
zxing-cpp library are used only as internal fallbacks for robustness; there is no external decoding API.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable

import cv2
import numpy as np

try:  # optional internal fallback
    import zxingcpp  # type: ignore
    _HAS_ZXING = True
except Exception:  # pragma: no cover
    zxingcpp = None  # type: ignore
    _HAS_ZXING = False


@dataclass
class DetectedQR:
    index: int
    decoded: bool
    payload: str | None
    bbox: list[list[int]]          # 4 corner points, clockwise, in image pixel coordinates
    decoder: str
    variant: str
    note: str | None = None


@dataclass
class DecodeResult:
    codes: list[DetectedQR] = field(default_factory=list)
    attempts: list[str] = field(default_factory=list)
    duration_ms: float = 0.0
    encoding_note: str = "Text as returned by the decoder (character encoding/ECI is not exposed by OpenCV)."

    @property
    def count(self) -> int:
        return len(self.codes)

    @property
    def decoded_codes(self) -> list[DetectedQR]:
        return [c for c in self.codes if c.decoded]


Engine = Callable[[np.ndarray], list[tuple[str | None, np.ndarray]]]


def _opencv_classic(img: np.ndarray) -> list[tuple[str | None, np.ndarray]]:
    det = cv2.QRCodeDetector()
    ok, infos, pts, _ = det.detectAndDecodeMulti(img)
    return _collect(ok, infos, pts)


def _opencv_aruco(img: np.ndarray) -> list[tuple[str | None, np.ndarray]]:
    if not hasattr(cv2, "QRCodeDetectorAruco"):
        return []
    det = cv2.QRCodeDetectorAruco()
    ok, infos, pts, _ = det.detectAndDecodeMulti(img)
    return _collect(ok, infos, pts)


def _collect(ok: bool, infos: Any, pts: Any) -> list[tuple[str | None, np.ndarray]]:
    out: list[tuple[str | None, np.ndarray]] = []
    if pts is None or len(pts) == 0:
        return out
    infos = list(infos) if infos is not None else []
    for i, p in enumerate(pts):
        text = infos[i] if i < len(infos) else ""
        out.append((text if text else None, np.asarray(p, dtype=float).reshape(-1, 2)))
    return out


def _zxing(img: np.ndarray) -> list[tuple[str | None, np.ndarray]]:
    if not _HAS_ZXING:
        return []
    try:
        results = zxingcpp.read_barcodes(img, formats=zxingcpp.BarcodeFormat.QRCode)
    except TypeError:  # pragma: no cover - older API
        results = [r for r in zxingcpp.read_barcodes(img) if r.format == zxingcpp.BarcodeFormat.QRCode]
    out = []
    for r in results:
        p = r.position
        pts = np.array([[p.top_left.x, p.top_left.y], [p.top_right.x, p.top_right.y],
                        [p.bottom_right.x, p.bottom_right.y], [p.bottom_left.x, p.bottom_left.y]], dtype=float)
        out.append((r.text if r.text else None, pts))
    return out


def _variants(bgr: np.ndarray) -> list[tuple[str, np.ndarray, float, int]]:
    """Image variants (name, image, scale, pad) tried in order. Coordinates are mapped back afterwards."""
    h, w = bgr.shape[:2]
    gray = cv2.cvtColor(bgr, cv2.COLOR_BGR2GRAY)
    out: list[tuple[str, np.ndarray, float, int]] = [("original", bgr, 1.0, 0)]
    pad = 40
    padded = cv2.copyMakeBorder(bgr, pad, pad, pad, pad, cv2.BORDER_CONSTANT, value=(255, 255, 255))
    out.append(("padded", padded, 1.0, pad))
    if min(h, w) < 900:
        up = cv2.resize(bgr, None, fx=2.0, fy=2.0, interpolation=cv2.INTER_CUBIC)
        out.append(("upscaled_2x", up, 2.0, 0))
    clahe = cv2.createCLAHE(clipLimit=3.0, tileGridSize=(8, 8)).apply(gray)
    out.append(("clahe", cv2.cvtColor(clahe, cv2.COLOR_GRAY2BGR), 1.0, 0))
    blur = cv2.GaussianBlur(gray, (0, 0), 3)
    sharp = cv2.addWeighted(gray, 1.8, blur, -0.8, 0)
    out.append(("sharpened", cv2.cvtColor(sharp, cv2.COLOR_GRAY2BGR), 1.0, 0))
    thr = cv2.adaptiveThreshold(gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 41, 8)
    out.append(("adaptive_threshold", cv2.cvtColor(thr, cv2.COLOR_GRAY2BGR), 1.0, 0))
    out.append(("inverted", cv2.bitwise_not(bgr), 1.0, 0))
    return out


def _geom(pts: np.ndarray) -> tuple[np.ndarray, float]:
    c = pts.mean(axis=0)
    size = float(max(np.ptp(pts[:, 0]), np.ptp(pts[:, 1])))
    return c, size


def detect_and_decode(bgr: np.ndarray, *, time_budget_s: float = 12.0) -> DecodeResult:
    """Detect every QR code in the image and decode it without executing anything."""
    t0 = time.perf_counter()
    res = DecodeResult()
    found: list[dict[str, Any]] = []

    def merge(payload: str | None, pts: np.ndarray, decoder: str, variant: str) -> None:
        c, size = _geom(pts)
        for f in found:
            fc, fs = _geom(f["pts"])
            if np.linalg.norm(c - fc) < 0.5 * min(size, fs):
                if f["payload"] is None and payload is not None:   # upgrade a detection-only entry
                    f.update(payload=payload, pts=pts, decoder=decoder, variant=variant)
                return
        found.append({"payload": payload, "pts": pts, "decoder": decoder, "variant": variant})

    engines: list[tuple[str, Engine]] = [("opencv-qrcodedetector", _opencv_classic),
                                         ("opencv-qrcodedetector-aruco", _opencv_aruco)]
    variants = _variants(bgr)
    for vname, img, scale, pad in variants:
        for ename, eng in engines:
            if time.perf_counter() - t0 > time_budget_s:
                res.attempts.append("time budget exhausted")
                break
            try:
                hits = eng(img)
            except cv2.error:
                res.attempts.append(f"{ename}/{vname}: opencv error")
                continue
            res.attempts.append(f"{ename}/{vname}: {len(hits)} detected, {sum(1 for h in hits if h[0])} decoded")
            for payload, pts in hits:
                merge(payload, (pts - pad) / scale, ename, vname)
        # stop early once everything detected so far is decoded
        if found and all(f["payload"] is not None for f in found) and vname in {"original", "padded", "upscaled_2x"}:
            break

    # internal fallback only when OpenCV left something undecoded or found nothing
    if (not found or any(f["payload"] is None for f in found)) and _HAS_ZXING:
        for vname, img, scale, pad in variants[:3]:
            try:
                hits = _zxing(img)
            except Exception:  # pragma: no cover - defensive
                continue
            res.attempts.append(f"zxing-cpp (fallback)/{vname}: {len(hits)} detected, {sum(1 for h in hits if h[0])} decoded")
            for payload, pts in hits:
                merge(payload, (pts - pad) / scale, "zxing-cpp (fallback)", vname)
            if found and all(f["payload"] is not None for f in found):
                break

    found.sort(key=lambda f: (round(float(f["pts"][:, 1].min()) / 50), float(f["pts"][:, 0].min())))
    for i, f in enumerate(found):
        pts = np.rint(f["pts"]).astype(int).tolist()
        decoded = f["payload"] is not None
        res.codes.append(DetectedQR(
            index=i, decoded=decoded, payload=f["payload"], bbox=pts, decoder=f["decoder"], variant=f["variant"],
            note=None if decoded else "A QR pattern was located but its content could not be decoded.",
        ))
    res.duration_ms = round((time.perf_counter() - t0) * 1000, 1)
    return res
