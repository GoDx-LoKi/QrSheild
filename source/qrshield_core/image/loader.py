"""Safe image ingestion: size/format limits, decompression-bomb guard, EXIF orientation, quality metrics.

The uploaded bytes are treated as untrusted. They are only ever parsed by Pillow/OpenCV; no filename,
metadata or embedded text is executed or interpolated into a shell/path.
"""
from __future__ import annotations

import hashlib
import io
import re
from dataclasses import dataclass, field
from typing import Any

import cv2
import numpy as np
from PIL import Image, ImageOps, UnidentifiedImageError

ALLOWED_FORMATS = {"PNG", "JPEG", "WEBP", "BMP", "GIF", "MPO"}


class ImageError(Exception):
    """Raised for rejected images. ``code`` is machine-readable; ``message`` is user-safe."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass
class LoadedImage:
    bgr: np.ndarray = field(repr=False)
    width: int
    height: int
    original_width: int
    original_height: int
    sha256: str
    format: str
    quality: dict[str, Any]
    warnings: list[str]
    png_bytes: bytes = field(repr=False, default=b"")

    def meta(self) -> dict[str, Any]:
        return {
            "sha256": self.sha256,
            "format": self.format,
            "width": self.width,
            "height": self.height,
            "original_width": self.original_width,
            "original_height": self.original_height,
            "quality": self.quality,
            "warnings": self.warnings,
        }


def sanitize_filename(name: str | None) -> str:
    """Return a display-safe filename (never used as a filesystem path)."""
    base = (name or "upload").replace("\\", "/").split("/")[-1]
    base = re.sub(r"[^A-Za-z0-9._ -]", "_", base)[:80].strip(" .")
    return base or "upload"


def image_quality(bgr: np.ndarray) -> tuple[dict[str, Any], list[str]]:
    gray = cv2.cvtColor(bgr, cv2.COLOR_BGR2GRAY)
    h, w = gray.shape
    sharp = float(cv2.Laplacian(gray, cv2.CV_64F).var())
    mean = float(gray.mean())
    std = float(gray.std())
    q = {
        "sharpness_laplacian_var": round(sharp, 1),
        "mean_brightness": round(mean, 1),
        "contrast_std": round(std, 1),
        "min_side_px": int(min(h, w)),
    }
    warns: list[str] = []
    if min(h, w) < 300:
        warns.append("Low resolution: the shorter image side is under 300 px.")
    if sharp < 50:
        warns.append("Image may be blurred (low Laplacian variance); decoding and OCR can be unreliable.")
    if mean < 50:
        warns.append("Image is very dark.")
    elif mean > 225:
        warns.append("Image is very bright or washed out.")
    if std < 25:
        warns.append("Image has low contrast.")
    return q, warns


def load_image(data: bytes, *, max_bytes: int, max_pixels: int, max_side: int) -> LoadedImage:
    if not data:
        raise ImageError("empty", "The uploaded file is empty.")
    if len(data) > max_bytes:
        raise ImageError("too_large", f"The image exceeds the {max_bytes // (1024 * 1024)} MB limit.")
    Image.MAX_IMAGE_PIXELS = max_pixels
    try:
        probe = Image.open(io.BytesIO(data))
        fmt = (probe.format or "").upper()
        if fmt not in ALLOWED_FORMATS:
            raise ImageError("unsupported_format", "Unsupported image format. Use PNG, JPEG, WEBP, BMP or GIF.")
        ow, oh = probe.size
        if ow * oh > max_pixels:
            raise ImageError("too_many_pixels", "The image has too many pixels to process safely.")
        probe.load()
        img = ImageOps.exif_transpose(probe)
        img = img.convert("RGB")
    except ImageError:
        raise
    except Image.DecompressionBombError as exc:      # Pillow's own guard fires inside Image.open; report it accurately
        raise ImageError("too_many_pixels", "The image has too many pixels to process safely.") from exc
    except (UnidentifiedImageError, OSError, ValueError, SyntaxError) as exc:
        raise ImageError("invalid_image", "The file could not be read as a valid image.") from exc

    w, h = img.size
    scale = min(1.0, max_side / max(w, h))
    if scale < 1.0:
        img = img.resize((max(1, int(w * scale)), max(1, int(h * scale))), Image.LANCZOS)
        w, h = img.size
    arr = np.asarray(img)[:, :, ::-1].copy()  # RGB -> BGR
    quality, warns = image_quality(arr)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return LoadedImage(
        bgr=arr, width=w, height=h, original_width=ow, original_height=oh,
        sha256=hashlib.sha256(data).hexdigest(), format=fmt, quality=quality,
        warnings=warns, png_bytes=buf.getvalue(),
    )
