from __future__ import annotations

import sys

from fastapi import APIRouter, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse, JSONResponse

from qrshield_core import __version__

from .analyze import qs_, render

router = APIRouter()


@router.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    qs = qs_(request)
    s, e = qs.settings, qs.engine
    ti = e.ti_service.provider_state()
    return render(request, "settings.html", {
        "page": "settings", "s": s, "ti": ti, "rule_version": e.reg.version, "ref_version": e.ref.version,
        "n_rules": len(e.reg.all()), "ocr_name": getattr(e.ocr_provider, "name", "none"), "py": sys.version.split()[0]})


@router.post("/settings/check-ocr", response_class=HTMLResponse)
async def check_ocr(request: Request):
    """Initialises the OCR engine on demand (first use may download model files)."""
    prov = qs_(request).engine.ocr_provider
    if prov is None:
        return render(request, "partials/status.html", {"ok": False, "text": "OCR is disabled (OCR_ENABLED=false)."})
    ok, why = await run_in_threadpool(prov.available)
    raw_provider_name = str(getattr(prov, "name", "OCR"))
    provider_name = {"paddleocr": "PaddleOCR", "tesseract": "Tesseract"}.get(
        raw_provider_name.lower(), raw_provider_name.replace("_", " ").title()
    )
    text = f"{provider_name} is initialised and ready." if ok else f"{provider_name} is unavailable: {why[:240]}"
    return render(request, "partials/status.html", {"ok": ok, "text": text})


@router.get("/health")
async def health():
    return JSONResponse({"status": "ok", "version": __version__})
