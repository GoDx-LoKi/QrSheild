"""JSON API (programmatic access to the same engine). Payloads are data; nothing is ever executed or fetched."""
from __future__ import annotations

from fastapi import APIRouter, File, Form, Request, UploadFile
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse

from qrshield_core.context.extract import build_context, context_from_scenario
from qrshield_core.image.loader import ImageError
from qrshield_core.pipeline import ABLATIONS, AnalysisConfig

from ..schemas import AnalyzePayloadRequest

router = APIRouter(prefix="/api/v1", tags=["api"])


@router.post("/analyze-payload")
async def analyze_payload(request: Request, body: AnalyzePayloadRequest):
    eng = request.app.state.qs.engine
    base = ABLATIONS[body.ablation]
    cfg = AnalysisConfig(body.ablation, base.use_payload, base.use_context, base.use_action, "lookup" if body.threat_intel else "off")
    ctx = context_from_scenario(body.context.model_dump(), source="user_input")
    res = await run_in_threadpool(eng.analyze_payload, body.payload, ctx, cfg)
    return res.to_dict()


@router.post("/analyze")
async def analyze_image(request: Request, image: UploadFile = File(...), organization: str = Form(""), context_type: str = Form(""),
                        purpose: str = Form(""), amount: str = Form(""), additional: str = Form(""), qr_index: int | None = Form(None),
                        use_unconfirmed_ocr: bool = Form(False)):
    qs = request.app.state.qs
    data = await image.read(qs.settings.max_image_size_mb * 1024 * 1024 + 1)
    try:
        prep = await run_in_threadpool(qs.engine.prepare_image, data, image.filename)
    except ImageError as exc:
        return JSONResponse({"error": exc.code, "detail": exc.message}, 400)
    if prep.decode.count == 0:
        return JSONResponse({"error": "no_qr_found", "detail": "No QR code was detected. This is not a security verdict.",
                             "ocr_status": prep.ocr.status}, 422)
    if prep.decode.count > 1 and qr_index is None:
        return JSONResponse({"error": "select_qr", "detail": f"{prep.decode.count} QR codes found; explicitly pass qr_index.", "count": prep.decode.count}, 422)
    selected_index = 0 if qr_index is None else qr_index
    if selected_index < 0 or selected_index >= prep.decode.count:
        return JSONResponse({"error": "select_qr", "detail": f"qr_index must be between 0 and {prep.decode.count - 1}.", "count": prep.decode.count}, 422)
    manual = {"organization": organization, "context_type": context_type, "purpose": purpose, "amount": amount, "additional": additional}
    ctx = build_context(prep.candidates, None, manual, auto_use_unconfirmed=use_unconfirmed_ocr)
    res = await run_in_threadpool(qs.engine.analyze_prepared, prep, selected_index, ctx, AnalysisConfig("full"))
    return res.to_dict()


@router.get("/rules")
async def list_rules(request: Request):
    e = request.app.state.qs.engine
    return {"rule_version": e.reg.version, "reference_data_version": e.ref.version,
            "rules": [{"id": r.id, "title": r.title, "category": r.category, "severity": r.severity.value, "family": r.family.value,
                       "layer": r.layer, "applicability": r.applicability, "rationale": r.rationale} for r in e.reg.all()]}
