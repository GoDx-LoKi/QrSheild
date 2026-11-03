"""Analyze workflow: upload → review detected QR + OCR context → analyze → results/exports."""
from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, File, Request, UploadFile
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response

from qrshield_core.context.extract import ContextDecision, build_context
from qrshield_core.image.loader import ImageError
from qrshield_core.pipeline import AnalysisConfig
from qrshield_core.reporting.export import findings_csv, to_json_bytes

from ..state import ID_RE, AppState

router = APIRouter()
SEV_RANK = {"strong": 3, "meaningful": 2, "weak": 1, "info": 0}
CONTEXT_TYPES = ["", "hotel", "restaurant", "shop", "salon", "clinic", "hospital", "university", "school", "bank",
                 "government office", "event", "transit", "parking", "website", "poster", "package", "receipt", "product", "office", "other"]
ATTR_TITLES = {"organization": "Organization / venue", "purpose": "Stated purpose", "amount": "Displayed amount", "domain": "Displayed website",
               "email": "Displayed email", "phone": "Displayed phone", "network": "Network label", "context_type": "Context type"}


def qs_(request: Request) -> AppState:
    return request.app.state.qs


def render(request: Request, name: str, ctx: dict[str, Any], status: int = 200) -> HTMLResponse:
    try:
        return request.app.state.templates.TemplateResponse(request, name, ctx, status_code=status)
    except TypeError:
        return request.app.state.templates.TemplateResponse(name, {"request": request, **ctx}, status_code=status)


def view_result(res: dict[str, Any]) -> dict[str, Any]:
    """Pre-compute the evidence ledger (grouped by family) for the template. Pure presentation logic."""
    by: dict[str, list[dict]] = {}
    for key, scope in (("payload_findings", "local"), ("context_findings", "local"), ("action_findings", "local"), ("threat_intel_findings", "external")):
        for e in res.get(key, []):
            by.setdefault(e["family"], []).append({**e, "scope": scope})
    groups = []
    for g in res.get("evidence_groups", []):
        items = sorted(by.get(g["family"], []), key=lambda e: (-SEV_RANK[e["severity"]], e["indicator_id"]))
        groups.append({**g, "findings": items})
    return {"res": res, "groups": groups}


def _clean(v: Any, limit: int = 200) -> str:
    return str(v or "").strip()[:limit]


@router.get("/", response_class=HTMLResponse)
async def index(request: Request):
    qs = qs_(request)
    return render(request, "analyze.html", {"page": "analyze", "max_mb": qs.settings.max_image_size_mb})


@router.post("/analyze/prepare", response_class=HTMLResponse)
async def prepare(request: Request, image: UploadFile = File(...)):
    qs = qs_(request)
    limit = qs.settings.max_image_size_mb * 1024 * 1024
    data = await image.read(limit + 1)
    try:
        prep = await run_in_threadpool(qs.engine.prepare_image, data, image.filename)
    except ImageError as exc:
        return render(request, "partials/error.html", {"title": "The image could not be used", "message": exc.message}, 400)
    qs.save_upload(prep.analysis_id, prep.loaded.png_bytes)
    qs.put(prep.analysis_id, {"prep": prep})
    previews = [qs.engine.preview_payload(c.payload) if c.decoded and c.payload is not None else None for c in prep.decode.codes]
    cands: dict[str, list] = {}
    for c in prep.candidates:
        cands.setdefault(c.attribute, []).append(c)
    ti = qs.engine.ti_service.provider_state()
    return render(request, "partials/prepared.html", {
        "prep": prep, "previews": previews, "cands_by_attr": cands, "attr_titles": ATTR_TITLES, "context_types": CONTEXT_TYPES,
        "ti_available": qs.settings.threat_intel_enabled and ti["configured"], "ti_state": ti,
        "multi": prep.decode.count > 1})


@router.post("/analyze/run", response_class=HTMLResponse)
async def run(request: Request):
    qs = qs_(request)
    form = await request.form()
    aid = _clean(form.get("analysis_id"), 40)
    sess = qs.get(aid) if ID_RE.match(aid) else None
    if not sess:
        return render(request, "partials/error.html", {"title": "Session expired", "message": "The uploaded image is no longer in memory. Please upload it again."}, 410)
    prep = sess["prep"]
    sel = _clean(form.get("qr_index"), 10)
    if sel == "all":
        idxs = [c.index for c in prep.decode.codes]
    elif sel.isdigit() and int(sel) < prep.decode.count:
        idxs = [int(sel)]
    else:
        return render(request, "partials/error.html", {"title": "Select a QR code",
                      "message": "Several QR codes (or none) were found; choose which one to analyse. QRShield never picks one silently."}, 400)
    decisions: dict[str, ContextDecision] = {}
    for c in prep.candidates:
        act = _clean(form.get(f"cand_{c.candidate_id}"), 10)
        if act in ("use", "edit", "ignore"):
            decisions[c.candidate_id] = ContextDecision(act, _clean(form.get(f"cand_{c.candidate_id}_value")))
    manual = {k: _clean(form.get(k), 1000 if k == "additional" else 200) for k in ("organization", "context_type", "purpose", "amount", "additional")}
    ctx = build_context(prep.candidates, decisions, manual)
    cfg = AnalysisConfig("full", threat_intel_mode="lookup" if form.get("ti_lookup") == "on" else "off")
    results = []
    for i in idxs:
        rid = uuid.uuid4().hex
        res = await run_in_threadpool(qs.engine.analyze_prepared, prep, i, ctx, cfg, None, rid)
        data = res.to_dict()
        qs.save_result(rid, data)
        raw = prep.decode.codes[i].payload
        qs.put(rid, {"raw": raw, "context": ctx, "qr_index": i, "prep": prep})
        results.append(view_result(data))
    return render(request, "partials/results.html", {"items": results, "ti_available": qs.settings.threat_intel_enabled and qs.engine.ti_service.provider_state()["configured"]})


# NOTE: the export routes must be registered before the generic /results/{rid} route, which would otherwise match 'abc.json'.
@router.get("/results/{rid}.json")
async def result_json(request: Request, rid: str):
    data = qs_(request).load_result(rid)
    if not data:
        return JSONResponse({"error": "not_found"}, 404)
    return Response(to_json_bytes(data), media_type="application/json", headers={"Content-Disposition": f'attachment; filename="qrshield-{rid[:8]}.json"'})


@router.get("/results/{rid}.csv")
async def result_csv(request: Request, rid: str):
    data = qs_(request).load_result(rid)
    if not data:
        return JSONResponse({"error": "not_found"}, 404)
    return Response(findings_csv(data), media_type="text/csv", headers={"Content-Disposition": f'attachment; filename="qrshield-{rid[:8]}-findings.csv"'})


@router.get("/results/{rid}", response_class=HTMLResponse)
async def result_page(request: Request, rid: str):
    data = qs_(request).load_result(rid)
    if not data:
        return render(request, "partials/error_page.html", {"page": "analyze", "title": "Result not found", "message": "This result does not exist or has expired."}, 404)
    return render(request, "result_page.html", {"page": "analyze", "items": [view_result(data)], "ti_available": False})


@router.get("/image/{aid}")
async def image(request: Request, aid: str):
    p = qs_(request).upload_path(aid)
    if not p:
        return JSONResponse({"error": "not_found"}, 404)
    return FileResponse(p, media_type="image/png")


@router.post("/results/{rid}/scan", response_class=HTMLResponse)
async def explicit_scan(request: Request, rid: str):
    """Fresh external scan: runs ONLY after explicit confirmation, because it sends the URL to the provider."""
    qs = qs_(request)
    form = await request.form()
    sess = qs.get(rid) if ID_RE.match(rid) else None
    if form.get("confirm") != "yes":
        return render(request, "partials/error.html", {"title": "Confirmation required", "message": "Tick the confirmation box: a fresh scan sends the URL to the external provider."}, 400)
    if not sess:
        return render(request, "partials/error.html", {"title": "Session expired", "message": "Re-run the analysis to request a scan."}, 410)
    new_id = uuid.uuid4().hex
    res = await run_in_threadpool(qs.engine.analyze_payload, sess["raw"], sess["context"], AnalysisConfig("full", threat_intel_mode="scan"),
                                  analysis_id=new_id, ocr=sess["prep"].ocr, candidates=sess["prep"].candidates)
    data = res.to_dict()
    qs.save_result(new_id, data)
    qs.put(new_id, sess)
    return render(request, "partials/results.html", {"items": [view_result(data)], "ti_available": False})
