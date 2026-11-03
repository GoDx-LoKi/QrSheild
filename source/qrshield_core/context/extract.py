"""Context extraction: OCR blocks -> candidate context attributes with provenance and confidence; and the
construction of the confirmed :class:`Context` from user decisions, manual input, or (explicitly) unconfirmed OCR."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from ..models import CONF_ORDER, Confidence, Context, ContextAttribute, min_conf
from ..ocr.engine import AMOUNT_RE, DOMAIN_RE, EMAIL_RE, PHONE_RE, OCRBlock
from ..rules import ReferenceData
from .purpose import infer_context_type, infer_purpose

ATTR_FOR_TYPE = {"organization": "organization", "purpose": "purpose", "amount": "amount", "domain": "domain",
                 "email": "email", "phone": "phone", "network": "network", "application": "application"}

_LABEL_PATTERNS = {
    "organization": re.compile(r"(?i)^\s*(?:organization|organisation|merchant|business|venue|company|operated\s+by|a\s+unit\s+of|parent|subsidiary\s+of|dba)\s*[:\-]?\s*(.*)$"),
    "purpose": re.compile(r"(?i)^\s*purpose\s*[:\-]\s*(.*)$"),
    "amount": re.compile(r"(?i)^\s*amount\s*[:\-]\s*(.*)$"),
    "domain": re.compile(r"(?i)^\s*(?:official\s+domain|website|site|web\s+address)\s*[:\-]\s*(.*)$"),
    "email": re.compile(r"(?i)^\s*(?:contact\s+email|email|email\s+address)\s*[:\-]\s*(.*)$"),
    "phone": re.compile(r"(?i)^\s*(?:displayed\s+phone|contact\s+phone|phone|telephone|tel)\s*[:\-]\s*(.*)$"),
    "network": re.compile(r"(?i)^\s*(?:network|ssid|wi[- ]?fi\s+network|network\s+name)\s*[:\-]\s*(.*)$"),
}
_PARENT_ORG_INLINE_RE = re.compile(r"(?i)(?:operated\s+by|a\s+unit\s+of|parent\s*(?:company)?|dba|billed\s+as)\s*[:\-]?\s*([A-Za-z0-9][A-Za-z0-9 &.,'-]{2,45})")

_EMAIL_VALUE_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_PHONE_VALUE_RE = re.compile(r"(?<![\w.])\+?\d[\d\s().-]{7,16}\d(?![\w])")
_DOMAIN_VALUE_RE = re.compile(r"(?i)(?:https?://)?(?:www\.)?[a-z0-9-]+(?:\.[a-z0-9-]+)+")
_WATERMARK_RE = re.compile(r"(?i)^\s*synthetic\s+test\s+scenario\s*$")
_CONTINUATION_RE = re.compile(r"^[a-z0-9._-]+$")
_BARE_TLD_RE = re.compile(r"^(?:test|invalid|example|local|com|org|net|edu|gov|in|io|co)$")


def is_explicit_label_or_watermark(text: str) -> bool:
    """Return True if text begins with an explicit context label or is a synthetic watermark."""
    t = (text or "").strip()
    if not t:
        return False
    if _WATERMARK_RE.match(t):
        return True
    return any(p.match(t) for p in _LABEL_PATTERNS.values())


@dataclass
class ContextCandidate:
    candidate_id: str
    attribute: str
    raw_text: str
    normalized_text: str
    value: str
    confidence: Confidence
    bbox: list[list[int]]
    source: str = "ocr"
    candidate_type: str = "other"
    note: str | None = None
    rank: int = 0


def _bbox_height(b: list[list[int]]) -> float:
    ys = [p[1] for p in b] or [0]
    return float(max(ys) - min(ys))


def _lower(c: Confidence) -> Confidence:
    return {Confidence.HIGH: Confidence.MEDIUM, Confidence.MEDIUM: Confidence.LOW, Confidence.LOW: Confidence.LOW}[c]


def _join_wrapped_pieces(pieces: list[str], attr: str) -> str:
    """Join multi-line OCR pieces, restoring a dropped dot before a bare TLD if OCR wrapped at '.'."""
    non_empty = [p.strip() for p in pieces if p and p.strip()]
    if not non_empty:
        return ""
    if attr not in {"email", "domain"}:
        return " ".join(non_empty).strip()
    acc = re.sub(r"\s+", "", non_empty[0])
    for part in non_empty[1:]:
        p_clean = re.sub(r"\s+", "", part)
        if not p_clean:
            continue
        if (
            not acc.endswith(".")
            and not p_clean.startswith(".")
            and _BARE_TLD_RE.match(p_clean.lower())
            and (("@" in acc and "." not in acc.split("@", 1)[1]) or (attr == "domain" and "." not in acc))
        ):
            acc = f"{acc}.{p_clean}"
        else:
            acc = f"{acc}{p_clean}"
    return acc.strip()


def extract_candidates(blocks: list[OCRBlock], ref: ReferenceData) -> list[ContextCandidate]:
    cands: list[ContextCandidate] = []
    n = 0
    existing: set[tuple[str, str]] = set()
    consumed_ids: set[str] = set()

    def add(attr: str, blk: OCRBlock, value: str, note: str | None = None, conf: Confidence | None = None, rank: int = 0) -> None:
        value = (value or "").strip()
        if not value:
            return
        key = (attr, value.lower())
        if key in existing:
            return
        existing.add(key)
        nonlocal n
        n += 1
        cands.append(ContextCandidate(f"c{n}", attr, blk.raw_text, blk.normalized_text, value, conf or blk.confidence,
                                      blk.bbox, "ocr", blk.candidate_type, note, rank))

    orgs: list[OCRBlock] = []

    def _bbox_union(items: list[OCRBlock]) -> list[list[int]]:
        xs = [pt[0] for b in items for pt in b.bbox] or [0]
        ys = [pt[1] for b in items for pt in b.bbox] or [0]
        return [[min(xs), min(ys)], [max(xs), min(ys)], [max(xs), max(ys)], [min(xs), max(ys)]]

    def _label_value(items: list[OCRBlock], attr: str, line_index: int) -> tuple[str, list[OCRBlock]] | None:
        first = items[line_index]
        m = _LABEL_PATTERNS[attr].match(first.normalized_text)
        if not m:
            return None
        first_val = m.group(1).strip()
        pieces = [first_val]
        used = [first]
        allow_multiline = (not first_val) or (attr in {"email", "domain", "phone"})
        if not allow_multiline:
            return first_val, used

        for j in range(line_index + 1, min(line_index + 3, len(items))):
            nxt = items[j]
            nxt_txt = nxt.normalized_text.strip()
            if not nxt_txt or is_explicit_label_or_watermark(nxt_txt):
                break
            candidate = _join_wrapped_pieces(pieces, attr)
            parsed = (_EMAIL_VALUE_RE.search(candidate) if attr == "email" else
                      _PHONE_VALUE_RE.search(candidate) if attr == "phone" else
                      _DOMAIN_VALUE_RE.search(candidate) if attr == "domain" else
                      bool(candidate))
            is_wrapped_tail = (
                attr in {"email", "domain"}
                and len(nxt_txt) <= 14
                and " " not in nxt_txt
                and bool(_CONTINUATION_RE.match(nxt_txt))
            )
            if parsed and not is_wrapped_tail:
                break
            if nxt.bbox and first.bbox:
                fy = max(pt[1] for pt in first.bbox)
                ny = min(pt[1] for pt in nxt.bbox)
                if ny - fy > max(80, int(_bbox_height(first.bbox) * 2.5)):
                    break
            pieces.append(nxt_txt)
            used.append(nxt)
            if first_val == "" and attr not in {"email", "domain", "phone"}:
                break
        return _join_wrapped_pieces(pieces, attr), used

    for b in blocks:
        if _WATERMARK_RE.match(b.normalized_text.strip()):
            consumed_ids.add(b.block_id)

    for i, b in enumerate(blocks):
        if b.block_id in consumed_ids:
            continue
        for attr, pat in _LABEL_PATTERNS.items():
            if not pat.match(b.normalized_text):
                continue
            lv = _label_value(blocks, attr, i)
            if not lv:
                continue
            raw_value, used = lv
            for u_blk in used:
                consumed_ids.add(u_blk.block_id)
            norm = raw_value.strip().strip("\u2014\u2013-:;() ")
            value = norm
            if attr == "email":
                norm = re.sub(r"\s+", "", norm)
                m = _EMAIL_VALUE_RE.search(norm)
                if m:
                    value = m.group(0)
            elif attr == "phone":
                m = _PHONE_VALUE_RE.search(norm)
                if m:
                    value = m.group(0).strip()
            elif attr == "domain":
                m = _DOMAIN_VALUE_RE.search(norm)
                if m:
                    value = m.group(0).lower().rstrip("./")
                    value = re.sub(r"^https?://", "", value, flags=re.I).removeprefix("www.")
            elif attr == "amount":
                m = re.search(r"(?<![A-Za-z])[-+]?\d[\d,]*(?:\.\d{1,2})?", norm)
                if m:
                    value = m.group(0).replace(",", "")
            elif attr == "purpose":
                value = norm
            elif attr == "network":
                value = norm
            elif attr == "organization":
                value = norm
            if value:
                source_blk = used[0]
                eff_conf = source_blk.confidence
                if eff_conf is Confidence.LOW and source_blk.score >= 0.35:
                    eff_conf = Confidence.MEDIUM
                note = "Extracted from an explicit context label."
                if len(used) > 1:
                    note += " OCR-wrapped value was reconstructed from adjacent lines."
                is_sub_org = bool(re.match(r"(?i)^\s*(?:operated\s+by|a\s+unit\s+of|parent|subsidiary\s+of|dba)\b", source_blk.normalized_text))
                org_rank = (1 if any(c.attribute == "organization" and c.rank == 0 for c in cands) else 0) if attr == "organization" else 0
                if is_sub_org:
                    org_rank = max(1, org_rank)
                add(attr, OCRBlock(source_blk.block_id, source_blk.raw_text, " ".join(u.normalized_text for u in used),
                                    source_blk.score, eff_conf, _bbox_union(used), source_blk.candidate_type),
                    value, note=note, conf=eff_conf, rank=org_rank)

    # Generic OCR classification remains in place for unlabeled context blocks not already consumed.
    for b in blocks:
        if b.block_id in consumed_ids:
            continue
        t = b.normalized_text
        if is_explicit_label_or_watermark(t):
            continue
        m_parent = _PARENT_ORG_INLINE_RE.search(t)
        if m_parent:
            add("organization", b, m_parent.group(1).strip(" ()-"), note="Extracted parent/operating entity.", rank=1)
        if b.candidate_type == "email":
            m_em = EMAIL_RE.search(t)
            if m_em:
                add("email", b, m_em.group(0))
        elif b.candidate_type == "amount":
            m = AMOUNT_RE.search(t)
            digits = re.sub(r"[^\d.]", "", (m.group(0) if m else t)).strip(".")
            cur = "INR" if re.search(r"₹|rs|inr|/-", t, re.I) else "USD" if re.search(r"\$|usd", t, re.I) else "EUR" if re.search(r"€|eur", t, re.I) else None
            add("amount", b, digits, note=f"currency inferred: {cur}" if cur else None)
        elif b.candidate_type == "phone":
            m_ph = PHONE_RE.search(t)
            if m_ph:
                ph_val = m_ph.group(0).strip()
                ph_conf = (
                    Confidence.MEDIUM
                    if (b.confidence is Confidence.LOW and b.score >= 0.33 and len(re.sub(r"\D", "", ph_val)) >= 10)
                    else b.confidence
                )
                add("phone", b, ph_val, conf=ph_conf)
        elif b.candidate_type == "domain":
            m_dm = DOMAIN_RE.search(t)
            if m_dm:
                add("domain", b, m_dm.group(0).lower())
        elif b.candidate_type == "purpose":
            add("purpose", b, t)
        elif b.candidate_type == "network":
            add("network", b, t)
        elif b.candidate_type == "organization":
            orgs.append(b)

    # organisation ranking: prominent (tall), confident, high on the page
    has_explicit_org = any(c.attribute == "organization" and c.rank == 0 for c in cands)
    ranked = sorted(orgs, key=lambda b: -(_bbox_height(b.bbox) * max(b.score, 0.01)))
    for i, b in enumerate(ranked[:3]):
        rank_idx = (i + 1) if has_explicit_org else i
        conf = b.confidence
        note = None
        if rank_idx == 0 and len(ranked) > 1 and ranked[1].confidence is not Confidence.LOW:
            h0, h1 = _bbox_height(ranked[0].bbox), _bbox_height(ranked[1].bbox)
            if h1 >= 0.85 * h0:
                conf, note = _lower(conf), "Several similarly prominent names were found; confirm which one identifies the venue."
        if rank_idx > 0:
            conf = _lower(conf)
        if b.raw_text != b.normalized_text:
            note = (note + " " if note else "") + "OCR artefacts were normalised; raw text differs."
        add("organization", b, b.normalized_text, note, conf, rank=rank_idx)

    # Ensure at least one rank=0 organization exists if any organization candidates were extracted
    org_cands = [c for c in cands if c.attribute == "organization"]
    if org_cands and not any(c.rank == 0 for c in org_cands):
        org_cands[0].rank = 0

    # context type suggestion from the primary organisation / purpose text
    prim = next((c for c in cands if c.attribute == "organization" and c.rank == 0), None)
    text = " ".join([prim.value] if prim else []) + " " + " ".join(c.value for c in cands if c.attribute == "purpose")
    ctype, kw = infer_context_type(text, ref)
    if ctype:
        base = prim or cands[0]
        n += 1
        cands.append(ContextCandidate(f"c{n}", "context_type", base.raw_text, base.normalized_text, ctype, Confidence.MEDIUM,
                                      base.bbox, "ocr", "inferred", f"Inferred from the word '{kw}'.", 0))
    return cands


@dataclass
class ContextDecision:
    action: str            # use | edit | ignore
    value: str | None = None


def build_context(candidates: list[ContextCandidate] | None = None,
                  decisions: dict[str, ContextDecision] | None = None,
                  manual: dict[str, str] | None = None,
                  *, auto_use_unconfirmed: bool = False, default_source: str = "user_input") -> Context:
    """Assemble the confirmed context."""
    ctx = Context()
    manual = manual or {}
    for attr in ("organization", "context_type", "purpose", "amount", "additional", "domain", "email", "phone", "network", "application"):
        v = (manual.get(attr) or "").strip()
        if v:
            ctx.attributes.append(ContextAttribute(attr, v, default_source, Confidence.HIGH))
    add_text = (manual.get("additional") or "")
    if add_text:
        for m in EMAIL_RE.findall(add_text):
            ctx.attributes.append(ContextAttribute("email", m, default_source, Confidence.HIGH))
        for m in PHONE_RE.findall(add_text):
            ctx.attributes.append(ContextAttribute("phone", m.strip(), default_source, Confidence.HIGH))
        for m in re.findall(r"(?i)\b(?:https?://)?(?:www\.)?[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,24}\b", add_text):
            if "@" not in m and not re.fullmatch(r"[\d.]+", m):
                ctx.attributes.append(ContextAttribute("domain", m.lower(), default_source, Confidence.HIGH))
    for c in sorted(candidates or [], key=lambda x: x.rank):
        d = (decisions or {}).get(c.candidate_id)
        if d is None and not auto_use_unconfirmed:
            continue
        if d is not None and d.action == "ignore":
            continue
        if d is None:
            ctx.attributes.append(ContextAttribute(c.attribute, c.value, "ocr", c.confidence, c.raw_text, c.bbox, c.candidate_id))
        elif d.action == "edit" and (d.value or "").strip():
            ctx.attributes.append(ContextAttribute(c.attribute, d.value.strip(), "user_input", Confidence.HIGH, c.raw_text, c.bbox, c.candidate_id))
        elif d.action == "use":
            ctx.attributes.append(ContextAttribute(c.attribute, c.value, "user_confirmed_ocr", Confidence.HIGH, c.raw_text, c.bbox, c.candidate_id))
    return ctx


def context_from_scenario(d: dict[str, Any] | None, source: str = "scenario_input") -> Context:
    """Context for controlled dataset scenarios (the dataset plays the role of confirmed context)."""
    src = d or {}
    aliases = {
        "official_domain": "domain",
        "contact_email": "email",
        "contact_phone": "phone",
        "displayed_phone": "phone",
        "merchant": "organization",
    }
    manual: dict[str, str] = {}
    for k, v in src.items():
        if v in (None, ""):
            continue
        target = aliases.get(k, k)
        manual.setdefault(target, str(v))
    return build_context(manual=manual, default_source=source)
