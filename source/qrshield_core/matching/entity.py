"""Entity matching: organisation names, organisation↔domain, SSID↔organisation.

Design notes
- Matching is lexical and heuristic. It never infers *ownership*; ``LIKELY MATCH`` means "same distinctive name
  once legal-form and generic descriptive words are ignored".
- Results are one of MATCH / LIKELY MATCH / UNCERTAIN / MISMATCH / INSUFFICIENT CONTEXT.
- A ``confidence_cap`` is returned when the comparison relied on weak evidence (e.g. only generic words).
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from typing import Any

from ..models import Confidence, MatchResult
from ..rules import Brand, ReferenceData
from .domains import registrable_domain, split_host

_GROUP_DOMAIN_WORDS = {
    "group", "holdings", "holding", "hospitality", "dining", "retail", "health",
    "medical", "partners", "ventures", "global", "corp", "enterprises", "network",
}
_ROGUE_SSID_SUFFIXES = {"portal", "login", "verify", "auth", "evil", "rogue", "phish", "intercept"}


@dataclass
class NameMatch:
    result: MatchResult
    rationale: str
    details: dict[str, Any] = field(default_factory=dict)
    exception_hint: str | None = None
    confidence_cap: Confidence | None = None


def _alnum(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", s.lower())


class Matcher:
    FUZZY = 0.84

    def __init__(self, ref: ReferenceData):
        self.ref = ref

    # ---- normalisation -------------------------------------------------
    def norm(self, s: str | None) -> str:
        s = unicodedata.normalize("NFKD", (s or "").casefold())
        s = "".join(c for c in s if not unicodedata.combining(c))
        s = s.replace("&", " and ")
        s = re.sub(r"[^a-z0-9]+", " ", s)
        return re.sub(r"\s+", " ", s).strip()

    def core_distinct(self, normalized: str) -> tuple[list[str], list[str]]:
        toks = [t for t in normalized.split() if t not in self.ref.legal_suffixes]
        distinct = [t for t in toks if t not in self.ref.generic_descriptors]
        return toks, distinct

    def processor_hint(self, name: str | None) -> str | None:
        n = f" {self.norm(name)} "
        for p in self.ref.processors:
            if f" {self.norm(p)} " in n:
                return (f"The name contains '{p}', which appears on the reference list of payment processors/aggregators. "
                        "Processors often appear as the payee, but a name alone does not prove a legitimate relationship.")
        return None

    # ---- name vs name --------------------------------------------------
    def compare_names(self, expected: str | None, observed: str | None) -> NameMatch:
        na, nb = self.norm(expected), self.norm(observed)
        if not na or not nb:
            return NameMatch(MatchResult.INSUFFICIENT_CONTEXT, "One of the two names is empty.")
        if na == nb:
            return NameMatch(MatchResult.MATCH, "Names are identical after case/punctuation normalisation.")
        ca, da = self.core_distinct(na)
        cb, db = self.core_distinct(nb)
        sa, sb = set(da), set(db)
        hint = self.processor_hint(observed)
        det = {"expected_tokens": da, "observed_tokens": db}
        if sa and sb:
            if sa == sb:
                return NameMatch(MatchResult.LIKELY_MATCH, "Same distinctive name once legal-form and generic descriptive words are ignored.", det)
            if sa <= sb or sb <= sa:
                return NameMatch(MatchResult.LIKELY_MATCH, "The distinctive words of one name are contained in the other.", det)
            if "".join(da) == "".join(db):
                return NameMatch(MatchResult.LIKELY_MATCH, "Names are equal when spacing is ignored.", det)
            small, big = (sa, sb) if len(sa) <= len(sb) else (sb, sa)
            if all(any(SequenceMatcher(None, t, u).ratio() >= self.FUZZY for u in big) for t in small):
                return NameMatch(MatchResult.UNCERTAIN, "Names are lexically very similar but not identical (possible OCR error, variant spelling or look-alike).", det, hint)
            if sa & sb:
                return NameMatch(MatchResult.UNCERTAIN, "Names share some distinctive words but differ in others.", det, hint)
            if len(sa) == 1 and len(db) >= 2 and "".join(w[0] for w in db) in sa:
                return NameMatch(MatchResult.UNCERTAIN, "One name may be an acronym of the other.", det, hint)
            if len(sb) == 1 and len(da) >= 2 and "".join(w[0] for w in da) in sb:
                return NameMatch(MatchResult.UNCERTAIN, "One name may be an acronym of the other.", det, hint)
            if hint:
                return NameMatch(MatchResult.UNCERTAIN, "The names are unrelated, but the observed name resembles a known payment intermediary.", det, hint)
            return NameMatch(MatchResult.MISMATCH, "No distinctive words in common and no known relationship.", det)
        # at least one side has only generic words: compare weakly
        if not (ca or cb):
            return NameMatch(MatchResult.INSUFFICIENT_CONTEXT, "Names contain no usable words.", det)
        det.update(expected_core=ca, observed_core=cb)
        if set(ca) & set(cb):
            return NameMatch(MatchResult.UNCERTAIN, "Only generic descriptive words are shared.", det, hint, Confidence.LOW)
        return NameMatch(MatchResult.MISMATCH, "Names share no words; comparison relied on generic words only.", det, hint, Confidence.LOW)

    # ---- organisation vs domain ---------------------------------------
    def org_domain_relation(self, org: str | None, host: str | None) -> NameMatch:
        h = (host or "").lower().strip(".")
        n = self.norm(org)
        if not h or not n:
            return NameMatch(MatchResult.INSUFFICIENT_CONTEXT, "Organisation or domain missing.")
        if re.fullmatch(r"[\d.:]+", h) or ":" in h:
            return NameMatch(MatchResult.UNCERTAIN, "An IP address carries no organisational identity to compare.", {"is_ip": True}, None, Confidence.LOW)
        hp = split_host(h)
        label = _alnum(hp.sld)
        core, distinct = self.core_distinct(n)
        if not core:
            return NameMatch(MatchResult.INSUFFICIENT_CONTEXT, "Organisation name contains no usable words.")
        concat_core, concat_dist = "".join(core), "".join(distinct)
        det = {"domain_label": label, "registrable": hp.registrable, "organisation_tokens": core}
        if label and label in {concat_core, concat_dist}:
            return NameMatch(MatchResult.LIKELY_MATCH, "The domain name equals the organisation name (spacing and legal form ignored).", det)
        parts = [_alnum(x) for x in hp.sld.split("-") if x]
        # Acronym + parent/group descriptor domain (Weakness 3: e.g. hbb-dining-group.org for Harborview Bistro)
        if len(parts) >= 2 and len(core) >= 2:
            initials = "".join(w[0] for w in core if w)
            if (
                len(initials) >= 2
                and parts[0].startswith(initials)
                and len(parts[0]) <= len(initials) + 2
                and all(p in _GROUP_DOMAIN_WORDS for p in parts[1:])
            ):
                return NameMatch(MatchResult.LIKELY_MATCH, "The domain label matches the organisation's initials followed by a group/sector descriptor.", det)
        if len(parts) > 1 and any(p in {concat_core, concat_dist} for p in parts if p):
            return NameMatch(MatchResult.UNCERTAIN, "The domain contains the organisation name plus extra words (for example 'verify' or 'secure'). This pattern is used in impersonation but also by legitimate sub-brands.", det)
        if concat_dist and len(concat_dist) >= 4 and concat_dist in label:
            return NameMatch(MatchResult.UNCERTAIN, "The domain label contains the organisation's distinctive name inside a longer string.", det)
        sub_join = _alnum("".join(hp.subdomains))
        if concat_dist and len(concat_dist) >= 4 and concat_dist in sub_join:
            det["impersonation_hint"] = True
            return NameMatch(MatchResult.MISMATCH, "The organisation name appears only as a subdomain of an unrelated registrable domain.", det)
        base = concat_dist or concat_core
        if base and label and SequenceMatcher(None, label, base).ratio() >= 0.85:
            return NameMatch(MatchResult.UNCERTAIN, "The domain label is lexically very close to the organisation name (possible look-alike or variant).", det)
        return NameMatch(MatchResult.MISMATCH, "The domain does not appear related to the organisation name. Many legitimate organisations use unrelated or third-party domains.", det)

    # ---- organisation vs SSID -----------------------------------------
    def ssid_relation(self, org: str | None, ssid: str | None) -> NameMatch:
        n = self.norm(org)
        if not n or not (ssid or "").strip():
            return NameMatch(MatchResult.INSUFFICIENT_CONTEXT, "Organisation or SSID missing.")
        spaced = re.sub(r"([a-z])([A-Z])", r"\1 \2", ssid)
        toks = [t for t in re.split(r"[^a-z0-9]+", spaced.lower()) if t]
        s_dist = [t for t in toks if t not in self.ref.wifi_generic and not t.isdigit()]
        concat = "".join(toks)
        core, distinct = self.core_distinct(n)
        basis = distinct or core
        cap = None if distinct else Confidence.LOW
        if not basis:
            return NameMatch(MatchResult.INSUFFICIENT_CONTEXT, "Organisation name contains no usable words.")
        det = {"ssid_tokens": toks, "ssid_identifying_tokens": s_dist, "organisation_tokens": basis}
        rogue_toks = [t for t in toks if t in _ROGUE_SSID_SUFFIXES and t not in core]
        if rogue_toks:
            return NameMatch(MatchResult.MISMATCH, f"The SSID appends an unverified portal/authentication token ({', '.join(rogue_toks)}) not present in the venue name.", det, None, cap)
        if any(t in basis for t in s_dist) or any(len(o) >= 3 and o in concat for o in basis):
            return NameMatch(MatchResult.LIKELY_MATCH, "The SSID contains the organisation's name.", det, None, cap)
        if not s_dist:
            return NameMatch(MatchResult.UNCERTAIN, "The SSID is generic and does not name any organisation.", det, None, Confidence.LOW)
        if all(any(SequenceMatcher(None, t, o).ratio() >= self.FUZZY for o in basis) for t in s_dist):
            return NameMatch(MatchResult.UNCERTAIN, "The SSID is lexically close to the organisation name but not identical.", det, None, cap)
        return NameMatch(MatchResult.MISMATCH, "The SSID names something unrelated to the organisation.", det, None, cap)

    # ---- brand registry ------------------------------------------------
    def known_brand(self, org: str | None) -> Brand | None:
        """Return the reference brand the organisation name refers to, or None when absent or ambiguous.

        Name comparison deliberately ignores generic descriptive words, so "ABC Shop" and "ABC Bank" share the
        distinctive token "abc". Brand lookup is therefore stricter: contradictory category words veto a match
        (shop vs bank) and ties are treated as ambiguous rather than guessed.
        """
        n_org = self.norm(org)
        if not n_org:
            return None
        core_o, dist_o = self.core_distinct(n_org)
        desc_o = set(core_o) - set(dist_o)
        best: list[tuple[int, Brand]] = []
        for b in self.ref.brands:
            score = 0
            for nm in [b.name, *b.aliases]:
                n_b = self.norm(nm)
                if self.compare_names(org, nm).result not in (MatchResult.MATCH, MatchResult.LIKELY_MATCH):
                    continue
                core_b, dist_b = self.core_distinct(n_b)
                if not dist_b:
                    continue
                desc_b = set(core_b) - set(dist_b)
                if desc_o and desc_b and not (desc_o & desc_b):
                    continue            # contradictory category words (e.g. shop vs bank)
                score = max(score, len(set(core_o) & set(core_b)))
            if score:
                best.append((score, b))
        if not best:
            return None
        top = max(sc for sc, _ in best)
        winners = [b for sc, b in best if sc == top]
        return winners[0] if len(winners) == 1 else None

    def is_official_domain(self, brand: Brand, host: str) -> bool:
        reg = registrable_domain(host)
        return reg in {registrable_domain(d) for d in brand.domains}
