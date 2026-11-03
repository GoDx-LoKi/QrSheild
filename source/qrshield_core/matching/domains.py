"""Host/domain helpers. A small built-in multi-part-suffix set is used instead of the full Public Suffix
List so the engine works offline; this is a documented approximation."""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

MULTI_SUFFIX = {
    "co.in", "org.in", "net.in", "gov.in", "ac.in", "edu.in", "nic.in", "res.in", "firm.in", "gen.in", "ind.in",
    "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "com.sg", "com.my", "co.jp", "co.za", "com.br", "com.cn", "com.hk", "co.kr", "com.mx",
    "com.tr", "com.pk", "com.bd", "com.np", "co.id", "co.th", "com.vn", "com.ph", "com.sa", "com.eg",
    "co.il", "com.ng", "co.ke", "com.ar", "com.co", "com.pe", "com.ua", "com.pl",
}

_CONFUSABLES = {
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c", "\u0445": "x", "\u0443": "y",
    "\u0456": "i", "\u0455": "s", "\u0501": "d", "\u0261": "g", "\u03bf": "o", "\u03bd": "v", "\u03c1": "p",
    "\u03b1": "a", "\u0131": "i", "\u0578": "n", "\u0585": "o",
}
_HOMO = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "$": "s", "|": "l", "@": "a", "!": "i"})


@dataclass
class HostParts:
    host: str
    subdomains: list[str]
    sld: str
    suffix: str
    registrable: str


def split_host(host: str) -> HostParts:
    h = (host or "").lower().rstrip(".")
    labels = [x for x in h.split(".") if x]
    if len(labels) < 2:
        return HostParts(h, [], h, "", h)
    last2 = ".".join(labels[-2:])
    if last2 in MULTI_SUFFIX and len(labels) >= 3:
        suffix, sld, subs = last2, labels[-3], labels[:-3]
    else:
        suffix, sld, subs = labels[-1], labels[-2], labels[:-2]
    return HostParts(h, subs, sld, suffix, f"{sld}.{suffix}")


def registrable_domain(host: str) -> str:
    return split_host(host).registrable


def skeleton(s: str) -> str:
    """Confusable-folded form used for homoglyph comparison (ASCII digits/letters only)."""
    s = "".join(_CONFUSABLES.get(c, c) for c in (s or "").lower())
    s = unicodedata.normalize("NFKD", s).encode("ascii", "ignore").decode("ascii")
    s = s.replace("rn", "m").replace("vv", "w").translate(_HOMO)
    return re.sub(r"[^a-z0-9]", "", s)


def edit_distance(a: str, b: str) -> int:
    if a == b:
        return 0
    if abs(len(a) - len(b)) > 3:
        return abs(len(a) - len(b))
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def normalize_phone(p: str) -> str:
    return re.sub(r"\D", "", p or "")


def phones_equal(a: str, b: str) -> bool:
    da, db = normalize_phone(a), normalize_phone(b)
    if len(da) < 7 or len(db) < 7:
        return False
    n = min(10, len(da), len(db))
    return da[-n:] == db[-n:]
