"""Versioned rule registry and reference-data loader.

Rules live in ``rules/*.yaml`` (one file per payload family) and reference lists in
``rules/reference/*.yaml``. Synthetic test fixtures live in ``rules/test_fixtures/*.yaml``
and are only loaded when ``include_synthetic=True``. Analyzers never hard-code severity:
they ask the registry to build an :class:`Evidence` object for a rule id, so every finding
is traceable and auditable.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .models import Confidence, Evidence, Family, MismatchType, Severity, Source


@dataclass
class Rule:
    id: str
    title: str
    description: str
    category: str
    rationale: str
    severity: Severity
    applicability: list[str]
    family: Family
    independent_group: str
    layer: str = "payload"
    recommendation: str | None = None
    mismatch_type: MismatchType | None = None
    file: str = ""


class RuleRegistry:
    def __init__(self, rules_dir: Path):
        self.rules_dir = Path(rules_dir)
        self._rules: dict[str, Rule] = {}
        self.file_versions: dict[str, str] = {}
        self._hash = hashlib.sha256()
        self._load()

    def _load(self) -> None:
        for path in sorted(self.rules_dir.glob("*.yaml")):
            raw = path.read_bytes()
            self._hash.update(raw)
            doc = yaml.safe_load(raw) or {}
            self.file_versions[path.name] = str(doc.get("version", "unversioned"))
            defaults = doc.get("defaults", {}) or {}
            for r in doc.get("rules", []) or []:
                merged = {**defaults, **r}
                rid = merged["id"]
                if rid in self._rules:
                    raise ValueError(f"duplicate rule id {rid} in {path.name}")
                mt = merged.get("mismatch_type")
                self._rules[rid] = Rule(
                    id=rid,
                    title=merged["title"],
                    description=merged["description"].strip(),
                    category=merged["category"],
                    rationale=merged["rationale"].strip(),
                    severity=Severity(merged["severity"]),
                    applicability=list(merged.get("applicability", [])),
                    family=Family(merged["family"]),
                    independent_group=merged["independent_group"],
                    layer=merged.get("layer", "payload"),
                    recommendation=merged.get("recommendation"),
                    mismatch_type=MismatchType(mt) if mt else None,
                    file=path.name,
                )

    @property
    def version(self) -> str:
        return self._hash.hexdigest()[:12]

    def get(self, rule_id: str) -> Rule:
        try:
            return self._rules[rule_id]
        except KeyError as exc:
            raise KeyError(f"unregistered rule id: {rule_id}") from exc

    def all(self) -> list[Rule]:
        return list(self._rules.values())

    def make(
        self,
        rule_id: str,
        observation: str,
        *,
        source: Source,
        confidence: Confidence = Confidence.HIGH,
        expected: str | None = None,
        payload_field: str | None = None,
        context_attribute: str | None = None,
        related_action: str | None = None,
        severity: Severity | None = None,
        mismatch_type: MismatchType | None = None,
        plausible_exceptions: list[str] | None = None,
        provenance: str | None = None,
        recommendation: str | None = None,
        independent_group: str | None = None,
        notes: list[str] | None = None,
    ) -> Evidence:
        r = self.get(rule_id)
        return Evidence(
            indicator_id=r.id,
            title=r.title,
            category=r.category,
            severity=severity or r.severity,
            source=source,
            observation=observation,
            expected=expected,
            confidence=confidence,
            rationale=r.rationale,
            payload_field=payload_field,
            context_attribute=context_attribute,
            related_action=related_action,
            family=r.family,
            independent_group=independent_group or r.independent_group,
            recommendation=recommendation or r.recommendation,
            mismatch_type=mismatch_type or r.mismatch_type,
            plausible_exceptions=plausible_exceptions or [],
            provenance=provenance,
            layer=r.layer,
            notes=notes or [],
        )


@dataclass
class Brand:
    name: str
    aliases: list[str]
    domains: list[str]
    category: str = ""
    synthetic: bool = False


@dataclass
class ReferenceData:
    """Small, versioned reference lists. These are heuristics, not authoritative registries."""

    version: str = ""
    shorteners: dict[str, str] = field(default_factory=dict)          # domain -> category
    email_providers: set[str] = field(default_factory=set)
    processors: list[str] = field(default_factory=list)
    thresholds: dict[str, Any] = field(default_factory=dict)
    url_keywords: dict[str, list[str]] = field(default_factory=dict)
    legal_suffixes: set[str] = field(default_factory=set)
    generic_descriptors: set[str] = field(default_factory=set)
    wifi_generic: set[str] = field(default_factory=set)
    brands: list[Brand] = field(default_factory=list)
    schemes: dict[str, dict[str, Any]] = field(default_factory=dict)
    operations: dict[str, list[str]] = field(default_factory=dict)
    purposes: list[dict[str, Any]] = field(default_factory=list)
    context_types: dict[str, list[str]] = field(default_factory=dict)
    lexicon: dict[str, Any] = field(default_factory=dict)
    payment_app_schemes: set[str] = field(default_factory=set)
    file_versions: dict[str, str] = field(default_factory=dict)

    @classmethod
    def load(cls, rules_dir: Path, include_synthetic: bool = True) -> "ReferenceData":
        ref_dir = Path(rules_dir) / "reference"
        fix_dir = Path(rules_dir) / "test_fixtures"
        h = hashlib.sha256()
        ref = cls()

        def read_path(p: Path, key_name: str) -> dict:
            raw = p.read_bytes()
            h.update(raw)
            doc = yaml.safe_load(raw) or {}
            ref.file_versions[key_name] = str(doc.get("version", "unversioned"))
            return doc

        def read(name: str) -> dict:
            return read_path(ref_dir / name, name)

        lists = read("lists.yaml")
        ref.shorteners = {d.lower(): c for c, ds in lists["shorteners"].items() for d in ds}
        ref.email_providers = {d.lower() for d in lists["email_providers"]}
        ref.processors = [p.lower() for p in lists["payment_processors"]]
        ref.thresholds = lists["thresholds"]
        ref.url_keywords = {k: [x.lower() for x in v] for k, v in lists["url_keywords"].items()}
        ref.legal_suffixes = {x.lower() for x in lists["entity_lexicon"]["legal_suffixes"]}
        ref.generic_descriptors = {x.lower() for x in lists["entity_lexicon"]["generic_descriptors"]}
        ref.wifi_generic = {x.lower() for x in lists["entity_lexicon"]["wifi_generic"]}
        ref.payment_app_schemes = {x.lower() for x in lists["payment_app_schemes"]}

        def add_brands(doc: dict, synthetic: bool) -> None:
            for b in doc.get("brands", []):
                ref.brands.append(Brand(b["name"], b.get("aliases", []), [d.lower() for d in b["domains"]],
                                        b.get("category", ""), synthetic))

        add_brands(read("brands.yaml"), False)
        if include_synthetic:
            syn_path = fix_dir / "brands_synthetic.yaml"
            if not syn_path.exists():
                syn_path = ref_dir / "brands_synthetic.yaml"
            syn = read_path(syn_path, "brands_synthetic.yaml")
            add_brands(syn, True)
            ref.processors += [p.lower() for p in syn.get("payment_processors", [])]
            ref.email_providers |= {d.lower() for d in syn.get("email_providers", [])}
            for c, ds in (syn.get("shorteners") or {}).items():
                for d in ds:
                    ref.shorteners[d.lower()] = c
        sch = read("schemes.yaml")
        ref.schemes = {k.lower(): v for k, v in sch["schemes"].items()}
        ref.operations = {k: [x.lower() for x in v] for k, v in sch["operations"].items()}
        pur = read("purposes.yaml")
        ref.purposes = pur["purposes"]
        ref.context_types = {k: [x.lower() for x in v] for k, v in pur["context_types"].items()}
        ref.lexicon = read("lexicon.yaml")
        ref.version = h.hexdigest()[:12]
        return ref
