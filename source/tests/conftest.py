"""Shared fixtures. All tests run offline, without API keys and without PaddleOCR models."""
from __future__ import annotations

from pathlib import Path

import pytest

from qrshield_core.analyzers import Deps
from qrshield_core.config import Settings
from qrshield_core.context.consistency import ConsistencyEngine
from qrshield_core.context.extract import context_from_scenario
from qrshield_core.matching.entity import Matcher
from qrshield_core.normalizer.normalize import normalize
from qrshield_core.pipeline import QRShieldEngine
from qrshield_core.rules import ReferenceData, RuleRegistry

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="session")
def settings(tmp_path_factory) -> Settings:
    s = Settings.from_env()
    s.load_synthetic_reference = True
    s.artifacts_dir = tmp_path_factory.mktemp("artifacts")
    s.log_level = "WARNING"
    s.env = "test"
    s.virustotal_api_key = ""          # tests must never depend on (or use) a real key
    s.access_token = ""                # tests explicitly enable auth for remote-host cases
    s.allowed_hosts = ["127.0.0.1", "localhost", "[::1]", "testserver"]
    return s


@pytest.fixture(scope="session")
def reg() -> RuleRegistry:
    return RuleRegistry(ROOT / "rules")


@pytest.fixture(scope="session")
def ref() -> ReferenceData:
    return ReferenceData.load(ROOT / "rules", include_synthetic=True)


@pytest.fixture(scope="session")
def matcher(ref) -> Matcher:
    return Matcher(ref)


@pytest.fixture(scope="session")
def deps(reg, ref, matcher) -> Deps:
    return Deps(reg, ref, matcher)


@pytest.fixture(scope="session")
def consistency(deps) -> ConsistencyEngine:
    return ConsistencyEngine(deps)


@pytest.fixture(scope="session")
def engine(settings) -> QRShieldEngine:
    return QRShieldEngine(settings, use_default_ocr=False)


@pytest.fixture()
def norm(ref):
    return lambda raw: normalize(raw, ref)


@pytest.fixture()
def ctx():
    return context_from_scenario


def ids(evidence) -> set[str]:
    return {e.indicator_id for e in evidence}
