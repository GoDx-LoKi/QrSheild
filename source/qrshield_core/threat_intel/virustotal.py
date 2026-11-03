"""VirusTotal v3 provider (URL report lookup; explicit scan submission).

Only the indicator (the URL) is sent. The API key is read from configuration, sent only in the ``x-apikey`` header,
and never logged or returned to the browser.
"""
from __future__ import annotations

import base64
from typing import Any

import httpx

from ..models import ThreatIntelStatus
from .base import ResultCache, ThreatIntelProvider, ThreatIntelResult, classify_stats

BASE = "https://www.virustotal.com/api/v3"


class VirusTotalProvider(ThreatIntelProvider):
    name = "VirusTotal"

    def __init__(self, api_key: str, *, client: httpx.Client | None = None, timeout: float = 10.0,
                 malicious_threshold: int = 3, cache: ResultCache | None = None):
        self._key = api_key
        self._client = client
        self.timeout = timeout
        self.threshold = malicious_threshold
        self.cache = cache

    def configured(self) -> tuple[bool, str]:
        return (bool(self._key), "" if self._key else "No VIRUSTOTAL_API_KEY configured.")

    @staticmethod
    def url_id(url: str) -> str:
        return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

    def _http(self) -> httpx.Client:
        return self._client or httpx.Client(timeout=self.timeout, follow_redirects=False)

    def _req(self, method: str, path: str, **kw: Any) -> httpx.Response:
        c = self._http()
        try:
            return c.request(method, BASE + path, headers={"x-apikey": self._key, "accept": "application/json"}, timeout=self.timeout, **kw)
        finally:
            if self._client is None:
                c.close()

    def _fail(self, url: str, qtype: str, exc: Exception | None = None, resp: httpx.Response | None = None) -> ThreatIntelResult:
        if resp is not None:
            if resp.status_code in (401, 403):
                return ThreatIntelResult(self.name, qtype, url, ThreatIntelStatus.AUTH_FAILURE, "Provider rejected the API key.")
            if resp.status_code == 429:
                return ThreatIntelResult(self.name, qtype, url, ThreatIntelStatus.RATE_LIMITED, "Provider rate limit reached; try again later.")
            return ThreatIntelResult(self.name, qtype, url, ThreatIntelStatus.UNAVAILABLE, f"Provider returned HTTP {resp.status_code}.")
        kind = "timed out" if isinstance(exc, httpx.TimeoutException) else "could not be reached"
        return ThreatIntelResult(self.name, qtype, url, ThreatIntelStatus.UNAVAILABLE, f"Provider {kind}.")

    def _parse_report(self, url: str, qtype: str, data: dict) -> ThreatIntelResult:
        try:
            attrs = data["data"]["attributes"]
            stats = {k: int(v) for k, v in attrs["last_analysis_stats"].items()}
        except (KeyError, TypeError, ValueError, AttributeError):
            return ThreatIntelResult(self.name, qtype, url, ThreatIntelStatus.UNAVAILABLE, "Provider response was malformed.")
        status = classify_stats(stats, self.threshold)
        msg = (f"{stats.get('malicious', 0)} malicious, {stats.get('suspicious', 0)} suspicious, "
               f"{stats.get('harmless', 0)} harmless, {stats.get('undetected', 0)} undetected engine verdicts.")
        return ThreatIntelResult(self.name, qtype, url, status, msg, stats=stats,
                                 reference_link=f"https://www.virustotal.com/gui/url/{self.url_id(url)}")

    def lookup(self, url: str) -> ThreatIntelResult:
        ok, why = self.configured()
        if not ok:
            return ThreatIntelResult(self.name, "none", url, ThreatIntelStatus.UNAVAILABLE, why)
        if self.cache:
            hit = self.cache.get("lookup:" + url)
            if hit:
                r = ThreatIntelResult(**{**hit, "status": ThreatIntelStatus(hit["status"]), "cached": True})
                return r
        try:
            resp = self._req("GET", f"/urls/{self.url_id(url)}")
        except httpx.HTTPError as exc:
            return self._fail(url, "lookup", exc=exc)
        if resp.status_code == 404:
            return ThreatIntelResult(self.name, "lookup", url, ThreatIntelStatus.NO_RESULT,
                                     "No existing report. A fresh scan can be requested explicitly (this sends the URL to the provider).")
        if resp.status_code != 200:
            return self._fail(url, "lookup", resp=resp)
        try:
            res = self._parse_report(url, "lookup", resp.json())
        except ValueError:
            return ThreatIntelResult(self.name, "lookup", url, ThreatIntelStatus.UNAVAILABLE, "Provider response was not valid JSON.")
        if self.cache and res.status not in (ThreatIntelStatus.UNAVAILABLE,):
            from dataclasses import asdict
            d = asdict(res)
            d["status"] = res.status.value
            self.cache.put("lookup:" + url, d)
        return res

    def submit_scan(self, url: str) -> ThreatIntelResult:
        ok, why = self.configured()
        if not ok:
            return ThreatIntelResult(self.name, "none", url, ThreatIntelStatus.UNAVAILABLE, why)
        try:
            resp = self._req("POST", "/urls", data={"url": url})
            if resp.status_code != 200:
                return self._fail(url, "scan", resp=resp)
            aid = resp.json()["data"]["id"]
            ana = self._req("GET", f"/analyses/{aid}")
            if ana.status_code != 200:
                return self._fail(url, "scan", resp=ana)
            body = ana.json()
            attrs = body["data"]["attributes"]
            if attrs.get("status") != "completed":
                return ThreatIntelResult(self.name, "scan", url, ThreatIntelStatus.NO_RESULT,
                                         "Scan submitted; the analysis is not complete yet. Look the URL up again shortly.")
            stats = {k: int(v) for k, v in attrs["stats"].items()}
            return ThreatIntelResult(self.name, "scan", url, classify_stats(stats, self.threshold),
                                     f"{stats.get('malicious', 0)} malicious, {stats.get('suspicious', 0)} suspicious engine verdicts.",
                                     stats=stats, reference_link=f"https://www.virustotal.com/gui/url/{self.url_id(url)}")
        except httpx.HTTPError as exc:
            return self._fail(url, "scan", exc=exc)
        except (KeyError, TypeError, ValueError):
            return ThreatIntelResult(self.name, "scan", url, ThreatIntelStatus.UNAVAILABLE, "Provider response was malformed.")
