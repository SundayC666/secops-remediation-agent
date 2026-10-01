"""
Fail-closed tests for the CVE lookup.

The bug these tests pin down (fail-open): when NVD returned an error, the
collector swallowed it and returned an empty list, the API answered 200 with
zero findings, and the UI told the user "Your system appears to be up to
date". An upstream failure must never be presented as "safe".

No test here touches the network. For the duration of each test,
httpx.AsyncClient.get is replaced with a fake (pytest's `monkeypatch`
fixture restores the real one afterwards).
"""

import json
from typing import Optional

import httpx
import pytest
from fastapi.testclient import TestClient

from main import app

# A real browser UA so OS detection picks "macOS" and the /latest route
# actually queries NVD (it skips the lookup for unknown systems).
BROWSER_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 15_0) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/152.0 Safari/537.36"
)


class FakeResponse:
    """The minimum the collector reads from an httpx response."""

    def __init__(self, status_code: int, payload: Optional[dict] = None):
        self.status_code = status_code
        self._payload = payload or {}
        self.text = json.dumps(self._payload)

    def json(self) -> dict:
        return self._payload


def fake_get(nvd_status: int, nvd_payload: Optional[dict] = None):
    """Build a replacement for httpx.AsyncClient.get.

    NVD calls get `nvd_status` / `nvd_payload`. Every other call (CISA KEV,
    Ollama) gets a harmless 200 with an empty-but-valid body, so those code
    paths neither fail nor hit the network.
    """

    async def _get(self, url, *args, **kwargs):
        if "nvd.nist.gov" in str(url):
            return FakeResponse(nvd_status, nvd_payload)
        return FakeResponse(200, {"vulnerabilities": [], "models": []})

    return _get


@pytest.fixture
def client() -> TestClient:
    return TestClient(app, headers={"User-Agent": BROWSER_UA})


def test_analyze_reports_nvd_outage_not_safe(client, monkeypatch):
    # Arrange: NVD is down — every call to it answers 503.
    monkeypatch.setattr(httpx.AsyncClient, "get", fake_get(503))

    # Act
    response = client.post("/api/cve/analyze", json={"query": "windows 11", "limit": 5})

    # Assert (fail-closed): the API must say "lookup failed", never "0 findings".
    assert response.status_code == 503, (
        f"expected 503 when NVD is down, got {response.status_code}: {response.text[:200]}"
    )


def test_latest_reports_nvd_outage_not_safe(client, monkeypatch):
    # The page-load request is the one that showed "up to date" in the UI.
    monkeypatch.setattr(httpx.AsyncClient, "get", fake_get(503))

    response = client.get("/api/cve/latest?limit=5")

    assert response.status_code == 503, (
        f"expected 503 when NVD is down, got {response.status_code}: {response.text[:200]}"
    )


def test_genuinely_empty_result_is_still_200(client, monkeypatch):
    # Guard against over-correcting: NVD works and simply has no CVEs for the
    # query. That is a normal answer, not an error.
    monkeypatch.setattr(
        httpx.AsyncClient, "get", fake_get(200, {"totalResults": 0, "vulnerabilities": []})
    )

    response = client.post("/api/cve/analyze", json={"query": "windows 11", "limit": 5})

    assert response.status_code == 200
    assert response.json()["total_results"] == 0
