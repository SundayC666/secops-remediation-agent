"""
Small hardening checks found during the web-app security checklist review.

Each test was written before the fix (red), then the fix makes it pass (green).
"""

import pytest
from fastapi.testclient import TestClient

from main import app


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


@pytest.mark.parametrize("path", ["/api/health", "/api/os/detect"])
def test_public_endpoints_are_rate_limited(client, path):
    # These two routes had no @limiter.limit at all, while README claims
    # "rate limiting on all endpoints". 60/minute matches the other GET routes.
    for _ in range(60):
        assert client.get(path).status_code == 200
    assert client.get(path).status_code == 429, f"{path} is not rate limited"


def test_version_status_does_not_leak_server_path(client):
    # get_status() returned the absolute path of the cache file on the server,
    # and /versions/buttons sends that to every browser on page load.
    body = client.get("/api/versions/buttons").json()
    cache_status = body.get("cache_status", {})
    assert "cache_file" not in cache_status, f"server path leaked: {cache_status.get('cache_file')}"
