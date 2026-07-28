"""HTTP surface: verdict semantics, input handling, and the SSRF fence."""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from behavry_verify.app import app
from behavry_verify.fetch import FetchError, fetch_package


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


def post_package(client, builder, *, anchor=None, zip_bytes=None):
    files = {"package": ("apr.zip", zip_bytes or builder.zip_bytes(), "application/zip")}
    data = {"trust_anchor": json.dumps(anchor)} if anchor is not None else {}
    return client.post("/api/v1/verify", files=files, data=data)


# ---------------------------------------------------------------------------
# Verdicts
# ---------------------------------------------------------------------------


def test_valid_package_verifies(client, builder):
    response = post_package(client, builder, anchor=builder.anchor())
    assert response.status_code == 200
    body = response.json()
    assert body["verified"] is True
    assert body["apr_identifier"] == "APR-2026-001942"
    assert body["trust_source"] == "supplied_anchor"


def test_failed_verification_is_a_200_not_an_error(client, builder):
    """The caller asked a question and got an answer. That is a success."""
    components = builder.components()
    components["manifest.json"]["event_count"] = 999
    response = post_package(client, builder, anchor=builder.anchor(),
                            zip_bytes=builder.zip_bytes(components))
    assert response.status_code == 200
    assert response.json()["verified"] is False


def test_malformed_input_is_a_400(client, builder):
    response = client.post(
        "/api/v1/verify",
        files={"package": ("x.zip", b"not a zip", "application/zip")},
    )
    assert response.status_code == 400


def test_missing_input_is_a_400(client):
    assert client.post("/api/v1/verify").status_code == 400


def test_both_inputs_at_once_is_a_400(client, builder):
    response = client.post(
        "/api/v1/verify",
        files={"package": ("apr.zip", builder.zip_bytes(), "application/zip")},
        data={"package_url": "https://example.com/apr.zip"},
    )
    assert response.status_code == 400


def test_bad_trust_anchor_json_is_a_400(client, builder):
    response = client.post(
        "/api/v1/verify",
        files={"package": ("apr.zip", builder.zip_bytes(), "application/zip")},
        data={"trust_anchor": "{not json"},
    )
    assert response.status_code == 400


def test_anchor_without_keys_is_a_400(client, builder):
    response = client.post(
        "/api/v1/verify",
        files={"package": ("apr.zip", builder.zip_bytes(), "application/zip")},
        data={"trust_anchor": json.dumps({"schema": "x", "keys": []})},
    )
    assert response.status_code == 400
    assert "no keys" in response.json()["detail"]


def test_no_anchor_and_unpublished_key_explains_what_to_do(client, builder):
    response = post_package(client, builder)
    body = response.json()
    assert body["verified"] is False
    assert body["trust_source"] == "none"
    assert "trust anchor" in (body["error"] or "").lower()


def test_report_always_states_its_trust_caveat(client, builder):
    body = post_package(client, builder, anchor=builder.anchor()).json()
    assert body["caveat"]
    assert "not consulted" in body["caveat"].lower()


# ---------------------------------------------------------------------------
# Text endpoint
# ---------------------------------------------------------------------------


def test_text_endpoint_uses_status_as_the_verdict(client, builder):
    good = client.post(
        "/api/v1/verify.txt",
        files={"package": ("apr.zip", builder.zip_bytes(), "application/zip")},
        data={"trust_anchor": json.dumps(builder.anchor())},
    )
    assert good.status_code == 200
    assert "VERIFIED" in good.text

    components = builder.components()
    components["hash_chain.json"][0]["verified"] = False
    bad = client.post(
        "/api/v1/verify.txt",
        files={"package": ("apr.zip", builder.zip_bytes(components), "application/zip")},
        data={"trust_anchor": json.dumps(builder.anchor())},
    )
    assert bad.status_code == 422
    assert "NOT VERIFIED" in bad.text


# ---------------------------------------------------------------------------
# Static surfaces
# ---------------------------------------------------------------------------


def test_trust_anchor_document_always_resolves(client):
    """Packages hardcode this URL, so it must never 404."""
    response = client.get("/trust-anchor.json")
    assert response.status_code == 200
    body = response.json()
    assert body["schema"] == "behavry.trust_anchor.v1"
    assert isinstance(body["keys"], list)


def test_health(client):
    assert client.get("/api/v1/health").json()["status"] == "ok"


def test_index_renders(client):
    response = client.get("/")
    assert response.status_code == 200
    assert "verify" in response.text.lower()


def test_security_headers_are_set(client):
    headers = client.get("/api/v1/health").headers
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-Frame-Options"] == "DENY"
    assert "frame-ancestors 'none'" in headers["Content-Security-Policy"]


# ---------------------------------------------------------------------------
# SSRF fence
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com/apr.zip",           # not https
        "https://127.0.0.1/apr.zip",            # loopback
        "https://localhost/apr.zip",            # loopback by name
        "https://10.0.0.5/apr.zip",             # private
        "https://192.168.1.1/apr.zip",          # private
        "https://169.254.169.254/latest/meta",  # cloud metadata
        "https://[::1]/apr.zip",                # loopback v6
    ],
)
def test_url_fetch_refuses_non_public_targets(url):
    with pytest.raises(FetchError):
        fetch_package(url)


def test_url_endpoint_surfaces_the_refusal(client):
    response = client.post(
        "/api/v1/verify", data={"package_url": "https://169.254.169.254/apr.zip"}
    )
    assert response.status_code == 400


def test_swagger_ui_is_disabled(client):
    """The docs UI pulls script from a third-party CDN, which this site's CSP
    blocks and whose trust posture it contradicts. The schema stays self-hosted."""
    assert client.get("/api/docs").status_code == 404
    assert client.get("/api/openapi.json").status_code == 200


@pytest.mark.parametrize(
    "asset",
    [
        "/static/styles.css",
        "/static/app.js",
        "/static/brand/behavry-horizontal-light.svg",
        "/static/brand/behavry-horizontal-dark.svg",
        "/static/brand/favicon.svg",
        "/static/fonts/inter-latin-400-normal.woff2",
        "/static/fonts/inter-latin-600-normal.woff2",
        "/static/fonts/inter-latin-700-normal.woff2",
        "/static/fonts/jetbrains-mono-latin-400-normal.woff2",
    ],
)
def test_brand_assets_are_served(client, asset):
    """Brand and font files are vendored, not fetched from a CDN, so a missing
    one degrades silently to a system font or a broken image unless caught."""
    assert client.get(asset).status_code == 200


def test_page_loads_no_third_party_assets(client):
    """The CSP is default-src 'self'; anything remote would simply not load."""
    html = client.get("/").text
    assert "http://" not in html
    for remote in ("https://fonts.googleapis.com", "https://cdn.", "https://fonts.gstatic.com"):
        assert remote not in html
