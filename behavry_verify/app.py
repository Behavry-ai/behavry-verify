"""verify.behavry.ai, the public verification service.

Stateless by design. Nothing about a submitted package is persisted, logged,
or forwarded: the request holds an audit trail from someone else's regulated
environment, so the only defensible retention policy is none. That property is
part of the product, not an implementation detail.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Annotated, Any

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from behavry_verify import __version__
from behavry_verify.anchor import AnchorError, validate_anchor
from behavry_verify.fetch import FetchError, fetch_package
from behavry_verify.package import (
    PackageError,
    load_package_from_bytes,
    verify_package,
)
from behavry_verify.registry import aggregate_anchor, anchor_for_kid
from behavry_verify.report import TrustSource, VerificationReport

MAX_UPLOAD_BYTES = int(os.environ.get("VERIFY_MAX_UPLOAD_BYTES", 32 * 1024 * 1024))

# Named "web", not "public": Vercel auto-serves a directory called `public`
# at the domain root, which would shadow this app's own routes. Routing every
# request through the app keeps local uvicorn and production byte-identical.
PUBLIC_DIR = Path(__file__).resolve().parent.parent / "web"

app = FastAPI(
    title="Behavry Verification Service",
    version=__version__,
    description=(
        "Independently verify a Behavry APR evidence package. No Behavry "
        "account, no tenant access, and no database required. Nothing "
        "submitted here is stored."
    ),
    docs_url="/api/docs",
    openapi_url="/api/openapi.json",
)


@app.middleware("http")
async def security_headers(request: Request, call_next):  # type: ignore[no-untyped-def]
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; "
        "base-uri 'none'",
    )
    return response


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


def _parse_anchor(raw: str | None) -> dict[str, Any] | None:
    if not raw or not raw.strip():
        return None
    try:
        anchor = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise HTTPException(400, f"trust anchor is not valid JSON: {exc}") from exc
    try:
        validate_anchor(anchor)
    except AnchorError as exc:
        raise HTTPException(400, str(exc)) from exc
    return anchor


async def _read_upload(upload: UploadFile) -> bytes:
    data = await upload.read()
    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(
            413,
            f"package is {len(data)} bytes, above this service's "
            f"{MAX_UPLOAD_BYTES} byte limit. Verify large packages offline with "
            "the bundled CLI: pipx run behavry-verify --package <file.zip> "
            "--trust-anchor <anchor.json>",
        )
    return data


def _resolve_trust(
    components: dict[str, Any], anchor: dict[str, Any] | None
) -> tuple[dict[str, Any] | None, TrustSource]:
    """Choose the anchor to verify against, preferring the caller's own."""
    if anchor is not None:
        return anchor, TrustSource.SUPPLIED_ANCHOR
    manifest = components.get("manifest.json") or {}
    kid = manifest.get("signer_kid") if isinstance(manifest, dict) else None
    published = anchor_for_kid(kid)
    if published is not None:
        return published, TrustSource.PUBLISHED_REGISTRY
    return None, TrustSource.NONE


def _verify(data: bytes, anchor: dict[str, Any] | None) -> VerificationReport:
    try:
        components = load_package_from_bytes(data)
    except PackageError as exc:
        raise HTTPException(400, str(exc)) from exc
    resolved, source = _resolve_trust(components, anchor)
    report = verify_package(components, anchor=resolved, trust_source=source)
    if source is TrustSource.NONE and report.error is None:
        report.error = (
            "No trust anchor was supplied and this package's signing key is "
            "not in the published registry, so signatures could not be "
            "checked. Ask the issuing tenant for their trust anchor "
            "(Behavry dashboard: Admin -> Trust anchor) and submit it with "
            "the package."
        )
    return report


@app.post("/api/v1/verify")
async def verify_endpoint(
    package: Annotated[UploadFile | None, File()] = None,
    package_url: Annotated[str | None, Form()] = None,
    trust_anchor: Annotated[str | None, Form()] = None,
) -> JSONResponse:
    """Verify an evidence package supplied as an upload or by URL.

    ``trust_anchor`` is the JSON text of an anchor obtained from the issuing
    tenant. Supplying it is what makes the result independent of Behavry.
    """
    if package is None and not package_url:
        raise HTTPException(400, "supply either a package file or a package_url")
    if package is not None and package_url:
        raise HTTPException(400, "supply a package file or a package_url, not both")

    anchor = _parse_anchor(trust_anchor)

    if package is not None:
        data = await _read_upload(package)
    else:
        try:
            data = fetch_package(str(package_url))
        except FetchError as exc:
            raise HTTPException(400, str(exc)) from exc

    report = _verify(data, anchor)
    # A failed verification is a successful request: the caller asked a
    # question and got a definitive answer. Only malformed input is a 4xx.
    return JSONResponse(report.to_dict())


@app.post("/api/v1/verify.txt", response_class=PlainTextResponse)
async def verify_text_endpoint(
    package: Annotated[UploadFile | None, File()] = None,
    trust_anchor: Annotated[str | None, Form()] = None,
) -> PlainTextResponse:
    """Same verification, rendered as the plain-text report (for CI use)."""
    if package is None:
        raise HTTPException(400, "supply a package file")
    report = _verify(await _read_upload(package), _parse_anchor(trust_anchor))
    return PlainTextResponse(
        report.to_text(), status_code=200 if report.verified else 422
    )


# ---------------------------------------------------------------------------
# Trust anchors
# ---------------------------------------------------------------------------


@app.get("/trust-anchor.json")
async def trust_anchor_document() -> JSONResponse:
    """The published keyset.

    Every evidence package hardcodes this URL in its
    ``verification_metadata.trust_anchor_url``, so it must always resolve.
    """
    return JSONResponse(
        aggregate_anchor(),
        headers={"Cache-Control": "public, max-age=300"},
    )


@app.get("/api/v1/health")
async def health() -> dict[str, Any]:
    return {"status": "ok", "version": __version__}


# ---------------------------------------------------------------------------
# Web UI
# ---------------------------------------------------------------------------


@app.get("/", response_class=HTMLResponse)
async def index() -> HTMLResponse:
    return HTMLResponse((PUBLIC_DIR / "index.html").read_text(encoding="utf-8"))


if PUBLIC_DIR.is_dir():
    app.mount("/static", StaticFiles(directory=PUBLIC_DIR), name="static")
