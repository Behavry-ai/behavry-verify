"""The published trust-anchor registry.

Behavry signing keys are **per tenant**: every deployment signs with its own
key, exported by a tenant admin from ``GET /api/v1/admin/apr-trust-anchor``.
There is therefore no single global anchor, and this registry is not one. It
is an operator-maintained collection of anchors that tenants have chosen to
publish, so that a third party holding only a package can still get a result.

Using a published anchor is strictly weaker than being handed the anchor by
the tenant, because the key then comes from Behavry rather than from an
independent source. Every report says which path it took (see
``report.TrustSource``).

Anchors live as ``anchors/<name>.json`` files committed to this repo, so the
set of published keys is auditable through git history rather than mutable at
runtime.
"""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from behavry_verify.anchor import AnchorError, validate_anchor

__all__ = [
    "ANCHOR_DIR",
    "aggregate_anchor",
    "anchor_for_kid",
    "load_registry",
]

ANCHOR_DIR = Path(__file__).resolve().parent.parent / "anchors"

REGISTRY_SCHEMA = "behavry.trust_anchor.v1"


@lru_cache(maxsize=1)
def load_registry(anchor_dir: str | None = None) -> dict[str, dict[str, Any]]:
    """Map ``kid -> key entry`` across every published anchor file.

    Malformed anchor files are skipped rather than fatal: one bad file must
    not take the whole service down. A duplicate ``kid`` across files is a
    genuine operator error, so the first one committed wins and later ones
    are ignored.
    """
    directory = Path(anchor_dir) if anchor_dir else ANCHOR_DIR
    registry: dict[str, dict[str, Any]] = {}
    if not directory.is_dir():
        return registry
    for path in sorted(directory.glob("*.json")):
        try:
            anchor = json.loads(path.read_text(encoding="utf-8"))
            keys = validate_anchor(anchor)
        except (json.JSONDecodeError, AnchorError, OSError):
            continue
        for entry in keys:
            kid = entry.get("kid")
            if not kid or kid in registry:
                continue
            registry[kid] = {**entry, "_source": path.name}
    return registry


def anchor_for_kid(kid: str | None, anchor_dir: str | None = None) -> dict[str, Any] | None:
    """Return a single-key anchor for ``kid``, or ``None`` if unpublished."""
    if not kid:
        return None
    entry = load_registry(anchor_dir).get(kid)
    if entry is None:
        return None
    published = {k: v for k, v in entry.items() if not k.startswith("_")}
    return {"schema": REGISTRY_SCHEMA, "keys": [published]}


def aggregate_anchor(anchor_dir: str | None = None) -> dict[str, Any]:
    """The full published keyset, served at ``/trust-anchor.json``.

    Evidence packages hardcode that URL in their
    ``verification_metadata.trust_anchor_url``, so it must always resolve to
    a well-formed anchor document, even when no keys are published yet.
    """
    registry = load_registry(anchor_dir)
    keys = [
        {k: v for k, v in entry.items() if not k.startswith("_")}
        for entry in registry.values()
    ]
    return {
        "schema": REGISTRY_SCHEMA,
        "description": (
            "Trust anchors published by Behavry tenants for third-party "
            "verification. Anchors obtained directly from the issuing tenant "
            "are stronger evidence than this list."
        ),
        "keys": keys,
    }
