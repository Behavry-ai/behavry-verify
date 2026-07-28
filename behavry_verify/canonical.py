"""Canonical byte forms, kept in lockstep with the Behavry producer.

Every function here reproduces, byte-for-byte, a form defined in the Behavry
backend. Any divergence is a verification break, so each carries a pointer to
its counterpart. These are the only places in this repo where a change can
silently turn a valid package into an invalid one.

Counterparts (repo ``Behavry-ai/behavry``):

  ``canonical_signing_bytes``            -> ``backend/behavry/audit/signer.py``
  ``canonical_signing_bytes_exposure``   -> ``backend/behavry/audit/signer.py``
  ``canonical_signing_bytes_disclosure_ack`` -> ``backend/behavry/audit/signer.py``
  ``canonical_package_manifest_bytes``   -> ``backend/behavry/apr/packages.py``
"""
from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

__all__ = [
    "canonical_package_manifest_bytes",
    "canonical_signing_bytes",
    "canonical_signing_bytes_disclosure_ack",
    "canonical_signing_bytes_exposure",
    "normalize_timestamp",
]


def normalize_timestamp(timestamp: Any) -> str:
    """Render a timestamp the way the signer did when it signed.

    UTC, microsecond precision. Unparseable strings are passed through
    unchanged so a malformed timestamp fails signature verification rather
    than being silently coerced into a different value.
    """
    if timestamp is None:
        return ""
    if isinstance(timestamp, str):
        try:
            dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        except ValueError:
            return timestamp
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt.astimezone(UTC).isoformat(timespec="microseconds")
    if isinstance(timestamp, datetime):
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=UTC)
        return timestamp.astimezone(UTC).isoformat(timespec="microseconds")
    return str(timestamp)


def _dumps(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def canonical_signing_bytes(
    *,
    event_hash: str | None,
    previous_hash: str | None,
    timestamp: Any,
    tenant_id: str | None,
) -> bytes:
    """Per-event canonical payload for a decision event."""
    payload = {
        "event_hash": event_hash or "",
        "previous_hash": previous_hash or "GENESIS",
        "timestamp": normalize_timestamp(timestamp),
        "tenant_id": tenant_id or "",
    }
    return _dumps(payload)


def canonical_signing_bytes_exposure(
    *,
    event_hash: str | None,
    previous_hash: str | None,
    timestamp: Any,
    tenant_id: str | None,
    device_id: str | None,
) -> bytes:
    """Per-event canonical payload for an ``exposure`` device claim.

    Binds ``claim_type`` and ``device_id`` so an exposure record verifies only
    under this form and only on its own device's chain.
    """
    payload = {
        "claim_type": "exposure",
        "device_id": device_id or "",
        "event_hash": event_hash or "",
        "previous_hash": previous_hash or "GENESIS",
        "tenant_id": tenant_id or "",
        "timestamp": normalize_timestamp(timestamp),
    }
    return _dumps(payload)


def canonical_signing_bytes_disclosure_ack(
    *,
    event_hash: str | None,
    previous_hash: str | None,
    timestamp: Any,
    tenant_id: str | None,
    device_id: str | None,
) -> bytes:
    """Per-event canonical payload for a ``disclosure_ack`` device claim."""
    payload = {
        "claim_type": "disclosure_ack",
        "device_id": device_id or "",
        "event_hash": event_hash or "",
        "previous_hash": previous_hash or "GENESIS",
        "tenant_id": tenant_id or "",
        "timestamp": normalize_timestamp(timestamp),
    }
    return _dumps(payload)


def canonical_package_manifest_bytes(manifest: dict[str, Any]) -> bytes:
    """APR evidence-package manifest canonical payload.

    The signature covers every manifest key *except* ``signature`` itself.
    ``default=str`` matches the producer so non-JSON-native values render
    identically on both sides.
    """
    body = {k: v for k, v in manifest.items() if k != "signature"}
    return json.dumps(
        body, sort_keys=True, separators=(",", ":"), default=str
    ).encode("utf-8")
