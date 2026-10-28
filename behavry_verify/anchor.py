"""Trust anchors: loading, key selection, and fingerprint cross-checks.

A *trust anchor* is the sealed, exported keyset a Behavry tenant publishes so
third parties can verify its evidence without talking to Behavry. Wire format
(``behavry.trust_anchor.v1``)::

    {
      "schema": "behavry.trust_anchor.v1",
      "keys": [
        {
          "kid": "<key id>",
          "algorithm": "ed25519" | "ecdsa-p256",   (absent: ed25519)
          "public_key": "<base64: 32 raw bytes (Ed25519) or SPKI DER (P-256)>",
          "not_before": "<ISO 8601>",
          "not_after": null
        }
      ]
    }

Anchors are **per tenant**, not global: each Behavry deployment signs with its
own key. A tenant admin exports theirs from
``GET /api/v1/admin/apr-trust-anchor``.

From AG-11 a tenant's key can rotate. A ``behavry.trust_anchor.v2`` anchor, or
a v1 anchor extended with a key history, carries every key the tenant has used
and the signed statements between them; :mod:`behavry_verify.keyhistory`
resolves those, and the selection functions here then enforce each key's
validity window. A v1 anchor on its own is selected exactly as before.
"""
from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any

from behavry_verify.keys import KeyFormatError, PublicKey, decode_public_key

__all__ = [
    "AnchorError",
    "public_key_fingerprint",
    "select_key_for_timestamp",
    "select_public_key",
    "summarize_anchor",
    "validate_anchor",
    "validate_observer_anchors",
]

ED25519_PUBLIC_KEY_BYTES = 32


class AnchorError(ValueError):
    """Raised when a trust anchor is malformed or holds no usable key."""


def _decode_key(entry: dict[str, Any]) -> PublicKey:
    """The entry's public key, tagged with its ``algorithm`` (absent: Ed25519).

    ``ed25519`` keys are base64 of the 32 raw bytes, ``ecdsa-p256`` keys base64
    of the SPKI DER (AG12-CONTRACTS section 1). Any other algorithm is refused.
    """
    try:
        return decode_public_key(entry.get("algorithm"), entry.get("public_key"))
    except KeyFormatError as exc:
        raise AnchorError(f"trust anchor key {entry.get('kid')!r} {exc}") from exc


def _parse_iso(value: Any) -> datetime | None:
    """Parse an ISO 8601 validity bound, normalized to UTC."""
    if not value:
        return None
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed


def validate_anchor(anchor: Any) -> list[dict[str, Any]]:
    """Return the anchor's key entries, raising ``AnchorError`` if unusable.

    A v2 anchor is resolved first (its statements verified, its windows
    rebuilt), and only the keys its statements reach are returned.
    """
    if not isinstance(anchor, dict):
        raise AnchorError("trust anchor must be a JSON object")
    from behavry_verify.keyhistory import history_of

    history = history_of(anchor)
    if history is not None:
        return history.entries()
    keys = anchor.get("keys")
    if not isinstance(keys, list) or not keys:
        raise AnchorError("trust anchor has no keys")
    for entry in keys:
        if not isinstance(entry, dict):
            raise AnchorError("trust anchor keys must be objects")
        _decode_key(entry)
    return keys


def public_key_fingerprint(public_key_b64: str) -> str:
    """Reproduce the ``public_key_hint`` a package carries for its signer.

    Mirrors ``APRPackageGenerator._public_key_hint``: sha256 over the *base64
    text* of the key (not the raw bytes), truncated to 16 hex characters.
    """
    digest = hashlib.sha256(public_key_b64.encode("utf-8")).hexdigest()
    return "sha256:" + digest[:16]


def _history_key(history: Any, kid: str) -> Any:
    key = history.keys.get(kid)
    if key is not None:
        return key
    why = history.unreachable_reason(kid)
    if why is not None:
        raise AnchorError(
            f"no key with kid={kid!r} in trust anchor (the key history lists it, but {why})"
        )
    raise AnchorError(f"no key with kid={kid!r} in trust anchor")


def _select_from_history(
    history: Any, kid: str | None, ts: Any, *, enforce: bool
) -> tuple[PublicKey, dict[str, Any]]:
    """Key selection against a resolved key history (AG11-CONTRACTS section 4)."""
    if kid is not None:
        key = _history_key(history, kid)
    else:
        keys = list(history.keys.values())
        if len(keys) == 1:
            key = keys[0]
        elif not enforce:
            raise AnchorError(
                "package has no signer_kid and the trust anchor holds multiple keys"
            )
        else:
            try:
                dt = _parse_iso(ts) if ts else None
            except ValueError as exc:
                raise AnchorError(f"cannot parse timestamp {ts!r} for key selection") from exc
            if dt is None:
                raise AnchorError(
                    "no timestamp available to select a key, and the anchor holds "
                    "multiple keys"
                )
            inside = [
                k
                for k in keys
                if (k.not_before is None or k.not_before <= dt)
                and (k.not_after is None or k.not_after > dt)
            ]
            if not inside:
                raise AnchorError(f"no key in the trust anchor was valid at {ts}")
            key = inside[0]
    if enforce:
        history.check(key, ts)
    return key.public_key, key.entry()


def select_public_key(
    anchor: dict[str, Any], kid: str | None
) -> tuple[PublicKey, dict[str, Any]]:
    """Select a key by ``kid``, or the sole key when the anchor holds one.

    No timestamp is involved, so no window is enforced here: signature checks
    go through :func:`select_key_for_timestamp`.
    """
    from behavry_verify.keyhistory import history_of

    history = history_of(anchor)
    if history is not None:
        return _select_from_history(history, kid, None, enforce=False)
    keys = validate_anchor(anchor)
    if kid is not None:
        matches = [k for k in keys if k.get("kid") == kid]
        if matches:
            return _decode_key(matches[0]), matches[0]
        raise AnchorError(f"no key with kid={kid!r} in trust anchor")
    if len(keys) == 1:
        return _decode_key(keys[0]), keys[0]
    raise AnchorError(
        "package has no signer_kid and the trust anchor holds multiple keys"
    )


def select_key_for_timestamp(
    anchor: dict[str, Any], kid: str | None, ts: str | None
) -> tuple[PublicKey, dict[str, Any]]:
    """Pick the key valid at ``ts``, honouring the anchor's validity windows.

    A matching ``kid`` always wins. Otherwise, with several keys present, the
    key whose ``[not_before, not_after)`` window contains ``ts`` is used, so a
    package signed before a key rotation still verifies against the rotated
    anchor.

    With a key history (a v2 anchor, or v1 plus ``--key-history``) the
    selected key's window is enforced against ``ts``, the record's signed
    timestamp: outside it raises ``KeyWindowError``, at or after the key's
    ``compromised_since`` raises ``KeyCompromisedError`` (both ``AnchorError``).
    """
    from behavry_verify.keyhistory import history_of

    history = history_of(anchor)
    if history is not None:
        return _select_from_history(history, kid, ts, enforce=True)
    if kid is not None:
        return select_public_key(anchor, kid)
    keys = validate_anchor(anchor)
    if len(keys) == 1:
        return _decode_key(keys[0]), keys[0]
    if not ts:
        raise AnchorError(
            "no timestamp available to select a key, and the anchor holds multiple keys"
        )
    try:
        dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except ValueError as exc:
        raise AnchorError(f"cannot parse timestamp {ts!r} for key selection") from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    for entry in keys:
        not_before = entry.get("not_before")
        not_after = entry.get("not_after")
        try:
            nb = _parse_iso(not_before)
            na = _parse_iso(not_after)
        except ValueError:
            continue
        if nb is not None and nb > dt:
            continue
        if na is not None and na <= dt:
            continue
        return _decode_key(entry), entry
    raise AnchorError(f"no key in the trust anchor was valid at {ts}")


def summarize_anchor(anchor: dict[str, Any]) -> dict[str, Any]:
    """Non-secret description of an anchor, safe to show in a report."""
    keys = anchor.get("keys") or []
    return {
        "schema": anchor.get("schema"),
        "key_count": len(keys),
        "kids": [k.get("kid") for k in keys if isinstance(k, dict)],
        "algorithms": {
            str(k.get("kid")): k.get("algorithm") or "ed25519"
            for k in keys
            if isinstance(k, dict)
        },
    }


def validate_observer_anchors(value: Any) -> list[dict[str, Any]]:
    """Validate observer anchors: one object or a list of them.

    Wire format, one per independent observer key (Sprint AG-1 E-3)::

        {"kid": "...", "public_key_hex": "<64 hex chars, raw Ed25519>",
         "observer_id": "...", "observer_type": "..."}

    These come from the observer (or whoever operates it), never from the
    package and never from Behavry: an observation is only as independent as
    the key it is checked against.
    """
    entries = value if isinstance(value, list) else [value]
    if not entries:
        raise AnchorError("observer anchor list is empty")
    for entry in entries:
        if not isinstance(entry, dict):
            raise AnchorError("observer anchor must be a JSON object")
        for field in ("kid", "public_key_hex", "observer_id", "observer_type"):
            if not isinstance(entry.get(field), str) or not entry.get(field):
                raise AnchorError(f"observer anchor is missing {field!r}")
        try:
            raw = bytes.fromhex(entry["public_key_hex"])
        except ValueError as exc:
            raise AnchorError(
                f"observer anchor {entry['kid']!r} public_key_hex is not hex"
            ) from exc
        if len(raw) != ED25519_PUBLIC_KEY_BYTES:
            raise AnchorError(
                f"observer anchor {entry['kid']!r} is {len(raw)} bytes, "
                f"expected {ED25519_PUBLIC_KEY_BYTES} for Ed25519"
            )
    return entries
