"""Key history: trust anchor v2, key statements and validity windows (AG-11).

From AG-11 a Behavry tenant signs with its own Ed25519 key, and every change
of that key is a signed **key statement** (``behavry.key_statement.v1``)::

    {"schema": "behavry.key_statement.v1", "type": "succession" | "compromise",
     "tenant_id": ..., "predecessor_kid": ..., "successor_kid": ...,
     "successor_algorithm": "ed25519", "successor_public_key": "<base64 raw>",
     "effective_at": ..., "reason": ..., "compromised_since": null | ...,
     "issued_at": ..., "signatures": [{"kid": ..., "sig": ...}]}

The signed bytes are the statement without ``signatures``, as compact JSON with
sorted keys. A ``succession`` is signed by both the predecessor and the
successor; a ``compromise`` by the successor and the deployment key, since the
compromised key's own signature proves nothing.

A statement closes the predecessor's window at ``effective_at`` and opens the
successor's there; a ``compromise`` also marks the predecessor compromised
from ``compromised_since``.

Two ways in (AG11-CONTRACTS section 4):

* **A v2 anchor** (``behavry.trust_anchor.v2``) passed as the trust anchor is
  trusted as a whole, as a v1 anchor is, but its listed windows are not: they
  are rebuilt from its statements, and an anchor whose statements do not all
  verify is refused.
* **A pinned v1 anchor plus a key history** (``--key-history``, a v2 document)
  treats the history as untrusted input. A history key is used only if a chain
  of verifying statements reaches it from a pinned key (or, for a compromise
  statement, from the deployment key, which must itself be pinned). Anything
  else is reported as unreachable and never used.

Either way, every signature checked against such a history must fall inside
its key's window, and one dated at or after ``compromised_since`` is reported
as untrusted (key compromised), distinct from a bad signature. A v1 anchor on
its own never reaches this module: no window is enforced, exactly as before.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from behavry_verify.anchor import AnchorError, _decode_key

__all__ = [
    "ANCHOR_V2_SCHEMA",
    "HISTORY_KEY",
    "STATEMENT_SCHEMA",
    "V1_SCHEMAS",
    "HistoryKey",
    "KeyCompromisedError",
    "KeyHistory",
    "KeyWindowError",
    "attach_history",
    "history_of",
    "history_start",
    "is_v2",
    "resolve_v2",
    "resolve_with_history",
    "statement_signing_bytes",
    "trust_anchor_with_history",
]

ANCHOR_V2_SCHEMA = "behavry.trust_anchor.v2"
STATEMENT_SCHEMA = "behavry.key_statement.v1"
V1_SCHEMAS = frozenset({"behavry.trust_anchor.v1", "behavry.apr_trust_anchor.v1"})

#: Where a resolved :class:`KeyHistory` rides on an anchor dict. It is only
#: honoured when the value is a ``KeyHistory`` instance, so JSON input that
#: happens to carry this name cannot inject one.
HISTORY_KEY = "_key_history"

MODE_V2 = "v2"
MODE_V1_HISTORY = "v1+history"

COMPROMISE_REASON = "suspected_compromise"
REASONS = frozenset({"infrastructure_migration", "scheduled_rotation", COMPROMISE_REASON})

#: ``t-<first 8 of the tenant UUID, no dashes>-ed25519-<16 hex of SHA-256(raw key)>``.
_TENANT_KID = re.compile(r"^t-([0-9a-f]{8})-ed25519-([0-9a-f]{16})$")

UNTRUSTED_COMPROMISED = "untrusted (key compromised)"


class KeyWindowError(AnchorError):
    """A signature dated outside its key's validity window."""


class KeyCompromisedError(KeyWindowError):
    """A signature dated at or after its key's ``compromised_since``."""


def is_v2(anchor: Any) -> bool:
    return isinstance(anchor, dict) and anchor.get("schema") == ANCHOR_V2_SCHEMA


def statement_signing_bytes(statement: dict[str, Any]) -> bytes:
    """AG11-CONTRACTS section 2: the statement without ``signatures``."""
    body = {k: v for k, v in statement.items() if k != "signatures"}
    return json.dumps(body, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode(
        "utf-8"
    )


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed


def _iso(value: datetime | None) -> str | None:
    return None if value is None else value.astimezone(UTC).isoformat(timespec="microseconds")


@dataclass
class HistoryKey:
    """One usable key and the window its statements give it."""

    kid: str
    public_key_b64: str
    public_key: bytes
    source: str
    """``pinned`` (the v1 anchor), ``anchor`` (a v2 anchor) or ``history``."""
    not_before: datetime | None = None
    not_after: datetime | None = None
    compromised_since: datetime | None = None
    listed: dict[str, Any] = field(default_factory=dict)

    @property
    def status(self) -> str:
        if self.compromised_since is not None:
            return "revoked"
        if self.not_after is not None:
            return "retired"
        return "active"

    @property
    def bounded(self) -> bool:
        return any(
            v is not None for v in (self.not_before, self.not_after, self.compromised_since)
        )

    def entry(self) -> dict[str, Any]:
        """An anchor-style key entry carrying the recomputed window."""
        return {
            "kid": self.kid,
            "algorithm": "ed25519",
            "public_key": self.public_key_b64,
            "status": self.status,
            "not_before": _iso(self.not_before),
            "not_after": _iso(self.not_after),
            "compromised_since": _iso(self.compromised_since),
        }

    def to_dict(self) -> dict[str, Any]:
        body = self.entry()
        body.pop("public_key")
        body["source"] = self.source
        differs = [
            name
            for name in ("status", "not_before", "not_after", "compromised_since")
            if name in self.listed and _norm(self.listed.get(name)) != _norm(body[name])
        ]
        if differs:
            # Informational: the recomputed window is the one enforced.
            body["listed_differs"] = differs
        return body


def _norm(value: Any) -> Any:
    parsed = _parse_time(value) if isinstance(value, str) else None
    return _iso(parsed) if parsed is not None else value


@dataclass
class KeyHistory:
    """A tenant's keys with windows rebuilt from verified statements."""

    mode: str
    tenant_id: str | None
    deployment_kid: str | None
    keys: dict[str, HistoryKey]
    statements: list[dict[str, Any]]
    unreachable: list[dict[str, Any]]
    notes: list[str] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    """Window failures met while verifying, appended by :meth:`check`."""

    @property
    def statements_verified(self) -> int:
        return sum(1 for s in self.statements if s.get("verified"))

    def entries(self) -> list[dict[str, Any]]:
        return [key.entry() for key in self.keys.values()]

    def unreachable_reason(self, kid: str) -> str | None:
        for row in self.unreachable:
            if row.get("kid") == kid:
                return str(row.get("reason"))
        return None

    def check(self, key: HistoryKey, ts: Any) -> None:
        """Raise unless a record dated ``ts`` lies inside ``key``'s window."""
        if not key.bounded:
            return
        when = _parse_time(ts if isinstance(ts, str) else (str(ts) if ts else None))
        if when is None:
            self._raise(
                KeyWindowError,
                key,
                ts,
                "outside_window",
                f"key {key.kid} has a validity window, but the record carries no readable "
                f"signed timestamp ({ts!r}) to place in it",
            )
        assert when is not None
        if key.compromised_since is not None and when >= key.compromised_since:
            self._raise(
                KeyCompromisedError,
                key,
                ts,
                "compromised",
                f"{UNTRUSTED_COMPROMISED}: key {key.kid} is marked compromised since "
                f"{_iso(key.compromised_since)} and the record is dated {ts}",
            )
        if key.not_before is not None and when < key.not_before:
            self._raise(
                KeyWindowError,
                key,
                ts,
                "outside_window",
                f"key {key.kid} is valid from {_iso(key.not_before)}, but the record it "
                f"signs is dated {ts}, before the key's window",
            )
        if key.not_after is not None and when >= key.not_after:
            self._raise(
                KeyWindowError,
                key,
                ts,
                "outside_window",
                f"key {key.kid} was succeeded at {_iso(key.not_after)}, but the record it "
                f"signs is dated {ts}, after the key's window",
            )

    def _raise(
        self, kind: type[KeyWindowError], key: HistoryKey, ts: Any, outcome: str, detail: str
    ) -> None:
        row = {"kid": key.kid, "timestamp": ts, "outcome": outcome, "detail": detail}
        if row not in self.findings:
            self.findings.append(row)
        raise kind(detail)

    def to_dict(self, findings: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        rows = self.findings if findings is None else findings
        return {
            "trust_mode": self.mode,
            "tenant_id": self.tenant_id,
            "deployment_kid": self.deployment_kid,
            "keys": [key.to_dict() for key in self.keys.values()],
            "statements": list(self.statements),
            "statements_verified": self.statements_verified,
            "statement_count": len(self.statements),
            "unreachable_keys": list(self.unreachable),
            "notes": list(self.notes),
            "untrusted_signatures": [r for r in rows if r["outcome"] == "compromised"],
            "window_failures": [r for r in rows if r["outcome"] == "outside_window"],
        }


# ---------------------------------------------------------------------------
# Building a history
# ---------------------------------------------------------------------------


def _key_from_entry(entry: dict[str, Any], source: str) -> HistoryKey:
    raw = _decode_key(entry)
    return HistoryKey(
        kid=str(entry.get("kid")),
        public_key_b64=str(entry.get("public_key")),
        public_key=raw,
        source=source,
        listed=dict(entry),
    )


def _decode_successor(statement: dict[str, Any]) -> bytes | None:
    raw = statement.get("successor_public_key")
    if not isinstance(raw, str) or not raw:
        return None
    try:
        decoded = base64.b64decode(raw, validate=True)
    except (binascii.Error, ValueError):
        return None
    return decoded if len(decoded) == 32 else None


def _signature_ok(statement: dict[str, Any], kid: str, key: bytes) -> bool:
    signed = statement_signing_bytes(statement)
    for row in statement.get("signatures") or []:
        if not isinstance(row, dict) or row.get("kid") != kid:
            continue
        try:
            sig = base64.b64decode(str(row.get("sig") or ""), validate=True)
            Ed25519PublicKey.from_public_bytes(key).verify(sig, signed)
        except (binascii.Error, ValueError, InvalidSignature):
            continue
        return True
    return False


def _tenant_prefix(tenant_id: Any) -> str | None:
    if not isinstance(tenant_id, str) or not tenant_id:
        return None
    return tenant_id.replace("-", "").lower()[:8]


def _walk(
    trusted: dict[str, HistoryKey],
    offered: dict[str, dict[str, Any]],
    statements: list[Any],
    *,
    tenant_id: Any,
    deployment_kid: Any,
    deployment_trusted: bool,
) -> list[dict[str, Any]]:
    """Apply statements in ``effective_at`` order to ``trusted``, in place.

    A statement takes effect only when it verifies and its predecessor is
    already trusted and still current (no ``not_after`` yet), so the history is
    one unforked chain and a statement cannot re-open a closed window.
    """
    indexed: list[tuple[int, Any, datetime | None]] = []
    for index, statement in enumerate(statements):
        when = _parse_time(statement.get("effective_at")) if isinstance(statement, dict) else None
        indexed.append((index, statement, when))
    # Stable: an unparseable effective_at sorts first and fails on its own.
    indexed.sort(key=lambda row: (row[2] is not None, row[2] or datetime.min.replace(tzinfo=UTC)))

    results: list[dict[str, Any]] = []
    for index, statement, effective in indexed:
        problems: list[str] = []
        row: dict[str, Any] = {"index": index}
        if not isinstance(statement, dict):
            row.update(verified=False, problems=["the statement is not a JSON object"])
            results.append(row)
            continue
        kind = statement.get("type")
        pred_kid = statement.get("predecessor_kid")
        succ_kid = statement.get("successor_kid")
        row.update(
            type=kind,
            predecessor_kid=pred_kid,
            successor_kid=succ_kid,
            effective_at=statement.get("effective_at"),
            reason=statement.get("reason"),
        )
        if statement.get("schema") != STATEMENT_SCHEMA:
            problems.append(f"schema is {statement.get('schema')!r}, expected {STATEMENT_SCHEMA}")
        if kind not in ("succession", "compromise"):
            problems.append(f"type {kind!r} is neither succession nor compromise")
        if effective is None:
            problems.append(f"effective_at {statement.get('effective_at')!r} is not ISO 8601")
        if tenant_id is not None and statement.get("tenant_id") != tenant_id:
            problems.append(
                f"it is for tenant {statement.get('tenant_id')!r}, the history for {tenant_id!r}"
            )
        if statement.get("reason") not in REASONS:
            problems.append(f"reason {statement.get('reason')!r} is not one of {sorted(REASONS)}")
        if statement.get("successor_algorithm") != "ed25519":
            problems.append(
                f"successor_algorithm {statement.get('successor_algorithm')!r} is not ed25519"
            )
        if not isinstance(succ_kid, str) or not succ_kid:
            problems.append("it names no successor_kid")
        successor_key = _decode_successor(statement)
        if successor_key is None:
            problems.append("successor_public_key is not a base64 32-byte Ed25519 key")

        # The successor kid must be derived from its key (section 1).
        if isinstance(succ_kid, str) and successor_key is not None:
            match = _TENANT_KID.match(succ_kid)
            if succ_kid.startswith("t-") and match is None:
                problems.append(f"successor kid {succ_kid!r} is not t-<8 hex>-ed25519-<16 hex>")
            elif match is not None:
                if match.group(2) != hashlib.sha256(successor_key).hexdigest()[:16]:
                    problems.append(
                        f"successor kid {succ_kid!r} is not derived from successor_public_key"
                    )
                prefix = _tenant_prefix(statement.get("tenant_id"))
                if prefix is not None and match.group(1) != prefix:
                    problems.append(
                        f"successor kid {succ_kid!r} does not carry tenant "
                        f"{statement.get('tenant_id')!r}"
                    )
            listed = offered.get(succ_kid)
            if listed is not None and listed.get("public_key") != statement.get(
                "successor_public_key"
            ):
                problems.append(
                    f"the history lists {succ_kid!r} with a different public key than the "
                    "statement introduces"
                )

        predecessor = trusted.get(pred_kid) if isinstance(pred_kid, str) else None
        if predecessor is None:
            problems.append(
                f"predecessor {pred_kid!r} is not a key already trusted at this point"
            )
        elif predecessor.not_after is not None:
            problems.append(
                f"predecessor {pred_kid!r} was already succeeded at "
                f"{_iso(predecessor.not_after)} (a second successor would fork the history)"
            )
        elif (
            effective is not None
            and predecessor.not_before is not None
            and effective < predecessor.not_before
        ):
            problems.append(
                f"effective_at is before the predecessor's own window opens "
                f"({_iso(predecessor.not_before)})"
            )

        existing = trusted.get(succ_kid) if isinstance(succ_kid, str) else None
        if existing is not None and not (
            existing.source == "pinned"
            and existing.public_key == successor_key
            and not existing.bounded
            and existing is not predecessor
        ):
            problems.append(f"successor {succ_kid!r} is already in the history")

        compromised_since: datetime | None = None
        if kind == "succession":
            if statement.get("compromised_since") is not None:
                problems.append("a succession statement must have compromised_since null")
            if statement.get("reason") == COMPROMISE_REASON:
                problems.append("reason suspected_compromise needs a compromise statement")
            if predecessor is not None and not _signature_ok(
                statement, str(pred_kid), predecessor.public_key
            ):
                problems.append(f"no valid signature by the predecessor {pred_kid!r}")
        elif kind == "compromise":
            if statement.get("reason") != COMPROMISE_REASON:
                problems.append("a compromise statement must have reason suspected_compromise")
            compromised_since = _parse_time(statement.get("compromised_since"))
            if compromised_since is None:
                problems.append("a compromise statement must set compromised_since")
            elif effective is not None and compromised_since > effective:
                problems.append("compromised_since is after effective_at")
            deployment = trusted.get(deployment_kid) if isinstance(deployment_kid, str) else None
            if pred_kid == deployment_kid:
                problems.append(
                    "a compromise statement cannot revoke the deployment key (a deployment "
                    "incident, outside the key statement contract)"
                )
            if not deployment_trusted or deployment is None or deployment.source == "history":
                problems.append(
                    f"the deployment key {deployment_kid!r} is not a trusted key, so the "
                    "compromise statement has no anchor"
                )
            elif not _signature_ok(statement, str(deployment_kid), deployment.public_key):
                problems.append(f"no valid signature by the deployment key {deployment_kid!r}")
        if (
            successor_key is not None
            and isinstance(succ_kid, str)
            and not _signature_ok(statement, succ_kid, successor_key)
        ):
            problems.append(f"no valid signature by the successor {succ_kid!r}")

        if problems:
            row.update(verified=False, problems=problems)
            results.append(row)
            continue

        assert predecessor is not None and effective is not None and successor_key is not None
        predecessor.not_after = effective
        if compromised_since is not None:
            predecessor.compromised_since = compromised_since
        if existing is not None:
            existing.not_before = effective
        else:
            listed = offered.get(str(succ_kid), {})
            trusted[str(succ_kid)] = HistoryKey(
                kid=str(succ_kid),
                public_key_b64=str(statement.get("successor_public_key")),
                public_key=successor_key,
                source="history",
                not_before=effective,
                listed=dict(listed),
            )
        row.update(verified=True)
        results.append(row)
    results.sort(key=lambda r: r["index"])
    return results


def _document_parts(doc: Any, what: str) -> tuple[list[dict[str, Any]], list[Any]]:
    if not isinstance(doc, dict):
        raise AnchorError(f"{what} must be a JSON object")
    if doc.get("schema") != ANCHOR_V2_SCHEMA:
        raise AnchorError(f"{what} schema is {doc.get('schema')!r}, expected {ANCHOR_V2_SCHEMA}")
    keys = doc.get("keys")
    if not isinstance(keys, list) or not all(isinstance(k, dict) for k in keys):
        raise AnchorError(f"{what} has no list of key objects")
    statements = doc.get("statements") or []
    if not isinstance(statements, list):
        raise AnchorError(f"{what} statements must be a list")
    return keys, statements


def resolve_v2(anchor: Any) -> KeyHistory:
    """Resolve a v2 trust anchor, refusing it unless every statement verifies."""
    keys, statements = _document_parts(anchor, "trust anchor")
    deployment_kid = anchor.get("deployment_kid")
    offered: dict[str, dict[str, Any]] = {}
    for entry in keys:
        kid = entry.get("kid")
        if not isinstance(kid, str) or not kid:
            raise AnchorError("trust anchor key has no kid")
        _decode_key(entry)
        offered.setdefault(kid, entry)
    if not isinstance(deployment_kid, str) or deployment_kid not in offered:
        raise AnchorError(
            f"trust anchor v2 deployment_kid {deployment_kid!r} is not one of its keys"
        )
    deployment = _key_from_entry(offered[deployment_kid], "anchor")
    trusted = {deployment_kid: deployment}
    results = _walk(
        trusted,
        offered,
        statements,
        tenant_id=anchor.get("tenant_id"),
        deployment_kid=deployment_kid,
        deployment_trusted=True,
    )
    failed = [r for r in results if not r.get("verified")]
    if failed:
        first = failed[0]
        extra = f" (+{len(failed) - 1} more)" if len(failed) > 1 else ""
        raise AnchorError(
            f"trust anchor v2 refused: statement #{first['index']} does not verify: "
            + "; ".join(first.get("problems") or [])
            + extra
        )
    for key in trusted.values():
        key.source = "anchor"
        key.listed = dict(offered.get(key.kid, key.listed))
    unreachable = [
        {
            "kid": kid,
            "reason": "no key statement introduces it, so it has no window and is not used",
        }
        for kid in offered
        if kid not in trusted
    ]
    return KeyHistory(
        mode=MODE_V2,
        tenant_id=anchor.get("tenant_id"),
        deployment_kid=deployment_kid,
        keys=trusted,
        statements=results,
        unreachable=unreachable,
    )


def resolve_with_history(pinned: Any, history: Any) -> KeyHistory:
    """Extend a pinned v1 anchor with an untrusted v2 key history.

    Malformed documents raise ``AnchorError``. A statement that fails does not:
    it is reported, and the keys it would have introduced stay unreachable.
    """
    from behavry_verify.anchor import validate_anchor

    if not isinstance(pinned, dict) or pinned.get("schema") not in V1_SCHEMAS:
        raise AnchorError(
            "--key-history extends a pinned v1 trust anchor; the trust anchor given is "
            f"{pinned.get('schema') if isinstance(pinned, dict) else None!r}"
        )
    pinned_keys = validate_anchor(pinned)
    keys, statements = _document_parts(history, "key history")
    trusted: dict[str, HistoryKey] = {}
    for entry in pinned_keys:
        kid = entry.get("kid")
        if isinstance(kid, str) and kid and kid not in trusted:
            trusted[kid] = _key_from_entry(entry, "pinned")
    notes: list[str] = []
    offered: dict[str, dict[str, Any]] = {}
    for entry in keys:
        kid = entry.get("kid")
        if not isinstance(kid, str) or not kid:
            notes.append("the key history lists a key with no kid; ignored")
            continue
        if kid in trusted:
            if entry.get("public_key") != trusted[kid].public_key_b64:
                notes.append(
                    f"the key history lists pinned kid {kid!r} with a different public key; "
                    "the pinned key is used"
                )
            trusted[kid].listed = dict(entry)
            continue
        offered.setdefault(kid, entry)
    deployment_kid = history.get("deployment_kid")
    results = _walk(
        trusted,
        offered,
        statements,
        tenant_id=history.get("tenant_id"),
        deployment_kid=deployment_kid,
        deployment_trusted=isinstance(deployment_kid, str) and deployment_kid in trusted,
    )
    if isinstance(deployment_kid, str) and deployment_kid not in trusted:
        notes.append(
            f"the key history's deployment key {deployment_kid!r} is not in the pinned "
            "anchor, so no compromise statement can be anchored on it"
        )
    failed = {r.get("successor_kid") for r in results if not r.get("verified")}
    unreachable = []
    for kid in offered:
        if kid in trusted:
            continue
        reason = (
            "its key statement does not verify"
            if kid in failed
            else "no chain of verifying key statements reaches it from the pinned anchor"
        )
        unreachable.append({"kid": kid, "reason": reason + ", so it is not used"})
    return KeyHistory(
        mode=MODE_V1_HISTORY,
        tenant_id=history.get("tenant_id"),
        deployment_kid=deployment_kid if isinstance(deployment_kid, str) else None,
        keys=trusted,
        statements=results,
        unreachable=unreachable,
        notes=notes,
    )


# ---------------------------------------------------------------------------
# Riding on the anchor dict
# ---------------------------------------------------------------------------


def _effective(source: dict[str, Any], history: KeyHistory) -> dict[str, Any]:
    return {
        "schema": source.get("schema"),
        "tenant_id": history.tenant_id,
        "keys": history.entries(),
        HISTORY_KEY: history,
    }


def history_of(anchor: Any) -> KeyHistory | None:
    """The history an anchor carries, resolving a raw v2 anchor on first use.

    ``None`` for a v1 anchor on its own: callers then behave exactly as
    before AG-11.
    """
    if not isinstance(anchor, dict):
        return None
    attached = anchor.get(HISTORY_KEY)
    if isinstance(attached, KeyHistory):
        return attached
    if is_v2(anchor):
        history = resolve_v2(anchor)
        anchor[HISTORY_KEY] = history
        return history
    return None


def trust_anchor_with_history(anchor: Any, key_history: Any | None = None) -> dict[str, Any]:
    """The anchor every check then uses: v1 as is, or v2 / v1+history resolved.

    Raises ``AnchorError`` for a malformed anchor or history, for a v2 anchor
    whose statements do not verify, and for ``key_history`` without a pinned
    v1 anchor.
    """
    from behavry_verify.anchor import validate_anchor

    if key_history is not None:
        return _effective(anchor, resolve_with_history(anchor, key_history))
    if is_v2(anchor):
        return _effective(anchor, resolve_v2(anchor))
    validate_anchor(anchor)
    return anchor


def history_start(anchor: Any) -> int | None:
    """Mark where this report's window findings begin (see :func:`attach_history`)."""
    try:
        history = history_of(anchor)
    except AnchorError:
        return None
    return None if history is None else len(history.findings)


def attach_history(report: Any, anchor: Any, start: int | None) -> None:
    """Put the ``key_history`` section on a report, with its own findings.

    One history can serve several reports (each ``--audit-anchor``, and the
    anchors nested in a package), so a report takes the findings recorded
    since its ``start`` rather than all of them.
    """
    try:
        history = history_of(anchor)
    except AnchorError:
        return
    if history is None:
        return
    findings = history.findings[start or 0 :]
    report.key_history = history.to_dict(findings)
