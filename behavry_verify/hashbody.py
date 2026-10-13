"""Content-hash bodies, kept byte-for-byte in lockstep with the Behavry producer.

Signatures prove that the holder of a key vouched for a hash. They say nothing
about whether the *content* shown next to that hash is what was hashed. This
module closes that gap: it rebuilds, from an exported record's own fields, the
exact canonical body Behavry hashed when it wrote the record, so a verifier can
recompute the hash instead of taking it as given.

Every function here mirrors a Behavry producer function byte-for-byte. Any
divergence makes genuine evidence read as tampered, so each one names its
counterpart (repo ``Behavry-ai/behavry``):

  ``decision_canonical_body``
      -> ``backend/behavry/audit/service.py::decision_canonical_body``
         (rebuilt from a row as ``decision_event_hash_matches`` does)
  ``governance_signals_hash``
      -> ``backend/behavry/audit/service.py::governance_signals_hash``
         (via ``signals_hash_for_row``)
  ``normalize_hashed_timestamp``
      -> ``backend/behavry/audit/service.py::normalize_hashed_time``, as exported
         (``tools/verify_event.py::_normalize_ts_isoformat``)
  ``compute_event_hash``
      -> ``backend/behavry/core/security.py::compute_event_hash``
  ``authorization_canonical_body``
      -> ``backend/behavry/audit/evidence.py::authorization_canonical_body``
         (via ``authorization_body_for_row``)
  ``observation_canonical_body``
      -> ``backend/behavry/audit/evidence.py::observation_canonical_body``
  ``canonical_signing_bytes_agent_claim``
      -> ``backend/behavry/audit/signer.py::canonical_signing_bytes_agent_claim``

Version branches are kept forever. A decision row is rebuilt under the
``hash_version`` it was WRITTEN with, never the current one: rebuilding a v1
row under the v8 shape yields a mismatch indistinguishable from tampering.

Bodies are hashed AS RECEIVED and are never Unicode-normalized. ``action`` and
``target`` are free text, and NFC/NFD forms of one string hash differently.
"""
from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from behavry_verify.canonical import normalize_timestamp

__all__ = [
    "AUTHORIZATION_CLAIM",
    "MAX_DECISION_HASH_VERSION",
    "V8_DECISION_FIELDS",
    "authorization_canonical_body",
    "canonical_signing_bytes_agent_claim",
    "compute_event_hash",
    "decision_canonical_body",
    "decision_hash_version",
    "governance_signals_hash",
    "normalize_hashed_timestamp",
    "observation_canonical_body",
    "recompute_authorization_record_hash",
    "recompute_decision_event_hash",
    "recompute_observation_event_hash",
]

#: Highest decision ``hash_version`` this verifier can rebuild. Mirrors
#: ``CURRENT_DECISION_HASH_VERSION`` in ``backend/behavry/audit/service.py``.
MAX_DECISION_HASH_VERSION = 8

#: Mirrors ``backend/behavry/audit/evidence.py::AUTHORIZATION_CLAIM``.
AUTHORIZATION_CLAIM = "authorization"

#: Mirrors ``backend/behavry/audit/service.py::V8_DECISION_FIELDS`` (Sprint AG-1).
V8_DECISION_FIELDS: tuple[str, ...] = (
    "tool_name",
    "mcp_server",
    "policy_id",
    "opa_input_digest",
    "policy_bundle_digest",
    "authorization_record_id",
    "authorization_hash",
    "execution_status",
    "response_digest",
)


# ---------------------------------------------------------------------------
# Shared primitives
# ---------------------------------------------------------------------------


def compute_event_hash(event_data: str, previous_hash: str | None) -> str:
    """``sha256(f"{previous_hash or 'GENESIS'}:{event_data}")``, hex.

    Mirrors ``backend/behavry/core/security.py::compute_event_hash`` byte-for-byte.
    """
    chain_input = f"{previous_hash or 'GENESIS'}:{event_data}"
    return hashlib.sha256(chain_input.encode()).hexdigest()


def normalize_hashed_timestamp(timestamp: Any) -> Any:
    """The timestamp string a decision body hashed, from its exported value.

    The writer hashes ``normalize_hashed_time(ts).isoformat()``, and the package
    exports ``event.timestamp.isoformat()`` of the same UTC value read back from
    a TIMESTAMPTZ column, so the exported string is passed through unchanged. A
    ``datetime`` is reduced to the same form. Anything else is left alone rather
    than guessed at: a wrong guess here reads as tampering.

    Mirrors ``tools/verify_event.py::_normalize_ts_isoformat`` in the Behavry repo.
    """
    if isinstance(timestamp, datetime):
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=UTC)
        return timestamp.astimezone(UTC).isoformat()
    return timestamp


def _reparse_to_hashed_iso(timestamp: Any) -> Any:
    """Exported ``_iso`` (microsecond) string -> the writer's ``isoformat()``.

    Authorization records and observations are exported through
    ``packages._iso``, which always renders microseconds, while their bodies
    hashed ``normalize_hashed_time(ts).isoformat()``, which omits a zero
    microsecond field. Re-parsing and re-rendering recovers the hashed form.
    Unparseable values pass through unchanged so they fail rather than coerce.
    """
    if isinstance(timestamp, datetime):
        dt = timestamp
    elif isinstance(timestamp, str):
        try:
            dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        except ValueError:
            return timestamp
    else:
        return timestamp
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC).isoformat()


# ---------------------------------------------------------------------------
# Decision events
# ---------------------------------------------------------------------------


def governance_signals_hash(event: dict[str, Any]) -> str | None:
    """v5's ``signals_hash`` rebuilt from an exported row, or None.

    Mirrors ``governance_signals_hash`` as reached through
    ``signals_hash_for_row`` in ``backend/behavry/audit/service.py``, including
    its type-directed leniency: a JSONB column yields only a list or None and a
    String column only a str or None, so a value of any other type cannot have
    been hashed and is treated as absent. Returns None when the row carries no
    findings at all, which is what the writer hashed for such a row.
    """

    def _list(v: Any) -> list[Any] | None:
        return v if isinstance(v, list) else None

    def _str(v: Any) -> str | None:
        return v if isinstance(v, str) else None

    dlp_findings = _list(event.get("dlp_findings"))
    dlp_action = _str(event.get("dlp_action"))
    inbound_findings = _list(event.get("inbound_findings"))
    injection_findings = _list(event.get("injection_findings"))
    injection_max_severity = _str(event.get("injection_max_severity"))
    if (
        not dlp_findings
        and not inbound_findings
        and not injection_findings
        and dlp_action is None
        and injection_max_severity is None
    ):
        return None
    payload = {
        "dlp_findings": dlp_findings or [],
        "dlp_action": dlp_action,
        "inbound_findings": inbound_findings or [],
        "injection_findings": injection_findings or [],
        "injection_max_severity": injection_max_severity,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def decision_hash_version(event: dict[str, Any]) -> int:
    """The body version a row was written with; non-integers read as 1.

    Mirrors the producer's ``raw if isinstance(raw, int) else 1``.
    """
    raw = event.get("hash_version")
    return raw if isinstance(raw, int) else 1


def decision_canonical_body(event: dict[str, Any]) -> str:
    """The canonical JSON a decision event's hash was computed over.

    Mirrors ``backend/behavry/audit/service.py::decision_canonical_body``
    byte-for-byte, for every version branch:

    * v1: timestamp, agent_id, session_id, action, target, policy_result, input_hash
    * v2: + human_session_id, device_id, user_identifier, mcp_server_id
    * v3: + requester_id, requester_channel, requester_verified (tri-state),
      instruction_hash
    * v4: + delegation_chain, claimed_delegation_chain, origin_principal,
      containment_event_id (chains hashed in order)
    * v5: + signals_hash (see :func:`governance_signals_hash`)
    * v6: + run_label
    * v7 (Sprint UADR-2): + args_digest (sha256 of the RFC 8785 tool arguments)
    * v8 (Sprint AG-1): + :data:`V8_DECISION_FIELDS` (tool_name, mcp_server,
      policy_id, the OPA input / policy bundle / response digests, the
      authorization binding, execution_status)
    """
    version = decision_hash_version(event)
    body: dict[str, Any] = {
        "timestamp": normalize_hashed_timestamp(event.get("timestamp")),
        "agent_id": event.get("agent_id"),
        "session_id": event.get("session_id"),
        "action": event.get("action"),
        "target": event.get("target"),
        "policy_result": event.get("policy_result"),
        "input_hash": event.get("input_hash"),
    }
    if version >= 2:
        body.update({
            "human_session_id": event.get("human_session_id"),
            "device_id": event.get("device_id"),
            "user_identifier": event.get("user_identifier"),
            "mcp_server_id": event.get("mcp_server_id"),
        })
    if version >= 3:
        body.update({
            "requester_id": event.get("requester_id"),
            "requester_channel": event.get("requester_channel"),
            # null / false / true are three distinct values. Never coerce.
            "requester_verified": event.get("requester_verified"),
            "instruction_hash": event.get("instruction_hash"),
        })
    if version >= 4:
        body.update({
            "delegation_chain": event.get("delegation_chain"),
            "claimed_delegation_chain": event.get("claimed_delegation_chain"),
            "origin_principal": event.get("origin_principal"),
            "containment_event_id": event.get("containment_event_id"),
        })
    if version >= 5:
        body["signals_hash"] = governance_signals_hash(event)
    if version >= 6:
        body["run_label"] = event.get("run_label")
    if version >= 7:
        body["args_digest"] = event.get("args_digest")
    if version >= 8:
        for field in V8_DECISION_FIELDS:
            body[field] = event.get(field)
    return json.dumps(body, sort_keys=True)


def recompute_decision_event_hash(event: dict[str, Any]) -> str:
    """A decision event's ``event_hash``, recomputed from its own fields.

    Mirrors ``decision_event_hash_matches`` in ``backend/behavry/audit/service.py``.
    """
    return compute_event_hash(decision_canonical_body(event), event.get("previous_hash"))


# ---------------------------------------------------------------------------
# Authorization records (Sprint AG-1 E-2)
# ---------------------------------------------------------------------------


def authorization_canonical_body(record: dict[str, Any]) -> str:
    """Canonical JSON an authorization record's ``record_hash`` covers.

    Mirrors ``backend/behavry/audit/evidence.py::authorization_canonical_body``
    as rebuilt by ``authorization_body_for_row``, byte-for-byte.
    """
    return json.dumps(
        {
            "claim_type": AUTHORIZATION_CLAIM,
            "timestamp": _reparse_to_hashed_iso(record.get("timestamp")),
            "tenant_id": record.get("tenant_id"),
            "agent_id": record.get("agent_id"),
            "session_id": record.get("session_id"),
            "tool_name": record.get("tool_name"),
            "mcp_server": record.get("mcp_server"),
            "mcp_server_id": record.get("mcp_server_id"),
            "action": record.get("action"),
            "target": record.get("target"),
            "policy_result": record.get("policy_result"),
            "policy_id": record.get("policy_id"),
            "args_digest": record.get("args_digest"),
            "opa_input_digest": record.get("opa_input_digest"),
            "policy_bundle_digest": record.get("policy_bundle_digest"),
        },
        sort_keys=True,
    )


def recompute_authorization_record_hash(record: dict[str, Any]) -> str:
    """An authorization record's ``record_hash``, recomputed from its fields.

    Mirrors ``authorization_record_hash_matches`` in ``backend/behavry/audit/evidence.py``.
    """
    return compute_event_hash(
        authorization_canonical_body(record), record.get("previous_hash")
    )


def canonical_signing_bytes_agent_claim(
    *,
    claim_type: str,
    event_hash: str | None,
    previous_hash: str | None,
    timestamp: Any,
    tenant_id: str | None,
    agent_id: str | None,
) -> bytes:
    """Ed25519 signing payload for an agent-scoped claim (e.g. ``authorization``).

    Mirrors ``backend/behavry/audit/signer.py::canonical_signing_bytes_agent_claim``
    byte-for-byte. The producer signs a ``datetime`` rendered as UTC
    ``isoformat(timespec="microseconds")``; the exported string is normalized
    back to that form.
    """
    payload = {
        "agent_id": agent_id or "",
        "claim_type": claim_type,
        "event_hash": event_hash or "",
        "previous_hash": previous_hash or "GENESIS",
        "tenant_id": tenant_id or "",
        "timestamp": normalize_timestamp(timestamp),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


# ---------------------------------------------------------------------------
# Execution observations (Sprint AG-1 E-3)
# ---------------------------------------------------------------------------


def observation_canonical_body(
    observation: dict[str, Any], *, decision_event_hash: str | None
) -> str:
    """The exact bytes an observer signed (UTF-8), for one observation.

    Mirrors ``backend/behavry/audit/evidence.py::observation_canonical_body``
    byte-for-byte, with ``observed_at`` rendered as the ingest route does
    (``normalize_hashed_time(observed_at).isoformat()``). ``decision_event_hash``
    must come from the decision event the observation points at, which is what
    stops an observation being re-pointed at another (or an edited) decision.
    """
    return json.dumps(
        {
            "tenant_id": observation.get("tenant_id"),
            "decision_event_id": observation.get("decision_event_id"),
            "decision_event_hash": decision_event_hash,
            "observer_type": observation.get("observer_type"),
            "observer_id": observation.get("observer_id"),
            "observed_at": _reparse_to_hashed_iso(observation.get("observed_at")),
            "observed_digest": observation.get("observed_digest"),
            "match_status": observation.get("match_status"),
            "raw_evidence_ref": observation.get("raw_evidence_ref"),
        },
        sort_keys=True,
    )


def recompute_observation_event_hash(
    observation: dict[str, Any], *, decision_event_hash: str | None
) -> str:
    """An observation's chain ``event_hash`` (``append_observation``)."""
    return compute_event_hash(
        observation_canonical_body(observation, decision_event_hash=decision_event_hash),
        observation.get("previous_hash"),
    )
