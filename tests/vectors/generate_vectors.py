"""Regenerate ``producer_vectors.json`` from the Behavry producer itself.

NOT a test, and never imported by one: the public verifier must not depend on
the Behavry backend. This script is committed so the provenance of the golden
vectors is auditable. It runs the producer's OWN functions (the exporter, the
canonical bodies, the hash and the signer payloads) over a fixed set of rows,
and writes what they produce. ``tests/test_vectors.py`` then asserts this
repo's independent port reproduces every byte.

Run from a Behavry checkout, with the backend's dependencies installed::

    PYTHONPATH=<behavry>/backend python tests/vectors/generate_vectors.py

Keys are derived from fixed seeds so the output is deterministic (Ed25519
signatures are deterministic too). They are test keys and protect nothing.
"""
from __future__ import annotations

import base64
import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from behavry.apr.packages import (
    _authorization_to_dict,
    _event_to_dict,
    _observation_to_dict,
)
from behavry.audit.evidence import (
    AUTHORIZATION_CLAIM,
    authorization_body_for_row,
    authorization_record_hash_matches,
    observation_canonical_body,
    verify_observer_signature,
)
from behavry.audit.service import (
    compute_event_hash,
    decision_canonical_body,
    decision_event_hash_matches,
    normalize_hashed_time,
    signals_hash_for_row,
    v8_fields_for_row,
)
from behavry.audit.signer import canonical_signing_bytes_agent_claim
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

OUT = Path(__file__).resolve().parent / "producer_vectors.json"
BEHAVRY_SEED = bytes(range(32))
OBSERVER_SEED = bytes([7]) * 32
TENANT = "tenant-vectors"

_ALL_ROW_FIELDS = (
    "id", "tenant_id", "timestamp", "agent_id", "session_id", "action", "target",
    "tool_name", "mcp_server", "policy_result", "policy_id", "policy_reason",
    "behavioral_score", "event_hash", "previous_hash", "signer_kid", "signature",
    "extra", "hash_version", "claim_type", "input_hash", "human_session_id",
    "device_id", "user_identifier", "mcp_server_id", "requester_id",
    "requester_channel", "requester_verified", "instruction_hash",
    "delegation_chain", "claimed_delegation_chain", "origin_principal",
    "containment_event_id", "run_label", "dlp_findings", "dlp_action",
    "inbound_findings", "injection_findings", "injection_max_severity",
    "args_digest", "opa_input_digest", "policy_bundle_digest",
    "authorization_record_id", "authorization_hash", "execution_status",
    "response_digest",
)


def _row(**fields: Any) -> SimpleNamespace:
    base = {f: None for f in _ALL_ROW_FIELDS}
    base.update(fields)
    return SimpleNamespace(**base)


def _producer_canonical(row: SimpleNamespace) -> str:
    """Exactly the call ``decision_event_hash_matches`` makes."""
    return decision_canonical_body(
        version=row.hash_version if isinstance(row.hash_version, int) else 1,
        timestamp_iso=row.timestamp.isoformat(),
        agent_id=row.agent_id,
        session_id=row.session_id,
        action=row.action,
        target=row.target,
        policy_result=row.policy_result,
        input_hash=row.input_hash,
        human_session_id=row.human_session_id,
        device_id=row.device_id,
        user_identifier=row.user_identifier,
        mcp_server_id=row.mcp_server_id,
        requester_id=row.requester_id,
        requester_channel=row.requester_channel,
        requester_verified=row.requester_verified,
        instruction_hash=row.instruction_hash,
        delegation_chain=row.delegation_chain,
        claimed_delegation_chain=row.claimed_delegation_chain,
        origin_principal=row.origin_principal,
        containment_event_id=row.containment_event_id,
        signals_hash=signals_hash_for_row(row),
        run_label=row.run_label,
        args_digest=row.args_digest,
        **v8_fields_for_row(row),
    )


def _json_roundtrip(body: Any) -> Any:
    """What a verifier reads back after the package's ``_dump``."""
    return json.loads(json.dumps(body, indent=2, sort_keys=True, default=str))


def main() -> None:
    behavry_key = Ed25519PrivateKey.from_private_bytes(BEHAVRY_SEED)
    observer_key = Ed25519PrivateKey.from_private_bytes(OBSERVER_SEED)

    # -- authorization record (E-2), zero-microsecond timestamp on purpose:
    # exported with microseconds, hashed without them.
    authz_ts = normalize_hashed_time(datetime(2026, 9, 1, 12, 0, 5, tzinfo=UTC))
    authz = SimpleNamespace(
        id="authz-0001", tenant_id=TENANT, timestamp=authz_ts, agent_id="agent-v",
        session_id="sess-v", tool_name="read_file", mcp_server="demo-filesystem",
        mcp_server_id="mcp-0001", action="tool_call", target="/srv/data/report.csv",
        policy_result="allow", policy_id="base.filesystem",
        args_digest="a" * 64, opa_input_digest="sha256:" + "b" * 64,
        policy_bundle_digest="sha256:" + "c" * 64, previous_hash="9" * 64,
        record_hash=None, signature=None, signer_kid="behavry-ed25519-vectors",
    )
    authz_body = authorization_body_for_row(authz)
    authz.record_hash = compute_event_hash(authz_body, authz.previous_hash)
    assert authorization_record_hash_matches(authz)
    authz_signing = canonical_signing_bytes_agent_claim(
        claim_type=AUTHORIZATION_CLAIM, event_hash=authz.record_hash,
        previous_hash=authz.previous_hash, timestamp=authz_ts, tenant_id=TENANT,
        agent_id=authz.agent_id,
    )
    authz.signature = behavry_key.sign(authz_signing)

    common = dict(
        tenant_id=TENANT, agent_id="agent-v", session_id="sess-v",
        action="tool_call", tool_name="read_file", mcp_server="demo-filesystem",
        policy_id="base.filesystem", policy_reason=None, behavioral_score=0.25,
        input_hash="d" * 64, signer_kid="behavry-ed25519-vectors",
    )
    rows = [
        _row(id="evt-v1", hash_version=1, policy_result="allow",
             timestamp=datetime(2026, 9, 1, 12, 0, 0, 123456, tzinfo=UTC),
             target="/tmp/a.txt", previous_hash=None, **common),
        _row(id="evt-v2", hash_version=2, policy_result="deny",
             timestamp=datetime(2026, 9, 1, 12, 0, 1, tzinfo=UTC),  # zero micros
             target="/etc/shadow", previous_hash="1" * 64,
             human_session_id="hs-1", device_id="dev-1", user_identifier="ana@example.com",
             mcp_server_id="mcp-0001", **common),
        _row(id="evt-v3", hash_version=3, policy_result="escalate",
             timestamp=datetime(2026, 9, 1, 12, 0, 2, 5, tzinfo=UTC),
             target="café / NFD text", previous_hash="2" * 64,
             mcp_server_id="mcp-0001", requester_id="user-9", requester_channel="slack",
             requester_verified=False, instruction_hash="e" * 64, **common),
        _row(id="evt-v4", hash_version=4, policy_result="allow",
             timestamp=datetime(2026, 9, 1, 12, 0, 3, 999999, tzinfo=UTC),
             target="repo/main", previous_hash="3" * 64, requester_verified=True,
             delegation_chain=["del-root", "del-leaf"],
             claimed_delegation_chain=["del-root", "del-mid", "del-leaf"],
             origin_principal="user-9", containment_event_id="cont-1", **common),
        _row(id="evt-v5", hash_version=5, policy_result="deny",
             timestamp=datetime(2026, 9, 1, 12, 0, 4, 10, tzinfo=UTC),
             target="https://api.example.com/x", previous_hash="4" * 64,
             dlp_findings=[{"type": "ssn", "redacted_sample": "***-**-1234",
                            "confidence": 0.9731, "severity": "critical"}],
             dlp_action="blocked", inbound_findings=[],
             injection_findings=[{"rule": "ignore-previous", "severity": "high"}],
             injection_max_severity="high", **common),
        _row(id="evt-v6", hash_version=6, policy_result="allow",
             timestamp=datetime(2026, 9, 1, 12, 0, 4, 500000, tzinfo=UTC),
             target="/tmp/b.txt", previous_hash="5" * 64, run_label="run-42", **common),
        _row(id="evt-v7", hash_version=7, policy_result="allow",
             timestamp=datetime(2026, 9, 1, 12, 0, 5, 750000, tzinfo=UTC),
             target="/tmp/c.txt", previous_hash="7" * 64, run_label="run-42",
             args_digest="0123456789abcdef" * 4, **common),
        _row(id="evt-v8", hash_version=8, policy_result="allow",
             timestamp=datetime(2026, 9, 1, 12, 0, 6, 250000, tzinfo=UTC),
             target="/srv/data/report.csv", previous_hash="6" * 64, run_label="run-42",
             mcp_server_id="mcp-0001", dlp_action="logged",
             args_digest=authz.args_digest, opa_input_digest=authz.opa_input_digest,
             policy_bundle_digest=authz.policy_bundle_digest,
             authorization_record_id=authz.id, authorization_hash=authz.record_hash,
             execution_status="success", response_digest="sha256:" + "f" * 64,
             **common),
    ]

    decisions = []
    for row in rows:
        canonical = _producer_canonical(row)
        row.event_hash = compute_event_hash(canonical, row.previous_hash)
        assert decision_event_hash_matches(row), row.id
        decisions.append({
            "exported": _json_roundtrip(_event_to_dict(row)),
            "canonical_body": canonical,
            "event_hash": row.event_hash,
            "signals_hash": signals_hash_for_row(row),
        })

    # -- observation (E-3) of the v8 decision, zero-microsecond observed_at.
    observed_at = normalize_hashed_time(datetime(2026, 9, 1, 12, 0, 9, tzinfo=UTC))
    v8 = rows[-1]
    obs_body = observation_canonical_body(
        tenant_id=TENANT, decision_event_id=v8.id, decision_event_hash=v8.event_hash,
        observer_type="minotaur", observer_id="minotaur-01",
        observed_at_iso=observed_at.isoformat(), observed_digest="sha256:" + "f" * 64,
        match_status="match", raw_evidence_ref="s3://bucket/obs/1.json",
    )
    obs_sig = observer_key.sign(obs_body.encode("utf-8"))
    observer_public_hex = observer_key.public_key().public_bytes_raw().hex()
    assert verify_observer_signature(observer_public_hex, obs_body, obs_sig)
    obs = SimpleNamespace(
        id="obs-0001", tenant_id=TENANT, decision_event_id=v8.id,
        observer_type="minotaur", observer_id="minotaur-01", observer_kid="minotaur-key-1",
        observed_at=observed_at, observed_digest="sha256:" + "f" * 64,
        match_status="match", raw_evidence_ref="s3://bucket/obs/1.json",
        observer_signature=obs_sig, previous_hash=None,
        event_hash=compute_event_hash(obs_body, None),
    )

    behavry_rev = subprocess.run(
        ["git", "rev-parse", "HEAD"], capture_output=True, text=True,
        cwd=Path(__import__("behavry").__file__).resolve().parent,
    ).stdout.strip()

    vectors = {
        "generated_from": {
            "repo": "Behavry-ai/behavry",
            "commit": behavry_rev or None,
            "by": "tests/vectors/generate_vectors.py",
        },
        "behavry_public_key_b64": base64.b64encode(
            behavry_key.public_key().public_bytes_raw()
        ).decode("ascii"),
        "decisions": decisions,
        "authorization": {
            "exported": _json_roundtrip(_authorization_to_dict(authz)),
            "canonical_body": authz_body,
            "record_hash": authz.record_hash,
            "signing_bytes": authz_signing.decode("utf-8"),
        },
        "observation": {
            "exported": _json_roundtrip(_observation_to_dict(obs)),
            "decision_event_hash": v8.event_hash,
            "canonical_body": obs_body,
            "event_hash": obs.event_hash,
            "observer_anchor": {
                "kid": "minotaur-key-1",
                "public_key_hex": observer_public_hex,
                "observer_id": "minotaur-01",
                "observer_type": "minotaur",
            },
        },
    }
    OUT.write_text(json.dumps(vectors, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
