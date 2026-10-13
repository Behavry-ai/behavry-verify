"""Golden-vector parity with the Behavry producer.

``tests/vectors/producer_vectors.json`` was written by the Behavry backend's
OWN functions (see ``tests/vectors/generate_vectors.py`` for exactly which),
over decision rows at every hash_version v1..v8, an authorization record and
an observation. These tests assert that this repo's independent port in
:mod:`behavry_verify.hashbody` reproduces every byte.

This file deliberately does NOT import the Behavry backend: the public
verifier cannot depend on it. It reads only the committed vectors.
"""
from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from behavry_verify.hashbody import (
    AUTHORIZATION_CLAIM,
    authorization_canonical_body,
    canonical_signing_bytes_agent_claim,
    decision_canonical_body,
    governance_signals_hash,
    observation_canonical_body,
    recompute_authorization_record_hash,
    recompute_decision_event_hash,
    recompute_observation_event_hash,
)
from behavry_verify.package import verify_package
from behavry_verify.report import CheckStatus, TrustSource

VECTORS = json.loads(
    (Path(__file__).parent / "vectors" / "producer_vectors.json").read_text("utf-8")
)
DECISIONS = VECTORS["decisions"]


def test_vectors_cover_every_hash_version():
    assert sorted(d["exported"]["hash_version"] for d in DECISIONS) == [1, 2, 3, 4, 5, 6, 7, 8]


@pytest.mark.parametrize(
    "vector", DECISIONS, ids=[f"v{d['exported']['hash_version']}" for d in DECISIONS]
)
def test_decision_body_and_hash_match_producer(vector):
    exported = vector["exported"]
    assert decision_canonical_body(exported) == vector["canonical_body"]
    assert governance_signals_hash(exported) == vector["signals_hash"]
    assert recompute_decision_event_hash(exported) == vector["event_hash"]
    assert exported["event_hash"] == vector["event_hash"]


def test_authorization_record_matches_producer():
    vector = VECTORS["authorization"]
    record = vector["exported"]
    assert authorization_canonical_body(record) == vector["canonical_body"]
    assert recompute_authorization_record_hash(record) == vector["record_hash"]
    payload = canonical_signing_bytes_agent_claim(
        claim_type=AUTHORIZATION_CLAIM,
        event_hash=record["record_hash"],
        previous_hash=record["previous_hash"],
        timestamp=record["timestamp"],
        tenant_id=record["tenant_id"],
        agent_id=record["agent_id"],
    )
    assert payload.decode("utf-8") == vector["signing_bytes"]
    key = Ed25519PublicKey.from_public_bytes(
        base64.b64decode(VECTORS["behavry_public_key_b64"])
    )
    key.verify(base64.b64decode(record["signature"]), payload)


def test_observation_matches_producer():
    vector = VECTORS["observation"]
    observation = vector["exported"]
    body = observation_canonical_body(
        observation, decision_event_hash=vector["decision_event_hash"]
    )
    assert body == vector["canonical_body"]
    assert (
        recompute_observation_event_hash(
            observation, decision_event_hash=vector["decision_event_hash"]
        )
        == vector["event_hash"]
    )
    key = Ed25519PublicKey.from_public_bytes(
        bytes.fromhex(vector["observer_anchor"]["public_key_hex"])
    )
    key.verify(base64.b64decode(observation["observer_signature"]), body.encode("utf-8"))


def test_producer_rows_pass_the_package_checks():
    """End to end: producer-exported rows through verify_package's new checks."""
    components = {
        "manifest.json": {"package_version": "1.2", "file_digests": {}},
        "timeline.json": [d["exported"] for d in DECISIONS],
        "authorization_records.json": [VECTORS["authorization"]["exported"]],
        "observations.json": [VECTORS["observation"]["exported"]],
    }
    report = verify_package(
        components,
        raw_public_key=base64.b64decode(VECTORS["behavry_public_key_b64"]),
        trust_source=TrustSource.SUPPLIED_KEY,
        observer_anchors=[VECTORS["observation"]["observer_anchor"]],
    )
    statuses = {c.id: c.status for c in report.checks}
    assert statuses["event_content"] is CheckStatus.PASS, report.to_text()
    assert statuses["authorization_records"] is CheckStatus.PASS, report.to_text()
    assert statuses["observations"] is CheckStatus.PASS, report.to_text()
