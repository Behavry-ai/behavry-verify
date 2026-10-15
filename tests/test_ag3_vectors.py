"""Parity with the Behavry producer for the AG-3 canonical forms.

``tests/vectors/ag3_vectors.json`` was written by Behavry's own
``audit/args_digest.canonical_json``, ``audit/digests.content_digest``,
``authority/provenance.provenance_canonical_body`` and ``entry_as_dict``, and
its signer (see ``generate_anchor_vectors.py``). This repo's independent ports
must reproduce every byte.
"""
from __future__ import annotations

import base64
import json
import math
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from behavry_verify.authority import provenance_canonical_body, provenance_entry_hash
from behavry_verify.hashbody import canonical_signing_bytes_agent_claim
from behavry_verify.jcs import NotCanonicalizableError, canonical_json, content_digest

DATA = json.loads((Path(__file__).parent / "vectors" / "ag3_vectors.json").read_text("utf-8"))


@pytest.mark.parametrize("case", DATA["jcs"], ids=lambda c: c["canonical"][:24])
def test_rfc8785_matches_the_producer(case):
    assert canonical_json(case["input"]) == case["canonical"]
    assert content_digest(case["input"]) == case["digest"]


@pytest.mark.parametrize("value", [math.nan, math.inf, -math.inf, 10**400, {"s": {1, 2}}])
def test_values_with_no_rfc8785_form_are_refused(value):
    with pytest.raises(NotCanonicalizableError):
        canonical_json(value)
    assert content_digest(value) is None


def test_non_string_key_fails_exactly_as_the_producer_does():
    """The producer sorts keys before its isinstance check, so a non-string key
    raises AttributeError there, not NotCanonicalizableError. Ported as is: JSON
    decoded from a package cannot carry one, and a "fix" here would be drift."""
    with pytest.raises(AttributeError):
        canonical_json({1: "x"})


def test_none_has_no_digest():
    assert content_digest(None) is None


@pytest.mark.parametrize("vector", DATA["provenance"], ids=lambda v: v["entry"]["entry_type"])
def test_provenance_entry_matches_the_producer(vector):
    entry = vector["entry"]
    assert provenance_canonical_body(entry) == vector["canonical_body"]
    assert provenance_entry_hash(entry) == entry["entry_hash"]
    assert content_digest(entry["body"]) == entry["body_digest"]
    payload = canonical_signing_bytes_agent_claim(
        claim_type="provenance",
        event_hash=entry["entry_hash"],
        previous_hash=entry["previous_hash"],
        timestamp=entry["timestamp"],
        tenant_id=entry["tenant_id"],
        agent_id=entry["agent_id"],
    )
    assert payload.decode("utf-8") == vector["signing_payload"]
    key = base64.b64decode(DATA["trust_anchor"]["keys"][0]["public_key"])
    Ed25519PublicKey.from_public_bytes(key).verify(
        base64.b64decode(entry["signature_b64"]), payload
    )


def test_provenance_vectors_chain_from_genesis():
    previous = None
    for vector in DATA["provenance"]:
        assert vector["entry"]["previous_hash"] == previous
        previous = vector["entry"]["entry_hash"]


def test_exported_evidence_refs_shape():
    """What the producer writes for an assessment entry, pinned for the consumer."""
    refs = [v["entry"]["evidence_refs"] for v in DATA["provenance"]
            if v["entry"]["entry_type"] == "assessment"]
    assert refs and refs[0][0]["type"] == "assessment"
    assert refs[0][0]["bundle_digest"].startswith("sha256:")
