"""Test fixtures: build genuine, signed evidence packages.

The builder here mirrors ``APRPackageGenerator`` in the Behavry backend
(``backend/behavry/apr/packages.py``): same manifest field set, same
two-pass signing order, same per-file JSON dump options, same ZIP layout.

That fidelity is the whole point of these tests. Verifying a package this
repo also built would only prove self-consistency; the fixture is written
against the producer's shape so a drift in either codebase shows up as a
failing test rather than as evidence that silently stops verifying.
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import zipfile
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from behavry_verify.canonical import (
    canonical_package_manifest_bytes,
    canonical_signing_bytes,
)
from behavry_verify.merkle import merkle_depth, merkle_root

PACKAGE_SCHEMA = "behavry.apr_evidence_package.v1"
PACKAGE_VERSION = "1.0"
KID = "behavry-ed25519-test-2026-01"
TENANT_ID = "tenant-0001"


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _dump(body: Any) -> bytes:
    """Mirror ``APRPackageGenerator._dump``."""
    return json.dumps(body, indent=2, sort_keys=True, default=str).encode("utf-8")


class PackageBuilder:
    """Builds a signed evidence package, and can be told to corrupt it."""

    def __init__(
        self,
        *,
        event_count: int = 4,
        agents: int = 1,
        package_version: str = PACKAGE_VERSION,
        agentless: bool = False,
    ) -> None:
        """``package_version`` defaults to 1.0 so existing tests keep exercising
        the legacy contiguity path unchanged.

        ``agentless`` models browser / Human Governance events: no agent_id, and
        therefore no link pointer at all, because the producer only chains
        per-agent. Under 1.0 rules such a package fails the walk outright, which
        is the defect 1.1 exists to correct.
        """
        self.private_key = Ed25519PrivateKey.generate()
        self.public_key_bytes = self.private_key.public_key().public_bytes_raw()
        self.public_key_b64 = base64.b64encode(self.public_key_bytes).decode("ascii")
        self.apr_identifier = "APR-2026-001942"
        self.tenant_id = TENANT_ID
        self.kid = KID
        self.package_version = package_version
        self.agentless = agentless
        self.events = self._make_events(event_count, agents)

    # -- construction --------------------------------------------------------

    def _make_events(self, count: int, agents: int) -> list[dict[str, Any]]:
        base_time = datetime(2026, 6, 9, 14, 32, 0, tzinfo=UTC)
        events: list[dict[str, Any]] = []
        previous_by_agent: dict[str, str | None] = {}
        for index in range(count):
            agent_id = None if self.agentless else f"agent-{index % agents}"
            timestamp = (base_time + timedelta(seconds=index)).isoformat(
                timespec="microseconds"
            )
            event_hash = _sha256_hex(f"event-{index}".encode())
            event = {
                "id": f"evt-{index:04d}",
                "tenant_id": self.tenant_id,
                "timestamp": timestamp,
                "agent_id": agent_id,
                "session_id": "sess-0001",
                "action": "tool_call",
                "target": "/etc/passwd" if index == 2 else "/tmp/report.csv",
                "tool_name": "read_file",
                "mcp_server": "demo-filesystem",
                "policy_result": "deny" if index == 2 else "allow",
                "policy_id": "base.filesystem",
                "policy_reason": "sensitive path" if index == 2 else None,
                "behavioral_score": 0.12,
                "event_hash": event_hash,
                # Agentless events are never linked: the producer looks up the
                # previous hash by agent_id, so a null agent yields nothing.
                "previous_hash": (
                    None if agent_id is None else previous_by_agent.get(agent_id)
                ),
                "signer_kid": self.kid,
            }
            event["signature"] = self._sign_event(event)
            previous_by_agent[agent_id] = event_hash
            events.append(event)
        return events

    def _sign_event(self, event: dict[str, Any]) -> str:
        payload = canonical_signing_bytes(
            event_hash=event.get("event_hash"),
            previous_hash=event.get("previous_hash"),
            timestamp=event.get("timestamp"),
            tenant_id=event.get("tenant_id"),
        )
        return base64.b64encode(self.private_key.sign(payload)).decode("ascii")

    def _hash_chain(self) -> list[dict[str, Any]]:
        if self.package_version != "1.0":
            # 1.1+ flags assert per-event integrity, which the producer
            # established at export time; nothing here depends on link order.
            return [
                {
                    "event_id": event["id"],
                    "hash": event["event_hash"],
                    "previous_hash": event["previous_hash"],
                    "verified": True,
                }
                for event in self.events
            ]
        expected: dict[str, str | None] = {}
        previous_by_agent: dict[str, str | None] = {}
        for event in self.events:
            agent = event["agent_id"]
            expected[event["id"]] = previous_by_agent.get(agent)
            previous_by_agent[agent] = event["event_hash"]
        links = []
        for event in self.events:
            want = expected[event["id"]]
            verified = (
                event["event_hash"] is not None
                if want is None
                else event["previous_hash"] == want
            )
            links.append(
                {
                    "event_id": event["id"],
                    "hash": event["event_hash"],
                    "previous_hash": event["previous_hash"],
                    "verified": verified,
                }
            )
        return links

    def components(self) -> dict[str, Any]:
        """Assemble and sign, returning the parsed component map."""
        event_hashes = [e["event_hash"] for e in self.events if e["event_hash"]]
        hash_chain = self._hash_chain()

        manifest: dict[str, Any] = {
            "schema": PACKAGE_SCHEMA,
            "apr_identifier": self.apr_identifier,
            "apr_id": "apr-uuid-0001",
            "tenant_id": self.tenant_id,
            "package_version": self.package_version,
            "created_at": datetime(2026, 6, 9, 15, 0, 0, tzinfo=UTC).isoformat(
                timespec="microseconds"
            ),
            "event_count": len(self.events),
            "hash_algorithm": "sha256",
            "root_hash": merkle_root(event_hashes),
            "merkle_depth": merkle_depth(len(event_hashes)),
            "chain_root_hash": event_hashes[-1] if event_hashes else None,
            "chain_status": "healthy"
            if all(link["verified"] for link in hash_chain)
            else "broken",
            "delegation_node_count": 0,
            "trajectory_included": False,
            "narrative_included": False,
            # Signer metadata is folded in *before* signing, exactly as the
            # producer does, because the canonical bytes exclude only
            # ``signature``.
            "signer_kid": self.kid,
            "signature_algorithm": "ed25519",
            "signing_backend": "internal",
        }
        signature = base64.b64encode(
            self.private_key.sign(canonical_package_manifest_bytes(manifest))
        ).decode("ascii")
        manifest["signature"] = signature

        return {
            "manifest.json": manifest,
            "apr.json": {
                "apr_identifier": self.apr_identifier,
                "tenant_id": self.tenant_id,
                "event_count": len(self.events),
                "lifecycle_state": "closed",
                "severity": "high",
            },
            "timeline.json": self.events,
            "delegation_graph.json": {
                "apr_identifier": self.apr_identifier,
                "max_depth": 0,
                "node_count": 0,
                "nodes": [],
            },
            "behavioral_trajectory.json": None,
            "policy_decisions.json": [
                {
                    "event_id": e["id"],
                    "timestamp": e["timestamp"],
                    "policy_result": e["policy_result"],
                }
                for e in self.events
            ],
            "hash_chain.json": hash_chain,
            "signature.json": {
                "signature": signature,
                "signer_kid": self.kid,
                "algorithm": "ed25519",
                "backend": "internal",
                "canonical_manifest_sha256": "sha256:"
                + _sha256_hex(canonical_package_manifest_bytes(manifest)),
            },
            "verification_metadata.json": {
                "schema": "behavry.apr_verification_metadata.v1",
                "signer_kid": self.kid,
                "algorithm": "ed25519",
                "public_key_hint": "sha256:"
                + _sha256_hex(self.public_key_b64.encode("utf-8"))[:16],
                "trust_anchor_url": "https://verify.behavry.ai/trust-anchor.json",
            },
        }

    def zip_bytes(self, components: dict[str, Any] | None = None) -> bytes:
        """Serialize to a ZIP, matching ``APRPackageGenerator.export_zip``."""
        components = components if components is not None else self.components()
        buffer = io.BytesIO()
        root = f"apr-{self.apr_identifier}"
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
            for name, body in components.items():
                zf.writestr(f"{root}/{name}", _dump(body))
        return buffer.getvalue()

    def anchor(self, *, kid: str | None = None) -> dict[str, Any]:
        return {
            "schema": "behavry.trust_anchor.v1",
            "keys": [
                {
                    "kid": kid or self.kid,
                    "algorithm": "ed25519",
                    "public_key": self.public_key_b64,
                    "not_before": "2026-01-01T00:00:00+00:00",
                    "not_after": None,
                }
            ],
        }


@pytest.fixture
def builder() -> PackageBuilder:
    return PackageBuilder()


@pytest.fixture
def components(builder: PackageBuilder) -> dict[str, Any]:
    return builder.components()


@pytest.fixture
def anchor(builder: PackageBuilder) -> dict[str, Any]:
    return builder.anchor()
