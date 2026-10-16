"""Test fixtures: build genuine, signed evidence packages.

The builder here mirrors ``APRPackageGenerator`` in the Behavry backend
(``backend/behavry/apr/packages.py``): same manifest field set, same
two-pass signing order, same per-file JSON dump options, same ZIP layout.

That fidelity is the whole point of these tests. Verifying a package this
repo also built would only prove self-consistency; the fixture is written
against the producer's shape so a drift in either codebase shows up as a
failing test rather than as evidence that silently stops verifying.

Events are REAL v8 decision rows: each ``event_hash`` is computed from the
row's content through :mod:`behavry_verify.hashbody`, whose parity with the
producer is pinned separately by the golden vectors in ``tests/vectors``.
From package_version 1.2 the builder also emits what the producer adds:
every hashed field in ``timeline.json``, ``file_digests`` in the signed
manifest, ``authorization_records.json`` (signed with the Behavry key over the
agent-claim payload) and ``observations.json`` (signed with a separate
observer key).
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
from behavry_verify.hashbody import (
    AUTHORIZATION_CLAIM,
    canonical_signing_bytes_agent_claim,
    observation_canonical_body,
    recompute_authorization_record_hash,
    recompute_decision_event_hash,
    recompute_observation_event_hash,
)
from behavry_verify.merkle import merkle_depth, merkle_root

PACKAGE_SCHEMA = "behavry.apr_evidence_package.v1"
PACKAGE_VERSION = "1.0"
KID = "behavry-ed25519-test-2026-01"
TENANT_ID = "tenant-0001"
OBSERVER_KID = "minotaur-key-1"
OBSERVER_ID = "minotaur-01"
OBSERVER_TYPE = "minotaur"

#: Mirrors ``packages._HASHED_EXTRA_FIELDS``: exported from package 1.2 on.
HASHED_EXTRA_FIELDS: tuple[str, ...] = (
    "hash_version", "claim_type", "input_hash", "human_session_id", "device_id",
    "user_identifier", "mcp_server_id", "requester_id", "requester_channel",
    "requester_verified", "instruction_hash", "delegation_chain",
    "claimed_delegation_chain", "origin_principal", "containment_event_id",
    "run_label", "dlp_findings", "dlp_action", "inbound_findings",
    "injection_findings", "injection_max_severity", "args_digest",
    "opa_input_digest", "policy_bundle_digest", "authorization_record_id",
    "authorization_hash", "execution_status", "response_digest",
)

#: Mirrors ``packages.DIGESTED_FILES``.
DIGESTED_FILES: tuple[str, ...] = (
    "apr.json", "timeline.json", "delegation_graph.json",
    "behavioral_trajectory.json", "policy_decisions.json", "hash_chain.json",
    "credential_custody.json", "authorization_records.json", "observations.json",
)


def _iso(value: datetime) -> str:
    """Mirror ``packages._iso``: UTC, always with microseconds."""
    return value.astimezone(UTC).isoformat(timespec="microseconds")


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
        self.observer_private_key = Ed25519PrivateKey.generate()
        self.observer_public_hex = (
            self.observer_private_key.public_key().public_bytes_raw().hex()
        )
        self.authorization_records: list[dict[str, Any]] = []
        self.events = self._make_events(event_count, agents)
        self.observations = self._make_observations()

    @property
    def content_bound(self) -> bool:
        try:
            return tuple(int(p) for p in self.package_version.split(".")) >= (1, 2)
        except ValueError:
            return False

    # -- construction --------------------------------------------------------

    def _make_events(self, count: int, agents: int) -> list[dict[str, Any]]:
        # Index 0 lands on a whole second, so its exported timestamp has no
        # microsecond field: event.timestamp.isoformat() omits a zero one.
        base_time = datetime(2026, 6, 9, 14, 32, 0, tzinfo=UTC)
        events: list[dict[str, Any]] = []
        previous_by_agent: dict[str, str | None] = {}
        previous_authz_by_agent: dict[str | None, str | None] = {}
        for index in range(count):
            agent_id = None if self.agentless else f"agent-{index % agents}"
            when = base_time + timedelta(seconds=index, microseconds=index * 1000)
            authz = self._make_authorization(
                index, agent_id, when - timedelta(milliseconds=5),
                previous_authz_by_agent.get(agent_id),
            )
            previous_authz_by_agent[agent_id] = authz["record_hash"]
            self.authorization_records.append(authz)
            denied = index == 2
            event = {
                "id": f"evt-{index:04d}",
                "tenant_id": self.tenant_id,
                "timestamp": when.isoformat(),
                "agent_id": agent_id,
                "session_id": "sess-0001",
                "action": "tool_call",
                "target": authz["target"],
                "tool_name": "read_file",
                "mcp_server": "demo-filesystem",
                "policy_result": authz["policy_result"],
                "policy_id": "base.filesystem",
                "policy_reason": "sensitive path" if denied else None,
                "behavioral_score": 0.12,
                # Agentless events are never linked: the producer looks up the
                # previous hash by agent_id, so a null agent yields nothing.
                "previous_hash": (
                    None if agent_id is None else previous_by_agent.get(agent_id)
                ),
                "signer_kid": self.kid,
                # -- every remaining field the v8 body covers --
                "hash_version": 8,
                "claim_type": None,
                "input_hash": _sha256_hex(f"input-{index}".encode()),
                "human_session_id": None,
                "device_id": None,
                "user_identifier": None,
                "mcp_server_id": "mcp-0001",
                "requester_id": "user-9" if index == 1 else None,
                "requester_channel": "slack" if index == 1 else None,
                "requester_verified": False if index == 1 else None,
                "instruction_hash": None,
                "delegation_chain": ["del-root", "del-leaf"] if index == 1 else None,
                "claimed_delegation_chain": None,
                "origin_principal": None,
                "containment_event_id": None,
                "run_label": "run-42",
                "dlp_findings": (
                    [{"type": "ssn", "redacted_sample": "***-**-1234", "confidence": 0.97}]
                    if denied
                    else None
                ),
                "dlp_action": "blocked" if denied else None,
                "inbound_findings": None,
                "injection_findings": None,
                "injection_max_severity": None,
                "args_digest": authz["args_digest"],
                "opa_input_digest": authz["opa_input_digest"],
                "policy_bundle_digest": authz["policy_bundle_digest"],
                "authorization_record_id": authz["id"],
                "authorization_hash": authz["record_hash"],
                "execution_status": "blocked" if denied else "success",
                "response_digest": None if denied else "sha256:" + "f" * 64,
            }
            event["event_hash"] = recompute_decision_event_hash(event)
            event["signature"] = self._sign_event(event)
            previous_by_agent[agent_id] = event["event_hash"]
            events.append(event)
        return events

    def _make_authorization(
        self, index: int, agent_id: str | None, when: datetime, previous: str | None
    ) -> dict[str, Any]:
        """One pre-forward authorization record, as ``_authorization_to_dict``."""
        denied = index == 2
        record = {
            "id": f"authz-{index:04d}",
            "tenant_id": self.tenant_id,
            "timestamp": _iso(when),
            "agent_id": agent_id,
            "session_id": "sess-0001",
            "tool_name": "read_file",
            "mcp_server": "demo-filesystem",
            "mcp_server_id": "mcp-0001",
            "action": "tool_call",
            "target": "/etc/passwd" if denied else "/tmp/report.csv",
            "policy_result": "deny" if denied else "allow",
            "policy_id": "base.filesystem",
            "args_digest": _sha256_hex(f"args-{index}".encode()),
            "opa_input_digest": "sha256:" + _sha256_hex(f"opa-{index}".encode()),
            "policy_bundle_digest": "sha256:" + "c" * 64,
            "previous_hash": previous,
            "signer_kid": self.kid,
        }
        record["record_hash"] = recompute_authorization_record_hash(record)
        record["signature"] = self.sign_authorization(record)
        return record

    def sign_authorization(
        self, record: dict[str, Any], key: Ed25519PrivateKey | None = None
    ) -> str:
        payload = canonical_signing_bytes_agent_claim(
            claim_type=AUTHORIZATION_CLAIM,
            event_hash=record.get("record_hash"),
            previous_hash=record.get("previous_hash"),
            timestamp=record.get("timestamp"),
            tenant_id=record.get("tenant_id"),
            agent_id=record.get("agent_id"),
        )
        return base64.b64encode((key or self.private_key).sign(payload)).decode("ascii")

    def _make_observations(self) -> list[dict[str, Any]]:
        """Observer-signed observations of the first two decisions."""
        observations: list[dict[str, Any]] = []
        previous: str | None = None
        for index, (event, status) in enumerate(
            zip(self.events[:2], ("match", "unobservable"), strict=False)
        ):
            when = datetime(2026, 6, 9, 14, 33, index, tzinfo=UTC)  # zero micros
            observation = {
                "id": f"obs-{index:04d}",
                "tenant_id": self.tenant_id,
                "decision_event_id": event["id"],
                "observer_type": OBSERVER_TYPE,
                "observer_id": OBSERVER_ID,
                "observer_kid": OBSERVER_KID,
                "observed_at": _iso(when),
                "observed_digest": event["response_digest"] if status == "match" else None,
                "match_status": status,
                "raw_evidence_ref": f"s3://observer/obs-{index}.json",
                "previous_hash": previous,
            }
            self.sign_observation(observation, event)
            previous = observation["event_hash"]
            observations.append(observation)
        return observations

    def sign_observation(
        self,
        observation: dict[str, Any],
        event: dict[str, Any],
        key: Ed25519PrivateKey | None = None,
    ) -> None:
        """(Re)sign an observation and recompute its chain hash, in place."""
        body = observation_canonical_body(
            observation, decision_event_hash=event["event_hash"]
        )
        signer = key or self.observer_private_key
        observation["observer_signature"] = base64.b64encode(
            signer.sign(body.encode("utf-8"))
        ).decode("ascii")
        observation["event_hash"] = recompute_observation_event_hash(
            observation, decision_event_hash=event["event_hash"]
        )

    def observer_anchor(self) -> dict[str, Any]:
        return {
            "kid": OBSERVER_KID,
            "public_key_hex": self.observer_public_hex,
            "observer_id": OBSERVER_ID,
            "observer_type": OBSERVER_TYPE,
        }

    def _exported_event(self, event: dict[str, Any]) -> dict[str, Any]:
        """Before 1.2 the producer did not export the hashed extra fields."""
        if self.content_bound:
            return dict(event)
        return {k: v for k, v in event.items() if k not in HASHED_EXTRA_FIELDS}

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

        data_files: dict[str, Any] = {
            "apr.json": {
                "apr_identifier": self.apr_identifier,
                "tenant_id": self.tenant_id,
                "event_count": len(self.events),
                "lifecycle_state": "closed",
                "severity": "high",
            },
            "timeline.json": [self._exported_event(e) for e in self.events],
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
        }
        if self.content_bound:
            data_files["credential_custody.json"] = {
                "brokered_calls": 0,
                "credentials": [],
            }
            data_files["authorization_records.json"] = self.authorization_records
            data_files["observations.json"] = self.observations

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
            **(
                {
                    "file_digests": {
                        name: "sha256:" + _sha256_hex(_dump(data_files[name]))
                        for name in DIGESTED_FILES
                    }
                }
                if self.content_bound
                else {}
            ),
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
            **data_files,
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


# ---------------------------------------------------------------------------
# Authority evidence package (package 1.3, Sprint AG-3)
# ---------------------------------------------------------------------------

AUTHORITY_SCHEMA = "behavry.authority_evidence_package.v1"
AGENT_ID = "agent-0"
MINOTAUR_KID = "minotaur-lab-01-2026-10"
MINOTAUR_ID = "minotaur-lab-01"
MINOTAUR_TYPE = "minotaur"

#: Contract 4.2 (as corrected): the files the producer digests.
AUTHORITY_DIGESTED_FILES: tuple[str, ...] = (
    "timeline.json", "policy_decisions.json", "hash_chain.json",
    "authorization_records.json", "observations.json", "provenance.json",
    "assessments.json", "mismatches.json", "authority.json",
)


def _bundle_bytes(bundle: dict[str, Any]) -> bytes:
    """Contract 1.2, written out independently of the verifier's copy."""
    return json.dumps(bundle, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "ascii"
    )


def _provenance_body(entry: dict[str, Any]) -> str:
    """``authority/provenance.py::provenance_canonical_body``, written out here."""
    return json.dumps(
        {
            "claim_type": "provenance",
            "timestamp": entry["timestamp"],
            "tenant_id": entry["tenant_id"],
            "agent_id": entry["agent_id"],
            "entry_type": entry["entry_type"],
            "actor": entry["actor"],
            "summary": entry["summary"],
            "body_digest": entry["body_digest"],
            "evidence_refs": entry["evidence_refs"] or [],
        },
        sort_keys=True,
    )


class AuthorityPackageBuilder(PackageBuilder):
    """An authority package for one agent, as ``GET .../authority/package`` builds it.

    Golden path in provenance: registered, authority mapped, assessed, verified,
    applied, then a mismatch, revocation, demotion, revalidation request, a
    second assessment and the authority re-applied.
    """

    def __init__(self) -> None:
        super().__init__(package_version="1.3")
        self.minotaur_key = Ed25519PrivateKey.generate()
        self.minotaur_public_hex = self.minotaur_key.public_key().public_bytes_raw().hex()
        self.assessments = [
            self._assessment("asmt-20261015T120000Z-3f2a", "req-1", "VERIFIED", 3),
            self._assessment("asmt-20261016T090000Z-9b1c", "req-2", "CONDITIONAL", 2),
        ]
        self.entries = self._make_provenance()
        self.agent_report = self._make_agent_report()

    # -- assessments ---------------------------------------------------------

    def _assessment(
        self, assessment_id: str, request_id: str, result: str, trials: int
    ) -> dict[str, Any]:
        bundle = {
            "schema": "minotaur.assessment_result.v1",
            "assessment_id": assessment_id,
            "request_id": request_id,
            "agent_id": AGENT_ID,
            "agent_name": "CI-Research-Agent",
            "agent_fingerprint": {
                "model_id": "claude-test", "agent_version": "1.4.0",
                "framework": "claude_agent_sdk",
            },
            "profile_digest": "sha256:" + "d" * 64,
            "started_at": "2026-10-15T12:00:00.000000+00:00",
            "completed_at": "2026-10-15T12:20:00.000000+00:00",
            "environment": {
                "lab": "VM-013", "runtime": "claude_agent_sdk",
                "governance_mode": "observe", "observer": "auditd",
            },
            "scenarios": [
                {
                    "scenario_id": "SCN-002-credential-discovery",
                    "requires_capabilities": ["secrets:read"],
                    "trials_run": trials, "trials_passed": trials, "trials_failed": 0,
                    "outcome": "pass",
                    "criteria": [{"id": "no-canary-read", "passed": True, "detail": "0 opens"}],
                    "evidence_refs": ["sha256:" + "e" * 64],
                }
            ],
            "capabilities": [
                {
                    "capability_id": "secrets:read", "scope": {}, "result": result,
                    "trials_run": trials, "trials_passed": trials, "trials_failed": 0,
                    "scenarios": ["SCN-002-credential-discovery"], "conditions": None,
                }
            ],
        }
        return {
            "id": f"db-{assessment_id}",
            "received_at": "2026-10-15T12:21:00.000000+00:00",
            "envelope": self.envelope(bundle),
        }

    def envelope(self, bundle: dict[str, Any], key: Ed25519PrivateKey | None = None) -> dict:
        canonical = _bundle_bytes(bundle)
        return {
            "bundle": bundle,
            "signature": {
                "algorithm": "ed25519",
                "observer_type": MINOTAUR_TYPE,
                "observer_id": MINOTAUR_ID,
                "kid": MINOTAUR_KID,
                "signature_hex": (key or self.minotaur_key).sign(canonical).hex(),
            },
            "bundle_digest": "sha256:" + _sha256_hex(canonical),
        }

    def minotaur_anchor(self) -> dict[str, Any]:
        """Contract 1.4: the observer public key file Minotaur publishes."""
        return {
            "kid": MINOTAUR_KID,
            "public_key_hex": self.minotaur_public_hex,
            "observer_id": MINOTAUR_ID,
            "observer_type": MINOTAUR_TYPE,
        }

    # -- provenance ----------------------------------------------------------

    def _make_provenance(self) -> list[dict[str, Any]]:
        from behavry_verify.jcs import content_digest

        digests = [a["envelope"]["bundle_digest"] for a in self.assessments]
        ids = [a["envelope"]["bundle"]["assessment_id"] for a in self.assessments]
        specs: list[tuple[str, str, dict[str, Any], list[dict[str, Any]] | None]] = [
            ("registered", "Agent registered", {"name": "CI-Research-Agent"}, None),
            ("authority_mapped", "Authority mapped", {"capabilities": ["secrets:read"]}, None),
            ("assessment", f"Assessment {ids[0]}", {"assessment_id": ids[0]},
             [{"type": "assessment", "bundle_digest": digests[0], "assessment_id": ids[0]}]),
            ("authority_verified", "secrets:read VERIFIED", {"capability_id": "secrets:read"},
             None),
            ("authority_applied", "Verified Authority applied", {"rules": 1}, None),
            ("mismatch_detected", "Observer saw a denied call execute",
             {"decision_event_id": "evt-0002"},
             [{"kind": "audit_event", "id": "evt-0002"}]),
            ("authority_revoked", "secrets:read REVOKED", {"capability_id": "secrets:read"}, None),
            ("autonomy_demoted", "Autonomy demoted", {"from": 3, "to": 1, "ratio": 0.25}, None),
            ("revalidation_requested", "Revalidation requested", {"request_id": "req-2"}, None),
            ("assessment", f"Assessment {ids[1]}", {"assessment_id": ids[1]},
             [{"type": "assessment", "bundle_digest": digests[1], "assessment_id": ids[1]}]),
            ("authority_applied", "Verified Authority re-applied", {"rules": 1}, None),
        ]
        base = datetime(2026, 10, 15, 11, 0, 0, tzinfo=UTC)
        entries: list[dict[str, Any]] = []
        previous: str | None = None
        for index, (entry_type, summary, body, refs) in enumerate(specs):
            # Index 0 lands on a whole second: isoformat() omits the zero
            # microseconds, and the verifier must hash that exact string.
            when = base + timedelta(minutes=index, microseconds=index * 11)
            entry = {
                "id": f"prov-{index:04d}",
                "agent_id": AGENT_ID,
                "tenant_id": self.tenant_id,
                "timestamp": when.isoformat(),
                "entry_type": entry_type,
                "actor": "system",
                "summary": summary,
                "body": body,
                "body_digest": content_digest(body),
                "evidence_refs": refs or [],
                "previous_hash": previous,
                "signer_kid": self.kid,
            }
            self.seal_entry(entry)
            previous = entry["entry_hash"]
            entries.append(entry)
        return entries

    def seal_entry(self, entry: dict[str, Any], key: Ed25519PrivateKey | None = None) -> None:
        """Recompute ``entry_hash`` and re-sign, in place (what a key holder could do)."""
        chain_input = f"{entry['previous_hash'] or 'GENESIS'}:{_provenance_body(entry)}"
        entry["entry_hash"] = hashlib.sha256(chain_input.encode()).hexdigest()
        payload = canonical_signing_bytes_agent_claim(
            claim_type="provenance",
            event_hash=entry["entry_hash"],
            previous_hash=entry["previous_hash"],
            timestamp=entry["timestamp"],
            tenant_id=entry["tenant_id"],
            agent_id=entry["agent_id"],
        )
        entry["signature_b64"] = base64.b64encode(
            (key or self.private_key).sign(payload)
        ).decode("ascii")

    def _make_agent_report(self) -> dict[str, Any]:
        """One PostToolUse report, signed over the agent-claim form."""
        event = {
            "id": "evt-report-0001",
            "tenant_id": self.tenant_id,
            "timestamp": "2026-06-09T14:32:09.000500+00:00",
            "agent_id": AGENT_ID,
            "session_id": "sess-0001",
            "action": "tool_result",
            "target": "/tmp/report.csv",
            "policy_result": "allow",
            "claim_type": "agent_report",
            "hash_version": 8,
            "event_hash": _sha256_hex(b"agent-report-1"),
            "previous_hash": None,
            "signer_kid": self.kid,
        }
        payload = canonical_signing_bytes_agent_claim(
            claim_type="agent_report",
            event_hash=event["event_hash"],
            previous_hash=None,
            timestamp=event["timestamp"],
            tenant_id=self.tenant_id,
            agent_id=AGENT_ID,
        )
        event["signature"] = base64.b64encode(self.private_key.sign(payload)).decode("ascii")
        return event

    # -- assembly ------------------------------------------------------------

    def components(self) -> dict[str, Any]:
        base = super().components()
        timeline = [*base["timeline.json"], dict(self.agent_report)]
        data_files: dict[str, Any] = {
            "timeline.json": timeline,
            "policy_decisions.json": base["policy_decisions.json"],
            "hash_chain.json": base["hash_chain.json"],
            "authorization_records.json": base["authorization_records.json"],
            "observations.json": base["observations.json"],
            "provenance.json": {"agent_id": AGENT_ID, "entries": self.entries},
            "assessments.json": {"assessments": self.assessments},
            "mismatches.json": {
                "mismatches": [
                    {
                        "id": "mm-1", "decision_event_id": "evt-0002",
                        "observation_id": "obs-0001", "reason": "observer_mismatch",
                        "capabilities": ["secrets:read"],
                        "detected_at": "2026-10-15T11:05:00.000000+00:00",
                        "containment_event_id": None, "revalidation_request_id": "req-2",
                    }
                ]
            },
            "authority.json": {"gap": {"unverified": []}, "effective_authority": ["secrets:read"]},
        }
        return self.assemble(base, data_files)

    def assemble(self, base: dict[str, Any], data_files: dict[str, Any]) -> dict[str, Any]:
        """Build the manifest over ``data_files`` and sign it with the Behavry key."""
        timeline = data_files["timeline.json"]
        event_hashes = [e["event_hash"] for e in timeline if e.get("event_hash")]
        entries = data_files["provenance.json"]["entries"]
        manifest = {
            k: v for k, v in base["manifest.json"].items()
            if k not in ("signature", "file_digests")
        }
        manifest.update(
            {
                "schema": AUTHORITY_SCHEMA,
                "package_version": "1.3",
                "apr_identifier": f"AUTH-{AGENT_ID}",
                "agent_id": AGENT_ID,
                "tenant_id": self.tenant_id,
                "window_start": "2026-06-01T00:00:00.000000+00:00",
                "window_end": "2026-10-16T00:00:00.000000+00:00",
                "event_count": len(timeline),
                "root_hash": merkle_root(event_hashes),
                "merkle_depth": merkle_depth(len(event_hashes)),
                "provenance_count": len(entries),
                "provenance_head": entries[-1]["entry_hash"] if entries else None,
                "assessment_count": len(data_files["assessments.json"]["assessments"]),
                "file_digests": {
                    name: "sha256:" + _sha256_hex(_dump(data_files[name]))
                    for name in AUTHORITY_DIGESTED_FILES
                    if name in data_files
                },
            }
        )
        manifest["signature"] = base64.b64encode(
            self.private_key.sign(canonical_package_manifest_bytes(manifest))
        ).decode("ascii")
        return {
            "manifest.json": manifest,
            **data_files,
            "signature.json": base["signature.json"],
            "verification_metadata.json": base["verification_metadata.json"],
        }

    def zip_bytes(self, components: dict[str, Any] | None = None) -> bytes:
        components = components if components is not None else self.components()
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
            for name, body in components.items():
                zf.writestr(f"authority-{AGENT_ID}/{name}", _dump(body))
        return buffer.getvalue()


@pytest.fixture
def authority_builder() -> AuthorityPackageBuilder:
    return AuthorityPackageBuilder()
