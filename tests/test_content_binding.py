"""Package 1.2 content binding: recompute, don't trust.

Before 1.2 the verifier took each event's ``event_hash`` as given and checked
only that those hashes were signed and rolled into the Merkle root. A package
whose events had their action, target, policy_result or tool_name rewritten
therefore still verified. These tests pin that it no longer does, and that the
right check names the right events.
"""
from __future__ import annotations

import copy
import io
import json
import zipfile

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from behavry_verify.package import load_package_from_bytes, verify_package
from behavry_verify.report import CheckStatus, TrustSource
from tests.conftest import PackageBuilder


def check(report, check_id: str):
    return next(c for c in report.checks if c.id == check_id)


def status_of(report, check_id: str) -> CheckStatus:
    return check(report, check_id).status


def verify(components, builder: PackageBuilder, *, observers=None):
    extra = {"observer_anchors": observers} if observers is not None else {}
    return verify_package(
        components,
        anchor=builder.anchor(),
        trust_source=TrustSource.SUPPLIED_ANCHOR,
        **extra,
    )


@pytest.fixture
def b12() -> PackageBuilder:
    return PackageBuilder(event_count=4, package_version="1.2")


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_genuine_1_2_package_verifies_with_every_new_check_passing(b12):
    report = verify(b12.components(), b12, observers=[b12.observer_anchor()])
    assert report.verified, report.to_text()
    for check_id in ("file_digests", "event_content", "authorization_records", "observations"):
        assert status_of(report, check_id) is CheckStatus.PASS, report.to_text()
    assert "4 decision event hash(es) recomputed" in check(report, "event_content").detail


def test_genuine_1_2_package_verifies_through_a_real_zip(b12):
    components = load_package_from_bytes(b12.zip_bytes())
    report = verify(components, b12, observers=[b12.observer_anchor()])
    assert report.verified, report.to_text()
    # Raw archive bytes were hashed, not a re-serialization.
    assert "re-serialized" not in check(report, "file_digests").detail


def test_multi_agent_1_2_package_verifies():
    builder = PackageBuilder(event_count=9, agents=3, package_version="1.2")
    report = verify(builder.components(), builder, observers=[builder.observer_anchor()])
    assert report.verified, report.to_text()


# ---------------------------------------------------------------------------
# (a) THE TAMPER PROBE
# ---------------------------------------------------------------------------


def test_tamper_probe_rewritten_decision_fails(b12):
    """Rewrite what an event says happened, keep its hash and signatures."""
    components = b12.components()
    event = components["timeline.json"][2]
    event["action"] = "tool_call_benign"
    event["target"] = "/tmp/harmless.txt"
    event["policy_result"] = "allow"
    event["tool_name"] = "list_dir"

    report = verify(components, b12)
    assert not report.verified
    content = check(report, "event_content")
    assert content.status is CheckStatus.FAIL
    assert "'evt-0002'" in content.detail
    # The signed hash itself is untouched, so these still hold: the point is
    # that they are no longer enough.
    assert status_of(report, "signature") is CheckStatus.PASS
    assert status_of(report, "event_signatures") is CheckStatus.PASS
    assert status_of(report, "merkle_root") is CheckStatus.PASS


def test_tamper_probe_stands_without_file_digests(b12):
    """Content recompute does not lean on the digests. A key holder who
    rewrites a decision and re-signs a manifest WITH fresh digests passes every
    signature and digest check, and is still caught by the recompute."""
    import base64
    import hashlib

    from behavry_verify.canonical import canonical_package_manifest_bytes

    components = b12.components()
    components["timeline.json"][2]["target"] = "/tmp/harmless.txt"
    manifest = components["manifest.json"]
    manifest["file_digests"]["timeline.json"] = "sha256:" + hashlib.sha256(
        json.dumps(components["timeline.json"], indent=2, sort_keys=True).encode()
    ).hexdigest()
    manifest["signature"] = base64.b64encode(
        b12.private_key.sign(canonical_package_manifest_bytes(manifest))
    ).decode("ascii")

    report = verify(components, b12)
    assert status_of(report, "signature") is CheckStatus.PASS
    assert status_of(report, "file_digests") is CheckStatus.PASS
    assert status_of(report, "event_content") is CheckStatus.FAIL
    assert not report.verified


@pytest.mark.parametrize(
    "field,value",
    [
        ("action", "tool_call_benign"),
        ("target", "/tmp/harmless.txt"),
        ("policy_result", "allow"),
        ("tool_name", "list_dir"),
        ("mcp_server", "other-server"),
        ("policy_id", "base.permissive"),
        ("timestamp", "2026-06-09T14:32:02.002001+00:00"),
        ("agent_id", "agent-9"),
        ("session_id", "sess-9999"),
        ("requester_verified", True),
        ("run_label", "run-99"),
        ("dlp_action", "logged"),
        ("dlp_findings", []),
        ("execution_status", "success"),
        ("authorization_hash", "0" * 64),
        ("args_digest", "0" * 64),
        ("hash_version", 7),
        ("hash_version", 6),
    ],
)
def test_each_single_field_edit_fails(b12, field, value):
    components = b12.components()
    assert components["timeline.json"][2].get(field) != value
    components["timeline.json"][2][field] = value
    report = verify(components, b12)
    assert not report.verified
    assert status_of(report, "event_content") is CheckStatus.FAIL
    assert "'evt-0002'" in check(report, "event_content").detail


def test_stripped_hashed_fields_fail_rather_than_skip(b12):
    """Removing the body from a 1.2 row must not downgrade it to 'not checkable'."""
    components = b12.components()
    del components["timeline.json"][1]["hash_version"]
    report = verify(components, b12)
    content = check(report, "event_content")
    assert content.status is CheckStatus.FAIL
    assert "no hash_version" in content.detail and "'evt-0001'" in content.detail


def test_flipping_claim_type_to_dodge_recompute_is_caught(b12):
    """agent_report rows are not recomputed, but the timeline is digested."""
    components = b12.components()
    event = components["timeline.json"][2]
    event["claim_type"] = "agent_report"
    event["policy_result"] = "allow"
    report = verify(components, b12)
    assert not report.verified
    assert status_of(report, "file_digests") is CheckStatus.FAIL
    assert "agent_report" in check(report, "event_content").detail


def test_future_hash_version_fails_with_upgrade_hint(b12):
    components = b12.components()
    components["timeline.json"][0]["hash_version"] = 9  # first version past v8
    report = verify(components, b12)
    content = check(report, "event_content")
    assert content.status is CheckStatus.FAIL
    assert "upgrade" in content.detail


# ---------------------------------------------------------------------------
# (b) File digests
# ---------------------------------------------------------------------------


def _rezip(data: bytes, mutate) -> bytes:
    src = zipfile.ZipFile(io.BytesIO(data))
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as dst:
        for info in src.infolist():
            dst.writestr(info.filename, mutate(info.filename, src.read(info)))
    return out.getvalue()


def test_edited_file_bytes_fail_file_digests(b12):
    """A whitespace-only edit changes no parsed value, yet breaks the digest."""

    def mutate(name: str, body: bytes) -> bytes:
        return body + b"\n" if name.endswith("/apr.json") else body

    components = load_package_from_bytes(_rezip(b12.zip_bytes(), mutate))
    report = verify(components, b12)
    digests = check(report, "file_digests")
    assert digests.status is CheckStatus.FAIL
    assert "apr.json digest differs" in digests.detail
    assert not report.verified


def test_edited_component_fails_file_digests(b12):
    components = b12.components()
    components["policy_decisions.json"][2]["policy_result"] = "allow"
    report = verify(components, b12)
    assert status_of(report, "file_digests") is CheckStatus.FAIL
    assert "policy_decisions.json" in check(report, "file_digests").detail


def test_missing_digested_file_fails(b12):
    components = b12.components()
    del components["observations.json"]
    report = verify(components, b12)
    assert status_of(report, "file_digests") is CheckStatus.FAIL
    assert "observations.json missing" in check(report, "file_digests").detail


def test_1_2_manifest_without_file_digests_fails():
    """A 1.2 manifest that drops file_digests is re-signed by the key holder
    or broken; either way the verifier must not quietly skip the check."""
    builder = PackageBuilder(event_count=3, package_version="1.2")
    components = builder.components()
    manifest = components["manifest.json"]
    del manifest["file_digests"]
    import base64

    from behavry_verify.canonical import canonical_package_manifest_bytes

    manifest["signature"] = base64.b64encode(
        builder.private_key.sign(canonical_package_manifest_bytes(manifest))
    ).decode("ascii")
    report = verify(components, builder)
    assert status_of(report, "signature") is CheckStatus.PASS
    assert status_of(report, "file_digests") is CheckStatus.FAIL


# ---------------------------------------------------------------------------
# (c) Authorization records
# ---------------------------------------------------------------------------


def test_edited_authorization_record_fails(b12):
    components = b12.components()
    components["authorization_records.json"][2]["policy_result"] = "allow"
    report = verify(components, b12)
    authz = check(report, "authorization_records")
    assert authz.status is CheckStatus.FAIL
    assert "'authz-0002' content does not reproduce record_hash" in authz.detail
    assert not report.verified


def test_authorization_record_signed_by_wrong_key_fails(b12):
    components = b12.components()
    record = components["authorization_records.json"][1]
    record["signature"] = b12.sign_authorization(record, Ed25519PrivateKey.generate())
    report = verify(components, b12)
    authz = check(report, "authorization_records")
    assert authz.status is CheckStatus.FAIL
    assert "'authz-0001' signature failed" in authz.detail


def test_authorization_signature_is_bound_to_the_claim_type(b12):
    """A decision-form signature over the record hash must not verify."""
    import base64

    from behavry_verify.canonical import canonical_signing_bytes

    components = b12.components()
    record = components["authorization_records.json"][0]
    record["signature"] = base64.b64encode(
        b12.private_key.sign(
            canonical_signing_bytes(
                event_hash=record["record_hash"],
                previous_hash=record["previous_hash"],
                timestamp=record["timestamp"],
                tenant_id=record["tenant_id"],
            )
        )
    ).decode("ascii")
    report = verify(components, b12)
    assert status_of(report, "authorization_records") is CheckStatus.FAIL


def test_decision_authorization_hash_mismatch_fails(b12):
    """Re-point a decision at another genuine record: hash binding must fail.

    The edit also breaks the decision's own content hash; both are reported.
    """
    components = b12.components()
    event = components["timeline.json"][3]
    event["authorization_hash"] = components["authorization_records.json"][0]["record_hash"]
    report = verify(components, b12)
    authz = check(report, "authorization_records")
    assert authz.status is CheckStatus.FAIL
    assert "event 'evt-0003' authorization_hash does not match" in authz.detail
    assert status_of(report, "event_content") is CheckStatus.FAIL


def test_missing_referenced_authorization_record_fails(b12):
    components = b12.components()
    del components["authorization_records.json"][1]
    report = verify(components, b12)
    authz = check(report, "authorization_records")
    assert authz.status is CheckStatus.FAIL
    assert "'authz-0001', which is not in the package" in authz.detail


def test_authorization_signatures_skip_without_a_key(b12):
    report = verify_package(b12.components(), trust_source=TrustSource.NONE)
    assert status_of(report, "authorization_records") is CheckStatus.SKIPPED


def test_authorization_records_verify_with_raw_public_key(b12):
    report = verify_package(
        b12.components(),
        raw_public_key=b12.public_key_bytes,
        trust_source=TrustSource.SUPPLIED_KEY,
    )
    assert status_of(report, "authorization_records") is CheckStatus.PASS
    assert report.verified


# ---------------------------------------------------------------------------
# (d) Observations
# ---------------------------------------------------------------------------


def test_valid_observations_pass_and_are_summarized(b12):
    report = verify(b12.components(), b12, observers=[b12.observer_anchor()])
    assert status_of(report, "observations") is CheckStatus.PASS
    assert report.observation_summary == {
        "match": 1, "mismatch": 0, "absent": 0, "unobservable": 1,
    }
    assert "Observer verdicts" in report.to_text()


def test_missing_observer_anchor_is_skipped_never_passed(b12):
    report = verify(b12.components(), b12)
    obs = check(report, "observations")
    assert obs.status is CheckStatus.SKIPPED
    assert "observer key not supplied — cannot verify independently" in obs.detail
    # A skipped observation check does not, by itself, sink the package.
    assert report.verified


def test_wrong_observer_key_fails(b12):
    impostor = dict(b12.observer_anchor())
    impostor["public_key_hex"] = (
        Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()
    )
    report = verify(b12.components(), b12, observers=[impostor])
    obs = check(report, "observations")
    assert obs.status is CheckStatus.FAIL
    assert "observer signature failed" in obs.detail
    assert not report.verified


def test_observation_signed_by_another_key_fails(b12):
    components = b12.components()
    observation = components["observations.json"][0]
    b12.sign_observation(observation, b12.events[0], Ed25519PrivateKey.generate())
    report = verify(components, b12, observers=[b12.observer_anchor()])
    assert status_of(report, "observations") is CheckStatus.FAIL


def test_observation_repointed_at_another_decision_fails(b12):
    components = b12.components()
    components["observations.json"][0]["decision_event_id"] = "evt-0003"
    report = verify(components, b12, observers=[b12.observer_anchor()])
    assert status_of(report, "observations") is CheckStatus.FAIL


def test_observation_of_a_decision_not_in_the_timeline_fails(b12):
    components = b12.components()
    components["observations.json"][0]["decision_event_id"] = "evt-gone"
    report = verify(components, b12)
    obs = check(report, "observations")
    assert obs.status is CheckStatus.FAIL
    assert "not in the timeline" in obs.detail


def test_edited_match_status_fails(b12):
    components = b12.components()
    components["observations.json"][1]["match_status"] = "match"
    report = verify(components, b12, observers=[b12.observer_anchor()])
    assert status_of(report, "observations") is CheckStatus.FAIL


def test_observer_identity_must_match_its_key(b12):
    anchor = dict(b12.observer_anchor())
    anchor["observer_id"] = "someone-else"
    report = verify(b12.components(), b12, observers=[anchor])
    obs = check(report, "observations")
    assert obs.status is CheckStatus.FAIL
    assert "belongs to" in obs.detail


# ---------------------------------------------------------------------------
# (e) Backward compatibility
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("version", ["1.0", "1.1"])
def test_legacy_package_verifies_with_new_checks_skipped(version):
    builder = PackageBuilder(event_count=4, package_version=version)
    components = builder.components()
    assert "hash_version" not in components["timeline.json"][0]
    report = verify(components, builder)
    assert report.verified, report.to_text()
    for check_id in ("file_digests", "event_content", "authorization_records", "observations"):
        assert status_of(report, check_id) is CheckStatus.SKIPPED
    assert "NOT bound" in check(report, "event_content").detail
    assert "NOT covered" in check(report, "file_digests").detail


def test_legacy_package_carrying_bodies_is_still_recomputed():
    """A pre-1.2 package whose rows DO carry hash_version gets checked anyway."""
    builder = PackageBuilder(event_count=3, package_version="1.1")
    components = builder.components()
    components["timeline.json"] = copy.deepcopy(builder.events)
    assert status_of(verify(components, builder), "event_content") is CheckStatus.PASS
    components["timeline.json"][1]["target"] = "/tmp/other"
    assert status_of(verify(components, builder), "event_content") is CheckStatus.FAIL


def test_report_serializes_observation_summary(b12):
    report = verify(b12.components(), b12, observers=[b12.observer_anchor()])
    body = json.loads(json.dumps(report.to_dict()))
    assert body["observation_summary"]["match"] == 1
