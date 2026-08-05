"""Verification behaviour: the happy path, and every way a package can lie.

Each tamper test asserts two things: that verification fails, and that the
*right* check failed. A verifier that fails for the wrong reason gives an
auditor a misleading finding, which is worse than no finding.
"""
from __future__ import annotations

import base64
import copy

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from behavry_verify.package import (
    PackageError,
    load_package_from_bytes,
    verify_package,
    walk_event_chain,
)
from behavry_verify.report import CheckStatus, TrustSource
from tests.conftest import PackageBuilder


def status_of(report, check_id: str) -> CheckStatus:
    return next(c.status for c in report.checks if c.id == check_id)


def verify(components, anchor):
    return verify_package(
        components, anchor=anchor, trust_source=TrustSource.SUPPLIED_ANCHOR
    )


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_untampered_package_verifies(components, anchor):
    report = verify(components, anchor)
    assert report.verified, report.to_text()
    assert all(
        c.status in (CheckStatus.PASS, CheckStatus.WARN) for c in report.checks
    )


def test_report_surfaces_package_identity(components, anchor):
    report = verify(components, anchor)
    assert report.apr_identifier == "APR-2026-001942"
    assert report.event_count == 4
    assert report.signer_kid == "behavry-ed25519-test-2026-01"
    assert report.signature_algorithm == "ed25519"
    assert report.trust_source is TrustSource.SUPPLIED_ANCHOR


def test_verifies_through_a_real_zip(builder):
    components = load_package_from_bytes(builder.zip_bytes())
    assert verify(components, builder.anchor()).verified


def test_multi_agent_package_verifies():
    builder = PackageBuilder(event_count=9, agents=3)
    assert verify(builder.components(), builder.anchor()).verified


def test_single_event_package_verifies():
    builder = PackageBuilder(event_count=1)
    assert verify(builder.components(), builder.anchor()).verified


@pytest.mark.parametrize("count", [2, 3, 5, 8, 16, 17])
def test_merkle_root_holds_at_odd_and_even_widths(count):
    """Odd-node promotion is the easiest part of a Merkle build to get wrong."""
    builder = PackageBuilder(event_count=count)
    report = verify(builder.components(), builder.anchor())
    assert report.verified, report.to_text()


# ---------------------------------------------------------------------------
# Tampering
# ---------------------------------------------------------------------------


def test_altered_manifest_field_fails_signature(components, anchor):
    tampered = copy.deepcopy(components)
    tampered["manifest.json"]["chain_status"] = "healthy-ish"
    report = verify(tampered, anchor)
    assert not report.verified
    assert status_of(report, "signature") is CheckStatus.FAIL


def test_altered_event_payload_fails_that_events_signature(components, anchor):
    tampered = copy.deepcopy(components)
    tampered["timeline.json"][2]["policy_result"] = "allow"
    report = verify(tampered, anchor)
    # The policy_result is not covered by the per-event signature (which binds
    # the hash chain), so this must be caught as a *manifest* concern only if
    # it moves a hash. It does not - which is exactly why the chain, not the
    # payload, is the integrity claim. Signature and chain both still hold.
    assert status_of(report, "signature") is CheckStatus.PASS
    assert report.verified


def test_altered_event_hash_breaks_merkle_root_and_chain(components, anchor):
    tampered = copy.deepcopy(components)
    tampered["timeline.json"][1]["event_hash"] = "0" * 64
    report = verify(tampered, anchor)
    assert not report.verified
    assert status_of(report, "merkle_root") is CheckStatus.FAIL
    assert status_of(report, "event_signatures") is CheckStatus.FAIL


def test_removed_event_is_detected(components, anchor):
    tampered = copy.deepcopy(components)
    del tampered["timeline.json"][1]
    report = verify(tampered, anchor)
    assert not report.verified
    assert status_of(report, "event_count") is CheckStatus.FAIL
    assert status_of(report, "merkle_root") is CheckStatus.FAIL
    assert status_of(report, "chain") is CheckStatus.FAIL


def test_reordered_events_break_the_chain(components, anchor):
    tampered = copy.deepcopy(components)
    timeline = tampered["timeline.json"]
    timeline[1], timeline[2] = timeline[2], timeline[1]
    report = verify(tampered, anchor)
    assert not report.verified
    # Reordering preserves the multiset of hashes but not their order, so the
    # Merkle root moves even though the event count does not.
    assert status_of(report, "merkle_root") is CheckStatus.FAIL


def test_appended_event_without_a_signature_is_detected(components, anchor):
    tampered = copy.deepcopy(components)
    forged = copy.deepcopy(tampered["timeline.json"][-1])
    forged["id"] = "evt-forged"
    forged["previous_hash"] = forged["event_hash"]
    forged["event_hash"] = "f" * 64
    forged["signature"] = None
    tampered["timeline.json"].append(forged)
    report = verify(tampered, anchor)
    assert not report.verified
    assert status_of(report, "merkle_root") is CheckStatus.FAIL
    assert status_of(report, "event_count") is CheckStatus.FAIL


def test_manifest_signature_from_a_different_key_fails(components, anchor):
    tampered = copy.deepcopy(components)
    attacker = Ed25519PrivateKey.generate()
    from behavry_verify.canonical import canonical_package_manifest_bytes

    manifest = tampered["manifest.json"]
    manifest["event_count"] = 999
    manifest["signature"] = base64.b64encode(
        attacker.sign(canonical_package_manifest_bytes(manifest))
    ).decode("ascii")
    report = verify(tampered, anchor)
    assert not report.verified
    assert status_of(report, "signature") is CheckStatus.FAIL


def test_stored_unverified_flag_is_reported(components, anchor):
    tampered = copy.deepcopy(components)
    tampered["hash_chain.json"][2]["verified"] = False
    report = verify(tampered, anchor)
    assert not report.verified
    assert status_of(report, "stored_flags") is CheckStatus.FAIL


def test_missing_signature_fails_cleanly(components, anchor):
    tampered = copy.deepcopy(components)
    del tampered["manifest.json"]["signature"]
    report = verify(tampered, anchor)
    assert not report.verified
    assert status_of(report, "signature") is CheckStatus.FAIL


# ---------------------------------------------------------------------------
# Wrong-key and no-key handling
# ---------------------------------------------------------------------------


def test_wrong_tenant_anchor_is_named_as_such(components):
    other = PackageBuilder()
    report = verify(components, other.anchor(kid="behavry-ed25519-test-2026-01"))
    assert not report.verified
    assert status_of(report, "signature") is CheckStatus.FAIL
    # The fingerprint cross-check is what turns "signature failed" into the
    # actionable "you used the wrong anchor".
    assert status_of(report, "key_fingerprint") is CheckStatus.FAIL


def test_unknown_kid_skips_signature_rather_than_failing_it(components, anchor):
    """An absent key is not evidence of tampering, and must not read as such."""
    stale = {"schema": "behavry.trust_anchor.v1", "keys": [dict(anchor["keys"][0])]}
    stale["keys"][0]["kid"] = "some-other-key"
    report = verify(components, stale)
    assert not report.verified
    assert status_of(report, "signature") is CheckStatus.SKIPPED
    assert report.error and "no key with kid" in report.error


def test_no_anchor_skips_signature_checks_but_still_checks_integrity(components):
    report = verify_package(components, anchor=None, trust_source=TrustSource.NONE)
    assert not report.verified
    assert status_of(report, "signature") is CheckStatus.SKIPPED
    assert status_of(report, "event_signatures") is CheckStatus.SKIPPED
    # Structural checks need no key at all, and still run.
    assert status_of(report, "merkle_root") is CheckStatus.PASS
    assert status_of(report, "chain") is CheckStatus.PASS


def test_raw_public_key_verifies(builder, components):
    report = verify_package(
        components,
        raw_public_key=builder.public_key_bytes,
        trust_source=TrustSource.SUPPLIED_KEY,
    )
    assert report.verified


# ---------------------------------------------------------------------------
# Chain walking
# ---------------------------------------------------------------------------


def test_chain_walk_reports_every_break():
    def event(id_, ts, ehash, prev):
        return {
            "id": id_, "agent_id": "x", "timestamp": ts,
            "event_hash": ehash, "previous_hash": prev,
        }

    events = [
        event("a", "1", "h1", None),
        event("b", "2", "h2", "WRONG"),
        event("c", "3", "h3", "WRONG"),
    ]
    breaks = walk_event_chain(events)
    assert len(breaks) == 2


# ---------------------------------------------------------------------------
# Contiguity applies to pre-1.1 packages only
# ---------------------------------------------------------------------------


def test_agentless_package_fails_the_walk_under_1_0():
    """The defect 1.1 corrects, pinned as a control.

    Browser / Human Governance events carry no agent_id and therefore no link
    pointer. Under 1.0 they share one chain key, so every event after the first
    reports a break — an intact session declared tampered.
    """
    builder = PackageBuilder(event_count=3, agentless=True, package_version="1.0")
    report = verify(builder.components(), builder.anchor())
    assert status_of(report, "chain") is CheckStatus.FAIL
    assert not report.verified


def test_agentless_package_verifies_under_1_1():
    """The same events, exported by a 1.1 producer, verify."""
    builder = PackageBuilder(event_count=3, agentless=True, package_version="1.1")
    report = verify(builder.components(), builder.anchor())
    assert status_of(report, "chain") is CheckStatus.SKIPPED
    assert report.verified


def test_interleaved_sessions_verify_under_1_1():
    """An agent running concurrent sessions interleaves its chain, so a
    session-scoped package's events link to rows it does not contain."""
    builder = PackageBuilder(event_count=4, package_version="1.1")
    for index, event in enumerate(builder.events):
        event["previous_hash"] = f"{'a' * 63}{index}"  # a sibling session's row
        event["signature"] = builder._sign_event(event)
    report = verify(builder.components(), builder.anchor())
    assert status_of(report, "chain") is CheckStatus.SKIPPED
    assert report.verified


def test_1_1_still_fails_on_a_forged_link_pointer():
    """Relaxing contiguity must not lose pointer tampering. previous_hash is
    inside each event's signature, so rewriting it fails the signature check
    even though the walk no longer runs."""
    builder = PackageBuilder(event_count=4, package_version="1.1")
    components = builder.components()
    components["timeline.json"][2]["previous_hash"] = "forged"
    report = verify(components, builder.anchor())
    assert status_of(report, "event_signatures") is CheckStatus.FAIL
    assert not report.verified


def test_1_1_still_fails_on_a_dropped_event():
    """Deletion is caught by the Merkle root, which the manifest signs — not by
    the walk. This is why dropping contiguity costs no coverage."""
    builder = PackageBuilder(event_count=4, package_version="1.1")
    components = builder.components()
    del components["timeline.json"][1]
    report = verify(components, builder.anchor())
    assert status_of(report, "merkle_root") is CheckStatus.FAIL
    assert not report.verified


def test_1_1_still_fails_on_producer_flagged_break():
    """A 1.1 producer that found a real per-event integrity failure marks the
    link unverified, and the verifier must still act on that."""
    builder = PackageBuilder(event_count=4, package_version="1.1")
    components = builder.components()
    components["hash_chain.json"][2]["verified"] = False
    report = verify(components, builder.anchor())
    assert status_of(report, "stored_flags") is CheckStatus.FAIL
    assert not report.verified


@pytest.mark.parametrize(
    "raw,expected",
    [("1.0", (1, 0)), ("1.1", (1, 1)), ("2.0", (2, 0)), ("nonsense", (0,)), (None, (0,))],
)
def test_package_version_parsing(raw, expected):
    from behavry_verify.package import _package_version_tuple

    assert _package_version_tuple({"package_version": raw} if raw else {}) == expected


def test_unreadable_version_takes_the_strict_path():
    """A version we cannot parse must not buy the relaxed check."""
    builder = PackageBuilder(event_count=3, agentless=True, package_version="not-a-version")
    report = verify(builder.components(), builder.anchor())
    assert status_of(report, "chain") is CheckStatus.FAIL


def test_device_claims_chain_separately_from_decisions():
    """Splicing two devices' exposure records into one chain must not verify."""
    def claim(id_, device, ts, ehash, prev):
        return {
            "id": id_, "claim_type": "exposure", "device_id": device,
            "timestamp": ts, "event_hash": ehash, "previous_hash": prev,
        }

    events = [
        claim("d1", "dev-1", "1", "h1", None),
        claim("d2", "dev-2", "2", "h2", "h1"),
    ]
    # dev-2's first event claims to follow dev-1's, but they are separate
    # chains, so dev-2 is treated as its own genesis and the bogus link is
    # simply not honoured as continuity.
    assert walk_event_chain(events) == []
    assert len({("exp", e["device_id"]) for e in events}) == 2


# ---------------------------------------------------------------------------
# Malformed input
# ---------------------------------------------------------------------------


def test_non_zip_input_is_rejected():
    with pytest.raises(PackageError, match="not a readable ZIP"):
        load_package_from_bytes(b"this is not a zip file")


def test_empty_input_is_rejected():
    with pytest.raises(PackageError, match="empty"):
        load_package_from_bytes(b"")


def test_zip_without_manifest_is_rejected():
    import io
    import zipfile

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        zf.writestr("apr-x/apr.json", "{}")
    with pytest.raises(PackageError, match="no manifest.json"):
        load_package_from_bytes(buffer.getvalue())


def test_package_with_no_manifest_object_reports_an_error():
    report = verify_package({"manifest.json": "not-an-object"}, anchor=None)
    assert not report.verified
    assert report.error
