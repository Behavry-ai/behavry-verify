"""AG-11: trust anchor v2, key statements, ``--key-history`` and key windows.

The fixtures build a tenant's key history the way AG11-CONTRACTS sections 1 to
3 describe it: a deployment key, a first tenant key introduced from it by an
``infrastructure_migration`` succession, a rotation, and a compromise. The
package fixture is the ordinary ``PackageBuilder`` with each record re-signed
by whichever key was current at its signed timestamp.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
from datetime import datetime
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from behavry_verify.anchor import AnchorError, select_key_for_timestamp, validate_anchor
from behavry_verify.app import app
from behavry_verify.audit_anchor import verify_audit_anchor
from behavry_verify.canonical import canonical_signing_bytes
from behavry_verify.cli import EXIT_NOT_VERIFIED, EXIT_USAGE, EXIT_VERIFIED, main
from behavry_verify.keyhistory import (
    KeyCompromisedError,
    KeyWindowError,
    statement_signing_bytes,
    trust_anchor_with_history,
)
from behavry_verify.package import verify_package
from behavry_verify.report import CheckStatus, TrustSource
from behavry_verify.witness import signer_key_for
from tests.conftest import AnchoredAuthorityPackageBuilder, PackageBuilder

TENANT = "dae96c58-1b2c-4d3e-8f90-0a1b2c3d4e5f"

# The package's events are 14:32:00, :01.001, :02.002 and :03.003 on 9 June;
# each authorization record is 5 ms before its event; the manifest is 15:00.
MIGRATION_AT = "2026-06-01T00:00:00.000000+00:00"
ROTATION_AT = "2026-06-09T14:32:02.000000+00:00"
COMPROMISE_AT = "2026-06-09T14:50:00.000000+00:00"
COMPROMISED_SINCE = "2026-06-09T14:32:03.000000+00:00"


# ---------------------------------------------------------------------------
# Building keys, statements and anchors
# ---------------------------------------------------------------------------


class Key:
    def __init__(self, kid: str | None = None) -> None:
        self.private = Ed25519PrivateKey.generate()
        self.raw = self.private.public_key().public_bytes_raw()
        self.b64 = base64.b64encode(self.raw).decode("ascii")
        self.kid = kid or (
            "t-" + TENANT.replace("-", "")[:8] + "-ed25519-"
            + hashlib.sha256(self.raw).hexdigest()[:16]
        )

    def sign(self, data: bytes) -> str:
        return base64.b64encode(self.private.sign(data)).decode("ascii")

    def entry(self, **window: Any) -> dict[str, Any]:
        return {
            "kid": self.kid, "algorithm": "ed25519", "public_key": self.b64,
            "status": window.get("status", "active"),
            "not_before": window.get("not_before"),
            "not_after": window.get("not_after"),
            "compromised_since": window.get("compromised_since"),
        }


def statement(
    predecessor: Key,
    successor: Key,
    effective_at: str,
    signers: list[Key],
    *,
    kind: str = "succession",
    reason: str = "scheduled_rotation",
    compromised_since: str | None = None,
) -> dict[str, Any]:
    body = {
        "schema": "behavry.key_statement.v1",
        "type": kind,
        "tenant_id": TENANT,
        "predecessor_kid": predecessor.kid,
        "successor_kid": successor.kid,
        "successor_algorithm": "ed25519",
        "successor_public_key": successor.b64,
        "effective_at": effective_at,
        "reason": reason,
        "compromised_since": compromised_since,
        "issued_at": effective_at,
    }
    signed = statement_signing_bytes(body)
    body["signatures"] = [{"kid": k.kid, "sig": k.sign(signed)} for k in signers]
    return body


def anchor_v2(deployment: Key, keys: list[Key], statements: list[dict]) -> dict[str, Any]:
    return {
        "schema": "behavry.trust_anchor.v2",
        "tenant_id": TENANT,
        "exported_at": "2026-10-27T00:00:00+00:00",
        "deployment_kid": deployment.kid,
        # The listed windows are deliberately wrong: the verifier must rebuild
        # them from the statements and not trust these.
        "keys": [k.entry(not_before="2020-01-01T00:00:00+00:00") for k in keys],
        "statements": statements,
    }


def anchor_v1(key: Key) -> dict[str, Any]:
    return {
        "schema": "behavry.trust_anchor.v1",
        "keys": [{"kid": key.kid, "public_key": key.b64,
                  "not_before": "2026-10-01T00:00:00+00:00", "not_after": None}],
    }


class History:
    """Deployment key D, first tenant key K1 (migration), K2 (rotation)."""

    def __init__(self) -> None:
        self.d = Key("ed25519-8bc39d1abca0ff87")
        self.k1 = Key()
        self.k2 = Key()
        self.migration = statement(
            self.d, self.k1, MIGRATION_AT, [self.d, self.k1], reason="infrastructure_migration"
        )
        self.rotation = statement(self.k1, self.k2, ROTATION_AT, [self.k1, self.k2])

    def v2(self, *extra: dict, keys: list[Key] | None = None) -> dict[str, Any]:
        return anchor_v2(
            self.d, keys or [self.d, self.k1, self.k2], [self.migration, self.rotation, *extra]
        )

    def key_at(self, ts: str) -> Key:
        when = datetime.fromisoformat(ts)
        return self.k1 if when < datetime.fromisoformat(ROTATION_AT) else self.k2


def resign_event(event: dict[str, Any], key: Key) -> None:
    event["signer_kid"] = key.kid
    event["signature"] = key.sign(
        canonical_signing_bytes(
            event_hash=event.get("event_hash"),
            previous_hash=event.get("previous_hash"),
            timestamp=event.get("timestamp"),
            tenant_id=event.get("tenant_id"),
        )
    )


def resign_authorization(builder: PackageBuilder, record: dict[str, Any], key: Key) -> None:
    record["signer_kid"] = key.kid
    record["signature"] = builder.sign_authorization(record, key.private)


def rotated_package(
    history: History,
    *,
    signer_for: Any = None,
    manifest_key: Key | None = None,
) -> dict[str, Any]:
    """A 1.2 package whose records are signed across the K1 -> K2 rotation."""
    builder = PackageBuilder(package_version="1.2")
    pick = signer_for or (lambda index, ts: history.key_at(ts))
    for index, record in enumerate(builder.authorization_records):
        resign_authorization(builder, record, pick(index, record["timestamp"]))
    for index, event in enumerate(builder.events):
        resign_event(event, pick(index, event["timestamp"]))
    final = manifest_key or history.k2
    builder.private_key = final.private
    builder.kid = final.kid
    builder.public_key_b64 = final.b64
    return builder.components()


def status_of(report, check_id: str) -> CheckStatus:
    return next(c.status for c in report.checks if c.id == check_id)


def detail_of(report, check_id: str) -> str:
    return next(c.detail for c in report.checks if c.id == check_id)


def verify(components: dict[str, Any], anchor: dict[str, Any], history: Any = None):
    return verify_package(
        components,
        anchor=trust_anchor_with_history(anchor, history),
        trust_source=TrustSource.SUPPLIED_ANCHOR,
    )


@pytest.fixture
def history() -> History:
    return History()


# ---------------------------------------------------------------------------
# Rotation across both keys
# ---------------------------------------------------------------------------


def test_rotation_package_verifies_across_both_keys_with_a_v2_anchor(history):
    report = verify(rotated_package(history), history.v2())
    assert report.verified, [c.to_dict() for c in report.checks]
    assert status_of(report, "event_signatures") is CheckStatus.PASS
    assert status_of(report, "authorization_records") is CheckStatus.PASS
    kh = report.to_dict()["key_history"]
    assert kh["trust_mode"] == "v2"
    assert kh["statements_verified"] == 2 and kh["statement_count"] == 2
    assert kh["unreachable_keys"] == []
    windows = {k["kid"]: k for k in kh["keys"]}
    # Rebuilt from the statements, not the (wrong) listed not_before.
    assert windows[history.d.kid]["not_before"] is None
    assert windows[history.d.kid]["not_after"] == MIGRATION_AT
    assert windows[history.k1.kid]["not_before"] == MIGRATION_AT
    assert windows[history.k1.kid]["not_after"] == ROTATION_AT
    assert windows[history.k1.kid]["status"] == "retired"
    assert windows[history.k2.kid]["not_before"] == ROTATION_AT
    assert windows[history.k2.kid]["status"] == "active"
    assert "not_before" in windows[history.k1.kid]["listed_differs"]


def test_raw_v2_anchor_is_resolved_on_first_use(history):
    """A library caller passing the v2 document directly gets the same rules."""
    report = verify_package(rotated_package(history), anchor=history.v2())
    assert report.verified
    assert report.key_history["trust_mode"] == "v2"


def test_v1_pinned_plus_history_reaches_the_new_keys(history):
    report = verify(rotated_package(history), anchor_v1(history.d), history.v2())
    assert report.verified, [c.to_dict() for c in report.checks]
    kh = report.key_history
    assert kh["trust_mode"] == "v1+history"
    assert {k["kid"]: k["source"] for k in kh["keys"]} == {
        history.d.kid: "pinned", history.k1.kid: "history", history.k2.kid: "history",
    }


def test_v1_pinned_alone_cannot_verify_the_rotated_keys(history):
    report = verify(rotated_package(history), anchor_v1(history.d))
    assert not report.verified
    assert "no key with kid" in (report.error or "")
    assert report.key_history is None


def test_cli_key_history_flag(tmp_path, history, capsys):
    builder_components = rotated_package(history)
    package = tmp_path / "pkg"
    package.mkdir()
    for name, body in builder_components.items():
        (package / name).write_text(json.dumps(body, indent=2, sort_keys=True, default=str))
    pinned = tmp_path / "pinned.json"
    pinned.write_text(json.dumps(anchor_v1(history.d)))
    keys = tmp_path / "signing-keys.json"
    keys.write_text(json.dumps(history.v2()))

    args = ["--package", str(package), "--trust-anchor", str(pinned), "--key-history", str(keys)]
    assert main(args) == EXIT_VERIFIED
    out = capsys.readouterr().out
    assert "Key history" in out and "v1+history: 3 key(s) usable" in out
    assert f"#1 succession {history.k1.kid} -> {history.k2.kid}" in out

    assert main([*args, "--json"]) == EXIT_VERIFIED
    payload = json.loads(capsys.readouterr().out)
    assert payload["key_history"]["trust_mode"] == "v1+history"

    # The v2 file alone, as the trust anchor.
    assert main(["--package", str(package), "--trust-anchor", str(keys)]) == EXIT_VERIFIED
    capsys.readouterr()
    # Without the history: the pinned key does not reach the new keys.
    assert main(["--package", str(package), "--trust-anchor", str(pinned)]) == EXIT_NOT_VERIFIED
    capsys.readouterr()
    # --key-history needs a pinned v1 anchor.
    assert main(["--package", str(package), "--trust-anchor", str(keys),
                 "--key-history", str(keys)]) == EXIT_USAGE
    assert main(["--package", str(package), "--public-key", history.d.b64,
                 "--key-history", str(keys)]) == EXIT_USAGE


def test_api_accepts_a_key_history(history):
    builder = PackageBuilder(package_version="1.2")
    components = rotated_package(history)
    client = TestClient(app)
    files = {"package": ("apr.zip", builder.zip_bytes(components), "application/zip")}
    data = {
        "trust_anchor": json.dumps(anchor_v1(history.d)),
        "key_history": json.dumps(history.v2()),
    }
    body = client.post("/api/v1/verify", files=files, data=data).json()
    assert body["verified"] is True
    assert body["key_history"]["trust_mode"] == "v1+history"
    forged = history.v2()
    forged["statements"][1]["signatures"] = forged["statements"][1]["signatures"][1:]
    data["trust_anchor"] = json.dumps(forged)
    del data["key_history"]
    files = {"package": ("apr.zip", builder.zip_bytes(components), "application/zip")}
    assert client.post("/api/v1/verify", files=files, data=data).status_code == 400


# ---------------------------------------------------------------------------
# Forged statements
# ---------------------------------------------------------------------------


def test_v2_anchor_with_a_statement_missing_a_signature_is_refused(history):
    forged = history.v2()
    # Only the successor signed: the predecessor's signature is missing.
    forged["statements"][1]["signatures"] = [
        s for s in forged["statements"][1]["signatures"] if s["kid"] == history.k2.kid
    ]
    with pytest.raises(AnchorError, match="predecessor"):
        trust_anchor_with_history(forged)
    with pytest.raises(AnchorError, match="refused"):
        validate_anchor(copy.deepcopy(forged))


def test_v2_anchor_with_a_signature_by_the_wrong_key_is_refused(history):
    impostor = Key(history.k1.kid)  # same kid, different key
    forged = history.v2()
    body = {k: v for k, v in forged["statements"][1].items() if k != "signatures"}
    signed = statement_signing_bytes(body)
    forged["statements"][1]["signatures"] = [
        {"kid": history.k1.kid, "sig": impostor.sign(signed)},
        {"kid": history.k2.kid, "sig": history.k2.sign(signed)},
    ]
    with pytest.raises(AnchorError, match="predecessor"):
        trust_anchor_with_history(forged)


def test_altered_statement_is_refused(history):
    forged = history.v2()
    forged["statements"][1]["effective_at"] = "2026-06-09T14:00:00.000000+00:00"
    with pytest.raises(AnchorError, match="does not verify"):
        trust_anchor_with_history(forged)


def test_forged_history_key_is_unreachable_with_a_pinned_anchor(history):
    forged = history.v2()
    forged["statements"][1]["signatures"] = forged["statements"][1]["signatures"][1:]
    report = verify(rotated_package(history), anchor_v1(history.d), forged)
    assert not report.verified
    kh = report.key_history
    assert [s["verified"] for s in kh["statements"]] == [True, False]
    assert kh["unreachable_keys"][0]["kid"] == history.k2.kid
    assert "does not verify" in kh["unreachable_keys"][0]["reason"]
    assert history.k2.kid not in {k["kid"] for k in kh["keys"]}
    assert "unreachable" not in detail_of(report, "event_signatures")
    assert "not used" in detail_of(report, "event_signatures")


def test_successor_kid_must_be_derived_from_its_key(history):
    wrong = Key("t-dae96c58-ed25519-0000000000000000")
    bad = statement(history.k1, wrong, ROTATION_AT, [history.k1, wrong])
    with pytest.raises(AnchorError, match="not derived"):
        trust_anchor_with_history(
            anchor_v2(history.d, [history.d, history.k1, wrong], [history.migration, bad])
        )


def test_a_retired_key_cannot_introduce_a_second_successor(history):
    k3 = Key()
    fork = statement(history.k1, k3, "2026-06-10T00:00:00+00:00", [history.k1, k3])
    with pytest.raises(AnchorError, match="fork"):
        trust_anchor_with_history(history.v2(fork, keys=[history.d, history.k1, history.k2, k3]))


def test_unreachable_history_key_is_not_used(history):
    stray = Key()
    events_by_stray = {1}

    def pick(index, ts):
        return stray if index in events_by_stray else history.key_at(ts)

    keys = [history.d, history.k1, history.k2, stray]
    doc = anchor_v2(history.d, keys, [history.migration, history.rotation])
    report = verify(rotated_package(history, signer_for=pick), anchor_v1(history.d), doc)
    assert not report.verified
    kh = report.key_history
    assert kh["unreachable_keys"] == [
        {
            "kid": stray.kid,
            "reason": "no chain of verifying key statements reaches it from the pinned "
            "anchor, so it is not used",
        }
    ]
    assert f"no key with kid={stray.kid!r}" in detail_of(report, "event_signatures")
    # In a v2 anchor such a key is also listed as unreachable, never used.
    resolved = trust_anchor_with_history(doc)
    assert stray.kid not in {k["kid"] for k in resolved["keys"]}


# ---------------------------------------------------------------------------
# Windows
# ---------------------------------------------------------------------------


def test_new_key_signing_a_record_dated_before_the_rotation_fails(history):
    # Event 1 (14:32:01.001) is before the rotation, but signed by K2.
    def pick(index, ts):
        return history.k2 if index == 1 else history.key_at(ts)

    report = verify(rotated_package(history, signer_for=pick), history.v2())
    assert not report.verified
    assert status_of(report, "event_signatures") is CheckStatus.FAIL
    detail = detail_of(report, "event_signatures")
    assert "event #1" in detail and "before the key's window" in detail
    # The authorization record 1 was re-signed by K2 too, also before its window.
    assert "before the key's window" in detail_of(report, "authorization_records")
    assert report.key_history["window_failures"]
    assert report.key_history["untrusted_signatures"] == []


def test_old_key_signing_a_record_dated_after_the_rotation_fails(history):
    def pick(index, ts):
        return history.k1 if index == 3 else history.key_at(ts)

    report = verify(rotated_package(history, signer_for=pick), history.v2())
    assert not report.verified
    detail = detail_of(report, "event_signatures")
    assert "event #3" in detail and "after the key's window" in detail


def test_manifest_signed_by_the_retired_key_fails_the_signature_check(history):
    report = verify(rotated_package(history, manifest_key=history.k1), history.v2())
    assert not report.verified
    assert status_of(report, "signature") is CheckStatus.FAIL
    assert "after the key's window" in detail_of(report, "signature")


def test_compromise_earlier_signatures_pass_later_ones_are_untrusted(history):
    k3 = Key()
    compromise = statement(
        history.k2, k3, COMPROMISE_AT, [k3, history.d],
        kind="compromise", reason="suspected_compromise", compromised_since=COMPROMISED_SINCE,
    )
    doc = history.v2(compromise, keys=[history.d, history.k1, history.k2, k3])
    for anchor, extra in ((doc, None), (anchor_v1(history.d), doc)):
        report = verify(rotated_package(history, manifest_key=k3), anchor, extra)
        assert not report.verified
        # Event 3 (14:32:03.003) is after compromised_since; event 2 and every
        # authorization record are before it and still verify.
        detail = detail_of(report, "event_signatures")
        assert detail.startswith("event #3")
        assert "untrusted (key compromised)" in detail and "more)" not in detail
        assert status_of(report, "authorization_records") is CheckStatus.PASS
        # The manifest (15:00) is K3's, inside its window: only event 3 fails.
        assert status_of(report, "signature") is CheckStatus.PASS
        kh = report.key_history
        assert [r["kid"] for r in kh["untrusted_signatures"]] == [history.k2.kid]
        windows = {k["kid"]: k for k in kh["keys"]}
        assert windows[history.k2.kid]["status"] == "revoked"
        assert windows[history.k2.kid]["compromised_since"] == COMPROMISED_SINCE
        assert windows[k3.kid]["not_before"] == COMPROMISE_AT


def test_compromised_key_signing_the_manifest_is_reported_untrusted(history):
    k3 = Key()
    compromise = statement(
        history.k2, k3, COMPROMISE_AT, [k3, history.d],
        kind="compromise", reason="suspected_compromise", compromised_since=COMPROMISED_SINCE,
    )
    doc = history.v2(compromise, keys=[history.d, history.k1, history.k2, k3])
    report = verify(rotated_package(history), doc)
    assert status_of(report, "signature") is CheckStatus.FAIL
    assert detail_of(report, "signature").startswith("untrusted (key compromised)")
    assert "Key compromised" in report.to_text()


def test_compromise_statement_signed_by_the_compromised_key_is_refused(history):
    k3 = Key()
    compromise = statement(
        history.k2, k3, COMPROMISE_AT, [k3, history.k2],
        kind="compromise", reason="suspected_compromise", compromised_since=COMPROMISED_SINCE,
    )
    keys = [history.d, history.k1, history.k2, k3]
    with pytest.raises(AnchorError, match="deployment key"):
        trust_anchor_with_history(history.v2(compromise, keys=keys))
    # With a pinned anchor the successor is simply unreachable.
    resolved = trust_anchor_with_history(anchor_v1(history.d), history.v2(compromise, keys=keys))
    assert k3.kid not in {k["kid"] for k in resolved["keys"]}


def test_compromise_needs_the_deployment_key_pinned(history):
    """A pinned anchor without the deployment key cannot anchor a compromise."""
    k3 = Key()
    compromise = statement(
        history.k2, k3, COMPROMISE_AT, [k3, history.d],
        kind="compromise", reason="suspected_compromise", compromised_since=COMPROMISED_SINCE,
    )
    doc = history.v2(compromise, keys=[history.d, history.k1, history.k2, k3])
    resolved = trust_anchor_with_history(anchor_v1(history.k1), doc)
    kh = resolved["_key_history"]
    assert history.k2.kid in kh.keys  # reached from the pinned K1
    assert k3.kid not in kh.keys
    assert any("deployment key" in note for note in kh.notes)


def test_select_key_for_timestamp_enforces_windows(history):
    resolved = trust_anchor_with_history(history.v2())
    key, entry = select_key_for_timestamp(resolved, history.k1.kid, "2026-06-09T14:00:00Z")
    assert key == history.k1.raw and entry["not_after"] == ROTATION_AT
    with pytest.raises(KeyWindowError):
        select_key_for_timestamp(resolved, history.k1.kid, ROTATION_AT)  # not_after exclusive
    key, _ = select_key_for_timestamp(resolved, history.k2.kid, ROTATION_AT)  # inclusive
    assert key == history.k2.raw
    with pytest.raises(KeyWindowError, match="no readable signed timestamp"):
        select_key_for_timestamp(resolved, history.k2.kid, None)
    # Without a kid the window containing the timestamp picks the key.
    key, _ = select_key_for_timestamp(resolved, None, "2026-06-05T00:00:00Z")
    assert key == history.k1.raw
    # The deployment key's window ends at the migration for this tenant.
    with pytest.raises(KeyWindowError):
        select_key_for_timestamp(resolved, history.d.kid, "2026-06-05T00:00:00Z")
    key, _ = select_key_for_timestamp(resolved, history.d.kid, "2025-01-01T00:00:00Z")
    assert key == history.d.raw


def test_compromised_error_is_a_window_error(history):
    k3 = Key()
    compromise = statement(
        history.k2, k3, COMPROMISE_AT, [k3, history.d],
        kind="compromise", reason="suspected_compromise", compromised_since=COMPROMISED_SINCE,
    )
    resolved = trust_anchor_with_history(
        history.v2(compromise, keys=[history.d, history.k1, history.k2, k3])
    )
    with pytest.raises(KeyCompromisedError, match=r"^untrusted \(key compromised\)"):
        select_key_for_timestamp(resolved, history.k2.kid, "2026-06-09T15:00:00Z")
    select_key_for_timestamp(resolved, history.k2.kid, "2026-06-09T14:32:02.5Z")


# ---------------------------------------------------------------------------
# Audit anchors (sealed_at), provenance (timestamp) and the witness signer
# ---------------------------------------------------------------------------


@pytest.fixture
def sealed() -> AnchoredAuthorityPackageBuilder:
    return AnchoredAuthorityPackageBuilder()


def _builder_history(builder: AnchoredAuthorityPackageBuilder, migrate_at: str):
    """The builder's own key is the deployment key, migrated to K1 at ``migrate_at``."""
    d = Key(builder.kid)
    d.private, d.raw, d.b64 = builder.private_key, builder.public_key_bytes, builder.public_key_b64
    k1 = Key()
    migration = statement(d, k1, migrate_at, [d, k1], reason="infrastructure_migration")
    return d, anchor_v2(d, [d, k1], [migration])


def test_audit_anchor_sealed_inside_the_window_verifies(sealed):
    _, doc = _builder_history(sealed, "2026-10-15T12:00:00+00:00")
    report = verify_audit_anchor(sealed.anchors[0], anchor=trust_anchor_with_history(doc))
    assert status_of(report, "signature") is CheckStatus.PASS
    assert status_of(report, "provenance_signatures") is CheckStatus.PASS
    assert report.key_history["trust_mode"] == "v2"


def test_audit_anchor_sealed_after_its_key_was_succeeded_fails(sealed):
    # Anchor 0 covers 11:00-11:05 and is sealed at 11:05:04.
    _, doc = _builder_history(sealed, "2026-10-15T11:03:00+00:00")
    report = verify_audit_anchor(sealed.anchors[0], anchor=trust_anchor_with_history(doc))
    assert not report.verified
    assert status_of(report, "signature") is CheckStatus.FAIL
    assert "after the key's window" in detail_of(report, "signature")
    # Provenance entries dated after 11:03 fail too; earlier ones do not.
    assert status_of(report, "provenance_signatures") is CheckStatus.FAIL


def test_authority_package_provenance_entries_respect_windows(sealed):
    _, doc = _builder_history(sealed, "2026-10-15T11:03:00+00:00")
    report = verify_package(sealed.components(), anchor=trust_anchor_with_history(doc))
    assert not report.verified
    assert "after the key's window" in detail_of(report, "provenance")


def test_witness_resolves_the_anchor_signer_through_the_history(sealed):
    record = sealed.anchors[0]
    _, inside = _builder_history(sealed, "2026-10-15T12:00:00+00:00")
    assert signer_key_for(record, trust_anchor_with_history(inside), None) == (
        sealed.public_key_bytes
    )
    _, outside = _builder_history(sealed, "2026-10-15T11:03:00+00:00")
    assert signer_key_for(record, trust_anchor_with_history(outside), None) is None


# ---------------------------------------------------------------------------
# v1 on its own: unchanged
# ---------------------------------------------------------------------------


def test_v1_anchor_alone_enforces_no_window(builder, components):
    anchor = builder.anchor()
    # A listed window that excludes every record: ignored when the kid matches,
    # exactly as before AG-11.
    anchor["keys"][0]["not_before"] = "2030-01-01T00:00:00+00:00"
    assert trust_anchor_with_history(anchor) is anchor
    report = verify_package(components, anchor=anchor, trust_source=TrustSource.SUPPLIED_ANCHOR)
    assert report.verified
    assert report.key_history is None
    assert "key_history" not in report.to_dict()
    assert "Key history" not in report.to_text()


def test_injected_history_field_in_json_is_ignored(builder, components):
    anchor = builder.anchor()
    anchor["_key_history"] = {"keys": {}}
    report = verify_package(components, anchor=anchor)
    assert report.verified and report.key_history is None


def test_registry_serves_a_v2_file_whole(tmp_path, history):
    from behavry_verify.keyhistory import history_of
    from behavry_verify.registry import aggregate_anchor, anchor_for_kid

    (tmp_path / "tenant-v2.json").write_text(json.dumps(history.v2()))
    served = anchor_for_kid(history.k2.kid, str(tmp_path))
    assert served is not None and history_of(served).mode == "v2"
    report = verify_package(rotated_package(history), anchor=served)
    assert report.verified
    # Listed in the v1 aggregate, the keys would verify outside their windows.
    assert aggregate_anchor(str(tmp_path))["keys"] == []
