"""Witness receipts (Behavry Sprint AG-10): check 16 and the standalone record check.

Receipts come from :mod:`tests.rekor_fixture`, a fixture log that builds
leaves, RFC 6962 trees, signed-note checkpoints and SignedEntryTimestamps in
the byte formats of Rekor v1.5.5 (AG10-CONTRACTS sections 1 to 4).
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
from datetime import datetime, timedelta
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from behavry_verify.audit_anchor import verify_audit_anchor
from behavry_verify.cli import main
from behavry_verify.package import load_package_from_bytes, verify_package
from behavry_verify.report import TrustSource
from behavry_verify.rfc3161 import load_pem_certificates
from behavry_verify.witness import (
    NO_TRUST_NOTE,
    WitnessOptions,
    WitnessTrustError,
    load_witness_trust,
    parse_signed_note,
    verify_inclusion_proof,
)
from tests.conftest import (
    OMIT,
    PredecessorAuthorityPackageBuilder,
    WitnessedAuthorityPackageBuilder,
    header_only,
)
from tests.rekor_fixture import FixtureLog, leaf_hash, mth, path

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _trust(builder) -> Any:
    return load_witness_trust(json.dumps(builder.log.trusted_root()).encode())


def _options(builder, *, trust: bool = True, require: bool = False, window: int = 7200):
    return WitnessOptions(
        trust=_trust(builder) if trust else None, require=require, window=window
    )


def _verify(builder, components=None, *, heads=None, witness: Any = "default"):
    if witness == "default":
        witness = _options(builder)
    return verify_package(
        components if components is not None else builder.components(),
        anchor=builder.anchor(),
        trust_source=TrustSource.SUPPLIED_ANCHOR,
        observer_anchors=[builder.observer_anchor(), builder.minotaur_anchor()],
        tsa_roots=load_pem_certificates(builder.tsa.roots_pem),
        anchor_heads=heads,
        witness=witness,
    )


def _check(report, check_id: str = "witness"):
    matches = [c for c in report.checks if c.id == check_id]
    assert matches, f"no {check_id} check in {[c.id for c in report.checks]}"
    return matches[0]


def _row(report, role: str = "anchor", index: int | None = 1) -> dict[str, Any]:
    return next(
        r for r in report.witness["records"] if r["role"] == role and r["index"] == index
    )


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _tampered(builder, mutate, index: int = 1):
    """Verify after ``mutate(receipt)`` on run anchor ``index``; return its row."""
    mutate(builder.anchors[index]["witness"])
    report = _verify(builder)
    return report, _row(report, index=index)


# ---------------------------------------------------------------------------
# The happy path
# ---------------------------------------------------------------------------


def test_valid_1_7_package_passes(witnessed_builder):
    components = witnessed_builder.components()
    manifest = components["manifest.json"]
    assert manifest["package_version"] == "1.7"
    assert manifest["witness_since"] == witnessed_builder.anchors[0]["period_start"]
    report = _verify(witnessed_builder, components)
    assert report.verified, report.to_text()
    assert _check(report).status.value == "pass"
    assert _check(report, "provenance_anchoring").status.value == "pass"
    wi = report.witness
    assert wi["verified"] == 5 and wi["failed"] == 0 and wi["missing"] == 0
    assert wi["witness_since"] == witnessed_builder.anchors[0]["period_start"]
    assert wi["window_seconds"] == 7200 and wi["required"] is False
    row = _row(report, index=0)
    receipt = witnessed_builder.anchors[0]["witness"]
    assert row["status"] == "verified" and row["required"] is True
    assert row["log_index"] == receipt["log_index"]
    assert row["integrated_time"] == receipt["integrated_time"]
    assert row["failed_checks"] == [] and row["findings"] == []
    pred = _row(report, "predecessor", None)
    assert pred["status"] == "verified" and pred["required"] is False
    assert "5 witness receipt(s) verified" in _check(report).detail


def test_1_7_report_json_and_text(witnessed_builder):
    report = _verify(witnessed_builder)
    body = json.loads(json.dumps(report.to_dict()))
    wi = body["witness"]
    assert set(wi) == {
        "trust", "trust_note", "required", "window_seconds", "verified", "failed",
        "not_checked", "missing", "absent", "records", "witness_since",
    }
    assert wi["trust"]["source"] == "trusted_root"
    assert wi["trust"]["logs"][0]["log_id"] == witnessed_builder.log.log_id
    assert set(wi["records"][0]) >= {
        "role", "anchor_id", "log_index", "integrated_time", "status", "failed_checks",
    }
    text = report.to_text()
    assert "Witness" in text and "verified" in text
    assert f"log index {witnessed_builder.anchors[0]['witness']['log_index']}" in text
    assert "Witness since" in text


def test_zip_round_trip(witnessed_builder):
    components = load_package_from_bytes(witnessed_builder.zip_bytes())
    assert _verify(witnessed_builder, components).verified


def test_ed25519_log_key_variant():
    builder = WitnessedAuthorityPackageBuilder(log=FixtureLog(key_type="ed25519"))
    report = _verify(builder)
    assert report.verified, report.to_text()
    assert report.witness["trust"]["logs"][0]["algorithm"] == "ed25519"


@pytest.mark.parametrize("key_type", ["ecdsa", "ed25519"])
def test_pem_trust_root(key_type):
    builder = WitnessedAuthorityPackageBuilder(log=FixtureLog(key_type=key_type))
    trust = load_witness_trust(builder.log.pem())
    assert trust.source == "pem" and list(trust.keys) == [builder.log.log_id]
    report = _verify(builder, witness=WitnessOptions(trust=trust))
    assert report.verified, report.to_text()


# ---------------------------------------------------------------------------
# Tampering: each piece fails the right W check
# ---------------------------------------------------------------------------


def test_tampered_body_fails_w1(witnessed_builder):
    def mutate(receipt):
        leaf = json.loads(base64.b64decode(receipt["body"]))
        leaf["spec"]["signatures"][0]["signature"] = "AAAA" + leaf["spec"]["signatures"][0][
            "signature"
        ][4:]
        receipt["body"] = _b64(
            json.dumps(leaf, sort_keys=True, separators=(",", ":")).encode()
        )

    report, row = _tampered(witnessed_builder, mutate)
    assert not report.verified
    assert _check(report).status.value == "fail"
    assert "W1" in row["failed_checks"] and row["status"] == "failed"
    assert any("inclusion proof does not take the leaf" in f for f in row["findings"])


def test_tampered_proof_hash_fails_w1_only(witnessed_builder):
    def mutate(receipt):
        hashes = receipt["inclusion_proof"]["hashes"]
        hashes[0] = ("0" if hashes[0][0] != "0" else "1") + hashes[0][1:]

    report, row = _tampered(witnessed_builder, mutate)
    assert not report.verified
    assert row["failed_checks"] == ["W1"]


def test_tampered_root_hash_fails_w1_only(witnessed_builder):
    def mutate(receipt):
        receipt["inclusion_proof"]["root_hash"] = hashlib.sha256(b"other").hexdigest()

    report, row = _tampered(witnessed_builder, mutate)
    assert row["failed_checks"] == ["W1"]
    assert any("checkpoint commits to root" in f for f in row["findings"])


def test_tampered_checkpoint_signature_fails_w1_only(witnessed_builder):
    def mutate(receipt):
        note = receipt["inclusion_proof"]["checkpoint"]
        text, sigline = note.rsplit("\n\n", 1)
        dash, name, b64 = sigline.rstrip("\n").split(" ")
        raw = bytearray(base64.b64decode(b64))
        raw[-1] ^= 0x01
        receipt["inclusion_proof"]["checkpoint"] = f"{text}\n\n{dash} {name} {_b64(bytes(raw))}\n"

    report, row = _tampered(witnessed_builder, mutate)
    assert row["failed_checks"] == ["W1"]
    assert any("checkpoint signature does not verify" in f for f in row["findings"])


def test_checkpoint_for_another_tree_size_fails_w1(witnessed_builder):
    def mutate(receipt):
        proof = receipt["inclusion_proof"]
        root = bytes.fromhex(proof["root_hash"])
        proof["checkpoint"] = witnessed_builder.log.checkpoint(proof["tree_size"] + 1, root)

    report, row = _tampered(witnessed_builder, mutate)
    assert row["failed_checks"] == ["W1"]
    assert any("checkpoint is for tree size" in f for f in row["findings"])


def test_checkpoint_signed_by_another_key_fails_w1(witnessed_builder):
    other = FixtureLog()

    def mutate(receipt):
        proof = receipt["inclusion_proof"]
        proof["checkpoint"] = other.checkpoint(
            proof["tree_size"], bytes.fromhex(proof["root_hash"])
        )

    report, row = _tampered(witnessed_builder, mutate)
    assert row["failed_checks"] == ["W1"]
    assert any("key's hint" in f for f in row["findings"])


def test_tampered_set_fails_w3_only(witnessed_builder):
    def mutate(receipt):
        raw = bytearray(base64.b64decode(receipt["signed_entry_timestamp"]))
        raw[-1] ^= 0x01
        receipt["signed_entry_timestamp"] = _b64(bytes(raw))

    report, row = _tampered(witnessed_builder, mutate)
    assert row["failed_checks"] == ["W3"]
    assert any("SignedEntryTimestamp does not verify" in f for f in row["findings"])


def test_edited_integrated_time_breaks_the_set(witnessed_builder):
    def mutate(receipt):
        receipt["integrated_time"] -= 30

    report, row = _tampered(witnessed_builder, mutate)
    assert row["failed_checks"] == ["W3"]


def test_tampered_envelope_fails_w2_only(witnessed_builder):
    def mutate(receipt):
        env = json.loads(receipt["envelope"])
        env["signatures"][0]["keyid"] = "another-kid"
        receipt["envelope"] = json.dumps(env, separators=(",", ":"), sort_keys=True)

    report, row = _tampered(witnessed_builder, mutate)
    assert row["failed_checks"] == ["W2"]
    assert any("envelopeHash" in f for f in row["findings"])


def test_tampered_payload_fails_w2_only(witnessed_builder):
    def mutate(receipt):
        env = json.loads(receipt["envelope"])
        env["payload"] = _b64(witnessed_builder.anchors[0]["anchor_digest"].encode())
        receipt["envelope"] = json.dumps(env, separators=(",", ":"), sort_keys=True)

    report, row = _tampered(witnessed_builder, mutate)
    assert row["failed_checks"] == ["W2"]
    assert any("payload is not this anchor's digest" in f for f in row["findings"])
    assert any("does not verify over its DSSE PAE" in f for f in row["findings"])


def test_entry_logged_by_another_key_fails_w2(witnessed_builder):
    record = witnessed_builder.anchors[1]
    record["witness"] = witnessed_builder.log.log_anchor(
        record, Ed25519PrivateKey.generate(), witnessed_builder.kid
    )
    report = _verify(witnessed_builder)
    row = _row(report)
    assert not report.verified
    assert row["failed_checks"] == ["W2"]
    assert any("verifier is not the anchor's signer key" in f for f in row["findings"])


def test_receipt_for_another_anchor_fails_w2(witnessed_builder):
    witnessed_builder.anchors[1]["witness"] = copy.deepcopy(
        witnessed_builder.anchors[0]["witness"]
    )
    report = _verify(witnessed_builder)
    row = _row(report)
    assert row["failed_checks"] == ["W2"]
    assert any("entry is for another anchor" in f for f in row["findings"])


def test_logged_envelope_over_another_digest_fails_w2(witnessed_builder):
    """The key holder logs a DSSE over some other digest and attaches it."""
    record = witnessed_builder.anchors[1]
    fake = {**record, "anchor_digest": hashlib.sha256(b"forged").hexdigest()}
    record["witness"] = witnessed_builder.log.log_anchor(
        fake, witnessed_builder.private_key, witnessed_builder.kid
    )
    report = _verify(witnessed_builder)
    row = _row(report)
    assert row["failed_checks"] == ["W2"]


def test_log_not_in_trust_root_fails_w1(witnessed_builder):
    other = FixtureLog()
    trust = load_witness_trust(other.pem())
    report = _verify(witnessed_builder, witness=WitnessOptions(trust=trust))
    assert not report.verified
    row = _row(report)
    assert "W1" in row["failed_checks"]
    assert any("not a log in the supplied trust root" in f for f in row["findings"])


def test_unknown_log_kind_fails(witnessed_builder):
    report, row = _tampered(witnessed_builder, lambda r: r.update(log="rekor-v2"))
    assert row["status"] == "failed"
    assert any("rekor-v1" in f for f in row["findings"])


def test_non_object_receipt_fails(witnessed_builder):
    witnessed_builder.anchors[1]["witness"] = "not a receipt"
    report = _verify(witnessed_builder)
    assert _row(report)["status"] == "failed"
    assert not report.verified


# ---------------------------------------------------------------------------
# W3 Prompt: the window
# ---------------------------------------------------------------------------


def _end(record: dict[str, Any]) -> int:
    return int(datetime.fromisoformat(record["period_end"]).timestamp())


def test_late_integrated_time_fails_w3(witnessed_builder):
    record = witnessed_builder.anchors[1]
    witnessed_builder.witness(record, integrated_time=_end(record) + 7201)
    report = _verify(witnessed_builder)
    row = _row(report)
    assert not report.verified
    assert row["failed_checks"] == ["W3"]
    assert any("past the 7200 s window" in f for f in row["findings"])


def test_logged_exactly_at_the_window_passes(witnessed_builder):
    record = witnessed_builder.anchors[1]
    witnessed_builder.witness(record, integrated_time=_end(record) + 7200)
    assert _verify(witnessed_builder).verified


def test_window_flag_widens_and_narrows(witnessed_builder):
    record = witnessed_builder.anchors[1]
    witnessed_builder.witness(record, integrated_time=_end(record) + 9000)
    assert not _verify(witnessed_builder).verified
    report = _verify(witnessed_builder, witness=_options(witnessed_builder, window=9000))
    assert report.verified, report.to_text()
    assert report.witness["window_seconds"] == 9000
    narrow = _verify(witnessed_builder, witness=_options(witnessed_builder, window=30))
    # Every receipt is logged 60 s after its period: all fail W3 under a 30 s window.
    assert narrow.witness["failed"] == 5


def test_logged_before_the_period_ended_fails_w3(witnessed_builder):
    record = witnessed_builder.anchors[1]
    witnessed_builder.witness(record, integrated_time=_end(record) - 301)
    row = _row(_verify(witnessed_builder))
    assert row["failed_checks"] == ["W3"]
    witnessed_builder.witness(record, integrated_time=_end(record) - 300)
    assert _verify(witnessed_builder).verified


def test_log_key_not_yet_valid_fails_w3(witnessed_builder):
    root = witnessed_builder.log.trusted_root(valid_from="2030-01-01T00:00:00Z")
    trust = load_witness_trust(json.dumps(root).encode())
    report = _verify(witnessed_builder, witness=WitnessOptions(trust=trust))
    assert not report.verified
    assert "W3" in _row(report)["failed_checks"]


# ---------------------------------------------------------------------------
# W4 Required
# ---------------------------------------------------------------------------


def test_missing_receipt_after_witness_since_fails_w4(witnessed_builder):
    del witnessed_builder.anchors[2]["witness"]
    report = _verify(witnessed_builder)
    assert not report.verified
    row = _row(report, index=2)
    assert row["status"] == "missing" and row["failed_checks"] == ["W4"]
    assert "required for this record" in _check(report).detail
    assert "MISSING" in report.to_text()


def test_missing_receipt_fails_w4_even_without_a_trust_root(witnessed_builder):
    del witnessed_builder.anchors[2]["witness"]
    report = _verify(witnessed_builder, witness=_options(witnessed_builder, trust=False))
    assert not report.verified
    assert _check(report).status.value == "fail"


def test_anchor_before_witness_since_is_not_required(witnessed_builder):
    witnessed_builder.witness_since = witnessed_builder.anchors[2]["period_start"]
    del witnessed_builder.anchors[0]["witness"]
    del witnessed_builder.anchors[1]["witness"]
    report = _verify(witnessed_builder)
    assert report.verified, report.to_text()
    assert _row(report, index=0)["status"] == "absent"
    assert _row(report, index=2)["required"] is True


def test_predecessor_after_witness_since_is_required(witnessed_builder):
    witnessed_builder.witness_since = witnessed_builder.predecessor["period_start"]
    del witnessed_builder.predecessor["witness"]
    report = _verify(witnessed_builder)
    assert not report.verified
    assert _row(report, "predecessor", None)["status"] == "missing"


def test_null_witness_since_requires_nothing():
    builder = WitnessedAuthorityPackageBuilder(witness_since=None)
    for record in [builder.predecessor, *builder.anchors]:
        del record["witness"]
    report = _verify(builder)
    assert report.verified, report.to_text()
    check = _check(report)
    assert check.status.value == "skipped"
    assert "witness_since is null" in check.detail
    assert report.witness["witness_since"] is None


def test_require_witness_overrides_the_manifest():
    builder = WitnessedAuthorityPackageBuilder(witness_since=None)
    del builder.anchors[2]["witness"]
    assert _verify(builder).verified
    report = _verify(builder, witness=_options(builder, require=True))
    assert not report.verified
    assert _row(report, index=2)["status"] == "missing"


def test_require_witness_applies_to_heads(witnessed_builder):
    later = witnessed_builder.seal_after()
    head = header_only(later[0])
    report = _verify(witnessed_builder, heads=[head])
    assert report.verified, report.to_text()
    assert _row(report, "head", 0)["status"] == "absent"
    required = _verify(
        witnessed_builder, heads=[head], witness=_options(witnessed_builder, require=True)
    )
    assert not required.verified
    assert _row(required, "head", 0)["status"] == "missing"
    witnessed_builder.witness(head)
    required = _verify(
        witnessed_builder, heads=[head], witness=_options(witnessed_builder, require=True)
    )
    assert required.verified, required.to_text()


def test_head_carrying_a_bad_receipt_fails(witnessed_builder):
    head = header_only(witnessed_builder.seal_after()[0])
    witnessed_builder.witness(head, integrated_time=_end(head) + 10_000)
    report = _verify(witnessed_builder, heads=[head])
    assert not report.verified
    assert _row(report, "head", 0)["failed_checks"] == ["W3"]
    assert "anchor head" in _check(report).detail


def test_manifest_without_witness_since_fails():
    builder = WitnessedAuthorityPackageBuilder(witness_since=OMIT)
    report = _verify(builder)
    assert not report.verified
    assert "states no witness_since" in _check(report).detail


def test_unreadable_witness_since_fails():
    builder = WitnessedAuthorityPackageBuilder(witness_since="last tuesday")
    report = _verify(builder)
    assert not report.verified
    assert "is not ISO 8601" in _check(report).detail


# ---------------------------------------------------------------------------
# No trust root
# ---------------------------------------------------------------------------


def test_no_trust_root_reports_not_checked(witnessed_builder):
    report = _verify(witnessed_builder, witness=_options(witnessed_builder, trust=False))
    assert report.verified, report.to_text()
    check = _check(report)
    assert check.status.value == "skipped" and NO_TRUST_NOTE in check.detail
    assert report.witness["not_checked"] == 5
    assert report.witness["trust_note"] == NO_TRUST_NOTE
    assert NO_TRUST_NOTE in report.to_text()


def test_no_witness_options_at_all_reports_not_checked(witnessed_builder):
    report = _verify(witnessed_builder, witness=None)
    assert report.verified
    assert NO_TRUST_NOTE in _check(report).detail


def test_no_trust_root_fails_under_require(witnessed_builder):
    report = _verify(
        witnessed_builder, witness=_options(witnessed_builder, trust=False, require=True)
    )
    assert not report.verified
    assert NO_TRUST_NOTE in _check(report).detail


# ---------------------------------------------------------------------------
# Package 1.6 and older keep their behaviour
# ---------------------------------------------------------------------------


def test_1_6_package_is_unchanged(predecessor_builder):
    components = predecessor_builder.components()
    log = FixtureLog()
    trust = load_witness_trust(log.pem())
    before = _verify(predecessor_builder, components, witness=None)
    after = _verify(predecessor_builder, components, witness=WitnessOptions(trust=trust))
    assert before.verified and after.verified
    assert [c.to_dict() for c in before.checks] == [c.to_dict() for c in after.checks]
    assert all(c.id != "witness" for c in after.checks)
    assert after.witness is None and "witness" not in after.to_dict()
    assert "Witness" not in after.to_text()


def test_1_6_package_under_require_fails(predecessor_builder):
    log = FixtureLog()
    report = _verify(
        predecessor_builder,
        witness=WitnessOptions(trust=load_witness_trust(log.pem()), require=True),
    )
    assert not report.verified
    assert "witness_since" not in report.witness
    assert report.witness["missing"] == 5


def test_1_6_anchor_carrying_a_receipt_is_checked():
    builder = PredecessorAuthorityPackageBuilder()
    log = FixtureLog()
    builder.anchors[0]["witness"] = log.log_anchor(builder.anchors[0], builder.private_key,
                                                   builder.kid)
    trust = load_witness_trust(log.pem())
    report = _verify(builder, witness=WitnessOptions(trust=trust))
    assert report.verified, report.to_text()
    assert _check(report).status.value == "pass"
    assert _row(report, index=0)["status"] == "verified"
    assert _row(report, index=1)["status"] == "absent"
    builder.anchors[0]["witness"]["integrated_time"] += 1
    assert not _verify(builder, witness=WitnessOptions(trust=trust)).verified


# ---------------------------------------------------------------------------
# A standalone anchor record (--audit-anchor)
# ---------------------------------------------------------------------------


def _verify_record(builder, record, witness):
    return verify_audit_anchor(
        record,
        anchor=builder.anchor(),
        trust_source=TrustSource.SUPPLIED_ANCHOR,
        tsa_roots=load_pem_certificates(builder.tsa.roots_pem),
        witness=witness,
    )


def test_standalone_record_with_a_receipt(witnessed_builder):
    record = witnessed_builder.anchors[0]
    report = _verify_record(witnessed_builder, record, _options(witnessed_builder))
    assert report.verified, report.to_text()
    assert _check(report).status.value == "pass"
    assert report.witness["records"][0]["status"] == "verified"
    record["witness"]["inclusion_proof"]["root_hash"] = "00" * 32
    report = _verify_record(witnessed_builder, record, _options(witnessed_builder))
    assert not report.verified


def test_standalone_record_without_a_receipt_is_unchanged(predecessor_builder):
    record = predecessor_builder.anchors[0]
    log = FixtureLog()
    before = verify_audit_anchor(
        record, anchor=predecessor_builder.anchor(), trust_source=TrustSource.SUPPLIED_ANCHOR
    )
    after = verify_audit_anchor(
        record,
        anchor=predecessor_builder.anchor(),
        trust_source=TrustSource.SUPPLIED_ANCHOR,
        witness=WitnessOptions(trust=load_witness_trust(log.pem())),
    )
    assert [c.to_dict() for c in before.checks] == [c.to_dict() for c in after.checks]
    required = verify_audit_anchor(
        record,
        anchor=predecessor_builder.anchor(),
        trust_source=TrustSource.SUPPLIED_ANCHOR,
        witness=WitnessOptions(trust=load_witness_trust(log.pem()), require=True),
    )
    assert not required.verified
    assert required.witness["records"][0]["status"] == "missing"


def test_standalone_record_without_a_trust_root(witnessed_builder):
    report = _verify_record(
        witnessed_builder, witnessed_builder.anchors[0], WitnessOptions()
    )
    assert report.verified
    assert NO_TRUST_NOTE in _check(report).detail


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _files(tmp_path, builder):
    package = tmp_path / "authority.zip"
    package.write_bytes(builder.zip_bytes())
    anchor = tmp_path / "anchor.json"
    anchor.write_text(json.dumps(builder.anchor()))
    roots = tmp_path / "tsa.pem"
    roots.write_bytes(builder.tsa.roots_pem)
    trust = tmp_path / "trusted_root.json"
    trust.write_text(json.dumps(builder.log.trusted_root()))
    return package, anchor, roots, trust


def test_cli_package_with_witness_trust(tmp_path, witnessed_builder, capsys):
    package, anchor, roots, trust = _files(tmp_path, witnessed_builder)
    base = ["--package", str(package), "--trust-anchor", str(anchor), "--tsa-roots", str(roots)]
    assert main([*base, "--witness-trust", str(trust), "--require-witness"]) == 0
    out = capsys.readouterr().out
    assert "Witness" in out and "verified" in out
    assert main([*base, "--witness-trust", str(trust), "--json"]) == 0
    body = json.loads(capsys.readouterr().out)
    assert body["witness"]["verified"] == 5
    assert main([*base, "--require-witness"]) == 1
    assert NO_TRUST_NOTE in capsys.readouterr().out
    assert main([*base, "--witness-trust", str(trust), "--witness-window", "30"]) == 1


def test_cli_rejects_a_bad_trust_root_and_window(tmp_path, witnessed_builder, capsys):
    package, anchor, _, _ = _files(tmp_path, witnessed_builder)
    bad = tmp_path / "bad.json"
    bad.write_text('{"tlogs": []}')
    base = ["--package", str(package), "--trust-anchor", str(anchor)]
    assert main([*base, "--witness-trust", str(bad)]) == 2
    assert "could not read witness trust root" in capsys.readouterr().err
    assert main([*base, "--witness-window", "-1"]) == 2


def test_cli_audit_anchor_with_witness(tmp_path, witnessed_builder, capsys):
    _, anchor, roots, trust = _files(tmp_path, witnessed_builder)
    record = tmp_path / "record.json"
    record.write_text(json.dumps(witnessed_builder.anchors[0]))
    args = ["--audit-anchor", str(record), "--trust-anchor", str(anchor), "--tsa-roots",
            str(roots)]
    assert main([*args, "--witness-trust", str(trust), "--json"]) == 0
    body = json.loads(capsys.readouterr().out)
    assert body["witness"]["records"][0]["log_index"] == (
        witnessed_builder.anchors[0]["witness"]["log_index"]
    )
    late = copy.deepcopy(witnessed_builder.anchors[0])
    late["witness"] = witnessed_builder.log.log_anchor(
        late, witnessed_builder.private_key, witnessed_builder.kid,
        integrated_time=_end(late) + 7201,
    )
    record.write_text(json.dumps(late))
    assert main([*args, "--witness-trust", str(trust)]) == 1
    assert "FAILED: W3" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# Units: RFC 6962 proofs, signed notes, trust roots
# ---------------------------------------------------------------------------


def test_inclusion_proofs_for_every_leaf_of_small_trees():
    for size in range(1, 18):
        leaves = [f"leaf-{i}".encode() for i in range(size)]
        root = mth(leaves)
        for index in range(size):
            proof = path(index, leaves)
            assert verify_inclusion_proof(index, size, leaf_hash(leaves[index]), proof, root)
            assert not verify_inclusion_proof(
                index, size, leaf_hash(b"other"), proof, root
            )
            if size > 1:
                assert not verify_inclusion_proof(
                    (index + 1) % size, size, leaf_hash(leaves[index]), proof, root
                ) or leaves[(index + 1) % size] == leaves[index]
                assert not verify_inclusion_proof(
                    index, size, leaf_hash(leaves[index]), [*proof, root], root
                )
                assert not verify_inclusion_proof(
                    index, size, leaf_hash(leaves[index]), proof[:-1], root
                )
        assert not verify_inclusion_proof(size, size, leaf_hash(leaves[0]), [], root)


def test_signed_note_parses_like_rekor():
    log = FixtureLog()
    root = mth([b"a", b"b", b"c"])
    note = parse_signed_note(log.checkpoint(3, root))
    assert note.origin.startswith("fixture-log.test - ")
    assert note.size == 3 and note.root_hash == root
    assert note.text.endswith(b"\n") and not note.text.endswith(b"\n\n")
    assert note.signatures[0][1] == hashlib.sha256(log.der).digest()[:4]
    for bad in ("no blank line\n", "o\n1\nAA==\n\n\u2014 n c2ln\n", "o\n1\nAA==\n\n- n AAAAAAA=\n",
                "o\n1x\nAA==\n\n\u2014 n AAAAAAA=\n", "o\n1\nAA==\n\n\u2014 n AAAAAAA="):
        with pytest.raises(ValueError):
            parse_signed_note(bad)


def test_one_verifying_signature_line_suffices(witnessed_builder):
    """C2SP signed notes: lines from keys the verifier does not know are ignored."""
    other = FixtureLog()

    def mutate(receipt):
        proof = receipt["inclusion_proof"]
        foreign = other.checkpoint(proof["tree_size"], bytes.fromhex(proof["root_hash"]))
        foreign_line = foreign.rsplit("\n\n", 1)[1]
        proof["checkpoint"] = proof["checkpoint"].replace(
            "\n\n", "\n\n" + foreign_line.replace("fixture-log.test", "other-witness"), 1
        )

    report, row = _tampered(witnessed_builder, mutate)
    assert row["status"] == "verified", row["findings"]


def test_trusted_root_checks_log_id_and_skips_unknown_key_types():
    log = FixtureLog()
    root = log.trusted_root()
    root["tlogs"][0]["logId"]["keyId"] = _b64(hashlib.sha256(b"x").digest())
    with pytest.raises(WitnessTrustError, match="logId.keyId"):
        load_witness_trust(json.dumps(root).encode())
    rsa_der = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key(
    ).public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    root = log.trusted_root()
    root["tlogs"].insert(
        0, {"publicKey": {"rawBytes": _b64(rsa_der), "keyDetails": "PKIX_RSA_PKCS1V15_2048_SHA256"}}
    )
    trust = load_witness_trust(json.dumps(root).encode())
    assert list(trust.keys) == [log.log_id]
    with pytest.raises(WitnessTrustError):
        load_witness_trust(b"-----BEGIN PUBLIC KEY-----\nnope\n-----END PUBLIC KEY-----\n")
    with pytest.raises(WitnessTrustError):
        load_witness_trust(b"not json")
    root = log.trusted_root()
    root["tlogs"][0]["publicKey"]["keyDetails"] = "PKIX_ED25519"
    with pytest.raises(WitnessTrustError, match="keyDetails"):
        load_witness_trust(json.dumps(root).encode())


def test_receipt_shape_matches_the_contract(witnessed_builder):
    """AG10-CONTRACTS section 3, and section 1 for the envelope."""
    receipt = witnessed_builder.anchors[0]["witness"]
    assert set(receipt) == {
        "log", "log_url", "entry_id", "log_id", "log_index", "integrated_time", "body",
        "signed_entry_timestamp", "inclusion_proof", "envelope",
    }
    assert set(receipt["inclusion_proof"]) == {
        "log_index", "tree_size", "root_hash", "hashes", "checkpoint",
    }
    env = json.loads(receipt["envelope"])
    assert base64.b64decode(env["payload"]) == (
        witnessed_builder.anchors[0]["anchor_digest"].encode()
    )
    leaf = json.loads(base64.b64decode(receipt["body"]))
    verifier = base64.b64decode(leaf["spec"]["signatures"][0]["verifier"])
    assert verifier.startswith(b"-----BEGIN PUBLIC KEY-----\n") and verifier.endswith(b"\n")
    assert receipt["log_index"] != receipt["inclusion_proof"]["log_index"]


def test_witness_window_default_matches_the_contract():
    assert WitnessOptions().window == 7200
    assert timedelta(seconds=WitnessOptions().window) == timedelta(hours=2)
