"""Authority evidence package (package 1.3, Behavry Sprint AG-3): checks 12 to 14.

Each tamper test edits one thing and, where the edit would also be caught by
the file digests (check 8), re-seals the manifest with the Behavry key so the
new check is shown catching it on its own. A party holding the Behavry key can
re-sign a manifest; it still cannot rewrite history without breaking the
provenance chain's hashes and links, or forge Minotaur's signature.
"""
from __future__ import annotations

import copy
import io
import json
import zipfile
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from behavry_verify.authority import (
    AUTHORITY_PACKAGE_SCHEMA,
    bundle_digest,
    provenance_entry_hash,
)
from behavry_verify.cli import main
from behavry_verify.package import load_package_from_bytes, load_package_from_path, verify_package
from tests.conftest import AuthorityPackageBuilder


def _verify(builder: AuthorityPackageBuilder, components: dict[str, Any], *, observers=None):
    anchors = [builder.observer_anchor()] if observers is None else observers
    return verify_package(components, anchor=builder.anchor(), observer_anchors=anchors)


def _check(report, check_id: str):
    matches = [c for c in report.checks if c.id == check_id]
    assert matches, f"no {check_id} check in {[c.id for c in report.checks]}"
    return matches[0]


def _status(report, check_id: str) -> str:
    return _check(report, check_id).status.value


def _resealed(builder: AuthorityPackageBuilder, components: dict[str, Any]) -> dict[str, Any]:
    """Rebuild digests, counts and the manifest signature over edited data files."""
    data = {
        k: v
        for k, v in components.items()
        if k not in ("manifest.json", "signature.json", "verification_metadata.json")
    }
    base = builder.components()
    return builder.assemble(base, data)


@pytest.fixture
def full_observers(authority_builder: AuthorityPackageBuilder) -> list[dict[str, Any]]:
    return [authority_builder.observer_anchor(), authority_builder.minotaur_anchor()]


# ---------------------------------------------------------------------------
# The happy path
# ---------------------------------------------------------------------------


def test_authority_package_verifies(authority_builder, full_observers):
    report = _verify(authority_builder, authority_builder.components(), observers=full_observers)
    assert report.verified, report.to_text()
    for check_id in ("provenance", "assessments", "file_digests", "event_signatures"):
        assert _status(report, check_id) == "pass", report.to_text()
    assert _status(report, "lifecycle") == "info"
    assert report.package_schema == AUTHORITY_PACKAGE_SCHEMA


def test_authority_schema_draws_no_schema_warning(authority_builder, full_observers):
    report = _verify(authority_builder, authority_builder.components(), observers=full_observers)
    assert not [c for c in report.checks if c.id == "schema"]


def test_apr_schema_still_draws_no_warning_and_no_authority_checks(builder):
    report = verify_package(builder.components(), anchor=builder.anchor())
    ids = [c.id for c in report.checks]
    assert "schema" not in ids
    assert not {"provenance", "assessments", "lifecycle"} & set(ids)


def test_file_digests_cover_the_new_files(authority_builder, full_observers):
    report = _verify(authority_builder, authority_builder.components(), observers=full_observers)
    assert "9 files match" in _check(report, "file_digests").detail


def test_zip_with_authority_root_loads(authority_builder, full_observers):
    components = load_package_from_bytes(authority_builder.zip_bytes())
    report = verify_package(
        components, anchor=authority_builder.anchor(), observer_anchors=full_observers
    )
    assert report.verified, report.to_text()


def test_unpacked_authority_directory_loads(tmp_path, authority_builder, full_observers):
    with zipfile.ZipFile(io.BytesIO(authority_builder.zip_bytes())) as zf:
        zf.extractall(tmp_path)
    assert (tmp_path / "authority-agent-0" / "manifest.json").is_file()
    components = load_package_from_path(tmp_path)
    report = verify_package(
        components, anchor=authority_builder.anchor(), observer_anchors=full_observers
    )
    assert report.verified, report.to_text()


def test_agent_report_events_verify_under_the_agent_claim_form(authority_builder):
    """Authority timelines carry agent_report rows, signed over the agent-claim payload."""
    report = _verify(authority_builder, authority_builder.components())
    assert _status(report, "event_signatures") == "pass"
    assert "5 of 5" in _check(report, "event_signatures").detail


def test_lifecycle_reports_every_golden_path_element(authority_builder, full_observers):
    report = _verify(authority_builder, authority_builder.components(), observers=full_observers)
    assert report.lifecycle is not None
    assert all(report.lifecycle.values()), report.lifecycle
    assert report.to_dict()["lifecycle"]["revalidated_and_applied"] is True


def test_lifecycle_is_informational_on_a_short_history(authority_builder, full_observers):
    components = authority_builder.components()
    components["provenance.json"]["entries"] = components["provenance.json"]["entries"][:2]
    report = _verify(authority_builder, _resealed(authority_builder, components),
                     observers=full_observers)
    assert report.verified, report.to_text()
    assert report.lifecycle["mismatch_detected"] is False
    assert "not evidenced" in _check(report, "lifecycle").detail


# ---------------------------------------------------------------------------
# 13 without an observer anchor: never passed
# ---------------------------------------------------------------------------


def test_without_minotaur_anchor_bundles_are_not_independently_verified(authority_builder):
    report = _verify(authority_builder, authority_builder.components())
    check = _check(report, "assessments")
    assert check.status.value == "skipped"
    assert "not independently verified" in check.detail
    # The rest of the package still stands on the Behavry signature.
    assert report.verified


# ---------------------------------------------------------------------------
# Tampering: provenance (check 12)
# ---------------------------------------------------------------------------


def test_edited_provenance_summary_fails(authority_builder, full_observers):
    components = authority_builder.components()
    components["provenance.json"]["entries"][6]["summary"] = "secrets:read kept"
    report = _verify(authority_builder, _resealed(authority_builder, components),
                     observers=full_observers)
    assert not report.verified
    assert _status(report, "provenance") == "fail"
    assert "entry_hash" in _check(report, "provenance").detail


def test_edited_provenance_body_fails(authority_builder, full_observers):
    components = authority_builder.components()
    components["provenance.json"]["entries"][7]["body"]["to"] = 3
    report = _verify(authority_builder, _resealed(authority_builder, components),
                     observers=full_observers)
    assert _status(report, "provenance") == "fail"
    assert "body_digest" in _check(report, "provenance").detail


def test_dropped_provenance_entry_fails(authority_builder, full_observers):
    """Removing the mismatch entry breaks the link its successor carries."""
    components = authority_builder.components()
    del components["provenance.json"]["entries"][5]
    report = _verify(authority_builder, _resealed(authority_builder, components),
                     observers=full_observers)
    assert _status(report, "provenance") == "fail"
    assert "links to" in _check(report, "provenance").detail


def test_dropped_last_entry_fails_against_the_original_manifest(authority_builder, full_observers):
    """Truncating the tail keeps every link intact; the signed head catches it."""
    components = authority_builder.components()
    components["provenance.json"]["entries"].pop()
    report = _verify(authority_builder, components, observers=full_observers)
    assert _status(report, "provenance") == "fail"
    assert "provenance_head" in _check(report, "provenance").detail


def test_reordered_provenance_entries_fail(authority_builder, full_observers):
    components = authority_builder.components()
    entries = components["provenance.json"]["entries"]
    entries[3], entries[4] = entries[4], entries[3]
    report = _verify(authority_builder, _resealed(authority_builder, components),
                     observers=full_observers)
    assert _status(report, "provenance") == "fail"


def test_rehashed_entry_without_the_key_fails_on_signature(authority_builder, full_observers):
    """Recomputing the hash after an edit does not help without Behavry's key."""
    components = authority_builder.components()
    entries = components["provenance.json"]["entries"]
    entries[-1]["summary"] = "Verified Authority NOT re-applied"
    authority_builder.seal_entry(entries[-1], key=Ed25519PrivateKey.generate())
    report = _verify(authority_builder, _resealed(authority_builder, components),
                     observers=full_observers)
    assert _status(report, "provenance") == "fail"
    assert "signature failed" in _check(report, "provenance").detail


def test_provenance_count_mismatch_fails(authority_builder, full_observers):
    components = authority_builder.components()
    manifest = components["manifest.json"]
    manifest["provenance_count"] = 12
    report = _verify(authority_builder, components, observers=full_observers)
    # The manifest signature catches it, and check 12 names it.
    assert _status(report, "signature") == "fail"
    assert "states 12" in _check(report, "provenance").detail


def test_entry_from_another_agent_fails(authority_builder, full_observers):
    components = authority_builder.components()
    entry = components["provenance.json"]["entries"][1]
    entry["agent_id"] = "agent-other"
    authority_builder.seal_entry(entry)
    report = _verify(authority_builder, _resealed(authority_builder, components),
                     observers=full_observers)
    assert _status(report, "provenance") == "fail"
    assert "belongs to agent" in _check(report, "provenance").detail


def test_missing_provenance_file_fails_for_the_authority_schema(authority_builder):
    components = authority_builder.components()
    del components["provenance.json"]
    report = _verify(authority_builder, components)
    assert _status(report, "provenance") == "fail"


def test_redacted_body_is_bound_by_digest_only(authority_builder, full_observers):
    components = authority_builder.components()
    components["provenance.json"]["entries"][0]["body"] = None
    report = _verify(authority_builder, _resealed(authority_builder, components),
                     observers=full_observers)
    assert _status(report, "provenance") == "pass", report.to_text()
    assert "redacted" in _check(report, "provenance").detail


def test_entry_hash_matches_a_hand_rebuilt_body(authority_builder):
    entry = authority_builder.entries[0]
    assert "." not in entry["timestamp"]  # zero microseconds omitted, as exported
    assert provenance_entry_hash(entry) == entry["entry_hash"]


# ---------------------------------------------------------------------------
# Tampering: assessments (check 13)
# ---------------------------------------------------------------------------


def test_edited_bundle_field_fails(authority_builder, full_observers):
    components = authority_builder.components()
    bundle = components["assessments.json"]["assessments"][1]["envelope"]["bundle"]
    bundle["capabilities"][0]["result"] = "VERIFIED"
    report = _verify(authority_builder, _resealed(authority_builder, components),
                     observers=full_observers)
    assert _status(report, "assessments") == "fail"
    assert "bundle_digest" in _check(report, "assessments").detail


def test_edited_bundle_with_recomputed_digest_fails_on_signature(authority_builder,
                                                                  full_observers):
    components = authority_builder.components()
    envelope = components["assessments.json"]["assessments"][1]["envelope"]
    envelope["bundle"]["capabilities"][0]["result"] = "VERIFIED"
    envelope["bundle_digest"] = bundle_digest(envelope["bundle"])
    report = _verify(authority_builder, _resealed(authority_builder, components),
                     observers=full_observers)
    detail = _check(report, "assessments").detail
    assert _status(report, "assessments") == "fail"
    assert "observer signature failed" in detail
    # And the provenance entry still names the original digest.
    assert "not in assessments.json" in detail


def test_swapped_observer_key_fails(authority_builder):
    impostor = dict(authority_builder.minotaur_anchor())
    impostor["public_key_hex"] = Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()
    report = _verify(
        authority_builder,
        authority_builder.components(),
        observers=[authority_builder.observer_anchor(), impostor],
    )
    assert _status(report, "assessments") == "fail"
    assert "observer signature failed" in _check(report, "assessments").detail


def test_observer_identity_mismatch_fails(authority_builder):
    wrong = dict(authority_builder.minotaur_anchor())
    wrong["observer_id"] = "minotaur-lab-99"
    report = _verify(
        authority_builder,
        authority_builder.components(),
        observers=[authority_builder.observer_anchor(), wrong],
    )
    assert _status(report, "assessments") == "fail"
    assert "belongs to" in _check(report, "assessments").detail


def test_bundle_not_referenced_fails(authority_builder, full_observers):
    """An assessment entry naming a bundle the package does not carry."""
    components = authority_builder.components()
    del components["assessments.json"]["assessments"][0]
    report = _verify(authority_builder, _resealed(authority_builder, components),
                     observers=full_observers)
    assert _status(report, "assessments") == "fail"
    assert "not in assessments.json" in _check(report, "assessments").detail


def test_assessment_entry_without_a_bundle_digest_fails(authority_builder, full_observers):
    components = authority_builder.components()
    entry = components["provenance.json"]["entries"][2]
    entry["evidence_refs"] = [{"kind": "audit_event", "id": "evt-1"}]
    authority_builder.seal_entry(entry)
    # Re-link the successors so only check 13 has something to say.
    entries = components["provenance.json"]["entries"]
    for i in range(3, len(entries)):
        entries[i]["previous_hash"] = entries[i - 1]["entry_hash"]
        authority_builder.seal_entry(entries[i])
    report = _verify(authority_builder, _resealed(authority_builder, components),
                     observers=full_observers)
    assert _status(report, "provenance") == "pass", report.to_text()
    assert _status(report, "assessments") == "fail"
    assert "names no bundle_digest" in _check(report, "assessments").detail


def test_assessment_count_mismatch_fails(authority_builder, full_observers):
    components = authority_builder.components()
    components["assessments.json"]["assessments"].append(
        copy.deepcopy(components["assessments.json"]["assessments"][0])
    )
    report = _verify(authority_builder, components, observers=full_observers)
    assert "states 2" in _check(report, "assessments").detail


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def test_cli_verifies_an_authority_zip_with_minotaurs_key(tmp_path, authority_builder, capsys):
    package = tmp_path / "authority-agent-0.zip"
    package.write_bytes(authority_builder.zip_bytes())
    anchor = tmp_path / "anchor.json"
    anchor.write_text(json.dumps(authority_builder.anchor()))
    minotaur = tmp_path / "minotaur.json"
    minotaur.write_text(json.dumps(authority_builder.minotaur_anchor()))
    observer = tmp_path / "observer.json"
    observer.write_text(json.dumps(authority_builder.observer_anchor()))
    code = main(
        [
            "--package", str(package), "--trust-anchor", str(anchor),
            "--observer-anchor", str(minotaur), "--observer-anchor", str(observer),
        ]
    )
    out = capsys.readouterr().out
    assert code == 0, out
    assert "Assessment bundles valid" in out
    assert "Provenance chain valid" in out
