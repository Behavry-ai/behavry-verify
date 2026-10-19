"""Provenance anchored (Behavry Sprint AG-4 G-1): anchor schema v3 and check 15.

The anchors here are built in-test (``tests/conftest.py``), signed with the
package's Behavry test key and timestamped by a test TSA (``tests/tsa.py``),
following ``docs/strategy/AG4-CONTRACTS.md`` in the Behavry repo. The v1 and
v2 anchors stay pinned to Behavry's own output by ``anchor_vectors.json``.

The point of check 15 is the case a key holder can otherwise get away with:
rewrite a provenance entry, re-chain everything after it, re-sign the
manifest. Checks 8 and 12 then pass, because the same key signs all of them.
The anchor was timestamped by a third party before the rewrite, so the
rewritten entry is not in it.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
from datetime import datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient

from behavry_verify.app import app
from behavry_verify.audit_anchor import (
    ANCHOR_SCHEMA_V3,
    canonical_anchor_bytes,
    verify_anchor_chain,
    verify_audit_anchor,
)
from behavry_verify.cli import main
from behavry_verify.package import verify_package
from behavry_verify.report import TrustSource
from behavry_verify.rfc3161 import load_pem_certificates
from tests.conftest import AnchoredAuthorityPackageBuilder, provenance_record


def _status(report, check_id: str) -> str:
    matches = [c for c in report.checks if c.id == check_id]
    assert matches, f"no {check_id} check in {[c.id for c in report.checks]}"
    return matches[0].status.value


def _detail(report, check_id: str) -> str:
    return next(c for c in report.checks if c.id == check_id).detail


def _roots(builder: AnchoredAuthorityPackageBuilder):
    return load_pem_certificates(builder.tsa.roots_pem)


def _observers(builder) -> list[dict[str, Any]]:
    return [builder.observer_anchor(), builder.minotaur_anchor()]


def _verify(builder, components, *, roots=True, anchor="default"):
    return verify_package(
        components,
        anchor=builder.anchor() if anchor == "default" else anchor,
        trust_source=TrustSource.SUPPLIED_ANCHOR,
        observer_anchors=_observers(builder),
        tsa_roots=_roots(builder) if roots else None,
    )


def _data_files(components: dict[str, Any]) -> dict[str, Any]:
    return {
        k: v
        for k, v in components.items()
        if k not in ("manifest.json", "signature.json", "verification_metadata.json")
    }


def _resealed(builder, components: dict[str, Any]) -> dict[str, Any]:
    """What a Behavry key holder can do: re-sign the manifest over edited files."""
    return builder.assemble(builder.components(), _data_files(components))


def _rechain(builder, entries: list[dict[str, Any]], start: int) -> None:
    """Re-link and re-sign every entry from ``start`` on (also a key holder's power)."""
    for index in range(start, len(entries)):
        entries[index]["previous_hash"] = entries[index - 1]["entry_hash"] if index else None
        builder.seal_entry(entries[index])


def _verify_anchor(export, builder, *, roots=True):
    return verify_audit_anchor(
        export,
        anchor=builder.anchor(),
        trust_source=TrustSource.SUPPLIED_ANCHOR,
        tsa_roots=_roots(builder) if roots else None,
    )


# ---------------------------------------------------------------------------
# Anchor schema v3
# ---------------------------------------------------------------------------


def test_v3_canonical_bytes_reproduce_the_contract_digest(anchored_builder):
    for export in anchored_builder.anchors:
        assert export["schema"] == ANCHOR_SCHEMA_V3
        digest = hashlib.sha256(canonical_anchor_bytes(export)).hexdigest()
        assert digest == export["anchor_digest"]


def test_v3_canonical_bytes_carry_the_four_provenance_keys(anchored_builder):
    payload = json.loads(canonical_anchor_bytes(anchored_builder.anchors[0]))
    assert set(payload) == {
        "schema", "tenant_id", "period_start", "period_end", "event_count", "merkle_root",
        "first_event_hash", "last_event_hash", "previous_anchor_digest",
        "provenance_count", "provenance_root", "first_provenance_hash", "last_provenance_hash",
    }
    assert payload["first_event_hash"] == "" and payload["previous_anchor_digest"] == ""


def test_v3_empty_provenance_uses_the_empty_root(anchored_builder):
    start = datetime.fromisoformat("2026-10-15T09:00:00+00:00")
    export = anchored_builder.seal_anchor(start, start + timedelta(hours=1), [], None)
    assert export["provenance_count"] == 0
    assert export["provenance_root"] == "sha256:" + hashlib.sha256(b"").hexdigest()
    exported = dict(export, provenance_root=None)  # None and the empty root agree
    assert canonical_anchor_bytes(exported) == canonical_anchor_bytes(export)
    report = _verify_anchor(export, anchored_builder)
    assert report.verified, report.to_text()


def test_v3_anchor_verifies_end_to_end(anchored_builder):
    report = _verify_anchor(anchored_builder.anchors[0], anchored_builder)
    assert report.verified, report.to_text()
    for check_id in (
        "merkle_root", "event_count", "boundary_hashes", "anchor_digest", "signature",
        "provenance_root", "provenance_count", "provenance_boundary_hashes",
        "provenance_signatures", "tsa_imprint", "tsa_signature", "tsa_chain",
    ):
        assert _status(report, check_id) == "pass", (check_id, report.to_text())
    assert "schema" not in {c.id for c in report.checks}  # v3 is recognized
    assert report.anchor_summary["provenance_count"] == 5
    assert "Provenance root" in report.to_text()


def test_v3_records_carry_no_summary_or_body(anchored_builder):
    for record in anchored_builder.anchors[0]["provenance"]:
        assert "summary" not in record and "body" not in record


def test_v3_anchors_chain_like_v2(anchored_builder):
    ok, lines = verify_anchor_chain(anchored_builder.anchors)
    assert ok, lines
    assert any("1 linked" in line for line in lines), lines
    assert not any("pre-AUD-LINK" in line for line in lines), lines


def test_v3_chain_with_a_missing_period_is_reported(anchored_builder):
    start = datetime.fromisoformat("2026-10-15T11:08:00+00:00")
    third = anchored_builder.seal_anchor(
        start, start + timedelta(minutes=5), [], anchored_builder.anchors[1]["anchor_digest"]
    )
    ok, lines = verify_anchor_chain([anchored_builder.anchors[0], third])
    assert not ok
    assert any("MISSING PERIOD" in line for line in lines), lines


def test_v3_dropped_record_fails_the_root_and_count(anchored_builder):
    export = copy.deepcopy(anchored_builder.anchors[0])
    del export["provenance"][2]
    report = _verify_anchor(export, anchored_builder)
    assert not report.verified
    assert _status(report, "provenance_root") == "fail"
    assert _status(report, "provenance_count") == "fail"
    assert _status(report, "anchor_digest") == "pass"  # the sealed claim is intact


def test_v3_altered_provenance_root_fails_digest_and_signature(anchored_builder):
    export = copy.deepcopy(anchored_builder.anchors[0])
    export["provenance_root"] = "sha256:" + "0" * 64
    report = _verify_anchor(export, anchored_builder)
    assert not report.verified
    assert _status(report, "anchor_digest") == "fail"
    assert _status(report, "signature") == "fail"
    assert _status(report, "provenance_root") == "fail"


def test_v3_altered_boundary_hash_fails(anchored_builder):
    export = copy.deepcopy(anchored_builder.anchors[0])
    export["provenance"][0], export["provenance"][1] = (
        export["provenance"][1], export["provenance"][0],
    )
    report = _verify_anchor(export, anchored_builder)
    assert _status(report, "provenance_root") == "fail"
    assert _status(report, "provenance_boundary_hashes") == "fail"


def test_v3_record_with_a_forged_signature_fails(anchored_builder):
    export = copy.deepcopy(anchored_builder.anchors[0])
    export["provenance"][1]["signature_b64"] = export["provenance"][2]["signature_b64"]
    report = _verify_anchor(export, anchored_builder)
    assert _status(report, "provenance_signatures") == "fail"
    assert _status(report, "provenance_root") == "pass"


def test_v3_without_provenance_array_fails(anchored_builder):
    export = copy.deepcopy(anchored_builder.anchors[0])
    del export["provenance"]
    assert _status(_verify_anchor(export, anchored_builder), "provenance_root") == "fail"


def test_cli_audit_anchor_reports_provenance_figures(tmp_path, anchored_builder, capsys):
    path = tmp_path / "anchor.json"
    path.write_text(json.dumps(anchored_builder.anchors[0]))
    trust = tmp_path / "trust.json"
    trust.write_text(json.dumps(anchored_builder.anchor()))
    roots = tmp_path / "roots.pem"
    roots.write_bytes(anchored_builder.tsa.roots_pem)
    code = main(
        ["--audit-anchor", str(path), "--trust-anchor", str(trust), "--tsa-roots", str(roots)]
    )
    out = capsys.readouterr().out
    assert code == 0, out
    assert "Provenance entries" in out and anchored_builder.anchors[0]["provenance_root"] in out
    assert "Provenance root matches" in out


# ---------------------------------------------------------------------------
# Check 15: the happy path
# ---------------------------------------------------------------------------


def test_anchored_package_verifies(anchored_builder):
    report = _verify(anchored_builder, anchored_builder.components())
    assert report.verified, report.to_text()
    assert _status(report, "provenance_anchoring") == "pass"
    assert _status(report, "file_digests") == "pass"
    assert _status(report, "provenance") == "pass"
    pa = report.provenance_anchoring
    assert (pa["anchor_count"], pa["anchored"], pa["not_yet_anchored"], pa["missing"]) == (
        2, 8, 3, 0
    )
    assert pa["unanchored"] == 0 and pa["anchor_unverified"] == 0
    assert all(a["verified"] and a["tsa_chain"] == "pass" for a in pa["anchors"])
    assert "8 of 11 provenance entries anchored, 3 not yet anchored, 0 missing" in _detail(
        report, "provenance_anchoring"
    )


def test_anchored_entries_report_the_tsa_gen_time(anchored_builder):
    report = _verify(anchored_builder, anchored_builder.components())
    entries = report.provenance_anchoring["entries"]
    first = entries[0]
    assert first["status"] == "anchored"
    assert first["anchor_id"] == "anchor-1100"
    assert first["tsa_gen_time"].startswith("2026-10-15T11:05:03")
    assert entries[-1]["status"] == "not_yet_anchored"
    assert entries[-1]["tsa_gen_time"] is None
    assert "11:05:03" in _detail(report, "provenance_anchoring")


def test_report_json_carries_provenance_anchoring(anchored_builder):
    body = _verify(anchored_builder, anchored_builder.components()).to_dict()
    pa = body["provenance_anchoring"]
    assert set(pa) == {
        "anchor_count", "anchored", "not_yet_anchored", "missing", "unanchored",
        "anchor_unverified", "anchors", "entries",
    }
    assert set(pa["anchors"][0]) == {
        "anchor_id", "schema", "period_start", "period_end", "anchor_digest",
        "provenance_count", "verified", "failed_checks", "signature", "tsa_gen_time",
        "tsa_chain",
    }
    assert set(pa["entries"][0]) == {
        "id", "entry_hash", "timestamp", "status", "anchor_id", "tsa_gen_time", "reason",
    }
    json.dumps(body)  # serializable as-is
    assert "Provenance anchoring" in _verify(
        anchored_builder, anchored_builder.components()
    ).to_text()


def test_without_tsa_roots_the_chain_is_not_validated_but_passes(anchored_builder):
    report = _verify(anchored_builder, anchored_builder.components(), roots=False)
    assert report.verified, report.to_text()
    assert all(a["tsa_chain"] == "skipped" for a in report.provenance_anchoring["anchors"])


def test_untimestamped_anchor_reports_no_tsa(anchored_builder):
    start, end = anchored_builder.periods[0]
    anchored_builder.anchors[0] = anchored_builder.seal_anchor(
        start, end, anchored_builder.entries_in(start, end), None, timestamped=False
    )
    anchored_builder.anchors[1] = anchored_builder.seal_anchor(
        *anchored_builder.periods[1],
        anchored_builder.entries_in(*anchored_builder.periods[1]),
        anchored_builder.anchors[0]["anchor_digest"],
    )
    report = _verify(anchored_builder, anchored_builder.components())
    assert report.verified, report.to_text()
    assert "no TSA" in _detail(report, "provenance_anchoring")
    assert report.provenance_anchoring["entries"][0]["tsa_gen_time"] is None


def test_package_1_3_skips_check_15_with_a_reason(authority_builder):
    report = verify_package(
        authority_builder.components(),
        anchor=authority_builder.anchor(),
        observer_anchors=[authority_builder.observer_anchor(), authority_builder.minotaur_anchor()],
    )
    assert report.verified, report.to_text()
    assert _status(report, "provenance_anchoring") == "skipped"
    assert "predates anchors.json (1.4)" in _detail(report, "provenance_anchoring")
    assert report.provenance_anchoring is None


def test_apr_package_has_no_check_15(builder):
    report = verify_package(builder.components(), anchor=builder.anchor())
    assert "provenance_anchoring" not in {c.id for c in report.checks}


def test_without_a_key_check_15_is_skipped_not_passed(anchored_builder):
    report = _verify(anchored_builder, anchored_builder.components(), anchor=None)
    assert not report.verified
    assert _status(report, "provenance_anchoring") == "skipped"
    assert report.provenance_anchoring["anchored"] == 0


def test_zip_round_trip(anchored_builder):
    from behavry_verify.package import load_package_from_bytes

    components = load_package_from_bytes(anchored_builder.zip_bytes())
    report = _verify(anchored_builder, components)
    assert report.verified, report.to_text()
    assert _status(report, "file_digests") == "pass"


# ---------------------------------------------------------------------------
# Check 15: tampering
# ---------------------------------------------------------------------------


def test_edited_entry_fails_digest_chain_and_anchoring(anchored_builder):
    """Edit an anchored entry and re-seal it, without touching the manifest."""
    components = anchored_builder.components()
    entry = components["provenance.json"]["entries"][2]
    entry["summary"] = "Assessment that never happened"
    anchored_builder.seal_entry(entry)
    report = _verify(anchored_builder, components)
    assert not report.verified
    assert _status(report, "file_digests") == "fail"
    assert _status(report, "provenance") == "fail"  # the next entry's link breaks
    assert _status(report, "provenance_anchoring") == "fail"
    assert report.provenance_anchoring["missing"] == 1
    assert report.provenance_anchoring["entries"][2]["status"] == "missing"


def test_key_holder_rewrite_is_caught_only_by_the_anchor(anchored_builder):
    """Re-chain and re-sign everything: checks 8 and 12 pass, check 15 does not."""
    components = anchored_builder.components()
    entries = components["provenance.json"]["entries"]
    entries[3]["summary"] = "secrets:read VERIFIED (rewritten)"
    _rechain(anchored_builder, entries, 3)
    report = _verify(anchored_builder, _resealed(anchored_builder, components))
    assert not report.verified
    assert _status(report, "signature") == "pass"
    assert _status(report, "file_digests") == "pass"
    assert _status(report, "provenance") == "pass"
    assert _status(report, "provenance_anchoring") == "fail"
    pa = report.provenance_anchoring
    # 3 and 4 in the first period, 5 to 7 in the second, all re-hashed.
    assert pa["missing"] == 5 and pa["anchored"] == 3
    assert "added or altered after sealing" in pa["entries"][3]["reason"]


def test_rewriting_the_anchor_too_fails_its_root(anchored_builder):
    """Swapping the new hash into the anchor's records breaks its sealed root."""
    components = anchored_builder.components()
    entries = components["provenance.json"]["entries"]
    entries[4]["summary"] = "Verified Authority applied (rewritten)"
    anchored_builder.seal_entry(entries[4])
    _rechain(anchored_builder, entries, 5)
    anchors = components["anchors.json"]["anchors"]
    anchors[0]["provenance"][4] = provenance_record(entries[4])
    report = _verify(anchored_builder, _resealed(anchored_builder, components))
    assert _status(report, "provenance_anchoring") == "fail"
    row = report.provenance_anchoring["anchors"][0]
    assert not row["verified"]
    assert "provenance_root" in row["failed_checks"]
    assert report.provenance_anchoring["entries"][4]["status"] == "anchor_unverified"


def test_dropped_record_from_an_anchor_fails(anchored_builder):
    components = anchored_builder.components()
    del components["anchors.json"]["anchors"][0]["provenance"][1]
    report = _verify(anchored_builder, _resealed(anchored_builder, components))
    assert not report.verified
    assert _status(report, "provenance_anchoring") == "fail"
    pa = report.provenance_anchoring
    assert {"provenance_root", "provenance_count"} <= set(pa["anchors"][0]["failed_checks"])
    assert pa["entries"][1]["status"] == "missing"


def test_altered_provenance_root_fails(anchored_builder):
    components = anchored_builder.components()
    components["anchors.json"]["anchors"][1]["provenance_root"] = "sha256:" + "1" * 64
    report = _verify(anchored_builder, _resealed(anchored_builder, components))
    assert _status(report, "provenance_anchoring") == "fail"
    failed = report.provenance_anchoring["anchors"][1]["failed_checks"]
    assert {"anchor_digest", "signature", "provenance_root", "tsa_imprint"} <= set(failed)


def test_entry_newer_than_the_last_anchor_is_not_yet_anchored(anchored_builder):
    components = anchored_builder.components()
    entries = components["provenance.json"]["entries"]
    new = dict(entries[-1])
    new.update(
        id="prov-new", timestamp="2026-10-16T09:00:00+00:00", summary="Later entry",
        previous_hash=entries[-1]["entry_hash"],
    )
    anchored_builder.seal_entry(new)
    entries.append(new)
    report = _verify(anchored_builder, _resealed(anchored_builder, components))
    assert report.verified, report.to_text()
    assert _status(report, "provenance_anchoring") == "pass"
    assert report.provenance_anchoring["not_yet_anchored"] == 4
    assert report.provenance_anchoring["entries"][-1]["status"] == "not_yet_anchored"


def test_backdated_entry_inside_a_sealed_period_is_missing(anchored_builder):
    """Appended to the chain (so check 12 passes) but timestamped into period 1."""
    components = anchored_builder.components()
    entries = components["provenance.json"]["entries"]
    new = dict(entries[-1])
    new.update(
        id="prov-backdated", timestamp="2026-10-15T11:02:30+00:00",
        summary="Assessment backdated", previous_hash=entries[-1]["entry_hash"],
    )
    anchored_builder.seal_entry(new)
    entries.append(new)
    report = _verify(anchored_builder, _resealed(anchored_builder, components))
    assert not report.verified
    assert _status(report, "provenance") == "pass"
    assert _status(report, "provenance_anchoring") == "fail"
    item = report.provenance_anchoring["entries"][-1]
    assert (item["status"], item["anchor_id"]) == ("missing", "anchor-1100")
    assert "'prov-backdated'" in _detail(report, "provenance_anchoring")


def test_anchor_count_mismatch_fails(anchored_builder):
    components = anchored_builder.components()
    manifest = dict(components["manifest.json"])
    manifest["anchor_count"] = 3
    components["manifest.json"] = manifest
    report = _verify(anchored_builder, components)
    assert _status(report, "signature") == "fail"
    assert "anchor_count 3" in _detail(report, "provenance_anchoring")


def test_missing_anchors_file_fails_for_1_4(anchored_builder):
    components = anchored_builder.components()
    del components["anchors.json"]
    report = _verify(anchored_builder, components)
    assert _status(report, "provenance_anchoring") == "fail"
    assert _status(report, "file_digests") == "fail"


def test_anchor_from_another_tenant_fails(anchored_builder):
    anchored_builder.tenant_id = "tenant-other"
    start, end = anchored_builder.periods[0]
    in_period = anchored_builder.entries_in(start, end)
    foreign = anchored_builder.seal_anchor(start, end, in_period, None)
    anchored_builder.tenant_id = "tenant-0001"
    anchored_builder.anchors[0] = foreign
    report = _verify(anchored_builder, anchored_builder.components())
    assert _status(report, "provenance_anchoring") == "fail"
    assert "tenant" in report.provenance_anchoring["anchors"][0]["failed_checks"]


def test_withheld_anchor_leaves_entries_unanchored_with_a_warning(anchored_builder):
    """Drop the first anchor: its entries sit before the remaining sealed span."""
    components = anchored_builder.components()
    del components["anchors.json"]["anchors"][0]
    report = _verify(anchored_builder, _resealed(anchored_builder, components))
    assert _status(report, "provenance_anchoring") == "warn"
    pa = report.provenance_anchoring
    assert (pa["unanchored"], pa["anchored"], pa["missing"]) == (5, 3, 0)
    assert "ask for the anchors of those periods" in _detail(report, "provenance_anchoring")


def test_entry_in_a_pre_v3_period_is_unanchored_not_missing(anchored_builder):
    """A v2 anchor commits to no provenance, so an entry in its period is not missing."""
    components = anchored_builder.components()
    export = components["anchors.json"]["anchors"][0]
    export["schema"] = "behavry.audit_anchor.v2"
    for key in (
        "provenance", "provenance_count", "provenance_root", "first_provenance_hash",
        "last_provenance_hash",
    ):
        export.pop(key)
    canonical = canonical_anchor_bytes(export)
    export["anchor_digest"] = hashlib.sha256(canonical).hexdigest()
    export["signature"] = base64.b64encode(anchored_builder.private_key.sign(canonical)).decode()
    export["tsa"] = dict(export["tsa"], status="disabled", token_der_b64=None, gen_time=None)
    report = _verify(anchored_builder, _resealed(anchored_builder, components))
    pa = report.provenance_anchoring
    assert pa["anchors"][0]["verified"], pa["anchors"][0]
    assert pa["unanchored"] == 5 and pa["missing"] == 0
    assert "predates provenance anchoring" in pa["entries"][0]["reason"]
    assert _status(report, "provenance_anchoring") == "pass"


# ---------------------------------------------------------------------------
# CLI and API
# ---------------------------------------------------------------------------


@pytest.fixture
def package_files(tmp_path, anchored_builder):
    paths = {
        "package": tmp_path / "authority.zip",
        "trust": tmp_path / "trust.json",
        "observer": tmp_path / "observer.json",
        "minotaur": tmp_path / "minotaur.json",
        "roots": tmp_path / "roots.pem",
    }
    paths["package"].write_bytes(anchored_builder.zip_bytes())
    paths["trust"].write_text(json.dumps(anchored_builder.anchor()))
    paths["observer"].write_text(json.dumps(anchored_builder.observer_anchor()))
    paths["minotaur"].write_text(json.dumps(anchored_builder.minotaur_anchor()))
    paths["roots"].write_bytes(anchored_builder.tsa.roots_pem)
    return paths


def test_cli_package_with_tsa_roots(package_files, capsys):
    code = main(
        [
            "--package", str(package_files["package"]),
            "--trust-anchor", str(package_files["trust"]),
            "--observer-anchor", str(package_files["observer"]),
            "--observer-anchor", str(package_files["minotaur"]),
            "--tsa-roots", str(package_files["roots"]),
            "--json",
        ]
    )
    body = json.loads(capsys.readouterr().out)
    assert code == 0, body
    assert body["provenance_anchoring"]["anchored"] == 8
    assert all(a["tsa_chain"] == "pass" for a in body["provenance_anchoring"]["anchors"])


def test_api_accepts_observer_key_files_and_tsa_roots(package_files, anchored_builder):
    client = TestClient(app)
    js = "application/json"
    files = [
        ("package", ("authority.zip", package_files["package"].read_bytes(), "application/zip")),
        ("observer_anchor", ("observer.json", package_files["observer"].read_bytes(), js)),
        ("observer_anchor", ("minotaur.json", package_files["minotaur"].read_bytes(), js)),
    ]
    data = {
        "trust_anchor": json.dumps(anchored_builder.anchor()),
        "tsa_roots": anchored_builder.tsa.roots_pem.decode(),
    }
    response = client.post("/api/v1/verify", files=files, data=data)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["verified"] is True, body
    checks = {c["id"]: c["status"] for c in body["checks"]}
    assert checks["assessments"] == "pass"
    assert checks["observations"] == "pass"
    assert checks["provenance_anchoring"] == "pass"
    assert body["provenance_anchoring"]["anchors"][0]["tsa_chain"] == "pass"


def test_api_without_observer_files_does_not_verify_bundles(package_files, anchored_builder):
    client = TestClient(app)
    files = {"package": ("a.zip", package_files["package"].read_bytes(), "application/zip")}
    response = client.post(
        "/api/v1/verify", files=files, data={"trust_anchor": json.dumps(anchored_builder.anchor())}
    )
    checks = {c["id"]: c["status"] for c in response.json()["checks"]}
    assert checks["assessments"] == "skipped"


def test_api_rejects_a_malformed_observer_key_file(package_files, anchored_builder):
    client = TestClient(app)
    files = [
        ("package", ("a.zip", package_files["package"].read_bytes(), "application/zip")),
        ("observer_anchor", ("bad.json", b"{not json", "application/json")),
    ]
    response = client.post("/api/v1/verify", files=files)
    assert response.status_code == 400
    assert "bad.json" in response.json()["detail"]

    files[1] = ("observer_anchor", ("partial.json", b'{"kid": "x"}', "application/json"))
    assert client.post("/api/v1/verify", files=files).status_code == 400


def test_api_rejects_bad_tsa_roots(package_files):
    client = TestClient(app)
    files = {"package": ("a.zip", package_files["package"].read_bytes(), "application/zip")}
    response = client.post("/api/v1/verify", files=files, data={"tsa_roots": "not a pem"})
    assert response.status_code == 400


def test_api_verifies_a_v3_audit_anchor(anchored_builder):
    client = TestClient(app)
    response = client.post(
        "/api/v1/verify-anchor",
        files={
            "audit_anchor": ("a.json", json.dumps(anchored_builder.anchors[0]), "application/json")
        },
        data={
            "trust_anchor": json.dumps(anchored_builder.anchor()),
            "tsa_roots": anchored_builder.tsa.roots_pem.decode(),
        },
    )
    body = response.json()
    assert body["verified"] is True, body
    assert body["anchor_summary"]["provenance_count"] == 5


def test_api_verifies_a_gzipped_audit_anchor(anchored_builder):
    """AG-8: the web upload takes a WORM object as stored."""
    import gzip

    client = TestClient(app)
    body = gzip.compress(json.dumps(anchored_builder.anchors[0]).encode(), mtime=0)
    response = client.post(
        "/api/v1/verify-anchor",
        files={"audit_anchor": ("a.json.gz", body, "application/gzip")},
        data={
            "trust_anchor": json.dumps(anchored_builder.anchor()),
            "tsa_roots": anchored_builder.tsa.roots_pem.decode(),
        },
    )
    assert response.json()["verified"] is True, response.json()
    bad = client.post(
        "/api/v1/verify-anchor",
        files={"audit_anchor": ("a.json", b"[1, 2]", "application/json")},
        data={"trust_anchor": json.dumps(anchored_builder.anchor())},
    )
    assert bad.status_code == 400
