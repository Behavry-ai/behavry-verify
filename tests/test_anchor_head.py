"""The independent anchor head (Behavry Sprint AG-6): package 1.6 and check 15 v3.

Package 1.5 proves nothing is missing inside the anchor run, not that the run
reaches either end of the chain. AG-6 closes both ends:

* **front:** ``anchors.json`` carries the run's predecessor as a header-only
  record, bound by ``anchor_predecessor_digest`` in the signed manifest. When
  it is v3, anchoring had already begun, so an entry before the run is missing
  (P1, P2);
* **tail:** the verifying party supplies anchor heads obtained independently of
  the package. Every entry older than a verified head's period end must be
  anchored (H1 to H3). Without one, the report says truncation of the newest
  anchors cannot be ruled out (H4).

See ``docs/strategy/AG6-CONTRACTS.md`` in the Behavry repo.
"""
from __future__ import annotations

import copy
import json
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient

from behavry_verify.app import app
from behavry_verify.audit_anchor import HEADER_CHECKS_SKIPPED_REASON, verify_audit_anchor
from behavry_verify.authority import NO_HEAD_NOTE
from behavry_verify.cli import main
from behavry_verify.package import load_package_from_bytes, verify_package
from behavry_verify.report import TrustSource
from behavry_verify.rfc3161 import load_pem_certificates
from tests.conftest import (
    ANCHOR_V2,
    AnchoredAuthorityPackageBuilder,
    ChainedAuthorityPackageBuilder,
    PredecessorAuthorityPackageBuilder,
    header_only,
)

BASE = datetime(2026, 10, 15, 11, 0, 0, tzinfo=UTC)
RECORD_CHECKS = (
    "merkle_root", "event_count", "boundary_hashes", "event_signatures",
    "provenance_root", "provenance_count", "provenance_boundary_hashes",
    "provenance_signatures",
)


def _status(report, check_id: str) -> str:
    matches = [c for c in report.checks if c.id == check_id]
    assert matches, f"no {check_id} check in {[c.id for c in report.checks]}"
    return matches[0].status.value


def _detail(report, check_id: str) -> str:
    return next(c for c in report.checks if c.id == check_id).detail


def _verify(builder, components, *, heads: list[dict[str, Any]] | None = None):
    return verify_package(
        components,
        anchor=builder.anchor(),
        trust_source=TrustSource.SUPPLIED_ANCHOR,
        observer_anchors=[builder.observer_anchor(), builder.minotaur_anchor()],
        tsa_roots=load_pem_certificates(builder.tsa.roots_pem),
        anchor_heads=heads,
    )


def _verify_record(export, builder):
    return verify_audit_anchor(
        export,
        anchor=builder.anchor(),
        trust_source=TrustSource.SUPPLIED_ANCHOR,
        tsa_roots=load_pem_certificates(builder.tsa.roots_pem),
    )


def _statuses(report) -> dict[str, str]:
    return {e["id"]: e["status"] for e in report.provenance_anchoring["entries"]}


def _entry(report, entry_id: str) -> dict[str, Any]:
    return next(e for e in report.provenance_anchoring["entries"] if e["id"] == entry_id)


# ---------------------------------------------------------------------------
# Header-only records
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("schema", ["behavry.audit_anchor.v3", ANCHOR_V2])
def test_header_only_record_verifies_its_signed_bytes_and_skips_the_records(schema):
    builder = PredecessorAuthorityPackageBuilder(predecessor_schema=schema)
    header = builder.predecessor
    assert header["records"] == "header"
    assert "events" not in header and "provenance" not in header
    report = _verify_record(header, builder)
    assert report.verified, report.to_text()
    for check_id in ("anchor_digest", "signature", "tsa_imprint", "tsa_signature", "tsa_chain"):
        assert _status(report, check_id) == "pass", check_id
    expected = RECORD_CHECKS if schema.endswith("v3") else RECORD_CHECKS[:4]
    for check_id in expected:
        assert _status(report, check_id) == "skipped", check_id
        assert _detail(report, check_id) == HEADER_CHECKS_SKIPPED_REASON
    # Never reported as passed.
    assert not any(
        c.status.value == "pass" for c in report.checks if c.id in RECORD_CHECKS
    )
    assert report.anchor_summary["records"] == "header"


def test_header_of_any_run_anchor_keeps_its_digest(predecessor_builder):
    full = predecessor_builder.anchors[2]
    header = header_only(full)
    assert header["anchor_digest"] == full["anchor_digest"]
    assert _verify_record(header, predecessor_builder).verified


def test_header_only_record_still_signs_its_fields(predecessor_builder):
    header = copy.deepcopy(predecessor_builder.predecessor)
    header["provenance_count"] = 9
    report = _verify_record(header, predecessor_builder)
    assert not report.verified
    assert _status(report, "anchor_digest") == "fail"
    assert _status(report, "provenance_count") == "skipped"


def test_header_only_record_carrying_records_ignores_them(predecessor_builder):
    header = header_only(predecessor_builder.anchors[0])
    header["provenance"] = [{"entry_hash": "f" * 64}]
    report = _verify_record(header, predecessor_builder)
    assert _status(report, "anchor_format") == "warn"
    assert _status(report, "provenance_root") == "skipped"
    assert report.verified


def test_cli_audit_anchor_reports_a_header_only_record(tmp_path, predecessor_builder, capsys):
    path = tmp_path / "head.json"
    path.write_text(json.dumps(predecessor_builder.predecessor))
    trust = tmp_path / "trust.json"
    trust.write_text(json.dumps(predecessor_builder.anchor()))
    code = main(["--audit-anchor", str(path), "--trust-anchor", str(trust)])
    out = capsys.readouterr().out
    assert code == 0, out
    assert HEADER_CHECKS_SKIPPED_REASON in out


# ---------------------------------------------------------------------------
# Package 1.6: the happy path
# ---------------------------------------------------------------------------


def test_valid_1_6_package_passes_without_a_head(predecessor_builder):
    components = predecessor_builder.components()
    manifest = components["manifest.json"]
    assert manifest["package_version"] == "1.6"
    assert (
        manifest["anchor_predecessor_digest"]
        == predecessor_builder.predecessor["anchor_digest"]
        == predecessor_builder.anchors[0]["previous_anchor_digest"]
    )
    report = _verify(predecessor_builder, components)
    assert report.verified, report.to_text()
    assert _status(report, "provenance_anchoring") == "pass"
    pa = report.provenance_anchoring
    assert pa["anchored"] == 11 and pa["missing"] == 0
    assert pa["predecessor"] == {
        "anchor_id": "anchor-1056",
        "schema": "behavry.audit_anchor.v3",
        "anchor_digest": predecessor_builder.predecessor["anchor_digest"],
        "verified": True,
        "period_start": "2026-10-15T10:56:00.000000+00:00",
        "period_end": "2026-10-15T11:00:00.000000+00:00",
        "failed_checks": [],
    }
    assert pa["heads"] == [] and pa["head_note"] == NO_HEAD_NOTE
    detail = _detail(report, "provenance_anchoring")
    assert NO_HEAD_NOTE in detail and "predecessor anchor-1056" in detail
    text = report.to_text()
    assert NO_HEAD_NOTE in text and "Run predecessor" in text


def test_valid_1_6_package_passes_with_its_own_head(predecessor_builder):
    head = header_only(predecessor_builder.anchors[-1])
    report = _verify(predecessor_builder, predecessor_builder.components(), heads=[head])
    assert report.verified, report.to_text()
    pa = report.provenance_anchoring
    assert pa["head_note"] is None
    assert pa["heads"] == [
        {
            "anchor_id": "anchor-1111",
            "period_start": "2026-10-15T11:11:00.000000+00:00",
            "period_end": "2026-10-15T11:15:00.000000+00:00",
            "anchor_digest": head["anchor_digest"],
            "verified": True,
            "tsa_gen_time": "2026-10-15T11:15:03+00:00",
            "failed_checks": [],
        }
    ]
    assert "1 independent anchor head(s) verified" in _detail(report, "provenance_anchoring")
    assert "Anchor head" in report.to_text()


def test_head_newer_than_every_entry_passes(predecessor_builder):
    later = predecessor_builder.seal_after(2)
    report = _verify(
        predecessor_builder, predecessor_builder.components(), heads=[header_only(later[-1])]
    )
    assert report.verified, report.to_text()
    assert report.provenance_anchoring["anchored"] == 11


def test_full_record_is_accepted_as_a_head(predecessor_builder):
    later = predecessor_builder.seal_after()
    report = _verify(predecessor_builder, predecessor_builder.components(), heads=later)
    assert report.verified, report.to_text()
    assert report.provenance_anchoring["heads"][0]["verified"] is True


def test_1_6_report_shape(predecessor_builder):
    body = _verify(predecessor_builder, predecessor_builder.components()).to_dict()
    pa = json.loads(json.dumps(body))["provenance_anchoring"]
    assert set(pa) == {
        "anchor_count", "anchored", "not_yet_anchored", "missing", "unanchored",
        "anchor_unverified", "anchors", "entries", "package_version",
        "anchor_head_digest", "chain_unbroken", "chain_breaks",
        "heads", "head_note", "predecessor",
    }


def test_1_6_zip_round_trip(predecessor_builder):
    components = load_package_from_bytes(predecessor_builder.zip_bytes())
    assert _verify(predecessor_builder, components).verified


def test_run_that_starts_the_chain_has_no_predecessor():
    builder = PredecessorAuthorityPackageBuilder(predecessor_schema=None)
    components = builder.components()
    assert components["anchors.json"]["predecessor"] is None
    assert components["manifest.json"]["anchor_predecessor_digest"] is None
    report = _verify(builder, components)
    assert report.verified, report.to_text()
    assert report.provenance_anchoring["predecessor"] is None
    assert "starts the anchor chain" in _detail(report, "provenance_anchoring")


def test_empty_1_6_run_passes():
    builder = PredecessorAuthorityPackageBuilder(predecessor_schema=None)
    builder.anchors = []
    report = _verify(builder, builder.components())
    assert report.verified, report.to_text()
    assert report.provenance_anchoring["not_yet_anchored"] == 11


# ---------------------------------------------------------------------------
# Tail truncation, re-signed by the key holder: only a head catches it
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("dropped", [(2, 3), (1, 2, 3)])
def test_tail_truncation_passes_without_a_head_and_fails_with_one(dropped):
    builder = PredecessorAuthorityPackageBuilder()
    newest = header_only(builder.anchors[-1])
    builder.anchors = [a for i, a in enumerate(builder.anchors) if i not in dropped]
    # components() re-signs a consistent manifest: anchor_count, head digest
    # and file digests all match what remains.
    components = builder.components()
    manifest = components["manifest.json"]
    assert manifest["anchor_count"] == 4 - len(dropped)
    assert manifest["anchor_head_digest"] == builder.anchors[-1]["anchor_digest"]

    without = _verify(builder, components)
    assert without.verified, without.to_text()
    assert without.provenance_anchoring["head_note"] == NO_HEAD_NOTE
    hidden = range(min(dropped) * 3 + 1, 11)  # entries 7.. (or 4..) read not yet anchored
    assert {_statuses(without)[f"prov-{i:04d}"] for i in hidden} == {"not_yet_anchored"}

    report = _verify(builder, components, heads=[newest])
    assert not report.verified
    assert _status(report, "provenance_anchoring") == "fail"
    assert {_statuses(report)[f"prov-{i:04d}"] for i in hidden} == {"missing"}
    entry = _entry(report, "prov-0010")
    assert entry["anchor_id"] == "anchor-1111"
    assert "the package does not carry" in entry["reason"]
    assert "missing" in _detail(report, "provenance_anchoring")


def test_dropping_only_an_empty_newest_anchor_hides_nothing():
    """H3 is about entries: with every entry still anchored, a newer head passes."""
    builder = PredecessorAuthorityPackageBuilder()
    newest = header_only(builder.anchors[-1])
    builder.anchors = builder.anchors[:3]
    report = _verify(builder, builder.components(), heads=[newest])
    assert report.verified, report.to_text()
    assert report.provenance_anchoring["anchored"] == 11


def test_entry_inside_the_heads_period_gets_the_contract_reason():
    """Run ends at 11:07 and the head seals 11:07-11:11: the contract's own wording."""
    builder = PredecessorAuthorityPackageBuilder()
    head = header_only(builder.anchors[2])
    builder.anchors = builder.anchors[:2]
    report = _verify(builder, builder.components(), heads=[head])
    entry = _entry(report, "prov-0008")
    assert entry["reason"] == (
        "sealed by anchor anchor-1107 (2026-10-15T11:07:00.000000+00:00.."
        "2026-10-15T11:11:00.000000+00:00), which the package does not carry"
    )


def test_tail_truncation_with_a_head_fails_on_a_1_5_package():
    builder = ChainedAuthorityPackageBuilder()
    newest = header_only(builder.anchors[-1])
    builder.anchors = builder.anchors[:2]
    components = builder.components()
    assert _verify(builder, components).verified
    report = _verify(builder, components, heads=[newest])
    assert not report.verified
    statuses = _statuses(report)
    assert [statuses[f"prov-{i:04d}"] for i in range(7, 11)] == ["missing"] * 4
    pa = report.provenance_anchoring
    assert "predecessor" not in pa
    assert pa["heads"][0]["verified"] is True and pa["head_note"] is None


def test_head_applied_to_a_valid_1_5_package_passes():
    builder = ChainedAuthorityPackageBuilder()
    report = _verify(builder, builder.components(), heads=[header_only(builder.anchors[-1])])
    assert report.verified, report.to_text()


def test_head_applied_to_a_1_4_package():
    builder = AnchoredAuthorityPackageBuilder()
    # The 1.4 package's newest anchor ends at 11:08; entries 8 to 10 are not
    # yet anchored. A head sealed over 11:08-11:12 proves they were.
    head = builder.seal_anchor(
        BASE + timedelta(minutes=8), BASE + timedelta(minutes=12),
        builder.entries_in(BASE + timedelta(minutes=8), BASE + timedelta(minutes=12)),
        builder.anchors[-1]["anchor_digest"],
    )
    components = builder.components()
    assert _verify(builder, components).verified
    report = _verify(builder, components, heads=[header_only(head)])
    assert not report.verified
    assert _statuses(report)["prov-0009"] == "missing"


def test_1_5_report_without_a_head_keeps_its_shape():
    builder = ChainedAuthorityPackageBuilder()
    pa = _verify(builder, builder.components()).provenance_anchoring
    assert "heads" not in pa and "head_note" not in pa and "predecessor" not in pa


# ---------------------------------------------------------------------------
# Front truncation and the predecessor (P1, P2)
# ---------------------------------------------------------------------------


def test_front_truncation_resigned_fails_on_p2():
    """Drop the oldest anchor and name it as the (v3) predecessor: early entries are missing."""
    builder = PredecessorAuthorityPackageBuilder()
    dropped = builder.anchors[0]
    builder.anchors = builder.anchors[1:]
    builder.predecessor = header_only(dropped)
    components = builder.components()
    report = _verify(builder, components)
    assert not report.verified
    assert _status(report, "provenance_anchoring") == "fail"
    pa = report.provenance_anchoring
    assert pa["predecessor"]["verified"] is True
    statuses = _statuses(report)
    assert [statuses[f"prov-{i:04d}"] for i in range(4)] == ["missing"] * 4
    assert "anchoring had already begun" in _entry(report, "prov-0000")["reason"]


def test_front_truncation_is_unanchored_in_1_5():
    """The 1.5 known limit, pinned: the same truncation passes there."""
    builder = ChainedAuthorityPackageBuilder()
    builder.anchors = builder.anchors[1:]
    report = _verify(builder, builder.components())
    assert report.verified
    assert _statuses(report)["prov-0000"] == "unanchored"


def test_predecessor_not_the_first_anchors_pointer_fails(predecessor_builder):
    predecessor_builder.predecessor = header_only(predecessor_builder.anchors[1])
    report = _verify(predecessor_builder, predecessor_builder.components())
    assert not report.verified
    assert "is not the first anchor's previous_anchor_digest" in _detail(
        report, "provenance_anchoring"
    )


def test_missing_predecessor_fails_when_the_pointer_is_set(predecessor_builder):
    predecessor_builder.predecessor = None
    components = predecessor_builder.components()
    assert components["manifest.json"]["anchor_predecessor_digest"] is None
    report = _verify(predecessor_builder, components)
    assert not report.verified
    assert "carries no predecessor" in _detail(report, "provenance_anchoring")
    assert report.provenance_anchoring["predecessor"] is None


def test_predecessor_present_when_the_run_starts_the_chain_fails():
    builder = PredecessorAuthorityPackageBuilder(predecessor_schema=None)
    other = PredecessorAuthorityPackageBuilder()
    builder.predecessor = other.predecessor
    report = _verify(builder, builder.components())
    assert not report.verified
    assert "so it must be null" in _detail(report, "provenance_anchoring")


def test_manifest_predecessor_digest_must_match(predecessor_builder):
    predecessor_builder.manifest_overrides["anchor_predecessor_digest"] = "0" * 64
    report = _verify(predecessor_builder, predecessor_builder.components())
    assert _status(report, "signature") == "pass"
    assert "anchor_predecessor_digest" in _detail(report, "provenance_anchoring")
    assert not report.verified


def test_manifest_without_predecessor_digest_fails(predecessor_builder):
    original = predecessor_builder.extra_manifest

    def without(data_files):
        body = original(data_files)
        body.pop("anchor_predecessor_digest")
        return body

    predecessor_builder.extra_manifest = without  # type: ignore[method-assign]
    report = _verify(predecessor_builder, predecessor_builder.components())
    assert "states no anchor_predecessor_digest" in _detail(report, "provenance_anchoring")


def test_tampered_predecessor_fails(predecessor_builder):
    predecessor_builder.predecessor["period_start"] = "2026-10-15T10:50:00.000000+00:00"
    report = _verify(predecessor_builder, predecessor_builder.components())
    assert not report.verified
    pa = report.provenance_anchoring
    assert pa["predecessor"]["verified"] is False
    assert "anchor_digest" in pa["predecessor"]["failed_checks"]


def test_full_record_as_predecessor_fails(predecessor_builder):
    """The contract makes the predecessor header-only; a full record is a malformed package."""
    full = predecessor_builder.seal_record(BASE - timedelta(minutes=4), BASE, None)
    assert full["anchor_digest"] == predecessor_builder.predecessor["anchor_digest"]
    predecessor_builder.predecessor = full
    report = _verify(predecessor_builder, predecessor_builder.components())
    assert "records" in report.provenance_anchoring["predecessor"]["failed_checks"]


@pytest.mark.parametrize("schema", [ANCHOR_V2, None])
def test_v2_or_no_predecessor_keeps_early_entries_unanchored(schema):
    builder = PredecessorAuthorityPackageBuilder(
        predecessor_schema=schema,
        periods=[
            (BASE + timedelta(minutes=3), BASE + timedelta(minutes=7)),
            (BASE + timedelta(minutes=7), BASE + timedelta(minutes=11)),
            (BASE + timedelta(minutes=11), BASE + timedelta(minutes=15)),
        ],
    )
    report = _verify(builder, builder.components())
    assert report.verified, report.to_text()
    statuses = _statuses(report)
    assert [statuses[f"prov-{i:04d}"] for i in range(3)] == ["unanchored"] * 3
    pred = report.provenance_anchoring["predecessor"]
    if schema is None:
        assert pred is None
    else:
        assert pred["schema"] == ANCHOR_V2 and pred["verified"] is True


def test_v3_predecessor_makes_early_entries_missing():
    builder = PredecessorAuthorityPackageBuilder(
        periods=[
            (BASE + timedelta(minutes=3), BASE + timedelta(minutes=7)),
            (BASE + timedelta(minutes=7), BASE + timedelta(minutes=11)),
            (BASE + timedelta(minutes=11), BASE + timedelta(minutes=15)),
        ],
    )
    report = _verify(builder, builder.components())
    assert not report.verified
    statuses = _statuses(report)
    assert [statuses[f"prov-{i:04d}"] for i in range(3)] == ["missing"] * 3


# ---------------------------------------------------------------------------
# Heads that are findings themselves (H1, H2)
# ---------------------------------------------------------------------------


def test_fork_fails(predecessor_builder):
    """A head sealing the same period as a run anchor, with a different digest."""
    run = predecessor_builder.anchors
    fork = predecessor_builder.seal_record(
        datetime.fromisoformat(run[3]["period_start"]),
        datetime.fromisoformat(run[3]["period_end"]),
        run[1]["anchor_digest"],
    )
    assert fork["period_start"] == run[3]["period_start"]
    assert fork["anchor_digest"] != run[3]["anchor_digest"]
    report = _verify(
        predecessor_builder, predecessor_builder.components(), heads=[header_only(fork)]
    )
    assert not report.verified
    assert report.provenance_anchoring["heads"][0]["verified"] is True
    assert "fork: anchor head anchor-1111" in _detail(report, "provenance_anchoring")


def test_head_from_another_tenant_fails_and_is_not_used():
    builder = PredecessorAuthorityPackageBuilder()
    newest = header_only(builder.anchors[-1])
    builder.anchors = builder.anchors[:2]
    foreign = builder.reseal({**copy.deepcopy(newest), "tenant_id": "tenant-other-9"})
    assert _verify_record(foreign, builder).verified  # well-formed, just not this tenant's
    report = _verify(builder, builder.components(), heads=[foreign])
    assert not report.verified
    row = report.provenance_anchoring["heads"][0]
    assert row["verified"] is False and row["failed_checks"] == ["tenant"]
    detail = _detail(report, "provenance_anchoring")
    assert "does not verify and is not used" in detail and "tenant-other-9" in detail
    # Not used: the entries it would have caught still read as not yet anchored.
    assert _statuses(report)["prov-0010"] == "not_yet_anchored"


def test_head_with_a_bad_signature_fails_and_is_not_used():
    builder = PredecessorAuthorityPackageBuilder()
    newest = header_only(builder.anchors[-1])
    builder.anchors = builder.anchors[:2]
    sig = newest["signature"]
    newest["signature"] = ("A" if sig[0] != "A" else "B") + sig[1:]
    report = _verify(builder, builder.components(), heads=[newest])
    assert not report.verified
    row = report.provenance_anchoring["heads"][0]
    assert row["verified"] is False and "signature" in row["failed_checks"]
    assert _statuses(report)["prov-0010"] == "not_yet_anchored"
    assert "NOT VERIFIED, not used" in report.to_text()


def test_bad_head_fails_an_otherwise_valid_package(predecessor_builder):
    head = header_only(predecessor_builder.anchors[-1])
    head["anchor_digest"] = "0" * 64
    report = _verify(predecessor_builder, predecessor_builder.components(), heads=[head])
    assert not report.verified
    assert _status(report, "provenance_anchoring") == "fail"


def test_heads_are_ignored_before_package_1_4():
    builder = ChainedAuthorityPackageBuilder()
    builder.authority_version = "1.3"
    head = header_only(builder.anchors[-1])
    report = _verify(builder, builder.components(), heads=[head])
    assert _status(report, "provenance_anchoring") == "skipped"
    assert "were not applied" in _detail(report, "provenance_anchoring")


# ---------------------------------------------------------------------------
# CLI and HTTP surfaces
# ---------------------------------------------------------------------------


def _truncated(tmp_path):
    builder = PredecessorAuthorityPackageBuilder()
    newest = header_only(builder.anchors[-1])
    builder.anchors = builder.anchors[:2]
    package = tmp_path / "authority.zip"
    package.write_bytes(builder.zip_bytes())
    head = tmp_path / "head.json"
    head.write_text(json.dumps(newest))
    trust = tmp_path / "trust.json"
    trust.write_text(json.dumps(builder.anchor()))
    return builder, package, head, trust


def test_cli_anchor_head(tmp_path, capsys):
    builder, package, head, trust = _truncated(tmp_path)
    observers = tmp_path / "observers.json"
    observers.write_text(json.dumps([builder.observer_anchor(), builder.minotaur_anchor()]))
    base = ["--package", str(package), "--trust-anchor", str(trust),
            "--observer-anchor", str(observers)]
    assert main(base) == 0
    assert NO_HEAD_NOTE in capsys.readouterr().out
    assert main([*base, "--anchor-head", str(head), "--anchor-head", str(head)]) == 1
    out = capsys.readouterr().out
    assert "the package does not carry" in out
    assert main([*base, "--anchor-head", str(head), "--json"]) == 1
    body = json.loads(capsys.readouterr().out)
    assert body["provenance_anchoring"]["heads"][0]["anchor_id"] == "anchor-1111"


def test_cli_anchor_head_usage_errors(tmp_path, capsys):
    _, package, head, trust = _truncated(tmp_path)
    bad = tmp_path / "bad.json"
    bad.write_text("[1, 2]")
    assert main(["--package", str(package), "--trust-anchor", str(trust),
                 "--anchor-head", str(bad)]) == 2
    assert main(["--audit-anchor", str(head), "--trust-anchor", str(trust),
                 "--anchor-head", str(head)]) == 2


def test_api_anchor_head_is_a_repeatable_file_field(tmp_path):
    builder, package, head, _ = _truncated(tmp_path)
    client = TestClient(app)
    files = [
        ("package", ("authority.zip", package.read_bytes(), "application/zip")),
        ("anchor_head", ("head.json", head.read_bytes(), "application/json")),
        ("anchor_head", ("head2.json", head.read_bytes(), "application/json")),
    ]
    data = {
        "trust_anchor": json.dumps(builder.anchor()),
        "observer_anchors": json.dumps([builder.observer_anchor(), builder.minotaur_anchor()]),
    }
    response = client.post("/api/v1/verify", files=files, data=data)
    assert response.status_code == 200
    body = response.json()
    assert body["verified"] is False
    assert len(body["provenance_anchoring"]["heads"]) == 2

    text = client.post("/api/v1/verify.txt", files=files, data=data)
    assert text.status_code == 422
    assert "the package does not carry" in text.text

    plain = client.post("/api/v1/verify", files=files[:1], data=data)
    assert plain.json()["verified"] is True
    assert plain.json()["provenance_anchoring"]["head_note"] == NO_HEAD_NOTE

    bad = client.post(
        "/api/v1/verify",
        files=[files[0], ("anchor_head", ("bad.json", b"{nope", "application/json"))],
        data=data,
    )
    assert bad.status_code == 400


def test_page_offers_anchor_head_upload():
    client = TestClient(app)
    page = client.get("/").text
    assert 'id="anchor-heads"' in page and "--anchor-head" in page
    script = client.get("/static/app.js").text
    assert '"anchor_head"' in script and "head_note" in script


def test_head_newer_than_the_package_says_it_may_simply_predate_it():
    builder = PredecessorAuthorityPackageBuilder()
    newest = header_only(builder.anchors[-1])
    builder.anchors = builder.anchors[:2]
    stale = _detail(_verify(builder, builder.components(), heads=[newest]), "provenance_anchoring")
    assert "the package may simply predate it" in stale
    # Created after the head was sealed: the package should have carried it.
    builder.manifest_overrides["created_at"] = "2026-10-15T12:00:00.000000+00:00"
    fresh = _detail(_verify(builder, builder.components(), heads=[newest]), "provenance_anchoring")
    assert "run stops short of the head" in fresh
    assert "predate" not in fresh
