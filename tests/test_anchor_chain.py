"""A withheld anchor fails (Behavry Sprint AG-5 H-1): package 1.5 and check 15 v2.

In package 1.4, ``anchors.json`` held only the anchors whose periods contain
one of the package's provenance entries. A producer that left one out was
reported with a warning, because the AUD-LINK back-pointers of a non-contiguous
set cannot say whether something is missing. Package 1.5 carries the whole
run of v3 anchors over the package's span, as provenance-only records, and the
signed manifest commits to its count and head. So:

* dropping an anchor from the middle breaks the chain, and fails;
* dropping the head changes ``anchor_head_digest``, and fails;
* an entry inside the span but in no anchor's period is missing, and fails.

See ``docs/strategy/AG5-CONTRACTS.md`` sections 1 to 3 in the Behavry repo.
"""
from __future__ import annotations

import copy
import json
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from behavry_verify.audit_anchor import EVENT_CHECKS_SKIPPED_REASON, verify_audit_anchor
from behavry_verify.cli import main
from behavry_verify.package import load_package_from_bytes, verify_package
from behavry_verify.report import TrustSource
from behavry_verify.rfc3161 import load_pem_certificates
from tests.conftest import (
    AnchoredAuthorityPackageBuilder,
    ChainedAuthorityPackageBuilder,
)

BASE = datetime(2026, 10, 15, 11, 0, 0, tzinfo=UTC)
EVENT_CHECKS = ("merkle_root", "event_count", "boundary_hashes", "event_signatures")


def _status(report, check_id: str) -> str:
    matches = [c for c in report.checks if c.id == check_id]
    assert matches, f"no {check_id} check in {[c.id for c in report.checks]}"
    return matches[0].status.value


def _detail(report, check_id: str) -> str:
    return next(c for c in report.checks if c.id == check_id).detail


def _verify(builder, components, *, roots: bool = True):
    return verify_package(
        components,
        anchor=builder.anchor(),
        trust_source=TrustSource.SUPPLIED_ANCHOR,
        observer_anchors=[builder.observer_anchor(), builder.minotaur_anchor()],
        tsa_roots=load_pem_certificates(builder.tsa.roots_pem) if roots else None,
    )


def _verify_anchor(export, builder):
    return verify_audit_anchor(
        export,
        anchor=builder.anchor(),
        trust_source=TrustSource.SUPPLIED_ANCHOR,
        tsa_roots=load_pem_certificates(builder.tsa.roots_pem),
    )


def _statuses(report) -> dict[str, str]:
    return {e["id"]: e["status"] for e in report.provenance_anchoring["entries"]}


def _without(builder, *indexes: int) -> dict[str, Any]:
    """A key holder withholds anchors and re-signs a consistent manifest."""
    builder.anchors = [a for i, a in enumerate(builder.anchors) if i not in indexes]
    return builder.components()


# ---------------------------------------------------------------------------
# The happy path
# ---------------------------------------------------------------------------


def test_valid_1_5_package_passes(chained_builder):
    components = chained_builder.components()
    manifest = components["manifest.json"]
    assert manifest["package_version"] == "1.5"
    assert manifest["anchor_count"] == 4
    assert manifest["anchor_head_digest"] == chained_builder.anchors[-1]["anchor_digest"]

    report = _verify(chained_builder, components)
    assert report.verified, report.to_text()
    assert _status(report, "provenance_anchoring") == "pass"
    pa = report.provenance_anchoring
    assert (pa["anchor_count"], pa["anchored"], pa["not_yet_anchored"], pa["missing"]) == (
        4, 11, 0, 0
    )
    assert pa["unanchored"] == 0 and pa["anchor_unverified"] == 0
    assert pa["package_version"] == "1.5"
    assert pa["chain_unbroken"] is True and pa["chain_breaks"] == []
    assert pa["anchor_head_digest"] == chained_builder.anchors[-1]["anchor_digest"]
    assert [a["linked"] for a in pa["anchors"]] == [None, True, True, True]
    assert all(a["records"] == "provenance" for a in pa["anchors"])
    # Skipped, never passed.
    assert all(a["event_checks"] == "skipped" for a in pa["anchors"])
    detail = _detail(report, "provenance_anchoring")
    assert "11 of 11 provenance entries anchored" in detail
    assert "chain unbroken across 4 anchors" in detail
    assert "event checks skipped" in detail


def test_records_are_tenant_wide(chained_builder):
    """Another agent's entry is in the anchor, so the root reproduces."""
    first = chained_builder.anchors[0]
    agents = {r["agent_id"] for r in first["provenance"]}
    assert len(agents) == 2
    report = _verify(chained_builder, chained_builder.components())
    assert report.provenance_anchoring["anchors"][0]["verified"]
    assert len(report.provenance_anchoring["entries"]) == 11


def test_report_json_round_trips(chained_builder):
    body = _verify(chained_builder, chained_builder.components()).to_dict()
    pa = json.loads(json.dumps(body))["provenance_anchoring"]
    assert set(pa) == {
        "anchor_count", "anchored", "not_yet_anchored", "missing", "unanchored",
        "anchor_unverified", "anchors", "entries", "package_version",
        "anchor_head_digest", "chain_unbroken", "chain_breaks",
    }
    assert set(pa["anchors"][0]) == {
        "anchor_id", "schema", "period_start", "period_end", "anchor_digest",
        "provenance_count", "verified", "failed_checks", "signature", "tsa_gen_time",
        "tsa_chain", "records", "previous_anchor_digest", "event_checks", "linked",
    }


def test_zip_round_trip(chained_builder):
    components = load_package_from_bytes(chained_builder.zip_bytes())
    report = _verify(chained_builder, components)
    assert report.verified, report.to_text()


def test_empty_anchors_in_1_5_is_not_yet_anchored_and_passes():
    builder = ChainedAuthorityPackageBuilder()
    builder.anchors = []
    components = builder.components()
    assert components["manifest.json"]["anchor_count"] == 0
    assert components["manifest.json"]["anchor_head_digest"] is None
    report = _verify(builder, components)
    assert report.verified, report.to_text()
    assert _status(report, "provenance_anchoring") == "pass"
    pa = report.provenance_anchoring
    assert pa["not_yet_anchored"] == 11 and pa["anchored"] == 0
    assert pa["chain_unbroken"] is True and pa["anchor_head_digest"] is None


def test_entries_before_the_first_anchor_are_unanchored_not_failed():
    """v3 anchoring began after the agent's first entries: reported, never a failure."""
    builder = ChainedAuthorityPackageBuilder(
        periods=[
            (BASE + timedelta(minutes=3), BASE + timedelta(minutes=7)),
            (BASE + timedelta(minutes=7), BASE + timedelta(minutes=11)),
            (BASE + timedelta(minutes=11), BASE + timedelta(minutes=15)),
        ]
    )
    report = _verify(builder, builder.components())
    assert report.verified, report.to_text()
    assert _status(report, "provenance_anchoring") == "pass"
    statuses = _statuses(report)
    assert [statuses[f"prov-{i:04d}"] for i in range(3)] == ["unanchored"] * 3
    assert report.provenance_anchoring["anchored"] == 8


def test_entries_after_the_head_are_not_yet_anchored():
    """The run ends at the newest sealed anchor when none starts after the last entry.

    Entry 8 is at 11:08:00.000088, after the last period's end (11:08) but
    before that anchor was sealed (11:08:04): the normal race at a period
    boundary, still not yet anchored.
    """
    builder = ChainedAuthorityPackageBuilder(
        periods=[
            (BASE, BASE + timedelta(minutes=5)),
            (BASE + timedelta(minutes=5), BASE + timedelta(minutes=8)),
        ]
    )
    report = _verify(builder, builder.components())
    assert report.verified, report.to_text()
    statuses = _statuses(report)
    assert [statuses[f"prov-{i:04d}"] for i in (8, 9, 10)] == ["not_yet_anchored"] * 3
    assert builder.anchors[-1]["sealed_at"] > builder.entries[8]["timestamp"]


# ---------------------------------------------------------------------------
# A withheld anchor fails
# ---------------------------------------------------------------------------


def test_anchor_dropped_from_the_middle_breaks_the_chain(chained_builder):
    report = _verify(chained_builder, _without(chained_builder, 1))
    assert not report.verified
    assert _status(report, "provenance_anchoring") == "fail"
    detail = _detail(report, "provenance_anchoring")
    assert (
        "anchor chain broken between 2026-10-15T11:04:00.000000+00:00 and "
        "2026-10-15T11:07:00.000000+00:00: an anchor is missing"
    ) in detail
    pa = report.provenance_anchoring
    assert pa["chain_unbroken"] is False
    assert pa["chain_breaks"] == [
        {
            "after_anchor_id": "anchor-1100",
            "before_anchor_id": "anchor-1107",
            "period_end": "2026-10-15T11:04:00.000000+00:00",
            "period_start": "2026-10-15T11:07:00.000000+00:00",
        }
    ]
    assert [a["linked"] for a in pa["anchors"]] == [None, False, True]
    # The entries of the withheld period are missing as well.
    statuses = _statuses(report)
    assert [statuses[f"prov-{i:04d}"] for i in (4, 5, 6)] == ["missing"] * 3
    # Every anchor that IS present still verifies on its own.
    assert all(a["verified"] for a in pa["anchors"])


def test_anchor_sealing_the_last_entry_dropped_fails(chained_builder):
    """The following (empty) anchor is still included, so its back-pointer betrays it."""
    report = _verify(chained_builder, _without(chained_builder, 2))
    assert not report.verified
    assert _status(report, "provenance_anchoring") == "fail"
    assert "anchor chain broken between 2026-10-15T11:07:00.000000+00:00" in _detail(
        report, "provenance_anchoring"
    )
    statuses = _statuses(report)
    assert statuses["prov-0010"] == "missing"
    assert report.provenance_anchoring["missing"] == 4


def test_first_anchor_predecessor_is_not_checked(chained_builder):
    """The run starts inside the chain; its first back-pointer leaves the span."""
    builder = ChainedAuthorityPackageBuilder(
        periods=[
            (BASE - timedelta(minutes=4), BASE),
            (BASE, BASE + timedelta(minutes=11)),
            (BASE + timedelta(minutes=11), BASE + timedelta(minutes=15)),
        ]
    )
    components = _without(builder, 0)
    assert builder.anchors[0]["previous_anchor_digest"]
    report = _verify(builder, components)
    assert report.verified, report.to_text()


def test_anchors_out_of_order_break_the_chain(chained_builder):
    chained_builder.anchors[1], chained_builder.anchors[2] = (
        chained_builder.anchors[2], chained_builder.anchors[1]
    )
    report = _verify(chained_builder, chained_builder.components())
    assert _status(report, "provenance_anchoring") == "fail"
    assert "anchor chain broken" in _detail(report, "provenance_anchoring")


def test_wrong_anchor_head_digest_fails(chained_builder):
    chained_builder.manifest_overrides["anchor_head_digest"] = chained_builder.anchors[2][
        "anchor_digest"
    ]
    report = _verify(chained_builder, chained_builder.components())
    assert _status(report, "signature") == "pass"
    assert _status(report, "provenance_anchoring") == "fail"
    assert "anchor_head_digest" in _detail(report, "provenance_anchoring")


def test_wrong_anchor_count_fails(chained_builder):
    chained_builder.manifest_overrides["anchor_count"] = 5
    report = _verify(chained_builder, chained_builder.components())
    assert _status(report, "provenance_anchoring") == "fail"
    assert "anchor_count 5" in _detail(report, "provenance_anchoring")


def test_missing_anchor_head_digest_fails(chained_builder):
    chained_builder.extra_manifest = lambda data_files: {}  # type: ignore[method-assign]
    report = _verify(chained_builder, chained_builder.components())
    assert _status(report, "provenance_anchoring") == "fail"
    assert "states no anchor_head_digest" in _detail(report, "provenance_anchoring")


def test_empty_run_with_a_head_digest_fails():
    builder = ChainedAuthorityPackageBuilder()
    head = builder.anchors[-1]["anchor_digest"]
    builder.anchors = []
    builder.manifest_overrides["anchor_head_digest"] = head
    report = _verify(builder, builder.components())
    assert _status(report, "provenance_anchoring") == "fail"


def test_head_dropped_without_resigning_fails(chained_builder):
    """Edit anchors.json after signing: the digest, count and head all disagree."""
    components = chained_builder.components()
    components["anchors.json"]["anchors"].pop()
    report = _verify(chained_builder, components)
    assert not report.verified
    assert _status(report, "file_digests") == "fail"
    detail = _detail(report, "provenance_anchoring")
    assert "anchor_count 4" in detail and "anchor_head_digest" in detail


def test_entry_in_a_gap_between_chained_anchors_is_missing():
    """The chain is unbroken, but 11:04-11:05 was sealed by no anchor: backdated."""
    builder = ChainedAuthorityPackageBuilder(
        periods=[
            (BASE, BASE + timedelta(minutes=4)),
            (BASE + timedelta(minutes=5), BASE + timedelta(minutes=11)),
            (BASE + timedelta(minutes=11), BASE + timedelta(minutes=15)),
        ]
    )
    report = _verify(builder, builder.components())
    assert not report.verified
    assert _status(report, "provenance_anchoring") == "fail"
    pa = report.provenance_anchoring
    assert pa["chain_unbroken"] is True
    entry = next(e for e in pa["entries"] if e["id"] == "prov-0004")
    assert entry["status"] == "missing"
    assert "backdated" in entry["reason"]
    assert pa["missing"] == 1 and pa["anchored"] == 10
    assert "prov-0004" in _detail(report, "provenance_anchoring")


def test_1_4_withheld_anchor_still_only_warns():
    """A withheld anchor in a 1.4 package keeps the AG-4 warning, not a failure."""
    builder = AnchoredAuthorityPackageBuilder()
    builder.anchors = [builder.anchors[1]]
    report = _verify(builder, builder.components())
    assert _status(report, "provenance_anchoring") == "warn"


def test_1_4_report_keeps_its_ag4_shape(anchored_builder):
    pa = _verify(anchored_builder, anchored_builder.components()).provenance_anchoring
    assert set(pa) == {
        "anchor_count", "anchored", "not_yet_anchored", "missing", "unanchored",
        "anchor_unverified", "anchors", "entries",
    }
    assert "linked" not in pa["anchors"][0]


def test_non_v3_anchor_in_a_1_5_run_fails(chained_builder):
    chained_builder.anchors[1]["schema"] = "behavry.audit_anchor.v2"
    report = _verify(chained_builder, chained_builder.components())
    assert _status(report, "provenance_anchoring") == "fail"
    assert "v3 anchors only" in _detail(report, "provenance_anchoring")


# ---------------------------------------------------------------------------
# Provenance-only records: event checks skipped, never passed
# ---------------------------------------------------------------------------


def test_provenance_only_record_skips_event_checks(chained_builder):
    export = chained_builder.anchors[0]
    assert "events" not in export and export["records"] == "provenance"
    report = _verify_anchor(export, chained_builder)
    assert report.verified, report.to_text()
    for check_id in EVENT_CHECKS:
        assert _status(report, check_id) == "skipped", check_id
        assert _detail(report, check_id) == EVENT_CHECKS_SKIPPED_REASON
    for check_id in ("anchor_digest", "signature", "provenance_root", "tsa_imprint"):
        assert _status(report, check_id) == "pass", check_id
    assert report.anchor_summary["records"] == "provenance"


def test_provenance_only_record_still_signs_the_event_fields(chained_builder):
    export = copy.deepcopy(chained_builder.anchors[0])
    export["event_count"] = 7
    report = _verify_anchor(export, chained_builder)
    assert not report.verified
    assert _status(report, "anchor_digest") == "fail"
    assert _status(report, "event_count") == "skipped"


def test_full_record_without_events_still_fails(chained_builder):
    export = copy.deepcopy(chained_builder.anchors[0])
    del export["records"]
    assert _status(_verify_anchor(export, chained_builder), "merkle_root") == "fail"


def test_provenance_only_is_v3_only(chained_builder):
    export = copy.deepcopy(chained_builder.anchors[0])
    export["schema"] = "behavry.audit_anchor.v2"
    report = _verify_anchor(export, chained_builder)
    assert not report.verified
    assert _status(report, "anchor_format") == "fail"


def test_unknown_records_kind_is_checked_as_a_full_record(chained_builder):
    export = copy.deepcopy(chained_builder.anchors[0])
    export["records"] = "summaries"
    report = _verify_anchor(export, chained_builder)
    assert _status(report, "anchor_format") == "warn"
    assert _status(report, "merkle_root") == "fail"


def test_cli_audit_anchor_says_event_checks_were_skipped(tmp_path, chained_builder, capsys):
    path = tmp_path / "anchor.json"
    path.write_text(json.dumps(chained_builder.anchors[0]))
    trust = tmp_path / "trust.json"
    trust.write_text(json.dumps(chained_builder.anchor()))
    roots = tmp_path / "roots.pem"
    roots.write_bytes(chained_builder.tsa.roots_pem)
    code = main(
        ["--audit-anchor", str(path), "--trust-anchor", str(trust), "--tsa-roots", str(roots)]
    )
    out = capsys.readouterr().out
    assert code == 0, out
    assert "event records are not carried" in out
    assert "Records carried" in out


# ---------------------------------------------------------------------------
# AG5-CONTRACTS section 3: device_bound is informational
# ---------------------------------------------------------------------------


class _DeviceBoundBuilder(ChainedAuthorityPackageBuilder):
    """Entry 11 is a ``device_bound`` entry at 11:10:30, inside the third anchor."""

    def _make_provenance(self) -> list[dict[str, Any]]:
        from behavry_verify.jcs import content_digest

        entries = super()._make_provenance()
        body = {
            "from": None,
            "to": "device-7",
            "client_type": {"from": None, "to": "claude_desktop"},
        }
        entry = {
            "id": "prov-0011",
            "agent_id": entries[-1]["agent_id"],
            "tenant_id": self.tenant_id,
            "timestamp": (BASE + timedelta(minutes=10, seconds=30)).isoformat(),
            "entry_type": "device_bound",
            "actor": "system",
            "summary": "Agent bound to device build-host-7",
            "body": body,
            "body_digest": content_digest(body),
            "evidence_refs": [],
            "previous_hash": entries[-1]["entry_hash"],
            "signer_kid": self.kid,
        }
        self.seal_entry(entry)
        return [*entries, entry]


@pytest.mark.parametrize("version", ["1.4", "1.5"])
def test_device_bound_entry_is_informational(version):
    builder = _DeviceBoundBuilder()
    builder.authority_version = version
    plain = ChainedAuthorityPackageBuilder()
    plain.authority_version = version
    report = _verify(builder, builder.components())
    baseline = _verify(plain, plain.components())

    assert report.verified, report.to_text()
    assert _status(report, "provenance") == "pass"
    assert _status(report, "assessments") == "pass"
    assert _status(report, "provenance_anchoring") == "pass"
    assert _statuses(report)["prov-0011"] == "anchored"
    # The lifecycle line neither gains nor loses an element for it.
    assert _status(report, "lifecycle") == "info"
    assert report.lifecycle == baseline.lifecycle
    assert _detail(report, "lifecycle") == _detail(baseline, "lifecycle")
    assert "device" not in _detail(report, "lifecycle")


def test_truncated_tail_under_a_resigned_manifest_is_a_known_limit(chained_builder):
    """What 1.5 does NOT close: a key holder drops the newest anchors and re-signs.

    The run then ends early, its head digest is consistent, and the entries
    after it read as not yet anchored. Only the head of the producer's WORM
    store, fetched independently, closes this. Pinned here so a change in
    behaviour is a decision, not an accident.
    """
    report = _verify(chained_builder, _without(chained_builder, 2, 3))
    assert _status(report, "provenance_anchoring") == "pass"
    statuses = _statuses(report)
    assert [statuses[f"prov-{i:04d}"] for i in range(7, 11)] == ["not_yet_anchored"] * 4
