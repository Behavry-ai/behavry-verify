"""Gaps between held anchor heads (Behavry Sprint AG-9, item M-4).

Every v2 and v3 anchor signs ``previous_anchor_digest``, so the heads an
auditor holds, in ``period_start`` order, must link. ``collect-heads`` checks
the chain across its folder after collecting, and ``--anchor-heads-dir``
checks each folder's verified heads under check 15. See
``docs/strategy/AG9-CONTRACTS.md`` section 5 in the Behavry repo.
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest

from behavry_verify.audit_anchor import (
    ANCHOR_SCHEMA_V1,
    ANCHOR_SCHEMA_V2,
    ANCHOR_SCHEMA_V3,
    find_head_gaps,
)
from behavry_verify.cli import main
from behavry_verify.collect import head_file_name
from tests.conftest import PredecessorAuthorityPackageBuilder, header_only
from tests.test_collect_heads import TOKEN, FeedServer, _package_args

# ---------------------------------------------------------------------------
# find_head_gaps on plain records (signatures are not its business)
# ---------------------------------------------------------------------------


def _head(
    n: int, previous: str | None, *, schema: str = ANCHOR_SCHEMA_V3, digest: str | None = None
) -> dict[str, Any]:
    return {
        "schema": schema,
        "anchor_id": f"anchor-{n}",
        "period_start": f"2026-10-15T11:{n:02d}:00.000000+00:00",
        "period_end": f"2026-10-15T11:{n + 1:02d}:00.000000+00:00",
        "anchor_digest": digest or f"d{n}",
        "previous_anchor_digest": previous,
    }


def _chain(count: int, first_previous: str | None = None) -> list[dict[str, Any]]:
    heads = [_head(0, first_previous)]
    for n in range(1, count):
        heads.append(_head(n, heads[-1]["anchor_digest"]))
    return heads


def test_a_complete_chain_has_no_gap():
    assert find_head_gaps(_chain(5)) == []


def test_order_comes_from_period_start_not_the_input():
    heads = _chain(5)
    assert find_head_gaps(list(reversed(heads))) == []


def test_a_withheld_middle_head_is_a_gap_naming_both_heads():
    heads = _chain(5)
    del heads[2]
    gaps = find_head_gaps(heads)
    assert len(gaps) == 1
    gap = gaps[0]
    assert gap["earlier_anchor_id"] == "anchor-1"
    assert gap["later_anchor_id"] == "anchor-3"
    assert gap["earlier_period_start"] == heads[1]["period_start"]
    assert gap["later_period_start"] == heads[2]["period_start"]
    assert gap["later_previous_anchor_digest"] == "d2"
    assert gap["names_held_anchor_id"] is None


def test_the_first_held_head_starts_a_segment_whatever_it_points_at():
    # The tenant's chain began long before: d-old is not held, and need not be.
    assert find_head_gaps(_chain(3, first_previous="d-old")) == []


def test_identical_digests_count_once():
    heads = _chain(4)
    assert find_head_gaps([*heads, *(dict(h) for h in heads)]) == []


def test_v1_heads_start_segments_and_are_never_gaps():
    # v1 carries no back-pointer: a v1 run with holes in it shows no gap, and
    # the first v2 head after it starts the chain.
    v1 = [_head(n, None, schema=ANCHOR_SCHEMA_V1) for n in (0, 2, 5)]
    v2 = _head(7, None, schema=ANCHOR_SCHEMA_V2)
    v3 = _head(8, "d7")
    assert find_head_gaps([*v1, v2, v3]) == []


def test_a_v1_head_ignores_a_stray_previous_anchor_digest():
    # v1 does not sign the field, so whatever it holds proves nothing.
    heads = [_head(0, None), _head(3, "not-signed", schema=ANCHOR_SCHEMA_V1)]
    assert find_head_gaps(heads) == []


@pytest.mark.parametrize("empty", [None, ""])
def test_a_null_previous_digest_starts_a_new_segment(empty):
    heads = [*_chain(2), _head(5, empty), _head(6, "d5")]
    assert find_head_gaps(heads) == []


def test_a_pointer_to_a_held_head_that_is_not_the_one_before_is_a_gap():
    heads = _chain(4)
    heads[3]["previous_anchor_digest"] = "d1"
    gaps = find_head_gaps(heads)
    assert [(g["earlier_anchor_id"], g["later_anchor_id"]) for g in gaps] == [
        ("anchor-2", "anchor-3")
    ]
    assert gaps[0]["names_held_anchor_id"] == "anchor-1"


def test_every_gap_is_reported():
    heads = _chain(8)
    del heads[5]
    del heads[2]
    gaps = find_head_gaps(heads)
    assert [(g["earlier_anchor_id"], g["later_anchor_id"]) for g in gaps] == [
        ("anchor-1", "anchor-3"),
        ("anchor-4", "anchor-6"),
    ]


def test_a_fork_is_not_reported_again_as_a_gap():
    # anchor-2 and its fork share a period. The fork points elsewhere, the
    # genuine one links, and anchor-3 links to the genuine one: no gap (H2b
    # reports the fork itself).
    heads = _chain(4)
    fork = _head(2, "d-elsewhere", digest="d2-fork")
    assert find_head_gaps([*heads, fork]) == []
    # anchor-3 linking to the forked side instead is no gap either.
    heads[3]["previous_anchor_digest"] = "d2-fork"
    assert find_head_gaps([*heads, fork]) == []


def test_a_gap_before_a_fork_is_reported_once():
    heads = _chain(5)
    del heads[2]  # anchor-3 now follows anchor-1
    fork = _head(3, "d-elsewhere", digest="d3-fork")
    gaps = find_head_gaps([*heads, fork])
    assert len(gaps) == 1
    assert (gaps[0]["earlier_anchor_id"], gaps[0]["later_anchor_id"]) == (
        "anchor-1", "anchor-3",
    )


def test_heads_without_a_readable_period_start_are_left_out():
    heads = _chain(3)
    junk = {"anchor_id": "x", "period_start": "yesterday", "anchor_digest": "dx"}
    assert find_head_gaps([*heads, junk, "not a record"]) == []  # type: ignore[list-item]


# ---------------------------------------------------------------------------
# --anchor-heads-dir: a gap fails check 15
# ---------------------------------------------------------------------------


@pytest.fixture
def builder() -> PredecessorAuthorityPackageBuilder:
    return PredecessorAuthorityPackageBuilder()


def _tenant_heads(builder: PredecessorAuthorityPackageBuilder) -> list[dict[str, Any]]:
    """predecessor, the four run anchors, and one sealed after the run."""
    after = builder.seal_after(1)
    return [builder.predecessor, *(header_only(a) for a in [*builder.anchors, *after])]


def _folder(tmp_path: Path, heads: list[dict[str, Any]], name: str = "heads") -> Path:
    folder = tmp_path / name
    folder.mkdir()
    for head in heads:
        (folder / head_file_name(head)).write_text(json.dumps(head))
    return folder


def _verify_json(args: list[str], capsys) -> tuple[int, dict[str, Any]]:
    capsys.readouterr()
    code = main([*args, "--json"])
    return code, json.loads(capsys.readouterr().out)


def _check(body: dict[str, Any], check_id: str = "provenance_anchoring") -> dict[str, Any]:
    return next(c for c in body["checks"] if c["id"] == check_id)


def test_complete_folder_passes_with_no_gap(tmp_path, builder, capsys):
    folder = _folder(tmp_path, _tenant_heads(builder))
    code, body = _verify_json(
        [*_package_args(tmp_path, builder), "--anchor-heads-dir", str(folder)], capsys
    )
    assert code == 0
    assert body["provenance_anchoring"]["head_gaps"] == []
    assert "link, with no gap" in _check(body)["detail"]


def test_folder_with_a_withheld_middle_head_fails_the_package(tmp_path, builder, capsys):
    heads = _tenant_heads(builder)
    withheld = heads.pop(3)  # run anchor 2 of 0..3; the package itself is complete
    folder = _folder(tmp_path, heads)
    args = [*_package_args(tmp_path, builder), "--anchor-heads-dir", str(folder)]
    code, body = _verify_json(args, capsys)
    assert code == 1
    assert body["verified"] is False
    gaps = body["provenance_anchoring"]["head_gaps"]
    assert len(gaps) == 1
    gap = gaps[0]
    assert gap["folder"] == str(folder)
    assert gap["earlier_anchor_id"] == heads[2]["anchor_id"]
    assert gap["later_anchor_id"] == heads[3]["anchor_id"]
    assert gap["later_previous_anchor_digest"] == withheld["anchor_digest"]
    check = _check(body)
    assert check["status"] == "fail"
    assert "cannot vouch for completeness" in check["detail"]
    assert heads[2]["anchor_id"] in check["detail"] and heads[3]["anchor_id"] in check["detail"]
    # The text report names both heads too.
    capsys.readouterr()
    assert main(args) == 1
    text = capsys.readouterr().out
    assert "Head gap" in text and heads[3]["period_start"] in text


def test_the_same_heads_as_separate_anchor_head_files_are_not_checked_for_gaps(
    tmp_path, builder, capsys
):
    # Separate heads are usually a sparse sample: only a folder must link.
    heads = _tenant_heads(builder)
    del heads[3]
    folder = _folder(tmp_path, heads)
    files = [arg for p in sorted(folder.glob("*.json")) for arg in ("--anchor-head", str(p))]
    code, body = _verify_json([*_package_args(tmp_path, builder), *files], capsys)
    assert code == 0
    assert "head_gaps" not in body["provenance_anchoring"]


def test_each_folder_is_checked_on_its_own(tmp_path, builder, capsys):
    # Two folders that each link, one holding the older heads and one the
    # newer: no gap, though neither alone covers the chain.
    heads = _tenant_heads(builder)
    older = _folder(tmp_path, heads[:3], "older")
    newer = _folder(tmp_path, heads[4:], "newer")
    code, body = _verify_json(
        [*_package_args(tmp_path, builder), "--anchor-heads-dir", str(older),
         "--anchor-heads-dir", str(newer)],
        capsys,
    )
    assert code == 0
    assert body["provenance_anchoring"]["head_gaps"] == []


def test_a_fork_in_the_folder_is_a_fork_not_a_gap(tmp_path, builder, capsys):
    heads = _tenant_heads(builder)
    run = builder.anchors
    fork = header_only(builder.seal_record(
        datetime.fromisoformat(run[3]["period_start"]),
        datetime.fromisoformat(run[3]["period_end"]),
        run[1]["anchor_digest"],
    ))
    fork = builder.reseal({**fork, "anchor_id": "zz-forked-anchor"})
    folder = _folder(tmp_path, [*heads, fork])
    code, body = _verify_json(
        [*_package_args(tmp_path, builder), "--anchor-heads-dir", str(folder)], capsys
    )
    assert code == 1
    pa = body["provenance_anchoring"]
    assert pa["forks"]
    assert pa["head_gaps"] == []


def test_a_fork_and_a_gap_are_both_reported(tmp_path, builder, capsys):
    heads = _tenant_heads(builder)
    run = builder.anchors
    fork = builder.reseal({
        **header_only(builder.seal_record(
            datetime.fromisoformat(run[3]["period_start"]),
            datetime.fromisoformat(run[3]["period_end"]),
            run[1]["anchor_digest"],
        )),
        "anchor_id": "zz-forked-anchor",
    })
    del heads[2]  # run anchor 1: run anchor 2 no longer links
    folder = _folder(tmp_path, [*heads, fork])
    code, body = _verify_json(
        [*_package_args(tmp_path, builder), "--anchor-heads-dir", str(folder)], capsys
    )
    assert code == 1
    pa = body["provenance_anchoring"]
    assert pa["forks"]
    assert [(g["earlier_anchor_id"], g["later_anchor_id"]) for g in pa["head_gaps"]] == [
        (heads[1]["anchor_id"], heads[2]["anchor_id"])
    ]


def test_an_unverified_head_cannot_bridge_a_gap(tmp_path, builder, capsys):
    heads = _tenant_heads(builder)
    tampered = dict(heads[3])
    tampered["signature"] = heads[2]["signature"]  # no longer verifies
    heads[3] = tampered
    folder = _folder(tmp_path, heads)
    code, body = _verify_json(
        [*_package_args(tmp_path, builder), "--anchor-heads-dir", str(folder)], capsys
    )
    assert code == 1
    gaps = body["provenance_anchoring"]["head_gaps"]
    assert [(g["earlier_anchor_id"], g["later_anchor_id"]) for g in gaps] == [
        (heads[2]["anchor_id"], heads[4]["anchor_id"])
    ]


# ---------------------------------------------------------------------------
# collect-heads: the chain across the folder after collecting
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def token_env(monkeypatch):
    monkeypatch.setenv("BEHAVRY_TOKEN", TOKEN)


def _collect(feed: FeedServer, out: Path, *extra: str) -> int:
    return main(["collect-heads", "--base-url", feed.url, "--out", str(out), *extra])


def test_collect_reports_that_a_complete_folder_links(tmp_path, builder, capsys):
    out = tmp_path / "heads"
    with FeedServer(_tenant_heads(builder)) as feed:
        assert _collect(feed, out) == 0
    text = capsys.readouterr().out
    assert "the 6 head(s)" in text and "link, no gap" in text


def test_collect_where_the_feed_skips_a_head_exits_1_naming_both(tmp_path, builder, capsys):
    heads = _tenant_heads(builder)
    skipped = heads[3]
    out = tmp_path / "heads"
    with FeedServer([h for h in heads if h is not skipped]) as feed:
        assert _collect(feed, out) == 1
    text = capsys.readouterr().out
    assert "1 GAP(S)" in text
    earlier, later = heads[2], heads[4]
    for name in ("anchor_id", "period_start"):
        assert earlier[name] in text and later[name] in text
    assert "CONFLICT" not in text and "5 new head(s)" in text
    # A later run that obtains the withheld head closes the gap.
    with FeedServer(heads) as feed:
        assert _collect(feed, out, "--since", heads[0]["period_start"]) == 0
    text = capsys.readouterr().out
    assert "GAP" not in text and "link, no gap" in text


def test_collect_checks_the_whole_folder_not_only_this_run(tmp_path, builder, capsys):
    heads = _tenant_heads(builder)
    out = tmp_path / "heads"
    with FeedServer(heads[:3]) as feed:
        assert _collect(feed, out) == 0
    # The feed now resumes past a withheld head: what this run fetched links
    # within itself, but not to what the folder already held.
    with FeedServer(heads[4:]) as feed:
        assert _collect(feed, out) == 1
    assert "GAP" in capsys.readouterr().out


def test_a_fresh_folder_started_with_since_starts_its_own_segment(tmp_path, builder, capsys):
    heads = _tenant_heads(builder)
    out = tmp_path / "heads"
    with FeedServer(heads) as feed:
        assert _collect(feed, out, "--since", heads[2]["period_start"]) == 0
    assert "link, no gap" in capsys.readouterr().out
