"""Collecting anchor heads (Behavry Sprint AG-8, item L-2).

``behavry-verify collect-heads`` pages a tenant's heads feed into a directory,
and ``--anchor-heads-dir`` reads that directory back as ``--anchor-head``
files, offline. See ``docs/strategy/AG8-CONTRACTS.md`` section 3 in the
Behavry repo.

The feed here is a real HTTP server on loopback (``http.server`` in a thread)
serving genuine signed header-only records from the 0.6/0.7 fixtures.
"""
from __future__ import annotations

import copy
import gzip
import json
import threading
from collections.abc import Iterator
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

import pytest

from behavry_verify.cli import main
from behavry_verify.collect import HEADS_PATH, PAGE_LIMIT, head_file_name
from tests.conftest import PredecessorAuthorityPackageBuilder, header_only

TOKEN = "s3cret-test-token-do-not-print"


class FeedServer:
    """A stub ``GET /api/v1/audit/anchors/heads``, with AG7-CONTRACTS section 2 paging."""

    def __init__(self, heads: list[dict[str, Any]], *, page_size: int = 2) -> None:
        self.heads = heads
        self.page_size = page_size
        self.requests: list[dict[str, Any]] = []
        self.status = 200
        self.redirect_to: str | None = None
        feed = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                url = urlparse(self.path)
                query = {k: v[0] for k, v in parse_qs(url.query).items()}
                feed.requests.append(
                    {"path": url.path, "query": query,
                     "authorization": self.headers.get("Authorization")}
                )
                if feed.redirect_to is not None:
                    self.send_response(302)
                    self.send_header("Location", feed.redirect_to)
                    self.end_headers()
                    return
                if url.path != HEADS_PATH or feed.status != 200:
                    self._send(feed.status if feed.status != 200 else 404, {"detail": "no"})
                    return
                if self.headers.get("Authorization") != f"Bearer {TOKEN}":
                    self._send(401, {"detail": "unauthorized"})
                    return
                body = feed.page(query.get("since"), int(query.get("limit", "100")))
                self._send(200, body)

            def _send(self, status: int, body: Any) -> None:
                data = json.dumps(body).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args: Any) -> None:
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def page(self, since: str | None, limit: int) -> dict[str, Any]:
        ordered = sorted(self.heads, key=lambda h: datetime.fromisoformat(h["period_start"]))
        if since is not None:
            after = datetime.fromisoformat(since)
            ordered = [h for h in ordered if datetime.fromisoformat(h["period_start"]) > after]
        page = ordered[: min(limit, self.page_size)]
        return {"heads": page, "next_since": page[-1]["period_start"] if page else None}

    def __enter__(self) -> FeedServer:
        self.thread.start()
        return self

    def __exit__(self, *exc: Any) -> None:
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def builder() -> PredecessorAuthorityPackageBuilder:
    return PredecessorAuthorityPackageBuilder()


def _heads(builder: PredecessorAuthorityPackageBuilder) -> list[dict[str, Any]]:
    """The tenant's heads in feed order: predecessor, the run, one sealed after it."""
    after = builder.seal_after(1)
    return [builder.predecessor, *(header_only(a) for a in [*builder.anchors, *after])]


@pytest.fixture
def feed(builder) -> Iterator[FeedServer]:
    with FeedServer(_heads(builder)) as server:
        yield server


@pytest.fixture(autouse=True)
def token_env(monkeypatch):
    monkeypatch.setenv("BEHAVRY_TOKEN", TOKEN)


def _collect(feed: FeedServer, out: Path, *extra: str) -> int:
    return main(["collect-heads", "--base-url", feed.url, "--out", str(out), *extra])


def _trust(tmp_path: Path, builder) -> Path:
    path = tmp_path / "trust.json"
    path.write_text(json.dumps(builder.anchor()))
    return path


def _stored(out: Path) -> dict[str, dict[str, Any]]:
    return {p.name: json.loads(p.read_text()) for p in sorted(out.glob("*.json"))}


# ---------------------------------------------------------------------------
# Paging, naming, token
# ---------------------------------------------------------------------------


def test_collects_every_page_and_names_files_by_period(tmp_path, feed, capsys):
    out = tmp_path / "heads"
    assert _collect(feed, out) == 0
    stored = _stored(out)
    assert len(stored) == len(feed.heads) == 6
    assert list(stored) == sorted(head_file_name(h) for h in feed.heads)
    for head in feed.heads:
        assert stored[head_file_name(head)] == head
    first = feed.heads[0]
    start = datetime.fromisoformat(first["period_start"])
    expected = f"{start.strftime('%Y%m%dT%H%M%SZ')}-{first['anchor_id'][:8]}.json"
    assert head_file_name(first) == expected
    # 6 heads at 2 a page: three pages, then the empty page that ends it.
    assert len(feed.requests) == 4
    assert all(r["query"]["limit"] == str(PAGE_LIMIT) for r in feed.requests)
    assert "since" not in feed.requests[0]["query"]
    assert [r["query"]["since"] for r in feed.requests[1:]] == [
        feed.heads[1]["period_start"], feed.heads[3]["period_start"],
        feed.heads[5]["period_start"],
    ]
    out_text = capsys.readouterr()
    assert "6 new head(s)" in out_text.out


def test_token_comes_from_the_environment_as_a_bearer_header(tmp_path, feed, capsys):
    assert _collect(feed, tmp_path / "a") == 0
    assert {r["authorization"] for r in feed.requests} == {f"Bearer {TOKEN}"}
    captured = capsys.readouterr()
    assert TOKEN not in captured.out + captured.err


def test_token_env_names_another_variable(tmp_path, feed, monkeypatch):
    monkeypatch.delenv("BEHAVRY_TOKEN")
    monkeypatch.setenv("TENANT_FEED_TOKEN", TOKEN)
    assert _collect(feed, tmp_path / "a", "--token-env", "TENANT_FEED_TOKEN") == 0
    assert len(_stored(tmp_path / "a")) == 6


def test_missing_token_is_a_usage_error(tmp_path, feed, monkeypatch, capsys):
    monkeypatch.delenv("BEHAVRY_TOKEN")
    assert _collect(feed, tmp_path / "a") == 2
    assert "BEHAVRY_TOKEN" in capsys.readouterr().err
    assert feed.requests == []


def test_token_is_never_accepted_on_the_command_line(tmp_path, feed):
    assert _collect(feed, tmp_path / "a", "--token", TOKEN) == 2
    assert feed.requests == []


def test_wrong_token_is_an_http_error_that_does_not_echo_it(tmp_path, feed, monkeypatch, capsys):
    monkeypatch.setenv("BEHAVRY_TOKEN", "wrong-token-value")
    assert _collect(feed, tmp_path / "a") == 2
    captured = capsys.readouterr()
    assert "HTTP 401" in captured.err
    assert "wrong-token-value" not in captured.out + captured.err


# ---------------------------------------------------------------------------
# Resume
# ---------------------------------------------------------------------------


def test_second_run_resumes_after_the_newest_stored_head(tmp_path, feed, capsys):
    out = tmp_path / "heads"
    assert _collect(feed, out) == 0
    feed.requests.clear()
    assert _collect(feed, out) == 0
    assert len(feed.requests) == 1
    assert feed.requests[0]["query"]["since"] == feed.heads[-1]["period_start"]
    assert "0 new head(s)" in capsys.readouterr().out


def test_resume_reads_period_start_from_content_not_file_names(tmp_path, builder):
    heads = _heads(builder)
    out = tmp_path / "heads"
    out.mkdir()
    # The newest stored head under a name that sorts first.
    (out / "aaaa.json").write_text(json.dumps(heads[3]))
    (out / "zzzz.json").write_text(json.dumps(heads[1]))
    with FeedServer(heads) as feed:
        assert _collect(feed, out) == 0
        assert feed.requests[0]["query"]["since"] == heads[3]["period_start"]
    names = set(_stored(out))
    assert names == {"aaaa.json", "zzzz.json", *(head_file_name(h) for h in heads[4:])}


def test_resume_picks_up_heads_sealed_since_the_last_run(tmp_path, builder):
    heads = _heads(builder)
    out = tmp_path / "heads"
    with FeedServer(heads[:4]) as feed:
        assert _collect(feed, out) == 0
    assert len(_stored(out)) == 4
    with FeedServer(heads) as feed:
        assert _collect(feed, out) == 0
        assert feed.requests[0]["query"]["since"] == heads[3]["period_start"]
    assert len(_stored(out)) == 6


def test_resume_reads_gzipped_heads_in_the_directory(tmp_path, builder):
    heads = _heads(builder)
    out = tmp_path / "heads"
    out.mkdir()
    (out / "worm.json.gz").write_bytes(gzip.compress(json.dumps(heads[4]).encode(), mtime=0))
    with FeedServer(heads) as feed:
        assert _collect(feed, out) == 0
        assert feed.requests[0]["query"]["since"] == heads[4]["period_start"]


def test_since_overrides_resume_and_counts_heads_already_present(tmp_path, feed, capsys):
    out = tmp_path / "heads"
    assert _collect(feed, out) == 0
    capsys.readouterr()
    feed.requests.clear()
    assert _collect(feed, out, "--since", feed.heads[2]["period_start"]) == 0
    assert feed.requests[0]["query"]["since"] == feed.heads[2]["period_start"]
    assert "3 already present" in capsys.readouterr().out


def test_bad_since_is_a_usage_error(tmp_path, feed):
    assert _collect(feed, tmp_path / "a", "--since", "yesterday") == 2
    assert feed.requests == []


def test_unreadable_file_in_out_is_a_usage_error(tmp_path, feed):
    out = tmp_path / "heads"
    out.mkdir()
    (out / "junk.json").write_text("not json")
    assert _collect(feed, out) == 2


# ---------------------------------------------------------------------------
# Conflicts
# ---------------------------------------------------------------------------


def test_stored_head_with_different_content_is_a_conflict_and_not_overwritten(
    tmp_path, feed, capsys
):
    out = tmp_path / "heads"
    assert _collect(feed, out) == 0
    target = out / head_file_name(feed.heads[2])
    altered = json.loads(target.read_text())
    altered["sealed_at"] = "2026-10-15T12:00:00+00:00"
    target.write_text(json.dumps(altered))
    before = target.read_bytes()
    capsys.readouterr()
    assert _collect(feed, out, "--since", feed.heads[0]["period_start"]) == 1
    assert target.read_bytes() == before
    out_text = capsys.readouterr().out
    assert "1 CONFLICT(S)" in out_text and str(target) in out_text
    assert "not overwritten" in out_text


def test_same_content_in_another_layout_is_not_a_conflict(tmp_path, feed):
    out = tmp_path / "heads"
    assert _collect(feed, out) == 0
    target = out / head_file_name(feed.heads[2])
    target.write_text(json.dumps(json.loads(target.read_text()), separators=(",", ":")))
    assert _collect(feed, out, "--since", feed.heads[0]["period_start"]) == 0


def test_fork_for_a_stored_period_is_a_conflict_and_not_saved(tmp_path, builder, capsys):
    heads = _heads(builder)
    out = tmp_path / "heads"
    with FeedServer(heads) as feed:
        assert _collect(feed, out) == 0
    run = builder.anchors
    fork = header_only(builder.seal_record(
        datetime.fromisoformat(run[2]["period_start"]),
        datetime.fromisoformat(run[2]["period_end"]),
        run[0]["anchor_digest"],
    ))
    # Another id too, so it would not even collide on the file name.
    fork = builder.reseal({**fork, "anchor_id": "zz-forked-anchor"})
    assert fork["period_start"] == run[2]["period_start"]
    capsys.readouterr()
    with FeedServer([fork]) as feed:
        assert _collect(feed, out, "--since", heads[0]["period_start"]) == 1
    assert head_file_name(fork) not in _stored(out)
    assert "two records for one period" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# --trust-anchor
# ---------------------------------------------------------------------------


def test_trust_anchor_verifies_and_saves_genuine_heads(tmp_path, builder, feed, capsys):
    out = tmp_path / "heads"
    assert _collect(feed, out, "--trust-anchor", str(_trust(tmp_path, builder))) == 0
    assert len(_stored(out)) == 6
    assert "6 new head(s) verified and saved" in capsys.readouterr().out


def test_trust_anchor_with_tsa_roots(tmp_path, builder, feed):
    roots = tmp_path / "roots.pem"
    roots.write_bytes(builder.tsa.roots_pem)
    out = tmp_path / "heads"
    assert _collect(feed, out, "--trust-anchor", str(_trust(tmp_path, builder)),
                    "--tsa-roots", str(roots)) == 0
    assert len(_stored(out)) == 6


def test_trust_anchor_rejects_a_tampered_head(tmp_path, builder, capsys):
    heads = _heads(builder)
    tampered = copy.deepcopy(heads[3])
    tampered["event_count"] = 99
    with FeedServer([*heads[:3], tampered, *heads[4:]]) as feed:
        out = tmp_path / "heads"
        assert _collect(feed, out, "--trust-anchor", str(_trust(tmp_path, builder))) == 1
    stored = _stored(out)
    assert head_file_name(tampered) not in stored
    assert len(stored) == 5
    text = capsys.readouterr().out
    assert "NOT VERIFIED, not saved" in text and "anchor_digest" in text


def test_trust_anchor_rejects_a_bad_signature(tmp_path, builder, capsys):
    heads = _heads(builder)
    bad = copy.deepcopy(heads[1])
    sig = bad["signature"]
    bad["signature"] = ("A" if sig[0] != "A" else "B") + sig[1:]
    with FeedServer([bad]) as feed:
        assert _collect(feed, tmp_path / "h", "--trust-anchor", str(_trust(tmp_path, builder))) == 1
    assert _stored(tmp_path / "h") == {}
    assert "signature" in capsys.readouterr().out


def test_without_trust_anchor_a_tampered_head_is_saved_unchecked(tmp_path, builder):
    heads = _heads(builder)
    tampered = copy.deepcopy(heads[3])
    tampered["event_count"] = 99
    with FeedServer([tampered]) as feed:
        assert _collect(feed, tmp_path / "h") == 0
    assert len(_stored(tmp_path / "h")) == 1


# ---------------------------------------------------------------------------
# Network and usage errors
# ---------------------------------------------------------------------------


def test_http_error_exits_2(tmp_path, feed, capsys):
    feed.status = 500
    assert _collect(feed, tmp_path / "a") == 2
    assert "HTTP 500" in capsys.readouterr().err


def test_unreachable_feed_exits_2(tmp_path, feed):
    url = feed.url
    feed.__exit__()
    assert main(["collect-heads", "--base-url", url, "--out", str(tmp_path / "a")]) == 2


def test_redirect_is_refused_so_the_token_goes_nowhere_else(tmp_path, builder):
    with FeedServer([]) as elsewhere, FeedServer(_heads(builder)) as feed:
        feed.redirect_to = f"{elsewhere.url}{HEADS_PATH}"
        assert _collect(feed, tmp_path / "a") == 2
        assert elsewhere.requests == []


def test_plain_http_is_refused_for_a_remote_host(tmp_path):
    assert main(["collect-heads", "--base-url", "http://behavry.example",
                 "--out", str(tmp_path / "a")]) == 2


def test_feed_that_does_not_advance_stops(tmp_path, builder):
    heads = _heads(builder)
    with FeedServer(heads) as feed:
        stuck = {"heads": heads[:1], "next_since": heads[0]["period_start"]}
        feed.page = lambda since, limit: stuck
        assert _collect(feed, tmp_path / "a", "--since", heads[0]["period_start"]) == 2
        assert len(feed.requests) == 1


def test_missing_required_arguments_exit_2(tmp_path):
    assert main(["collect-heads", "--out", str(tmp_path)]) == 2
    assert main(["collect-heads", "--base-url", "https://behavry.example"]) == 2


def test_flat_invocations_still_parse_without_a_subcommand(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    with pytest.raises(SystemExit) as exc:
        main(["--package", "x.zip"])  # no key: the flat parser's own usage error
    assert exc.value.code == 2


# ---------------------------------------------------------------------------
# --anchor-heads-dir (offline package verification)
# ---------------------------------------------------------------------------


def _package_args(tmp_path: Path, builder) -> list[str]:
    package = tmp_path / "authority.zip"
    package.write_bytes(builder.zip_bytes())
    observers = tmp_path / "observers.json"
    observers.write_text(json.dumps([builder.observer_anchor(), builder.minotaur_anchor()]))
    return ["--package", str(package), "--trust-anchor", str(_trust(tmp_path, builder)),
            "--observer-anchor", str(observers)]


def test_collected_dir_verifies_the_package_it_matches(tmp_path, builder, feed):
    out = tmp_path / "heads"
    assert _collect(feed, out) == 0
    assert main([*_package_args(tmp_path, builder), "--anchor-heads-dir", str(out)]) == 0


def test_collected_dir_fails_a_truncated_package(tmp_path, builder, feed, capsys):
    out = tmp_path / "heads"
    assert _collect(feed, out) == 0
    builder.anchors = builder.anchors[:2]
    args = _package_args(tmp_path, builder)
    capsys.readouterr()
    assert main(args) == 0
    assert main([*args, "--anchor-heads-dir", str(out)]) == 1
    assert "the package does not carry" in capsys.readouterr().out


def test_dir_with_a_contradicting_head_fails_the_package(tmp_path, builder, capsys):
    run = builder.anchors
    fork = header_only(builder.seal_record(
        datetime.fromisoformat(run[3]["period_start"]),
        datetime.fromisoformat(run[3]["period_end"]),
        run[1]["anchor_digest"],
    ))
    heads = tmp_path / "heads"
    heads.mkdir()
    (heads / "fork.json.gz").write_bytes(gzip.compress(json.dumps(fork).encode(), mtime=0))
    args = _package_args(tmp_path, builder)
    capsys.readouterr()
    assert main([*args, "--anchor-heads-dir", str(heads), "--json"]) == 1
    body = json.loads(capsys.readouterr().out)
    forks = body["provenance_anchoring"]["forks"]
    assert forks and forks[0]["against"] == "run"


def test_dir_combines_with_anchor_head(tmp_path, builder, capsys):
    newest = header_only(builder.anchors[-1])
    builder.anchors = builder.anchors[:2]
    args = _package_args(tmp_path, builder)
    empty = tmp_path / "empty"
    empty.mkdir()
    (empty / "notes.txt").write_text("ignored: not *.json or *.json.gz")
    sub = empty / "nested"
    sub.mkdir()
    (sub / "deep.json").write_text(json.dumps(newest))  # non-recursive: not read
    head = tmp_path / "head.json"
    head.write_text(json.dumps(newest))
    assert main([*args, "--anchor-heads-dir", str(empty)]) == 0
    capsys.readouterr()
    assert main([*args, "--anchor-heads-dir", str(empty), "--anchor-head", str(head),
                 "--json"]) == 1
    body = json.loads(capsys.readouterr().out)
    assert len(body["provenance_anchoring"]["heads"]) == 1  # nested/ was not read
    # The dir's heads and --anchor-head are combined.
    (empty / "copy.json").write_text(json.dumps(newest))
    assert main([*args, "--anchor-heads-dir", str(empty), "--anchor-head", str(head),
                 "--json"]) == 1
    assert len(json.loads(capsys.readouterr().out)["provenance_anchoring"]["heads"]) == 2


def test_anchor_heads_dir_usage_errors(tmp_path, builder):
    args = _package_args(tmp_path, builder)
    assert main([*args, "--anchor-heads-dir", str(tmp_path / "missing")]) == 2
    bad = tmp_path / "bad"
    bad.mkdir()
    (bad / "x.json").write_text("[1, 2]")
    assert main([*args, "--anchor-heads-dir", str(bad)]) == 2
    good = tmp_path / "good"
    good.mkdir()
    (good / "p.json").write_text(json.dumps(builder.predecessor))
    record = tmp_path / "record.json"
    record.write_text(json.dumps(builder.predecessor))
    assert main(["--audit-anchor", str(record), "--trust-anchor", str(tmp_path / "trust.json"),
                 "--anchor-heads-dir", str(good)]) == 2
