"""``behavry-verify collect-heads``: keep your own copy of a tenant's anchor heads.

Behavry Sprint AG-8 (``docs/strategy/AG8-CONTRACTS.md`` section 3). A package
can only be shown to be cut short at its newest anchors by heads obtained
outside it (AG-6 H3), and a fork only by a head it contradicts (AG-7 H2). This
command pages the tenant's heads feed, ``GET /api/v1/audit/anchors/heads``,
into a directory that ``--anchor-heads-dir`` then reads offline.

It is the only part of behavry-verify that touches the network. It uses the
standard library alone (``urllib``), so the CLI keeps its single third-party
dependency; ``urllib`` honours ``HTTPS_PROXY`` / ``NO_PROXY`` and the system CA
store (``SSL_CERT_FILE`` / ``SSL_CERT_DIR``) by default.

Rules:

* resume after the newest head already in the directory, by ``period_start``
  inside the files, not their names (unless ``--since``);
* save each head as ``<YYYYmmddTHHMMSSZ of period_start>-<anchor_id[:8]>.json``;
* a file that already holds a different record (another ``anchor_digest``)
  is never overwritten: it is a conflict. One with the same ``anchor_digest``
  is already present, whatever its unsigned fields say. A head whose
  ``period_start`` equals a stored head's with a different ``anchor_digest``
  is a conflict too: two records for one period;
* with ``--trust-anchor``, a head that does not verify (digest, signature,
  TSA) is not saved and is reported;
* the bearer token comes from an environment variable, never from argv, and
  is never printed. Redirects are refused, so it is never sent anywhere but
  ``--base-url``, and plain ``http://`` is accepted for a loopback host only.

Exit codes: 0 everything collected verified or was not checked; 1 any conflict
or unverified head; 2 usage, network or HTTP error.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import ssl
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from behavry_verify.anchor import AnchorError, validate_anchor
from behavry_verify.audit_anchor import load_anchor_record_bytes, verify_audit_anchor
from behavry_verify.report import CheckStatus, TrustSource
from behavry_verify.rfc3161 import load_pem_certificates

__all__ = ["HEADS_PATH", "PAGE_LIMIT", "collect_heads_main", "head_file_name", "load_heads_dir"]

HEADS_PATH = "/api/v1/audit/anchors/heads"
PAGE_LIMIT = 1000
DEFAULT_TOKEN_ENV = "BEHAVRY_TOKEN"
TIMEOUT_SECONDS = 30.0
MAX_PAGE_BYTES = 64 * 1024 * 1024
HEAD_PATTERNS = ("*.json", "*.json.gz")
_ID_PREFIX = re.compile(r"^[A-Za-z0-9_-]{1,8}$")

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2


class CollectError(Exception):
    """A usage, network or HTTP error: the run cannot continue (exit 2)."""


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def head_file_name(record: dict[str, Any]) -> str:
    """``<YYYYmmddTHHMMSSZ of period_start in UTC>-<first 8 of anchor_id>.json``.

    Raises :class:`ValueError` when the record has no usable ``period_start``
    or ``anchor_id`` (an id prefix that is not ``[A-Za-z0-9_-]`` could name a
    path outside the directory, so it is refused rather than escaped).
    """
    start = _parse_time(record.get("period_start"))
    if start is None:
        raise ValueError(f"period_start {record.get('period_start')!r} is not an ISO 8601 time")
    anchor_id = record.get("anchor_id")
    if not isinstance(anchor_id, str) or not _ID_PREFIX.match(anchor_id[:8]):
        raise ValueError(f"anchor_id {anchor_id!r} cannot name a file")
    return f"{start.astimezone(UTC).strftime('%Y%m%dT%H%M%SZ')}-{anchor_id[:8]}.json"


def head_paths(directory: Path) -> list[Path]:
    """Every ``*.json`` and ``*.json.gz`` file directly in ``directory``, sorted."""
    found: set[Path] = set()
    for pattern in HEAD_PATTERNS:
        found.update(p for p in directory.glob(pattern) if p.is_file())
    return sorted(found)


def load_heads_dir(directory: Path) -> list[tuple[Path, dict[str, Any]]]:
    """Load every head file in ``directory`` (non-recursive, sorted by name).

    Raises :class:`OSError` when the directory cannot be read and
    :class:`ValueError` naming the file when one is not an anchor record.
    """
    if not directory.is_dir():
        raise OSError(f"{directory} is not a directory")
    loaded: list[tuple[Path, dict[str, Any]]] = []
    for path in head_paths(directory):
        try:
            loaded.append((path, load_anchor_record_bytes(path.read_bytes())))
        except ValueError as exc:
            raise ValueError(f"{path}: {exc}") from exc
    return loaded


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse redirects: following one would carry the bearer token elsewhere."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise CollectError(
            f"the heads feed answered HTTP {code} with a redirect; redirects are not "
            "followed, so the token is only ever sent to --base-url. Pass the final URL."
        )


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _check_base_url(base_url: str) -> str:
    parsed = urllib.parse.urlparse(base_url)
    if parsed.scheme not in ("https", "http") or not parsed.hostname:
        raise CollectError(f"--base-url {base_url!r} is not an http(s) URL")
    if parsed.scheme == "http" and not _is_loopback(parsed.hostname):
        raise CollectError(
            "--base-url must be https:// (plain http:// is accepted for a loopback "
            "host only, since the bearer token would travel in the clear)"
        )
    if parsed.query or parsed.fragment:
        raise CollectError("--base-url must not carry a query or fragment")
    return base_url.rstrip("/")


def _fetch_page(opener: urllib.request.OpenerDirector, url: str, token: str) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
    )
    # Never put the URL's credentials or the token in a message: the URL holds
    # neither (the token is a header), so naming the URL is safe.
    try:
        with opener.open(request, timeout=TIMEOUT_SECONDS) as response:
            body = response.read(MAX_PAGE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        raise CollectError(f"GET {url} returned HTTP {exc.code}") from None
    except (urllib.error.URLError, OSError, ssl.SSLError) as exc:
        reason = getattr(exc, "reason", exc)
        raise CollectError(f"GET {url} failed: {reason}") from None
    if len(body) > MAX_PAGE_BYTES:
        raise CollectError(f"GET {url}: the page exceeds {MAX_PAGE_BYTES} bytes")
    try:
        value = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CollectError(f"GET {url}: the response is not JSON: {exc}") from None
    if not isinstance(value, dict) or not isinstance(value.get("heads"), list):
        raise CollectError(f'GET {url}: the response is not {{"heads": [...], "next_since": ...}}')
    return value


# ---------------------------------------------------------------------------
# Collection
# ---------------------------------------------------------------------------


@dataclass
class _Tally:
    saved: list[str] = field(default_factory=list)
    present: int = 0
    conflicts: list[str] = field(default_factory=list)
    rejected: list[str] = field(default_factory=list)

    @property
    def findings(self) -> bool:
        return bool(self.conflicts or self.rejected)


def _describe(record: dict[str, Any]) -> str:
    return f"head {record.get('anchor_id')!r} (period_start {record.get('period_start')})"


def _verify_head(
    record: dict[str, Any], anchor: dict[str, Any], roots: list | None
) -> list[str]:
    """The failed checks of a standalone head, exactly as check 15 verifies one."""
    sub = verify_audit_anchor(
        record,
        anchor=anchor,
        trust_source=TrustSource.SUPPLIED_ANCHOR,
        tsa_roots=roots,
    )
    failed = [c.id for c in sub.checks if c.status is CheckStatus.FAIL]
    if not sub.verified and not failed:
        failed.append("signature not checked")
    return failed


def _write_new(path: Path, record: dict[str, Any]) -> bool:
    """Create ``path`` with ``record``; False when it already exists. Never overwrites."""
    data = (json.dumps(record, indent=2, sort_keys=True) + "\n").encode("utf-8")
    fd, tmp = tempfile.mkstemp(prefix=".collect-", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(tmp, path)  # atomic, and fails if the name is taken
        except FileExistsError:
            return False
        return True
    finally:
        os.unlink(tmp)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="behavry-verify collect-heads",
        description=(
            "Page a tenant's anchor heads feed (GET /api/v1/audit/anchors/heads) into "
            "a directory, for --anchor-heads-dir. The only behavry-verify command that "
            "uses the network."
        ),
    )
    parser.add_argument(
        "--base-url", required=True, help="The tenant's Behavry URL, e.g. https://behavry.example"
    )
    parser.add_argument("--out", type=Path, required=True, metavar="DIR",
                        help="Directory to save heads in (created if missing)")
    parser.add_argument(
        "--token-env",
        default=DEFAULT_TOKEN_ENV,
        metavar="NAME",
        help=f"Environment variable holding the bearer token (default {DEFAULT_TOKEN_ENV})",
    )
    parser.add_argument(
        "--since",
        metavar="ISO",
        help="Collect heads with period_start strictly after this time, instead of "
        "resuming after the newest head already in DIR",
    )
    parser.add_argument(
        "--trust-anchor",
        type=Path,
        metavar="FILE",
        help="Verify each head (digest, signature, TSA) under this trust anchor "
        "before saving it; one that does not verify is not saved",
    )
    parser.add_argument(
        "--tsa-roots",
        type=Path,
        metavar="PEM",
        help="With --trust-anchor: TSA roots to validate each head's TSA chain against",
    )
    return parser


def collect_heads_main(argv: list[str]) -> int:
    try:
        args = build_parser().parse_args(argv)
    except SystemExit as exc:  # argparse: --help is 0, a usage error is 2
        return int(exc.code or 0)
    try:
        return _run(args)
    except CollectError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE


def _run(args: argparse.Namespace) -> int:
    base = _check_base_url(args.base_url)
    token = os.environ.get(args.token_env, "")
    if not token.strip():
        raise CollectError(
            f"no bearer token: set the environment variable {args.token_env} "
            "(the token is never taken from the command line)"
        )
    token = token.strip()

    anchor: dict[str, Any] | None = None
    roots: list | None = None
    if args.trust_anchor is not None:
        try:
            anchor = json.loads(args.trust_anchor.read_text(encoding="utf-8"))
            validate_anchor(anchor)
        except (OSError, json.JSONDecodeError, AnchorError) as exc:
            raise CollectError(f"could not read trust anchor: {exc}") from None
    if args.tsa_roots is not None:
        if anchor is None:
            raise CollectError("--tsa-roots applies only with --trust-anchor")
        try:
            roots = load_pem_certificates(args.tsa_roots.read_bytes())
        except (OSError, ValueError) as exc:
            raise CollectError(f"could not read TSA roots {args.tsa_roots}: {exc}") from None

    out: Path = args.out
    try:
        out.mkdir(parents=True, exist_ok=True)
        stored = load_heads_dir(out)
    except (OSError, ValueError) as exc:
        raise CollectError(f"could not read --out: {exc}") from None

    # period_start -> anchor_digest of every stored head, to catch a second
    # record for a period even when its anchor_id gives it another file name.
    by_period: dict[datetime, set[Any]] = {}
    newest: tuple[datetime, str] | None = None
    for _, record in stored:
        start = _parse_time(record.get("period_start"))
        if start is None:
            continue
        by_period.setdefault(start, set()).add(record.get("anchor_digest"))
        if newest is None or start > newest[0]:
            newest = (start, record["period_start"])

    if args.since is not None:
        if _parse_time(args.since) is None:
            raise CollectError(f"--since {args.since!r} is not an ISO 8601 time")
        since: str | None = args.since
    else:
        since = newest[1] if newest else None

    handlers: list[urllib.request.BaseHandler] = [_NoRedirect()]
    if _is_loopback(urllib.parse.urlparse(base).hostname or ""):
        # A proxy cannot reach this machine's loopback; never route it there.
        handlers.append(urllib.request.ProxyHandler({}))
    opener = urllib.request.build_opener(*handlers)
    tally = _Tally()
    pages = 0
    while True:
        query: dict[str, Any] = {"limit": PAGE_LIMIT}
        if since is not None:
            query = {"since": since, **query}
        url = f"{base}{HEADS_PATH}?{urllib.parse.urlencode(query)}"
        page = _fetch_page(opener, url, token)
        heads = page["heads"]
        pages += 1
        if not heads:
            break
        for record in heads:
            _take(record, out, anchor, roots, by_period, tally)
        next_since = page.get("next_since")
        if not isinstance(next_since, str) or not next_since:
            last = heads[-1] if isinstance(heads[-1], dict) else {}
            next_since = last.get("period_start")
        after, before = _parse_time(next_since), _parse_time(since)
        if after is None or (before is not None and after <= before):
            raise CollectError(
                f"the heads feed did not advance past since={since!r} "
                f"(next_since {next_since!r}); stopping rather than looping"
            )
        since = next_since

    _report(tally, pages, out, checked=anchor is not None)
    return EXIT_FINDINGS if tally.findings else EXIT_OK


def _take(
    record: Any,
    out: Path,
    anchor: dict[str, Any] | None,
    roots: list | None,
    by_period: dict[datetime, set[Any]],
    tally: _Tally,
) -> None:
    if not isinstance(record, dict):
        tally.rejected.append("a head that is not a JSON object")
        return
    try:
        name = head_file_name(record)
    except ValueError as exc:
        tally.rejected.append(f"{_describe(record)}: {exc}")
        return
    if anchor is not None:
        failed = _verify_head(record, anchor, roots)
        if failed:
            tally.rejected.append(f"{_describe(record)} does not verify: {', '.join(failed)}")
            return
    path = out / name
    if path.exists():
        try:
            existing = load_anchor_record_bytes(path.read_bytes())
        except (OSError, ValueError):
            existing = None
        # Same signed content, not same bytes: fields outside the canonical
        # anchor bytes (anchor_id, sealed_at, ...) may differ without making
        # it another record. A tampered stored file is caught when
        # --anchor-heads-dir verifies it.
        stored_digest = existing.get("anchor_digest") if existing else None
        if stored_digest and stored_digest == record.get("anchor_digest"):
            tally.present += 1
        else:
            tally.conflicts.append(
                f"{path} already holds a different record than {_describe(record)} "
                "(two records for one period); it was not overwritten"
            )
        return
    start = _parse_time(record["period_start"])
    assert start is not None  # head_file_name parsed it
    digests = by_period.get(start, set())
    if digests and record.get("anchor_digest") not in digests:
        tally.conflicts.append(
            f"{_describe(record)} has anchor_digest {record.get('anchor_digest')}, but a head "
            f"already in {out} seals the same period_start with another digest (two "
            "records for one period); it was not saved"
        )
        return
    if not _write_new(path, record):
        tally.conflicts.append(f"{path} appeared while collecting; it was not overwritten")
        return
    by_period.setdefault(start, set()).add(record.get("anchor_digest"))
    tally.saved.append(name)


def _report(tally: _Tally, pages: int, out: Path, *, checked: bool) -> None:
    verified = "verified and saved" if checked else "saved (not verified: no --trust-anchor)"
    print(f"collect-heads: {pages} page(s) read into {out}")
    print(f"  {len(tally.saved)} new head(s) {verified}")
    print(f"  {tally.present} already present")
    if tally.conflicts:
        print(f"  {len(tally.conflicts)} CONFLICT(S):")
        for line in tally.conflicts:
            print(f"    {line}")
    if tally.rejected:
        label = "NOT VERIFIED, not saved" if checked else "unusable, not saved"
        print(f"  {len(tally.rejected)} {label}:")
        for line in tally.rejected:
            print(f"    {line}")
