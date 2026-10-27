"""Offline command-line verifier.

The air-gapped path: no network, no service, no account. Everything the web UI
does runs here against the same code, which is the point. If the hosted
service ever disagreed with this CLI, one of them would be wrong; sharing the
verification core means they cannot.

    behavry-verify --package apr-APR-2026-001942.zip \\
                   --trust-anchor behavry-trust-anchor.json

    behavry-verify --package authority-<agent_id>.zip \\
                   --trust-anchor behavry-trust-anchor.json \\
                   --observer-anchor minotaur-observer-key.json \\
                   [--tsa-roots your-tsa-roots.pem] \\
                   [--anchor-head anchor-head.json]

    behavry-verify --audit-anchor behavry-anchor.json \\
                   --trust-anchor behavry-trust-anchor.json \\
                   [--tsa-roots your-tsa-roots.pem]

``--audit-anchor`` is repeatable: given two or more exports for one tenant, each
is verified and then the AUD-LINK back-pointers are walked to report a period
missing from the set.

``--anchor-head`` is repeatable too: each is an anchor record obtained from the
tenant independently of the package (``GET /api/v1/audit/anchors/head``), and
every provenance entry older than a verified head's period must be anchored in
the package. A head file is a `.json` record or a gzipped `.json.gz` object
as the WORM bucket stores it, told apart by content. Without one, dropping the
newest anchors cannot be ruled out. ``--anchor-heads-dir DIR`` adds every
``*.json`` and ``*.json.gz`` file in a directory as a head, and requires the
folder's heads to link (a gap between two of them fails check 15). Separate
``--anchor-head`` files are not checked for gaps: they are usually a sparse
sample.

Anchors witnessed in a public transparency log (AG-10, package 1.7) carry a
``witness`` receipt. ``--witness-trust FILE`` (Sigstore's ``trusted_root.json``
or the log's PEM public key) checks each receipt offline: the entry is in the
log, it is bound to the anchor's digest and signer key, and it was logged no
later than ``--witness-window SECONDS`` (default 7200) after the period ended.
``--require-witness`` requires a receipt on every anchor and head.

    behavry-verify --package authority-<agent_id>.zip \\
                   --trust-anchor behavry-trust-anchor.json \\
                   --witness-trust trusted_root.json [--require-witness]

Collecting heads is the one networked command, kept separate so that every
verification above stays offline (see :mod:`behavry_verify.collect`):

    BEHAVRY_TOKEN=... behavry-verify collect-heads --base-url https://behavry.example \\
                   --out heads/ [--token-env NAME] [--since ISO] \\
                   [--trust-anchor behavry-trust-anchor.json]

    behavry-verify --package authority-<agent_id>.zip \\
                   --trust-anchor behavry-trust-anchor.json --anchor-heads-dir heads/

Exit codes:
    0  verified
    1  not verified
    2  usage error / unreadable input
"""
from __future__ import annotations

import argparse
import base64
import binascii
import json
import sys
from pathlib import Path

from behavry_verify import __version__
from behavry_verify.anchor import AnchorError, validate_anchor, validate_observer_anchors
from behavry_verify.audit_anchor import (
    load_anchor_record_bytes,
    verify_anchor_chain,
    verify_audit_anchor,
)
from behavry_verify.collect import collect_heads_main, load_heads_dir
from behavry_verify.package import PackageError, load_package_from_path, verify_package
from behavry_verify.report import TrustSource, VerificationReport
from behavry_verify.rfc3161 import load_pem_certificates
from behavry_verify.witness import (
    DEFAULT_WINDOW_SECONDS,
    WitnessOptions,
    WitnessTrustError,
    load_witness_trust,
)

EXIT_VERIFIED = 0
EXIT_NOT_VERIFIED = 1
EXIT_USAGE = 2

#: The one subcommand. Every other invocation is the flat verification parser,
#: unchanged, so ``behavry-verify --package ...`` parses exactly as before.
COLLECT_HEADS = "collect-heads"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="behavry-verify",
        description=(
            "Independently verify a Behavry evidence package (APR or authority) "
            "or an audit anchor offline. Requires no Behavry account, database, "
            "or network access."
        ),
    )
    subject = parser.add_mutually_exclusive_group(required=True)
    subject.add_argument(
        "--package",
        type=Path,
        help="Evidence package: a .zip archive or an unpacked directory",
    )
    subject.add_argument(
        "--audit-anchor",
        type=Path,
        action="append",
        metavar="PATH",
        help=(
            "Audit anchor export JSON (GET /api/v1/audit/anchors/{id}/export): the "
            "RFC 3161 timestamp proof. Repeatable; with two or more, the anchor "
            "chain is also walked for a missing period."
        ),
    )
    key = parser.add_mutually_exclusive_group(required=True)
    key.add_argument(
        "--trust-anchor",
        type=Path,
        help="Path to the issuing tenant's behavry-trust-anchor.json",
    )
    key.add_argument(
        "--public-key",
        type=str,
        help="Base64-encoded 32-byte raw Ed25519 public key (bypasses the anchor)",
    )
    parser.add_argument(
        "--observer-anchor",
        type=Path,
        action="append",
        default=[],
        metavar="PATH",
        help=(
            "JSON file with an independent observer's public key "
            '({"kid","public_key_hex","observer_id","observer_type"}, or a list of '
            "them). Repeatable. Observations whose key is not supplied are reported "
            "as not independently verified. Also checks Minotaur assessment "
            "bundles in an authority package."
        ),
    )
    parser.add_argument(
        "--tsa-roots",
        type=Path,
        metavar="PEM",
        help=(
            "PEM bundle of TSA root certificates you trust, for --audit-anchor and "
            "for the audit anchors a 1.4 authority package carries (check 15). "
            "Without it the TSA certificate chain is reported as not validated."
        ),
    )
    parser.add_argument(
        "--anchor-head",
        type=Path,
        action="append",
        default=[],
        metavar="FILE",
        help=(
            "An anchor record obtained independently of the package, such as the "
            "tenant's head (GET /api/v1/audit/anchors/head). Repeatable, --package "
            "only. Every provenance entry older than a verified head's period must "
            "be anchored in the package, which rules out dropping the newest anchors. "
            "A .json record or a gzipped .json.gz object as the WORM bucket stores it."
        ),
    )
    parser.add_argument(
        "--anchor-heads-dir",
        type=Path,
        action="append",
        default=[],
        metavar="DIR",
        help=(
            "A directory of anchor heads, such as one filled by `behavry-verify "
            "collect-heads`: every *.json and *.json.gz file directly in it is passed "
            "as an --anchor-head, and the folder's heads must link: a gap between two "
            "of them fails the package. Repeatable, combines with --anchor-head, "
            "--package only."
        ),
    )
    parser.add_argument(
        "--witness-trust",
        type=Path,
        metavar="FILE",
        help=(
            "The transparency log's public key: Sigstore's trusted_root.json, or one "
            "PEM public key (ECDSA P-256 or Ed25519). Checks each anchor's witness "
            "receipt (check 16): inclusion in the log, binding to the anchor, and that "
            "it was logged promptly. Without it, receipts are reported as not checked."
        ),
    )
    parser.add_argument(
        "--require-witness",
        action="store_true",
        help=(
            "Every anchor, the run's predecessor and every supplied head (or the "
            "--audit-anchor record) must carry a witness receipt that verifies, "
            "whatever the package manifest says. Needs --witness-trust."
        ),
    )
    parser.add_argument(
        "--witness-window",
        type=int,
        default=DEFAULT_WINDOW_SECONDS,
        metavar="SECONDS",
        help=(
            "How long after its period ends an anchor may be logged and still count as "
            f"prompt (default {DEFAULT_WINDOW_SECONDS})."
        ),
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit the machine-readable report instead of the text report",
    )
    parser.add_argument("--version", action="version", version=__version__)
    parser.epilog = (
        f"To collect a tenant's anchor heads (network): behavry-verify {COLLECT_HEADS} --help"
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    if argv and argv[0] == COLLECT_HEADS:
        return collect_heads_main(list(argv[1:]))
    args = build_parser().parse_args(argv)

    anchor = None
    raw_public_key = None
    trust_source = TrustSource.NONE

    if args.trust_anchor is not None:
        try:
            anchor = json.loads(args.trust_anchor.read_text(encoding="utf-8"))
            validate_anchor(anchor)
        except (OSError, json.JSONDecodeError, AnchorError) as exc:
            print(f"error: could not read trust anchor: {exc}", file=sys.stderr)
            return EXIT_USAGE
        trust_source = TrustSource.SUPPLIED_ANCHOR
    else:
        try:
            raw_public_key = base64.b64decode(args.public_key, validate=True)
        except (binascii.Error, ValueError) as exc:
            print(f"error: --public-key is not valid base64: {exc}", file=sys.stderr)
            return EXIT_USAGE
        if len(raw_public_key) != 32:
            print(
                f"error: --public-key is {len(raw_public_key)} bytes, "
                "expected 32 for Ed25519",
                file=sys.stderr,
            )
            return EXIT_USAGE
        trust_source = TrustSource.SUPPLIED_KEY

    observer_anchors: list[dict] = []
    for path in args.observer_anchor:
        try:
            observer_anchors.extend(
                validate_observer_anchors(json.loads(path.read_text(encoding="utf-8")))
            )
        except (OSError, json.JSONDecodeError, AnchorError) as exc:
            print(f"error: could not read observer anchor {path}: {exc}", file=sys.stderr)
            return EXIT_USAGE

    roots = None
    if args.tsa_roots is not None:
        try:
            roots = load_pem_certificates(args.tsa_roots.read_bytes())
        except (OSError, ValueError) as exc:
            print(f"error: could not read TSA roots {args.tsa_roots}: {exc}", file=sys.stderr)
            return EXIT_USAGE

    if args.witness_window < 0:
        print("error: --witness-window must be zero or more seconds", file=sys.stderr)
        return EXIT_USAGE
    witness_trust = None
    if args.witness_trust is not None:
        try:
            witness_trust = load_witness_trust(args.witness_trust.read_bytes())
        except (OSError, WitnessTrustError) as exc:
            print(
                f"error: could not read witness trust root {args.witness_trust}: {exc}",
                file=sys.stderr,
            )
            return EXIT_USAGE
    witness = WitnessOptions(
        trust=witness_trust, require=args.require_witness, window=args.witness_window
    )

    heads: list[dict] = []
    head_dirs: list[tuple[str, list[dict]]] = []
    for path in args.anchor_head:
        try:
            value = load_anchor_record_bytes(path.read_bytes())
        except (OSError, ValueError) as exc:
            print(f"error: could not read anchor head {path}: {exc}", file=sys.stderr)
            return EXIT_USAGE
        heads.append(value)
    for directory in args.anchor_heads_dir:
        try:
            loaded = load_heads_dir(directory)
        except (OSError, ValueError) as exc:
            print(f"error: could not read anchor heads dir {directory}: {exc}", file=sys.stderr)
            return EXIT_USAGE
        head_dirs.append((str(directory), [value for _, value in loaded]))

    if args.audit_anchor:
        if args.anchor_head or args.anchor_heads_dir:
            print(
                "error: --anchor-head and --anchor-heads-dir apply to --package; to verify "
                "a head on its own, pass it as --audit-anchor",
                file=sys.stderr,
            )
            return EXIT_USAGE
        return _run_audit_anchors(args, anchor, raw_public_key, trust_source, roots, witness)

    try:
        components = load_package_from_path(args.package)
    except (PackageError, OSError) as exc:
        print(f"error: could not read package: {exc}", file=sys.stderr)
        return EXIT_USAGE

    report = verify_package(
        components,
        anchor=anchor,
        raw_public_key=raw_public_key,
        trust_source=trust_source,
        observer_anchors=observer_anchors,
        tsa_roots=roots,
        anchor_heads=heads,
        anchor_head_dirs=head_dirs,
        witness=witness,
    )

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(report.to_text())
    return EXIT_VERIFIED if report.verified else EXIT_NOT_VERIFIED


def _run_audit_anchors(
    args: argparse.Namespace,
    anchor: dict | None,
    raw_public_key: bytes | None,
    trust_source: TrustSource,
    roots: list | None,
    witness: WitnessOptions,
) -> int:
    exports: list[tuple[Path, dict]] = []
    for path in args.audit_anchor:
        # AG-8: as stored in WORM too, so ``.json.gz`` objects verify as-is.
        try:
            value = load_anchor_record_bytes(path.read_bytes())
        except (OSError, ValueError) as exc:
            print(f"error: could not read audit anchor {path}: {exc}", file=sys.stderr)
            return EXIT_USAGE
        exports.append((path, value))

    reports: list[tuple[Path, VerificationReport]] = [
        (
            path,
            verify_audit_anchor(
                export,
                anchor=anchor,
                raw_public_key=raw_public_key,
                trust_source=trust_source,
                tsa_roots=roots,
                witness=witness,
            ),
        )
        for path, export in exports
    ]
    chain: tuple[bool, list[str]] | None = None
    if len(exports) > 1:
        chain = verify_anchor_chain([export for _, export in exports])
    all_ok = all(r.verified for _, r in reports) and (chain is None or chain[0])

    if args.json:
        if chain is None:
            print(json.dumps(reports[0][1].to_dict(), indent=2))
        else:
            body = {
                "verified": all_ok,
                "anchors": [{"path": str(p), "report": r.to_dict()} for p, r in reports],
                "chain": {"verified": chain[0], "findings": chain[1]},
            }
            print(json.dumps(body, indent=2))
    elif chain is None:
        print(reports[0][1].to_text())
    else:
        for path, report in reports:
            print(f"== {path} ==")
            print(report.to_text())
            print()
        print("== Anchor chain ==")
        print("VERIFIED" if chain[0] else "NOT VERIFIED")
        for line in chain[1]:
            print(f"  {line}")
    return EXIT_VERIFIED if all_ok else EXIT_NOT_VERIFIED


if __name__ == "__main__":
    sys.exit(main())
