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
                   [--tsa-roots your-tsa-roots.pem]

    behavry-verify --audit-anchor behavry-anchor.json \\
                   --trust-anchor behavry-trust-anchor.json \\
                   [--tsa-roots your-tsa-roots.pem]

``--audit-anchor`` is repeatable: given two or more exports for one tenant, each
is verified and then the AUD-LINK back-pointers are walked to report a period
missing from the set.

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
from behavry_verify.audit_anchor import verify_anchor_chain, verify_audit_anchor
from behavry_verify.package import PackageError, load_package_from_path, verify_package
from behavry_verify.report import TrustSource, VerificationReport
from behavry_verify.rfc3161 import load_pem_certificates

EXIT_VERIFIED = 0
EXIT_NOT_VERIFIED = 1
EXIT_USAGE = 2


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
        "--json",
        action="store_true",
        help="Emit the machine-readable report instead of the text report",
    )
    parser.add_argument("--version", action="version", version=__version__)
    return parser


def main(argv: list[str] | None = None) -> int:
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

    if args.audit_anchor:
        return _run_audit_anchors(args, anchor, raw_public_key, trust_source, roots)

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
) -> int:
    exports: list[tuple[Path, dict]] = []
    for path in args.audit_anchor:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"error: could not read audit anchor {path}: {exc}", file=sys.stderr)
            return EXIT_USAGE
        if not isinstance(value, dict):
            print(f"error: audit anchor {path} is not a JSON object", file=sys.stderr)
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
