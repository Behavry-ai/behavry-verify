"""Offline command-line verifier.

The air-gapped path: no network, no service, no account. Everything the web UI
does runs here against the same code, which is the point. If the hosted
service ever disagreed with this CLI, one of them would be wrong; sharing the
verification core means they cannot.

    behavry-verify --package apr-APR-2026-001942.zip \\
                   --trust-anchor behavry-trust-anchor.json

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
from behavry_verify.anchor import AnchorError, validate_anchor
from behavry_verify.package import PackageError, load_package_from_path, verify_package
from behavry_verify.report import TrustSource

EXIT_VERIFIED = 0
EXIT_NOT_VERIFIED = 1
EXIT_USAGE = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="behavry-verify",
        description=(
            "Independently verify a Behavry APR evidence package offline. "
            "Requires no Behavry account, database, or network access."
        ),
    )
    parser.add_argument(
        "--package",
        type=Path,
        required=True,
        help="Evidence package: a .zip archive or an unpacked directory",
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
    )

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(report.to_text())
    return EXIT_VERIFIED if report.verified else EXIT_NOT_VERIFIED


if __name__ == "__main__":
    sys.exit(main())
