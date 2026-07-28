"""APR evidence-package loading and verification.

Verifies a ``behavry.apr_evidence_package.v1`` archive with no Behavry
database, no live KMS, and no network call: the package plus a public key is
everything required.

Chain of trust::

    trust anchor -> package manifest signature -> Merkle root
                 -> per-event signatures -> per-agent hash chain

Unlike the reference CLI in the Behavry repo (``tools/verify_event.py``),
which returns on the first failed check, this module runs every check it can
and reports each independently. Checks whose meaning depends on a failed
predecessor are marked SKIPPED rather than passed.
"""
from __future__ import annotations

import base64
import binascii
import io
import json
import zipfile
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from behavry_verify.anchor import (
    AnchorError,
    public_key_fingerprint,
    select_key_for_timestamp,
)
from behavry_verify.canonical import (
    canonical_package_manifest_bytes,
    canonical_signing_bytes,
    canonical_signing_bytes_disclosure_ack,
    canonical_signing_bytes_exposure,
)
from behavry_verify.merkle import merkle_root
from behavry_verify.report import TrustSource, VerificationReport

__all__ = [
    "MAX_MEMBER_COUNT",
    "MAX_TOTAL_UNCOMPRESSED_BYTES",
    "PackageError",
    "load_package_from_bytes",
    "load_package_from_path",
    "verify_package",
]

PACKAGE_SCHEMA = "behavry.apr_evidence_package.v1"

# Archive-bomb guards. A real package is a handful of JSON files; these caps
# are orders of magnitude above any legitimate export.
MAX_MEMBER_COUNT = 512
MAX_TOTAL_UNCOMPRESSED_BYTES = 256 * 1024 * 1024  # 256 MiB
MAX_SINGLE_MEMBER_BYTES = 128 * 1024 * 1024  # 128 MiB


class PackageError(ValueError):
    """Raised when a package cannot be read at all (not merely invalid)."""


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------


def _load_from_zipfile(zf: zipfile.ZipFile) -> dict[str, Any]:
    infos = [i for i in zf.infolist() if not i.is_dir()]
    if len(infos) > MAX_MEMBER_COUNT:
        raise PackageError(
            f"archive has {len(infos)} members, refusing above {MAX_MEMBER_COUNT}"
        )
    total = sum(i.file_size for i in infos)
    if total > MAX_TOTAL_UNCOMPRESSED_BYTES:
        raise PackageError(
            f"archive expands to {total} bytes, refusing above "
            f"{MAX_TOTAL_UNCOMPRESSED_BYTES}"
        )

    members: dict[str, str] = {}
    for info in infos:
        short = info.filename.rsplit("/", 1)[-1]
        if not short.endswith(".json"):
            # narrative.txt / narrative.pdf are not part of the integrity
            # envelope; verification operates over the JSON components only.
            continue
        if info.file_size > MAX_SINGLE_MEMBER_BYTES:
            raise PackageError(f"member {short!r} is too large to verify")
        try:
            members[short] = zf.read(info).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise PackageError(f"member {short!r} is not valid UTF-8") from exc
    return _parse_members(members)


def _parse_members(members: dict[str, str]) -> dict[str, Any]:
    if "manifest.json" not in members:
        raise PackageError("package has no manifest.json")
    parsed: dict[str, Any] = {}
    for name, text in members.items():
        try:
            parsed[name] = json.loads(text)
        except json.JSONDecodeError as exc:
            raise PackageError(f"{name} is not valid JSON: {exc}") from exc
    return parsed


def load_package_from_bytes(data: bytes) -> dict[str, Any]:
    """Load an evidence package from ZIP bytes."""
    if not data:
        raise PackageError("package is empty")
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            return _load_from_zipfile(zf)
    except zipfile.BadZipFile as exc:
        raise PackageError(
            "not a readable ZIP archive (expected the .zip produced by "
            "GET /api/v1/apr/{id}/export?format=zip)"
        ) from exc


def load_package_from_path(path: Path) -> dict[str, Any]:
    """Load an evidence package from a ZIP file or an unpacked directory."""
    if path.is_dir():
        roots = [p for p in path.iterdir() if p.is_dir() and p.name.startswith("apr-")]
        base = roots[0] if roots else path
        members = {f.name: f.read_text(encoding="utf-8") for f in base.glob("*.json")}
        return _parse_members(members)
    try:
        with zipfile.ZipFile(path) as zf:
            return _load_from_zipfile(zf)
    except zipfile.BadZipFile as exc:
        raise PackageError(f"{path} is not a readable ZIP archive") from exc


# ---------------------------------------------------------------------------
# Primitives
# ---------------------------------------------------------------------------


def _verify_ed25519(public_key: bytes, signature_b64: str, payload: bytes) -> bool:
    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except (binascii.Error, ValueError):
        return False
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, payload)
    except (InvalidSignature, ValueError):
        return False
    return True


def _event_payload(event: dict[str, Any]) -> bytes:
    """Select the canonical signing form for an event by its claim type."""
    claim_type = event.get("claim_type")
    if claim_type == "exposure":
        return canonical_signing_bytes_exposure(
            event_hash=event.get("event_hash"),
            previous_hash=event.get("previous_hash"),
            timestamp=event.get("timestamp"),
            tenant_id=event.get("tenant_id"),
            device_id=event.get("device_id"),
        )
    if claim_type == "disclosure_ack":
        return canonical_signing_bytes_disclosure_ack(
            event_hash=event.get("event_hash"),
            previous_hash=event.get("previous_hash"),
            timestamp=event.get("timestamp"),
            tenant_id=event.get("tenant_id"),
            device_id=event.get("device_id"),
        )
    return canonical_signing_bytes(
        event_hash=event.get("event_hash"),
        previous_hash=event.get("previous_hash"),
        timestamp=event.get("timestamp"),
        tenant_id=event.get("tenant_id"),
    )


def _chain_key(event: dict[str, Any]) -> tuple[str, Any]:
    """Group events into their independent hash chains.

    Behavry chains decision events per agent and device claims per device.
    Keeping exposure and disclosure_ack on their own device-scoped keys is
    what stops two devices' records from being spliced into one chain.
    """
    claim_type = event.get("claim_type")
    if claim_type == "exposure":
        return ("exp", event.get("device_id"))
    if claim_type == "disclosure_ack":
        return ("ack", event.get("device_id"))
    return ("dec", event.get("agent_id"))


def walk_event_chain(events: list[dict[str, Any]]) -> list[str]:
    """Walk each independent hash chain; return every break found.

    Returns an empty list when every link holds. Unlike the reference
    verifier this collects *all* breaks, so a report can say "3 breaks"
    rather than stopping at the first.
    """
    by_chain: dict[tuple[str, Any], list[dict[str, Any]]] = {}
    for event in events:
        by_chain.setdefault(_chain_key(event), []).append(event)

    breaks: list[str] = []
    for key, chain in by_chain.items():
        chain.sort(key=lambda e: e.get("timestamp") or "")
        previous: str | None = None
        for position, event in enumerate(chain):
            link_previous = event.get("previous_hash")
            if previous is not None and link_previous != previous:
                breaks.append(
                    f"chain {key[0]}:{key[1]!r} broken at event "
                    f"{position + 1} of {len(chain)} "
                    f"(id={event.get('id')!r}): previous_hash="
                    f"{link_previous!r}, expected {previous!r}"
                )
            previous = event.get("event_hash")
    return breaks


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


def verify_package(
    components: dict[str, Any],
    *,
    anchor: dict[str, Any] | None = None,
    raw_public_key: bytes | None = None,
    trust_source: TrustSource = TrustSource.NONE,
) -> VerificationReport:
    """Verify an assembled evidence package and return a full report."""
    report = VerificationReport(trust_source=trust_source)

    manifest = components.get("manifest.json")
    if not isinstance(manifest, dict):
        report.error = "package has no usable manifest.json"
        report.add_fail("manifest", "Manifest present", report.error)
        return report.finalize()

    # Manifest metadata is echoed even on failure: an auditor needs to know
    # *which* package failed, and these fields are covered by the signature
    # check that follows, so a tampered value cannot pass unnoticed.
    report.apr_identifier = manifest.get("apr_identifier")
    report.package_version = manifest.get("package_version")
    report.package_schema = manifest.get("schema")
    report.event_count = manifest.get("event_count")
    report.root_hash = manifest.get("root_hash")
    report.chain_status = manifest.get("chain_status")
    report.created_at = manifest.get("created_at")
    report.signer_kid = manifest.get("signer_kid")
    report.signature_algorithm = manifest.get("signature_algorithm")
    report.signing_backend = manifest.get("signing_backend")

    if report.package_schema and report.package_schema != PACKAGE_SCHEMA:
        report.add_warn(
            "schema",
            "Package schema recognized",
            f"expected {PACKAGE_SCHEMA}, package declares {report.package_schema}",
        )

    timeline = components.get("timeline.json") or []
    if not isinstance(timeline, list):
        timeline = []

    # -- 1. Manifest signature ------------------------------------------------
    public_key, key_entry = _resolve_key(report, manifest, anchor, raw_public_key)
    signature_ok = False
    if public_key is None:
        report.add_skip(
            "signature",
            "Signature valid",
            report.error or "no trust anchor or public key available",
        )
    elif not manifest.get("signature"):
        report.add_fail("signature", "Signature valid", "manifest carries no signature")
    else:
        signature_ok = _verify_ed25519(
            public_key,
            manifest["signature"],
            canonical_package_manifest_bytes(manifest),
        )
        if signature_ok:
            report.add_pass(
                "signature",
                "Signature valid",
                f"Ed25519 over the canonical manifest, key {report.signer_kid or 'unknown'}",
            )
        else:
            report.add_fail(
                "signature",
                "Signature valid",
                "manifest signature did not verify against the selected key "
                "(the manifest was altered, or the key is not the signer's)",
            )

    # -- 2. Signer fingerprint cross-check ------------------------------------
    _check_fingerprint(report, components, key_entry)

    # -- 3. Merkle root -------------------------------------------------------
    event_hashes = [
        e.get("event_hash") for e in timeline if isinstance(e, dict) and e.get("event_hash")
    ]
    recomputed = merkle_root(event_hashes)
    claimed_root = manifest.get("root_hash")
    if recomputed == claimed_root:
        report.add_pass(
            "merkle_root",
            "Merkle root matches",
            f"recomputed over {len(event_hashes)} event hashes",
        )
    else:
        report.add_fail(
            "merkle_root",
            "Merkle root matches",
            f"recomputed {recomputed}, manifest claims {claimed_root}",
        )

    # -- 4. Event count -------------------------------------------------------
    claimed_count = manifest.get("event_count")
    if claimed_count is None:
        report.add_skip("event_count", "Event count verified", "manifest has no event_count")
    elif len(timeline) == claimed_count:
        report.add_pass(
            "event_count", "Event count verified", f"{len(timeline)} events"
        )
    else:
        report.add_fail(
            "event_count",
            "Event count verified",
            f"timeline holds {len(timeline)} events, manifest claims {claimed_count}",
        )

    # -- 5. Per-event signatures ----------------------------------------------
    _check_event_signatures(report, timeline, anchor, raw_public_key, public_key)

    # -- 6. Hash chain walk ---------------------------------------------------
    breaks = walk_event_chain([e for e in timeline if isinstance(e, dict)])
    if not breaks:
        report.add_pass(
            "chain",
            "No chain breaks",
            f"{len(timeline)} events linked across "
            f"{len({_chain_key(e) for e in timeline if isinstance(e, dict)})} chain(s)",
        )
    else:
        head = breaks[0]
        extra = f" (+{len(breaks) - 1} more)" if len(breaks) > 1 else ""
        report.add_fail("chain", "No chain breaks", head + extra)

    # -- 7. Stored per-link verified flags ------------------------------------
    _check_stored_flags(report, components)

    return report.finalize()


def _resolve_key(
    report: VerificationReport,
    manifest: dict[str, Any],
    anchor: dict[str, Any] | None,
    raw_public_key: bytes | None,
) -> tuple[bytes | None, dict[str, Any] | None]:
    if raw_public_key is not None:
        return raw_public_key, None
    if anchor is None:
        report.error = "no trust anchor or public key was supplied"
        return None, None
    try:
        return select_key_for_timestamp(
            anchor, manifest.get("signer_kid"), manifest.get("created_at")
        )
    except AnchorError as exc:
        report.error = str(exc)
        return None, None


def _check_fingerprint(
    report: VerificationReport,
    components: dict[str, Any],
    key_entry: dict[str, Any] | None,
) -> None:
    """Cross-check the package's ``public_key_hint`` against the key used.

    The hint is a truncated fingerprint, not a key, so it proves nothing on
    its own. It does catch the common operational mistake of verifying
    against the wrong tenant's anchor, which would otherwise surface only as
    an unexplained signature failure.
    """
    metadata = components.get("verification_metadata.json")
    hint = metadata.get("public_key_hint") if isinstance(metadata, dict) else None
    if not hint:
        report.add_skip(
            "key_fingerprint",
            "Signer fingerprint matches",
            "package carries no public_key_hint",
        )
        return
    if key_entry is None or not key_entry.get("public_key"):
        report.add_skip(
            "key_fingerprint",
            "Signer fingerprint matches",
            "no anchor key entry to compare against",
        )
        return
    actual = public_key_fingerprint(str(key_entry["public_key"]))
    if actual == hint:
        report.add_pass("key_fingerprint", "Signer fingerprint matches", hint)
    else:
        report.add_fail(
            "key_fingerprint",
            "Signer fingerprint matches",
            f"package expects signer {hint}, the supplied key is {actual} "
            "(this is likely the wrong tenant's trust anchor)",
        )


def _check_event_signatures(
    report: VerificationReport,
    timeline: list[Any],
    anchor: dict[str, Any] | None,
    raw_public_key: bytes | None,
    manifest_key: bytes | None,
) -> None:
    signed = [
        e for e in timeline if isinstance(e, dict) and e.get("signature")
    ]
    if not signed:
        report.add_skip(
            "event_signatures",
            "Event signatures valid",
            "no events in this package carry a per-event signature",
        )
        return
    if anchor is None and raw_public_key is None and manifest_key is None:
        report.add_skip(
            "event_signatures",
            "Event signatures valid",
            "no trust anchor or public key available",
        )
        return

    failures: list[str] = []
    for index, event in enumerate(signed):
        if anchor is not None:
            try:
                key, _ = select_key_for_timestamp(
                    anchor, event.get("signer_kid"), event.get("timestamp")
                )
            except AnchorError as exc:
                failures.append(f"event #{index} ({event.get('id')!r}): {exc}")
                continue
        else:
            key = raw_public_key if raw_public_key is not None else manifest_key  # type: ignore[assignment]
        if not _verify_ed25519(key, str(event["signature"]), _event_payload(event)):
            failures.append(f"event #{index} ({event.get('id')!r}) signature failed")

    if not failures:
        report.add_pass(
            "event_signatures",
            "Event signatures valid",
            f"{len(signed)} of {len(timeline)} events individually signed and verified",
        )
    else:
        head = failures[0]
        extra = f" (+{len(failures) - 1} more)" if len(failures) > 1 else ""
        report.add_fail("event_signatures", "Event signatures valid", head + extra)


def _check_stored_flags(report: VerificationReport, components: dict[str, Any]) -> None:
    hash_chain = components.get("hash_chain.json")
    if not isinstance(hash_chain, list) or not hash_chain:
        report.add_skip(
            "stored_flags",
            "Producer chain flags intact",
            "package carries no hash_chain.json",
        )
        return
    broken = [
        link
        for link in hash_chain
        if isinstance(link, dict) and link.get("verified") is False
    ]
    if not broken:
        report.add_pass(
            "stored_flags",
            "Producer chain flags intact",
            f"{len(hash_chain)} links recorded as verified at export time",
        )
    else:
        report.add_fail(
            "stored_flags",
            "Producer chain flags intact",
            f"{len(broken)} of {len(hash_chain)} links were already marked unverified "
            f"at export time (first: event_id={broken[0].get('event_id')!r})",
        )
