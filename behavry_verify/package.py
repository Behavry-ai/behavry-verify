"""APR evidence-package loading and verification.

Verifies a ``behavry.apr_evidence_package.v1`` archive with no Behavry
database, no live KMS, and no network call: the package plus a public key is
everything required.

Chain of trust::

    trust anchor -> package manifest signature -> Merkle root
                 -> per-event signatures -> per-agent hash chain
                 -> (1.2+) file digests -> event content -> authorization records
    observer anchor -> observer signatures over observations

From package_version 1.2 the producer exports every field a decision event's
hash covers, so each ``event_hash`` is RECOMPUTED from content here rather than
taken as given. Before 1.2 only the signed hashes could be checked, and the
report says so explicitly (``event_content`` SKIPPED, content NOT bound).

Unlike the reference CLI in the Behavry repo (``tools/verify_event.py``),
which returns on the first failed check, this module runs every check it can
and reports each independently. Checks whose meaning depends on a failed
predecessor are marked SKIPPED rather than passed.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
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
from behavry_verify.hashbody import (
    AUTHORIZATION_CLAIM,
    MAX_DECISION_HASH_VERSION,
    canonical_signing_bytes_agent_claim,
    observation_canonical_body,
    recompute_authorization_record_hash,
    recompute_decision_event_hash,
    recompute_observation_event_hash,
)
from behavry_verify.merkle import merkle_root
from behavry_verify.report import TrustSource, VerificationReport

__all__ = [
    "MAX_MEMBER_COUNT",
    "MAX_TOTAL_UNCOMPRESSED_BYTES",
    "PackageComponents",
    "PackageError",
    "load_package_from_bytes",
    "load_package_from_path",
    "verify_package",
]

PACKAGE_SCHEMA = "behavry.apr_evidence_package.v1"

# From package_version 1.1 onward, ``hash_chain.json``'s ``verified`` flag
# asserts per-event integrity (each event's own hash reconstructs) rather than
# contiguity between consecutive events in the package. The chain walk is not
# applicable to those packages — see the "Hash chain walk" step for why it was
# never a sound check on a session-scoped export.
CONTIGUITY_MAX_VERSION = (1, 1)

# From package_version 1.2 the producer exports every hashed field of each
# decision event, plus ``file_digests`` in the signed manifest and the
# authorization records and observations behind each decision.
CONTENT_BINDING_MIN_VERSION = (1, 2)

# Claim types whose content this verifier does not rebuild. Their hashes are
# still covered by the Merkle root and their own signatures; only the
# content-recompute step is skipped for them, and the report says so.
NON_DECISION_CLAIM_TYPES = frozenset(
    {"exposure", "disclosure_ack", "agent_report", "host_journal"}
)

# How many offending ids a report detail names before summarizing the rest.
_MAX_NAMED = 10

# Archive-bomb guards. A real package is a handful of JSON files; these caps
# are orders of magnitude above any legitimate export.
MAX_MEMBER_COUNT = 512
MAX_TOTAL_UNCOMPRESSED_BYTES = 256 * 1024 * 1024  # 256 MiB
MAX_SINGLE_MEMBER_BYTES = 128 * 1024 * 1024  # 128 MiB


class PackageError(ValueError):
    """Raised when a package cannot be read at all (not merely invalid)."""


class PackageComponents(dict[str, Any]):
    """Parsed package members, plus the raw bytes each was parsed from.

    ``file_digests`` (package 1.2+) commit to the exact bytes in the archive, so
    the loader keeps them. A plain ``dict`` is still accepted everywhere; for
    those, the digest check re-serializes with the producer's dump options.
    """

    def __init__(self, parsed: dict[str, Any], raw: dict[str, bytes]) -> None:
        super().__init__(parsed)
        self.raw: dict[str, bytes] = dict(raw)


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

    members: dict[str, bytes] = {}
    for info in infos:
        short = info.filename.rsplit("/", 1)[-1]
        if not short.endswith(".json"):
            # narrative.txt / narrative.pdf are not part of the integrity
            # envelope; verification operates over the JSON components only.
            continue
        if info.file_size > MAX_SINGLE_MEMBER_BYTES:
            raise PackageError(f"member {short!r} is too large to verify")
        members[short] = zf.read(info)
    return _parse_members(members)


def _parse_members(members: dict[str, bytes]) -> PackageComponents:
    if "manifest.json" not in members:
        raise PackageError("package has no manifest.json")
    parsed: dict[str, Any] = {}
    for name, data in members.items():
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise PackageError(f"member {name!r} is not valid UTF-8") from exc
        try:
            parsed[name] = json.loads(text)
        except json.JSONDecodeError as exc:
            raise PackageError(f"{name} is not valid JSON: {exc}") from exc
    return PackageComponents(parsed, members)


def load_package_from_bytes(data: bytes) -> PackageComponents:
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


def load_package_from_path(path: Path) -> PackageComponents:
    """Load an evidence package from a ZIP file or an unpacked directory."""
    if path.is_dir():
        roots = [p for p in path.iterdir() if p.is_dir() and p.name.startswith("apr-")]
        base = roots[0] if roots else path
        members = {f.name: f.read_bytes() for f in base.glob("*.json")}
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


def _package_version_tuple(manifest: dict[str, Any]) -> tuple[int, ...]:
    """``package_version`` as a comparable tuple; ``(0,)`` when unreadable.

    An absent, non-string or unparseable version sorts below every real one, so
    a package we cannot place takes the strictest available path. A verifier
    that relaxes a check because it failed to understand the input is worse than
    one that reports a break it cannot explain.
    """
    raw = manifest.get("package_version")
    if not isinstance(raw, str):
        return (0,)
    try:
        return tuple(int(part) for part in raw.split("."))
    except ValueError:
        return (0,)


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
    observer_anchors: list[dict[str, Any]] | None = None,
) -> VerificationReport:
    """Verify an assembled evidence package and return a full report.

    ``observer_anchors`` are the public keys of independent observers (see
    :func:`behavry_verify.anchor.validate_observer_anchors`), supplied by the
    verifying party. Observations whose key is not supplied are reported as
    not independently verified, never as passed.
    """
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

    # -- 6. Hash chain walk (packages before 1.1 only) ------------------------
    #
    # Contiguity is a property of a WHOLE chain, not of a slice of one. Behavry
    # hashes per agent, and an evidence package holds a single session, so its
    # events are a subsequence: consecutive events in the package legitimately
    # link to rows outside it when an agent runs two sessions at once, and
    # agentless browser events carry no link pointer at all while sharing one
    # chain key. Walking a package therefore reported breaks on intact sessions.
    #
    # From 1.1 the producer states per-event integrity instead, which holds for
    # any subset, and this walk does not apply. Deletion, insertion and pointer
    # tampering remain covered for every version by checks that do not depend on
    # ordering: the Merkle root (step 3) is computed over the event set and is
    # signed as part of the manifest, and each event's own signature (step 5)
    # covers its previous_hash.
    #
    # Older packages are still walked, because their stored flags were produced
    # under the old rule and the two must agree. An unrecognized version sorts
    # below 1.1 and takes the stricter path: never relax a check because the
    # version could not be read.
    if _package_version_tuple(manifest) < CONTIGUITY_MAX_VERSION:
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
    else:
        report.add_skip(
            "chain",
            "No chain breaks",
            "not applicable to package_version "
            f"{report.package_version or 'unknown'}: an evidence package holds one "
            "session, which is a subsequence of the agent's chain, so consecutive "
            "events need not link to each other. Integrity of this package's "
            "events is covered by the Merkle root and the per-event signatures.",
        )

    # -- 7. Stored per-link verified flags ------------------------------------
    _check_stored_flags(report, components)

    # -- 8. File digests (1.2+) -----------------------------------------------
    #
    # Before 1.2 the manifest signed only itself, so every other file could be
    # edited without breaking a signature. 1.2 puts a digest of each data file
    # INSIDE the signed manifest.
    content_bound = _package_version_tuple(manifest) >= CONTENT_BINDING_MIN_VERSION
    _check_file_digests(report, components, manifest, content_bound)

    # -- 9. Event content (1.2+, or any row carrying hash_version) ------------
    #
    # Every check above rests on the signed hashes. This one proves the
    # content shown with each hash is what was hashed: a rewritten action,
    # target, policy_result or tool_name changes the recomputation.
    _check_event_content(report, timeline, content_bound)

    # -- 10. Authorization records (1.2+) -------------------------------------
    _check_authorization_records(
        report, components, timeline, anchor, raw_public_key, public_key
    )

    # -- 11. Independent observations (1.2+) ----------------------------------
    by_id = {
        e.get("id"): e for e in timeline if isinstance(e, dict) and e.get("id") is not None
    }
    _check_observations(report, components, by_id, observer_anchors or [])

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


# ---------------------------------------------------------------------------
# Content binding (package 1.2+, Sprint AG-1)
# ---------------------------------------------------------------------------


def _producer_dump(body: Any) -> bytes:
    """Mirror ``APRPackageGenerator._dump``: the bytes each file was written as."""
    return json.dumps(body, indent=2, sort_keys=True, default=str).encode("utf-8")


def _named(items: list[str]) -> str:
    head = ", ".join(items[:_MAX_NAMED])
    extra = f" (+{len(items) - _MAX_NAMED} more)" if len(items) > _MAX_NAMED else ""
    return head + extra


def _check_file_digests(
    report: VerificationReport,
    components: dict[str, Any],
    manifest: dict[str, Any],
    content_bound: bool,
) -> None:
    label = "File digests match"
    digests = manifest.get("file_digests")
    if not content_bound and digests is None:
        report.add_skip(
            "file_digests",
            label,
            f"package_version {report.package_version or 'unknown'} predates file "
            "digests: files other than the manifest are NOT covered by its signature",
        )
        return
    if not isinstance(digests, dict) or not digests:
        report.add_fail(
            "file_digests",
            label,
            "the manifest carries no file_digests, which every package_version "
            "1.2+ manifest must",
        )
        return

    raw = getattr(components, "raw", None)
    failures: list[str] = []
    reserialized = 0
    for name in sorted(digests):
        claimed = digests[name]
        if name not in components:
            failures.append(f"{name} missing")
            continue
        if isinstance(raw, dict) and name in raw:
            data = raw[name]
        else:
            data = _producer_dump(components[name])
            reserialized += 1
        actual = "sha256:" + hashlib.sha256(data).hexdigest()
        if actual != claimed:
            failures.append(f"{name} digest differs")
    if failures:
        report.add_fail("file_digests", label, _named(failures))
        return
    note = (
        f" ({reserialized} re-serialized with the producer's dump options, since "
        "raw bytes were not available)"
        if reserialized
        else ""
    )
    report.add_pass(
        "file_digests",
        label,
        f"{len(digests)} files match the digests in the signed manifest{note}",
    )


def _is_decision(event: dict[str, Any]) -> bool:
    return event.get("claim_type") in (None, "decision")


def _check_event_content(
    report: VerificationReport, timeline: list[Any], content_bound: bool
) -> None:
    label = "Event content matches hashes"
    events = [e for e in timeline if isinstance(e, dict)]
    carries_bodies = any("hash_version" in e for e in events)
    if not content_bound and not carries_bodies:
        report.add_skip(
            "event_content",
            label,
            f"package_version {report.package_version or 'unknown'} does not export "
            "the hashed fields, so event content is NOT bound: only the signed "
            "hashes were verified, and fields such as action, target, "
            "policy_result and tool_name could differ from what was hashed "
            "without detection",
        )
        return

    mismatched: list[str] = []
    stripped: list[str] = []
    unsupported: list[str] = []
    unhashed: list[str] = []
    non_decision: dict[str, int] = {}
    recomputed = 0
    for event in events:
        ident = repr(event.get("id"))
        if not _is_decision(event):
            claim = str(event.get("claim_type"))
            non_decision[claim] = non_decision.get(claim, 0) + 1
            continue
        # PRESENCE of the key, not its value: a 1.2 exporter always writes it,
        # so an absent key means the body was removed after signing.
        if "hash_version" not in event:
            if content_bound:
                stripped.append(ident)
            continue
        version = event.get("hash_version")
        if isinstance(version, int) and version > MAX_DECISION_HASH_VERSION:
            unsupported.append(f"{ident} (v{version})")
            continue
        if not event.get("event_hash"):
            unhashed.append(ident)
            continue
        recomputed += 1
        if recompute_decision_event_hash(event) != event.get("event_hash"):
            mismatched.append(ident)

    notes: list[str] = []
    if non_decision:
        kinds = ", ".join(f"{n} {k}" for k, n in sorted(non_decision.items()))
        notes.append(
            f"content recompute not applicable to non-decision claims ({kinds}); "
            "their hashes are covered by the Merkle root and signatures only"
        )
    if unhashed:
        notes.append(f"{len(unhashed)} decision event(s) carry no event_hash")

    problems: list[str] = []
    if mismatched:
        problems.append(
            "content does not reproduce the signed event_hash for event(s) "
            + _named(mismatched)
        )
    if stripped:
        problems.append(
            "hashed fields missing (no hash_version) for event(s) " + _named(stripped)
        )
    if unsupported:
        problems.append(
            "cannot rebuild newer hash_version for event(s) "
            + _named(unsupported)
            + f"; this verifier supports up to v{MAX_DECISION_HASH_VERSION}, upgrade "
            "behavry-verify"
        )
    if problems:
        report.add_fail("event_content", label, "; ".join(problems + notes))
        return
    if recomputed == 0:
        report.add_skip(
            "event_content",
            label,
            "; ".join(["no decision events to recompute"] + notes),
        )
        return
    report.add_pass(
        "event_content",
        label,
        "; ".join(
            [f"{recomputed} decision event hash(es) recomputed from content"] + notes
        ),
    )


def _key_for(
    anchor: dict[str, Any] | None,
    raw_public_key: bytes | None,
    manifest_key: bytes | None,
    kid: str | None,
    timestamp: Any,
) -> bytes:
    if anchor is not None:
        key, _ = select_key_for_timestamp(anchor, kid, timestamp)
        return key
    key = raw_public_key if raw_public_key is not None else manifest_key
    if key is None:
        raise AnchorError("no trust anchor or public key available")
    return key


def _check_authorization_records(
    report: VerificationReport,
    components: dict[str, Any],
    timeline: list[Any],
    anchor: dict[str, Any] | None,
    raw_public_key: bytes | None,
    manifest_key: bytes | None,
) -> None:
    label = "Authorization records valid"
    raw_records = components.get("authorization_records.json")
    records = [r for r in raw_records if isinstance(r, dict)] if isinstance(
        raw_records, list
    ) else []
    referencing = [
        e
        for e in timeline
        if isinstance(e, dict) and e.get("authorization_record_id") is not None
    ]
    if not records and not referencing:
        report.add_skip(
            "authorization_records",
            label,
            "package carries no authorization records",
        )
        return

    failures: list[str] = []
    by_id: dict[Any, dict[str, Any]] = {}
    signed = 0
    sig_unchecked: str | None = None
    have_key = anchor is not None or raw_public_key is not None or manifest_key is not None
    for record in records:
        ident = repr(record.get("id"))
        by_id[record.get("id")] = record
        if recompute_authorization_record_hash(record) != record.get("record_hash"):
            failures.append(f"record {ident} content does not reproduce record_hash")
        signature = record.get("signature")
        if not signature:
            continue
        signed += 1
        if not have_key:
            sig_unchecked = "no trust anchor or public key available"
            continue
        try:
            key = _key_for(
                anchor, raw_public_key, manifest_key,
                record.get("signer_kid"), record.get("timestamp"),
            )
        except AnchorError as exc:
            failures.append(f"record {ident}: {exc}")
            continue
        payload = canonical_signing_bytes_agent_claim(
            claim_type=AUTHORIZATION_CLAIM,
            event_hash=record.get("record_hash"),
            previous_hash=record.get("previous_hash"),
            timestamp=record.get("timestamp"),
            tenant_id=record.get("tenant_id"),
            agent_id=record.get("agent_id"),
        )
        if not _verify_ed25519(key, str(signature), payload):
            failures.append(f"record {ident} signature failed")

    for event in referencing:
        ident = repr(event.get("id"))
        record = by_id.get(event.get("authorization_record_id"))
        if record is None:
            failures.append(
                f"event {ident} references authorization record "
                f"{event.get('authorization_record_id')!r}, which is not in the package"
            )
        elif event.get("authorization_hash") != record.get("record_hash"):
            failures.append(
                f"event {ident} authorization_hash does not match record "
                f"{record.get('id')!r}"
            )

    if failures:
        report.add_fail("authorization_records", label, _named(failures))
        return
    unsigned = len(records) - signed
    summary = (
        f"{len(records)} record hash(es) recomputed, {len(referencing)} decision "
        f"binding(s) hold, {signed} signature(s)"
    )
    if unsigned:
        summary += f"; {unsigned} record(s) unsigned (bound through the decision hash only)"
    if sig_unchecked:
        report.add_skip(
            "authorization_records",
            label,
            f"{summary} NOT checked: {sig_unchecked}",
        )
        return
    report.add_pass("authorization_records", label, f"{summary} verified")


def _check_observations(
    report: VerificationReport,
    components: dict[str, Any],
    decisions_by_id: dict[Any, dict[str, Any]],
    observer_anchors: list[dict[str, Any]],
) -> None:
    label = "Observer signatures valid"
    raw_observations = components.get("observations.json")
    observations = (
        [o for o in raw_observations if isinstance(o, dict)]
        if isinstance(raw_observations, list)
        else []
    )
    if not observations:
        report.add_skip("observations", label, "package carries no observations")
        return

    counts = {"match": 0, "mismatch": 0, "absent": 0, "unobservable": 0}
    other = 0
    for observation in observations:
        status = observation.get("match_status")
        if status in counts:
            counts[status] += 1
        else:
            other += 1
    report.observation_summary = {**counts, **({"other": other} if other else {})}

    anchors_by_kid = {a.get("kid"): a for a in observer_anchors}
    failures: list[str] = []
    unverifiable: list[str] = []
    verified = 0
    for observation in observations:
        ident = repr(observation.get("id"))
        decision = decisions_by_id.get(observation.get("decision_event_id"))
        if decision is None:
            failures.append(
                f"observation {ident} points at decision event "
                f"{observation.get('decision_event_id')!r}, which is not in the timeline"
            )
            continue
        decision_hash = decision.get("event_hash")
        if observation.get("event_hash") is not None and recompute_observation_event_hash(
            observation, decision_event_hash=decision_hash
        ) != observation.get("event_hash"):
            failures.append(f"observation {ident} content does not reproduce its event_hash")
            continue
        kid = observation.get("observer_kid")
        observer = anchors_by_kid.get(kid)
        if observer is None:
            unverifiable.append(f"{ident} (kid {kid!r})")
            continue
        if observer.get("observer_id") != observation.get("observer_id") or observer.get(
            "observer_type"
        ) != observation.get("observer_type"):
            failures.append(
                f"observation {ident} claims observer "
                f"{observation.get('observer_type')}/{observation.get('observer_id')}, "
                f"but key {kid!r} belongs to "
                f"{observer.get('observer_type')}/{observer.get('observer_id')}"
            )
            continue
        body = observation_canonical_body(observation, decision_event_hash=decision_hash)
        if not _verify_ed25519(
            bytes.fromhex(observer["public_key_hex"]),
            str(observation.get("observer_signature") or ""),
            body.encode("utf-8"),
        ):
            failures.append(f"observation {ident} observer signature failed")
            continue
        verified += 1

    if failures:
        detail = _named(failures)
        if unverifiable:
            detail += (
                f"; {len(unverifiable)} not verified: observer key not supplied"
            )
        report.add_fail("observations", label, detail)
        return
    if unverifiable:
        report.add_skip(
            "observations",
            label,
            f"{verified} of {len(observations)} verified; observer key not supplied "
            f"— cannot verify independently: {_named(unverifiable)}",
        )
        return
    report.add_pass(
        "observations",
        label,
        f"{verified} observation(s) verified against the observer keys you supplied",
    )
