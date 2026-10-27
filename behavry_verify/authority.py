"""Authority evidence package checks (package 1.3, Behavry Sprint AG-3).

``GET /api/v1/agents/{id}/authority/package`` returns a ZIP rooted at
``authority-<agent_id>/`` with schema ``behavry.authority_evidence_package.v1``.
It is built with the same helpers as the APR package, so checks 1 to 11 in
:mod:`behavry_verify.package` apply unchanged. This module adds:

12. **Provenance chain** (``provenance.json``). For every entry: ``body_digest``
    recomputed over the RFC 8785 form of ``body``; ``entry_hash`` recomputed as
    ``compute_event_hash(provenance_canonical_body, previous_hash)``; the links
    from ``previous_hash = null`` at genesis; the Ed25519 signature under the
    Behavry trust anchor over the agent-claim payload with claim type
    ``provenance``; and the head and count against the signed manifest.
13. **Assessment bundles** (``assessments.json``). Each Minotaur envelope's
    canonical bytes and ``bundle_digest`` are recomputed, and its Ed25519
    signature is checked under an observer anchor the verifying party supplies,
    matching ``kid``, ``observer_id`` and ``observer_type``. Without one the
    bundle is not independently verified (SKIPPED, never passed). Every
    ``assessment`` provenance entry must reference a bundle present here.
14. **Lifecycle** (informational): which golden-path elements the provenance
    chain evidences.
15. **Provenance anchored** (package 1.4, Sprint AG-4 G-1, ``anchors.json``).
    Each audit anchor is verified as ``--audit-anchor`` would (canonical bytes
    and ``anchor_digest``, Behavry signature, RFC 3161 imprint and TSA
    signature, and the ``provenance_root`` recomputed from its records). Each
    provenance entry is then anchored, not yet anchored (newer than the last
    sealed period: reported, never a failure) or missing (inside a sealed
    period but not in its anchor: a failure, because it was added or altered
    after sealing). See ``docs/strategy/AG4-CONTRACTS.md`` section 4.

    Package 1.5 (Sprint AG-5 H-1, ``docs/strategy/AG5-CONTRACTS.md`` section 2)
    makes ``anchors.json`` a contiguous run of v3 anchors over the package's
    span, as provenance-only records (``records: "provenance"``, no events, so
    the event checks are skipped, never passed). Across the run the AUD-LINK
    chain must be unbroken, and ``anchor_count`` and ``anchor_head_digest`` in
    the signed manifest must match it. A withheld anchor then fails: in the
    middle it breaks the chain, at the head it breaks the head digest, and an
    entry inside the span but in no anchor's period is missing, not a warning.

    Package 1.6 (Sprint AG-6, ``docs/strategy/AG6-CONTRACTS.md`` section 4)
    adds the run's ``predecessor`` as a header-only record, committed to by
    ``anchor_predecessor_digest`` in the signed manifest, which closes front
    truncation: when it is v3, anchoring had already begun, so entries before
    the run are missing. Tail truncation is closed by anchor heads the
    verifying party obtains independently (``--anchor-head``): every entry
    older than a verified head's period end must be anchored. Heads apply to
    1.4 and 1.5 packages too, because they are evidence about the tenant.

    Since 0.7.0 (Sprint AG-7, ``docs/strategy/AG7-CONTRACTS.md`` section 3), a
    verified head whose period overlaps a run anchor, the predecessor or
    another verified head, with a different digest, is a fork and fails.

    Since 0.9.0 (Sprint AG-9, ``docs/strategy/AG9-CONTRACTS.md`` section 5),
    the verified heads of each ``--anchor-heads-dir`` folder must link: a
    v2/v3 head whose ``previous_anchor_digest`` is not the preceding held
    head's digest is a gap and fails.

Counterparts (repo ``Behavry-ai/behavry``):

  ``provenance_canonical_body`` -> ``backend/behavry/authority/provenance.py``
  ``bundle_canonical_bytes``    -> ``docs/strategy/AG3-CONTRACTS.md`` section 1.2
"""
from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from behavry_verify.anchor import AnchorError, select_key_for_timestamp
from behavry_verify.hashbody import (
    canonical_signing_bytes_agent_claim,
    compute_event_hash,
    normalize_hashed_timestamp,
)
from behavry_verify.jcs import content_digest
from behavry_verify.report import VerificationReport

__all__ = [
    "AUTHORITY_PACKAGE_SCHEMA",
    "LIFECYCLE_ELEMENTS",
    "PROVENANCE_CLAIM",
    "bundle_canonical_bytes",
    "bundle_digest",
    "check_assessments",
    "check_lifecycle",
    "check_provenance",
    "check_provenance_anchoring",
    "is_authority_package",
    "provenance_canonical_body",
    "provenance_entry_hash",
]

AUTHORITY_PACKAGE_SCHEMA = "behavry.authority_evidence_package.v1"
PROVENANCE_CLAIM = "provenance"
ASSESSMENT_BUNDLE_SCHEMA = "minotaur.assessment_result.v1"

_MAX_NAMED = 10


def _named(items: list[str]) -> str:
    head = ", ".join(items[:_MAX_NAMED])
    extra = f" (+{len(items) - _MAX_NAMED} more)" if len(items) > _MAX_NAMED else ""
    return head + extra


def is_authority_package(manifest: dict[str, Any], components: dict[str, Any]) -> bool:
    """1.3 checks apply to the authority schema, or to any package carrying provenance."""
    return manifest.get("schema") == AUTHORITY_PACKAGE_SCHEMA or "provenance.json" in components


# ---------------------------------------------------------------------------
# Canonical forms
# ---------------------------------------------------------------------------


def provenance_canonical_body(entry: dict[str, Any]) -> str:
    """Canonical JSON an entry's ``entry_hash`` covers.

    Mirrors ``authority/provenance.py::provenance_canonical_body`` (via
    ``body_for_row``): ``json.dumps(..., sort_keys=True)`` with the DEFAULT
    separators and ASCII escaping, and ``evidence_refs or []``. The exported
    ``timestamp`` is ``normalize_hashed_time(ts).isoformat()``, exactly the
    string that was hashed, so it is passed through unchanged (as for decision
    rows); re-rendering would add a zero microsecond field the producer omits.
    """
    return json.dumps(
        {
            "claim_type": PROVENANCE_CLAIM,
            "timestamp": normalize_hashed_timestamp(entry.get("timestamp")),
            "tenant_id": entry.get("tenant_id"),
            "agent_id": entry.get("agent_id"),
            "entry_type": entry.get("entry_type"),
            "actor": entry.get("actor"),
            "summary": entry.get("summary"),
            "body_digest": entry.get("body_digest"),
            "evidence_refs": entry.get("evidence_refs") or [],
        },
        sort_keys=True,
    )


def provenance_entry_hash(entry: dict[str, Any]) -> str:
    return compute_event_hash(provenance_canonical_body(entry), entry.get("previous_hash"))


def bundle_canonical_bytes(bundle: Any) -> bytes:
    """Contract 1.2: what Minotaur signs and what ``bundle_digest`` covers."""
    return json.dumps(bundle, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "ascii"
    )


def bundle_digest(bundle: Any) -> str:
    return "sha256:" + hashlib.sha256(bundle_canonical_bytes(bundle)).hexdigest()


# ---------------------------------------------------------------------------
# 12. Provenance chain
# ---------------------------------------------------------------------------


def _verify_signature_b64(public_key: bytes, signature_b64: str, payload: bytes) -> bool:
    from behavry_verify.package import _verify_signature

    return _verify_signature(public_key, signature_b64, payload)


def _entries(components: dict[str, Any]) -> tuple[list[dict[str, Any]] | None, Any]:
    raw = components.get("provenance.json")
    if not isinstance(raw, dict):
        return None, None
    entries = raw.get("entries")
    if not isinstance(entries, list):
        return None, raw.get("agent_id")
    return [e if isinstance(e, dict) else {} for e in entries], raw.get("agent_id")


def check_provenance(
    report: VerificationReport,
    components: dict[str, Any],
    manifest: dict[str, Any],
    anchor: dict[str, Any] | None,
    raw_public_key: bytes | None,
    manifest_key: bytes | None,
) -> None:
    label = "Provenance chain valid"
    entries, file_agent = _entries(components)
    if entries is None:
        report.add_fail(
            "provenance",
            label,
            "the package carries no readable provenance.json "
            '({"agent_id", "entries": [...]}), which every authority package must',
        )
        return

    agent_id = manifest.get("agent_id")
    failures: list[str] = []
    redacted = 0
    unchecked_sig: str | None = None
    have_key = anchor is not None or raw_public_key is not None or manifest_key is not None
    if agent_id is not None and file_agent is not None and file_agent != agent_id:
        failures.append(
            f"provenance.json is for agent {file_agent!r}, the manifest for {agent_id!r}"
        )

    previous: str | None = None
    for index, entry in enumerate(entries):
        ident = f"#{index} ({entry.get('id')!r}, {entry.get('entry_type')})"
        if agent_id is not None and entry.get("agent_id") != agent_id:
            # agent_id is in the hashed and signed scope, so a spliced entry
            # from another agent's chain may well verify on its own.
            failures.append(f"entry {ident} belongs to agent {entry.get('agent_id')!r}")
        if entry.get("previous_hash") != previous:
            failures.append(
                f"entry {ident} links to {entry.get('previous_hash')!r}, expected "
                f"{previous!r} (an entry was removed, inserted or reordered)"
            )
        # The body is bound through body_digest. A redacted body (absent or
        # null) leaves the chain verifiable from the digest alone.
        if entry.get("body") is None:
            redacted += 1
        elif content_digest(entry.get("body")) != entry.get("body_digest"):
            failures.append(f"entry {ident} body does not reproduce its body_digest")
        if provenance_entry_hash(entry) != entry.get("entry_hash"):
            failures.append(f"entry {ident} content does not reproduce its entry_hash")

        signature = entry.get("signature_b64")
        if not signature:
            failures.append(f"entry {ident} is unsigned")
        elif not have_key:
            unchecked_sig = "no trust anchor or public key available"
        else:
            try:
                if anchor is not None:
                    key, _ = select_key_for_timestamp(
                        anchor, entry.get("signer_kid"), entry.get("timestamp")
                    )
                else:
                    key = raw_public_key if raw_public_key is not None else manifest_key  # type: ignore[assignment]
            except AnchorError as exc:
                failures.append(f"entry {ident}: {exc}")
            else:
                payload = canonical_signing_bytes_agent_claim(
                    claim_type=PROVENANCE_CLAIM,
                    event_hash=entry.get("entry_hash"),
                    previous_hash=entry.get("previous_hash"),
                    timestamp=entry.get("timestamp"),
                    tenant_id=entry.get("tenant_id"),
                    agent_id=entry.get("agent_id"),
                )
                if key is None or not _verify_signature_b64(key, str(signature), payload):
                    failures.append(f"entry {ident} signature failed")
        previous = entry.get("entry_hash")

    head = entries[-1].get("entry_hash") if entries else None
    if "provenance_head" not in manifest:
        failures.append("the manifest states no provenance_head")
    elif manifest.get("provenance_head") != head:
        failures.append(
            f"the chain ends at {head!r}, the signed manifest states provenance_head "
            f"{manifest.get('provenance_head')!r} (entries were removed or appended)"
        )
    if "provenance_count" not in manifest:
        failures.append("the manifest states no provenance_count")
    elif manifest.get("provenance_count") != len(entries):
        failures.append(
            f"provenance.json holds {len(entries)} entries, the signed manifest states "
            f"{manifest.get('provenance_count')}"
        )

    if failures:
        report.add_fail("provenance", label, _named(failures))
        return
    detail = f"{len(entries)} entr{'y' if len(entries) == 1 else 'ies'} linked from genesis"
    if redacted:
        detail += f"; {redacted} body(ies) redacted, bound by body_digest only"
    if unchecked_sig:
        report.add_skip(
            "provenance",
            label,
            f"{detail}; hashes hold but signatures NOT checked: {unchecked_sig}",
        )
        return
    report.add_pass(
        "provenance",
        label,
        f"{detail}, every hash recomputed and every signature verified; head matches the manifest",
    )


# ---------------------------------------------------------------------------
# 13. Assessment bundles
# ---------------------------------------------------------------------------


def _assessment_refs(entry: dict[str, Any]) -> list[str]:
    """``bundle_digest`` values an ``assessment`` entry's evidence_refs name.

    The producer writes ``{"type": "assessment", "bundle_digest": "sha256:...",
    "assessment_id": "..."}``. Any dict carrying ``bundle_digest`` counts, as
    does a bare ``"sha256:..."`` string.
    """
    out: list[str] = []
    for ref in entry.get("evidence_refs") or []:
        if isinstance(ref, dict) and isinstance(ref.get("bundle_digest"), str):
            out.append(ref["bundle_digest"])
        elif isinstance(ref, str) and ref.startswith("sha256:"):
            out.append(ref)
    return out


def check_assessments(
    report: VerificationReport,
    components: dict[str, Any],
    manifest: dict[str, Any],
    observer_anchors: list[dict[str, Any]],
) -> None:
    label = "Assessment bundles valid"
    raw = components.get("assessments.json")
    items_raw = raw.get("assessments") if isinstance(raw, dict) else None
    items = [i for i in items_raw if isinstance(i, dict)] if isinstance(items_raw, list) else []
    entries, _ = _entries(components)
    assessment_entries = [e for e in (entries or []) if e.get("entry_type") == "assessment"]

    failures: list[str] = []
    if raw is not None and not isinstance(items_raw, list):
        failures.append('assessments.json is not {"assessments": [...]}')
    if "assessment_count" in manifest and manifest.get("assessment_count") != len(items):
        failures.append(
            f"assessments.json holds {len(items)}, the signed manifest states "
            f"{manifest.get('assessment_count')}"
        )
    if not items and not assessment_entries and not failures:
        report.add_skip("assessments", label, "the package carries no assessments")
        return

    anchors_by_kid = {a.get("kid"): a for a in observer_anchors}
    digests: set[str] = set()
    verified = 0
    unverifiable: list[str] = []
    for item in items:
        envelope = item.get("envelope") if isinstance(item.get("envelope"), dict) else {}
        bundle = envelope.get("bundle")
        sig = envelope.get("signature") if isinstance(envelope.get("signature"), dict) else {}
        ident = repr(
            (bundle.get("assessment_id") if isinstance(bundle, dict) else None) or item.get("id")
        )
        if not isinstance(bundle, dict):
            failures.append(f"assessment {ident} has no bundle")
            continue
        computed = bundle_digest(bundle)
        digests.add(computed)
        if envelope.get("bundle_digest") != computed:
            failures.append(
                f"assessment {ident} bundle does not reproduce its bundle_digest (the bundle "
                "was edited after it was signed)"
            )
            continue
        if bundle.get("schema") != ASSESSMENT_BUNDLE_SCHEMA:
            failures.append(f"assessment {ident} bundle schema is {bundle.get('schema')!r}")
            continue
        if sig.get("algorithm") not in (None, "ed25519"):
            failures.append(
                f"assessment {ident} uses unsupported algorithm {sig.get('algorithm')!r}"
            )
            continue
        kid = sig.get("kid")
        observer = anchors_by_kid.get(kid)
        if observer is None:
            unverifiable.append(f"{ident} (kid {kid!r})")
            continue
        if observer.get("observer_id") != sig.get("observer_id") or observer.get(
            "observer_type"
        ) != sig.get("observer_type"):
            failures.append(
                f"assessment {ident} claims observer {sig.get('observer_type')}/"
                f"{sig.get('observer_id')}, but key {kid!r} belongs to "
                f"{observer.get('observer_type')}/{observer.get('observer_id')}"
            )
            continue
        if not _verify_hex(observer["public_key_hex"], sig.get("signature_hex"), bundle):
            failures.append(f"assessment {ident} observer signature failed")
            continue
        verified += 1

    for entry in assessment_entries:
        ident = f"{entry.get('id')!r}"
        refs = _assessment_refs(entry)
        if not refs:
            failures.append(f"assessment provenance entry {ident} names no bundle_digest")
        for ref in refs:
            if ref not in digests:
                failures.append(
                    f"assessment provenance entry {ident} references bundle {ref}, which is "
                    "not in assessments.json"
                )

    if failures:
        detail = _named(failures)
        if unverifiable:
            detail += f"; {len(unverifiable)} not verified: observer key not supplied"
        report.add_fail("assessments", label, detail)
        return
    binding = f"{len(assessment_entries)} assessment provenance entr" + (
        "y references" if len(assessment_entries) == 1 else "ies reference"
    ) + " a bundle present"
    if unverifiable:
        report.add_skip(
            "assessments",
            label,
            f"{verified} of {len(items)} verified; {binding}; observer key not supplied, "
            f"so not independently verified: {_named(unverifiable)}",
        )
        return
    report.add_pass(
        "assessments",
        label,
        f"{verified} bundle(s) verified against the observer keys you supplied; {binding}",
    )


def _verify_hex(public_key_hex: str, signature_hex: Any, bundle: dict[str, Any]) -> bool:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    if not isinstance(signature_hex, str):
        return False
    try:
        signature = bytes.fromhex(signature_hex)
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex)).verify(
            signature, bundle_canonical_bytes(bundle)
        )
    except (ValueError, InvalidSignature):
        return False
    return True


# ---------------------------------------------------------------------------
# 14. Lifecycle (informational)
# ---------------------------------------------------------------------------

#: (key, label) in golden-path order.
LIFECYCLE_ELEMENTS: tuple[tuple[str, str], ...] = (
    ("authority_mapped", "authority mapped"),
    ("assessment", "assessed"),
    ("authority_verified_or_failed", "verified or failed"),
    ("authority_applied", "authority applied"),
    ("mismatch_detected", "mismatch detected"),
    ("authority_revoked", "authority revoked"),
    ("autonomy_demoted", "autonomy demoted"),
    ("revalidation_requested", "revalidation requested"),
    ("revalidated_and_applied", "re-assessed and re-applied"),
)


def check_lifecycle(report: VerificationReport, components: dict[str, Any]) -> None:
    """Which golden-path elements the provenance chain evidences.

    Informational only: a young agent legitimately has a short history. It is
    read from entry types, so it is only as strong as check 12.
    """
    entries, _ = _entries(components)
    types = [str(e.get("entry_type")) for e in (entries or [])]
    present = set(types)
    found = {
        "authority_mapped": "authority_mapped" in present,
        "assessment": "assessment" in present,
        "authority_verified_or_failed": bool(present & {"authority_verified", "authority_failed"}),
        "authority_applied": "authority_applied" in present,
        "mismatch_detected": "mismatch_detected" in present,
        "authority_revoked": "authority_revoked" in present,
        "autonomy_demoted": "autonomy_demoted" in present,
        "revalidation_requested": "revalidation_requested" in present,
        "revalidated_and_applied": False,
    }
    # A later assessment followed by authority_applied, after a mismatch:
    # restored or kept restricted.
    if "mismatch_detected" in present:
        after = types[types.index("mismatch_detected") + 1 :]
        if "assessment" in after:
            tail = after[after.index("assessment") + 1 :]
            found["revalidated_and_applied"] = "authority_applied" in tail
    report.lifecycle = found
    labels = dict(LIFECYCLE_ELEMENTS)
    shown = [labels[k] for k, _ in LIFECYCLE_ELEMENTS if found[k]]
    missing = [labels[k] for k, _ in LIFECYCLE_ELEMENTS if not found[k]]
    detail = f"evidenced: {', '.join(shown) or 'none'}"
    if missing:
        detail += f"; not evidenced: {', '.join(missing)}"
    report.add_info("lifecycle", "Authority lifecycle (informational)", detail)


# ---------------------------------------------------------------------------
# 15. Provenance anchored (package 1.4, and the chained run of 1.5)
# ---------------------------------------------------------------------------

#: The first package version that carries ``anchors.json``.
ANCHORING_MIN_VERSION = (1, 4)
#: AG-5 H-1: ``anchors.json`` is a contiguous AUD-LINK run (check 15 v2).
ANCHOR_CHAIN_MIN_VERSION = (1, 5)
#: AG-6: ``anchors.json`` carries the run's predecessor (check 15 v3).
ANCHOR_PREDECESSOR_MIN_VERSION = (1, 6)

#: AG6-CONTRACTS section 4, H4, verbatim.
NO_HEAD_NOTE = (
    "no independent anchor head supplied: truncation of the newest anchors cannot be "
    "ruled out"
)

_ANCHOR_V3 = "behavry.audit_anchor.v3"


def _overlaps(start: Any, end: Any, other_start: Any, other_end: Any) -> bool:
    """AG7-CONTRACTS section 3: two periods overlap when each starts before the other ends.

    Periods are half-open, so one that ends where the other starts does not
    overlap it. When either end is unreadable, an equal start still counts
    (the AG-6 form of H2).
    """
    if None not in (start, end, other_start, other_end):
        return start < other_end and other_start < end
    return start is not None and start == other_start


def _in_span_gap(sealed: list[Any], ts: Any) -> bool:
    """True when ``ts`` lies inside the run's span but in no anchor's period."""
    bounds = [(s[0], s[1]) for s in sealed if s[0] is not None and s[1] is not None]
    if not bounds:
        return False
    first = min(start for start, _ in bounds)
    last = max(end for _, end in bounds)
    return first <= ts < last and not any(start <= ts < end for start, end in bounds)


def check_provenance_anchoring(
    report: VerificationReport,
    components: dict[str, Any],
    manifest: dict[str, Any],
    anchor: dict[str, Any] | None,
    raw_public_key: bytes | None,
    tsa_roots: list[Any] | None,
    heads: list[dict[str, Any]] | None = None,
    head_folders: list[tuple[str, list[int]]] | None = None,
) -> None:
    """Check 15: every anchor in ``anchors.json``, then classify each entry.

    The result is written to ``report.provenance_anchoring`` as well as to the
    check: counts per class, one row per anchor, and one per provenance entry.
    A 1.5 package adds the chain (``chain_unbroken``, ``chain_breaks``) and the
    head digest, and per anchor ``records``, ``previous_anchor_digest``,
    ``event_checks`` and ``linked``. A 1.4 report keeps its AG-4 shape.

    ``heads`` are anchor records the verifying party obtained independently of
    the package (``GET /api/v1/audit/anchors/head``, AG6-CONTRACTS section 2).
    A 1.6 report, or any report given a head, adds ``heads`` and
    ``head_note``; a 1.6 report adds ``predecessor``.

    ``head_folders`` name the heads that came from one folder
    (``--anchor-heads-dir``), as ``(name, indices into heads)``. Each folder's
    verified heads must link (AG9-CONTRACTS section 5); a gap fails the check
    and is a row in ``head_gaps``, which a report given a folder carries.
    """
    # Imported here: audit_anchor imports package, which imports this module.
    from behavry_verify.audit_anchor import (
        _parse_time,
        anchor_provenance_hashes,
        describe_head_gap,
        find_head_gaps,
        verify_audit_anchor,
    )
    from behavry_verify.package import _package_version_tuple
    from behavry_verify.report import CheckStatus

    check_id = "provenance_anchoring"
    label = "Provenance anchored"
    version = _package_version_tuple(manifest)
    chained = version >= ANCHOR_CHAIN_MIN_VERSION
    with_predecessor = version >= ANCHOR_PREDECESSOR_MIN_VERSION
    heads = list(heads or [])
    if version < ANCHORING_MIN_VERSION:
        unused = (
            f"; the {len(heads)} anchor head(s) supplied were not applied" if heads else ""
        )
        report.add_skip(
            check_id,
            label,
            f"package_version {manifest.get('package_version') or 'unknown'} predates "
            "anchors.json (1.4), so provenance entries are not checked against audit "
            "anchors: the package proves what Behavry signed, not when" + unused,
        )
        return

    raw = components.get("anchors.json")
    exports_raw = raw.get("anchors") if isinstance(raw, dict) else None
    if not isinstance(exports_raw, list):
        report.add_fail(
            check_id,
            label,
            f"a package_version {manifest.get('package_version')} package must carry "
            'anchors.json ({"anchors": [...]})',
        )
        return
    exports = [a if isinstance(a, dict) else {} for a in exports_raw]

    failures: list[str] = []
    if "anchor_count" not in manifest:
        failures.append("the signed manifest states no anchor_count")
    elif manifest.get("anchor_count") != len(exports):
        failures.append(
            f"anchors.json holds {len(exports)} anchor(s), the signed manifest states "
            f"anchor_count {manifest.get('anchor_count')}"
        )
    if chained:
        # AG5-CONTRACTS section 2 item 6: the manifest commits to the head of
        # the run, so the newest anchor cannot be dropped and re-counted.
        head = exports[-1].get("anchor_digest") if exports else None
        if "anchor_head_digest" not in manifest:
            failures.append("the signed manifest states no anchor_head_digest")
        elif manifest.get("anchor_head_digest") != head:
            failures.append(
                f"the signed manifest states anchor_head_digest "
                f"{manifest.get('anchor_head_digest')}, the last anchor in anchors.json has "
                f"{head}"
            )

    tenant = manifest.get("tenant_id")
    rows: list[dict[str, Any]] = []
    for index, export in enumerate(exports):
        sub = verify_audit_anchor(
            export,
            anchor=anchor,
            raw_public_key=raw_public_key,
            trust_source=report.trust_source,
            tsa_roots=tsa_roots,
        )
        failed = [c.id for c in sub.checks if c.status is CheckStatus.FAIL]
        if tenant is not None and export.get("tenant_id") != tenant:
            failed.append("tenant")
        statuses = {c.id: c.status.value for c in sub.checks}
        summary = sub.anchor_summary or {}
        ident = export.get("anchor_id") or f"#{index}"
        period = f"{export.get('period_start')}..{export.get('period_end')}"
        row = {
            "anchor_id": export.get("anchor_id"),
            "schema": export.get("schema"),
            "period_start": export.get("period_start"),
            "period_end": export.get("period_end"),
            "anchor_digest": export.get("anchor_digest"),
            "provenance_count": export.get("provenance_count"),
            "verified": sub.verified and not failed,
            "failed_checks": failed,
            "signature": statuses.get("signature"),
            "tsa_gen_time": summary.get("tsa_gen_time"),
            "tsa_chain": statuses.get("tsa_chain"),
        }
        if chained:
            row.update(
                {
                    "records": export.get("records"),
                    "previous_anchor_digest": export.get("previous_anchor_digest"),
                    # skip for a provenance-only record: never a pass.
                    "event_checks": statuses.get("merkle_root"),
                    "linked": None,
                }
            )
            if export.get("schema") != _ANCHOR_V3:
                failed.append("schema")
        rows.append(row)
        if failed:
            what = ", ".join(failed)
            if "tenant" in failed:
                what += f" (anchor is for tenant {export.get('tenant_id')!r}, package {tenant!r})"
            if "schema" in failed:
                what += (
                    f" (a package 1.5 or later carries {_ANCHOR_V3} anchors only, this "
                    f"one is {export.get('schema')!r})"
                )
            failures.append(f"anchor {ident} ({period}) failed: {what}")

    # AG5-CONTRACTS section 2 item 5: the AUD-LINK chain across the run. The
    # first anchor's predecessor is outside the span and is not checked.
    breaks: list[dict[str, Any]] = []
    if chained:
        for index in range(1, len(exports)):
            before, after = exports[index - 1], exports[index]
            linked = bool(after.get("previous_anchor_digest")) and (
                after.get("previous_anchor_digest") == before.get("anchor_digest")
            )
            rows[index]["linked"] = linked
            if not linked:
                breaks.append(
                    {
                        "after_anchor_id": before.get("anchor_id"),
                        "before_anchor_id": after.get("anchor_id"),
                        "period_end": before.get("period_end"),
                        "period_start": after.get("period_start"),
                    }
                )
                failures.append(
                    f"anchor chain broken between {before.get('period_end')} and "
                    f"{after.get('period_start')}: an anchor is missing"
                )

    def _verify_record(record: dict[str, Any]) -> tuple[bool, list[str], dict[str, Any]]:
        sub = verify_audit_anchor(
            record,
            anchor=anchor,
            raw_public_key=raw_public_key,
            trust_source=report.trust_source,
            tsa_roots=tsa_roots,
        )
        failed = [c.id for c in sub.checks if c.status is CheckStatus.FAIL]
        if tenant is None or record.get("tenant_id") != tenant:
            failed.append("tenant")
        if not sub.verified and not failed:
            # Nothing failed, yet nothing proves who sealed it either.
            failed.append("signature not checked")
        return sub.verified and not failed, failed, sub.anchor_summary or {}

    def _what(record: dict[str, Any], failed: list[str]) -> str:
        what = ", ".join(failed)
        if "tenant" in failed:
            what += f" (record is for tenant {record.get('tenant_id')!r}, package {tenant!r})"
        return what

    # AG6-CONTRACTS section 4, P1: the run's predecessor (package 1.6).
    predecessor_row: dict[str, Any] | None = None
    predecessor_v3 = False
    predecessor: dict[str, Any] | None = None
    if with_predecessor:
        pointer = (exports[0].get("previous_anchor_digest") or None) if exports else None
        pred_raw = raw.get("predecessor")
        if pred_raw is not None and not isinstance(pred_raw, dict):
            failures.append("anchors.json predecessor is neither an anchor record nor null")
        predecessor = pred_raw if isinstance(pred_raw, dict) else None
        pred_digest = predecessor.get("anchor_digest") if predecessor is not None else None
        if "anchor_predecessor_digest" not in manifest:
            failures.append("the signed manifest states no anchor_predecessor_digest")
        elif manifest.get("anchor_predecessor_digest") != pred_digest:
            failures.append(
                f"the signed manifest states anchor_predecessor_digest "
                f"{manifest.get('anchor_predecessor_digest')}, the predecessor in "
                f"anchors.json has {pred_digest}"
            )
        if predecessor is not None:
            ok, failed, pred_summary = _verify_record(predecessor)
            if predecessor.get("records") != "header":
                failed.append("records")
                ok = False
            ident = predecessor.get("anchor_id") or "predecessor"
            predecessor_row = {
                "anchor_id": predecessor.get("anchor_id"),
                "schema": predecessor.get("schema"),
                "anchor_digest": pred_digest,
                "verified": ok,
                "period_start": predecessor.get("period_start"),
                "period_end": predecessor.get("period_end"),
                "failed_checks": failed,
            }
            predecessor_v3 = predecessor.get("schema") == _ANCHOR_V3
            if not ok:
                what = _what(predecessor, failed)
                if "records" in failed:
                    what += (
                        f" (the predecessor is a header-only record, this one carries "
                        f"records {predecessor.get('records')!r})"
                    )
                failures.append(f"predecessor {ident} does not verify: {what}")
            if pointer is None:
                failures.append(
                    "anchors.json carries a predecessor, but "
                    + (
                        "the run is empty"
                        if not exports
                        else "the first anchor starts the chain (no previous_anchor_digest)"
                    )
                    + ", so it must be null"
                )
            elif pred_digest != pointer:
                failures.append(
                    f"the predecessor's digest {pred_digest} is not the first anchor's "
                    f"previous_anchor_digest {pointer}: it is not the anchor before the run"
                )
        elif pointer is not None:
            failures.append(
                f"the first anchor's previous_anchor_digest is {pointer}, but anchors.json "
                "carries no predecessor, so where the run begins cannot be confirmed"
            )

    # AG6-CONTRACTS section 4, H1, and AG7-CONTRACTS section 3, H2a and H2b:
    # anchor heads supplied by the verifying party. A head that does not
    # verify is a finding, and unused.
    head_rows: list[dict[str, Any]] = []
    verified_heads: list[tuple[dict[str, Any], Any, Any]] = []
    verified_index: list[int] = []
    forks: list[dict[str, Any]] = []

    def _fork(
        kind: str,
        index: int,
        head: dict[str, Any],
        other: dict[str, Any],
        other_index: int | None = None,
    ) -> None:
        row = {
            "against": kind,
            "head_index": index,
            "head_anchor_id": head.get("anchor_id"),
            "head_period_start": head.get("period_start"),
            "head_period_end": head.get("period_end"),
            "head_anchor_digest": head.get("anchor_digest"),
            "anchor_id": other.get("anchor_id"),
            "anchor_period_start": other.get("period_start"),
            "anchor_period_end": other.get("period_end"),
            "anchor_digest": other.get("anchor_digest"),
        }
        if other_index is not None:
            row["other_head_index"] = other_index
        forks.append(row)
        for i in (index, other_index):
            if i is not None and "fork" not in head_rows[i]["failed_checks"]:
                head_rows[i]["failed_checks"].append("fork")
        what = {
            "run": "the package's anchor",
            "predecessor": "the run's predecessor",
            "head": "anchor head",
        }[kind]
        failures.append(
            f"fork: anchor head {head.get('anchor_id') or f'#{index}'} "
            f"({head.get('period_start')}..{head.get('period_end')}) contradicts {what} "
            f"{other.get('anchor_id')} ({other.get('period_start')}.."
            f"{other.get('period_end')}): their periods overlap, with different digests "
            f"({head.get('anchor_digest')} and {other.get('anchor_digest')})"
        )

    for index, head in enumerate(heads):
        head = head if isinstance(head, dict) else {}
        ok, failed, head_summary = _verify_record(head)
        ident = head.get("anchor_id") or f"#{index}"
        period = f"{head.get('period_start')}..{head.get('period_end')}"
        head_rows.append(
            {
                "anchor_id": head.get("anchor_id"),
                "period_start": head.get("period_start"),
                "period_end": head.get("period_end"),
                "anchor_digest": head.get("anchor_digest"),
                "verified": ok,
                "tsa_gen_time": head_summary.get("tsa_gen_time"),
                "failed_checks": failed,
            }
        )
        if not ok:
            failures.append(
                f"anchor head {ident} ({period}) does not verify and is not used: "
                f"{_what(head, failed)}"
            )
            continue
        head_start = _parse_time(head.get("period_start"))
        head_end = _parse_time(head.get("period_end"))
        # H2a: against every run anchor and the predecessor.
        known = [("run", other) for other in exports]
        if predecessor is not None:
            known.append(("predecessor", predecessor))
        for kind, other in known:
            if other.get("anchor_digest") != head.get("anchor_digest") and _overlaps(
                head_start, head_end,
                _parse_time(other.get("period_start")), _parse_time(other.get("period_end")),
            ):
                _fork(kind, index, head, other)
        # H2b: against every head verified before it.
        for (other, other_start, other_end), other_index in zip(
            verified_heads, verified_index, strict=True
        ):
            if other.get("anchor_digest") != head.get("anchor_digest") and _overlaps(
                head_start, head_end, other_start, other_end
            ):
                _fork("head", index, head, other, other_index)
        verified_heads.append((head, head_start, head_end))
        verified_index.append(index)

    # AG9-CONTRACTS section 5: a folder of heads must link. Only verified heads
    # count: one that does not verify is already a finding and is unused, and
    # an unverified record must not be able to bridge a gap. A fork inside the
    # folder is H2b above and is not reported again as a gap (find_head_gaps).
    head_gaps: list[dict[str, Any]] = []
    verified_set = set(verified_index)
    for folder, indices in head_folders or []:
        held = [heads[i] for i in indices if i in verified_set]
        for gap in find_head_gaps(held):
            head_gaps.append({"folder": folder, **gap})
            failures.append(
                f"anchor heads folder {folder}: {describe_head_gap(gap)}; a folder of heads "
                "that does not link cannot vouch for completeness"
            )

    # Classify each provenance entry of the package.
    first_start = _parse_time(exports[0].get("period_start")) if exports else None
    sealed = []
    for export, row in zip(exports, rows, strict=True):
        start = _parse_time(export.get("period_start"))
        end = _parse_time(export.get("period_end"))
        is_v3 = export.get("schema") == _ANCHOR_V3
        hashes = set(anchor_provenance_hashes(export) or []) if is_v3 else set()
        sealed.append((start, end, is_v3, hashes, row))
    ends = [end for _, end, _, _, _ in sealed if end is not None]
    latest_end = max(ends) if ends else None

    entries, _ = _entries(components)
    classified: list[dict[str, Any]] = []
    counts = {
        "anchored": 0, "not_yet_anchored": 0, "missing": 0, "unanchored": 0,
        "anchor_unverified": 0,
    }
    missing_named: list[str] = []
    front_missing: list[str] = []
    tail_missing: dict[int, tuple[dict[str, Any], list[str]]] = {}
    uncovered_named: list[str] = []
    for entry in entries or []:
        h = entry.get("entry_hash")
        ts = _parse_time(entry.get("timestamp"))
        item: dict[str, Any] = {
            "id": entry.get("id"),
            "entry_hash": h,
            "timestamp": entry.get("timestamp"),
            "status": "",
            "anchor_id": None,
            "tsa_gen_time": None,
            "reason": None,
        }
        holding = [s for s in sealed if s[2] and h and h in s[3]]
        verified = [s for s in holding if s[4]["verified"]]
        if verified:
            row = verified[0][4]
            item.update(
                status="anchored", anchor_id=row["anchor_id"], tsa_gen_time=row["tsa_gen_time"]
            )
        elif holding:
            row = holding[0][4]
            item.update(
                status="anchor_unverified",
                anchor_id=row["anchor_id"],
                reason="its hash is in an anchor whose own checks did not pass",
            )
        else:
            covering = [
                s for s in sealed
                if ts is not None and s[0] is not None and s[1] is not None
                and s[0] <= ts < s[1]
            ]
            v3_cover = [s for s in covering if s[2]]
            if v3_cover:
                row = v3_cover[0][4]
                item.update(
                    status="missing",
                    anchor_id=row["anchor_id"],
                    reason="inside a sealed period, but its hash is not in that anchor: it "
                    "was added or altered after sealing",
                )
                missing_named.append(f"{entry.get('id')!r} (period {row['period_start']})")
            elif chained and ts is not None and _in_span_gap(sealed, ts):
                # AG5-CONTRACTS section 2 item 7: with every anchor of the span
                # present, a gap between two of them is a period that held
                # nothing when it was sealed. An entry there was written later
                # and backdated. Under a broken chain it may instead sit in the
                # withheld anchor; the check fails on the break either way.
                item.update(
                    status="missing",
                    reason=(
                        "inside the anchored span but in no anchor's period: the chain "
                        "is broken here, so the anchor sealing it may have been withheld"
                    )
                    if breaks
                    else "inside the anchored span but in no anchor's period: that "
                    "period held nothing when it was sealed, so the entry was written "
                    "later and backdated",
                )
                missing_named.append(f"{entry.get('id')!r} (at {entry.get('timestamp')})")
            elif ts is not None and latest_end is not None and ts >= latest_end:
                item.update(
                    status="not_yet_anchored",
                    reason="newer than the latest sealed period in the package",
                )
            elif ts is not None and latest_end is None:
                item.update(
                    status="not_yet_anchored",
                    reason="the package carries no anchor yet",
                )
            elif covering:
                row = covering[0][4]
                item.update(
                    status="unanchored",
                    anchor_id=row["anchor_id"],
                    reason=f"its period was sealed under {row['schema']}, which predates "
                    "provenance anchoring",
                )
            elif (
                predecessor_v3 and ts is not None and first_start is not None
                and ts < first_start
            ):
                # AG6-CONTRACTS section 4, P2: the anchor before the run is v3,
                # so anchoring had already begun and the run starts too late.
                item.update(
                    status="missing",
                    anchor_id=predecessor_row["anchor_id"] if predecessor_row else None,
                    reason=(
                        "before the first anchor's period, but the anchor before the run "
                        f"({predecessor_row['anchor_id'] if predecessor_row else None}) is "
                        f"{_ANCHOR_V3}: anchoring had already begun, so the run should "
                        "have started earlier"
                    ),
                )
                front_missing.append(f"{entry.get('id')!r} (at {entry.get('timestamp')})")
            elif chained and ts is not None:
                item.update(
                    status="unanchored",
                    reason="before the first anchor's period: it predates provenance "
                    "anchoring (v3)",
                )
            else:
                item.update(
                    status="unanchored",
                    reason="no anchor in the package covers its time"
                    if ts is not None
                    else "its timestamp is unreadable",
                )
                uncovered_named.append(repr(entry.get("id")))
        if item["status"] == "not_yet_anchored" and ts is not None:
            # AG6-CONTRACTS section 4, H3: a verified head proves this time was
            # sealed, so an entry older than its period end must be anchored.
            covering_heads = sorted(
                (h for h in verified_heads if h[2] is not None and ts < h[2]),
                key=lambda h: h[2],
            )
            if covering_heads:
                head, head_start, _ = covering_heads[0]
                where = (
                    f"{head.get('anchor_id')} "
                    f"({head.get('period_start')}..{head.get('period_end')})"
                )
                if head_start is not None and ts < head_start:
                    reason = (
                        f"sealed before anchor {where}, by an anchor the package does not "
                        "carry"
                    )
                else:
                    reason = f"sealed by anchor {where}, which the package does not carry"
                item.update(status="missing", anchor_id=head.get("anchor_id"), reason=reason)
                tail_missing.setdefault(id(head), (head, []))[1].append(repr(entry.get("id")))
        counts[item["status"]] += 1
        classified.append(item)

    report.provenance_anchoring = {
        "anchor_count": len(exports),
        **counts,
        "anchors": rows,
        "entries": classified,
    }
    if chained:
        report.provenance_anchoring.update(
            {
                "package_version": manifest.get("package_version"),
                "anchor_head_digest": exports[-1].get("anchor_digest") if exports else None,
                "chain_unbroken": not breaks,
                "chain_breaks": breaks,
            }
        )
    if with_predecessor or heads:
        report.provenance_anchoring.update(
            {"heads": head_rows, "head_note": None if heads else NO_HEAD_NOTE}
        )
    if heads:
        report.provenance_anchoring["forks"] = forks
    if head_folders:
        report.provenance_anchoring["head_gaps"] = head_gaps
    if with_predecessor:
        report.provenance_anchoring["predecessor"] = predecessor_row

    if front_missing:
        failures.append(
            f"{len(front_missing)} provenance entr"
            f"{'y is' if len(front_missing) == 1 else 'ies are'} older than the run, but the "
            f"anchor before it ({predecessor_row['anchor_id'] if predecessor_row else None}) "
            f"is {_ANCHOR_V3}, so anchoring had already begun and the anchors sealing them "
            f"were left out: {_named(front_missing)}"
        )
    created = _parse_time(manifest.get("created_at"))
    for head, names in tail_missing.values():
        sealed_time = _parse_time(
            (head.get("tsa") or {}).get("gen_time") if isinstance(head.get("tsa"), dict) else None
        ) or _parse_time(head.get("sealed_at"))
        hint = ""
        if created is not None and sealed_time is not None and sealed_time > created:
            hint = (
                " (this head was sealed after the package was created, so the package may "
                "simply predate it: export a fresh package and verify it against this head)"
            )
        failures.append(
            f"{len(names)} provenance entr{'y' if len(names) == 1 else 'ies'} older than "
            f"the end of anchor head {head.get('anchor_id')} ({head.get('period_start')}.."
            f"{head.get('period_end')}) {'is' if len(names) == 1 else 'are'} not anchored in "
            "the package: the anchors sealing them exist but the package does not carry "
            f"them, so its run stops short of the head{hint}: {_named(names)}"
        )
    if missing_named:
        failures.append(
            f"{len(missing_named)} provenance entr"
            f"{'y is' if len(missing_named) == 1 else 'ies are'} missing from the anchor "
            f"sealing their period: {_named(missing_named)}"
        )

    tallies = (
        f"{counts['anchored']} of {len(classified)} provenance entries anchored, "
        f"{counts['not_yet_anchored']} not yet anchored, {counts['missing']} missing"
    )
    if counts["unanchored"]:
        tallies += f", {counts['unanchored']} unanchored"
    if failures:
        report.add_fail(check_id, label, f"{_named(failures)}; {tallies}")
        return
    unverified = [r for r in rows if not r["verified"]]
    if unverified:
        report.add_skip(
            check_id,
            label,
            f"{len(unverified)} of {len(rows)} anchor(s) could not be verified (their "
            "Behavry signature is absent, or no trust anchor or public key was available "
            f"to check it), so nothing in them is proven anchored; "
            f"{tallies}",
        )
        return
    times = []
    for row in rows:
        stamp = row["tsa_gen_time"] or "no TSA"
        times.append(f"{row['anchor_id']} ({row['period_start']}..{row['period_end']}): {stamp}")
    detail = f"{tallies}; {len(rows)} anchor(s) verified" + (
        f": {_named(times)}" if times else ""
    )
    if chained and len(rows) > 1:
        detail += f"; chain unbroken across {len(rows)} anchors"
    if chained and any(r.get("records") == "provenance" for r in rows):
        detail += (
            "; event checks skipped on provenance-only anchor records (the package's own "
            "events are covered by its Merkle root and signatures)"
        )
    if with_predecessor:
        if predecessor_row is not None:
            detail += (
                f"; the run follows predecessor {predecessor_row['anchor_id']} "
                f"({predecessor_row['schema']}), verified as a header-only record"
            )
        else:
            detail += "; the run starts the anchor chain (no predecessor)"
    if verified_heads:
        newest = max(
            verified_heads, key=lambda h: h[2] or datetime.min.replace(tzinfo=UTC)
        )[0]
        detail += (
            f"; {len(verified_heads)} independent anchor head(s) verified, the newest "
            f"{newest.get('anchor_id')} "
            f"({newest.get('period_start')}..{newest.get('period_end')}), "
            "so no older entry may read as not yet anchored"
        )
    elif with_predecessor:
        detail += f"; {NO_HEAD_NOTE}"
    if head_folders:
        detail += (
            f"; the verified heads of {len(head_folders)} anchor heads folder(s) link, "
            "with no gap"
        )
    if uncovered_named:
        report.add_warn(
            check_id,
            label,
            f"{detail}. No anchor in this package covers {_named(uncovered_named)}, inside "
            "the sealed span: ask for the anchors of those periods",
        )
        return
    report.add_pass(check_id, label, detail)
