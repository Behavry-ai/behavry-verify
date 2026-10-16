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

Counterparts (repo ``Behavry-ai/behavry``):

  ``provenance_canonical_body`` -> ``backend/behavry/authority/provenance.py``
  ``bundle_canonical_bytes``    -> ``docs/strategy/AG3-CONTRACTS.md`` section 1.2
"""
from __future__ import annotations

import hashlib
import json
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


def _verify_ed25519_b64(public_key: bytes, signature_b64: str, payload: bytes) -> bool:
    from behavry_verify.package import _verify_ed25519

    return _verify_ed25519(public_key, signature_b64, payload)


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
                if key is None or not _verify_ed25519_b64(key, str(signature), payload):
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
# 15. Provenance anchored (package 1.4)
# ---------------------------------------------------------------------------

#: The first package version that carries ``anchors.json``.
ANCHORING_MIN_VERSION = (1, 4)

_ANCHOR_V3 = "behavry.audit_anchor.v3"


def check_provenance_anchoring(
    report: VerificationReport,
    components: dict[str, Any],
    manifest: dict[str, Any],
    anchor: dict[str, Any] | None,
    raw_public_key: bytes | None,
    tsa_roots: list[Any] | None,
) -> None:
    """Check 15: every anchor in ``anchors.json``, then classify each entry.

    The result is written to ``report.provenance_anchoring`` as well as to the
    check: counts per class, one row per anchor, and one per provenance entry.
    """
    # Imported here: audit_anchor imports package, which imports this module.
    from behavry_verify.audit_anchor import (
        _parse_time,
        anchor_provenance_hashes,
        verify_audit_anchor,
    )
    from behavry_verify.package import _package_version_tuple
    from behavry_verify.report import CheckStatus

    check_id = "provenance_anchoring"
    label = "Provenance anchored"
    if _package_version_tuple(manifest) < ANCHORING_MIN_VERSION:
        report.add_skip(
            check_id,
            label,
            f"package_version {manifest.get('package_version') or 'unknown'} predates "
            "anchors.json (1.4), so provenance entries are not checked against audit "
            "anchors: the package proves what Behavry signed, not when",
        )
        return

    raw = components.get("anchors.json")
    exports_raw = raw.get("anchors") if isinstance(raw, dict) else None
    if not isinstance(exports_raw, list):
        report.add_fail(
            check_id,
            label,
            'a package_version 1.4 package must carry anchors.json ({"anchors": [...]})',
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
        rows.append(row)
        if failed:
            what = ", ".join(failed)
            if "tenant" in failed:
                what += f" (anchor is for tenant {export.get('tenant_id')!r}, package {tenant!r})"
            failures.append(f"anchor {ident} ({period}) failed: {what}")

    # Classify each provenance entry of the package.
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
            else:
                item.update(
                    status="unanchored",
                    reason="no anchor in the package covers its time"
                    if ts is not None
                    else "its timestamp is unreadable",
                )
                uncovered_named.append(repr(entry.get("id")))
        counts[item["status"]] += 1
        classified.append(item)

    report.provenance_anchoring = {
        "anchor_count": len(exports),
        **counts,
        "anchors": rows,
        "entries": classified,
    }

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
    if uncovered_named:
        report.add_warn(
            check_id,
            label,
            f"{detail}. No anchor in this package covers {_named(uncovered_named)}, inside "
            "the sealed span: ask for the anchors of those periods",
        )
        return
    report.add_pass(check_id, label, detail)
