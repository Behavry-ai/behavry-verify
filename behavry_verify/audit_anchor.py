"""Audit-anchor verification: the RFC 3161 "when" proof (Behavry E-8).

An evidence package proves that the holder of a key vouched for a record. That
is a claim made by a party that also owns the clock. An **audit anchor** adds
the one thing it cannot: a timestamp from an authority whose key Behavry does
not hold, over a digest that commits to a tenant's whole audit trail for one
period.

Input is the JSON from ``GET /api/v1/audit/anchors/{id}/export``, which is
byte-for-byte what the WORM copy holds. This is a port of
``tools/verify_event.py --anchor`` and ``--anchor-chain`` in the Behavry repo,
with the canonical form mirroring ``backend/behavry/audit/anchoring.py``:

1. recompute the Merkle root over the period's ordered event hashes and check
   it, the event count and the first/last hash against the anchor;
2. rebuild the canonical anchor bytes and check their SHA-256 against
   ``anchor_digest``;
3. check Behavry's signature over those bytes under the trust anchor;
4. check each anchored event's own signature;
5. check the RFC 3161 token's message imprint equals that digest;
6. check the TSA's own signature on the token (the reference verifier does not);
7. walk the TSA's certificate chain to roots the verifying party supplies.

``openssl ts -verify`` alone cannot do 1 to 3: it validates a token against a
digest you hand it, and cannot tell you that the digest is the one these
events produce. That link is the whole claim.

Unlike the reference, every check runs and is reported (see
:mod:`behavry_verify.report`), and an anchor carrying no Behavry signature is
NOT VERIFIED here: the reference prints a note and passes it, but a verdict
this tool calls verified always rests on a checked signature.
"""
from __future__ import annotations

import base64
import binascii
import gzip
import hashlib
import io
import json
import zlib
from datetime import UTC, datetime
from typing import Any

from cryptography import x509

from behavry_verify.anchor import AnchorError, select_key_for_timestamp
from behavry_verify.keyhistory import KeyWindowError, attach_history, history_start
from behavry_verify.merkle import merkle_root
from behavry_verify.package import _event_payload, _verify_ed25519
from behavry_verify.report import TrustSource, VerificationReport
from behavry_verify.rfc3161 import (
    DERError,
    parse_timestamp_token,
    validate_tsa_chain,
    verify_tsa_signature,
)
from behavry_verify.witness import WitnessOptions, check_record_witness

__all__ = [
    "ANCHOR_SCHEMA",
    "ANCHOR_SCHEMA_V1",
    "ANCHOR_SCHEMA_V2",
    "ANCHOR_SCHEMA_V3",
    "EVENT_CHECKS_SKIPPED_REASON",
    "HEADER_CHECKS_SKIPPED_REASON",
    "RECORDS_HEADER",
    "RECORDS_PROVENANCE",
    "anchor_provenance_hashes",
    "canonical_anchor_bytes",
    "describe_head_gap",
    "find_head_gaps",
    "load_anchor_record_bytes",
    "verify_audit_anchor",
    "verify_anchor_chain",
]

# Mirrors audit/anchoring's schema constants. The schema string is inside the
# signed payload, so a mismatch is a signature failure, not a soft warning.
# Every version is kept forever: an anchor is rebuilt under the schema IT was
# sealed with, never the current one.
ANCHOR_SCHEMA_V1 = "behavry.audit_anchor.v1"
# AUD-LINK: adds previous_anchor_digest inside the signed bytes.
ANCHOR_SCHEMA_V2 = "behavry.audit_anchor.v2"
# AG-4 G-1: adds the period's agent provenance (root, count, first/last hash).
ANCHOR_SCHEMA_V3 = "behavry.audit_anchor.v3"
ANCHOR_SCHEMA = ANCHOR_SCHEMA_V3

#: AG-5 H-1: an export carrying ``records: "provenance"`` holds the period's
#: provenance records and no events (AG5-CONTRACTS section 1).
RECORDS_PROVENANCE = "provenance"
#: The reason AG5-CONTRACTS section 2 item 4 gives, verbatim.
EVENT_CHECKS_SKIPPED_REASON = (
    "event records are not carried; the package's own events are covered by its "
    "Merkle root and signatures"
)

#: AG-6: an export carrying ``records: "header"`` holds the signed fields and
#: no records at all, neither events nor provenance (AG6-CONTRACTS section 1).
#: It is what ``/anchors/head`` and ``/anchors/{id}/header`` return, and the
#: form of a package 1.6 ``predecessor``.
RECORDS_HEADER = "header"
#: The reason AG6-CONTRACTS section 1 gives, verbatim.
HEADER_CHECKS_SKIPPED_REASON = (
    "header-only record: the signed bytes are verified, the records they commit to "
    "are not carried"
)

_KNOWN_SCHEMAS = frozenset({ANCHOR_SCHEMA_V1, ANCHOR_SCHEMA_V2, ANCHOR_SCHEMA_V3})
#: Schemas carrying the AUD-LINK back-pointer. v3 keeps it.
_CHAINED_SCHEMAS = frozenset({ANCHOR_SCHEMA_V2, ANCHOR_SCHEMA_V3})


def canonical_anchor_bytes(anchor: dict[str, Any]) -> bytes:
    """Canonical bytes an anchor's signature and TSA token cover.

    Mirrors ``audit/anchoring.canonical_anchor_bytes`` exactly: sorted keys,
    tight separators, ASCII-escaped. Timestamps are taken from the export
    verbatim (the exporter already wrote them in UTC microsecond form), since
    re-rendering is a second chance to disagree with the producer.

    ``tenant_id``, ``first_event_hash``, ``last_event_hash``, (v2, v3)
    ``previous_anchor_digest`` and (v3) ``first_provenance_hash`` and
    ``last_provenance_hash`` fall back to ``""`` as the producer does, so
    ``None`` and ``""`` yield the same bytes; a v3 ``provenance_root`` falls
    back to the empty root and ``provenance_count`` to 0, again as the producer
    does (AG4-CONTRACTS section 1). The export's OWN ``schema`` picks the
    shape, defaulting to v1 for anchors sealed before the field existed.
    """
    schema = anchor.get("schema") or ANCHOR_SCHEMA_V1
    payload = {
        "schema": schema,
        "tenant_id": anchor.get("tenant_id") or "",
        "period_start": anchor.get("period_start"),
        "period_end": anchor.get("period_end"),
        "event_count": anchor.get("event_count"),
        "merkle_root": anchor.get("merkle_root"),
        "first_event_hash": anchor.get("first_event_hash") or "",
        "last_event_hash": anchor.get("last_event_hash") or "",
    }
    if schema in _CHAINED_SCHEMAS:
        payload["previous_anchor_digest"] = anchor.get("previous_anchor_digest") or ""
    if schema == ANCHOR_SCHEMA_V3:
        count = anchor.get("provenance_count")
        payload["provenance_count"] = 0 if count is None else count
        payload["provenance_root"] = anchor.get("provenance_root") or merkle_root([])
        payload["first_provenance_hash"] = anchor.get("first_provenance_hash") or ""
        payload["last_provenance_hash"] = anchor.get("last_provenance_hash") or ""
    return json.dumps(payload, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode(
        "utf-8"
    )


#: The gzip magic number. AG7-CONTRACTS section 4: a ``.json.gz`` anchor or
#: head object is told apart by content, never by file name.
GZIP_MAGIC = b"\x1f\x8b"
#: The most a gzipped anchor record may inflate to, against a gzip bomb.
MAX_ANCHOR_RECORD_BYTES = 64 * 1024 * 1024


def load_anchor_record_bytes(data: bytes) -> dict[str, Any]:
    """An anchor record from the bytes of a file: JSON, or gzipped JSON.

    AG7-CONTRACTS section 4: a ``--anchor-head`` file is a header-only or full
    record as ``.json``, or a gzipped record exactly as Behavry's WORM bucket
    stores ``anchor/<period>.json.gz`` and ``head/<period>.json.gz``. The form
    is detected by the gzip magic number. Raises :class:`ValueError` with a
    reason when the bytes are neither, or do not hold a JSON object.
    """
    if data[:2] == GZIP_MAGIC:
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(data)) as stream:
                inflated = stream.read(MAX_ANCHOR_RECORD_BYTES + 1)
        except (OSError, EOFError, zlib.error) as exc:
            raise ValueError(f"not a valid gzip file: {exc}") from exc
        if len(inflated) > MAX_ANCHOR_RECORD_BYTES:
            raise ValueError(
                f"gzipped record inflates past {MAX_ANCHOR_RECORD_BYTES} bytes"
            )
        data = inflated
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"not valid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError("an anchor record must be a JSON object")
    return value


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)


def _openssl_hint(digest_hex: str) -> str:
    return (
        "To check it against your own roots instead: extract the token with "
        "python -c \"import base64,json,sys;open('token.tsr','wb').write("
        "base64.b64decode(json.load(open(sys.argv[1]))['tsa']['token_der_b64']))\" "
        f"<anchor.json>, then openssl ts -verify -token_in -in token.tsr -digest "
        f"{digest_hex} -CAfile your-tsa-roots.pem"
    )


def verify_audit_anchor(
    export: dict[str, Any],
    *,
    anchor: dict[str, Any] | None = None,
    raw_public_key: bytes | None = None,
    trust_source: TrustSource = TrustSource.NONE,
    tsa_roots: list[x509.Certificate] | None = None,
    witness: WitnessOptions | None = None,
) -> VerificationReport:
    """Verify one exported audit anchor offline and return a full report.

    ``witness`` (AG-10) adds the Witness check for a standalone record: run
    when the record carries a ``witness`` receipt or ``witness.require`` is
    set. ``None`` adds nothing; a package's anchors are witnessed by check 16
    instead.

    ``anchor`` is the issuing tenant's Behavry trust anchor (or pass
    ``raw_public_key``). ``tsa_roots`` are the TSA root certificates the
    verifying party trusts; without them the TSA certificate chain is
    reported as not validated, never as passed.
    """
    report = VerificationReport(trust_source=trust_source, kind="audit_anchor")
    history_mark = history_start(anchor)
    if not isinstance(export, dict):
        report.error = "audit anchor export must be a JSON object"
        report.add_fail("anchor_format", "Anchor readable", report.error)
        return report.finalize()

    schema = export.get("schema") or ANCHOR_SCHEMA_V1
    tsa = export.get("tsa") if isinstance(export.get("tsa"), dict) else {}
    report.package_schema = schema
    report.event_count = export.get("event_count")
    report.root_hash = export.get("merkle_root")
    report.created_at = export.get("sealed_at")
    report.signer_kid = export.get("signer_kid")
    report.signature_algorithm = export.get("signing_algorithm")
    report.signing_backend = export.get("signing_backend")
    summary: dict[str, Any] = {
        "anchor_id": export.get("anchor_id"),
        "tenant_id": export.get("tenant_id"),
        "period_start": export.get("period_start"),
        "period_end": export.get("period_end"),
        "anchor_digest": export.get("anchor_digest"),
        "previous_anchor_digest": export.get("previous_anchor_digest"),
        "tsa_status": tsa.get("status"),
        "tsa_url": tsa.get("url"),
    }
    report.anchor_summary = summary

    if schema not in _KNOWN_SCHEMAS:
        report.add_warn(
            "schema",
            "Anchor schema recognized",
            f"{schema!r} is newer than this verifier knows; its canonical form "
            "may differ, so upgrade behavry-verify if the digest check fails",
        )

    events_raw = export.get("events")
    events = (
        [e for e in events_raw if isinstance(e, dict)] if isinstance(events_raw, list) else None
    )
    records_kind = export.get("records")
    provenance_only = records_kind == RECORDS_PROVENANCE
    header_only = records_kind == RECORDS_HEADER
    if records_kind is not None:
        summary["records"] = records_kind
    if header_only:
        # AG6-CONTRACTS section 1: defined for every schema, since the head and
        # a package's predecessor may be v1, v2 or v3. Records it should not
        # carry are not checked: checking them would turn a header into a
        # partial full record whose other half is unverified.
        carried = [k for k in ("events", "provenance") if export.get(k) is not None]
        if carried:
            report.add_warn(
                "anchor_format",
                "Anchor readable",
                f"a header-only record carries {' and '.join(carried)}; they are ignored, "
                "and only the signed bytes are verified",
            )
    elif provenance_only and schema != ANCHOR_SCHEMA_V3:
        report.add_fail(
            "anchor_format",
            "Anchor readable",
            f'records "provenance" is defined for {ANCHOR_SCHEMA_V3} only; a {schema} '
            "anchor commits to no provenance, so this record carries nothing to check "
            "it against",
        )
        provenance_only = False
    elif records_kind is not None and not provenance_only:
        report.add_warn(
            "anchor_format",
            "Anchor readable",
            f"records {records_kind!r} is not a kind this verifier knows; the anchor is "
            "checked as a full record, with its events",
        )

    # -- 1. Merkle root, event count and boundary hashes ----------------------
    #
    # Only hash-bearing events are leaves (the producer filters the same way:
    # a row predating FE2-01 has no hash). event_count covers ALL records, so
    # it is compared with the records, never with the leaf count.
    #
    # A provenance-only record (AG5-CONTRACTS section 1, ``records:
    # "provenance"``) carries no events, so these are SKIPPED, never passed.
    # The event fields still count: they are inside the signed bytes, so the
    # digest and signature below still cover them.
    #
    # A header-only record (AG6-CONTRACTS section 1) carries no records of
    # either kind, so the event and provenance record checks are all SKIPPED
    # with the contract's reason, and the digest, signature and TSA token are
    # what it proves.
    if header_only or provenance_only:
        reason = HEADER_CHECKS_SKIPPED_REASON if header_only else EVENT_CHECKS_SKIPPED_REASON
        for check_id, check_label in (
            ("merkle_root", "Merkle root matches"),
            ("event_count", "Event count verified"),
            ("boundary_hashes", "First and last event hashes match"),
        ):
            report.add_skip(check_id, check_label, reason)
    elif events is None:
        report.add_fail(
            "merkle_root",
            "Merkle root matches",
            "the export has no events array to recompute the root from",
        )
        hashes: list[str] = []
    else:
        hashes = [str(e["event_hash"]) for e in events if e.get("event_hash")]
        recomputed = merkle_root(hashes)
        if recomputed == export.get("merkle_root"):
            report.add_pass(
                "merkle_root",
                "Merkle root matches",
                f"recomputed over {len(hashes)} event hash(es) in {len(events)} record(s)",
            )
        else:
            report.add_fail(
                "merkle_root",
                "Merkle root matches",
                f"recomputed {recomputed}, anchor claims {export.get('merkle_root')}",
            )
        stated = export.get("event_count")
        if stated is None:
            report.add_skip("event_count", "Event count verified", "anchor has no event_count")
        elif stated == len(events):
            report.add_pass("event_count", "Event count verified", f"{len(events)} records")
        else:
            report.add_fail(
                "event_count",
                "Event count verified",
                f"export holds {len(events)} record(s), anchor claims {stated}",
            )
        first = hashes[0] if hashes else None
        last = hashes[-1] if hashes else None
        problems = []
        if (export.get("first_event_hash") or None) != first:
            problems.append("first_event_hash does not match the first hashed event")
        if (export.get("last_event_hash") or None) != last:
            problems.append("last_event_hash does not match the last hashed event")
        if problems:
            report.add_fail(
                "boundary_hashes", "First and last event hashes match", "; ".join(problems)
            )
        else:
            report.add_pass("boundary_hashes", "First and last event hashes match")

    # -- 2. Canonical bytes and the digest the TSA was asked about ------------
    canonical = canonical_anchor_bytes(export)
    digest_hex = hashlib.sha256(canonical).hexdigest()
    stated_digest = export.get("anchor_digest")
    if not stated_digest:
        report.add_fail(
            "anchor_digest", "Anchor digest matches", "the anchor states no anchor_digest"
        )
    elif stated_digest == digest_hex:
        report.add_pass("anchor_digest", "Anchor digest matches", digest_hex)
    else:
        report.add_fail(
            "anchor_digest",
            "Anchor digest matches",
            f"recomputed {digest_hex} from the anchor's fields, anchor states {stated_digest}",
        )

    # -- 3. Behavry's signature over those bytes ------------------------------
    key: bytes | None = raw_public_key
    outside_window = False
    if key is None and anchor is not None:
        try:
            key, _ = select_key_for_timestamp(
                anchor, export.get("signer_kid"), export.get("sealed_at")
            )
        except KeyWindowError as exc:
            # AG-11: sealed outside the key's window, or after its compromise.
            report.error = str(exc)
            outside_window = True
        except AnchorError as exc:
            report.error = str(exc)
    if not export.get("signature"):
        # A signing failure costs the producer the signature, never the anchor,
        # so this is a real state. It is still unproven who sealed it.
        report.add_skip(
            "signature",
            "Anchor signature valid",
            "the anchor carries no Behavry signature, so who sealed it is not proven "
            "(the Merkle root, digest and any TSA token are still checked)",
        )
    elif outside_window:
        report.add_fail("signature", "Anchor signature valid", str(report.error))
    elif key is None:
        report.add_skip(
            "signature",
            "Anchor signature valid",
            report.error or "no trust anchor or public key available",
        )
    elif _verify_ed25519(key, str(export["signature"]), canonical):
        report.add_pass(
            "signature",
            "Anchor signature valid",
            f"Ed25519 over the canonical anchor bytes, key {export.get('signer_kid') or 'unknown'}",
        )
    else:
        report.add_fail(
            "signature",
            "Anchor signature valid",
            "the anchor signature did not verify against the selected key (the anchor "
            "was altered, or the key is not the signer's)",
        )

    # -- 4. Per-event signatures ----------------------------------------------
    #
    # The anchor record omits tenant_id per event (it is a property of the
    # anchor), but the signed tuple includes it, so it is supplied here.
    signed = [e for e in (events or []) if e.get("signature")]
    if header_only:
        report.add_skip(
            "event_signatures", "Event signatures valid", HEADER_CHECKS_SKIPPED_REASON
        )
    elif provenance_only:
        report.add_skip(
            "event_signatures", "Event signatures valid", EVENT_CHECKS_SKIPPED_REASON
        )
    elif not signed:
        report.add_skip(
            "event_signatures", "Event signatures valid", "no anchored event carries a signature"
        )
    elif key is None and anchor is None:
        report.add_skip(
            "event_signatures", "Event signatures valid", "no trust anchor or public key available"
        )
    else:
        failures: list[str] = []
        for index, event in enumerate(signed):
            candidate = dict(event)
            candidate.setdefault("tenant_id", export.get("tenant_id"))
            event_key = raw_public_key
            if anchor is not None:
                try:
                    event_key, _ = select_key_for_timestamp(
                        anchor, event.get("signer_kid"), event.get("timestamp")
                    )
                except AnchorError as exc:
                    failures.append(f"event #{index} ({event.get('id')!r}): {exc}")
                    continue
            if event_key is None or not _verify_ed25519(
                event_key, str(event["signature"]), _event_payload(candidate)
            ):
                failures.append(f"event #{index} ({event.get('id')!r}) signature failed")
        if failures:
            extra = f" (+{len(failures) - 1} more)" if len(failures) > 1 else ""
            report.add_fail("event_signatures", "Event signatures valid", failures[0] + extra)
        else:
            report.add_pass(
                "event_signatures",
                "Event signatures valid",
                f"{len(signed)} of {len(events or [])} records individually signed and verified",
            )

    # -- 4b. Provenance (v3) ---------------------------------------------------
    if schema == ANCHOR_SCHEMA_V3 and header_only:
        summary["provenance_count"] = export.get("provenance_count")
        summary["provenance_root"] = export.get("provenance_root")
        for check_id, check_label in (
            ("provenance_root", "Provenance root matches"),
            ("provenance_count", "Provenance count verified"),
            ("provenance_boundary_hashes", "First and last provenance hashes match"),
            ("provenance_signatures", "Provenance record signatures valid"),
        ):
            report.add_skip(check_id, check_label, HEADER_CHECKS_SKIPPED_REASON)
    elif schema == ANCHOR_SCHEMA_V3:
        _check_provenance(report, export, anchor, raw_public_key)

    # -- 5 to 7. The RFC 3161 token ---------------------------------------------
    _check_token(report, export, tsa, digest_hex, tsa_roots)

    # -- 8. Witness receipt (AG-10) ----------------------------------------------
    if witness is not None:
        check_record_witness(report, export, witness, key)
    attach_history(report, anchor, history_mark)
    return report.finalize()


def anchor_provenance_hashes(export: dict[str, Any]) -> list[str] | None:
    """The ``entry_hash`` leaves of a v3 export's provenance records, in order.

    ``None`` when the export carries no ``provenance`` array. Records without a
    hash are not leaves (the producer filters the same way), though they count
    toward ``provenance_count``.
    """
    raw = export.get("provenance")
    if not isinstance(raw, list):
        return None
    return [str(r["entry_hash"]) for r in raw if isinstance(r, dict) and r.get("entry_hash")]


def _check_provenance(
    report: VerificationReport,
    export: dict[str, Any],
    anchor: dict[str, Any] | None,
    raw_public_key: bytes | None,
) -> None:
    """AG-4 G-1: recompute the provenance commitment from the hash-only records.

    Mirrors ``audit/anchoring.collect_period_provenance``: the root is the same
    Merkle construction as the event root, over every hashed record's
    ``entry_hash`` in ``(timestamp, id)`` order; the count covers all records.
    Each record's own Behavry signature (agent-claim form, claim type
    ``provenance``) is checked too, which the contract does not require but
    costs nothing and binds each record's link and time, not just its hash.
    """
    from behavry_verify.hashbody import canonical_signing_bytes_agent_claim

    summary = report.anchor_summary if report.anchor_summary is not None else {}
    summary["provenance_count"] = export.get("provenance_count")
    summary["provenance_root"] = export.get("provenance_root")

    raw = export.get("provenance")
    hashes = anchor_provenance_hashes(export)
    if hashes is None:
        report.add_fail(
            "provenance_root",
            "Provenance root matches",
            "a v3 anchor export must carry a provenance array to recompute the root from",
        )
        return
    records = [r for r in raw if isinstance(r, dict)]  # type: ignore[union-attr]
    claimed_root = export.get("provenance_root") or merkle_root([])
    recomputed = merkle_root(hashes)
    if recomputed == claimed_root:
        report.add_pass(
            "provenance_root",
            "Provenance root matches",
            f"recomputed over {len(hashes)} provenance entry hash(es)",
        )
    else:
        report.add_fail(
            "provenance_root",
            "Provenance root matches",
            f"recomputed {recomputed}, anchor claims {claimed_root} (a provenance record "
            "was added, removed, reordered or altered)",
        )
    stated = export.get("provenance_count")
    stated = 0 if stated is None else stated
    if stated == len(records):
        report.add_pass(
            "provenance_count", "Provenance count verified", f"{len(records)} records"
        )
    else:
        report.add_fail(
            "provenance_count",
            "Provenance count verified",
            f"export holds {len(records)} provenance record(s), anchor claims {stated}",
        )
    problems = []
    if (export.get("first_provenance_hash") or None) != (hashes[0] if hashes else None):
        problems.append("first_provenance_hash does not match the first record")
    if (export.get("last_provenance_hash") or None) != (hashes[-1] if hashes else None):
        problems.append("last_provenance_hash does not match the last record")
    if problems:
        report.add_fail(
            "provenance_boundary_hashes",
            "First and last provenance hashes match",
            "; ".join(problems),
        )
    else:
        report.add_pass(
            "provenance_boundary_hashes", "First and last provenance hashes match"
        )

    label = "Provenance record signatures valid"
    signed = [r for r in records if r.get("signature_b64")]
    if not signed:
        report.add_skip(
            "provenance_signatures", label, "no anchored provenance record carries a signature"
        )
        return
    if anchor is None and raw_public_key is None:
        report.add_skip(
            "provenance_signatures", label, "no trust anchor or public key available"
        )
        return
    failures: list[str] = []
    for index, record in enumerate(signed):
        key = raw_public_key
        if anchor is not None:
            try:
                key, _ = select_key_for_timestamp(
                    anchor, record.get("signer_kid"), record.get("timestamp")
                )
            except AnchorError as exc:
                failures.append(f"record #{index} ({record.get('id')!r}): {exc}")
                continue
        payload = canonical_signing_bytes_agent_claim(
            claim_type="provenance",
            event_hash=record.get("entry_hash"),
            previous_hash=record.get("previous_hash"),
            timestamp=record.get("timestamp"),
            tenant_id=export.get("tenant_id"),
            agent_id=record.get("agent_id"),
        )
        if key is None or not _verify_ed25519(key, str(record["signature_b64"]), payload):
            failures.append(f"record #{index} ({record.get('id')!r}) signature failed")
    if failures:
        extra = f" (+{len(failures) - 1} more)" if len(failures) > 1 else ""
        report.add_fail("provenance_signatures", label, failures[0] + extra)
    else:
        report.add_pass(
            "provenance_signatures",
            label,
            f"{len(signed)} of {len(records)} provenance records individually signed and "
            "verified",
        )


def _check_token(
    report: VerificationReport,
    export: dict[str, Any],
    tsa: dict[str, Any],
    digest_hex: str,
    tsa_roots: list[x509.Certificate] | None,
) -> None:
    label = "RFC 3161 token covers the anchor digest"
    token_b64 = tsa.get("token_der_b64")
    if not token_b64:
        # No TSA configured is the normal state of an air-gapped deployment,
        # and a TSA outage is recorded rather than hidden. The integrity claims
        # above stand; only the external time claim is absent, and the report
        # says exactly that rather than over-claiming.
        report.add_skip(
            "tsa_imprint",
            label,
            f"NO RFC 3161 token on this anchor (tsa status={tsa.get('status')!r}): the "
            "Merkle root, digest and signature are checked, but no third party attests to when",
        )
        return
    try:
        token = parse_timestamp_token(base64.b64decode(str(token_b64), validate=True))
    except (DERError, binascii.Error, ValueError, IndexError) as exc:
        report.add_fail("tsa_imprint", label, f"the timestamp token is unreadable: {exc}")
        return

    summary = report.anchor_summary or {}
    summary.update(
        {
            "tsa_gen_time": token.gen_time.isoformat(),
            "tsa_serial_number": str(token.serial_number),
            "tsa_policy": token.policy,
        }
    )

    if token.imprint_algorithm != "sha256":
        report.add_fail(
            "tsa_imprint", label, f"token imprint uses {token.imprint_algorithm}, expected sha256"
        )
    elif token.imprint != bytes.fromhex(digest_hex):
        report.add_fail(
            "tsa_imprint",
            label,
            "the token covers a different digest than this anchor, so it does not "
            "attest to these events",
        )
    else:
        stated_time = _parse_time(tsa.get("gen_time"))
        if tsa.get("gen_time") and stated_time != token.gen_time:
            report.add_fail(
                "tsa_imprint",
                label,
                f"the export states gen_time {tsa.get('gen_time')}, but the token says "
                f"{token.gen_time.isoformat()}",
            )
        else:
            report.add_pass(
                "tsa_imprint",
                label,
                f"genTime {token.gen_time.isoformat()}, serial {token.serial_number}, "
                f"policy {token.policy}",
            )

    sig = verify_tsa_signature(token)
    sig_label = "TSA signature valid"
    if sig.status == "valid":
        subject = sig.certificate.subject.rfc4514_string() if sig.certificate else "unknown"
        report.add_pass(
            "tsa_signature",
            sig_label,
            f"{sig.detail} under the certificate embedded in the token ({subject})",
        )
    elif sig.status == "invalid":
        report.add_fail("tsa_signature", sig_label, sig.detail)
    elif sig.status == "absent":
        report.add_warn("tsa_signature", sig_label, sig.detail)
    else:
        report.add_skip("tsa_signature", sig_label, f"not checked: {sig.detail}")

    chain_label = "TSA certificate chain valid"
    if sig.status != "valid" or sig.certificate is None:
        report.add_skip(
            "tsa_chain",
            chain_label,
            "imprint checked, TSA certificate chain not validated: the TSA signature "
            "was not verified, so there is no certificate to chain",
        )
        return
    if not tsa_roots:
        report.add_skip(
            "tsa_chain",
            chain_label,
            "imprint checked, TSA certificate chain not validated: that needs your "
            "trust store, not Behavry's. Supply your TSA roots with --tsa-roots. "
            + _openssl_hint(digest_hex),
        )
        return
    ok, detail = validate_tsa_chain(sig.certificate, token, tsa_roots)
    if ok:
        report.add_pass(
            "tsa_chain",
            chain_label,
            f"{detail}, valid at genTime; revocation (CRL/OCSP) not checked",
        )
    else:
        report.add_fail("tsa_chain", chain_label, detail)


def verify_anchor_chain(exports: list[dict[str, Any]]) -> tuple[bool, list[str]]:
    """Walk a set of anchor exports and report whether a period is missing.

    Port of ``tools/verify_event.py::verify_anchor_chain`` (Sprint AUD-LINK).
    Each v2 (and v3) anchor commits to its predecessor's ``anchor_digest`` inside its own
    signed and timestamped bytes. Two findings mean opposite things:

    * **MISSING PERIOD**: a back-pointer names a digest no supplied anchor has.
      Evidence was removed, or was never handed over.
    * **TAMPERED CHAIN**: a back-pointer names an anchor that IS present, but
      not the one immediately before it in period order, or a later v2 anchor
      carries no back-pointer at all.

    Per-anchor integrity is NOT rechecked here; that is
    :func:`verify_audit_anchor`'s job. v1 anchors carry no back-pointer and are
    reported as unchained, not as breaks.
    """
    if not exports:
        return False, ["no anchor exports supplied"]
    tenants = {a.get("tenant_id") for a in exports}
    if len(tenants) > 1:
        return False, [
            "anchors span more than one tenant "
            f"({sorted(str(t) for t in tenants)}): chains are per-tenant and splicing "
            "two of them would compare records never sealed in sequence"
        ]

    ordered = sorted(exports, key=lambda a: a.get("period_start") or "")
    by_digest = {a.get("anchor_digest"): a for a in ordered if a.get("anchor_digest")}
    lines: list[str] = []
    problems: list[str] = []
    linked = unchained = 0
    seen_chained = False
    for i, item in enumerate(ordered):
        label = f"{item.get('period_start')}..{item.get('period_end')}"
        if (item.get("schema") or ANCHOR_SCHEMA_V1) not in _CHAINED_SCHEMAS:
            unchained += 1
            continue
        stated = item.get("previous_anchor_digest") or None
        if stated is None:
            # Legitimate exactly once: the first v2 anchor in the set.
            if seen_chained:
                problems.append(
                    f"TAMPERED CHAIN at {label}: a v2 anchor later in the set carries no "
                    "back-pointer, so the link to the period before it was removed"
                )
            else:
                lines.append(f"Chain starts at {label} (no predecessor claimed)")
                seen_chained = True
            continue
        predecessor = by_digest.get(stated)
        if predecessor is None:
            problems.append(
                f"MISSING PERIOD before {label}: this anchor commits to predecessor "
                f"digest {stated} and no supplied anchor has it. The record for that "
                "period is not in this set."
            )
            continue
        expected = ordered[i - 1] if i > 0 else None
        if predecessor is not expected:
            problems.append(
                f"TAMPERED CHAIN at {label}: back-pointer names the anchor for "
                f"{predecessor.get('period_start')}, which is not the period immediately "
                "before this one"
            )
            continue
        linked += 1
        seen_chained = True

    lines.append(f"{len(ordered)} anchor(s) supplied, {linked} linked to their predecessor")
    if unchained:
        lines.append(
            f"{unchained} pre-AUD-LINK anchor(s) carry no back-pointer: not a gap; the "
            "chain begins at the v1/v2 boundary and cannot be backfilled"
        )
    if problems:
        return False, lines + problems
    return True, lines + ["Anchor chain VERIFIED: no period is missing from this set"]


def find_head_gaps(heads: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The gaps in a set of held anchor heads (Behavry Sprint AG-9 M-4).

    ``docs/strategy/AG9-CONTRACTS.md`` section 5: every v2 and v3 anchor signs
    ``previous_anchor_digest``, so the heads an auditor holds, in
    ``period_start`` order, must link. Rules:

    * heads are ordered by ``period_start``; identical ``anchor_digest`` values
      count once (the same record held twice, say ``.json`` and ``.json.gz``);
    * heads sharing a ``period_start`` with different digests are a fork (two
      records for one period), which check 15 (H2b) and ``collect-heads``
      already report. They are one position in the order: a later head links
      when it names ANY of them, and that position links when ANY of them
      starts a segment or names a digest of the position before. So a fork is
      never reported a second time as a gap, while a fork whose every side
      fails to link still shows the gap before it;
    * the first position, any v1 head (no back-pointer in its schema) and any
      head whose ``previous_anchor_digest`` is null or empty start a segment
      and are not gaps;
    * otherwise a back-pointer that names a digest other than the preceding
      position's is a gap between those two positions: the feed withheld at
      least one head between them, or the folder is missing one. That holds
      when the digest named is another held head too (the order disagrees with
      the chain), which the row says in ``names_held_anchor_id``.

    A head with no readable ``period_start`` cannot be placed and is left out.
    Signatures are not checked here: pass verified heads where it matters.
    Each gap is a row naming both heads, in period order.
    """
    seen: set[Any] = set()
    placed: list[tuple[datetime, dict[str, Any]]] = []
    for head in heads:
        if not isinstance(head, dict):
            continue
        start = _parse_time(head.get("period_start"))
        if start is None:
            continue
        digest = head.get("anchor_digest")
        if digest:
            if digest in seen:
                continue
            seen.add(digest)
        placed.append((start, head))
    placed.sort(key=lambda item: (item[0], str(item[1].get("anchor_digest") or "")))

    positions: list[list[dict[str, Any]]] = []
    last_start: datetime | None = None
    for start, head in placed:
        if positions and start == last_start:
            positions[-1].append(head)
        else:
            positions.append([head])
        last_start = start
    by_digest = {h.get("anchor_digest"): h for _, h in placed if h.get("anchor_digest")}

    gaps: list[dict[str, Any]] = []
    for index in range(1, len(positions)):
        earlier, later = positions[index - 1], positions[index]
        digests = {h.get("anchor_digest") for h in earlier if h.get("anchor_digest")}
        unlinked: list[dict[str, Any]] = []
        for head in later:
            schema = head.get("schema") or ANCHOR_SCHEMA_V1
            pointer = head.get("previous_anchor_digest") or None
            if schema not in _CHAINED_SCHEMAS or pointer is None or pointer in digests:
                unlinked = []
                break
            unlinked.append(head)
        if not unlinked:
            continue
        before, after = earlier[-1], unlinked[0]
        named = by_digest.get(after.get("previous_anchor_digest"))
        gaps.append(
            {
                "earlier_anchor_id": before.get("anchor_id"),
                "earlier_period_start": before.get("period_start"),
                "earlier_period_end": before.get("period_end"),
                "earlier_anchor_digest": before.get("anchor_digest"),
                "later_anchor_id": after.get("anchor_id"),
                "later_period_start": after.get("period_start"),
                "later_period_end": after.get("period_end"),
                "later_previous_anchor_digest": after.get("previous_anchor_digest"),
                "names_held_anchor_id": named.get("anchor_id") if named else None,
            }
        )
    return gaps


def describe_head_gap(gap: dict[str, Any]) -> str:
    """One line naming both heads of a gap (period and anchor_id)."""
    line = (
        f"gap between head {gap.get('earlier_anchor_id')} "
        f"({gap.get('earlier_period_start')}..{gap.get('earlier_period_end')}) and head "
        f"{gap.get('later_anchor_id')} "
        f"({gap.get('later_period_start')}..{gap.get('later_period_end')}): the later head's "
        f"previous_anchor_digest {gap.get('later_previous_anchor_digest')} "
    )
    if gap.get("names_held_anchor_id") is not None:
        return line + (
            f"names held head {gap['names_held_anchor_id']}, not the head before it in "
            "period order"
        )
    return line + "is not the earlier head's, so at least one head between them is not held"
