"""Witness receipts: an anchor logged to a public append-only log (Behavry AG-10).

Every check before this one rests on evidence Behavry or the tenant produced
or kept. A witness receipt adds a party neither controls: a Rekor v1
transparency log that recorded, at sealing time, a DSSE envelope over the
anchor's digest, signed by the anchor's own key. A forgery made after the fact
is either absent from the log or logged after the fact, and the log's signed
``integratedTime`` says which.

The receipt format and the checks follow Behavry's
``docs/strategy/AG10-CONTRACTS.md`` sections 1, 3 and 4. Byte formats are those
of Rekor v1.5.5:

* the leaf is the JCS form of the canonical ``dsse`` v0.0.1 entry
  (``pkg/types/dsse/v0.0.1/entry.go``), hashed as an RFC 6962 leaf;
* the checkpoint is a signed note (``pkg/util/signed_note.go`` and
  ``pkg/util/checkpoint.go``): origin, size and base64 root hash, then a blank
  line and ``"\\u2014 <name> <base64(4-byte key hint || signature)>"`` lines;
* the SignedEntryTimestamp is the log's signature over
  ``JCS({"body","integratedTime","logID","logIndex"})`` (``pkg/api/entries.go``
  ``signEntry`` and ``pkg/verify/verify.go``).

Checks, each reported on its own:

* **W1 Inclusion.** The leaf's RFC 6962 inclusion proof reaches ``root_hash``,
  and a checkpoint line signed by the trusted log key commits to that root
  and tree size.
* **W2 Binding.** The leaf is a ``dsse`` entry for SHA-256 of the anchor's
  digest, its one verifier is the anchor's signer key (Ed25519, or ECDSA P-256
  compared as SPKI DER), and the stored envelope hashes to the leaf's
  ``envelopeHash`` and verifies over its DSSE PAE with that key's algorithm.
* **W3 Prompt.** The SignedEntryTimestamp verifies, and the anchor was logged
  no earlier than five minutes before its period ended and no later than
  ``window`` seconds after.
* **W4 Required.** Applied by the caller: a package 1.7 anchor whose period
  starts at or after the manifest's ``witness_since``, or every record under
  ``--require-witness``, must carry a receipt that passes W1 to W3.

Only :mod:`cryptography` is used, as for the rest of the CLI.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from behavry_verify.jcs import NotCanonicalizableError, canonical_json
from behavry_verify.keys import (
    PublicKey,
    algorithm_label,
    algorithm_of,
    public_key_from_pem,
    same_public_key,
    verify_signature_bytes,
)

__all__ = [
    "DEFAULT_WINDOW_SECONDS",
    "DSSE_PAYLOAD_TYPE",
    "EARLY_TOLERANCE_SECONDS",
    "NO_TRUST_NOTE",
    "LogKey",
    "WitnessOptions",
    "WitnessTrust",
    "WitnessTrustError",
    "check_record_witness",
    "check_witness",
    "dsse_pae",
    "load_witness_trust",
    "parse_signed_note",
    "verify_inclusion_proof",
    "verify_receipt",
]

#: AG10-CONTRACTS section 4, W3: the default promptness window.
DEFAULT_WINDOW_SECONDS = 7200
#: W3's lower bound: logged at most this long before the period ends.
EARLY_TOLERANCE_SECONDS = 300
#: AG10-CONTRACTS section 1.
DSSE_PAYLOAD_TYPE = "application/vnd.behavry.anchor-digest.v1"
#: AG10-CONTRACTS section 3: the one log kind this verifier knows.
LOG_REKOR_V1 = "rekor-v1"
#: AG10-CONTRACTS section 4, verbatim.
NO_TRUST_NOTE = "witness not checked: no log trust root supplied"
#: The first package version whose manifest carries ``witness_since``.
WITNESS_MIN_VERSION = (1, 7)

#: Sigstore ``keyDetails`` values for the two log key types accepted here.
_KEY_DETAILS = {
    "PKIX_ECDSA_P256_SHA_256": "ecdsa-p256-sha256",
    "PKIX_ED25519": "ed25519",
}

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_DECIMAL = re.compile(r"^[0-9]+$")
_EM_DASH = "\u2014"
_MAX_NAMED = 10


class WitnessTrustError(ValueError):
    """Raised when a ``--witness-trust`` file holds no usable log key."""


# ---------------------------------------------------------------------------
# Trust: the log public keys
# ---------------------------------------------------------------------------


@dataclass
class LogKey:
    """One transparency log's public key, as the verifying party trusts it."""

    log_id: str
    """Hex SHA-256 of the key's DER SubjectPublicKeyInfo (Rekor's logID)."""
    algorithm: str
    """``ecdsa-p256-sha256`` or ``ed25519``."""
    public_key: Any
    der: bytes
    base_url: str | None = None
    valid_from: datetime | None = None
    valid_until: datetime | None = None

    @property
    def key_hint(self) -> bytes:
        """The signed note key hint: the first four bytes of SHA-256(DER)."""
        return hashlib.sha256(self.der).digest()[:4]

    def verify(self, signature: bytes, message: bytes) -> bool:
        """ECDSA P-256 with SHA-256 (ASN.1 DER signature), or plain Ed25519."""
        try:
            if self.algorithm == "ed25519":
                self.public_key.verify(signature, message)
            else:
                self.public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        except (InvalidSignature, ValueError, TypeError):
            return False
        return True

    def summary(self) -> dict[str, Any]:
        return {
            "log_id": self.log_id,
            "algorithm": self.algorithm,
            "base_url": self.base_url,
            "valid_from": self.valid_from.isoformat() if self.valid_from else None,
            "valid_until": self.valid_until.isoformat() if self.valid_until else None,
        }


@dataclass
class WitnessTrust:
    """The log keys from one ``--witness-trust`` file, by ``log_id``."""

    keys: dict[str, LogKey]
    source: str
    """``trusted_root`` or ``pem``."""

    def summary(self) -> dict[str, Any]:
        return {"source": self.source, "logs": [k.summary() for k in self.keys.values()]}


@dataclass
class WitnessOptions:
    """What the verifying party asked for: ``--witness-*`` flags."""

    trust: WitnessTrust | None = None
    require: bool = False
    window: int = DEFAULT_WINDOW_SECONDS


def _key_from_der(der: bytes) -> tuple[Any, str]:
    try:
        key = serialization.load_der_public_key(der)
    except (ValueError, TypeError) as exc:
        raise WitnessTrustError(f"not a DER public key: {exc}") from exc
    return key, _algorithm_of(key)


def _algorithm_of(key: Any) -> str:
    if isinstance(key, Ed25519PublicKey):
        return "ed25519"
    if isinstance(key, ec.EllipticCurvePublicKey):
        if not isinstance(key.curve, ec.SECP256R1):
            raise WitnessTrustError(
                f"ECDSA log keys must be P-256, this one is {key.curve.name}"
            )
        return "ecdsa-p256-sha256"
    raise WitnessTrustError(
        f"unsupported log key type {type(key).__name__}: ECDSA P-256 or Ed25519 only"
    )


def _der_of(key: Any) -> bytes:
    return key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def _parse_rfc3339(value: Any, what: str) -> datetime | None:
    if value in (None, ""):
        return None
    if not isinstance(value, str):
        raise WitnessTrustError(f"{what} is not a timestamp string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise WitnessTrustError(f"{what} {value!r} is not RFC 3339") from exc
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)


def _load_trusted_root(doc: dict[str, Any]) -> WitnessTrust:
    tlogs = doc.get("tlogs")
    if not isinstance(tlogs, list) or not tlogs:
        raise WitnessTrustError("trusted_root.json has no tlogs")
    keys: dict[str, LogKey] = {}
    skipped: list[str] = []
    for index, tlog in enumerate(tlogs):
        if not isinstance(tlog, dict):
            raise WitnessTrustError(f"tlogs[{index}] is not an object")
        public = tlog.get("publicKey") if isinstance(tlog.get("publicKey"), dict) else {}
        raw = public.get("rawBytes")
        if not isinstance(raw, str) or not raw:
            raise WitnessTrustError(f"tlogs[{index}].publicKey.rawBytes is missing")
        try:
            der = base64.b64decode(raw, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise WitnessTrustError(f"tlogs[{index}].publicKey.rawBytes is not base64") from exc
        details = public.get("keyDetails")
        if details is not None and details not in _KEY_DETAILS:
            # A log type this verifier cannot check (RSA, other curves). It is
            # left out rather than failing the whole root, which may list
            # several logs.
            skipped.append(f"tlogs[{index}] ({details})")
            continue
        try:
            key, algorithm = _key_from_der(der)
        except WitnessTrustError as exc:
            if details is None:
                skipped.append(f"tlogs[{index}] ({exc})")
                continue
            raise WitnessTrustError(f"tlogs[{index}]: {exc}") from exc
        if details is not None and _KEY_DETAILS[details] != algorithm:
            raise WitnessTrustError(
                f"tlogs[{index}].publicKey.keyDetails is {details}, but the key is {algorithm}"
            )
        log_id = hashlib.sha256(der).hexdigest()
        stated = tlog.get("logId", {}).get("keyId") if isinstance(tlog.get("logId"), dict) else None
        if stated is not None:
            try:
                stated_hex = base64.b64decode(stated, validate=True).hex()
            except (binascii.Error, ValueError, TypeError) as exc:
                raise WitnessTrustError(f"tlogs[{index}].logId.keyId is not base64") from exc
            if stated_hex != log_id:
                raise WitnessTrustError(
                    f"tlogs[{index}].logId.keyId is {stated_hex}, but SHA-256 of its key is "
                    f"{log_id}"
                )
        valid = public.get("validFor") if isinstance(public.get("validFor"), dict) else {}
        keys[log_id] = LogKey(
            log_id=log_id,
            algorithm=algorithm,
            public_key=key,
            der=der,
            base_url=tlog.get("baseUrl") if isinstance(tlog.get("baseUrl"), str) else None,
            valid_from=_parse_rfc3339(valid.get("start"), f"tlogs[{index}] validFor.start"),
            valid_until=_parse_rfc3339(valid.get("end"), f"tlogs[{index}] validFor.end"),
        )
    if not keys:
        raise WitnessTrustError(
            "trusted_root.json holds no ECDSA P-256 or Ed25519 log key"
            + (f" (skipped {', '.join(skipped)})" if skipped else "")
        )
    return WitnessTrust(keys=keys, source="trusted_root")


def load_witness_trust(data: bytes) -> WitnessTrust:
    """Log keys from a Sigstore ``trusted_root.json`` or one PEM public key.

    Raises :class:`WitnessTrustError` with a reason when neither form holds a
    usable ECDSA P-256 or Ed25519 key.
    """
    stripped = data.lstrip()
    if stripped.startswith(b"-----BEGIN"):
        try:
            key = serialization.load_pem_public_key(data)
        except (ValueError, TypeError) as exc:
            raise WitnessTrustError(f"not a PEM public key: {exc}") from exc
        algorithm = _algorithm_of(key)
        der = _der_of(key)
        log_id = hashlib.sha256(der).hexdigest()
        return WitnessTrust(
            keys={log_id: LogKey(log_id=log_id, algorithm=algorithm, public_key=key, der=der)},
            source="pem",
        )
    try:
        doc = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WitnessTrustError(
            f"neither a PEM public key nor a trusted_root.json: {exc}"
        ) from exc
    if not isinstance(doc, dict):
        raise WitnessTrustError("trusted_root.json must be a JSON object")
    return _load_trusted_root(doc)


# ---------------------------------------------------------------------------
# RFC 6962 inclusion proofs
# ---------------------------------------------------------------------------


def _leaf_hash(leaf: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + leaf).digest()


def _node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def verify_inclusion_proof(
    leaf_index: int, tree_size: int, leaf_hash: bytes, proof: list[bytes], root: bytes
) -> bool:
    """RFC 9162 section 2.1.3.2: does ``proof`` take ``leaf_hash`` to ``root``?"""
    if not 0 <= leaf_index < tree_size:
        return False
    fn, sn, r = leaf_index, tree_size - 1, leaf_hash
    for p in proof:
        if len(p) != 32 or sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = _node_hash(p, r)
            while not fn & 1 and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            r = _node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


# ---------------------------------------------------------------------------
# Signed notes (checkpoints)
# ---------------------------------------------------------------------------


@dataclass
class SignedNote:
    text: bytes
    """The signed text: up to and including the newline before the blank line."""
    origin: str
    size: int
    root_hash: bytes
    signatures: list[tuple[str, bytes, bytes]] = field(default_factory=list)
    """``(name, 4-byte key hint, signature)`` per signature line."""


def parse_signed_note(note: str) -> SignedNote:
    """Parse a checkpoint as Rekor's ``SignedCheckpoint.UnmarshalText`` does.

    Raises :class:`ValueError` with a reason when it is malformed.
    """
    data = note.encode("utf-8")
    split = data.rfind(b"\n\n")
    if split < 0:
        raise ValueError("malformed note: no blank line before the signatures")
    text, block = data[: split + 1], data[split + 2 :]
    if not block or not block.endswith(b"\n"):
        raise ValueError("malformed note: the signature block does not end with a newline")
    signatures: list[tuple[str, bytes, bytes]] = []
    for line in block[:-1].split(b"\n"):
        parts = line.decode("utf-8", "replace").split(" ")
        if len(parts) != 3 or parts[0] != _EM_DASH or not parts[1] or not parts[2]:
            raise ValueError(f"malformed signature line {line[:80]!r}")
        try:
            raw = base64.b64decode(parts[2], validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError("a signature line is not base64") from exc
        if len(raw) < 5:
            raise ValueError("a signature line is too short")
        signatures.append((parts[1], raw[:4], raw[4:]))
    if not signatures:
        raise ValueError("no signature lines")
    lines = text.split(b"\n")
    if len(lines) < 4:
        raise ValueError("invalid checkpoint: too few lines")
    origin = lines[0].decode("utf-8", "replace")
    if not origin:
        raise ValueError("invalid checkpoint: empty origin")
    size_text = lines[1].decode("ascii", "replace")
    if not _DECIMAL.match(size_text):
        raise ValueError(f"invalid checkpoint: size {size_text!r} is not a decimal integer")
    try:
        root_hash = base64.b64decode(lines[2], validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("invalid checkpoint: root hash is not base64") from exc
    return SignedNote(
        text=text, origin=origin, size=int(size_text), root_hash=root_hash,
        signatures=signatures,
    )


# ---------------------------------------------------------------------------
# DSSE
# ---------------------------------------------------------------------------


def dsse_pae(payload_type: str, payload: bytes) -> bytes:
    """The DSSE v1 pre-authentication encoding."""
    kind = payload_type.encode("utf-8")
    return b"DSSEv1 %d %s %d %s" % (len(kind), kind, len(payload), payload)


def _b64(value: Any) -> bytes:
    if not isinstance(value, str):
        raise ValueError("not a base64 string")
    return base64.b64decode(value, validate=True)


# ---------------------------------------------------------------------------
# One receipt: W1 to W3
# ---------------------------------------------------------------------------


def _int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _epoch(value: Any) -> float | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    parsed = parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed
    return parsed.timestamp()


def iso_from_epoch(value: Any) -> str | None:
    seconds = _int(value)
    if seconds is None:
        return None
    try:
        return datetime.fromtimestamp(seconds, UTC).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


def verify_receipt(
    record: dict[str, Any],
    receipt: Any,
    *,
    trust: WitnessTrust,
    signer_key: bytes | None,
    window: int = DEFAULT_WINDOW_SECONDS,
) -> dict[str, Any]:
    """Run W1 to W3 on one anchor record's ``witness`` receipt.

    ``signer_key`` is the key that verifies the anchor (the trust anchor's key
    for its ``signer_kid``), Ed25519 or ECDSA P-256 as its entry says. Returns a row: ``status``
    (``verified`` or ``failed``), ``log_index``, ``integrated_time``,
    ``failed_checks`` (the W ids that failed) and ``findings`` (why).
    """
    findings: list[tuple[str, str]] = []

    def fail(check: str, why: str) -> None:
        findings.append((check, why))

    row: dict[str, Any] = {
        "status": "failed",
        "log_index": None,
        "integrated_time": None,
        "integrated_at": None,
        "log_id": None,
        "entry_id": None,
        "failed_checks": [],
        "findings": [],
    }
    if not isinstance(receipt, dict):
        fail("W1", "the witness receipt is not a JSON object")
        return _finish(row, findings)

    log_index = _int(receipt.get("log_index"))
    integrated_time = _int(receipt.get("integrated_time"))
    log_id = receipt.get("log_id") if isinstance(receipt.get("log_id"), str) else None
    row.update(
        log_index=log_index,
        integrated_time=integrated_time,
        integrated_at=iso_from_epoch(integrated_time),
        log_id=log_id,
        entry_id=receipt.get("entry_id"),
    )
    if receipt.get("log") != LOG_REKOR_V1:
        fail("W1", f"log is {receipt.get('log')!r}; this verifier checks {LOG_REKOR_V1!r} only")
        return _finish(row, findings)

    key = trust.keys.get(log_id.lower()) if log_id else None
    if key is None:
        fail(
            "W1",
            f"log_id {log_id!r} is not a log in the supplied trust root "
            f"({', '.join(sorted(trust.keys))})",
        )

    body = receipt.get("body")
    leaf: bytes | None = None
    try:
        leaf = _b64(body)
    except (binascii.Error, ValueError):
        fail("W1", "body is not base64")

    # -- W1 Inclusion -------------------------------------------------------
    leaf_hash = _leaf_hash(leaf) if leaf is not None else None
    entry_id = receipt.get("entry_id")
    if (
        leaf_hash is not None
        and isinstance(entry_id, str)
        and re.fullmatch(r"(?:[0-9a-f]{16})?[0-9a-f]{64}", entry_id)
        and entry_id[-64:] != leaf_hash.hex()
    ):
        # Rekor's entry id is the 16 hex characters of the tree id, then the
        # leaf hash (sharding.CreateEntryIDFromParts).
        fail("W1", "entry_id does not name this leaf (its last 64 hex characters are not the "
             "leaf hash)")
    proof = receipt.get("inclusion_proof")
    proof = proof if isinstance(proof, dict) else {}
    p_index = _int(proof.get("log_index"))
    p_size = _int(proof.get("tree_size"))
    root_hex = proof.get("root_hash")
    root: bytes | None = None
    if isinstance(root_hex, str) and _HEX64.match(root_hex.lower()):
        root = bytes.fromhex(root_hex)
    path: list[bytes] | None = []
    for item in proof.get("hashes") if isinstance(proof.get("hashes"), list) else [None]:
        if not isinstance(item, str) or not _HEX64.match(item.lower()):
            path = None
            break
        path.append(bytes.fromhex(item))
    if p_index is None or p_size is None or root is None or path is None:
        fail(
            "W1",
            "inclusion_proof is incomplete (log_index, tree_size, root_hash and hashes of "
            "64 hex characters are required)",
        )
    elif leaf_hash is not None and not verify_inclusion_proof(
        p_index, p_size, leaf_hash, path, root
    ):
        fail(
            "W1",
            f"the inclusion proof does not take the leaf at index {p_index} of a "
            f"{p_size}-leaf tree to root_hash {root_hex}",
        )

    checkpoint = proof.get("checkpoint")
    note: SignedNote | None = None
    if not isinstance(checkpoint, str):
        fail("W1", "inclusion_proof carries no checkpoint")
    else:
        try:
            note = parse_signed_note(checkpoint)
        except ValueError as exc:
            fail("W1", f"the checkpoint is not a valid signed note: {exc}")
    if note is not None and key is not None:
        hinted = [s for s in note.signatures if s[1] == key.key_hint]
        if not hinted:
            fail(
                "W1",
                "no checkpoint signature line carries the trusted log key's hint "
                f"{key.key_hint.hex()}",
            )
        elif not any(key.verify(sig, note.text) for _, _, sig in hinted):
            fail("W1", "the checkpoint signature does not verify under the trusted log key")
        if p_size is not None and note.size != p_size:
            fail("W1", f"the checkpoint is for tree size {note.size}, the proof for {p_size}")
        if root is not None and note.root_hash != root:
            fail(
                "W1",
                f"the checkpoint commits to root {note.root_hash.hex()}, the proof to "
                f"{root_hex}",
            )

    # -- W2 Binding ---------------------------------------------------------
    _check_binding(record, receipt, leaf, signer_key, fail)

    # -- W3 Prompt ----------------------------------------------------------
    set_b64 = receipt.get("signed_entry_timestamp")
    if integrated_time is None or log_index is None or log_id is None or not isinstance(
        body, str
    ):
        fail("W3", "integrated_time, log_index, log_id and body are required for the "
             "SignedEntryTimestamp")
    elif key is not None:
        try:
            set_sig = _b64(set_b64)
        except (binascii.Error, ValueError):
            set_sig = None
            fail("W3", "signed_entry_timestamp is not base64")
        if set_sig is not None:
            try:
                signed = canonical_json(
                    {
                        "body": body,
                        "integratedTime": integrated_time,
                        "logID": log_id,
                        "logIndex": log_index,
                    }
                ).encode("utf-8")
            except NotCanonicalizableError:
                signed = b""
            if not key.verify(set_sig, signed):
                fail(
                    "W3",
                    "the SignedEntryTimestamp does not verify under the trusted log key over "
                    "body, integratedTime, logID and logIndex",
                )
    if integrated_time is not None:
        end = _epoch(record.get("period_end"))
        if end is None:
            fail("W3", "the anchor's period_end is unreadable, so promptness cannot be checked")
        else:
            earliest = end - EARLY_TOLERANCE_SECONDS
            latest = end + window
            at = iso_from_epoch(integrated_time)
            if integrated_time > latest:
                fail(
                    "W3",
                    f"logged at {at}, {int(integrated_time - end)} s after the period ended "
                    f"({record.get('period_end')}), past the {window} s window: a record "
                    "logged after the fact proves nothing about when it was sealed",
                )
            elif integrated_time < earliest:
                fail(
                    "W3",
                    f"logged at {at}, before its period ended ({record.get('period_end')}) "
                    f"by more than {EARLY_TOLERANCE_SECONDS} s",
                )
        if key is not None:
            when = datetime.fromtimestamp(integrated_time, UTC) if row["integrated_at"] else None
            if when is not None and (
                (key.valid_from is not None and when < key.valid_from)
                or (key.valid_until is not None and when >= key.valid_until)
            ):
                fail(
                    "W3",
                    f"logged at {row['integrated_at']}, outside the trusted log key's validity "
                    f"({key.valid_from}..{key.valid_until})",
                )
    return _finish(row, findings)


def _check_binding(
    record: dict[str, Any],
    receipt: dict[str, Any],
    leaf: bytes | None,
    signer_key: bytes | None,
    fail: Any,
) -> None:
    # Imported here: audit_anchor imports package, which imports authority.
    from behavry_verify.audit_anchor import canonical_anchor_bytes

    digest = record.get("anchor_digest")
    if not isinstance(digest, str) or not _HEX64.match(digest):
        fail("W2", "the anchor states no anchor_digest of 64 lowercase hex characters")
        return
    if hashlib.sha256(canonical_anchor_bytes(record)).hexdigest() != digest:
        fail("W2", "the anchor's anchor_digest is not the digest of its own fields")
    payload_hash = hashlib.sha256(digest.encode("ascii")).hexdigest()
    if signer_key is None:
        fail(
            "W2",
            "the anchor's signer key could not be resolved from the trust anchor, so the "
            "log entry cannot be bound to it",
        )

    sig_in_leaf: str | None = None
    if leaf is not None:
        try:
            entry = json.loads(leaf.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            entry = None
        if not isinstance(entry, dict):
            fail("W2", "the leaf is not a JSON object")
        else:
            try:
                canonical = canonical_json(entry).encode("utf-8") == leaf
            except NotCanonicalizableError:
                canonical = False
            if not canonical:
                fail("W2", "the leaf is not in canonical (JCS) form, as Rekor writes it")
            if entry.get("kind") != "dsse" or entry.get("apiVersion") != "0.0.1":
                fail(
                    "W2",
                    f"the leaf is kind {entry.get('kind')!r} apiVersion "
                    f"{entry.get('apiVersion')!r}, not dsse 0.0.1",
                )
            spec = entry.get("spec") if isinstance(entry.get("spec"), dict) else {}
            if spec.get("payloadHash") != {"algorithm": "sha256", "value": payload_hash}:
                fail(
                    "W2",
                    "the leaf's payloadHash is not SHA-256 of this anchor's digest: the entry "
                    "is for another anchor",
                )
            envelope = receipt.get("envelope")
            env_hash = (
                hashlib.sha256(envelope.encode("utf-8")).hexdigest()
                if isinstance(envelope, str)
                else None
            )
            if spec.get("envelopeHash") != {"algorithm": "sha256", "value": env_hash}:
                fail("W2", "the leaf's envelopeHash is not SHA-256 of the receipt's envelope")
            sigs = spec.get("signatures")
            if not isinstance(sigs, list) or len(sigs) != 1 or not isinstance(sigs[0], dict):
                fail("W2", "the leaf must carry exactly one signature")
            else:
                sig_in_leaf = sigs[0].get("signature")
                verifier = _verifier_key(sigs[0].get("verifier"))
                if verifier is None:
                    fail(
                        "W2",
                        "the leaf's verifier is not a base64 PEM Ed25519 or ECDSA P-256 "
                        "public key",
                    )
                elif signer_key is not None and not same_public_key(verifier, signer_key):
                    fail(
                        "W2",
                        "the leaf's verifier is not the anchor's signer key: the entry was "
                        f"logged by another key (an {algorithm_label(verifier.algorithm)} "
                        f"verifier, the anchor's key is "
                        f"{algorithm_label(algorithm_of(signer_key))})",
                    )

    envelope = receipt.get("envelope")
    try:
        env = json.loads(envelope) if isinstance(envelope, str) else None
    except json.JSONDecodeError:
        env = None
    if not isinstance(env, dict):
        fail("W2", "the receipt carries no DSSE envelope (a JSON string)")
        return
    payload_type = env.get("payloadType")
    if payload_type != DSSE_PAYLOAD_TYPE:
        fail("W2", f"the envelope's payloadType is {payload_type!r}, not {DSSE_PAYLOAD_TYPE}")
    try:
        payload = _b64(env.get("payload"))
    except (binascii.Error, ValueError):
        fail("W2", "the envelope's payload is not base64")
        return
    if payload != digest.encode("ascii"):
        fail("W2", "the envelope's payload is not this anchor's digest")
    signatures = env.get("signatures")
    if (
        not isinstance(signatures, list)
        or len(signatures) != 1
        or not isinstance(signatures[0], dict)
    ):
        fail("W2", "the envelope must carry exactly one signature")
        return
    sig_text = signatures[0].get("sig")
    if leaf is not None and sig_in_leaf is not None and sig_in_leaf != sig_text:
        fail("W2", "the envelope's signature is not the one the log recorded")
    try:
        sig = _b64(sig_text)
    except (binascii.Error, ValueError):
        fail("W2", "the envelope's signature is not base64")
        return
    # The anchor key's own algorithm (AG12-CONTRACTS section 4), never the
    # verifier's or the signature's.
    if (
        signer_key is not None
        and isinstance(payload_type, str)
        and not verify_signature_bytes(signer_key, sig, dsse_pae(payload_type, payload))
    ):
        fail(
            "W2",
            "the envelope's signature does not verify over its DSSE PAE under the "
            "anchor's signer key",
        )


def _verifier_key(value: Any) -> PublicKey | None:
    """The key in a Rekor ``verifier`` (base64 of a PKIX PEM public key).

    Ed25519 (raw bytes) or ECDSA P-256 (SPKI DER); anything else is ``None``.
    """
    try:
        pem = _b64(value)
    except (binascii.Error, ValueError, TypeError):
        return None
    return public_key_from_pem(pem)


def _finish(row: dict[str, Any], findings: list[tuple[str, str]]) -> dict[str, Any]:
    checks: list[str] = []
    for check, _ in findings:
        if check not in checks:
            checks.append(check)
    row["failed_checks"] = sorted(checks)
    row["findings"] = [f"{check}: {why}" for check, why in findings]
    row["status"] = "failed" if findings else "verified"
    return row


# ---------------------------------------------------------------------------
# Applying it: one record, and check 16 over a package
# ---------------------------------------------------------------------------


def signer_key_for(
    record: dict[str, Any], anchor: dict[str, Any] | None, raw_public_key: bytes | None
) -> bytes | None:
    """The key that verifies the anchor, resolved as its signature check does."""
    from behavry_verify.anchor import AnchorError, select_key_for_timestamp

    if raw_public_key is not None:
        return raw_public_key
    if anchor is None:
        return None
    try:
        key, _ = select_key_for_timestamp(anchor, record.get("signer_kid"), record.get("sealed_at"))
    except AnchorError:
        return None
    return key


def carries_witness(record: Any) -> bool:
    return isinstance(record, dict) and record.get("witness") is not None


def witness_row(
    record: dict[str, Any],
    *,
    role: str,
    index: int | None,
    required: bool,
    options: WitnessOptions,
    signer_key: bytes | None,
) -> dict[str, Any]:
    """One record's witness result, as a row of ``report.witness["records"]``.

    ``status`` is ``verified`` or ``failed`` (W1 to W3 ran), ``not_checked``
    (a receipt, but no trust root), ``missing`` (W4: required, none carried)
    or ``absent`` (none carried, none required).
    """
    base = {
        "role": role,
        "index": index,
        "anchor_id": record.get("anchor_id"),
        "period_start": record.get("period_start"),
        "period_end": record.get("period_end"),
        "anchor_digest": record.get("anchor_digest"),
        "required": required,
    }
    if not carries_witness(record):
        return {
            **base,
            "status": "missing" if required else "absent",
            "log_index": None,
            "integrated_time": None,
            "integrated_at": None,
            "log_id": None,
            "entry_id": None,
            "failed_checks": ["W4"] if required else [],
            "findings": (
                ["W4: a witness receipt is required for this record and it carries none"]
                if required
                else []
            ),
        }
    receipt = record.get("witness")
    if options.trust is None:
        rec = receipt if isinstance(receipt, dict) else {}
        return {
            **base,
            "status": "not_checked",
            "log_index": _int(rec.get("log_index")),
            "integrated_time": _int(rec.get("integrated_time")),
            "integrated_at": iso_from_epoch(rec.get("integrated_time")),
            "log_id": rec.get("log_id"),
            "entry_id": rec.get("entry_id"),
            "failed_checks": [],
            "findings": [],
        }
    result = verify_receipt(
        record, receipt, trust=options.trust, signer_key=signer_key, window=options.window
    )
    return {**base, **result}


def _describe(row: dict[str, Any]) -> str:
    role = {"anchor": "anchor", "predecessor": "predecessor", "head": "anchor head"}[row["role"]]
    ident = row.get("anchor_id") or (
        f"#{row['index']}" if row.get("index") is not None else row["role"]
    )
    return f"{role} {ident} ({row.get('period_start')}..{row.get('period_end')})"


def _named(items: list[str]) -> str:
    if len(items) <= _MAX_NAMED:
        return "; ".join(items)
    return "; ".join(items[:_MAX_NAMED]) + f"; and {len(items) - _MAX_NAMED} more"


def _summary(
    rows: list[dict[str, Any]],
    options: WitnessOptions,
    witness_since: Any,
    manifest_states: bool,
) -> dict[str, Any]:
    counts = {k: 0 for k in ("verified", "failed", "not_checked", "missing", "absent")}
    for row in rows:
        counts[row["status"]] += 1
    body: dict[str, Any] = {
        "trust": options.trust.summary() if options.trust is not None else None,
        "trust_note": None if options.trust is not None else NO_TRUST_NOTE,
        "required": options.require,
        "window_seconds": options.window,
        **counts,
        "records": rows,
    }
    if manifest_states:
        body["witness_since"] = witness_since
    return body


def _conclude(
    report: Any,
    rows: list[dict[str, Any]],
    options: WitnessOptions,
    problems: list[str],
    scope: str,
) -> None:
    """Turn rows into the one ``witness`` check (check 16)."""
    check_id, label = "witness", "Witness"
    failures = list(problems)
    for row in rows:
        if row["status"] in ("failed", "missing"):
            failures.append(f"{_describe(row)}: {'; '.join(row['findings'])}")
    not_checked = [r for r in rows if r["status"] == "not_checked"]
    if options.trust is None and options.require:
        failures.append(
            f"{NO_TRUST_NOTE}, and --require-witness needs every receipt checked"
        )
    if failures:
        report.add_fail(check_id, label, _named(failures))
        return
    if not_checked:
        report.add_skip(
            check_id,
            label,
            f"{NO_TRUST_NOTE} ({len(not_checked)} receipt(s) carried; pass --witness-trust "
            "with the log's trusted_root.json or public key)",
        )
        return
    verified = [r for r in rows if r["status"] == "verified"]
    if not verified:
        report.add_skip(
            check_id,
            label,
            f"no witness receipt to check: {scope}",
        )
        return
    times = [
        f"{_describe(r)}: log index {r['log_index']} at {r['integrated_at']}" for r in verified
    ]
    detail = (
        f"{len(verified)} witness receipt(s) verified (inclusion, binding to the anchor's "
        f"digest and signer key, logged within {options.window} s of the period end): "
        f"{_named(times)}"
    )
    report.add_pass(check_id, label, detail)


def check_record_witness(
    report: Any,
    record: dict[str, Any],
    options: WitnessOptions,
    signer_key: bytes | None,
) -> None:
    """The witness check on one standalone anchor record (``--audit-anchor``).

    Added only when the record carries a ``witness`` or ``--require-witness``
    was given, so a record without one reports exactly as before.
    """
    if not (carries_witness(record) or options.require):
        return
    row = witness_row(
        record, role="anchor", index=None, required=options.require, options=options,
        signer_key=signer_key,
    )
    report.witness = _summary([row], options, None, manifest_states=False)
    _conclude(report, [row], options, [], "the record carries none")


def check_witness(
    report: Any,
    components: dict[str, Any],
    manifest: dict[str, Any],
    anchor: dict[str, Any] | None,
    raw_public_key: bytes | None,
    heads: list[dict[str, Any]] | None,
    options: WitnessOptions | None,
) -> None:
    """Check 16: the witness receipts on a package's anchors, predecessor and heads.

    Runs for package 1.7, for any package whose anchor records (or supplied
    heads) carry a ``witness``, and under ``--require-witness``. Otherwise it
    adds nothing, so packages 1.6 and older report exactly as before.
    """
    from behavry_verify.audit_anchor import _parse_time
    from behavry_verify.package import _package_version_tuple

    options = options or WitnessOptions()
    version = _package_version_tuple(manifest)
    raw = components.get("anchors.json")
    exports_raw = raw.get("anchors") if isinstance(raw, dict) else None
    exports = [a if isinstance(a, dict) else {} for a in exports_raw or []] if isinstance(
        exports_raw, list
    ) else []
    predecessor = raw.get("predecessor") if isinstance(raw, dict) else None
    predecessor = predecessor if isinstance(predecessor, dict) else None
    head_records = [h if isinstance(h, dict) else {} for h in heads or []]
    with_manifest = version >= WITNESS_MIN_VERSION
    every = [*exports, *([predecessor] if predecessor else []), *head_records]
    if not (with_manifest or options.require or any(carries_witness(r) for r in every)):
        return

    problems: list[str] = []
    since_raw = manifest.get("witness_since")
    since = None
    if with_manifest:
        if "witness_since" not in manifest:
            problems.append("the signed manifest states no witness_since (package 1.7)")
        elif since_raw is not None:
            since = _parse_time(since_raw)
            if since is None:
                problems.append(
                    f"the signed manifest's witness_since {since_raw!r} is not ISO 8601"
                )

    def required(record: dict[str, Any], packaged: bool) -> bool:
        if options.require:
            return True
        if not packaged or since is None:
            return False
        start = _parse_time(record.get("period_start"))
        # An unreadable start cannot be placed before witness_since, so it is
        # held to the stricter rule.
        return start is None or start >= since

    rows: list[dict[str, Any]] = []
    for index, export in enumerate(exports):
        rows.append(
            witness_row(
                export, role="anchor", index=index, required=required(export, True),
                options=options, signer_key=signer_key_for(export, anchor, raw_public_key),
            )
        )
    if predecessor is not None:
        rows.append(
            witness_row(
                predecessor, role="predecessor", index=None,
                required=required(predecessor, True), options=options,
                signer_key=signer_key_for(predecessor, anchor, raw_public_key),
            )
        )
    for index, head in enumerate(head_records):
        rows.append(
            witness_row(
                head, role="head", index=index, required=required(head, False),
                options=options, signer_key=signer_key_for(head, anchor, raw_public_key),
            )
        )
    report.witness = _summary(rows, options, since_raw, manifest_states=with_manifest)
    if with_manifest and since_raw is None and not options.require:
        scope = "the manifest's witness_since is null (the tenant has not opted in) and no "\
            "record carries one"
    else:
        scope = "no record carries one"
    _conclude(report, rows, options, problems, scope)
