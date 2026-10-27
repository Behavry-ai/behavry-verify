"""A test fixture transparency log in the byte formats of Rekor v1.5.5.

It is a fixture, never presented as Rekor: it lets the witness checks
(AG10-CONTRACTS section 4) run offline against receipts built exactly as a
Rekor v1 log would build them, written here independently of
:mod:`behavry_verify.witness`:

* the leaf is the canonical ``dsse`` v0.0.1 entry
  (``pkg/types/dsse/v0.0.1/entry.go`` ``Canonicalize``, then JCS):
  ``{"apiVersion":"0.0.1","kind":"dsse","spec":{"envelopeHash":...,
  "payloadHash":...,"signatures":[{"signature":<sig>,"verifier":<b64 PEM>}]}}``;
* the tree is RFC 6962 (leaf ``SHA-256(0x00 || leaf)``, node
  ``SHA-256(0x01 || left || right)``), with proofs from RFC 6962 section 2.1.1;
* the checkpoint is a signed note as ``util.CreateAndSignCheckpoint`` writes
  it: origin ``"<hostname> - <tree id>"``, and one line
  ``"\\u2014 <hostname> <base64(key hint || signature)>"``;
* the SignedEntryTimestamp is the log key's signature over
  ``JCS({"body","integratedTime","logID","logIndex"})`` (``signEntry``), where
  ``logIndex`` is the virtual index across shards and the proof's
  ``log_index`` is the index in this tree, as in Rekor.

Every key here is a test key and protects nothing.
"""
from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

PAYLOAD_TYPE = "application/vnd.behavry.anchor-digest.v1"
TREE_ID = 1193050959916656506
#: Entries logged in earlier shards: the virtual index is this plus the tree index.
SHARD_OFFSET = 1_000_000


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _jcs(value: Any) -> str:
    """JCS for the values used here (ASCII strings, small integers, objects)."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def leaf_hash(leaf: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + leaf).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _split(n: int) -> int:
    """The largest power of two smaller than ``n``."""
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def mth(leaves: list[bytes]) -> bytes:
    """RFC 6962 section 2.1: the Merkle Tree Hash of the leaf inputs."""
    if not leaves:
        return hashlib.sha256(b"").digest()
    if len(leaves) == 1:
        return leaf_hash(leaves[0])
    k = _split(len(leaves))
    return node_hash(mth(leaves[:k]), mth(leaves[k:]))


def path(m: int, leaves: list[bytes]) -> list[bytes]:
    """RFC 6962 section 2.1.1: the audit path for leaf ``m``."""
    n = len(leaves)
    if n <= 1:
        return []
    k = _split(n)
    if m < k:
        return [*path(m, leaves[:k]), mth(leaves[k:])]
    return [*path(m - k, leaves[k:]), mth(leaves[:k])]


def dsse_pae(payload_type: str, payload: bytes) -> bytes:
    t = payload_type.encode("utf-8")
    return b"DSSEv1 " + str(len(t)).encode() + b" " + t + b" " + str(len(payload)).encode() + (
        b" " + payload
    )


def anchor_envelope(digest_hex: str, signer: Ed25519PrivateKey, kid: str) -> str:
    """AG10-CONTRACTS section 1: the DSSE envelope over the anchor digest, as submitted."""
    payload = digest_hex.encode("ascii")
    sig = _b64(signer.sign(dsse_pae(PAYLOAD_TYPE, payload)))
    return json.dumps(
        {
            "payload": _b64(payload),
            "payloadType": PAYLOAD_TYPE,
            "signatures": [{"keyid": kid, "sig": sig}],
        },
        separators=(",", ":"),
        sort_keys=True,
    )


def verifier_pem(public_key: Ed25519PublicKey) -> bytes:
    return public_key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def canonical_dsse_body(envelope_json: str, verifier: bytes) -> bytes:
    """What Rekor's dsse v0.0.1 ``Canonicalize`` writes, after JCS.

    ``payloadHash`` is SHA-256 of the decoded payload, ``envelopeHash`` of the
    envelope bytes as submitted, and the one signature's ``verifier`` is the
    base64 of the canonical PEM key (``x509.PublicKey.CanonicalValue``).
    """
    env = json.loads(envelope_json)
    payload = base64.b64decode(env["payload"])
    entry = {
        "apiVersion": "0.0.1",
        "kind": "dsse",
        "spec": {
            "envelopeHash": {
                "algorithm": "sha256",
                "value": hashlib.sha256(envelope_json.encode("utf-8")).hexdigest(),
            },
            "payloadHash": {"algorithm": "sha256", "value": hashlib.sha256(payload).hexdigest()},
            "signatures": sorted(
                ({"signature": s["sig"], "verifier": _b64(verifier)} for s in env["signatures"]),
                key=lambda s: s["signature"],
            ),
        },
    }
    return _jcs(entry).encode("utf-8")


class FixtureLog:
    """An in-memory RFC 6962 log with a P-256 (default) or Ed25519 key."""

    def __init__(
        self, *, key_type: str = "ecdsa", hostname: str = "fixture-log.test", filler: int = 5
    ) -> None:
        self.key_type = key_type
        self.hostname = hostname
        if key_type == "ecdsa":
            self.private_key: Any = ec.generate_private_key(ec.SECP256R1())
        elif key_type == "ed25519":
            self.private_key = Ed25519PrivateKey.generate()
        else:
            raise ValueError(key_type)
        self.der = self.private_key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.log_id = hashlib.sha256(self.der).hexdigest()
        self.leaves: list[bytes] = [f"filler-{i}".encode() for i in range(filler)]

    # -- keys ---------------------------------------------------------------

    def sign(self, message: bytes) -> bytes:
        if self.key_type == "ecdsa":
            return self.private_key.sign(message, ec.ECDSA(hashes.SHA256()))
        return self.private_key.sign(message)

    def pem(self) -> bytes:
        return self.private_key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def trusted_root(self, *, valid_from: str = "2021-01-12T11:53:27.000Z") -> dict[str, Any]:
        """A Sigstore ``trusted_root.json`` naming this log as its one tlog."""
        return {
            "mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
            "tlogs": [
                {
                    "baseUrl": f"https://{self.hostname}",
                    "hashAlgorithm": "SHA2_256",
                    "publicKey": {
                        "rawBytes": _b64(self.der),
                        "keyDetails": "PKIX_ECDSA_P256_SHA_256"
                        if self.key_type == "ecdsa"
                        else "PKIX_ED25519",
                        "validFor": {"start": valid_from},
                    },
                    "logId": {"keyId": _b64(hashlib.sha256(self.der).digest())},
                }
            ],
            "certificateAuthorities": [],
            "ctlogs": [],
            "timestampAuthorities": [],
        }

    # -- the log ------------------------------------------------------------

    def checkpoint(self, size: int, root: bytes) -> str:
        note = f"{self.hostname} - {TREE_ID}\n{size}\n{_b64(root)}\n"
        hint = hashlib.sha256(self.der).digest()[:4]
        sig = self.sign(note.encode("utf-8"))
        return note + "\n" + f"\u2014 {self.hostname} {_b64(hint + sig)}\n"

    def log_anchor(
        self,
        record: dict[str, Any],
        signer: Ed25519PrivateKey,
        kid: str,
        *,
        integrated_time: int | None = None,
        after: int = 2,
    ) -> dict[str, Any]:
        """Submit ``record``'s digest and return the AG10 section 3 receipt.

        ``integrated_time`` defaults to 60 s after the period ends. ``after``
        filler entries are logged behind it, so the proof is a real path.
        """
        envelope = anchor_envelope(record["anchor_digest"], signer, kid)
        body = canonical_dsse_body(envelope, verifier_pem(signer.public_key()))
        index = len(self.leaves)
        self.leaves.append(body)
        for i in range(after):
            self.leaves.append(f"filler-after-{index}-{i}".encode())
        if integrated_time is None:
            end = datetime.fromisoformat(record["period_end"])
            integrated_time = int(end.timestamp()) + 60
        size = len(self.leaves)
        root = mth(self.leaves)
        body_b64 = _b64(body)
        virtual = SHARD_OFFSET + index
        set_payload = _jcs(
            {
                "body": body_b64,
                "integratedTime": integrated_time,
                "logID": self.log_id,
                "logIndex": virtual,
            }
        ).encode("utf-8")
        return {
            "log": "rekor-v1",
            "log_url": f"https://{self.hostname}",
            "entry_id": f"{TREE_ID:016x}" + leaf_hash(body).hex(),
            "log_id": self.log_id,
            "log_index": virtual,
            "integrated_time": integrated_time,
            "body": body_b64,
            "signed_entry_timestamp": _b64(self.sign(set_payload)),
            "inclusion_proof": {
                "log_index": index,
                "tree_size": size,
                "root_hash": root.hex(),
                "hashes": [h.hex() for h in path(index, self.leaves)],
                "checkpoint": self.checkpoint(size, root),
            },
            "envelope": envelope,
        }
