"""Public keys and signature checks for Behavry's two signing algorithms (AG-12).

A Behavry key is one of:

* ``ed25519``: the 32 raw public key bytes. Signatures are the 64-byte
  Ed25519 signature over the message.
* ``ecdsa-p256``: ECDSA over NIST P-256 with SHA-256. The public key is the
  SubjectPublicKeyInfo DER. Signatures are ECDSA over SHA-256 of the same
  message bytes an Ed25519 key would sign, DER-encoded
  (``SEQUENCE { r INTEGER, s INTEGER }``).

Wherever a key is written as text it is base64 (standard, padded) of those
bytes, and so is a signature.

The algorithm always comes from the key entry (``algorithm`` in an anchor's
``keys[]``, ``successor_algorithm`` in a key statement), never from the
signature (AG12-CONTRACTS section 2). An entry with no ``algorithm`` is a
pre-AG-12 Ed25519 key. Any other algorithm is refused.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

__all__ = [
    "ALGORITHMS",
    "ECDSA_P256",
    "ED25519",
    "KeyFormatError",
    "PublicKey",
    "algorithm_label",
    "algorithm_of",
    "decode_public_key",
    "key_fingerprint_hex",
    "public_key_from_pem",
    "same_public_key",
    "verify_signature",
    "verify_signature_bytes",
]

ED25519 = "ed25519"
ECDSA_P256 = "ecdsa-p256"
ALGORITHMS = (ED25519, ECDSA_P256)

ED25519_PUBLIC_KEY_BYTES = 32

_LABELS = {ED25519: "Ed25519", ECDSA_P256: "ECDSA P-256"}


class KeyFormatError(ValueError):
    """A key entry names an unknown algorithm, or its bytes are not that kind of key."""


class PublicKey(bytes):
    """A public key's bytes, tagged with the algorithm they are for.

    It is ``bytes`` (raw for Ed25519, SPKI DER for P-256) so code that compares,
    hashes or encodes keys keeps working, and it carries ``algorithm`` so every
    signature check uses the key's own algorithm. Two keys are equal only when
    both the bytes and the algorithm are.
    """

    algorithm: str

    def __new__(cls, data: bytes, algorithm: str = ED25519) -> PublicKey:
        if algorithm not in ALGORITHMS:
            raise KeyFormatError(f"unsupported key algorithm {algorithm!r}")
        obj = super().__new__(cls, data)
        obj.algorithm = algorithm
        return obj

    def __eq__(self, other: object) -> bool:
        if isinstance(other, PublicKey) and other.algorithm != self.algorithm:
            return False
        return bytes.__eq__(self, other)

    def __ne__(self, other: object) -> bool:
        return not self.__eq__(other)

    def __hash__(self) -> int:
        return hash((self.algorithm, bytes(self)))

    def __reduce__(self) -> tuple[Any, ...]:
        return (PublicKey, (bytes(self), self.algorithm))

    def __repr__(self) -> str:
        return f"PublicKey({self.algorithm}, {bytes(self).hex()[:16]}...)"


def algorithm_of(key: bytes) -> str:
    """The algorithm a key is for. Untagged raw bytes are an Ed25519 key.

    Untagged bytes only come from places that have only ever taken Ed25519
    keys (``--public-key``, observer anchors).
    """
    return key.algorithm if isinstance(key, PublicKey) else ED25519


def algorithm_label(algorithm: str | None) -> str:
    return _LABELS.get(algorithm or ED25519, str(algorithm))


def _load_p256(der: bytes) -> ec.EllipticCurvePublicKey:
    try:
        key = serialization.load_der_public_key(der)
    except (ValueError, TypeError) as exc:
        raise KeyFormatError("is not a DER SubjectPublicKeyInfo") from exc
    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise KeyFormatError(f"is a {type(key).__name__}, not an ECDSA key")
    if not isinstance(key.curve, ec.SECP256R1):
        raise KeyFormatError(f"is on curve {key.curve.name}, not P-256")
    return key


def decode_public_key(algorithm: Any, value: Any) -> PublicKey:
    """Decode a base64 ``public_key`` for ``algorithm`` (``None`` is Ed25519).

    Raises :class:`KeyFormatError` with a message that completes the phrase
    "key X ...".
    """
    if algorithm is None:
        algorithm = ED25519
    if algorithm not in ALGORITHMS:
        raise KeyFormatError(
            f"has algorithm {algorithm!r}; only {' and '.join(ALGORITHMS)} are supported"
        )
    if not isinstance(value, str) or not value:
        raise KeyFormatError("has no public_key")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise KeyFormatError("public_key is not valid base64") from exc
    if algorithm == ED25519:
        if len(decoded) != ED25519_PUBLIC_KEY_BYTES:
            raise KeyFormatError(
                f"is {len(decoded)} bytes, expected {ED25519_PUBLIC_KEY_BYTES} for Ed25519"
            )
    else:
        try:
            _load_p256(decoded)
        except KeyFormatError as exc:
            raise KeyFormatError(f"public_key {exc} (ecdsa-p256 needs a P-256 SPKI DER)") from exc
    return PublicKey(decoded, algorithm)


def key_fingerprint_hex(key: bytes) -> str:
    """The 16 hex characters a ``t-...`` kid ends with: SHA-256 of the key bytes."""
    return hashlib.sha256(bytes(key)).hexdigest()[:16]


def _canonical(key: bytes) -> bytes:
    """Raw bytes for Ed25519; re-encoded SPKI DER (uncompressed point) for P-256."""
    if algorithm_of(key) == ED25519:
        return bytes(key)
    return _load_p256(bytes(key)).public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def same_public_key(a: bytes, b: bytes) -> bool:
    """Whether two keys are the same key: same algorithm, same point."""
    if algorithm_of(a) != algorithm_of(b):
        return False
    try:
        return _canonical(a) == _canonical(b)
    except KeyFormatError:
        return False


def public_key_from_pem(pem: bytes) -> PublicKey | None:
    """A PKIX PEM public key as a :class:`PublicKey`, or ``None`` if not one we use."""
    try:
        key = serialization.load_pem_public_key(pem)
    except (ValueError, TypeError):
        return None
    if isinstance(key, Ed25519PublicKey):
        return PublicKey(
            key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw), ED25519
        )
    if isinstance(key, ec.EllipticCurvePublicKey) and isinstance(key.curve, ec.SECP256R1):
        return PublicKey(
            key.public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            ),
            ECDSA_P256,
        )
    return None


def verify_signature_bytes(key: bytes, signature: bytes, message: bytes) -> bool:
    """Check ``signature`` over ``message`` with ``key``'s own algorithm."""
    algorithm = algorithm_of(key)
    try:
        if algorithm == ED25519:
            Ed25519PublicKey.from_public_bytes(bytes(key)).verify(signature, message)
        elif algorithm == ECDSA_P256:
            _load_p256(bytes(key)).verify(signature, message, ec.ECDSA(hashes.SHA256()))
        else:  # pragma: no cover - PublicKey refuses other algorithms
            return False
    except (InvalidSignature, ValueError, TypeError):
        return False
    return True


def verify_signature(key: bytes, signature_b64: str, message: bytes) -> bool:
    """Check a base64 signature over ``message`` with ``key``'s own algorithm."""
    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except (binascii.Error, ValueError, TypeError):
        return False
    return verify_signature_bytes(key, signature, message)
