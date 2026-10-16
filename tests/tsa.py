"""A test RFC 3161 time-stamping authority, written with ``cryptography`` alone.

The E-8 vectors (``tests/vectors/anchor_vectors.json``) carry tokens minted by
``generate_anchor_vectors.py`` with ``asn1crypto``, and that TSA's private key
was discarded, so it cannot stamp a new digest. AG-4's v3 anchors and 1.4
packages are built in-test, so they need a TSA that can. This is the same
construction (a root CA issuing a ``timeStamping`` certificate that signs CMS
SignedData over a TSTInfo, with signed attributes), with a minimal DER encoder
in place of ``asn1crypto`` so the test suite adds no dependency.

Every key here is a test key and protects nothing.
"""
from __future__ import annotations

import hashlib
from datetime import UTC, datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
OID_TST_INFO = "1.2.840.113549.1.9.16.1.4"
OID_CONTENT_TYPE = "1.2.840.113549.1.9.3"
OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
OID_SHA256 = "2.16.840.1.101.3.4.2.1"
OID_ECDSA_SHA256 = "1.2.840.10045.4.3.2"
TSA_POLICY = "1.3.6.1.4.1.13762.3"


# -- DER ------------------------------------------------------------------------


def _tlv(tag: int, content: bytes) -> bytes:
    n = len(content)
    if n < 0x80:
        length = bytes([n])
    else:
        raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(raw)]) + raw
    return bytes([tag]) + length + content


def _seq(*parts: bytes) -> bytes:
    return _tlv(0x30, b"".join(parts))


def _set(*parts: bytes) -> bytes:
    return _tlv(0x31, b"".join(sorted(parts)))  # DER: SET OF is sorted


def _int(value: int) -> bytes:
    raw = value.to_bytes(max(1, (value.bit_length() + 8) // 8), "big", signed=True)
    return _tlv(0x02, raw)


def _oid(dotted: str) -> bytes:
    parts = [int(p) for p in dotted.split(".")]
    body = bytearray([40 * parts[0] + parts[1]])
    for value in parts[2:]:
        chunk = [value & 0x7F]
        value >>= 7
        while value:
            chunk.append(0x80 | (value & 0x7F))
            value >>= 7
        body.extend(reversed(chunk))
    return _tlv(0x06, bytes(body))


def _octets(data: bytes) -> bytes:
    return _tlv(0x04, data)


def _gentime(when: datetime) -> bytes:
    return _tlv(0x18, when.astimezone(UTC).strftime("%Y%m%d%H%M%SZ").encode("ascii"))


def _explicit(n: int, content: bytes) -> bytes:
    return _tlv(0xA0 | n, content)


# -- The TSA --------------------------------------------------------------------


def _name(cn: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "behavry-verify AG-4 tests"),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]
    )


class TestTSA:
    """A root CA and an ECDSA time-stamping certificate it issued."""

    __test__ = False  # not a pytest class

    def __init__(self) -> None:
        not_before = datetime(2026, 1, 1, tzinfo=UTC)
        not_after = datetime(2036, 1, 1, tzinfo=UTC)
        root_key = ec.generate_private_key(ec.SECP256R1())
        self.root = (
            x509.CertificateBuilder()
            .subject_name(_name("AG-4 Test TSA Root"))
            .issuer_name(_name("AG-4 Test TSA Root"))
            .public_key(root_key.public_key())
            .serial_number(4001)
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
            .sign(root_key, hashes.SHA256())
        )
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.cert = (
            x509.CertificateBuilder()
            .subject_name(_name("AG-4 Test TSA"))
            .issuer_name(self.root.subject)
            .public_key(self.key.public_key())
            .serial_number(4002)
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), critical=True
            )
            .sign(root_key, hashes.SHA256())
        )
        self._serial = 5000

    @property
    def roots_pem(self) -> bytes:
        return self.root.public_bytes(serialization.Encoding.PEM)

    def stamp(self, digest: bytes, gen_time: datetime) -> tuple[bytes, int]:
        """A DER TimeStampToken over ``digest``; returns (token, serial)."""
        self._serial += 1
        serial = self._serial
        tst = _seq(
            _int(1),
            _oid(TSA_POLICY),
            _seq(_seq(_oid(OID_SHA256), _tlv(0x05, b"")), _octets(digest)),
            _int(serial),
            _gentime(gen_time),
            _int(serial * 7919),
        )
        attrs = [
            _seq(_oid(OID_CONTENT_TYPE), _set(_oid(OID_TST_INFO))),
            _seq(_oid(OID_MESSAGE_DIGEST), _set(_octets(hashlib.sha256(tst).digest()))),
        ]
        signed_set = _set(*attrs)  # what CMS signs: the attributes as a SET OF
        signature = self.key.sign(signed_set, ec.ECDSA(hashes.SHA256()))
        signed_attrs = b"\xa0" + signed_set[1:]  # [0] IMPLICIT in the SignerInfo
        signer_info = _seq(
            _int(1),
            _seq(self.cert.issuer.public_bytes(), _int(self.cert.serial_number)),
            _seq(_oid(OID_SHA256)),
            signed_attrs,
            _seq(_oid(OID_ECDSA_SHA256)),
            _octets(signature),
        )
        cert_der = self.cert.public_bytes(serialization.Encoding.DER)
        signed_data = _seq(
            _int(3),
            _set(_seq(_oid(OID_SHA256))),
            _seq(_oid(OID_TST_INFO), _explicit(0, _octets(tst))),
            _tlv(0xA0, cert_der),
            _set(signer_info),
        )
        return _seq(_oid(OID_SIGNED_DATA), _explicit(0, signed_data)), serial
