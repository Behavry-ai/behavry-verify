"""RFC 3161 TimeStampToken reading and checking, with no ASN.1 dependency.

The reference verifier in the Behavry repo (``tools/verify_event.py --anchor``)
reads tokens with ``asn1crypto``. This repo keeps ``cryptography`` as its only
runtime dependency, because an auditor has to install and trust whatever it
pulls in, and ``cryptography`` has no parser for RFC 3161 or CMS SignedData. So
this module carries a small DER walker that reads exactly the fields needed and
nothing else:

* ``TSTInfo``: the message imprint (algorithm and digest), ``genTime``, the
  serial number, the policy and the nonce. Mirrors ``_tstinfo_from_token``.
* The CMS ``SignerInfo``: the TSA's signature over the signed attributes, the
  ``messageDigest`` and ``contentType`` attributes, and the signing
  certificate the token embeds. The reference verifier does not check the TSA
  signature at all; this one does, because a token whose signature is not
  checked could have been minted by anyone, including the party whose clock
  it is supposed to be independent of.
* An optional certificate chain walk from the TSA's certificate to roots the
  verifying party supplies.

What is deliberately NOT done, and is said so in every report: revocation
(no CRL or OCSP fetch, since this tool makes no network calls) and the ESS
``signingCertificate`` binding. A root bundle is the auditor's choice, never
Behavry's, so without one the chain is reported as not validated.

DER only. A BER indefinite length is refused rather than guessed at.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, padding, rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import ExtendedKeyUsageOID

__all__ = [
    "DERError",
    "TimestampToken",
    "load_pem_certificates",
    "parse_timestamp_token",
    "validate_tsa_chain",
    "verify_tsa_signature",
]

# -- OIDs ---------------------------------------------------------------------

OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
OID_TST_INFO = "1.2.840.113549.1.9.16.1.4"
OID_ATTR_CONTENT_TYPE = "1.2.840.113549.1.9.3"
OID_ATTR_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"

DIGEST_OIDS: dict[str, str] = {
    "1.3.14.3.2.26": "sha1",
    "2.16.840.1.101.3.4.2.4": "sha224",
    "2.16.840.1.101.3.4.2.1": "sha256",
    "2.16.840.1.101.3.4.2.2": "sha384",
    "2.16.840.1.101.3.4.2.3": "sha512",
}

_HASHES: dict[str, type[hashes.HashAlgorithm]] = {
    "sha1": hashes.SHA1,
    "sha224": hashes.SHA224,
    "sha256": hashes.SHA256,
    "sha384": hashes.SHA384,
    "sha512": hashes.SHA512,
}

# signatureAlgorithm OID -> (family, hash or None to use digestAlgorithm)
SIGNATURE_OIDS: dict[str, tuple[str, str | None]] = {
    "1.2.840.113549.1.1.1": ("rsa", None),  # rsaEncryption
    "1.2.840.113549.1.1.5": ("rsa", "sha1"),
    "1.2.840.113549.1.1.14": ("rsa", "sha224"),
    "1.2.840.113549.1.1.11": ("rsa", "sha256"),
    "1.2.840.113549.1.1.12": ("rsa", "sha384"),
    "1.2.840.113549.1.1.13": ("rsa", "sha512"),
    "1.2.840.10045.2.1": ("ecdsa", None),  # id-ecPublicKey
    "1.2.840.10045.4.1": ("ecdsa", "sha1"),
    "1.2.840.10045.4.3.1": ("ecdsa", "sha224"),
    "1.2.840.10045.4.3.2": ("ecdsa", "sha256"),
    "1.2.840.10045.4.3.3": ("ecdsa", "sha384"),
    "1.2.840.10045.4.3.4": ("ecdsa", "sha512"),
    "1.3.101.112": ("ed25519", None),
    "1.3.101.113": ("ed448", None),
    "1.2.840.113549.1.1.10": ("rsa-pss", None),
}


class DERError(ValueError):
    """The bytes are not the DER structure expected at this point."""


# -- DER walker ---------------------------------------------------------------


@dataclass(frozen=True)
class TLV:
    """One DER element: its tag byte, and where its header and content sit."""

    tag: int
    start: int  # first byte of the header
    content_start: int
    end: int  # one past the last content byte
    data: bytes = field(repr=False)

    @property
    def content(self) -> bytes:
        return self.data[self.content_start : self.end]

    @property
    def encoded(self) -> bytes:
        return self.data[self.start : self.end]

    @property
    def constructed(self) -> bool:
        return bool(self.tag & 0x20)

    def children(self) -> list[TLV]:
        if not self.constructed:
            raise DERError(f"element with tag 0x{self.tag:02x} is not constructed")
        out: list[TLV] = []
        offset = self.content_start
        while offset < self.end:
            child = read_tlv(self.data, offset, self.end)
            out.append(child)
            offset = child.end
        return out


def read_tlv(data: bytes, offset: int = 0, limit: int | None = None) -> TLV:
    """Read one element at ``offset``. Refuses high tags and indefinite lengths."""
    limit = len(data) if limit is None else limit
    if offset + 2 > limit:
        raise DERError("truncated element header")
    tag = data[offset]
    if tag & 0x1F == 0x1F:
        raise DERError("high-tag-number form is not used by RFC 3161 tokens")
    first = data[offset + 1]
    pos = offset + 2
    if first < 0x80:
        length = first
    elif first == 0x80:
        raise DERError("indefinite length (BER) is not DER")
    else:
        count = first & 0x7F
        if count > 4 or pos + count > limit:
            raise DERError("unsupported or truncated length")
        length = int.from_bytes(data[pos : pos + count], "big")
        pos += count
    end = pos + length
    if end > limit:
        raise DERError("element runs past its container")
    return TLV(tag=tag, start=offset, content_start=pos, end=end, data=data)


def _expect(tlv: TLV, tag: int, what: str) -> TLV:
    if tlv.tag != tag:
        raise DERError(f"{what}: expected tag 0x{tag:02x}, found 0x{tlv.tag:02x}")
    return tlv


def decode_oid(content: bytes) -> str:
    if not content or content[-1] & 0x80:
        raise DERError("malformed OBJECT IDENTIFIER")
    arcs: list[int] = []
    value = 0
    for byte in content:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            arcs.append(value)
            value = 0
    first = min(arcs[0] // 40, 2)
    return ".".join(str(a) for a in [first, arcs[0] - 40 * first, *arcs[1:]])


def decode_integer(content: bytes) -> int:
    if not content:
        raise DERError("empty INTEGER")
    return int.from_bytes(content, "big", signed=True)


def decode_generalized_time(content: bytes) -> datetime:
    """``YYYYMMDDHHMMSS[.fff]Z``, the only form RFC 3161 permits for genTime."""
    text = content.decode("ascii")
    if not text.endswith("Z"):
        raise DERError(f"genTime {text!r} is not UTC")
    body = text[:-1]
    main, _, fraction = body.partition(".")
    dt = datetime.strptime(main, "%Y%m%d%H%M%S").replace(tzinfo=UTC)
    if fraction:
        dt = dt.replace(microsecond=int((fraction + "000000")[:6]))
    return dt


def decode_utc_or_generalized(tlv: TLV) -> datetime:
    if tlv.tag == 0x18:
        return decode_generalized_time(tlv.content)
    if tlv.tag == 0x17:
        text = tlv.content.decode("ascii")
        dt = datetime.strptime(text, "%y%m%d%H%M%SZ")
        return dt.replace(tzinfo=UTC)
    raise DERError("expected a UTCTime or GeneralizedTime")


# -- Token --------------------------------------------------------------------


@dataclass
class SignerInfo:
    sid_issuer: bytes | None  # DER Name, when the sid is IssuerAndSerialNumber
    sid_serial: int | None
    sid_ski: bytes | None  # when the sid is a SubjectKeyIdentifier
    digest_algorithm: str  # dotted OID
    signed_attrs: TLV | None
    signature_algorithm: str  # dotted OID
    signature: bytes


@dataclass
class TimestampToken:
    """The parts of a TimeStampToken this verifier reads."""

    imprint_algorithm: str  # "sha256", or the dotted OID when unknown
    imprint: bytes
    gen_time: datetime
    serial_number: int
    policy: str
    nonce: int | None
    tst_info_der: bytes
    certificates: list[bytes]
    signer_infos: list[SignerInfo]


def _read_signer_info(tlv: TLV) -> SignerInfo:
    parts = _expect(tlv, 0x30, "SignerInfo").children()
    if len(parts) < 5:
        raise DERError("SignerInfo is too short")
    sid = parts[1]
    issuer = serial = ski = None
    if sid.tag == 0x30:
        name, number = sid.children()[:2]
        issuer = name.encoded
        serial = decode_integer(_expect(number, 0x02, "serial").content)
    elif sid.tag == 0x80:
        ski = sid.content
    else:
        raise DERError("unrecognized SignerIdentifier")
    digest_algorithm = decode_oid(_expect(parts[2], 0x30, "digestAlgorithm").children()[0].content)
    index = 3
    signed_attrs = None
    if parts[index].tag == 0xA0:
        signed_attrs = parts[index]
        index += 1
    sig_alg_seq = _expect(parts[index], 0x30, "signatureAlgorithm")
    signature_algorithm = decode_oid(sig_alg_seq.children()[0].content)
    signature = _expect(parts[index + 1], 0x04, "signature").content
    return SignerInfo(
        sid_issuer=issuer,
        sid_serial=serial,
        sid_ski=ski,
        digest_algorithm=digest_algorithm,
        signed_attrs=signed_attrs,
        signature_algorithm=signature_algorithm,
        signature=signature,
    )


def parse_timestamp_token(token_der: bytes) -> TimestampToken:
    """Parse a DER ``TimeStampToken`` (a CMS ``ContentInfo`` of SignedData)."""
    content_info = read_tlv(token_der)
    if content_info.end != len(token_der):
        raise DERError("trailing bytes after the token")
    ci = _expect(content_info, 0x30, "ContentInfo").children()
    if decode_oid(_expect(ci[0], 0x06, "contentType").content) != OID_SIGNED_DATA:
        raise DERError("token is not CMS SignedData")
    signed_data = _expect(_expect(ci[1], 0xA0, "content").children()[0], 0x30, "SignedData")
    sd = signed_data.children()
    encap = _expect(sd[2], 0x30, "encapContentInfo").children()
    if decode_oid(_expect(encap[0], 0x06, "eContentType").content) != OID_TST_INFO:
        raise DERError("SignedData does not carry a TSTInfo")
    if len(encap) < 2:
        raise DERError("timestamp token carries no eContent")
    octets = _expect(_expect(encap[1], 0xA0, "eContent").children()[0], 0x04, "eContent")
    tst_der = octets.content

    certificates: list[bytes] = []
    signer_infos_tlv: TLV | None = None
    for part in sd[3:]:
        if part.tag == 0xA0:  # certificates [0] IMPLICIT SET OF CertificateChoices
            certificates = [c.encoded for c in part.children() if c.tag == 0x30]
        elif part.tag == 0x31:
            signer_infos_tlv = part
    if signer_infos_tlv is None:
        raise DERError("SignedData has no signerInfos")
    signer_infos = [_read_signer_info(s) for s in signer_infos_tlv.children()]

    tst = _expect(read_tlv(tst_der), 0x30, "TSTInfo").children()
    policy = decode_oid(_expect(tst[1], 0x06, "policy").content)
    imprint_parts = _expect(tst[2], 0x30, "messageImprint").children()
    algorithm_seq = _expect(imprint_parts[0], 0x30, "hashAlgorithm")
    algorithm_oid = decode_oid(algorithm_seq.children()[0].content)
    imprint = _expect(imprint_parts[1], 0x04, "hashedMessage").content
    serial = decode_integer(_expect(tst[3], 0x02, "serialNumber").content)
    gen_time = decode_generalized_time(_expect(tst[4], 0x18, "genTime").content)
    nonce: int | None = None
    for part in tst[5:]:
        if part.tag == 0x02:  # nonce is the only optional INTEGER
            nonce = decode_integer(part.content)
    return TimestampToken(
        imprint_algorithm=DIGEST_OIDS.get(algorithm_oid, algorithm_oid),
        imprint=imprint,
        gen_time=gen_time,
        serial_number=serial,
        policy=policy,
        nonce=nonce,
        tst_info_der=tst_der,
        certificates=certificates,
        signer_infos=signer_infos,
    )


# -- TSA signature ------------------------------------------------------------


@dataclass
class SignatureResult:
    """Outcome of checking the TSA's own signature on a token."""

    status: str  # "valid" | "invalid" | "absent" | "unsupported"
    detail: str
    certificate: x509.Certificate | None = None


def _tbs_issuer_and_serial(cert_der: bytes) -> tuple[bytes, int]:
    tbs = read_tlv(cert_der).children()[0].children()
    index = 1 if tbs[0].tag == 0xA0 else 0  # optional [0] EXPLICIT version
    serial = decode_integer(tbs[index].content)
    issuer = tbs[index + 2].encoded
    return issuer, serial


def _find_signer_certificate(
    info: SignerInfo, certificates: list[bytes]
) -> x509.Certificate | None:
    for der in certificates:
        try:
            cert = x509.load_der_x509_certificate(der)
        except ValueError:
            continue
        if info.sid_issuer is not None:
            issuer, serial = _tbs_issuer_and_serial(der)
            if issuer == info.sid_issuer and serial == info.sid_serial:
                return cert
        elif info.sid_ski is not None:
            try:
                ext = cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
            except x509.ExtensionNotFound:
                continue
            if ext.value.digest == info.sid_ski:
                return cert
    return None


def _attributes(signed_attrs: TLV) -> dict[str, list[TLV]]:
    out: dict[str, list[TLV]] = {}
    for attr in signed_attrs.children():
        oid_tlv, values = _expect(attr, 0x30, "Attribute").children()[:2]
        out[decode_oid(oid_tlv.content)] = values.children()
    return out


def verify_tsa_signature(token: TimestampToken) -> SignatureResult:
    """Check the TSA's signature over the token, with the certificate it embeds.

    Proves the token was signed by the key in that certificate. It does NOT
    prove the certificate belongs to a TSA anyone should trust: that is
    :func:`validate_tsa_chain`'s job, against roots the verifier supplies.
    """
    if not token.signer_infos:
        return SignatureResult(
            "absent",
            "the token carries no SignerInfo, so no TSA signed it: it attests to "
            "nothing beyond the imprint, and anyone could have produced it",
        )
    info = token.signer_infos[0]
    digest_name = DIGEST_OIDS.get(info.digest_algorithm)
    if digest_name is None:
        return SignatureResult("unsupported", f"digest algorithm {info.digest_algorithm}")
    family, sig_hash = SIGNATURE_OIDS.get(info.signature_algorithm, ("unknown", None))
    if family in ("unknown", "rsa-pss"):
        return SignatureResult(
            "unsupported",
            f"signature algorithm {info.signature_algorithm} is not checked by this "
            "verifier; check the token with openssl ts -verify",
        )
    cert = _find_signer_certificate(info, token.certificates)
    if cert is None:
        return SignatureResult(
            "unsupported",
            "the token does not embed the TSA's signing certificate (the request "
            "did not set certReq), so its signature cannot be checked offline",
        )

    hash_name = sig_hash or digest_name
    if info.signed_attrs is None:
        signed_bytes = token.tst_info_der
    else:
        attrs = _attributes(info.signed_attrs)
        digest_values = attrs.get(OID_ATTR_MESSAGE_DIGEST) or []
        content_types = attrs.get(OID_ATTR_CONTENT_TYPE) or []
        if len(digest_values) != 1 or len(content_types) != 1:
            return SignatureResult(
                "invalid", "signed attributes lack a single messageDigest and contentType"
            )
        if decode_oid(content_types[0].content) != OID_TST_INFO:
            return SignatureResult("invalid", "signed contentType is not id-ct-TSTInfo")
        expected = hashlib.new(digest_name, token.tst_info_der).digest()
        if digest_values[0].content != expected:
            return SignatureResult(
                "invalid",
                "messageDigest does not match the TSTInfo: the timestamp content was "
                "altered after the TSA signed it",
            )
        # CMS signs the attributes re-tagged as a SET OF (0x31), not as [0].
        encoded = info.signed_attrs.encoded
        signed_bytes = b"\x31" + encoded[1:]

    key = cert.public_key()
    try:
        if family == "rsa" and isinstance(key, rsa.RSAPublicKey):
            key.verify(info.signature, signed_bytes, padding.PKCS1v15(), _HASHES[hash_name]())
        elif family == "ecdsa" and isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(info.signature, signed_bytes, ec.ECDSA(_HASHES[hash_name]()))
        elif (family == "ed25519" and isinstance(key, ed25519.Ed25519PublicKey)) or (
            family == "ed448" and isinstance(key, ed448.Ed448PublicKey)
        ):
            key.verify(info.signature, signed_bytes)
        else:
            return SignatureResult(
                "invalid",
                f"signature algorithm {family} does not match the certificate's key type",
                cert,
            )
    except InvalidSignature:
        return SignatureResult(
            "invalid", "the TSA signature does not verify under its own certificate", cert
        )
    return SignatureResult("valid", f"{family}/{hash_name}", cert)


# -- Certificate chain --------------------------------------------------------


def load_pem_certificates(data: bytes) -> list[x509.Certificate]:
    """Every certificate in a PEM bundle. Raises ``ValueError`` when there are none."""
    certs = x509.load_pem_x509_certificates(data)
    if not certs:
        raise ValueError("no certificates in the PEM bundle")
    return certs


def _valid_at(cert: x509.Certificate, when: datetime) -> bool:
    return cert.not_valid_before_utc <= when <= cert.not_valid_after_utc


def _is_ca(cert: x509.Certificate) -> bool:
    try:
        return bool(
            cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
        )
    except x509.ExtensionNotFound:
        return False


def validate_tsa_chain(
    signer: x509.Certificate,
    token: TimestampToken,
    roots: list[x509.Certificate],
    *,
    max_depth: int = 8,
) -> tuple[bool, str]:
    """Walk from the TSA's certificate to one of ``roots``.

    Each link: the issuer's name matches, the issuer's signature on the child
    verifies, the issuer is a CA, and every certificate was valid at the
    token's ``genTime``. The TSA certificate must carry the ``timeStamping``
    extended key usage. Intermediates may come from the token or the bundle.
    No revocation is checked, and the caller's report says so.
    """
    when = token.gen_time
    try:
        eku = signer.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound:
        return False, "the TSA certificate has no extendedKeyUsage, so it is not a TSA certificate"
    if ExtendedKeyUsageOID.TIME_STAMPING not in eku:
        return False, "the TSA certificate is not authorized for timeStamping"

    pool: list[x509.Certificate] = list(roots)
    for der in token.certificates:
        try:
            pool.append(x509.load_der_x509_certificate(der))
        except ValueError:
            continue
    root_ders = {r.public_bytes(Encoding.DER) for r in roots}

    current = signer
    for _ in range(max_depth):
        if not _valid_at(current, when):
            return False, (
                f"certificate {current.subject.rfc4514_string()!r} was not valid at "
                f"genTime {when.isoformat()}"
            )
        if current.public_bytes(Encoding.DER) in root_ders:
            return True, f"chains to {current.subject.rfc4514_string()!r}"
        issuer = None
        for candidate in pool:
            if candidate.subject != current.issuer or candidate is current:
                continue
            try:
                current.verify_directly_issued_by(candidate)
            except (ValueError, TypeError, InvalidSignature):
                continue
            issuer = candidate
            break
        if issuer is None:
            return False, (
                f"no issuer for {current.subject.rfc4514_string()!r} among the roots "
                "you supplied and the certificates in the token"
            )
        if not _is_ca(issuer):
            return False, f"issuer {issuer.subject.rfc4514_string()!r} is not a CA"
        current = issuer
    return False, "certificate chain is longer than the depth this verifier walks"
