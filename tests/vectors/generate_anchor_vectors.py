"""Regenerate ``anchor_vectors.json`` and ``ag3_vectors.json`` from Behavry itself.

NOT a test, and never imported by one: the public verifier must not depend on
the Behavry backend. This script is committed so the provenance of the vectors
is auditable. Run from a Behavry checkout with the backend's dependencies::

    PYTHONPATH=<behavry>/backend python tests/vectors/generate_anchor_vectors.py

What it runs of Behavry's own code:

* ``audit/anchoring.py``: ``canonical_anchor_bytes``, ``anchor_digest``,
  ``anchor_export_payload`` (over a real ``AuditAnchor`` model) and
  ``_anchor_record`` (over event rows), so the export shape cannot drift.
* ``apr/packages.py::merkle_root`` for the root.
* ``audit/signer.py``: the process ``AuditSigner`` (with a seeded key injected)
  signs every anchored event, and ``apr/signing.py::Ed25519Signer`` signs the
  anchor exactly as ``seal_period`` does. ``public_keyset()`` is the trust
  anchor.
* ``audit/rfc3161.py::parse_timestamp_response`` accepts each minted token
  before it is stored, and the stored bytes are the ``token_der`` it returns,
  which is what ``seal_period`` persists.
* ``authority/provenance.py`` and ``audit/digests.py`` for the AG-3 vectors:
  ``provenance_canonical_body``, ``content_digest`` (RFC 8785), ``entry_as_dict``
  and ``compute_event_hash``.

The TSA is synthetic: a test root CA issues a time-stamping certificate (EKU
``timeStamping``, critical, as RFC 3161 requires) and that key signs genuine
CMS SignedData tokens with signed attributes. Nothing a real TSA returns is
missing, but no real authority stands behind it. The root's certificate is
written as ``tsa_root.pem`` so the chain path can be exercised; its private key
is discarded. Every key here is a test key and protects nothing.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import behavry.audit.signer as signer_module
from asn1crypto import algos, cms, core, tsp
from asn1crypto import x509 as asn1_x509
from behavry.apr.packages import merkle_root
from behavry.apr.signing import Ed25519Signer
from behavry.audit.anchoring import (
    ANCHOR_SCHEMA_V1,
    ANCHOR_SCHEMA_V2,
    _anchor_record,
    anchor_digest,
    anchor_export_payload,
    canonical_anchor_bytes,
)
from behavry.audit.digests import canonical_json, content_digest
from behavry.audit.rfc3161 import parse_timestamp_response
from behavry.audit.signer import AuditSigner, SignerKey, canonical_signing_bytes_agent_claim
from behavry.authority.provenance import (
    PROVENANCE_CLAIM,
    entry_as_dict,
    provenance_canonical_body,
)
from behavry.core.models import AuditAnchor
from behavry.core.security import compute_event_hash
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

OUT_DIR = Path(__file__).resolve().parent
TENANT = "11111111-1111-1111-1111-111111111111"
KID = "behavry-ed25519-anchor-vectors"
TSA_POLICY = "1.3.6.1.4.1.13762.3"


# ---------------------------------------------------------------------------
# Behavry's signer, with a seeded key
# ---------------------------------------------------------------------------


def _install_signer() -> AuditSigner:
    private = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"anchor-vectors").digest())
    key = SignerKey(
        kid=KID,
        private_key=private,
        public_key=private.public_key(),
        not_before=datetime(2026, 1, 1, tzinfo=UTC),
    )
    signer = AuditSigner(key)
    signer_module._signer = signer  # noqa: SLF001 - the process signer, seeded
    return signer


# ---------------------------------------------------------------------------
# A synthetic TSA: root CA -> time-stamping certificate
# ---------------------------------------------------------------------------


def _name(cn: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "behavry-verify test vectors"),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]
    )


def _make_tsa() -> dict[str, Any]:
    not_before = datetime(2026, 1, 1, tzinfo=UTC)
    not_after = datetime(2036, 1, 1, tzinfo=UTC)

    root_key = ec.generate_private_key(ec.SECP256R1())
    root = (
        x509.CertificateBuilder()
        .subject_name(_name("Test TSA Root"))
        .issuer_name(_name("Test TSA Root"))
        .public_key(root_key.public_key())
        .serial_number(1001)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True,
                crl_sign=True, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(root_key, hashes.SHA256())
    )

    def leaf(key: Any, cn: str, serial: int) -> x509.Certificate:
        return (
            x509.CertificateBuilder()
            .subject_name(_name(cn))
            .issuer_name(root.subject)
            .public_key(key.public_key())
            .serial_number(serial)
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), critical=True
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
            )
            .sign(root_key, hashes.SHA256())
        )

    ec_key = ec.generate_private_key(ec.SECP256R1())
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return {
        "root": root,
        "ec": (ec_key, leaf(ec_key, "Test TSA (ECDSA)", 2001)),
        "rsa": (rsa_key, leaf(rsa_key, "Test TSA (RSA)", 2002)),
    }


def _mint_response(
    digest: bytes,
    *,
    nonce: int,
    gen_time: datetime,
    serial: int,
    signer: tuple[Any, x509.Certificate] | None,
) -> bytes:
    """A DER ``TimeStampResp`` carrying a token over ``digest``."""
    tst = tsp.TSTInfo(
        {
            "version": "v1",
            "policy": TSA_POLICY,
            "message_imprint": tsp.MessageImprint(
                {"hash_algorithm": {"algorithm": "sha256"}, "hashed_message": digest}
            ),
            "serial_number": serial,
            "gen_time": gen_time,
            "nonce": nonce,
        }
    )
    tst_der = tst.dump()

    signer_infos: list[Any] = []
    certificates: list[Any] = []
    if signer is not None:
        key, cert = signer
        cert_asn1 = asn1_x509.Certificate.load(cert.public_bytes(serialization.Encoding.DER))
        certificates.append(cert_asn1)
        signed_attrs = cms.CMSAttributes(
            [
                cms.CMSAttribute({"type": "content_type", "values": ["tst_info"]}),
                cms.CMSAttribute(
                    {"type": "signing_time", "values": [cms.Time({"utc_time": gen_time})]}
                ),
                cms.CMSAttribute(
                    {"type": "message_digest", "values": [hashlib.sha256(tst_der).digest()]}
                ),
                cms.CMSAttribute(
                    {
                        "type": "signing_certificate_v2",
                        "values": [
                            {
                                "certs": [
                                    {
                                        "hash_algorithm": {"algorithm": "sha256"},
                                        "cert_hash": hashlib.sha256(
                                            cert_asn1.dump()
                                        ).digest(),
                                    }
                                ]
                            }
                        ],
                    }
                ),
            ]
        )
        to_sign = signed_attrs.dump()  # a SET OF, tag 0x31: what CMS signs
        if isinstance(key, rsa.RSAPrivateKey):
            signature = key.sign(to_sign, padding.PKCS1v15(), hashes.SHA256())
            sig_alg = "sha256_rsa"
        else:
            signature = key.sign(to_sign, ec.ECDSA(hashes.SHA256()))
            sig_alg = "sha256_ecdsa"
        signer_infos.append(
            cms.SignerInfo(
                {
                    "version": "v1",
                    "sid": cms.SignerIdentifier(
                        {
                            "issuer_and_serial_number": {
                                "issuer": cert_asn1.issuer,
                                "serial_number": cert_asn1.serial_number,
                            }
                        }
                    ),
                    "digest_algorithm": algos.DigestAlgorithm({"algorithm": "sha256"}),
                    "signed_attrs": signed_attrs,
                    "signature_algorithm": algos.SignedDigestAlgorithm(
                        {"algorithm": sig_alg}
                    ),
                    "signature": signature,
                }
            )
        )

    signed_data: dict[str, Any] = {
        "version": "v3",
        "digest_algorithms": [{"algorithm": "sha256"}],
        "encap_content_info": {
            "content_type": "tst_info",
            "content": core.ParsableOctetString(tst_der),
        },
        "signer_infos": signer_infos,
    }
    if certificates:
        signed_data["certificates"] = certificates
    token = cms.ContentInfo({"content_type": "signed_data", "content": cms.SignedData(signed_data)})
    return tsp.TimeStampResp(
        {"status": {"status": "granted"}, "time_stamp_token": token}
    ).dump()


# ---------------------------------------------------------------------------
# Anchors
# ---------------------------------------------------------------------------


def _events(
    signer: AuditSigner, start: datetime, count: int, seed: str, previous: str | None
) -> tuple[list[dict[str, Any]], list[str], str | None]:
    records: list[dict[str, Any]] = []
    hashes: list[str] = []
    for i in range(count):
        # One event per period has no hash: rows predating FE2-01 exist, and
        # the verifier must count them as records without making them leaves.
        unhashed = count > 2 and i == 1
        # Index 0 lands on a whole second, so isoformat drops nothing: the
        # export always writes microseconds through anchoring._iso.
        when = start + timedelta(minutes=5 * i, microseconds=i * 1234)
        event_hash = None if unhashed else hashlib.sha256(f"{seed}:{i}".encode()).hexdigest()
        signature = None
        kid = None
        if event_hash:
            signature, kid = signer.sign(
                event_hash=event_hash, previous_hash=previous, timestamp=when, tenant_id=TENANT
            )
        row = SimpleNamespace(
            id=str(uuid.UUID(hex=hashlib.sha256(f"{seed}-id-{i}".encode()).hexdigest()[:32])),
            timestamp=when,
            agent_id="agent-anchor-1",
            session_id="sess-anchor-1",
            action="tool_call",
            target="/srv/data/report.csv",
            policy_result="deny" if i == 2 else "allow",
            input_hash=hashlib.sha256(f"input-{seed}-{i}".encode()).hexdigest(),
            device_id=None,
            mcp_server_id="mcp-0001",
            human_session_id=None,
            hash_version=8 if event_hash else None,
            event_hash=event_hash,
            previous_hash=previous if event_hash else None,
            signature=signature,
            signer_kid=kid,
        )
        records.append(_anchor_record(row))
        if event_hash:
            hashes.append(event_hash)
            previous = event_hash
    return records, hashes, previous


def _anchor(
    *,
    name: str,
    signer: AuditSigner,
    tsa: dict[str, Any],
    period_start: datetime,
    event_count: int,
    schema: str,
    previous_anchor_digest: str | None,
    previous_event_hash: str | None,
    tsa_mode: str,
    serial: int,
) -> tuple[dict[str, Any], str | None]:
    period_end = period_start + timedelta(hours=1)
    records, hashes, last_hash = _events(
        signer, period_start, event_count, name, previous_event_hash
    )
    root = merkle_root(hashes)
    canonical = canonical_anchor_bytes(
        tenant_id=TENANT,
        period_start=period_start,
        period_end=period_end,
        event_count=len(records),
        merkle_root_value=root,
        first_event_hash=hashes[0] if hashes else None,
        last_event_hash=hashes[-1] if hashes else None,
        previous_anchor_digest=previous_anchor_digest,
        schema=schema,
    )
    digest = anchor_digest(canonical)
    signature = Ed25519Signer().sign(canonical)  # as seal_period signs

    gen_time = period_end + timedelta(hours=1, seconds=3)
    row = AuditAnchor()
    row.id = str(uuid.UUID(int=int(hashlib.sha256(name.encode()).hexdigest()[:32], 16)))
    row.tenant_id = TENANT
    row.period_start = period_start
    row.period_end = period_end
    row.event_count = len(records)
    row.merkle_root = root
    row.first_event_hash = hashes[0] if hashes else None
    row.last_event_hash = hashes[-1] if hashes else None
    row.anchor_digest = digest.hex()
    row.canonical_schema = schema
    row.previous_anchor_digest = previous_anchor_digest
    row.signature = signature.signature_b64
    row.signer_kid = signature.kid
    row.signing_algorithm = signature.algorithm
    row.signing_backend = signature.backend
    row.sealed_at = gen_time + timedelta(seconds=1)
    row.worm_status = "unconfigured"
    row.tsa_error = None

    if tsa_mode == "none":
        row.tsa_status = "unconfigured"
        row.tsa_url = None
        row.tsa_token = None
        row.tsa_gen_time = None
        row.tsa_policy = None
        row.tsa_serial_number = None
    else:
        nonce = int.from_bytes(hashlib.sha256(f"nonce-{name}".encode()).digest()[:8], "big")
        token_signer = None if tsa_mode == "unsigned" else tsa[tsa_mode]
        response = _mint_response(
            digest, nonce=nonce, gen_time=gen_time, serial=serial, signer=token_signer
        )
        # Behavry's own acceptance path, then the bytes it would persist.
        result = parse_timestamp_response(response, expected_digest=digest, expected_nonce=nonce)
        assert result.granted, result.error
        row.tsa_status = result.status
        row.tsa_url = "https://tsa.example.test/tsr"
        row.tsa_token = result.token_der
        row.tsa_gen_time = result.gen_time
        row.tsa_policy = result.tsa_policy
        row.tsa_serial_number = result.serial_number

    export = anchor_export_payload(row, records)
    return json.loads(json.dumps(export)), last_hash


def build_anchor_vectors() -> dict[str, Any]:
    signer = _install_signer()
    tsa = _make_tsa()
    start = datetime(2026, 9, 7, 12, 0, tzinfo=UTC)

    anchors: dict[str, Any] = {}
    # A chain of three v2 anchors, one per TSA mode that a sealed anchor can
    # carry: an ECDSA TSA, an RSA TSA, and no TSA configured at all.
    previous_digest: str | None = None
    previous_event: str | None = None
    for i, (mode, count) in enumerate((("ec", 4), ("rsa", 3), ("none", 5))):
        name = f"chain_{i}"
        export, previous_event = _anchor(
            name=name, signer=signer, tsa=tsa,
            period_start=start + timedelta(hours=i), event_count=count,
            schema=ANCHOR_SCHEMA_V2, previous_anchor_digest=previous_digest,
            previous_event_hash=previous_event, tsa_mode=mode, serial=100 + i,
        )
        anchors[name] = export
        previous_digest = export["anchor_digest"]

    # A pre-AUD-LINK v1 anchor, and a token with no SignerInfo (the shape
    # Behavry's own offline-verifier tests mint).
    anchors["v1_ec"], _ = _anchor(
        name="v1_ec", signer=signer, tsa=tsa, period_start=start - timedelta(days=30),
        event_count=2, schema=ANCHOR_SCHEMA_V1, previous_anchor_digest=None,
        previous_event_hash=None, tsa_mode="ec", serial=7,
    )
    anchors["unsigned_token"], _ = _anchor(
        name="unsigned_token", signer=signer, tsa=tsa,
        period_start=start - timedelta(days=10), event_count=1, schema=ANCHOR_SCHEMA_V2,
        previous_anchor_digest=None, previous_event_hash=None, tsa_mode="unsigned", serial=9,
    )

    trust_anchor = {"schema": "behavry.trust_anchor.v1", "keys": signer.public_keyset()}
    (OUT_DIR / "tsa_root.pem").write_bytes(
        tsa["root"].public_bytes(serialization.Encoding.PEM)
    )
    return {
        "_comment": (
            "Written by tests/vectors/generate_anchor_vectors.py from Behavry's own "
            "anchoring, signer and rfc3161 code. Test keys only."
        ),
        "trust_anchor": trust_anchor,
        "anchors": anchors,
    }


# ---------------------------------------------------------------------------
# AG-3: RFC 8785 and provenance entries
# ---------------------------------------------------------------------------

JCS_INPUTS: list[Any] = [
    {},
    [],
    None,
    {"b": 1, "a": [True, False, None], "c": "x"},
    {"num": [0, -0.0, 1, -1, 1.5, 1e21, 1e-7, 123456789012345680000, 0.1, 2**53 + 1]},
    {"s": "quote\" backslash\\ \b\f\n\r\t \u0001 <>&   é 😀"},
    {"€": 1, "\U0001f600": 2, "a": 3, "ﬁ": 4, "Z": 5},
    {"nested": {"z": {"y": [{"b": 2, "a": 1}]}}, "unicode_key_é": "v"},
]


def build_ag3_vectors() -> dict[str, Any]:
    signer = _install_signer()
    jcs = []
    for value in JCS_INPUTS:
        jcs.append(
            {"input": value, "canonical": canonical_json(value), "digest": content_digest(value)}
        )
    # Values with no RFC 8785 form: the port must refuse them the same way.
    jcs_errors = ["nan", "inf"]

    agent_id = "agent-prov-1"
    entries = []
    previous: str | None = None
    base = datetime(2026, 10, 15, 12, 0, tzinfo=UTC)
    asmt_ref = {
        "type": "assessment",
        "bundle_digest": "sha256:" + "a" * 64,
        "assessment_id": "asmt-1",
    }
    specs = [
        ("registered", "admin@example.com", "Agent registered",
         {"name": "CI-Research-Agent"}, None),
        ("authority_mapped", "system", "Authority mapped: 3 capabilities",
         {"capabilities": ["fs:read", "secrets:read"], "ratio": 0.5}, None),
        ("assessment", "minotaur-lab-01", "Assessment asmt-1 ingested",
         {"assessment_id": "asmt-1"}, [asmt_ref]),
        ("authority_verified", "system", "secrets:read VERIFIED",
         {"capability_id": "secrets:read", "état": "vérifié"},
         [{"kind": "audit_event", "id": "evt-1"}]),
    ]
    for i, (entry_type, actor, summary, body, refs) in enumerate(specs):
        # Index 0 has a zero microsecond field, so isoformat() omits it: the
        # verifier must hash the exported string, not re-render it.
        when = base + timedelta(minutes=i, microseconds=i * 7)
        digest = content_digest(body)
        canonical = provenance_canonical_body(
            timestamp_iso=when.isoformat(), tenant_id=TENANT, agent_id=agent_id,
            entry_type=entry_type, actor=actor, summary=summary, body_digest=digest,
            evidence_refs=refs,
        )
        entry_hash = compute_event_hash(canonical, previous)
        sig, kid = signer.sign_agent_claim(
            claim_type=PROVENANCE_CLAIM, event_hash=entry_hash, previous_hash=previous,
            timestamp=when, tenant_id=TENANT, agent_id=agent_id,
        )
        row = SimpleNamespace(
            id=f"prov-{i}", agent_id=agent_id, tenant_id=TENANT, timestamp=when,
            entry_type=entry_type, actor=actor, summary=summary, body=body,
            body_digest=digest, evidence_refs=refs, previous_hash=previous,
            entry_hash=entry_hash, signature=sig, signer_kid=kid,
        )
        exported = entry_as_dict(row)
        entries.append(
            {
                "entry": json.loads(json.dumps(exported)),
                "canonical_body": canonical,
                "signing_payload": canonical_signing_bytes_agent_claim(
                    claim_type=PROVENANCE_CLAIM, event_hash=entry_hash,
                    previous_hash=previous, timestamp=when, tenant_id=TENANT,
                    agent_id=agent_id,
                ).decode("utf-8"),
            }
        )
        previous = entry_hash

    return {
        "_comment": (
            "Written by tests/vectors/generate_anchor_vectors.py from Behavry's own "
            "args_digest, digests, provenance and signer code. Test keys only."
        ),
        "jcs": jcs,
        "jcs_errors": jcs_errors,
        "trust_anchor": {"schema": "behavry.trust_anchor.v1", "keys": signer.public_keyset()},
        "provenance": entries,
    }


def main() -> None:
    (OUT_DIR / "anchor_vectors.json").write_text(
        json.dumps(build_anchor_vectors(), indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (OUT_DIR / "ag3_vectors.json").write_text(
        json.dumps(build_ag3_vectors(), indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
