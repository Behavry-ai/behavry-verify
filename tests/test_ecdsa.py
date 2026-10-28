"""AG-12: ECDSA P-256 keys and signatures (AG12-CONTRACTS sections 1 to 4 and 7).

A P-256 key signs the same message bytes an Ed25519 key would, as a DER
ECDSA-SHA256 signature, and its public key is the SPKI DER. The verifier takes
the algorithm from the key entry and never from the signature.

Package fixtures are the ordinary builders from ``tests.conftest`` with their
signing key swapped for a P-256 one before anything is signed, so every
signature they make (manifest, events, authorization records, provenance,
anchors, heads, witness envelopes) is ECDSA.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from behavry_verify.anchor import AnchorError, select_key_for_timestamp, validate_anchor
from behavry_verify.audit_anchor import verify_audit_anchor
from behavry_verify.cli import EXIT_VERIFIED, main
from behavry_verify.keyhistory import statement_signing_bytes, trust_anchor_with_history
from behavry_verify.keys import (
    ECDSA_P256,
    ED25519,
    KeyFormatError,
    PublicKey,
    decode_public_key,
    same_public_key,
    verify_signature,
)
from behavry_verify.package import verify_package
from behavry_verify.registry import anchor_for_kid, load_registry
from behavry_verify.report import CheckStatus, TrustSource
from behavry_verify.rfc3161 import load_pem_certificates
from behavry_verify.witness import WitnessOptions, load_witness_trust
from tests.conftest import (
    PackageBuilder,
    PredecessorAuthorityPackageBuilder,
    WitnessedAuthorityPackageBuilder,
    header_only,
)
from tests.test_key_history import (
    MIGRATION_AT,
    ROTATION_AT,
    TENANT,
    Key,
    resign_authorization,
    resign_event,
)

# ---------------------------------------------------------------------------
# Keys
# ---------------------------------------------------------------------------


class P256Signer:
    """An ECDSA P-256 private key with Ed25519PrivateKey's ``sign`` shape.

    ``sign`` returns the DER signature over SHA-256 of the message, which is
    what KMS ``Sign(MessageType=DIGEST, ECDSA_SHA_256)`` over SHA-256 of the
    message returns (AG12-CONTRACTS section 2).
    """

    def __init__(self) -> None:
        self.private = ec.generate_private_key(ec.SECP256R1())

    def sign(self, data: bytes) -> bytes:
        return self.private.sign(data, ec.ECDSA(hashes.SHA256()))

    def public_key(self) -> _EcPublic:
        return _EcPublic(self.private.public_key())

    @property
    def der(self) -> bytes:
        return self.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )


class _EcPublic:
    """The P-256 public key; ``public_bytes_raw`` (which the builders read) is the SPKI DER."""

    def __init__(self, key: ec.EllipticCurvePublicKey) -> None:
        self.key = key

    def public_bytes(self, *args: Any) -> bytes:
        return self.key.public_bytes(*args)

    def public_bytes_raw(self) -> bytes:
        return self.public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )


def p256_kid(der: bytes, tenant: str = TENANT) -> str:
    return (
        "t-" + tenant.replace("-", "")[:8] + "-ecdsa-p256-" + hashlib.sha256(der).hexdigest()[:16]
    )


class EcKey(Key):
    """A tenant key from ``test_key_history``, but ECDSA P-256."""

    algorithm = ECDSA_P256

    def __init__(self, kid: str | None = None) -> None:
        self.private = P256Signer()  # type: ignore[assignment]
        self.raw = self.private.der
        self.b64 = base64.b64encode(self.raw).decode("ascii")
        self.kid = kid or p256_kid(self.raw)

    def entry(self, **window: Any) -> dict[str, Any]:
        body = super().entry(**window)
        body["algorithm"] = ECDSA_P256
        return body


def algorithm_of_key(key: Key) -> str:
    return getattr(key, "algorithm", ED25519)


def statement(
    predecessor: Key,
    successor: Key,
    effective_at: str,
    signers: list[Key],
    *,
    reason: str = "scheduled_rotation",
    successor_algorithm: str | None = None,
) -> dict[str, Any]:
    """A succession statement whose successor may be either algorithm."""
    body = {
        "schema": "behavry.key_statement.v1",
        "type": "succession",
        "tenant_id": TENANT,
        "predecessor_kid": predecessor.kid,
        "successor_kid": successor.kid,
        "successor_algorithm": successor_algorithm or algorithm_of_key(successor),
        "successor_public_key": successor.b64,
        "effective_at": effective_at,
        "reason": reason,
        "compromised_since": None,
        "issued_at": effective_at,
    }
    signed = statement_signing_bytes(body)
    body["signatures"] = [{"kid": k.kid, "sig": k.sign(signed)} for k in signers]
    return body


def anchor_v2(deployment: Key, keys: list[Key], statements: list[dict]) -> dict[str, Any]:
    return {
        "schema": "behavry.trust_anchor.v2",
        "tenant_id": TENANT,
        "exported_at": "2026-10-27T00:00:00+00:00",
        "deployment_kid": deployment.kid,
        "keys": [{**k.entry(), "custody": "behavry_kms"} for k in keys],
        "statements": statements,
    }


def anchor_v1(key: Key) -> dict[str, Any]:
    return {
        "schema": "behavry.trust_anchor.v1",
        "keys": [{"kid": key.kid, "algorithm": algorithm_of_key(key), "public_key": key.b64,
                  "not_before": None, "not_after": None}],
    }


class P256Mixin:
    """Swaps a builder's signing key for P-256 before its constructor signs anything.

    The base constructors assign an Ed25519 key to ``private_key`` and derive
    ``public_key_*`` from it; these properties keep the P-256 key instead.
    """

    _p256: P256Signer

    def _setup_p256(self) -> None:
        self._p256 = P256Signer()

    @property
    def private_key(self) -> Any:
        return self._p256

    @private_key.setter
    def private_key(self, value: Any) -> None:
        if isinstance(value, P256Signer):
            self._p256 = value

    @property
    def public_key_bytes(self) -> bytes:
        return self._p256.der

    @public_key_bytes.setter
    def public_key_bytes(self, value: bytes) -> None:
        pass

    @property
    def public_key_b64(self) -> str:
        return base64.b64encode(self._p256.der).decode("ascii")

    @public_key_b64.setter
    def public_key_b64(self, value: str) -> None:
        pass

    @property
    def kid(self) -> str:
        return p256_kid(self._p256.der, "dae96c58")

    @kid.setter
    def kid(self, value: str) -> None:
        pass

    def anchor(self, *, kid: str | None = None) -> dict[str, Any]:
        body = super().anchor(kid=kid)  # type: ignore[misc]
        body["keys"][0]["algorithm"] = ECDSA_P256
        return body


class P256PackageBuilder(P256Mixin, PackageBuilder):
    def __init__(self, **kwargs: Any) -> None:
        self._setup_p256()
        super().__init__(**kwargs)


class P256PredecessorBuilder(P256Mixin, PredecessorAuthorityPackageBuilder):
    def __init__(self, **kwargs: Any) -> None:
        self._setup_p256()
        super().__init__(**kwargs)


class P256WitnessedBuilder(P256Mixin, WitnessedAuthorityPackageBuilder):
    def __init__(self, **kwargs: Any) -> None:
        self._setup_p256()
        super().__init__(**kwargs)


def status_of(report, check_id: str) -> CheckStatus:
    return next(c.status for c in report.checks if c.id == check_id)


def detail_of(report, check_id: str) -> str:
    return next(c.detail for c in report.checks if c.id == check_id)


def _verify_authority(builder, components=None, *, anchor=None, heads=None, witness=None):
    return verify_package(
        components if components is not None else builder.components(),
        anchor=anchor if anchor is not None else builder.anchor(),
        trust_source=TrustSource.SUPPLIED_ANCHOR,
        observer_anchors=[builder.observer_anchor(), builder.minotaur_anchor()],
        tsa_roots=load_pem_certificates(builder.tsa.roots_pem),
        anchor_heads=heads,
        witness=witness,
    )


def _witness_options(builder) -> WitnessOptions:
    trust = load_witness_trust(json.dumps(builder.log.trusted_root()).encode())
    return WitnessOptions(trust=trust, window=7200)


def _with_key(anchor: dict[str, Any], *, algorithm: str, public_key: str) -> dict[str, Any]:
    body = copy.deepcopy(anchor)
    body["keys"][0]["algorithm"] = algorithm
    body["keys"][0]["public_key"] = public_key
    return body


# ---------------------------------------------------------------------------
# The primitives
# ---------------------------------------------------------------------------


def test_p256_signature_verifies_with_the_key_algorithm():
    signer = P256Signer()
    key = decode_public_key(ECDSA_P256, base64.b64encode(signer.der).decode())
    assert key.algorithm == ECDSA_P256 and bytes(key) == signer.der
    sig = base64.b64encode(signer.sign(b"message")).decode()
    assert verify_signature(key, sig, b"message")
    assert not verify_signature(key, sig, b"messagE")


def test_algorithm_comes_from_the_key_not_the_signature():
    ec_signer = P256Signer()
    ed = Ed25519PrivateKey.generate()
    ed_raw = ed.public_key().public_bytes_raw()
    ec_sig = base64.b64encode(ec_signer.sign(b"m")).decode()
    ed_sig = base64.b64encode(ed.sign(b"m")).decode()
    # Each signature fails under the other algorithm's key.
    assert not verify_signature(PublicKey(ed_raw, ED25519), ec_sig, b"m")
    assert not verify_signature(PublicKey(ec_signer.der, ECDSA_P256), ed_sig, b"m")
    # And a key's bytes under the wrong algorithm tag do not verify either.
    assert not verify_signature(PublicKey(ec_signer.der, ED25519), ec_sig, b"m")
    assert not verify_signature(PublicKey(ed_raw, ECDSA_P256), ed_sig, b"m")


def test_unknown_or_malformed_algorithms_are_refused():
    ec_b64 = base64.b64encode(P256Signer().der).decode()
    with pytest.raises(KeyFormatError, match="'rsa'"):
        decode_public_key("rsa", ec_b64)
    with pytest.raises(KeyFormatError):
        PublicKey(b"x" * 32, "rsa")
    # An Ed25519 entry holding SPKI bytes, and a P-256 entry holding raw bytes.
    with pytest.raises(KeyFormatError, match="expected 32"):
        decode_public_key(ED25519, ec_b64)
    raw = base64.b64encode(Ed25519PrivateKey.generate().public_key().public_bytes_raw()).decode()
    with pytest.raises(KeyFormatError, match="SPKI"):
        decode_public_key(ECDSA_P256, raw)
    # A P-384 SPKI is not a P-256 key.
    p384 = ec.generate_private_key(ec.SECP384R1()).public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with pytest.raises(KeyFormatError, match="secp384r1"):
        decode_public_key(ECDSA_P256, base64.b64encode(p384).decode())


def test_same_public_key_compares_spki_points():
    signer = P256Signer()
    der = signer.der
    compressed_point = signer.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint
    )
    compressed = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), compressed_point
    ).public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    assert same_public_key(PublicKey(der, ECDSA_P256), PublicKey(compressed, ECDSA_P256))
    assert not same_public_key(PublicKey(der, ECDSA_P256), PublicKey(P256Signer().der, ECDSA_P256))
    raw = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    assert not same_public_key(PublicKey(raw, ED25519), PublicKey(der, ECDSA_P256))


# ---------------------------------------------------------------------------
# Anchors
# ---------------------------------------------------------------------------


def test_v1_anchor_with_an_ecdsa_key_is_accepted_and_selected():
    builder = P256PackageBuilder()
    anchor = builder.anchor()
    keys = validate_anchor(anchor)
    assert keys[0]["algorithm"] == ECDSA_P256
    key, entry = select_key_for_timestamp(anchor, builder.kid, None)
    assert key.algorithm == ECDSA_P256 and bytes(key) == builder.public_key_bytes


def test_v1_anchor_with_an_rsa_key_is_refused():
    der = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    anchor = {
        "schema": "behavry.trust_anchor.v1",
        "keys": [{"kid": "k1", "algorithm": "rsa", "public_key": base64.b64encode(der).decode()}],
    }
    with pytest.raises(AnchorError, match="algorithm 'rsa'"):
        validate_anchor(anchor)
    with pytest.raises(AnchorError, match="algorithm 'rsa'"):
        trust_anchor_with_history(anchor)


def test_registry_serves_an_ecdsa_anchor(tmp_path):
    builder = P256PackageBuilder(package_version="1.2")
    (tmp_path / "acme.json").write_text(json.dumps(builder.anchor()))
    load_registry.cache_clear()
    try:
        anchor = anchor_for_kid(builder.kid, str(tmp_path))
        assert anchor is not None and anchor["keys"][0]["algorithm"] == ECDSA_P256
        report = verify_package(
            builder.components(), anchor=anchor, trust_source=TrustSource.PUBLISHED_REGISTRY
        )
        assert report.verified, report.to_text()
    finally:
        load_registry.cache_clear()


# ---------------------------------------------------------------------------
# A package signed with P-256
# ---------------------------------------------------------------------------


def test_p256_package_verifies():
    builder = P256PackageBuilder(package_version="1.2")
    report = verify_package(
        builder.components(),
        anchor=builder.anchor(),
        trust_source=TrustSource.SUPPLIED_ANCHOR,
        observer_anchors=[builder.observer_anchor()],
    )
    assert report.verified, report.to_text()
    assert "ECDSA P-256 over the canonical manifest" in detail_of(report, "signature")
    assert status_of(report, "event_signatures") is CheckStatus.PASS
    assert status_of(report, "authorization_records") is CheckStatus.PASS
    assert status_of(report, "key_fingerprint") is CheckStatus.PASS


def test_tampered_p256_package_fails():
    builder = P256PackageBuilder(package_version="1.2")
    components = builder.components()
    components["manifest.json"]["event_count"] += 1
    report = verify_package(components, anchor=builder.anchor())
    assert status_of(report, "signature") is CheckStatus.FAIL

    components = builder.components()
    event = components["timeline.json"][1]
    event["timestamp"] = event["timestamp"].replace("14:32", "14:33")
    report = verify_package(components, anchor=builder.anchor())
    assert status_of(report, "event_signatures") is CheckStatus.FAIL
    assert "event #1" in detail_of(report, "event_signatures")


def test_p256_package_under_an_ed25519_key_fails():
    """The same kid, but the anchor says Ed25519: every signature check fails."""
    builder = P256PackageBuilder(package_version="1.2")
    ed_raw = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    anchor = _with_key(
        builder.anchor(), algorithm=ED25519, public_key=base64.b64encode(ed_raw).decode()
    )
    report = verify_package(builder.components(), anchor=anchor)
    assert not report.verified
    assert status_of(report, "signature") is CheckStatus.FAIL
    assert status_of(report, "event_signatures") is CheckStatus.FAIL
    assert status_of(report, "authorization_records") is CheckStatus.FAIL


def test_ed25519_package_under_a_p256_key_fails():
    builder = PackageBuilder(package_version="1.2")
    anchor = _with_key(
        builder.anchor(),
        algorithm=ECDSA_P256,
        public_key=base64.b64encode(P256Signer().der).decode(),
    )
    report = verify_package(builder.components(), anchor=anchor)
    assert not report.verified
    assert status_of(report, "signature") is CheckStatus.FAIL
    assert status_of(report, "event_signatures") is CheckStatus.FAIL


def test_p256_key_labelled_ed25519_is_refused():
    """The algorithm is the entry's, so P-256 bytes under ``ed25519`` are not a key."""
    builder = P256PackageBuilder(package_version="1.2")
    anchor = _with_key(builder.anchor(), algorithm=ED25519, public_key=builder.public_key_b64)
    report = verify_package(builder.components(), anchor=anchor)
    assert not report.verified
    assert "expected 32 for Ed25519" in (report.error or "")


def test_cli_with_a_p256_anchor(tmp_path, capsys):
    builder = P256PackageBuilder(package_version="1.2")
    package = tmp_path / "pkg"
    package.mkdir()
    for name, body in builder.components().items():
        (package / name).write_text(json.dumps(body, indent=2, sort_keys=True, default=str))
    anchor = tmp_path / "anchor.json"
    anchor.write_text(json.dumps(builder.anchor()))
    assert main(["--package", str(package), "--trust-anchor", str(anchor)]) == EXIT_VERIFIED
    assert "ECDSA P-256 over the canonical manifest" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# Authority packages: provenance, anchors and heads signed with P-256
# ---------------------------------------------------------------------------


def test_p256_authority_package_with_anchors_and_heads_verifies():
    builder = P256PredecessorBuilder()
    head = header_only(builder.anchors[-1])
    report = _verify_authority(builder, heads=[head])
    assert report.verified, report.to_text()
    assert status_of(report, "provenance") is CheckStatus.PASS
    assert status_of(report, "provenance_anchoring") is CheckStatus.PASS
    assert report.provenance_anchoring["heads"][0]["verified"] is True


def test_p256_audit_anchor_record_verifies_and_tampering_fails():
    builder = P256PredecessorBuilder()
    record = copy.deepcopy(builder.anchors[0])
    report = verify_audit_anchor(
        record,
        anchor=builder.anchor(),
        trust_source=TrustSource.SUPPLIED_ANCHOR,
        tsa_roots=load_pem_certificates(builder.tsa.roots_pem),
    )
    assert report.verified, report.to_text()
    assert "ECDSA P-256 over the canonical anchor bytes" in detail_of(report, "signature")

    # A P-256 signature over other bytes (a different, validly signed anchor).
    record["signature"] = builder.anchors[1]["signature"]
    report = verify_audit_anchor(record, anchor=builder.anchor())
    assert status_of(report, "signature") is CheckStatus.FAIL


def test_p256_provenance_entry_tampering_fails():
    builder = P256PredecessorBuilder()
    components = builder.components()
    entry = components["provenance.json"]["entries"][2]
    entry["signature_b64"] = components["provenance.json"]["entries"][3]["signature_b64"]
    report = _verify_authority(builder, components)
    assert status_of(report, "provenance") is CheckStatus.FAIL
    assert "signature failed" in detail_of(report, "provenance")


# ---------------------------------------------------------------------------
# Witness (AG12-CONTRACTS section 4)
# ---------------------------------------------------------------------------


def test_p256_witnessed_package_passes_w1_to_w3():
    builder = P256WitnessedBuilder()
    leaf = json.loads(base64.b64decode(builder.anchors[0]["witness"]["body"]))
    pem = base64.b64decode(leaf["spec"]["signatures"][0]["verifier"])
    assert pem.startswith(b"-----BEGIN PUBLIC KEY-----\n") and pem.endswith(b"\n")
    report = _verify_authority(builder, witness=_witness_options(builder))
    assert report.verified, report.to_text()
    assert status_of(report, "witness") is CheckStatus.PASS
    assert report.witness["verified"] == 5 and report.witness["failed"] == 0


def _w2_row(report) -> dict[str, Any]:
    return next(
        r for r in report.witness["records"] if r["role"] == "anchor" and r["index"] == 1
    )


def test_entry_logged_by_another_p256_key_fails_w2():
    builder = P256WitnessedBuilder()
    record = builder.anchors[1]
    record["witness"] = builder.log.log_anchor(record, P256Signer(), builder.kid)
    report = _verify_authority(builder, witness=_witness_options(builder))
    row = _w2_row(report)
    assert not report.verified and row["failed_checks"] == ["W2"]
    assert any("verifier is not the anchor's signer key" in f for f in row["findings"])
    assert any("does not verify over its DSSE PAE" in f for f in row["findings"])


def test_ed25519_verifier_for_a_p256_anchor_fails_w2():
    builder = P256WitnessedBuilder()
    record = builder.anchors[1]
    record["witness"] = builder.log.log_anchor(record, Ed25519PrivateKey.generate(), builder.kid)
    report = _verify_authority(builder, witness=_witness_options(builder))
    row = _w2_row(report)
    assert row["failed_checks"] == ["W2"]
    assert any("an Ed25519 verifier" in f and "ECDSA P-256" in f for f in row["findings"])


def test_p256_verifier_for_an_ed25519_anchor_fails_w2(witnessed_builder):
    record = witnessed_builder.anchors[1]
    record["witness"] = witnessed_builder.log.log_anchor(
        record, P256Signer(), witnessed_builder.kid
    )
    report = _verify_authority(witnessed_builder, witness=_witness_options(witnessed_builder))
    row = _w2_row(report)
    assert row["failed_checks"] == ["W2"]
    assert any("an ECDSA P-256 verifier" in f for f in row["findings"])


def test_p256_envelope_signature_over_another_payload_fails_w2():
    builder = P256WitnessedBuilder()
    record = builder.anchors[1]
    receipt = record["witness"]
    env = json.loads(receipt["envelope"])
    env["signatures"][0]["sig"] = json.loads(builder.anchors[0]["witness"]["envelope"])[
        "signatures"
    ][0]["sig"]
    receipt["envelope"] = json.dumps(env, separators=(",", ":"), sort_keys=True)
    report = _verify_authority(builder, witness=_witness_options(builder))
    row = _w2_row(report)
    assert "W2" in row["failed_checks"]
    assert any("does not verify over its DSSE PAE" in f for f in row["findings"])


# ---------------------------------------------------------------------------
# Key statements across algorithms
# ---------------------------------------------------------------------------


class MixedHistory:
    """Deployment key D (Ed25519), K1 (P-256, migration), K2 (Ed25519, rotation)."""

    def __init__(self) -> None:
        self.d = Key("ed25519-8bc39d1abca0ff87")
        self.k1 = EcKey()
        self.k2 = Key()
        self.migration = statement(
            self.d, self.k1, MIGRATION_AT, [self.d, self.k1], reason="infrastructure_migration"
        )
        self.rotation = statement(self.k1, self.k2, ROTATION_AT, [self.k1, self.k2])

    def v2(self) -> dict[str, Any]:
        return anchor_v2(self.d, [self.d, self.k1, self.k2], [self.migration, self.rotation])

    def key_at(self, ts: str) -> Key:
        return self.k1 if ts < ROTATION_AT else self.k2


def mixed_package(history: MixedHistory) -> dict[str, Any]:
    """A 1.2 package signed by K1 (P-256) before the rotation and K2 (Ed25519) after."""
    builder = PackageBuilder(package_version="1.2")
    for record in builder.authorization_records:
        resign_authorization(builder, record, history.key_at(record["timestamp"]))
    for event in builder.events:
        resign_event(event, history.key_at(event["timestamp"]))
    builder.private_key = history.k2.private
    builder.kid = history.k2.kid
    builder.public_key_b64 = history.k2.b64
    return builder.components()


def test_cross_algorithm_v2_anchor_resolves():
    history = MixedHistory()
    resolved = trust_anchor_with_history(history.v2())
    algorithms = {k["kid"]: k["algorithm"] for k in resolved["keys"]}
    assert algorithms == {
        history.d.kid: ED25519, history.k1.kid: ECDSA_P256, history.k2.kid: ED25519,
    }
    kh = resolved["_key_history"]
    assert kh.statements_verified == 2


def test_cross_algorithm_package_verifies_with_v2_and_with_pinned_v1():
    history = MixedHistory()
    components = mixed_package(history)
    report = verify_package(
        components,
        anchor=trust_anchor_with_history(history.v2()),
        trust_source=TrustSource.SUPPLIED_ANCHOR,
    )
    assert report.verified, report.to_text()
    assert status_of(report, "event_signatures") is CheckStatus.PASS
    assert status_of(report, "authorization_records") is CheckStatus.PASS
    keys = {k["kid"]: k for k in report.key_history["keys"]}
    assert keys[history.k1.kid]["algorithm"] == ECDSA_P256
    text = report.to_text()
    assert f"{history.k1.kid} [ecdsa-p256]" in text and f"{history.k2.kid} [ed25519]" in text

    report = verify_package(
        components,
        anchor=trust_anchor_with_history(anchor_v1(history.d), history.v2()),
        trust_source=TrustSource.SUPPLIED_ANCHOR,
    )
    assert report.verified, report.to_text()
    assert report.key_history["trust_mode"] == "v1+history"


def test_cross_algorithm_package_fails_when_an_ecdsa_record_is_altered():
    history = MixedHistory()
    components = mixed_package(history)
    components["timeline.json"][0]["signature"] = components["timeline.json"][1]["signature"]
    report = verify_package(components, anchor=trust_anchor_with_history(history.v2()))
    assert status_of(report, "event_signatures") is CheckStatus.FAIL


def test_succession_needs_each_signature_under_its_own_algorithm():
    history = MixedHistory()
    # The P-256 successor's signature is replaced by an Ed25519 signature
    # under the same kid: it must not verify.
    impostor = Ed25519PrivateKey.generate()
    forged = history.v2()
    rotation = forged["statements"][1]
    signed = statement_signing_bytes(rotation)
    rotation["signatures"] = [
        {"kid": history.k1.kid, "sig": base64.b64encode(impostor.sign(signed)).decode()},
        {"kid": history.k2.kid, "sig": history.k2.sign(signed)},
    ]
    with pytest.raises(AnchorError, match="predecessor"):
        trust_anchor_with_history(forged)


def test_successor_algorithm_must_match_its_key_and_kid():
    history = MixedHistory()
    # successor_algorithm says ed25519, the key is a P-256 SPKI.
    bad = statement(
        history.d, history.k1, MIGRATION_AT, [history.d, history.k1],
        reason="infrastructure_migration", successor_algorithm=ED25519,
    )
    with pytest.raises(AnchorError, match="expected 32 for Ed25519"):
        trust_anchor_with_history(anchor_v2(history.d, [history.d, history.k1], [bad]))

    # An unknown successor_algorithm is refused outright.
    bad = statement(
        history.d, history.k1, MIGRATION_AT, [history.d, history.k1],
        reason="infrastructure_migration", successor_algorithm="rsa",
    )
    with pytest.raises(AnchorError, match="successor_algorithm 'rsa'"):
        trust_anchor_with_history(anchor_v2(history.d, [history.d, history.k1], [bad]))


def test_p256_kid_binding():
    history = MixedHistory()
    # The fingerprint is SHA-256 of the SPKI DER, not of the raw point.
    point = history.k1.private.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    wrong_hash = EcKey(
        "t-" + TENANT.replace("-", "")[:8] + "-ecdsa-p256-" + hashlib.sha256(point).hexdigest()[:16]
    )
    wrong_hash.private, wrong_hash.raw, wrong_hash.b64 = (
        history.k1.private, history.k1.raw, history.k1.b64,
    )
    bad = statement(
        history.d, wrong_hash, MIGRATION_AT, [history.d, wrong_hash],
        reason="infrastructure_migration",
    )
    with pytest.raises(AnchorError, match="not derived"):
        trust_anchor_with_history(anchor_v2(history.d, [history.d, wrong_hash], [bad]))

    # The right fingerprint under the ed25519 label in the kid.
    mislabelled = EcKey(history.k1.kid.replace("-ecdsa-p256-", "-ed25519-"))
    mislabelled.private, mislabelled.raw, mislabelled.b64 = (
        history.k1.private, history.k1.raw, history.k1.b64,
    )
    bad = statement(
        history.d, mislabelled, MIGRATION_AT, [history.d, mislabelled],
        reason="infrastructure_migration",
    )
    with pytest.raises(AnchorError, match="names algorithm ed25519"):
        trust_anchor_with_history(anchor_v2(history.d, [history.d, mislabelled], [bad]))

    # Another tenant's prefix.
    other = EcKey(p256_kid(history.k1.raw, "00000000-0000-0000-0000-000000000000"))
    other.private, other.raw, other.b64 = history.k1.private, history.k1.raw, history.k1.b64
    bad = statement(
        history.d, other, MIGRATION_AT, [history.d, other], reason="infrastructure_migration"
    )
    with pytest.raises(AnchorError, match="does not carry tenant"):
        trust_anchor_with_history(anchor_v2(history.d, [history.d, other], [bad]))

    # The documented example shape: 38 characters.
    assert len(history.k1.kid) == 38


def test_history_listing_a_key_under_another_algorithm_is_refused():
    history = MixedHistory()
    doc = history.v2()
    doc["keys"][1]["algorithm"] = ED25519
    with pytest.raises(AnchorError):
        trust_anchor_with_history(doc)


def test_p256_deployment_key_in_a_v1_pin_extends_through_a_history():
    """A P-256 key can be the pinned one, too: statements it signs verify."""
    deployment = EcKey("ecdsa-p256-deployment")
    k1 = Key()
    migration = statement(
        deployment, k1, MIGRATION_AT, [deployment, k1], reason="infrastructure_migration"
    )
    doc = anchor_v2(deployment, [deployment, k1], [migration])
    resolved = trust_anchor_with_history(anchor_v1(deployment), doc)
    assert {k["kid"] for k in resolved["keys"]} == {deployment.kid, k1.kid}
