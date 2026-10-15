"""Audit-anchor verification (Behavry E-8), against anchors Behavry itself sealed.

``tests/vectors/anchor_vectors.json`` was written by Behavry's own
``anchor_export_payload``, ``canonical_anchor_bytes``, signer and
``parse_timestamp_response`` (see ``generate_anchor_vectors.py``). The RFC 3161
tokens are genuine CMS SignedData from a test TSA whose root is
``tsa_root.pem``; ``openssl ts -verify`` accepts them.
"""
from __future__ import annotations

import base64
import copy
import datetime as dt
import json
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID

from behavry_verify.audit_anchor import (
    canonical_anchor_bytes,
    verify_anchor_chain,
    verify_audit_anchor,
)
from behavry_verify.cli import main
from behavry_verify.report import TrustSource
from behavry_verify.rfc3161 import load_pem_certificates, parse_timestamp_token

VECTORS = Path(__file__).parent / "vectors"
DATA = json.loads((VECTORS / "anchor_vectors.json").read_text("utf-8"))
TRUST = DATA["trust_anchor"]
ROOTS_PEM = (VECTORS / "tsa_root.pem").read_bytes()
ROOTS = load_pem_certificates(ROOTS_PEM)


def anchor(name: str) -> dict[str, Any]:
    return copy.deepcopy(DATA["anchors"][name])


def verify(export: dict[str, Any], *, trust: dict | None = TRUST, roots=ROOTS):
    return verify_audit_anchor(
        export, anchor=trust, trust_source=TrustSource.SUPPLIED_ANCHOR, tsa_roots=roots
    )


def status(report, check_id: str) -> str:
    return next(c for c in report.checks if c.id == check_id).status.value


def detail(report, check_id: str) -> str:
    return next(c for c in report.checks if c.id == check_id).detail


# ---------------------------------------------------------------------------
# Parity and the happy path
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", sorted(DATA["anchors"]))
def test_canonical_bytes_reproduce_the_producers_digest(name):
    import hashlib

    export = anchor(name)
    assert hashlib.sha256(canonical_anchor_bytes(export)).hexdigest() == export["anchor_digest"]


@pytest.mark.parametrize("name", ["chain_0", "chain_1", "v1_ec"])
def test_timestamped_anchor_verifies_end_to_end(name):
    report = verify(anchor(name))
    assert report.verified, report.to_text()
    for check_id in (
        "merkle_root", "event_count", "boundary_hashes", "anchor_digest", "signature",
        "event_signatures", "tsa_imprint", "tsa_signature", "tsa_chain",
    ):
        assert status(report, check_id) == "pass", (check_id, report.to_text())
    assert report.kind == "audit_anchor"
    assert report.anchor_summary["tsa_gen_time"]


def test_rsa_and_ecdsa_tsa_signatures_are_both_checked():
    assert detail(verify(anchor("chain_0")), "tsa_signature").startswith("ecdsa/sha256")
    assert detail(verify(anchor("chain_1")), "tsa_signature").startswith("rsa/sha256")


def test_hashless_records_count_but_are_not_leaves():
    report = verify(anchor("chain_0"))
    assert "3 event hash(es) in 4 record(s)" in detail(report, "merkle_root")


def test_without_roots_the_chain_is_honestly_not_validated():
    report = verify(anchor("chain_0"), roots=None)
    assert report.verified
    assert status(report, "tsa_chain") == "skipped"
    text = detail(report, "tsa_chain")
    assert "imprint checked, TSA certificate chain not validated" in text
    assert "openssl ts -verify" in text


def test_anchor_with_no_tsa_verifies_and_says_no_third_party_attests():
    report = verify(anchor("chain_2"))
    assert report.verified, report.to_text()
    assert status(report, "tsa_imprint") == "skipped"
    assert "no third party attests to when" in detail(report, "tsa_imprint")


def test_token_without_signer_is_a_warning_not_a_pass():
    report = verify(anchor("unsigned_token"))
    assert status(report, "tsa_imprint") == "pass"
    assert status(report, "tsa_signature") == "warn"
    assert "anyone could have produced it" in detail(report, "tsa_signature")
    assert status(report, "tsa_chain") == "skipped"


def test_raw_public_key_path():
    raw = base64.b64decode(TRUST["keys"][0]["public_key"])
    report = verify_audit_anchor(
        anchor("chain_0"), raw_public_key=raw, trust_source=TrustSource.SUPPLIED_KEY
    )
    assert report.verified, report.to_text()


def test_token_fields_are_read_without_asn1crypto():
    export = anchor("chain_0")
    token = parse_timestamp_token(base64.b64decode(export["tsa"]["token_der_b64"]))
    assert token.imprint.hex() == export["anchor_digest"]
    assert token.serial_number == int(export["tsa"]["serial_number"])
    assert token.policy == export["tsa"]["policy"]
    assert token.nonce is not None


# ---------------------------------------------------------------------------
# Tampering
# ---------------------------------------------------------------------------


def test_altered_root_fails():
    export = anchor("chain_0")
    export["merkle_root"] = "sha256:" + "0" * 64
    report = verify(export)
    assert not report.verified
    assert status(report, "merkle_root") == "fail"
    # The root is inside the signed and timestamped bytes, so all three break.
    assert status(report, "anchor_digest") == "fail"
    assert status(report, "signature") == "fail"
    assert status(report, "tsa_imprint") == "fail"


def test_removed_event_fails():
    export = anchor("chain_0")
    del export["events"][2]
    report = verify(export)
    assert status(report, "merkle_root") == "fail"
    assert status(report, "event_count") == "fail"


def test_altered_event_hash_fails():
    export = anchor("chain_0")
    export["events"][0]["event_hash"] = "f" * 64
    report = verify(export)
    assert status(report, "merkle_root") == "fail"
    assert status(report, "boundary_hashes") == "fail"
    assert status(report, "event_signatures") == "fail"


def test_altered_event_timestamp_fails_its_signature():
    export = anchor("chain_0")
    export["events"][3]["timestamp"] = "2026-09-07T12:59:59.000000+00:00"
    report = verify(export)
    assert status(report, "merkle_root") == "pass"
    assert status(report, "event_signatures") == "fail"
    assert not report.verified


def test_reordered_events_fail():
    export = anchor("chain_0")
    export["events"][0], export["events"][2] = export["events"][2], export["events"][0]
    assert status(verify(export), "merkle_root") == "fail"


def test_wrong_imprint_fails():
    """A genuine token, from the same TSA, over a different anchor."""
    export = anchor("chain_0")
    export["tsa"] = anchor("chain_1")["tsa"]
    report = verify(export)
    assert not report.verified
    assert status(report, "tsa_imprint") == "fail"
    assert "different digest" in detail(report, "tsa_imprint")


def test_altered_token_content_fails_the_tsa_signature():
    export = anchor("chain_0")
    der = base64.b64decode(export["tsa"]["token_der_b64"])
    assert der.count(b"20260907140003Z") == 1
    forged = der.replace(b"20260907140003Z", b"20260907120003Z")
    export["tsa"]["token_der_b64"] = base64.b64encode(forged).decode()
    export["tsa"]["gen_time"] = "2026-09-07T12:00:03.000000+00:00"
    report = verify(export)
    assert status(report, "tsa_imprint") == "pass"
    assert status(report, "tsa_signature") == "fail"
    assert "messageDigest" in detail(report, "tsa_signature")
    assert not report.verified


def test_misreported_gen_time_fails():
    export = anchor("chain_0")
    export["tsa"]["gen_time"] = "2026-09-07T12:30:00.000000+00:00"
    assert status(verify(export), "tsa_imprint") == "fail"


def test_garbage_token_fails_cleanly():
    export = anchor("chain_0")
    export["tsa"]["token_der_b64"] = base64.b64encode(b"\x30\x03\x02\x01").decode()
    report = verify(export)
    assert status(report, "tsa_imprint") == "fail"
    assert "unreadable" in detail(report, "tsa_imprint")


def test_wrong_key_fails():
    other = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    wrong = copy.deepcopy(TRUST)
    wrong["keys"][0]["public_key"] = base64.b64encode(other).decode()
    report = verify(anchor("chain_0"), trust=wrong)
    assert not report.verified
    assert status(report, "signature") == "fail"
    assert status(report, "event_signatures") == "fail"


def test_stripped_signature_is_not_verified():
    export = anchor("chain_0")
    export["signature"] = None
    report = verify(export)
    assert not report.verified
    assert status(report, "signature") == "skipped"
    assert "no Behavry signature" in detail(report, "signature")


def test_no_key_is_not_verified():
    report = verify_audit_anchor(anchor("chain_0"))
    assert not report.verified
    assert status(report, "signature") == "skipped"


def _other_root() -> x509.Certificate:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test TSA Root")])
    now = dt.datetime(2026, 1, 1, tzinfo=dt.UTC)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + dt.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )


def test_tsa_chain_to_an_untrusted_root_fails():
    report = verify(anchor("chain_0"), roots=[_other_root()])
    assert status(report, "tsa_chain") == "fail"
    assert "no issuer" in detail(report, "tsa_chain")
    assert not report.verified


def test_tsa_certificate_outside_its_validity_fails():
    export = anchor("chain_0")
    token = parse_timestamp_token(base64.b64decode(export["tsa"]["token_der_b64"]))
    from behavry_verify.rfc3161 import validate_tsa_chain, verify_tsa_signature

    cert = verify_tsa_signature(token).certificate
    token.gen_time = dt.datetime(2040, 1, 1, tzinfo=dt.UTC)
    ok, why = validate_tsa_chain(cert, token, ROOTS)
    assert not ok and "not valid at genTime" in why


# ---------------------------------------------------------------------------
# The anchor chain (AUD-LINK)
# ---------------------------------------------------------------------------


def test_complete_chain_verifies():
    ok, lines = verify_anchor_chain([anchor("chain_2"), anchor("chain_0"), anchor("chain_1")])
    assert ok, lines
    assert "2 linked" in " ".join(lines)


def test_missing_period_is_reported():
    ok, lines = verify_anchor_chain([anchor("chain_0"), anchor("chain_2")])
    assert not ok
    assert any(line.startswith("MISSING PERIOD") for line in lines)


def test_stripped_back_pointer_is_tampering():
    later = anchor("chain_2")
    later["previous_anchor_digest"] = None
    ok, lines = verify_anchor_chain([anchor("chain_0"), anchor("chain_1"), later])
    assert not ok
    assert any(line.startswith("TAMPERED CHAIN") for line in lines)


def test_pointer_to_a_non_adjacent_anchor_is_tampering():
    third = anchor("chain_2")
    third["previous_anchor_digest"] = anchor("chain_0")["anchor_digest"]
    ok, lines = verify_anchor_chain([anchor("chain_0"), anchor("chain_1"), third])
    assert not ok
    assert any("not the period immediately before" in line for line in lines)


def test_v1_anchors_are_unchained_not_broken():
    ok, lines = verify_anchor_chain([anchor("v1_ec"), anchor("chain_0"), anchor("chain_1")])
    assert ok, lines
    assert any("pre-AUD-LINK" in line for line in lines)


def test_cross_tenant_set_is_refused():
    other = anchor("chain_1")
    other["tenant_id"] = "someone-else"
    ok, _ = verify_anchor_chain([anchor("chain_0"), other])
    assert not ok


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


@pytest.fixture
def files(tmp_path: Path) -> dict[str, Path]:
    out = {"trust": tmp_path / "trust.json", "roots": tmp_path / "roots.pem"}
    out["trust"].write_text(json.dumps(TRUST))
    out["roots"].write_bytes(ROOTS_PEM)
    for name in DATA["anchors"]:
        out[name] = tmp_path / f"{name}.json"
        out[name].write_text(json.dumps(DATA["anchors"][name]))
    return out


def test_cli_single_anchor(files, capsys):
    code = main(
        ["--audit-anchor", str(files["chain_0"]), "--trust-anchor", str(files["trust"]),
         "--tsa-roots", str(files["roots"])]
    )
    out = capsys.readouterr().out
    assert code == 0, out
    assert out.startswith("VERIFIED")
    assert "TSA certificate chain valid" in out


def test_cli_anchor_set_walks_the_chain(files, capsys):
    code = main(
        ["--audit-anchor", str(files["chain_0"]), "--audit-anchor", str(files["chain_2"]),
         "--trust-anchor", str(files["trust"]), "--json"]
    )
    body = json.loads(capsys.readouterr().out)
    assert code == 1
    assert body["verified"] is False
    assert body["chain"]["verified"] is False
    assert all(a["report"]["verified"] for a in body["anchors"])


def test_cli_tampered_anchor_exits_one(files, capsys, tmp_path):
    export = anchor("chain_0")
    export["events"].pop()
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(export))
    assert main(["--audit-anchor", str(path), "--trust-anchor", str(files["trust"])]) == 1


def test_cli_bad_roots_is_a_usage_error(files, capsys, tmp_path):
    bad = tmp_path / "bad.pem"
    bad.write_text("not a certificate")
    code = main(
        ["--audit-anchor", str(files["chain_0"]), "--trust-anchor", str(files["trust"]),
         "--tsa-roots", str(bad)]
    )
    assert code == 2


def test_cli_package_and_anchor_are_exclusive(files, capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--audit-anchor", str(files["chain_0"]), "--package", "x.zip",
              "--trust-anchor", str(files["trust"])])
    assert exc.value.code == 2


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------


def test_api_verifies_an_anchor():
    from fastapi.testclient import TestClient

    from behavry_verify.app import app

    client = TestClient(app)
    response = client.post(
        "/api/v1/verify-anchor",
        files={"audit_anchor": ("a.json", json.dumps(anchor("chain_0")), "application/json")},
        data={"trust_anchor": json.dumps(TRUST), "tsa_roots": ROOTS_PEM.decode()},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["verified"] is True
    assert body["kind"] == "audit_anchor"
    assert {c["id"]: c["status"] for c in body["checks"]}["tsa_chain"] == "pass"


def test_api_without_a_key_explains():
    from fastapi.testclient import TestClient

    from behavry_verify.app import app

    response = TestClient(app).post(
        "/api/v1/verify-anchor",
        files={"audit_anchor": ("a.json", json.dumps(anchor("chain_0")), "application/json")},
    )
    body = response.json()
    assert body["verified"] is False
    assert "registry" in body["error"]


def test_api_rejects_non_json():
    from fastapi.testclient import TestClient

    from behavry_verify.app import app

    response = TestClient(app).post(
        "/api/v1/verify-anchor", files={"audit_anchor": ("a.json", b"nope", "application/json")}
    )
    assert response.status_code == 400


def test_roots_fixture_is_public_only():
    assert b"PRIVATE" not in ROOTS_PEM
    assert ROOTS[0].public_bytes(serialization.Encoding.PEM) == ROOTS_PEM
