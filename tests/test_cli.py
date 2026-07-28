"""The offline CLI. Exit codes are the contract for CI use."""
from __future__ import annotations

import base64
import json

import pytest

from behavry_verify.cli import EXIT_NOT_VERIFIED, EXIT_USAGE, EXIT_VERIFIED, main


@pytest.fixture
def package_path(tmp_path, builder):
    path = tmp_path / "apr.zip"
    path.write_bytes(builder.zip_bytes())
    return path


@pytest.fixture
def anchor_path(tmp_path, builder):
    path = tmp_path / "anchor.json"
    path.write_text(json.dumps(builder.anchor()))
    return path


def test_valid_package_exits_zero(package_path, anchor_path, capsys):
    code = main(["--package", str(package_path), "--trust-anchor", str(anchor_path)])
    assert code == EXIT_VERIFIED
    out = capsys.readouterr().out
    assert "VERIFIED" in out
    assert "APR-2026-001942" in out


def test_tampered_package_exits_one(tmp_path, builder, anchor_path, capsys):
    components = builder.components()
    components["manifest.json"]["event_count"] = 99
    path = tmp_path / "bad.zip"
    path.write_bytes(builder.zip_bytes(components))

    code = main(["--package", str(path), "--trust-anchor", str(anchor_path)])
    assert code == EXIT_NOT_VERIFIED
    assert "NOT VERIFIED" in capsys.readouterr().out


def test_raw_public_key_path(package_path, builder, capsys):
    key = base64.b64encode(builder.public_key_bytes).decode("ascii")
    assert main(["--package", str(package_path), "--public-key", key]) == EXIT_VERIFIED


def test_json_output_is_machine_readable(package_path, anchor_path, capsys):
    main(["--package", str(package_path), "--trust-anchor", str(anchor_path), "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["verified"] is True
    assert payload["trust_source"] == "supplied_anchor"
    assert len(payload["checks"]) >= 6


def test_unpacked_directory_verifies(tmp_path, builder, anchor_path):
    import zipfile

    zip_path = tmp_path / "apr.zip"
    zip_path.write_bytes(builder.zip_bytes())
    unpacked = tmp_path / "unpacked"
    with zipfile.ZipFile(zip_path) as zf:
        zf.extractall(unpacked)
    assert main(["--package", str(unpacked), "--trust-anchor", str(anchor_path)]) == EXIT_VERIFIED


def test_missing_package_is_a_usage_error(tmp_path, anchor_path, capsys):
    code = main([
        "--package", str(tmp_path / "nope.zip"),
        "--trust-anchor", str(anchor_path),
    ])
    assert code == EXIT_USAGE


def test_malformed_anchor_is_a_usage_error(tmp_path, package_path, capsys):
    bad = tmp_path / "bad-anchor.json"
    bad.write_text("{not json")
    code = main(["--package", str(package_path), "--trust-anchor", str(bad)])
    assert code == EXIT_USAGE


def test_wrong_length_public_key_is_a_usage_error(package_path, capsys):
    short = base64.b64encode(b"too short").decode("ascii")
    code = main(["--package", str(package_path), "--public-key", short])
    assert code == EXIT_USAGE
    assert "expected 32" in capsys.readouterr().err


def test_text_report_names_the_trust_source(package_path, anchor_path, capsys):
    main(["--package", str(package_path), "--trust-anchor", str(anchor_path)])
    assert "does not depend on trusting" in capsys.readouterr().out
