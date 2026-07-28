"""The published anchor registry, and the trust downgrade it implies."""
from __future__ import annotations

import json

from behavry_verify.registry import aggregate_anchor, anchor_for_kid, load_registry


def write_anchor(directory, name, builder, kid=None):
    path = directory / f"{name}.json"
    path.write_text(json.dumps(builder.anchor(kid=kid)))
    return path


def test_registry_indexes_published_keys(tmp_path, builder):
    write_anchor(tmp_path, "acme", builder)
    load_registry.cache_clear()
    registry = load_registry(str(tmp_path))
    assert builder.kid in registry
    assert registry[builder.kid]["_source"] == "acme.json"


def test_malformed_anchor_file_is_skipped_not_fatal(tmp_path, builder):
    write_anchor(tmp_path, "good", builder)
    (tmp_path / "broken.json").write_text("{not json")
    (tmp_path / "empty.json").write_text(json.dumps({"keys": []}))
    load_registry.cache_clear()
    registry = load_registry(str(tmp_path))
    assert builder.kid in registry
    assert len(registry) == 1


def test_anchor_for_kid_returns_a_single_key_anchor(tmp_path, builder):
    write_anchor(tmp_path, "acme", builder)
    load_registry.cache_clear()
    anchor = anchor_for_kid(builder.kid, str(tmp_path))
    assert anchor is not None
    assert len(anchor["keys"]) == 1
    # Internal bookkeeping must not leak into a served document.
    assert "_source" not in anchor["keys"][0]


def test_unknown_kid_is_not_published(tmp_path, builder):
    write_anchor(tmp_path, "acme", builder)
    load_registry.cache_clear()
    assert anchor_for_kid("who-is-this", str(tmp_path)) is None
    assert anchor_for_kid(None, str(tmp_path)) is None


def test_aggregate_anchor_is_wellformed_when_empty(tmp_path):
    load_registry.cache_clear()
    document = aggregate_anchor(str(tmp_path))
    assert document["schema"] == "behavry.trust_anchor.v1"
    assert document["keys"] == []


def test_registry_verification_is_reported_as_the_weaker_claim(tmp_path, builder):
    """A published-anchor result must never read like an independent one."""
    from behavry_verify.package import verify_package
    from behavry_verify.report import TrustSource

    write_anchor(tmp_path, "acme", builder)
    load_registry.cache_clear()
    anchor = anchor_for_kid(builder.kid, str(tmp_path))
    report = verify_package(
        builder.components(),
        anchor=anchor,
        trust_source=TrustSource.PUBLISHED_REGISTRY,
    )
    assert report.verified
    assert "came from Behavry" in report.caveat
    assert "obtain the trust anchor from the tenant" in report.caveat
