"""Behavry evidence-package verification.

Verifies ``behavry.apr_evidence_package.v1`` archives against a pinned public
key, with no Behavry service, database, or account in the loop.

The canonical byte forms in :mod:`behavry_verify.canonical` and the Merkle
construction in :mod:`behavry_verify.merkle` are compatibility surfaces: they
must match the Behavry producer exactly, or valid evidence stops verifying.
"""
from __future__ import annotations

__version__ = "0.1.0"

PACKAGE_SCHEMA = "behavry.apr_evidence_package.v1"

__all__ = ["PACKAGE_SCHEMA", "__version__"]
