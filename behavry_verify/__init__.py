"""Behavry evidence-package verification.

Verifies ``behavry.apr_evidence_package.v1`` archives against a pinned public
key, with no Behavry service, database, or account in the loop.

The canonical byte forms in :mod:`behavry_verify.canonical` and the Merkle
construction in :mod:`behavry_verify.merkle` are compatibility surfaces: they
must match the Behavry producer exactly, or valid evidence stops verifying.
"""
from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("behavry-verify")
except PackageNotFoundError:
    # Running from a source tree with nothing installed. Say "unknown" rather
    # than naming a release: a literal here is the same second source of truth
    # that made 0.2.0 ship to PyPI while reporting "0.1.0", and it would go
    # stale again at the next bump. A tool whose job is provenance should admit
    # it cannot determine its own version instead of guessing a plausible one.
    __version__ = "0.0.0+unknown"

PACKAGE_SCHEMA = "behavry.apr_evidence_package.v1"

__all__ = ["PACKAGE_SCHEMA", "__version__"]
