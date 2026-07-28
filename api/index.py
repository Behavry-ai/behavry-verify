"""Vercel entrypoint.

The Vercel Python runtime looks for a module-level ASGI callable named ``app``.
Everything of substance lives in :mod:`behavry_verify.app`, so the hosted
service and a local ``uvicorn behavry_verify.app:app`` run identical code.
"""
from __future__ import annotations

import sys
from pathlib import Path

# The function bundle is rooted at the repo, but the working directory during
# cold start is not guaranteed, so make the package importable explicitly.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from behavry_verify.app import app  # noqa: E402

__all__ = ["app"]
