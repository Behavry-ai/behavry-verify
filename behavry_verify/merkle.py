"""Merkle root over the ordered per-event hash list.

Mirrors ``backend/behavry/apr/packages.py::merkle_root`` in the Behavry repo.

A Merkle root (rather than a terminal chain hash) is what lets a holder prove
a single event's inclusion without revealing the whole chain, which is the
selective-disclosure property regulators ask for.
"""
from __future__ import annotations

import hashlib

__all__ = ["merkle_depth", "merkle_root"]


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def merkle_root(event_hashes: list[str]) -> str:
    """Compute the Merkle root over an ordered list of per-event hashes.

    Leaves are ``sha256(b"leaf:" + hash)``; internal nodes are
    ``sha256(b"node:" + left + right)``. A lone trailing node at any level is
    promoted unchanged (duplication-free and deterministic). Empty input
    yields the hash of the empty string so the field is always present.
    """
    if not event_hashes:
        return "sha256:" + _sha256_hex(b"")
    level = [_sha256_hex(b"leaf:" + h.encode("utf-8")) for h in event_hashes]
    while len(level) > 1:
        nxt: list[str] = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                nxt.append(_sha256_hex(("node:" + level[i] + level[i + 1]).encode("utf-8")))
            else:
                # Odd node promoted unchanged.
                nxt.append(level[i])
        level = nxt
    return "sha256:" + level[0]


def merkle_depth(event_count: int) -> int:
    """Tree depth = ceil(log2(event_count)); 0 for <= 1 events."""
    if event_count <= 1:
        return 0
    depth = 0
    n = 1
    while n < event_count:
        n *= 2
        depth += 1
    return depth
