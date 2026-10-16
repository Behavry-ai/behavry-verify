"""RFC 8785 (JCS) canonical JSON, ported byte-for-byte from the Behavry producer.

Counterpart (repo ``Behavry-ai/behavry``):
``backend/behavry/audit/args_digest.py::canonical_json``, used through
``backend/behavry/audit/digests.py::content_digest``. Provenance entries bind
their ``body`` through ``body_digest = "sha256:" + sha256(RFC 8785 of body)``
(Sprint AG-2 E-4), so this port must reproduce the producer exactly, including
where it refuses: a non-finite number, a number beyond a double's range, a
non-string key or a non-JSON type raises :class:`NotCanonicalizableError`.

The rules (RFC 8785):

* object keys sorted by UTF-16 code units, not code points;
* no whitespace;
* numbers as an IEEE double printed the way ECMAScript's
  ``Number.prototype.toString`` prints it (integers too: every number goes
  through a double first, so an integer past 2**53 loses the same precision on
  both sides);
* strings escape only ``"``, ``\\``, and control characters below U+0020
  (``\\b \\f \\n \\r \\t`` by name, the rest as ``\\u00XX``). ``<``, ``>``,
  ``&`` and U+2028 are written as themselves, unlike ``json.dumps``.

Parity is pinned by ``tests/vectors/ag3_vectors.json``, written by the
producer's own function.
"""
from __future__ import annotations

import hashlib
import math
from decimal import Decimal
from typing import Any

_NAMED_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}


class NotCanonicalizableError(ValueError):
    """The value has no RFC 8785 form (a non-finite number, or a non-JSON type)."""


def _es_number(value: float) -> str:
    """Format a double as ECMAScript's Number.prototype.toString does."""
    if math.isnan(value) or math.isinf(value):
        raise NotCanonicalizableError("non-finite number")
    if value == 0:
        return "0"
    # repr() is the shortest round-trip form, the same digits ECMAScript picks.
    shortest = repr(value)
    magnitude = abs(value)
    if 1e-6 <= magnitude < 1e21:
        # Fixed notation, no trailing zeros and no trailing point.
        return format(Decimal(shortest).normalize(), "f")
    # Exponent notation: Python writes 1e-07 and 1.5e+21, ECMAScript 1e-7 and
    # 1.5e+21. repr() always uses an exponent outside the fixed range above.
    mantissa, _, exponent = shortest.partition("e")
    sign, digits = exponent[0], exponent[1:].lstrip("0") or "0"
    return f"{mantissa}e{sign}{digits}"


def _write_string(out: list[str], value: str) -> None:
    out.append('"')
    for ch in value:
        named = _NAMED_ESCAPES.get(ch)
        if named is not None:
            out.append(named)
        elif ord(ch) < 0x20:
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    out.append('"')


def _utf16_key(value: str) -> bytes:
    # Big-endian UTF-16 compares byte-wise in code-unit order.
    return value.encode("utf-16-be", "surrogatepass")


def _write(out: list[str], value: Any) -> None:
    if value is None:
        out.append("null")
    elif value is True:
        out.append("true")
    elif value is False:
        out.append("false")
    elif isinstance(value, int | float):
        # Integers too: Go parses every number to a float64 first, so an integer
        # past 2**53 loses the same precision on both sides.
        try:
            as_double = float(value)
        except OverflowError:
            # Beyond a double's range. Go's ParseFloat fails on it too and
            # Warden sends no digest; here it must not fail the governed call.
            raise NotCanonicalizableError("number out of range") from None
        out.append(_es_number(as_double))
    elif isinstance(value, str):
        _write_string(out, value)
    elif isinstance(value, list | tuple):
        out.append("[")
        for i, item in enumerate(value):
            if i:
                out.append(",")
            _write(out, item)
        out.append("]")
    elif isinstance(value, dict):
        out.append("{")
        for i, key in enumerate(sorted(value, key=_utf16_key)):
            if not isinstance(key, str):
                raise NotCanonicalizableError("object key is not a string")
            if i:
                out.append(",")
            _write_string(out, key)
            out.append(":")
            _write(out, value[key])
        out.append("}")
    else:
        raise NotCanonicalizableError(f"unsupported type {type(value).__name__}")


def canonical_json(value: Any) -> str:
    """The RFC 8785 serialization of a decoded JSON value."""
    out: list[str] = []
    _write(out, value)
    return "".join(out)


DIGEST_PREFIX = "sha256:"


def content_digest(value: Any) -> str | None:
    """``sha256:<hex>`` over the RFC 8785 form, or None for None / no form.

    Mirrors ``backend/behavry/audit/digests.py::content_digest``.
    """
    if value is None:
        return None
    try:
        body = canonical_json(value)
    except (NotCanonicalizableError, RecursionError):
        return None
    return DIGEST_PREFIX + hashlib.sha256(body.encode("utf-8", "surrogatepass")).hexdigest()


__all__ = ["NotCanonicalizableError", "canonical_json", "content_digest"]
