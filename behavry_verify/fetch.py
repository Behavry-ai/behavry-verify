"""Guarded fetching of packages supplied by URL.

Accepting a URL means this service makes an outbound request on a stranger's
behalf, which is a server-side request forgery primitive unless it is fenced
in. Every hop is checked here:

* HTTPS only (evidence packages are confidential documents).
* The resolved address must be publicly routable. Loopback, private, link-local
  (including cloud metadata at 169.254.169.254), and reserved ranges are refused.
* Redirects are followed manually so each new destination is re-checked, and
  are capped.
* The response body is capped while streaming, so a hostile server cannot
  stream an unbounded body at us.
"""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

import httpx

__all__ = ["FetchError", "MAX_DOWNLOAD_BYTES", "fetch_package"]

MAX_DOWNLOAD_BYTES = 64 * 1024 * 1024  # 64 MiB
MAX_REDIRECTS = 3
TIMEOUT_SECONDS = 15.0


class FetchError(ValueError):
    """Raised when a URL cannot be fetched, or is not safe to fetch."""


def _assert_public_host(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise FetchError("only https:// URLs are accepted")
    host = parsed.hostname
    if not host:
        raise FetchError("URL has no host")

    try:
        infos = socket.getaddrinfo(host, parsed.port or 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise FetchError(f"cannot resolve host {host!r}") from exc

    for info in infos:
        address = ipaddress.ip_address(info[4][0])
        if (
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_reserved
            or address.is_multicast
            or address.is_unspecified
        ):
            raise FetchError(
                f"refusing to fetch {host!r}: it resolves to the non-public "
                f"address {address}"
            )


def fetch_package(url: str, *, max_bytes: int = MAX_DOWNLOAD_BYTES) -> bytes:
    """Fetch package bytes from ``url``, enforcing every guard above."""
    current = url
    with httpx.Client(follow_redirects=False, timeout=TIMEOUT_SECONDS) as client:
        for _ in range(MAX_REDIRECTS + 1):
            _assert_public_host(current)
            try:
                with client.stream("GET", current) as response:
                    if response.is_redirect:
                        location = response.headers.get("location")
                        if not location:
                            raise FetchError("redirect without a Location header")
                        current = str(httpx.URL(current).join(location))
                        continue
                    if response.status_code != 200:
                        raise FetchError(
                            f"fetch returned HTTP {response.status_code}"
                        )
                    declared = response.headers.get("content-length")
                    if declared and declared.isdigit() and int(declared) > max_bytes:
                        raise FetchError(
                            f"package is {declared} bytes, above the {max_bytes} limit"
                        )
                    chunks: list[bytes] = []
                    total = 0
                    for chunk in response.iter_bytes():
                        total += len(chunk)
                        if total > max_bytes:
                            raise FetchError(
                                f"package exceeds the {max_bytes} byte limit"
                            )
                        chunks.append(chunk)
                    return b"".join(chunks)
            except httpx.HTTPError as exc:
                raise FetchError(f"could not fetch the URL: {exc}") from exc
    raise FetchError(f"too many redirects (limit {MAX_REDIRECTS})")
