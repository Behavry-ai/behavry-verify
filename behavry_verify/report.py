"""The verification report: the product surface of this service.

Two properties matter more than anything else here:

1. **Every check runs.** The reference CLI verifier returns on the first
   failure. An auditor needs the opposite: a broken hash chain should still
   report whether the signature was valid, because "signed by Behavry but
   missing an event" and "not signed at all" are completely different
   findings. Checks that genuinely cannot run (a bad signature makes the
   claimed event count meaningless) are marked ``SKIPPED``, never ``PASS``.

2. **The trust source is always stated.** Verifying against an anchor the
   auditor supplied is a strong claim. Verifying against an anchor this
   service published is a weaker one, because then Behavry is vouching for
   Behavry. The report never blurs the two.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

__all__ = [
    "Check",
    "CheckStatus",
    "TrustSource",
    "VerificationReport",
]


class CheckStatus(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    SKIPPED = "skipped"
    WARN = "warn"


class TrustSource(StrEnum):
    """Where the public key used for verification came from, weakest last."""

    SUPPLIED_ANCHOR = "supplied_anchor"
    """The requester supplied the trust anchor. Behavry is not in the loop."""

    SUPPLIED_KEY = "supplied_key"
    """The requester supplied a raw public key directly."""

    PUBLISHED_REGISTRY = "published_registry"
    """An anchor this service publishes. Convenience, not independent proof."""

    NONE = "none"
    """No key available; signature checks could not run."""


# Phrased to describe where the key came from, never to assert an outcome:
# these lines appear on failed reports too, and "Verified against ..." above a
# NOT VERIFIED headline would be actively misleading.
TRUST_SOURCE_CAVEAT: dict[TrustSource, str] = {
    TrustSource.SUPPLIED_ANCHOR: (
        "Checked against the trust anchor you supplied. Behavry was not "
        "consulted for the key, so this result does not depend on trusting "
        "this service."
    ),
    TrustSource.SUPPLIED_KEY: (
        "Checked against the public key you supplied. Behavry was not "
        "consulted for the key, so this result does not depend on trusting "
        "this service."
    ),
    TrustSource.PUBLISHED_REGISTRY: (
        "Checked against a trust anchor published by this service. This is a "
        "convenience: it confirms the package is internally consistent and "
        "signed by the named key, but the key itself came from Behavry. For a "
        "result that does not rely on trusting Behavry, obtain the trust "
        "anchor from the tenant directly and verify against that."
    ),
    TrustSource.NONE: "No trust anchor or public key was available.",
}


@dataclass
class Check:
    """One named verification step and its outcome."""

    id: str
    label: str
    status: CheckStatus
    detail: str = ""

    @property
    def ok(self) -> bool:
        return self.status is CheckStatus.PASS

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "label": self.label,
            "status": self.status.value,
            "detail": self.detail,
        }


@dataclass
class VerificationReport:
    """The full result of verifying one evidence package."""

    verified: bool = False
    checks: list[Check] = field(default_factory=list)

    # Identity of what was verified, read from the manifest.
    apr_identifier: str | None = None
    package_version: str | None = None
    package_schema: str | None = None
    event_count: int | None = None
    root_hash: str | None = None
    chain_status: str | None = None
    created_at: str | None = None

    # Identity of who signed it.
    signer_kid: str | None = None
    signature_algorithm: str | None = None
    signing_backend: str | None = None

    trust_source: TrustSource = TrustSource.NONE
    verified_at: str = ""
    error: str | None = None

    def __post_init__(self) -> None:
        if not self.verified_at:
            self.verified_at = datetime.now(UTC).isoformat(timespec="seconds")

    # -- construction --------------------------------------------------------

    def add(
        self, check_id: str, label: str, status: CheckStatus, detail: str = ""
    ) -> Check:
        check = Check(id=check_id, label=label, status=status, detail=detail)
        self.checks.append(check)
        return check

    def add_pass(self, check_id: str, label: str, detail: str = "") -> Check:
        return self.add(check_id, label, CheckStatus.PASS, detail)

    def add_fail(self, check_id: str, label: str, detail: str = "") -> Check:
        return self.add(check_id, label, CheckStatus.FAIL, detail)

    def add_skip(self, check_id: str, label: str, detail: str = "") -> Check:
        return self.add(check_id, label, CheckStatus.SKIPPED, detail)

    def add_warn(self, check_id: str, label: str, detail: str = "") -> Check:
        return self.add(check_id, label, CheckStatus.WARN, detail)

    def finalize(self) -> VerificationReport:
        """Decide the verdict.

        A package is verified when its signature was actually checked and
        passed, and nothing else contradicted it.

        Skips are treated by kind rather than uniformly. A skipped *signature*
        check is fatal: without it nothing is proven, so the verdict cannot be
        positive. A skipped ancillary check is not. A package whose events
        carry no individual signatures, or a raw pinned key with no anchor
        entry to fingerprint, is still fully covered by the manifest
        signature, which commits to the Merkle root over every event. Treating
        those as failures would report tampering where there is none.
        """
        if not self.checks:
            self.verified = False
            return self
        signature_passed = any(
            c.id == "signature" and c.status is CheckStatus.PASS for c in self.checks
        )
        nothing_failed = all(c.status is not CheckStatus.FAIL for c in self.checks)
        self.verified = signature_passed and nothing_failed
        return self

    # -- rendering -----------------------------------------------------------

    @property
    def caveat(self) -> str:
        return TRUST_SOURCE_CAVEAT[self.trust_source]

    def to_dict(self) -> dict[str, Any]:
        body = asdict(self)
        body["checks"] = [c.to_dict() for c in self.checks]
        body["trust_source"] = self.trust_source.value
        body["caveat"] = self.caveat
        return body

    def to_text(self) -> str:
        """Plain-text report, the shape used by the CLI and the spec."""
        glyph = {
            CheckStatus.PASS: "✓",
            CheckStatus.FAIL: "✗",
            CheckStatus.SKIPPED: "–",
            CheckStatus.WARN: "⚠",
        }
        width = max((len(c.label) for c in self.checks), default=0)
        lines: list[str] = []
        headline = "VERIFIED" if self.verified else "NOT VERIFIED"
        lines.append(headline)
        lines.append("")
        for check in self.checks:
            detail = f"  {check.detail}" if check.detail else ""
            lines.append(f"{glyph[check.status]} {check.label.ljust(width)}{detail}")
        lines.append("")
        for label, value in (
            ("Signer identity", self._signer_line()),
            ("APR identifier", self.apr_identifier),
            ("Event count", self.event_count),
            ("Root hash", self.root_hash),
            ("Verified at", self.verified_at),
        ):
            if value not in (None, ""):
                lines.append(f"  {label.ljust(width)}  {value}")
        lines.append("")
        lines.append(f"  {self.caveat}")
        if self.error:
            lines.append("")
            lines.append(f"  Error: {self.error}")
        return "\n".join(lines)

    def _signer_line(self) -> str | None:
        if not self.signer_kid:
            return None
        parts = [self.signer_kid]
        if self.signature_algorithm:
            parts.append(f"({self.signature_algorithm})")
        if self.signing_backend:
            parts.append(f"via {self.signing_backend}")
        return " ".join(parts)
