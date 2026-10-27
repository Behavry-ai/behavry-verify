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
    INFO = "info"
    """Informational: reported, never part of the verdict."""


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


_ANCHOR_LABELS: dict[str, str] = {
    "anchor_id": "Anchor id",
    "tenant_id": "Tenant",
    "period_start": "Period start",
    "period_end": "Period end",
    "anchor_digest": "Anchor digest",
    "previous_anchor_digest": "Previous anchor",
    "tsa_status": "TSA status",
    "tsa_url": "TSA",
    "tsa_gen_time": "TSA genTime",
    "tsa_serial_number": "TSA serial",
    "tsa_policy": "TSA policy",
    "provenance_count": "Provenance entries",
    "provenance_root": "Provenance root",
    "records": "Records carried",
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

    # Observers' own verdicts (match / mismatch / absent / unobservable), as
    # claimed in the package. Informational: it does not affect the verdict,
    # and whether each claim was independently verified is the
    # ``observations`` check's job.
    observation_summary: dict[str, int] | None = None

    # What was verified: "evidence_package" or "audit_anchor".
    kind: str = "evidence_package"

    # Audit anchors only: what the anchor claims (period, tenant, TSA time).
    anchor_summary: dict[str, Any] | None = None

    # Authority packages (1.3) only: which golden-path elements the provenance
    # chain evidences. Informational, like ``observation_summary``.
    lifecycle: dict[str, bool] | None = None

    # Authority packages 1.4 only (check 15): each anchor in anchors.json and
    # how each provenance entry classifies (anchored, not yet anchored,
    # missing, unanchored, anchor_unverified). See
    # :func:`behavry_verify.authority.check_provenance_anchoring`. Package 1.6,
    # or any package given an anchor head, adds ``heads`` and ``head_note``;
    # 1.6 adds ``predecessor``. A package given an ``--anchor-heads-dir``
    # folder adds ``head_gaps`` (AG-9).
    provenance_anchoring: dict[str, Any] | None = None

    # Check 16 (AG-10): each record's witness receipt (log index, integrated
    # time, status, failed W checks). Present only when the check ran: package
    # 1.7, a record carrying ``witness``, or ``--require-witness``. See
    # :func:`behavry_verify.witness.check_witness`.
    witness: dict[str, Any] | None = None

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

    def add_info(self, check_id: str, label: str, detail: str = "") -> Check:
        return self.add(check_id, label, CheckStatus.INFO, detail)

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
        if body.get("witness") is None:
            # Absent rather than null, so a report without check 16 keeps the
            # shape it had before AG-10.
            body.pop("witness", None)
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
            CheckStatus.INFO: "i",
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
        if self.anchor_summary:
            for key, value in self.anchor_summary.items():
                if value not in (None, ""):
                    name = _ANCHOR_LABELS.get(key, key)
                    lines.append(f"  {name.ljust(width)}  {value}")
        if self.observation_summary:
            verdicts = ", ".join(f"{k} {v}" for k, v in self.observation_summary.items())
            lines.append(
                f"  {'Observer verdicts'.ljust(width)}  {verdicts} "
                "(informational, as claimed by observers)"
            )
        if self.provenance_anchoring:
            pa = self.provenance_anchoring
            lines.append(
                f"  {'Provenance anchoring'.ljust(width)}  {pa.get('anchored', 0)} anchored, "
                f"{pa.get('not_yet_anchored', 0)} not yet anchored, {pa.get('missing', 0)} "
                f"missing, {pa.get('unanchored', 0)} unanchored "
                f"(across {pa.get('anchor_count', 0)} anchor(s))"
            )
            if "chain_unbroken" in pa:
                lines.append(
                    f"  {'Anchor chain'.ljust(width)}  "
                    + ("unbroken" if pa["chain_unbroken"] else "BROKEN: an anchor is missing")
                )
            if "predecessor" in pa:
                pred = pa["predecessor"]
                if pred is None:
                    line = "none (the run starts the anchor chain)"
                else:
                    line = f"{pred.get('anchor_id')} ({pred.get('schema')}), " + (
                        "verified" if pred.get("verified") else "NOT VERIFIED"
                    )
                lines.append(f"  {'Run predecessor'.ljust(width)}  {line}")
            forks = pa.get("forks") or []
            for index, head in enumerate(pa.get("heads") or []):
                state = (
                    "verified"
                    if head.get("verified")
                    else "NOT VERIFIED, not used: " + ", ".join(head.get("failed_checks") or [])
                )
                # AG7-CONTRACTS section 3: name each anchor the head contradicts.
                against = [
                    fork_against(fork, index)
                    for fork in forks
                    if index in (fork.get("head_index"), fork.get("other_head_index"))
                ]
                if against:
                    state += ", FORK: contradicts " + "; ".join(against)
                lines.append(
                    f"  {'Anchor head'.ljust(width)}  {head.get('anchor_id')} "
                    f"({head.get('period_start')}..{head.get('period_end')}), {state}"
                )
            # AG9-CONTRACTS section 5: name both heads of each gap in a folder.
            for gap in pa.get("head_gaps") or []:
                lines.append(
                    f"  {'Head gap'.ljust(width)}  {gap.get('folder')}: between "
                    f"{gap.get('earlier_anchor_id')} ({gap.get('earlier_period_start')}) and "
                    f"{gap.get('later_anchor_id')} ({gap.get('later_period_start')}), "
                    "they do not link"
                )
            if pa.get("head_note"):
                lines.append(f"  {'Anchor head'.ljust(width)}  {pa['head_note']}")
        if self.witness:
            lines.extend(self._witness_lines(width))
        lines.append("")
        lines.append(f"  {self.caveat}")
        if self.error:
            lines.append("")
            lines.append(f"  Error: {self.error}")
        return "\n".join(lines)

    def _witness_lines(self, width: int) -> list[str]:
        wi = self.witness or {}
        lines: list[str] = []
        name = "Witness".ljust(width)
        if wi.get("trust_note"):
            lines.append(f"  {name}  {wi['trust_note']}")
        if wi.get("trust"):
            for log in wi["trust"].get("logs") or []:
                lines.append(
                    f"  {'Witness log'.ljust(width)}  {log.get('log_id')} "
                    f"({log.get('algorithm')}" + (
                        f", {log['base_url']})" if log.get("base_url") else ")"
                    )
                )
        if "witness_since" in wi:
            lines.append(
                f"  {'Witness since'.ljust(width)}  "
                + (wi["witness_since"] or "none (the manifest requires no receipt)")
            )
        role_name = {"anchor": "anchor", "predecessor": "predecessor", "head": "anchor head"}
        for row in wi.get("records") or []:
            if row.get("status") == "absent":
                continue
            what = (
                f"{role_name.get(row.get('role'), 'anchor')} {row.get('anchor_id')} "
                f"({row.get('period_start')}..{row.get('period_end')})"
            )
            status = row.get("status")
            if status == "missing":
                state = "MISSING: required, none carried"
            else:
                logged = f"log index {row.get('log_index')} at {row.get('integrated_at')}"
                if status == "verified":
                    state = f"{logged}, verified"
                elif status == "not_checked":
                    state = f"{logged}, not checked"
                else:
                    state = f"{logged}, FAILED: " + ", ".join(row.get("failed_checks") or [])
            lines.append(f"  {name}  {what}: {state}")
        return lines

    def _signer_line(self) -> str | None:
        if not self.signer_kid:
            return None
        parts = [self.signer_kid]
        if self.signature_algorithm:
            parts.append(f"({self.signature_algorithm})")
        if self.signing_backend:
            parts.append(f"via {self.signing_backend}")
        return " ".join(parts)


_FORK_KIND = {
    "run": "run anchor",
    "predecessor": "run predecessor",
    "head": "anchor head",
}


def fork_against(fork: dict[str, Any], index: int) -> str:
    """The anchor a fork row says head ``index`` contradicts, as text."""
    if fork.get("against") == "head" and fork.get("head_index") != index:
        # This head is the earlier one of the pair: name the later head.
        return (
            f"anchor head {fork.get('head_anchor_id')} "
            f"({fork.get('head_period_start')}..{fork.get('head_period_end')})"
        )
    kind = _FORK_KIND.get(str(fork.get("against")), "anchor")
    return (
        f"{kind} {fork.get('anchor_id')} "
        f"({fork.get('anchor_period_start')}..{fork.get('anchor_period_end')})"
    )
