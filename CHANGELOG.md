# Changelog

## 0.6.0

Sprint AG-6 (independent anchor head), following Behavry's
`docs/strategy/AG6-CONTRACTS.md`.

### Added

- **Header-only anchor records.** An export with `"records": "header"`, of any
  schema, carries the signed fields and no records. `--audit-anchor`,
  `POST /api/v1/verify-anchor` and check 15 verify its digest, signature and
  RFC 3161 token, and report every event and provenance record check skipped
  with the contract's reason, never passed. A header that carries records
  anyway warns, and they are ignored.
- **Check 15 v3 for authority packages 1.6.** `anchors.json` carries the run's
  `predecessor` as a header-only record, and the signed manifest states
  `anchor_predecessor_digest`. When the first anchor points back, the
  predecessor must be present, match that pointer and the manifest, verify
  under the trust anchor and be for the package's tenant; when the run is
  empty or starts the chain, both must be null (P1). When the predecessor is
  v3, an entry older than the run is `missing` and fails, which closes front
  truncation (P2); with a v1 or v2 predecessor, or none, it stays
  `unanchored`.
- **Anchor heads: `--anchor-head FILE`**, repeatable, and the repeatable file
  field `anchor_head` on `POST /api/v1/verify` and `/api/v1/verify.txt`, with a
  file input on the package form. Heads apply to packages 1.4, 1.5 and 1.6.
  A head must verify (header-only or full record) and be for the package's
  tenant, or it is reported, not used, and fails the check (H1). A head with
  a run anchor's `period_start` but another digest is a fork and fails (H2).
  Every entry older than a verified head's `period_end` must be anchored, so
  an entry that would read not yet anchored is `missing` and fails, which
  closes tail truncation by a key holder (H3). When the head was sealed after
  the package was created, the finding says the package may simply predate
  it. With no head, the report carries the H4 note.
- The JSON report adds `heads`, `head_note` and (1.6) `predecessor` to
  `provenance_anchoring`. The text and web reports show the predecessor, each
  head and the H4 note.

### Unchanged

- Packages 1.4 and 1.5 behave as before when no head is supplied, report
  shape included. Packages older than 1.4 skip check 15, and say that any
  heads supplied were not applied.

## 0.5.0

Sprint AG-5 (H-1, a withheld anchor fails), following Behavry's
`docs/strategy/AG5-CONTRACTS.md`.

### Added

- **Check 15 v2 for authority packages 1.5.** `anchors.json` is the whole run
  of v3 anchors over the package's span. Across it the AUD-LINK chain must be
  unbroken (each `previous_anchor_digest` equals the previous anchor's
  `anchor_digest`), or the check fails with "anchor chain broken between
  <period_end> and <period_start>: an anchor is missing". The signed
  manifest's `anchor_count` and new `anchor_head_digest` must match the run,
  and every anchor in it must be v3. With the chain unbroken, an entry inside
  the span but in no anchor's period is `missing` and fails, where 1.4 only
  warned. An empty run passes with every entry not yet anchored.
- **Provenance-only anchor records.** An export with `"records": "provenance"`
  and no `events` is accepted by check 15 and by `--audit-anchor` and
  `POST /api/v1/verify-anchor`. Its event Merkle root, count, boundary hashes
  and event signatures are reported skipped, with the contract's reason, never
  passed; the digest and signature still cover the event fields. The flag is
  defined for v3 only, so on a v1 or v2 anchor it fails, and an unknown
  `records` value warns and is checked as a full record.
- The 1.5 JSON report adds `package_version`, `anchor_head_digest`,
  `chain_unbroken` and `chain_breaks` to `provenance_anchoring`, and
  `records`, `previous_anchor_digest`, `event_checks` and `linked` to each
  anchor row. The text and web reports show the chain, and the web summary of
  a provenance-only anchor says its event checks were skipped.
- Tests pin the unknown provenance entry type `device_bound` as informational,
  including on the lifecycle line, and pin the limit 1.5 leaves open: a key
  holder dropping the newest anchors and re-signing the manifest.

### Unchanged

- Packages 1.4 keep the AG-4 behaviour and report shape, warning included.
  Packages older than 1.4 still skip check 15.

## 0.4.0

Sprint AG-4 (G-1 verifier and G-7), following Behavry's
`docs/strategy/AG4-CONTRACTS.md`.

### Added

- **Anchor schema v3.** `behavry.audit_anchor.v3` canonical bytes: the v2
  payload plus `provenance_count`, `provenance_root`, `first_provenance_hash`
  and `last_provenance_hash` (null hashes as `""`, a null root as the empty
  root). For v3 anchors `--audit-anchor` and `POST /api/v1/verify-anchor` also
  recompute the provenance root, count and first/last hashes from the export's
  hash-only `provenance` records, check each record's Behavry signature
  (agent-claim form, claim type `provenance`), and report the provenance
  figures. v1 and v2 bytes are unchanged.
- **Check 15, `provenance_anchoring`, for authority packages 1.4.** Each anchor
  in `anchors.json` is verified as `--audit-anchor` would, under the package's
  trust anchor, and must be for the package's tenant; `anchor_count` must
  match the signed manifest. Each provenance entry is classified `anchored`
  (with that anchor's TSA genTime, or "no TSA"), `not_yet_anchored` (reported,
  never a failure), `missing` (inside a sealed v3 period but not in its anchor:
  fails), `unanchored` (no anchor, or only a pre-v3 one, covers it; a warning
  when inside the sealed span) or `anchor_unverified`. Packages before 1.4
  skip with the reason. The JSON report gains `provenance_anchoring`.
- `--tsa-roots` now also applies to `--package`, for check 15's anchors, and
  `verify_package` takes `tsa_roots`.
- **API:** `POST /api/v1/verify` and `/api/v1/verify.txt` accept
  `observer_anchor` as a repeatable file field (one observer key file each)
  alongside the existing `observer_anchors` JSON text, and a `tsa_roots` PEM
  text field.
- **Web (G-7):** the verify page takes one or more observer key files (such as
  Minotaur's) and a TSA roots file with the package, and has a separate form
  that verifies an audit anchor JSON. The result shows the anchor period,
  provenance figures and provenance anchoring counts. Still no JS
  dependencies.
- `tests/tsa.py`: a test RFC 3161 TSA written with `cryptography` alone, so
  in-test anchors can be timestamped without adding `asn1crypto`.

### Fixed

- The anchor chain walk treated any schema other than v2 as pre-AUD-LINK. v3
  anchors keep the back-pointer and are now walked as chained.

## 0.3.0

Sprint AG-3 (Behavry E-8 and authority evidence package 1.3), plus the AG-1
work below that was never released on its own.

### Added

- **Audit-anchor verification (E-8).** `--audit-anchor PATH` on the CLI and
  `POST /api/v1/verify-anchor` on the API verify the JSON from Behavry's
  `GET /api/v1/audit/anchors/{id}/export`. This ports
  `tools/verify_event.py --anchor` from the Behavry repo. It recomputes the
  Merkle root, event count and first/last hashes, rebuilds the canonical anchor
  bytes (v1 and v2 schemas) and checks their SHA-256 against `anchor_digest`,
  checks Behavry's Ed25519 signature and every anchored event's signature, and
  checks that the RFC 3161 token's message imprint is that digest. Repeating
  `--audit-anchor` also walks the AUD-LINK back-pointers (port of
  `--anchor-chain`) and reports `MISSING PERIOD` or `TAMPERED CHAIN`.
- **TSA signature and chain checks, which the reference verifier does not
  perform.** The token's CMS signature (RSA PKCS#1 v1.5, ECDSA, Ed25519, Ed448)
  is verified over its signed attributes under the certificate the token
  embeds, and `messageDigest` must match the TSTInfo. `--tsa-roots PEM` walks
  the TSA certificate to roots you supply: issuer signatures, CA flags,
  validity at `genTime`, and the `timeStamping` EKU. Without roots the report
  says "imprint checked, TSA certificate chain not validated". Revocation is
  never checked (no network), and the report says so.
- `behavry_verify/rfc3161.py`: a minimal DER reader for TimeStampToken and
  CMS SignedData. `cryptography` remains the only runtime dependency.
- **Authority evidence package 1.3.** Schema
  `behavry.authority_evidence_package.v1` is accepted alongside the APR schema,
  with no schema warning for either, and the loader accepts an `authority-*`
  root directory as well as `apr-*`. New checks:
  - `provenance` (12): `body_digest` over RFC 8785, `entry_hash` from
    `provenance_canonical_body`, links from genesis, the Ed25519 signature under
    the trust anchor (agent-claim form, claim type `provenance`), agent
    consistency, and `provenance_head` and `provenance_count` against the
    signed manifest. A redacted body (`null`) is bound by its digest alone and
    counted.
  - `assessments` (13): each Minotaur envelope's canonical bytes, its
    `bundle_digest` and its Ed25519 signature under a supplied observer anchor
    with a matching `kid`, `observer_id` and `observer_type`. Without the key the
    check is `SKIPPED` (not independently verified), never passed. Every
    `assessment` provenance entry must reference, through an `evidence_refs`
    item carrying `bundle_digest`, a bundle present in `assessments.json`.
  - `lifecycle` (14): informational. Lists which golden-path steps the
    provenance evidences. Reported with the new `info` status, which never
    affects the verdict, and as `lifecycle` on the JSON report.
- `behavry_verify/jcs.py`: an exact copy of Behavry's RFC 8785
  `canonical_json`, with the same error behaviour, plus `content_digest`.
- Report fields `kind` (`evidence_package` or `audit_anchor`),
  `anchor_summary` and `lifecycle`.
- Producer vectors: `tests/vectors/anchor_vectors.json`, `ag3_vectors.json` and
  `tsa_root.pem`, written by `generate_anchor_vectors.py` from Behavry's own
  anchoring, signer, `parse_timestamp_response`, provenance and RFC 8785 code.
- A CI guard that every committed `anchors/*.json` is valid, holds only public
  keys, and repeats no `kid`. `anchors/README.md` now documents how a tenant
  anchor is published and rotated.

### Fixed

- **`agent_report` and `host_journal` timeline events failed their signature
  check.** They were checked against the decision signing form. They now use
  the agent-claim and device-claim forms, as in `tools/verify_event.py`.
  Authority package timelines carry `agent_report` rows, so this matters there.

### Unchanged

- APR packages verify exactly as before. The file digest check already
  iterates the manifest's `file_digests`, so the authority package's new files
  are covered with no change.

## Sprint AG-1 E-6 (never released alone; first shipped in 0.3.0)

### Fixed

- **Rewritten event content verified as genuine (Sprint AG-1 E-6).** The
  verifier took each timeline event's `event_hash` as given and checked only
  that those hashes were signed and rolled into the Merkle root. A package
  whose events had their `action`, `target`, `policy_result` or `tool_name`
  rewritten, with hashes and signatures left alone, still reported
  `VERIFIED`. For `package_version` 1.2 packages, which export every hashed
  field, each decision event's hash is now recomputed from its own fields
  under the `hash_version` (v1 to v8) it was written with, and any mismatch
  fails the new `event_content` check, naming the events.

### Added

- `behavry_verify/hashbody.py`: byte-for-byte ports of the producer's
  decision canonical body (v1 to v8: v7 adds `args_digest`, v8 the AG-1
  tool, policy, authorization and execution fields), `governance_signals_hash`, timestamp
  normalization, `compute_event_hash`, the authorization-record and
  observation canonical bodies, and the agent-claim signing payload.
- New checks, each `SKIPPED` (never passed) where they cannot apply:
  - `file_digests` (1.2+): every data file must match the SHA-256 the signed
    manifest commits to. Hashes the raw archive bytes.
  - `event_content` (1.2+, or any package whose rows carry `hash_version`).
    Before 1.2 it is `SKIPPED` with an explicit "content is NOT bound".
  - `authorization_records` (1.2+): record hash recomputed, Ed25519 signature
    checked under the Behavry trust anchor, and each decision's
    `authorization_hash` must match the record it names.
  - `observations` (1.2+): observer signatures checked against observer keys
    the verifying party supplies. Observations whose key was not supplied are
    `SKIPPED`: "observer key not supplied — cannot verify independently".
- `--observer-anchor PATH` (repeatable) on the CLI and an `observer_anchors`
  form field on `POST /api/v1/verify` and `/api/v1/verify.txt`. The web page
  does not have an input for it yet.
- `observation_summary` on the report: observers' own match / mismatch /
  absent / unobservable verdicts, informational only.
- Golden vectors generated by the Behavry backend itself
  (`tests/vectors/producer_vectors.json`) pin the port's parity without the
  tests importing the backend.

### Unchanged

- Packages before 1.2 verify exactly as before; the new checks report
  `SKIPPED` for them. `verify_package` gains only an optional
  `observer_anchors` argument, and the loaders now return a `dict` subclass
  that also carries each member's raw bytes.

## 0.2.1

### Fixed

- **`--version` reported `0.1.0` on a 0.2.0 install.** `__version__` was
  hardcoded in `behavry_verify/__init__.py` alongside the version in
  `pyproject.toml`, and the two drifted the moment one was bumped. It now reads
  installed package metadata. The number also feeds the service's OpenAPI
  document and `/health`, so all three were wrong together.

  This matters more here than in most tools. An auditor recording which
  verifier they ran would have recorded `0.1.0` — a version never published to
  PyPI, and specifically the one without `package_version` 1.1 handling. A tool
  whose purpose is establishing provenance must not misstate its own.

  The no-install fallback says `0.0.0+unknown` rather than naming a release,
  because a literal there is the same second source of truth that caused the
  drift and would go stale at the next bump. A test now asserts `__version__`
  matches both the installed distribution and `pyproject.toml`, so a stale
  editable install cannot hide a recurrence.

## 0.2.0 — first published release

The first version of `behavry-verify` on PyPI. Earlier `0.1.0` existed only in
this repository; nothing was ever installable, so there is no upgrade path to
describe and no prior behaviour to preserve.

### Changed

- **"No chain breaks" now applies only to evidence packages before
  `package_version` 1.1.** Behavry hashes its audit chain per agent, while a
  package holds a single session — a slice of a longer chain. The events in a
  slice need not link to one another: an agent running two sessions at once
  interleaves them, and browser-based events have no agent and so carry no link
  pointer at all. Walking a slice as though it were a whole chain reported
  breaks on intact sessions, and for multi-event browser sessions it did so
  every time. Packages from 1.1 assert per-event integrity instead, a claim
  that holds for any slice, and the walk is reported `SKIPPED` for them.

  Nothing is given up. An event removed or added still moves the Merkle root,
  which the manifest signature covers. A rewritten link pointer still fails
  that event's own signature, because `previous_hash` is inside the signed
  tuple. Both are asserted by tests rather than argued in prose.

  A `package_version` this tool cannot parse is treated as older than 1.1 and
  takes the stricter path.

### Added

- Tag-driven release workflow using PyPI Trusted Publishing, with a guard that
  refuses to publish when the tag and `pyproject.toml` disagree.
