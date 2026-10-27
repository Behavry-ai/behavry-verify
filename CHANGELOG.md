# Changelog

## 0.11.0

Sprint AG-11, following Behavry's `docs/strategy/AG11-CONTRACTS.md` sections
2, 3 and 4: per-tenant signing keys, rotation and key history.

### Added

- **Trust anchor v2** (`behavry.trust_anchor.v2`) as `--trust-anchor`. Every
  key's window is rebuilt from the anchor's key statements
  (`behavry.key_statement.v1`), never taken from the listed values, and every
  statement's signatures are checked: a `succession` by both the predecessor
  and the successor, a `compromise` by the successor and the anchor's
  `deployment_kid`. An anchor whose statements do not all verify is refused.
  The deployment key's `not_before` is null.
- **`--key-history FILE`**, with a pinned v1 `--trust-anchor`: a later v2
  document, treated as untrusted. A key in it is used only if a chain of
  verifying statements reaches it from a pinned key; a compromise statement
  is anchored on the deployment key, which must be in the pinned anchor.
  Unreachable keys are reported and never used. The web API takes the same
  input as the `key_history` form field.
- **Validity windows**, whenever the keys come from a v2 history: a signature
  by a key over a record dated outside the key's window fails. The date is the
  signed timestamp: event `timestamp`, audit anchor `sealed_at`, provenance
  entry and authorization record `timestamp`, package manifest `created_at`.
  A record dated at or after the key's `compromised_since` is reported as
  "untrusted (key compromised)", distinct from a bad signature. A manifest or
  anchor signature outside its window is a failed `signature` check, not a
  skipped one.
- **Check 16 (witness)** resolves the anchor's signer key through the same
  history, so W2 binds a receipt only to a key that was valid when the anchor
  was sealed.
- The JSON report gains `key_history` (only in the `v2` and `v1+history` trust
  modes): `trust_mode`, each key with its recomputed window, status and
  source, the statements and whether each verified, `unreachable_keys`,
  `notes`, `window_failures` and `untrusted_signatures`. The text report adds
  matching lines.
- The published registry serves a v2 anchor file whole for any of its kids,
  so its windows apply, and leaves its keys out of `/trust-anchor.json`.

### Rules the contract left open, as implemented

- A statement takes effect only when its predecessor is already trusted and
  not yet succeeded, so the history is a single chain: a second successor of
  the same key, or a statement that would reopen a closed window, fails.
- A successor kid of the tenant form (`t-<8 hex>-ed25519-<16 hex>`) must carry
  the statement's tenant and the first 16 hex characters of SHA-256 of its
  public key. A compromise statement cannot revoke the deployment key.
- A key in a v2 anchor that no statement introduces (other than the
  deployment key) is reported as unreachable and not used.
- Windows are half open: a key is valid from `not_before` inclusive to
  `not_after` exclusive, and untrusted from `compromised_since` inclusive.

### Unchanged

- A v1 anchor on its own (`behavry.trust_anchor.v1` or
  `behavry.apr_trust_anchor.v1`) behaves exactly as in 0.10.0: the kid must
  match, no window is enforced, and the report has no `key_history`.
- ECDSA P-256 and KMS-held keys are AG-12.

## 0.10.0

Sprint AG-10, following Behavry's `docs/strategy/AG10-CONTRACTS.md` sections
1, 3 and 4. Byte formats are those of Rekor v1.5.5.

### Added

- **Check 16, Witness.** An anchor record may carry `witness`: a receipt
  showing that a DSSE envelope over its `anchor_digest`, signed by the
  anchor's own key, was logged to a Rekor v1 transparency log. Each receipt is
  checked offline:
  - **W1 Inclusion.** The leaf's RFC 6962 inclusion proof reaches
    `root_hash`, and a checkpoint (a signed note) line with the trusted log
    key's hint verifies, for the same tree size and root.
  - **W2 Binding.** The leaf is a canonical `dsse` 0.0.1 entry whose
    `payloadHash` is SHA-256 of the anchor's digest, whose one verifier is the
    anchor's signer key, and whose `envelopeHash` is SHA-256 of the stored
    envelope; the envelope's signature verifies over its DSSE PAE.
  - **W3 Prompt.** The SignedEntryTimestamp verifies, and the anchor was
    logged between 300 s before and `--witness-window` seconds (default 7200)
    after its period ended. An anchor logged later fails: a forgery made after
    the fact is logged after the fact.
  - **W4 Required.** In a package 1.7, every anchor in `anchors.json` and the
    predecessor whose `period_start` is at or after the manifest's
    `witness_since` must carry a receipt that passes. With
    `--require-witness`, every anchor, the predecessor and every supplied head
    must, whatever the manifest says.
- **`--witness-trust FILE`**: Sigstore's `trusted_root.json` (its `tlogs`) or
  one PEM public key, ECDSA P-256 or Ed25519. The log is picked by the
  receipt's `log_id`, the hex SHA-256 of the key's DER. A `validFor` window in
  the trusted root is enforced at the receipt's `integrated_time`.
- **`--require-witness`** and **`--witness-window SECONDS`**.
- **`--audit-anchor`** checks a record's receipt too, when it carries one or
  under `--require-witness`.
- The JSON report gains `witness` (present only when check 16 ran): the trust
  root, counts, and one row per record with `role`, `log_index`,
  `integrated_time`, `status` (`verified`, `failed`, `not_checked`,
  `missing` or `absent`), `failed_checks` (W ids) and `findings`. The text
  report adds a `Witness` line per receipt.

### Unchanged

- Without `--witness-trust`, receipts are reported as "witness not checked:
  no log trust root supplied". That fails only under `--require-witness`; a
  required receipt that is missing still fails, since its absence needs no
  key to see.
- Packages 1.6 and older whose records carry no `witness` report exactly as
  before, with or without `--witness-trust`. A record that carries one is
  checked whatever the package version.
- The web page and `POST /api/v1/verify` take no log trust root yet, so a 1.7
  package verified there reports its receipts as not checked.

## 0.9.0

Sprint AG-9 (item M-4), following Behavry's `docs/strategy/AG9-CONTRACTS.md`
sections 5 and 6.

### Added

- **Gaps between held heads.** Every v2 and v3 anchor signs
  `previous_anchor_digest`, so the heads an auditor holds, in `period_start`
  order, must link. A v2 or v3 head whose `previous_anchor_digest` is not the
  `anchor_digest` of the held head before it is a gap: at least one head
  between them was withheld or is missing. The first held head, any v1 head
  and any head with a null or empty `previous_anchor_digest` start a segment
  and are not gaps. The same record held twice counts once. Two heads for one
  `period_start` with different digests (a fork, already reported) count as
  one position, so a fork is not reported again as a gap.
- **`collect-heads`** checks the chain across every head in `--out` after
  collecting, names both heads of each gap (`anchor_id` and period), and exits
  1 on any gap. Other exit codes are unchanged.
- **`--anchor-heads-dir`** checks each folder's verified heads the same way.
  A gap is a finding on check 15 that fails the package, and is a row in the
  new `provenance_anchoring.head_gaps` list (present whenever a folder was
  given, empty when every folder links). The text report adds a `Head gap`
  line per gap.

### Unchanged

- Heads given as separate `--anchor-head` files, and through the web upload
  and `POST /api/v1/verify`, are not checked for gaps: they are usually a
  sparse sample. Only a folder must link.
- A head that does not verify still fails the check on its own, and is not
  used to bridge a gap.
- A feed that withholds the newest heads is still not detectable from the
  heads alone (AG9-CONTRACTS section 6).

### Changed

- `find_head_gaps` and `describe_head_gap` are new in
  `behavry_verify.audit_anchor`; `verify_package` takes `anchor_head_dirs`
  (folder name and its records), and check 15 takes `head_folders`.

## 0.8.0

Sprint AG-8 (item L-2), following Behavry's `docs/strategy/AG8-CONTRACTS.md`
section 3.

### Added

- **`behavry-verify collect-heads --base-url URL --out DIR [--token-env NAME]
  [--since ISO] [--trust-anchor FILE] [--tsa-roots PEM]`.** Pages the tenant's
  heads feed, `GET /api/v1/audit/anchors/heads?since=&limit=1000`, until a page
  is empty, and saves each head as
  `DIR/<YYYYmmddTHHMMSSZ of period_start>-<anchor_id[:8]>.json`. It resumes
  after the newest head already in `DIR`, by the `period_start` inside the
  files, unless `--since` is given. The bearer token is read from the
  environment variable named by `--token-env` (default `BEHAVRY_TOKEN`), never
  from the command line, and is never printed. With `--trust-anchor`, each
  head is verified (digest, signature, TSA, and the TSA chain with
  `--tsa-roots`) before it is saved; one that does not verify is not saved
  and is reported. A stored file is never overwritten: one with another
  `anchor_digest`, or a stored head for the same `period_start` with another
  `anchor_digest`, is reported as a conflict. A stored file with the same
  `anchor_digest` is already present, even when fields outside the signed
  bytes (such as `anchor_id`) differ. Exit codes: 0 ok, 1 on any
  conflict or unverified head, 2 on a usage, network or HTTP error. It uses
  the standard library's `urllib` (proxy and CA settings from the
  environment), so the CLI still depends on `cryptography` alone; it refuses
  redirects, and accepts plain `http://` for a loopback host only.
- **`--anchor-heads-dir DIR`**, repeatable, for `--package`: every `*.json` and
  `*.json.gz` file directly in `DIR`, in name order, is loaded as an
  `--anchor-head` and combined with any `--anchor-head`. Package verification
  stays offline; only `collect-heads` uses the network.

### Unchanged

- Every existing invocation parses as before: `collect-heads` is recognized
  only as the first argument.
- The web upload and `POST /api/v1/verify` gain nothing: the repeatable
  `anchor_head` field already takes any number of head files, and the service
  never fetches heads on a caller's behalf.

### Fixed

- **`--audit-anchor` reads WORM objects as stored.** A gzipped
  `anchor/<period>.json.gz` or `head/<period>.json.gz` object used to stop
  the CLI with a traceback; it now verifies as-is, detected by the gzip magic
  number as `--anchor-head` already was. The web upload
  (`POST /api/v1/verify-anchor`) accepts the same forms, and a file that is
  neither JSON nor gzipped JSON is a usage error (exit 2, HTTP 400).

## 0.7.0

Sprint AG-7 (item K-4), following Behavry's `docs/strategy/AG7-CONTRACTS.md`
sections 3 and 4.

### Changed

- **H2 in its overlap form.** A verified head whose period overlaps a run
  anchor or the predecessor (`head.period_start < anchor.period_end` and
  `anchor.period_start < head.period_end`), with a different digest, is a
  fork and fails check 15 (H2a). This still includes the AG-6 equal-start
  case, and now also catches a key holder re-sealing a shifted period, signed
  and TSA-stamped. Two verified heads that overlap each other with different
  digests fail too (H2b). Periods are half-open, so touching at a boundary is
  not a fork, and a head equal to a run anchor stays consistent.

### Added

- `provenance_anchoring.forks`, present whenever a head is supplied: one row
  per fork, with `against` (`run`, `predecessor` or `head`), `head_index`,
  the head's id, period and digest, and the contradicted anchor's id, period
  and digest (`other_head_index` for a fork between two heads). The head's
  row gains `failed_checks: ["fork"]`, and the text and web reports name the
  anchor each forked head contradicts.
- **Gzipped head files.** `--anchor-head`, the `anchor_head` API field and the
  web upload accept a `.json` record (header-only or full) or a gzipped
  `.json.gz` record, exactly as Behavry's WORM bucket stores anchor and head
  objects. The form is detected by the gzip magic number, not the file name,
  and the server decompresses uploads (capped at 64 MiB inflated).

### Unchanged

- A report with no head keeps its 0.6.0 shape: `forks` is not added.

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
