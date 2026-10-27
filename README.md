# behavry-verify

**Independently verify a Behavry evidence package.** No Behavry account, no tenant access, no database, no network.

This is the code behind [verify.behavry.ai](https://verify.behavry.ai), plus the offline CLI that does the same job on an air-gapped machine.

It verifies three kinds of Behavry evidence:

- an **APR evidence package**: the sealed export of a single Agent Provenance Record, meaning what an AI agent did in one session, in order, with each step hash-linked and signed;
- an **authority evidence package** (package 1.3 to 1.5): one agent's whole authority history. It covers what it was assessed for, which independent assessment verified it, what was applied, what an observer saw, what was revoked, and how it was revalidated. From 1.4 it also carries the audit anchors that timestamped that history, and from 1.5 the whole unbroken run of them, so none can be withheld unnoticed;
- an **audit anchor**: a tenant's audit trail for one period, sealed under a Merkle root and timestamped by an RFC 3161 authority whose key Behavry does not hold.

For each, it answers one question without asking you to trust the answer:

> Is this exactly what Behavry signed, or has something been changed, removed, or reordered?

---

## Why this is a separate repo

Verification has to be believable to someone who does not trust Behavry: a regulator, an external auditor, a cyber-insurance assessor, an opposing party in litigation. That means the verifier must be readable, small, dependency-light, and separable from the product it checks.

The offline CLI depends on exactly one third-party package, `cryptography`. You can read the whole verification core in about twenty minutes.

---

## The trust model, stated plainly

Verification is only as good as the key it checks against. There are three ways to get one, and they are **not** equally strong. Every report says which one it used.

| Path | Strength | What it proves |
|---|---|---|
| **You supply the tenant's trust anchor** | Strongest | The package was signed by the key the tenant gave you, out-of-band. Behavry is not in the loop. |
| **You supply a raw public key** | Strongest | Same, with the key pinned directly. |
| **The published registry** (`/trust-anchor.json`) | Convenience only | The package is internally consistent and signed by the named key, but the key came from Behavry. Behavry vouching for Behavry. |

If a result matters, get the trust anchor from the issuing tenant directly. Their admin exports it from the Behavry dashboard (`GET /api/v1/admin/apr-trust-anchor`), and it is a small JSON file they can send you once and you can pin forever.

> **Note:** an evidence package does *not* contain the public key needed to verify it. It carries only a truncated fingerprint (`public_key_hint`) so you can confirm you are holding the right anchor. The anchor itself must come from the tenant or from the registry.

---

## What gets checked

```
✓ Signature valid               Ed25519 over the canonical manifest
✓ Signer fingerprint matches    the anchor really is this package's signer
✓ Merkle root matches           recomputed over every event hash
✓ Event count verified          the timeline holds what the manifest claims
✓ Event signatures valid        each event's own signature
✓ No chain breaks               every event links to its predecessor (1.0 only)
✓ Producer chain flags intact   nothing was already broken at export time
✓ File digests match            every data file matches the signed manifest (1.2+)
✓ Event content matches hashes  each event_hash recomputed from its fields (1.2+)
✓ Authorization records valid   pre-forward authorizations: hash, signature, binding (1.2+)
✓ Observer signatures valid     independent observations, against keys you supply (1.2+)
✓ Provenance chain valid        the agent's provenance, linked from genesis (authority 1.3)
✓ Assessment bundles valid      Minotaur's signed assessments, against its key (authority 1.3)
i Authority lifecycle           which golden-path steps the history evidences (informational)
✓ Provenance anchored           each provenance entry is in a timestamped audit anchor (authority 1.4+)
✓ Witness                       each anchor was logged promptly to a public append-only log (authority 1.7)
```

Every check runs independently. Unlike a first-failure verifier, a broken hash chain still tells you whether the signature was good, because "signed by Behavry but missing an event" and "not signed at all" are entirely different findings.

A check that cannot meaningfully run is reported as `SKIPPED`, never as a pass. An unknown key id skips the signature check rather than failing it: a key you do not have is not evidence of tampering.

### Content binding (package_version 1.2)

Signatures prove that the holder of a key vouched for a *hash*. On their own they say nothing about whether the action, target, policy result or tool shown next to that hash is what was hashed. Before 1.2 a package carried only the hashes, so a package whose events had been rewritten still verified.

From `package_version` **1.2** the package exports every field each decision's hash covers, and this verifier **recomputes** each `event_hash` from content instead of taking it as given:

| Check | What it proves | Fails when |
|---|---|---|
| `file_digests` | Every data file (`timeline.json`, `authorization_records.json`, `observations.json`, ...) is byte-identical to what the signed manifest committed to | a listed file is missing or its SHA-256 differs |
| `event_content` | Each decision event's `event_hash` reproduces from its own fields, under the `hash_version` (v1 to v8) it was written with | any field covered by the hash was changed; the report names the events. A 1.2 row stripped of its hashed fields also fails |
| `authorization_records` | Each pre-forward authorization record's `record_hash` reproduces from its fields, its Ed25519 signature verifies under the same trust anchor as the events, and each decision's `authorization_hash` matches the record it names | a record was edited, signed by another key, missing, or re-pointed |
| `observations` | Each independent observation was signed by the observer key you supplied, over a body that binds the decision event's hash | a signature is bad, or the observation points at a decision not in the timeline |

Non-decision claims (`exposure`, `disclosure_ack`, `agent_report`, `host_journal`) are not content-recomputed; the report says so, and their hashes stay covered by the Merkle root, their signatures and the file digests.

For packages **before 1.2**, `event_content` and `file_digests` are reported `SKIPPED` with an explicit statement that content is **not** bound: only the signed hashes were verified. Read a pre-1.2 `VERIFIED` accordingly.

### Observer anchors

An *observation* is a record, signed by something other than Behavry (an EDR, a cloud log, an agent-side hook), of what it saw happen for a given decision. It is only as independent as the key it is checked against, so that key must come from the observer or whoever operates it, never from the package and never from Behavry:

```json
{"kid": "minotaur-key-1", "public_key_hex": "<64 hex chars>", "observer_id": "minotaur-01", "observer_type": "minotaur"}
```

A file may hold one such object or a list. Supply them with `--observer-anchor PATH` (repeatable) on the CLI, or as the `observer_anchors` form field (JSON text) on the API. An observation whose key you did not supply is reported `SKIPPED` ("observer key not supplied — cannot verify independently"), never as a pass.

The report also prints the observers' own verdicts (`match`, `mismatch`, `absent`, `unobservable`) as an informational line. Those are claims made by the observers, not part of the pass/fail verdict.

### Authority evidence packages (package 1.3)

`GET /api/v1/agents/{id}/authority/package` returns a ZIP rooted at `authority-<agent_id>/` with schema `behavry.authority_evidence_package.v1`. It is built with the same helpers as an APR package, so every check above applies unchanged to its timeline, authorization records and observations. The manifest's `file_digests` cover `provenance.json`, `assessments.json`, `mismatches.json` and `authority.json` too, and the file digest check covers whatever the signed manifest lists. Three checks are added:

| Check | What it proves | Fails when |
|---|---|---|
| `provenance` | Every provenance entry's `body_digest` is the SHA-256 of the RFC 8785 form of its body, its `entry_hash` reproduces from its fields and its predecessor, the chain links from genesis, each entry is signed by the Behavry key (claim type `provenance`), and the last entry and the count match the signed manifest's `provenance_head` and `provenance_count` | an entry was edited, removed, inserted, reordered or moved from another agent's chain, or the tail was cut off |
| `assessments` | Each assessment bundle reproduces its `bundle_digest` and carries a valid Ed25519 signature under the Minotaur key **you** supply (matching `kid`, `observer_id` and `observer_type`), and every `assessment` provenance entry references a bundle the package carries | a bundle field was edited, the key does not match, or an assessment the history relies on is missing |
| `lifecycle` | Informational. Lists which golden-path steps the provenance evidences: authority mapped, assessed, verified or failed, applied, mismatch detected, revoked, autonomy demoted, revalidation requested, and re-assessed and re-applied | never fails |

A bundle whose Minotaur key you did not supply is reported `SKIPPED`, meaning not independently verified, and never as a pass. A provenance entry whose body was redacted (`body` null) still verifies through `body_digest`, and the report says how many were.

### Provenance anchored (package 1.4)

Checks 12 to 14 rest on Behavry's key. A party holding that key can rewrite a provenance entry, re-chain everything after it and re-sign the manifest, and those checks still pass. Package 1.4 closes that gap with `anchors.json`: every v3 audit anchor (below) whose period holds one of the package's provenance entries. Each anchor commits to the period's provenance `entry_hash`es under a Merkle root, inside bytes a third-party TSA timestamped when the period was sealed. A later rewrite produces a hash that anchor does not hold.

Check 15, `provenance_anchoring`, verifies each anchor exactly as `--audit-anchor` would (digest, Behavry signature, RFC 3161 imprint and TSA signature, the chain to `--tsa-roots` if you supply them, and the provenance root recomputed from its records), checks the manifest's `anchor_count` and that each anchor is for the package's tenant, and then classifies every provenance entry:

| Class | Meaning | Verdict |
|---|---|---|
| `anchored` | its `entry_hash` is in an anchor whose checks all pass; the report gives that anchor's TSA `genTime` (or "no TSA") | passes |
| `not_yet_anchored` | its timestamp is at or after the latest anchor's `period_end`: the period is not sealed yet | passes, reported |
| `missing` | its timestamp is inside an included v3 anchor's period, but its hash is not in that anchor: it was added or altered after sealing | **fails** |
| `unanchored` | no anchor in the package covers its time, or only a v1/v2 anchor does (those predate provenance anchoring) | passes; a `warn` when no anchor covers an entry inside the sealed span, since an anchor may have been withheld |
| `anchor_unverified` | its hash is in an anchor whose own checks did not pass | the anchor's failure fails the check |

Packages older than 1.4 skip check 15 and say why. The JSON report carries the detail as `provenance_anchoring`:

```json
{
  "anchor_count": 2,
  "anchored": 8, "not_yet_anchored": 3, "missing": 0, "unanchored": 0, "anchor_unverified": 0,
  "anchors": [{"anchor_id": "...", "schema": "behavry.audit_anchor.v3",
               "period_start": "...", "period_end": "...", "anchor_digest": "...",
               "provenance_count": 5, "verified": true, "failed_checks": [],
               "signature": "pass", "tsa_gen_time": "...", "tsa_chain": "pass"}],
  "entries": [{"id": "...", "entry_hash": "...", "timestamp": "...", "status": "anchored",
               "anchor_id": "...", "tsa_gen_time": "...", "reason": null}]
}
```

### A withheld anchor fails (package 1.5)

In 1.4 an anchor the producer left out was only a warning: the included anchors need not be contiguous, so their AUD-LINK back-pointers cannot say whether one is missing. Package 1.5 (Behavry Sprint AG-5) closes that. `anchors.json` holds every v3 anchor of the tenant over the package's span, in order and with no gaps, from the anchor that holds the first provenance entry to the first one that starts after the last. Each is a provenance-only record (`"records": "provenance"`, no `events`) whose `provenance` covers the whole tenant for that period, so its root still reproduces. The signed manifest states `anchor_count` and `anchor_head_digest`, the digest of the last anchor.

Check 15 then adds, for 1.5:

- per anchor, the event Merkle root, event count, boundary hashes and event signatures are **skipped** with the reason "event records are not carried; the package's own events are covered by its Merkle root and signatures". They are never reported as passed. The event fields are still inside the signed bytes, so the digest and signature checks still cover them;
- across the run, each anchor's `previous_anchor_digest` must equal the previous anchor's `anchor_digest`. A break **fails**: "anchor chain broken between <period_end> and <period_start>: an anchor is missing". The first anchor's predecessor lies outside the span and is not checked;
- `anchor_count` and `anchor_head_digest` must match the run, and every anchor in it must be v3;
- with the chain unbroken, an entry inside the span but in no anchor's period is `missing` and **fails**: that period held nothing when it was sealed, so the entry was written later and backdated. An entry before the first anchor's period is `unanchored` (it predates v3) and an entry at or after the last anchor's `period_end` is `not_yet_anchored`. Neither fails.

A 1.5 package with an empty `anchors.json` (`anchor_head_digest` null) passes, with every entry not yet anchored. 1.4 packages keep the AG-4 behaviour, warning included. A 1.5 report adds these keys to `provenance_anchoring`:

```json
{
  "package_version": "1.5",
  "anchor_head_digest": "...",
  "chain_unbroken": true,
  "chain_breaks": [{"after_anchor_id": "...", "before_anchor_id": "...",
                    "period_end": "...", "period_start": "..."}],
  "anchors": [{"...": "as in 1.4", "records": "provenance",
               "previous_anchor_digest": "...", "event_checks": "skipped", "linked": true}]
}
```

`linked` is null for the first anchor. One limit remains: a party holding Behavry's key can drop the newest anchors and re-sign a manifest whose head matches what is left. The entries after it then read as not yet anchored. Package 1.6 and anchor heads, below, close that.

Provenance entry types this verifier does not know, such as `device_bound`, are informational: they are hashed, chained and anchored like any other entry, and they neither add to nor take from the lifecycle line.

### The run reaches both ends (package 1.6 and anchor heads)

Package 1.5 proves nothing is missing inside the run, not that the run starts and ends where it should. Behavry Sprint AG-6 closes both ends.

**The front: the predecessor (package 1.6).** `anchors.json` becomes `{"anchors": [...], "predecessor": ...}`. The predecessor is the tenant's anchor just before the run, of any schema, as a **header-only record** (`"records": "header"`, no `events` and no `provenance`). The signed manifest states its digest as `anchor_predecessor_digest`. Check 15 then requires:

- **P1.** When the first anchor's `previous_anchor_digest` is set, the predecessor must be present, its digest must equal that pointer and the manifest's `anchor_predecessor_digest`, and it must verify as a header-only record under the same trust anchor and for the same tenant. When the run is empty or starts the chain, the predecessor and the manifest field must both be null. Anything else **fails**.
- **P2.** When the predecessor is v3, provenance anchoring had already begun, so an entry older than the run is `missing` and **fails**: the anchors sealing it were left out. When it is v1 or v2, or there is none, those entries are `unanchored` (they predate v3), as in 1.5.

**The tail: anchor heads (any package from 1.4).** The newest anchors can only be shown to be missing by something obtained outside the package. Ask the tenant for its newest sealed anchor, `GET /api/v1/audit/anchors/head` (or any anchor, `GET /api/v1/audit/anchors/{id}/header`), and pass it with `--anchor-head`, which may repeat:

- **H1.** Each head must verify, as a header-only or a full record, and be for the package's tenant. A head that does not is reported, is not used, and **fails** the check: a supplied head that does not verify is a finding.
- **H2.** A verified head whose period overlaps an anchor in the package, or its predecessor, with a different digest is a **fork**, and fails (H2a). Two verified heads that overlap each other with different digests are a fork too (H2b). Periods are half-open: a head overlaps an anchor when `head.period_start < anchor.period_end` and `anchor.period_start < head.period_end`, so a head that starts where an anchor ends is not a fork. A head equal to a run anchor (same digest) is consistent. Each fork names the two anchors and their periods, and the head's row carries `failed_checks: ["fork"]`. Since 0.7.0 (Behavry Sprint AG-7); 0.6.0 caught only an equal `period_start`.
- **H3.** Every entry older than a verified head's `period_end` must be `anchored`. One that would read `not_yet_anchored` becomes `missing`, "sealed by anchor <head id> (<period>), which the package does not carry", and the check **fails**. When the head was sealed after the package was created, the finding adds that the package may simply predate the head, and to export a fresh one.
- **H4.** With no head, the check passes or fails on the 1.5 rules, and the report says "no independent anchor head supplied: truncation of the newest anchors cannot be ruled out".

A head file may be a `.json` record (header-only or full) or a gzipped `.json.gz` record, exactly as Behavry's WORM bucket stores `tenant/<id>/anchor/<period>.json.gz` and `tenant/<id>/head/<period>.json.gz`. The form is told apart by its content (the gzip magic number), not its file name, on the CLI, the API and the web page alike.

A head covers only what was sealed when you obtained it. For the strongest statement, take a fresh head at verification time, or read the newest object in the tenant's WORM bucket yourself. Better still, keep every head as it is sealed: `behavry-verify collect-heads` (below) builds that collection, and `--anchor-heads-dir` passes all of it at once. A package that contradicts any head you already hold then fails, even if the tenant's feed later stops showing that head. A 1.6 report, or any report given a head, adds these keys to `provenance_anchoring` (`predecessor` is 1.6 only, and is null when the run starts the chain):

```json
{
  "heads": [{"anchor_id": "...", "period_start": "...", "period_end": "...",
             "anchor_digest": "...", "verified": true, "tsa_gen_time": "...",
             "failed_checks": []}],
  "head_note": null,
  "forks": [{"against": "run", "head_index": 0, "head_anchor_id": "...",
             "head_period_start": "...", "head_period_end": "...",
             "head_anchor_digest": "...", "anchor_id": "...",
             "anchor_period_start": "...", "anchor_period_end": "...",
             "anchor_digest": "..."}],
  "predecessor": {"anchor_id": "...", "schema": "behavry.audit_anchor.v3",
                  "anchor_digest": "...", "verified": true, "period_start": "...",
                  "period_end": "...", "failed_checks": []}
}
```

With `--anchor-heads-dir`, the report also carries `head_gaps` (empty when every folder links; see "Gaps between held heads" below):

```json
{
  "head_gaps": [{"folder": "heads", "earlier_anchor_id": "...",
                 "earlier_period_start": "...", "earlier_period_end": "...",
                 "earlier_anchor_digest": "...", "later_anchor_id": "...",
                 "later_period_start": "...", "later_period_end": "...",
                 "later_previous_anchor_digest": "...", "names_held_anchor_id": null}]
}
```

`head_note` holds the H4 text when no head was supplied, and is null otherwise. `forks` is present when a head was supplied, empty when there is none. `against` is `"run"`, `"predecessor"` or `"head"`; for a fork between two heads, `head_index` is the later head, `other_head_index` the earlier one, and the `anchor_*` fields describe the earlier head. A 1.4 or 1.5 report with no head keeps its earlier shape exactly.

#### Gaps between held heads (0.9.0)

Every v2 and v3 anchor signs `previous_anchor_digest`, the digest of the tenant's anchor before it. So a folder of heads, in `period_start` order, must link: each v2 or v3 head's `previous_anchor_digest` must be the `anchor_digest` of the held head before it. One that names any other digest is a **gap**: the feed withheld at least one head between the two, or the folder is missing one. `--anchor-heads-dir` checks each folder's verified heads, and a gap fails check 15 (a folder of heads that does not link cannot vouch for completeness); `collect-heads` checks the whole folder after every run.

- The first held head starts a segment, whatever it points at: the tenant's chain began before your collection did.
- A v1 head (its schema signs no `previous_anchor_digest`), and a head whose `previous_anchor_digest` is null or empty, start a new segment and are never gaps.
- The same record held twice (one `anchor_digest`, say as `.json` and `.json.gz`) counts once.
- Two heads for one `period_start` with different digests are a fork, which H2b (and `collect-heads`, as a conflict) already reports. They count as one position: the next head links when it names either of them, and the position links when either of them links back. A fork is therefore not reported a second time as a gap, while a head withheld before it still is.
- Under check 15, only verified heads count: one that does not verify is already a finding and cannot bridge a gap.
- Each folder is checked on its own. Heads given as separate `--anchor-head` files are not checked for gaps: they are usually a sparse sample, such as a head taken at verification time.
- A feed that withholds the newest heads is not a gap, since nothing after them links back. A fresh head obtained later, or one read from the WORM bucket, closes that.

### Witnessed in a public log (package 1.7)

Every check above rests on evidence that Behavry or the tenant produced or kept. A party holding the signing key could re-sign a different anchor, get it timestamped, and plant it. A **witness receipt** adds a party neither controls: a public append-only transparency log (Sigstore's Rekor v1). When a tenant opts in, Behavry submits each anchor to the log as it is sealed, and the anchor record carries the log's receipt as `witness`. The receipt proves that the anchor was logged to that public log, and when: the log's signed `integratedTime` must fall shortly after the period ended. A forgery made later is either absent from the log or logged later, and fails.

The log entry reveals only a SHA-256 hash, a signature and the public key that made it, never the anchor's bytes. Behavry signs a DSSE envelope whose payload is the anchor's hex `anchor_digest`, under the type `application/vnd.behavry.anchor-digest.v1`, with the anchor's own key.

Check 16 verifies each receipt offline against the log keys you supply with `--witness-trust`, either Sigstore's `trusted_root.json` or one PEM public key (ECDSA P-256 or Ed25519):

- **W1 Inclusion.** The entry is in the log: its RFC 6962 inclusion proof reaches the tree root, and the log's signed checkpoint commits to that root and tree size.
- **W2 Binding.** The entry is this anchor's: it is a `dsse` entry for SHA-256 of the anchor's digest, its verifier key is the key that signed the anchor, and the envelope in the receipt is the one logged and verifies over its DSSE PAE.
- **W3 Prompt.** The log's SignedEntryTimestamp verifies, and the anchor was logged no earlier than 300 s before its period ended and no later than `--witness-window` seconds after (default 7200, two hours).
- **W4 Required.** A package 1.7 manifest states `witness_since`, when the tenant began witnessing. Every anchor in `anchors.json`, and the predecessor, whose period starts at or after it must carry a receipt that passes W1 to W3. A key holder controls the manifest, so an auditor who knows the tenant opted in should pass `--require-witness`: every anchor, the predecessor and every supplied head must then carry one, whatever the manifest says.

A receipt is checked whenever a record carries one, in any package version, on `--anchor-head` and `--anchor-heads-dir` heads, and in `--audit-anchor` mode. Without `--witness-trust`, the check reports "witness not checked: no log trust root supplied", which fails only under `--require-witness`. A package 1.6 or older whose records carry no receipt reports exactly as before.

The report's `witness` key holds one row per record:

```json
{
  "witness": {
    "trust": {"source": "trusted_root", "logs": [{"log_id": "...", "algorithm": "ecdsa-p256-sha256",
              "base_url": "https://rekor.sigstore.dev", "valid_from": "...", "valid_until": null}]},
    "trust_note": null, "required": false, "window_seconds": 7200, "witness_since": "...",
    "verified": 5, "failed": 0, "not_checked": 0, "missing": 0, "absent": 0,
    "records": [{"role": "anchor", "index": 0, "anchor_id": "...", "period_start": "...",
                 "period_end": "...", "anchor_digest": "...", "required": true,
                 "status": "verified", "log_index": 123, "integrated_time": 1761500000,
                 "integrated_at": "...", "log_id": "...", "entry_id": "...",
                 "failed_checks": [], "findings": []}]
  }
}
```

`role` is `anchor`, `predecessor` or `head`. `status` is `verified`, `failed`, `not_checked` (no trust root), `missing` (required, none carried) or `absent` (none carried, none required). `failed_checks` names the W checks that failed, and `findings` says why. What remains open: completeness against the log (searching the log for every entry under Behavry's key) is a later sprint, and until per-tenant signing keys exist an entry is linkable to the Behavry deployment, not to the tenant.

### Passing Minotaur's key

Minotaur publishes its observer public key as a small JSON file. One key signs both its observations and its assessment bundles:

```json
{"kid": "minotaur-lab-01-2026-10", "public_key_hex": "<64 hex>", "observer_id": "minotaur-lab-01", "observer_type": "minotaur"}
```

Get it from whoever operates the Minotaur lab, not from the package and not from Behavry, and pass it like any observer anchor:

```bash
behavry-verify --package authority-agent-123.zip --trust-anchor behavry-trust-anchor.json \
               --observer-anchor minotaur-observer-key.json
```

### Audit anchors (RFC 3161)

An evidence package proves that the holder of a key vouched for a record. That claim comes from a party that also owns the clock. An audit anchor adds the missing piece: Behavry seals each period of a tenant's audit trail under a Merkle root, signs it, and has a third-party Time Stamp Authority timestamp the digest. The input is the JSON from `GET /api/v1/audit/anchors/{id}/export`, which is byte-for-byte what the WORM copy holds.

```
✓ Merkle root matches                      recomputed over the period's event hashes
✓ Event count verified                     every record in the period is present
✓ First and last event hashes match
✓ Anchor digest matches                    SHA-256 of the canonical anchor bytes
✓ Anchor signature valid                   Behavry's Ed25519 signature over those bytes
✓ Event signatures valid                   each anchored event's own signature
✓ RFC 3161 token covers the anchor digest  the token's message imprint, genTime, serial
✓ TSA signature valid                      the TSA's CMS signature over the token
✓ TSA certificate chain valid              to TSA roots you supply (--tsa-roots)
```

A `behavry.audit_anchor.v3` anchor (Behavry Sprint AG-4) also commits to the period's agent provenance: `provenance_count`, `provenance_root` and the first and last `entry_hash` are inside the signed and timestamped bytes, and the export carries hash-only provenance records (never a summary or body). For v3 four more checks run: the provenance root recomputed from those records, the count, the first and last hashes, and each record's own Behavry signature. The report shows the provenance figures. v1 and v2 anchors verify exactly as before.

A provenance-only v3 record (`"records": "provenance"`, as a package 1.5 carries) is accepted too. Its events are not carried, so the four event checks are reported **skipped**, with the reason, and never as passed.

A header-only record of any schema (`"records": "header"`, what `/api/v1/audit/anchors/head` and `/api/v1/audit/anchors/{id}/header` return) carries no records at all. Its digest, Behavry signature and RFC 3161 token are checked, and the event and provenance record checks are reported **skipped** with the reason "header-only record: the signed bytes are verified, the records they commit to are not carried", never as passed.

`openssl ts -verify` alone cannot replace the first five checks. It validates a token against a digest you give it, and it cannot tell you that the digest is the one these events produce. That link is the claim.

Be precise about the TSA. Without `--tsa-roots` the report says **"imprint checked, TSA certificate chain not validated"**: the token's signature was checked against the certificate it embeds, but nothing ties that certificate to an authority you trust. With `--tsa-roots` the chain is walked to your roots. Each issuer's signature, CA flag and validity at `genTime` are checked, and the TSA certificate must carry the `timeStamping` key usage. **Revocation (CRL or OCSP) is never checked**, because this tool makes no network calls. An anchor with no token (no TSA configured, or a TSA outage) still verifies, and the report states that no third party attests to the time. A token with no TSA signature at all is flagged as a warning, because anyone could have produced it. An anchor that carries no Behavry signature is reported NOT VERIFIED, because it is unproven who sealed it.

Given two or more anchors for one tenant, the AUD-LINK back-pointers are also walked. A `MISSING PERIOD` means an anchor commits to a predecessor that is not in the set. A `TAMPERED CHAIN` means a pointer names the wrong anchor, or was stripped.

### Trust assumptions that remain

- **Behavry still holds the event-signing key.** Recomputing hashes proves a package is internally consistent and that its content is what was hashed and signed. It cannot prove the key holder did not write a false record in the first place and sign it. The trust anchor you pin decides whose key that is; the RFC 3161 anchoring in the Behavry product is what bounds *when*.
- **Observations are only as independent as the observer key you supply.** An observer key handed to you by the same party that produced the package adds nothing. Obtain observer keys from the observer's operator.
- `hook` observers run alongside the agent and are cooperative with it, so they are weaker evidence than an EDR or a target-side log.

### "No chain breaks" and package_version

Behavry hashes its audit chain **per agent**, while an evidence package holds a **single session**. A session is therefore a slice of a longer chain, and its events need not link to each other: when an agent runs two sessions at once, the chains interleave, and browser-based events have no agent at all and so carry no link pointer.

Packages at `package_version` **1.0** claimed contiguity within the package, and this check enforced it. From **1.1** the producer states per-event integrity instead — a claim that holds for any slice — and the walk is reported `SKIPPED` as not applicable.

Nothing is given up. What the walk was reaching for is covered by checks that do not depend on ordering, for every version:

- **an event removed or added** moves the Merkle root, which the manifest signature covers;
- **a link pointer rewritten** breaks that event's own signature, because `previous_hash` is inside the signed tuple.

A `package_version` this tool cannot parse is treated as older than 1.1, so it takes the stricter path. A verifier should never relax a check because it failed to understand its input.

---

## Use it

### Web

Go to [verify.behavry.ai](https://verify.behavry.ai), drop in the `.zip`, and optionally add the trust anchor, one or more observer key files (such as Minotaur's), your TSA roots and one or more anchor heads. A separate form on the same page verifies an audit anchor JSON. The web page and API take no log trust root yet: witness receipts are checked by the CLI.

**Nothing you submit is stored, logged, or forwarded.** The package is verified in memory and discarded. It is someone's audit trail from a regulated environment; the only defensible retention policy is none.

### CLI (offline / air-gapped)

```bash
pipx install behavry-verify
```

```bash
behavry-verify --package apr-APR-2026-001942.zip --trust-anchor behavry-trust-anchor.json
```

Exit codes: `0` verified, `1` not verified, `2` unusable input, so it drops straight into CI.

```bash
behavry-verify --package apr.zip --trust-anchor anchor.json --json
```

```bash
behavry-verify --package apr.zip --trust-anchor anchor.json \
               --observer-anchor edr-observer.json --observer-anchor cloudtrail-observer.json
```

Authority package, with Minotaur's key (and, for a 1.4 package, your TSA roots for its anchors):

```bash
behavry-verify --package authority-agent-123.zip --trust-anchor anchor.json \
               --observer-anchor minotaur-observer-key.json --tsa-roots your-tsa-roots.pem
```

Authority package with the tenant's anchor head, obtained from Behavry separately (`GET /api/v1/audit/anchors/head`), so a run cut short at its newest anchors fails. `--anchor-head` may repeat:

```bash
behavry-verify --package authority-agent-123.zip --trust-anchor anchor.json \
               --observer-anchor minotaur-observer-key.json --anchor-head anchor-head.json

behavry-verify --package authority-agent-123.zip --trust-anchor anchor.json \
               --observer-anchor minotaur-observer-key.json \
               --anchor-head 20261015T111100Z.json.gz   # straight from the WORM bucket
```

A directory of heads, such as one kept by `collect-heads` (below): every `*.json` and `*.json.gz` file directly in it (not in subdirectories) is passed as an `--anchor-head`, and the folder's heads must link (a gap fails check 15; see "Gaps between held heads"). It may repeat, and combines with `--anchor-head`. This reads files only: package verification never touches the network.

```bash
behavry-verify --package authority-agent-123.zip --trust-anchor anchor.json \
               --observer-anchor minotaur-observer-key.json --anchor-heads-dir heads/
```

Authority package 1.7 with its witness receipts checked against the public log's key. Get `trusted_root.json` from Sigstore (for example from the `sigstore/root-signing` repository, or `cosign trusted-root create`), or pass the PEM public key of a private Rekor instance:

```bash
behavry-verify --package authority-agent-123.zip --trust-anchor anchor.json \
               --witness-trust trusted_root.json --require-witness

behavry-verify --package authority-agent-123.zip --trust-anchor anchor.json \
               --witness-trust private-rekor.pem --witness-window 3600
```

Audit anchor, optionally with your TSA roots. Repeat `--audit-anchor` to also walk a set for missing periods:

```bash
behavry-verify --audit-anchor behavry-anchor.json --trust-anchor anchor.json \
               --tsa-roots your-tsa-roots.pem

behavry-verify --audit-anchor 2026-09-07T12.json --audit-anchor 2026-09-07T13.json \
               --trust-anchor anchor.json --json
```

### Collecting heads (the one networked command)

`collect-heads` keeps your own copy of a tenant's anchor heads. It pages the tenant's heads feed, `GET /api/v1/audit/anchors/heads?since=&limit=1000`, until a page comes back empty, and saves each head into a directory you then pass to `--anchor-heads-dir`. Run it on a schedule: each run resumes after the newest head already in the directory, read from `period_start` inside the files rather than their names, unless you pass `--since`.

```bash
export BEHAVRY_TOKEN=...        # never on the command line
behavry-verify collect-heads --base-url https://behavry.example.com --out heads/ \
               --trust-anchor behavry-trust-anchor.json
```

```
behavry-verify collect-heads --base-url URL --out DIR [--token-env NAME]
                             [--since ISO] [--trust-anchor FILE] [--tsa-roots PEM]
```

- Each head is saved as `DIR/<YYYYmmddTHHMMSSZ of period_start, UTC>-<first 8 characters of anchor_id>.json`. `DIR` is created if it does not exist.
- The bearer token is read from the environment variable named by `--token-env` (default `BEHAVRY_TOKEN`). It is never accepted as an argument and never printed. Redirects are refused, so the token is only sent to `--base-url`, and plain `http://` is accepted only for a loopback host. The usual `HTTPS_PROXY`, `NO_PROXY`, `SSL_CERT_FILE` and `SSL_CERT_DIR` settings apply.
- With `--trust-anchor`, each head is verified before it is saved (digest, Behavry signature, RFC 3161 token, and the TSA chain if you add `--tsa-roots`), exactly as check 15 verifies a head. One that does not verify is not saved and is reported. Without `--trust-anchor`, heads are saved unchecked; `--anchor-heads-dir` still verifies each of them later.
- A stored file is never overwritten. If the file for a head already exists and holds a different `anchor_digest` (or none), or a stored head has the same `period_start` and a different `anchor_digest`, that is a **conflict**: two records for one period. It is reported and the new head is not saved. A stored file with the same `anchor_digest` counts as already present, even if fields outside the signed bytes (such as `anchor_id` or `sealed_at`) or its formatting differ; `--anchor-heads-dir` verifies its signed content when you use it.
- After collecting, the chain is checked across every head in `DIR`, not only those fetched by this run (see "Gaps between held heads"). Each gap is reported naming both heads, by `anchor_id` and period. A fresh `DIR` started with `--since` starts its own segment; a `--since` that skips past heads `DIR` already holds the next ones for is a gap.
- Exit codes: `0` when every head collected verified or was not checked and the heads in `DIR` link, `1` on any conflict, unverified head or gap, `2` on a usage, network or HTTP error.

A feed that withholds a head between two you collect is caught as a gap. One that withholds the newest heads is not, since nothing after them links back yet; it cannot, though, make a package verify that contradicts a head you already collected.

### API

```bash
curl -X POST https://verify.behavry.ai/api/v1/verify \
  -F package=@apr-APR-2026-001942.zip \
  -F trust_anchor=@behavry-trust-anchor.json \
  -F observer_anchor=@minotaur-observer-key.json \  # optional, repeatable file
  -F observer_anchor=@edr-observer.json \
  -F tsa_roots=@your-tsa-roots.pem \                # optional, for 1.4 anchors
  -F anchor_head=@anchor-head.json                  # optional, repeatable file
```

`anchor_head` is a file field too, and may repeat, like `--anchor-head`. It takes the same `.json` and `.json.gz` forms; the server decompresses a gzipped one. `POST /api/v1/verify.txt` takes it as well. There is no directory field: to send a collected directory, repeat `anchor_head` once per file (for example `for f in heads/*.json; do args+=(-F "anchor_head=@$f"); done`). The service never fetches heads itself.

`observer_anchor` is a file field and may repeat, one observer key file each, like `--observer-anchor`. The older `observer_anchors` field (JSON text of one anchor or a list) still works, and both are combined.

A package that fails verification still returns `200` with `"verified": false`: you asked a question and got a definitive answer. `4xx` means the input was malformed, not that the evidence was bad.

```bash
curl -X POST https://verify.behavry.ai/api/v1/verify-anchor \
  -F audit_anchor=@behavry-anchor.json \
  -F trust_anchor=@behavry-trust-anchor.json \
  -F tsa_roots=@your-tsa-roots.pem   # optional
```

`POST /api/v1/verify.txt` returns the plain-text report and uses the status code as the verdict (`200` / `422`), which is handier in a shell pipeline.

---

## Develop

```bash
python3.12 -m venv .venv && ./.venv/bin/pip install -e ".[service,dev]"
```

```bash
./.venv/bin/pytest
```

```bash
./.venv/bin/uvicorn behavry_verify.app:app --reload
```

### The compatibility surface

These modules must match the Behavry producer byte-for-byte, or valid evidence silently stops verifying:

- `behavry_verify/canonical.py` ↔ `backend/behavry/audit/signer.py` and `backend/behavry/apr/packages.py`
- `behavry_verify/merkle.py` ↔ `backend/behavry/apr/packages.py`
- `behavry_verify/hashbody.py` ↔ `backend/behavry/audit/service.py` (decision body v1 to v8), `backend/behavry/audit/evidence.py` (authorization and observation bodies), `backend/behavry/core/security.py` and `backend/behavry/audit/signer.py`
- `behavry_verify/jcs.py` ↔ `backend/behavry/audit/args_digest.py` (RFC 8785, copied exactly, including its error behaviour)
- `behavry_verify/authority.py` ↔ `backend/behavry/authority/provenance.py` and the assessment bundle form in Behavry's `docs/strategy/AG3-CONTRACTS.md` §1.2
- `behavry_verify/audit_anchor.py` ↔ `backend/behavry/audit/anchoring.py` and `tools/verify_event.py --anchor` / `--anchor-chain`; the v3 form follows Behavry's `docs/strategy/AG4-CONTRACTS.md` §1 and §2
- `behavry_verify/witness.py` ↔ Rekor v1.5.5 (`pkg/types/dsse/v0.0.1/entry.go`, `pkg/api/entries.go`, `pkg/verify/verify.go`, `pkg/util/signed_note.go`, `pkg/util/checkpoint.go`) and Behavry's `docs/strategy/AG10-CONTRACTS.md` §1, §3 and §4; `tests/rekor_fixture.py` is a fixture log that builds receipts in those byte formats, and is never presented as Rekor
- check 15 in `behavry_verify/authority.py` ↔ `backend/behavry/authority/package.py` (package 1.4) and AG4-CONTRACTS §3 and §4; for package 1.5, AG5-CONTRACTS §1 to §3

`behavry_verify/rfc3161.py` is a small DER reader for RFC 3161 tokens. `cryptography` has no TSP or CMS parser, and adding `asn1crypto` would double what an auditor has to install.

The AG-3 forms are pinned the same way: `tests/vectors/anchor_vectors.json`, `ag3_vectors.json` and `tsa_root.pem` are written by `tests/vectors/generate_anchor_vectors.py` from Behavry's own anchoring, signer, RFC 3161 parser, provenance and RFC 8785 code. The test TSA's tokens are genuine CMS SignedData that `openssl ts -verify` accepts against `tsa_root.pem`.

`hashbody.py` is pinned by golden vectors: `tests/vectors/producer_vectors.json` is written by the Behavry backend's own functions (`tests/vectors/generate_vectors.py`, run from a Behavry checkout), and `tests/test_vectors.py` asserts this repo's port reproduces every byte. The tests never import the backend. When the producer adds a hash version, regenerate the vectors and add the branch here in the same change.

The AG-4 v3 anchors, 1.4 packages and AG-5 1.5 packages are built in-test by `tests/conftest.py` from the contract, signed with test keys and timestamped by `tests/tsa.py`, a test TSA written with `cryptography` alone (the E-8 vectors' TSA key was discarded, so it cannot stamp new digests). Once Behavry's producer ships, add v3 vectors to `generate_anchor_vectors.py` so the byte form is pinned to Behavry's own output as v1 and v2 are.

`tests/conftest.py` builds packages the way the producer builds them (same manifest fields, same two-pass signing order, same JSON dump options, same ZIP layout), so drift on either side shows up as a failing test rather than as evidence that stops verifying in the field.

---

## Publishing a trust anchor

Anchors in `anchors/*.json` are served from `/trust-anchor.json`. The web API also uses them to pick a key for a package or audit anchor that arrives without one, matched by `signer_kid`, and it labels that result as the weaker path. They are committed files, not runtime state, so the set of published keys is auditable through git history. The registry is empty until a tenant consents. To publish one, open a PR adding the tenant's exported anchor, following [anchors/README.md](anchors/README.md). Never add a private key: an anchor contains public keys only.

---

## License

Source code is Apache-2.0.

The bundled fonts in `web/fonts/` are SIL OFL 1.1, and the Behavry name and logo are trademarks that the code license does not grant. If you fork this and run your own verifier, replace the branding. See [NOTICE.md](NOTICE.md).
