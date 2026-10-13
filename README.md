# behavry-verify

**Independently verify a Behavry evidence package.** No Behavry account, no tenant access, no database, no network.

This is the code behind [verify.behavry.ai](https://verify.behavry.ai), plus the offline CLI that does the same job on an air-gapped machine.

A Behavry *APR evidence package* is the sealed export of a single Agent Provenance Record: what an AI agent did, in order, with each step hash-linked and signed. This repo answers one question about such a package, and answers it without asking you to trust the answer:

> Is this package exactly what Behavry signed, or has something been changed, removed, or reordered?

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

Go to [verify.behavry.ai](https://verify.behavry.ai), drop in the `.zip`, optionally add the trust anchor.

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

### API

```bash
curl -X POST https://verify.behavry.ai/api/v1/verify \
  -F package=@apr-APR-2026-001942.zip \
  -F trust_anchor=@behavry-trust-anchor.json \
  -F observer_anchors=@observer-anchors.json   # optional
```

The web page does not yet have an observer-anchor input; use the CLI or the API for observations.

A package that fails verification still returns `200` with `"verified": false`: you asked a question and got a definitive answer. `4xx` means the input was malformed, not that the evidence was bad.

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

Three modules must match the Behavry producer byte-for-byte, or valid evidence silently stops verifying:

- `behavry_verify/canonical.py` ↔ `backend/behavry/audit/signer.py` and `backend/behavry/apr/packages.py`
- `behavry_verify/merkle.py` ↔ `backend/behavry/apr/packages.py`
- `behavry_verify/hashbody.py` ↔ `backend/behavry/audit/service.py` (decision body v1 to v8), `backend/behavry/audit/evidence.py` (authorization and observation bodies), `backend/behavry/core/security.py` and `backend/behavry/audit/signer.py`

`hashbody.py` is pinned by golden vectors: `tests/vectors/producer_vectors.json` is written by the Behavry backend's own functions (`tests/vectors/generate_vectors.py`, run from a Behavry checkout), and `tests/test_vectors.py` asserts this repo's port reproduces every byte. The tests never import the backend. When the producer adds a hash version, regenerate the vectors and add the branch here in the same change.

`tests/conftest.py` builds packages the way the producer builds them (same manifest fields, same two-pass signing order, same JSON dump options, same ZIP layout), so drift on either side shows up as a failing test rather than as evidence that stops verifying in the field.

---

## Publishing a trust anchor

Anchors in `anchors/*.json` are served from `/trust-anchor.json`. They are committed files, not runtime state, so the set of published keys is auditable through git history. To publish one, open a PR adding the tenant's exported anchor. Never add a private key: an anchor contains public keys only.

---

## License

Source code is Apache-2.0.

The bundled fonts in `web/fonts/` are SIL OFL 1.1, and the Behavry name and logo are trademarks that the code license does not grant. If you fork this and run your own verifier, replace the branding. See [NOTICE.md](NOTICE.md).
