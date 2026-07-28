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
✓ Signature valid              Ed25519 over the canonical manifest
✓ Signer fingerprint matches   the anchor really is this package's signer
✓ Merkle root matches          recomputed over every event hash
✓ Event count verified         the timeline holds what the manifest claims
✓ Event signatures valid       each event's own signature
✓ No chain breaks              every event links to its predecessor
✓ Producer chain flags intact  nothing was already broken at export time
```

Every check runs independently. Unlike a first-failure verifier, a broken hash chain still tells you whether the signature was good, because "signed by Behavry but missing an event" and "not signed at all" are entirely different findings.

A check that cannot meaningfully run is reported as `SKIPPED`, never as a pass. An unknown key id skips the signature check rather than failing it: a key you do not have is not evidence of tampering.

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

### API

```bash
curl -X POST https://verify.behavry.ai/api/v1/verify \
  -F package=@apr-APR-2026-001942.zip \
  -F trust_anchor=@behavry-trust-anchor.json
```

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

Two modules must match the Behavry producer byte-for-byte, or valid evidence silently stops verifying:

- `behavry_verify/canonical.py` ↔ `backend/behavry/audit/signer.py` and `backend/behavry/apr/packages.py`
- `behavry_verify/merkle.py` ↔ `backend/behavry/apr/packages.py`

`tests/conftest.py` builds packages the way the producer builds them (same manifest fields, same two-pass signing order, same JSON dump options, same ZIP layout), so drift on either side shows up as a failing test rather than as evidence that stops verifying in the field.

---

## Publishing a trust anchor

Anchors in `anchors/*.json` are served from `/trust-anchor.json`. They are committed files, not runtime state, so the set of published keys is auditable through git history. To publish one, open a PR adding the tenant's exported anchor. Never add a private key: an anchor contains public keys only.

---

## License

Source code is Apache-2.0.

The bundled fonts in `web/fonts/` are SIL OFL 1.1, and the Behavry name and logo are trademarks that the code license does not grant. If you fork this and run your own verifier, replace the branding. See [NOTICE.md](NOTICE.md).
