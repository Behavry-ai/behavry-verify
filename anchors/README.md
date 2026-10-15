# Published trust anchors

Each `*.json` file here is a trust anchor a Behavry tenant has chosen to publish. They are aggregated and served at `/trust-anchor.json`, which is the URL every evidence package carries in its `verification_metadata.trust_anchor_url`.

These are **committed files, not runtime state**, so the set of published keys is auditable through git history. Adding a key requires a reviewed pull request.

## What goes here

The exact JSON a tenant admin exports from `GET /api/v1/admin/apr-trust-anchor`:

```json
{
  "schema": "behavry.trust_anchor.v1",
  "keys": [
    {
      "kid": "behavry-ed25519-2026-01",
      "algorithm": "ed25519",
      "public_key": "<base64 32-byte raw Ed25519 point>",
      "not_before": "2026-01-01T00:00:00+00:00",
      "not_after": null
    }
  ]
}
```

Name the file after the tenant (`acme-corp.json`). A `kid` may appear only once across all files; the first one committed wins.

One anchor covers everything the tenant signs: APR evidence packages, authority evidence packages, and audit anchors are all signed under the same tenant key set, so a tenant publishes once.

## How a tenant anchor gets published

1. A tenant admin exports the anchor from the dashboard (Admin, then Trust anchor), or with `GET /api/v1/admin/apr-trust-anchor`, and sends it to Behavry with written consent to publish it.
2. Check the file before committing it. It must parse, every key must be a 32-byte Ed25519 public key, no `kid` may already appear in another file here, and it must hold no private material. `tests/test_registry.py::test_committed_anchors_are_valid_and_public` enforces all four in CI.
3. Verify a real package from that tenant against the file, so a wrong anchor is caught before it is served:

   ```bash
   behavry-verify --package <their package>.zip --trust-anchor anchors/<tenant>.json
   ```

4. Open a pull request adding `anchors/<tenant>.json`. Once it merges and deploys, `/trust-anchor.json` serves the key and the web API will use it for submissions that arrive without an anchor. Reports label that result as the weaker, published-registry path.

To rotate, the tenant exports again after rotating. Replace the file with the new export, which still contains the old key with its `not_after` set, so packages signed before the rotation keep verifying.

The registry ships empty. No key is published until a tenant asks for it, and no placeholder or example key is ever committed here, because a committed key would be served as real.

## Rules

- **Public keys only.** A trust anchor never contains private key material. Check before you commit.
- **Only publish with the tenant's consent.** An anchor names a customer.
- **Never delete a key to revoke it.** Removing a key does not invalidate anything already signed with it; it only breaks verification for everyone holding an older package. Set `not_after` instead.

## This is the weaker path

Verifying against an anchor published here is a convenience, not independent proof: the key comes from Behavry, so it is Behavry vouching for Behavry. Reports say so explicitly. Anyone who needs a result that stands on its own should get the anchor from the issuing tenant directly.
