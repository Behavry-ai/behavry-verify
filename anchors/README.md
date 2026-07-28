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

## Rules

- **Public keys only.** A trust anchor never contains private key material. Check before you commit.
- **Only publish with the tenant's consent.** An anchor names a customer.
- **Never delete a key to revoke it.** Removing a key does not invalidate anything already signed with it; it only breaks verification for everyone holding an older package. Set `not_after` instead.

## This is the weaker path

Verifying against an anchor published here is a convenience, not independent proof: the key comes from Behavry, so it is Behavry vouching for Behavry. Reports say so explicitly. Anyone who needs a result that stands on its own should get the anchor from the issuing tenant directly.
