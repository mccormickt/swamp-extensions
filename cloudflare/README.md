# @mccormick/cloudflare

Cloudflare One / Zero Trust Access discovery for
[swamp](https://github.com/systeminit/swamp).

Cloudflare One is both a relying party and an identity provider: Access
applications are gated by Access policies, configured identity providers are
the logins Cloudflare trusts, service tokens are machine credentials, and mTLS
certificates anchor certificate-based access. This extension inventories that
configuration so it can be audited, scored, or fed into a wider trust graph.

## Model

`@mccormick/cloudflare/zerotrust` — discovers, per Cloudflare account:

- **Access applications** — self-hosted, SaaS, and SSH apps, with their
  allowed identity providers.
- **Access policies** — the `include` / `require` / `exclude` rule sets,
  normalized into a set of conditional-access factors (`mfa`, `device-posture`,
  `mtls`, `ip`, …) and flagged when a policy effectively admits everyone.
- **Identity providers** — the configured OIDC / SAML / social logins.
- **Service tokens** — machine credentials, with their lifetime in days.
- **mTLS certificates** — CA certificates and their associated hostnames.

The `scan` method fans out across every configured account. A per-account or
per-app failure is recorded in the scan summary's `notes` and never aborts the
run, so one bad account still yields a full inventory of the rest.

Transport is the official [`cloudflare`](https://www.npmjs.com/package/cloudflare)
TypeScript SDK — authentication, retry/backoff, and pagination are handled by
the SDK.

## Read-only and credential-safe

The model only **reads** the Cloudflare API. Nothing is created, changed, or
deleted. No credential material is written to swamp data — secret *values* are
never requested, only configuration metadata. The API token is supplied through
a vault and redacted from logs and error messages.

## Prerequisites

### Vault

The Cloudflare API token is read from a swamp vault:

```sh
swamp vault create local_encryption cloudflare
swamp vault put cloudflare CLOUDFLARE_TOKEN
```

### Cloudflare token

An API token scoped to the account(s), all **Read**:

- `Access: Apps and Policies: Read`
- `Access: Organizations, Identity Providers, and Groups: Read`
- `Access: Service Tokens: Read`
- `Access: mTLS Certificates: Read`

## Quick start

```sh
# Install the extension.
swamp extension pull @mccormick/cloudflare

# Create a model instance — set globalArguments on the definition.
swamp model create @mccormick/cloudflare/zerotrust cf-scan
#   accountIds: ["<account-id>"]
#   cloudflareToken: ${{ vault.get("cloudflare", "CLOUDFLARE_TOKEN") }}

# Run the scan.
swamp model method run cf-scan scan
```

The scan writes one resource per discovered object — `access_app`,
`access_policy`, `identity_provider`, `service_token`, `mtls_cert` — plus a
single `access_summary` roll-up. Inspect them with `swamp data list --model
cf-scan` or wire them into a workflow with `data.findBySpec("cf-scan",
"access_app")`.

## Consuming the data

Each resource is a typed swamp data artifact. A downstream model or workflow
can read the scan output by spec name — for example, the
`@mccormick/trust-network` extension consumes `access_app`, `access_policy`,
`identity_provider`, and `service_token` to build a cross-platform trust graph.

## Known limitations

- **Account-scoped.** The scan covers Access configuration under the accounts
  listed in `accountIds`; it does not enumerate accounts for you.
- **Best-effort.** A failure on one account or one application's policies is
  recorded in `access_summary.notes` and does not abort the scan.

## License

MIT — see [LICENSE.md](./LICENSE.md).
