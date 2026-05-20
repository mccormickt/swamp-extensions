# @mccormick/trust-network

Inventory and report on OIDC trust policies and workload-identity federation
across [swamp](https://github.com/systeminit/swamp) — for GitHub, Google Cloud,
and Cloudflare One.

Modern identity is federated: GitHub Actions mints OIDC tokens for CI jobs,
Google Cloud trusts those tokens through Workload Identity Federation, and
Cloudflare One gates access with its own identity providers and policies. Each
platform is configured in isolation, so nobody can answer "which workloads can
assume which identities, under what conditions, and with what kind of
credential?" This extension answers that — and scores how much of the estate
still relies on long-lived secrets instead of ephemeral, conditionally-gated
federation.

## Models

- `@mccormick/trust-network/github` — discovers GitHub Actions OIDC
  subject-claim customization (org and repo level) and inventories Actions
  secrets and variables, classifying each secret name against known
  cloud-credential patterns. The fixed issuer
  `https://token.actions.githubusercontent.com` is recorded for correlation.
- `@mccormick/trust-network/gcp` — discovers Workload Identity Federation pools
  and providers (issuer URI, allowed audiences, attribute mapping, attribute
  condition), service accounts, user-managed service-account keys, and the
  `roles/iam.workloadIdentityUser` / `serviceAccountTokenCreator` bindings.
- `@mccormick/trust-network/cloudflare` — discovers Cloudflare One / Zero Trust
  Access applications and policies, configured identity providers, service
  tokens, and mTLS certificates. Access-policy rules are normalized into a set
  of conditional-access factors.
- `@mccormick/trust-network/graph` — reads the three scans and normalizes them
  into a **trust graph**: trust domains (nodes), identities, and trust edges.
  Each edge records its issuer, audience, subject pattern, claim conditions,
  credential type, whether it is ephemeral, its conditional-access factors, and
  severity-rated findings.

A method-scope report, `@mccormick/trust-network/posture`, runs after the graph
is built and produces a scorecard plus a severity-grouped finding list.

The models compose: run the three provider scans, then `graph build` correlates
them — for example matching a GCP Workload Identity provider whose issuer is
GitHub's against the GitHub repositories its attribute condition admits.

## Read-only and credential-safe

Every model only **reads** provider APIs. Nothing is created, changed, or
deleted. No credential material is ever written to swamp data — secret *values*
are not even requested (GitHub does not expose them; GCP key material is never
downloaded). Only configuration metadata is stored. API tokens are supplied
through a vault and redacted from logs and error messages.

## Prerequisites

### Vault

API tokens for GitHub and Cloudflare are read from a swamp vault:

```sh
swamp vault create local_encryption trust-network
swamp vault put trust-network GITHUB_TOKEN
swamp vault put trust-network CLOUDFLARE_TOKEN
```

### GitHub token

A fine-grained personal access token (or GitHub App installation token) with
**read-only** organization access:

- `Administration: read` — repository OIDC subject-claim customization
- `Secrets: read` and `Variables: read` — Actions secret/variable *names*
- `Environments: read` — environment-scoped secrets
- `Metadata: read` — repository enumeration

### Cloudflare token

An API token scoped to the account(s), all **Read**:

- `Access: Apps and Policies: Read`
- `Access: Organizations, Identity Providers, and Groups: Read`
- `Access: Service Tokens: Read`
- `Access: mTLS Certificates: Read`

### Google Cloud

No stored key. The `gcp` model obtains a short-lived access token from the
`gcloud` CLI (`gcloud auth print-access-token`), or from a `GCP_ACCESS_TOKEN`
environment variable if set. The authenticated principal needs read-only IAM
visibility on each project — for example `roles/iam.securityReviewer` plus
`roles/iam.workloadIdentityPoolViewer`, which together grant:

- `iam.workloadIdentityPools.list` / `.get` and the provider equivalents
- `iam.serviceAccounts.list` and `iam.serviceAccountKeys.list`
- `resourcemanager.projects.getIamPolicy`

## Quick start

Create and configure the four model instances, then run the workflow:

```sh
# Discovery models — set globalArguments on each definition.
swamp model create @mccormick/trust-network/github github-scan
#   orgs: ["acme"]
#   githubToken: ${{ vault.get("trust-network", "GITHUB_TOKEN") }}
swamp model create @mccormick/trust-network/gcp gcp-scan
#   projects: ["acme-prod", "acme-staging"]
swamp model create @mccormick/trust-network/cloudflare cf-scan
#   accountIds: ["<account-id>"]
#   cloudflareToken: ${{ vault.get("trust-network", "CLOUDFLARE_TOKEN") }}

# Aggregator — no configuration; the workflow feeds it the scan output.
swamp model create @mccormick/trust-network/graph trust-graph

# Run the whole pipeline: three scans, build the graph, emit the report.
swamp workflow run trust-inventory

# View the posture report.
swamp report get @mccormick/trust-network/posture --model trust-graph --markdown
```

Each discovery model also runs on its own — `swamp model method run github-scan
scan`, and likewise for `gcp-scan` and `cf-scan`.

### How the graph is wired

The `graph` model's `build` method takes each provider's scan output as a method
argument. The `trust-inventory` workflow supplies them with CEL
`data.findBySpec(...)` expressions, so every run re-reads the latest scans:

```yaml
# trust-inventory workflow — the `build` step's inputs
inputs:
  githubOidcSubjects: ${{ data.findBySpec("github-scan", "oidc_subject") }}
  githubSecrets:      ${{ data.findBySpec("github-scan", "actions_secret") }}
  gcpWifPools:        ${{ data.findBySpec("gcp-scan", "wif_pool") }}
  gcpWifProviders:    ${{ data.findBySpec("gcp-scan", "wif_provider") }}
  gcpServiceAccounts: ${{ data.findBySpec("gcp-scan", "service_account") }}
  gcpSaKeys:          ${{ data.findBySpec("gcp-scan", "sa_key") }}
  cfAccessApps:        ${{ data.findBySpec("cf-scan", "access_app") }}
  cfAccessPolicies:    ${{ data.findBySpec("cf-scan", "access_policy") }}
  cfIdentityProviders: ${{ data.findBySpec("cf-scan", "identity_provider") }}
  cfServiceTokens:     ${{ data.findBySpec("cf-scan", "service_token") }}
```

To build the graph outside the workflow, pass the same data with
`swamp model method run trust-graph build --input <name>:json=[...]`.

## Scheduled inventory

The `trust-inventory` workflow runs the three scans (in parallel), builds the
graph, and emits the posture report:

```sh
swamp workflow run trust-inventory
```

It carries a weekly `trigger.schedule`; run `swamp serve` to execute it
automatically. Provider scans are joined on `completed` (not `succeeded`), so a
single provider failing — an expired token, say — still yields a graph from the
providers that did succeed.

## What the posture report tells you

The report scores the trust graph on two axes and lists findings by severity:

- **Ephemeral-credential coverage** — the share of trust edges backed by
  short-lived OIDC federation rather than long-lived keys, static secrets, or
  non-expiring service tokens.
- **Conditional-access coverage** — the share of edges gated by an attribute
  condition, device posture, MFA, IP allow-list, or mTLS.

Representative findings:

| Code                             | Severity | Meaning                                                       |
| -------------------------------- | -------- | ------------------------------------------------------------- |
| `WIF_NO_ATTRIBUTE_CONDITION`     | critical | A WIF provider accepts any token from its issuer.             |
| `WIF_GITHUB_NO_ORG_PIN`          | high     | A GitHub-issued WIF provider does not pin `repository_owner`. |
| `GCP_USER_MANAGED_SA_KEY`        | high     | A long-lived user-managed service-account key exists.         |
| `GITHUB_STATIC_CLOUD_CREDENTIAL` | high     | An Actions secret is named like a static cloud credential.    |
| `CF_ACCESS_POLICY_ALLOW_ALL`     | high     | An Access policy allows everyone / has no `require` block.    |
| `CF_ACCESS_NO_POSTURE`           | medium   | An Access app's policies lack a device-posture or MFA factor. |
| `CF_SERVICE_TOKEN_NO_EXPIRY`     | medium   | A Cloudflare service token never expires or is long-lived.    |

## Known limitations

- **Heuristic claim analysis.** GCP `attributeCondition` expressions are
  recorded verbatim and checked heuristically (presence, `repository_owner`
  pin). The extension does not fully evaluate CEL conditions against concrete
  GitHub claim sets.
- **Best-effort scans.** A provider scan does not abort on one bad
  org/project/account; the failure is recorded in a `notes` array on the
  scan's summary resource and surfaced in the report.
- **Rate limits.** Large GitHub organizations generate many per-repository
  calls. Set `repos` explicitly to scope a scan to specific repositories.
- **Token lifetime.** A `gcloud` access token lasts about an hour — long
  enough for one scan. Re-run `gcloud auth login` if a scan reports an expired
  token.

## License

MIT — see [LICENSE.md](./LICENSE.md).
