/**
 * `@mccormick/trust-network` — shared schema contract.
 *
 * This module is the single source of truth for every type that crosses a
 * model boundary in the extension. The three provider models
 * (`github`, `gcp`, `cloudflare`) write the **provider resource schemas**; the
 * aggregator model (`graph`) reads them and emits the **normalized trust-graph
 * schemas** (`TrustDomain`, `Identity`, `TrustEdge`, `TrustInventory`); the
 * `posture` report renders the graph. Keeping all of these in one file keeps
 * producers and consumers in lock-step.
 *
 * @module
 */
import { z } from "npm:zod@4";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Fixed OIDC issuer for GitHub Actions workload tokens. */
export const GITHUB_ACTIONS_ISSUER =
  "https://token.actions.githubusercontent.com";

/** Sentinel `sourceIssuer` for trust edges backed by a non-OIDC credential. */
export const STATIC_ISSUER = "static";

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

/**
 * FNV-1a 32-bit hash, returned as zero-padded 8-char hex. Deterministic and
 * synchronous — used to derive stable, collision-resistant ids.
 */
export function stableHash(input: string): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < input.length; i++) {
    h ^= input.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return (h >>> 0).toString(16).padStart(8, "0");
}

/**
 * Normalize an arbitrary string into a safe `writeResource` instance name:
 * lowercase, non-alphanumeric runs collapsed to `-`, trimmed. `writeResource`
 * instance names are global across specs, so callers must still prefix with a
 * spec discriminator. Long inputs are truncated with a hash suffix to keep
 * uniqueness.
 */
export function sanitizeInstanceName(raw: string): string {
  const cleaned = raw
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
  if (cleaned.length === 0) return "unnamed";
  if (cleaned.length <= 100) return cleaned;
  return `${cleaned.slice(0, 91)}-${stableHash(raw)}`;
}

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

/** Platform a trust domain belongs to. `external` covers unrecognized issuers. */
export const PlatformSchema = z.enum([
  "github",
  "gcp",
  "cloudflare",
  "external",
]);
/** {@link PlatformSchema} */
export type Platform = z.infer<typeof PlatformSchema>;

/**
 * Kind of credential backing a trust edge. `oidc-federation` is the only
 * ephemeral kind; the rest are long-lived and should be migrated away from.
 */
export const CredentialTypeSchema = z.enum([
  "oidc-federation", // short-lived OIDC token exchange
  "cf-service-token", // Cloudflare service token (client id + secret)
  "mtls-cert", // mutual-TLS client certificate
  "sa-key", // GCP user-managed service-account key
  "github-secret", // static secret stored in GitHub Actions
  "static", // any other long-lived credential
]);
/** {@link CredentialTypeSchema} */
export type CredentialType = z.infer<typeof CredentialTypeSchema>;

/** Set of credential types considered ephemeral (short-lived). */
export const EPHEMERAL_CREDENTIAL_TYPES: ReadonlySet<CredentialType> = new Set<
  CredentialType
>(["oidc-federation"]);

/** Finding severity, ordered most to least urgent. */
export const SeveritySchema = z.enum([
  "critical",
  "high",
  "medium",
  "low",
  "info",
]);
/** {@link SeveritySchema} */
export type Severity = z.infer<typeof SeveritySchema>;

// ---------------------------------------------------------------------------
// Provider resource schemas — GitHub
// ---------------------------------------------------------------------------

/** GitHub Actions OIDC subject-claim customization at org or repository scope. */
export const GithubOidcSubjectSchema = z.object({
  scope: z.enum(["org", "repository"]),
  org: z.string(),
  repository: z.string().nullable().describe("`owner/repo`; null at org scope"),
  useDefault: z.boolean().describe(
    "True when the default `sub` claim format is in effect",
  ),
  includeClaimKeys: z.array(z.string()).default([]).describe(
    "Claim keys composing the custom `sub` template",
  ),
  issuer: z.string().describe("Always the GitHub Actions issuer"),
  observedAt: z.iso.datetime(),
});
/** {@link GithubOidcSubjectSchema} */
export type GithubOidcSubject = z.infer<typeof GithubOidcSubjectSchema>;

/** A GitHub Actions secret or variable (name and metadata only — never values). */
export const GithubActionsSecretSchema = z.object({
  scope: z.enum(["org", "repository", "environment"]),
  org: z.string(),
  repository: z.string().nullable(),
  environment: z.string().nullable(),
  kind: z.enum(["secret", "variable"]),
  name: z.string(),
  looksLikeCloudCredential: z.boolean().describe(
    "Name matches a known long-lived cloud-credential pattern",
  ),
  matchedPattern: z.string().nullable().describe(
    "Identifier of the matched pattern, when any",
  ),
  createdAt: z.string().nullable(),
  updatedAt: z.string().nullable(),
  observedAt: z.iso.datetime(),
});
/** {@link GithubActionsSecretSchema} */
export type GithubActionsSecret = z.infer<typeof GithubActionsSecretSchema>;

// ---------------------------------------------------------------------------
// Provider resource schemas — Google Cloud
// ---------------------------------------------------------------------------

/** A GCP Workload Identity Pool. */
export const GcpWifPoolSchema = z.object({
  project: z.string(),
  poolId: z.string(),
  name: z.string().describe("Full resource name"),
  displayName: z.string().nullable(),
  state: z.string().nullable().describe("`ACTIVE`, `DELETED`, ..."),
  disabled: z.boolean(),
  observedAt: z.iso.datetime(),
});
/** {@link GcpWifPoolSchema} */
export type GcpWifPool = z.infer<typeof GcpWifPoolSchema>;

/**
 * A GCP Workload Identity Pool Provider — the actual federation trust config:
 * which external issuer is trusted, under which audiences and CEL condition.
 */
export const GcpWifProviderSchema = z.object({
  project: z.string(),
  poolId: z.string(),
  providerId: z.string(),
  name: z.string().describe("Full resource name"),
  displayName: z.string().nullable(),
  state: z.string().nullable(),
  disabled: z.boolean(),
  providerKind: z.enum(["oidc", "aws", "saml", "x509", "unknown"]),
  issuerUri: z.string().nullable().describe("OIDC issuer URI, when OIDC"),
  allowedAudiences: z.array(z.string()).default([]),
  awsAccountId: z.string().nullable().describe("AWS account id, when AWS"),
  attributeMapping: z.record(z.string(), z.string()).default({}),
  attributeCondition: z.string().nullable().describe(
    "CEL gate on incoming assertions; null/empty means unconditioned",
  ),
  observedAt: z.iso.datetime(),
});
/** {@link GcpWifProviderSchema} */
export type GcpWifProvider = z.infer<typeof GcpWifProviderSchema>;

/** A GCP service account, with the federated principals allowed to assume it. */
export const GcpServiceAccountSchema = z.object({
  project: z.string(),
  email: z.string(),
  uniqueId: z.string().nullable(),
  displayName: z.string().nullable(),
  disabled: z.boolean(),
  impersonators: z.array(z.object({
    member: z.string().describe("`principal://` / `principalSet://` / etc."),
    role: z.string(),
  })).default([]).describe(
    "Bindings granting workloadIdentityUser / tokenCreator on this account",
  ),
  observedAt: z.iso.datetime(),
});
/** {@link GcpServiceAccountSchema} */
export type GcpServiceAccount = z.infer<typeof GcpServiceAccountSchema>;

/** A GCP user-managed service-account key — a long-lived credential. */
export const GcpSaKeySchema = z.object({
  project: z.string(),
  serviceAccountEmail: z.string(),
  keyId: z.string(),
  name: z.string().describe("Full resource name"),
  keyType: z.string().describe("`USER_MANAGED` or `SYSTEM_MANAGED`"),
  keyOrigin: z.string().nullable(),
  validAfter: z.string().nullable(),
  validBefore: z.string().nullable(),
  disabled: z.boolean(),
  observedAt: z.iso.datetime(),
});
/** {@link GcpSaKeySchema} */
export type GcpSaKey = z.infer<typeof GcpSaKeySchema>;

// ---------------------------------------------------------------------------
// Provider resource schemas — Cloudflare One
// ---------------------------------------------------------------------------

/** A Cloudflare Access application. */
export const CfAccessAppSchema = z.object({
  accountId: z.string(),
  appId: z.string(),
  name: z.string(),
  domain: z.string().nullable(),
  type: z.string().nullable().describe("`self_hosted`, `saas`, `ssh`, ..."),
  saasAuthType: z.string().nullable().describe(
    "`oidc` / `saml` when the app is a SaaS app (Cloudflare acts as IdP)",
  ),
  allowedIdps: z.array(z.string()).default([]),
  observedAt: z.iso.datetime(),
});
/** {@link CfAccessAppSchema} */
export type CfAccessApp = z.infer<typeof CfAccessAppSchema>;

/** A Cloudflare Access policy — the conditional-access ruleset for an app. */
export const CfAccessPolicySchema = z.object({
  accountId: z.string(),
  appId: z.string().nullable(),
  policyId: z.string(),
  name: z.string(),
  decision: z.string().describe("`allow`, `deny`, `bypass`, `non_identity`"),
  includeRuleTypes: z.array(z.string()).default([]),
  requireRuleTypes: z.array(z.string()).default([]),
  excludeRuleTypes: z.array(z.string()).default([]),
  factors: z.array(z.string()).default([]).describe(
    "Normalized conditional-access factors derived from the rules",
  ),
  allowsEveryone: z.boolean().describe(
    "True when the policy admits everyone with no `require` constraint",
  ),
  observedAt: z.iso.datetime(),
});
/** {@link CfAccessPolicySchema} */
export type CfAccessPolicy = z.infer<typeof CfAccessPolicySchema>;

/** A Cloudflare Access identity provider (a trusted login method). */
export const CfIdentityProviderSchema = z.object({
  accountId: z.string(),
  idpId: z.string(),
  name: z.string(),
  type: z.string().describe("`oidc`, `github`, `google`, `azureAD`, ..."),
  issuerUri: z.string().nullable(),
  observedAt: z.iso.datetime(),
});
/** {@link CfIdentityProviderSchema} */
export type CfIdentityProvider = z.infer<typeof CfIdentityProviderSchema>;

/** A Cloudflare Access service token (a machine credential). */
export const CfServiceTokenSchema = z.object({
  accountId: z.string(),
  tokenId: z.string(),
  name: z.string(),
  clientId: z.string().nullable(),
  createdAt: z.string().nullable(),
  expiresAt: z.string().nullable(),
  durationDays: z.number().nullable().describe(
    "Lifetime in days; null when the token never expires",
  ),
  observedAt: z.iso.datetime(),
});
/** {@link CfServiceTokenSchema} */
export type CfServiceToken = z.infer<typeof CfServiceTokenSchema>;

/** A Cloudflare Access mTLS CA certificate. */
export const CfMtlsCertSchema = z.object({
  accountId: z.string(),
  certId: z.string(),
  name: z.string(),
  fingerprint: z.string().nullable(),
  expiresOn: z.string().nullable(),
  associatedHostnames: z.array(z.string()).default([]),
  observedAt: z.iso.datetime(),
});
/** {@link CfMtlsCertSchema} */
export type CfMtlsCert = z.infer<typeof CfMtlsCertSchema>;

// ---------------------------------------------------------------------------
// Scan summary — emitted once per provider scan
// ---------------------------------------------------------------------------

/**
 * Roll-up of one provider scan. `notes` records per-target partial failures so
 * a single bad org/project/account never aborts the fan-out.
 */
export const ScanSummarySchema = z.object({
  platform: PlatformSchema,
  targetsScanned: z.number().int(),
  targetsFailed: z.number().int(),
  resourceCounts: z.record(z.string(), z.number().int()).default({}),
  notes: z.array(z.string()).default([]),
  scannedAt: z.iso.datetime(),
});
/** {@link ScanSummarySchema} */
export type ScanSummary = z.infer<typeof ScanSummarySchema>;

// ---------------------------------------------------------------------------
// Normalized trust-graph schemas — emitted by the `graph` model
// ---------------------------------------------------------------------------

/** A node in the trust graph: an org, project, account, or external issuer. */
export const TrustDomainSchema = z.object({
  id: z.string().describe(
    "Stable id, e.g. `github:org/acme`, `gcp:project/p-1`, `external:host`",
  ),
  platform: PlatformSchema,
  kind: z.enum(["org", "project", "account", "idp", "external"]),
  displayName: z.string(),
  issuerUri: z.string().nullable().describe(
    "OIDC issuer when this domain acts as an identity provider",
  ),
  discoveredAt: z.iso.datetime(),
});
/** {@link TrustDomainSchema} */
export type TrustDomain = z.infer<typeof TrustDomainSchema>;

/** A severity-rated issue attached to a trust edge or the inventory. */
export const FindingSchema = z.object({
  code: z.string().describe(
    "Stable machine code, e.g. `WIF_NO_ATTRIBUTE_CONDITION`",
  ),
  severity: SeveritySchema,
  title: z.string(),
  detail: z.string(),
  recommendation: z.string(),
});
/** {@link FindingSchema} */
export type Finding = z.infer<typeof FindingSchema>;

/** Whether and how a trust edge is gated beyond mere possession of a credential. */
export const ConditionalAccessSchema = z.object({
  present: z.boolean(),
  factors: z.array(z.string()).default([]).describe(
    "e.g. `attribute-condition`, `device-posture`, `mfa`, `ip`, `mtls`",
  ),
});
/** {@link ConditionalAccessSchema} */
export type ConditionalAccess = z.infer<typeof ConditionalAccessSchema>;

/**
 * A directed trust relationship: a source domain's identities may assume a
 * target identity, gated by `claimConditions` / `conditionalAccess`, using a
 * credential of `credentialType`.
 */
export const TrustEdgeSchema = z.object({
  id: z.string().describe("Stable hash of source, target, issuer, credential"),
  sourceDomainId: z.string(),
  sourceLabel: z.string().describe("Human-readable source identity"),
  sourceIssuer: z.string().describe(
    "OIDC issuer of the trusted party, or `static` for non-OIDC credentials",
  ),
  targetDomainId: z.string(),
  targetLabel: z.string().describe("Human-readable target identity"),
  audience: z.array(z.string()).default([]),
  subjectPattern: z.string().nullable().describe(
    "`sub` template / `principalSet` / policy decision criteria",
  ),
  claimConditions: z.string().nullable().describe(
    "Attribute condition or normalized policy summary; null = unconditioned",
  ),
  credentialType: CredentialTypeSchema,
  ephemeral: z.boolean().describe("Derived from `credentialType`"),
  conditionalAccess: ConditionalAccessSchema,
  permissions: z.array(z.string()).default([]),
  findings: z.array(FindingSchema).default([]),
  discoveredAt: z.iso.datetime(),
});
/** {@link TrustEdgeSchema} */
export type TrustEdge = z.infer<typeof TrustEdgeSchema>;

/** Graph-wide roll-up and scorecard, emitted once per `graph build`. */
export const TrustInventorySchema = z.object({
  domainCount: z.number().int(),
  edgeCount: z.number().int(),
  byCredentialType: z.record(z.string(), z.number().int()).default({}),
  byPlatform: z.record(z.string(), z.number().int()).default({}),
  ephemeralEdgeCount: z.number().int(),
  ephemeralPct: z.number().describe("Percentage, 0-100"),
  conditionalAccessEdgeCount: z.number().int(),
  conditionalAccessPct: z.number().describe("Percentage, 0-100"),
  findingsBySeverity: z.record(z.string(), z.number().int()).default({}),
  notes: z.array(z.string()).default([]).describe(
    "Cross-provider correlation warnings (missing scans, unknown issuers)",
  ),
  builtAt: z.iso.datetime(),
});
/** {@link TrustInventorySchema} */
export type TrustInventory = z.infer<typeof TrustInventorySchema>;

/**
 * Derive the stable id of a trust edge from its defining attributes. Two edges
 * with the same source, target, issuer, and credential type collapse to one.
 */
export function trustEdgeId(parts: {
  sourceDomainId: string;
  sourceLabel: string;
  targetLabel: string;
  sourceIssuer: string;
  credentialType: CredentialType;
}): string {
  return `edge-${
    stableHash(
      [
        parts.sourceDomainId,
        parts.sourceLabel,
        parts.targetLabel,
        parts.sourceIssuer,
        parts.credentialType,
      ].join("|"),
    )
  }`;
}
