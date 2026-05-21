/**
 * `@mccormick/cloudflare` — Cloudflare One / Zero Trust Access resource schemas.
 *
 * The `zerotrust` model writes these resources; downstream consumers (such as
 * `@mccormick/trust-network`) read them by spec name. The `Cf*` field shapes
 * are a **cross-extension data contract** — keep them stable.
 *
 * @module
 */
import { z } from "npm:zod@4";

/**
 * FNV-1a 32-bit hash, returned as zero-padded 8-char hex. Deterministic and
 * synchronous — used to derive stable, collision-resistant ids.
 */
function stableHash(input: string): string {
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
// Access resource schemas
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
// Scan summary — emitted once per scan
// ---------------------------------------------------------------------------

/**
 * Roll-up of one Cloudflare One scan. `notes` records per-target partial
 * failures so a single bad account never aborts the fan-out.
 */
export const ScanSummarySchema = z.object({
  platform: z.literal("cloudflare"),
  targetsScanned: z.number().int(),
  targetsFailed: z.number().int(),
  resourceCounts: z.record(z.string(), z.number().int()).default({}),
  notes: z.array(z.string()).default([]),
  scannedAt: z.iso.datetime(),
});
/** {@link ScanSummarySchema} */
export type ScanSummary = z.infer<typeof ScanSummarySchema>;
