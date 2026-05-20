/**
 * `@mccormick/trust-network` — Cloudflare One response-parsing helpers.
 *
 * Pure functions shared by the `cloudflare` model and its tests: Access-policy
 * rule normalization and service-token duration math.
 *
 * @module
 */
import { type CfAccessPolicy } from "./schema.ts";

/** Access-policy rule type → normalized conditional-access factor. */
const RULE_FACTOR: Readonly<Record<string, string>> = {
  device_posture: "device-posture",
  auth_method: "mfa",
  mfa: "mfa",
  geo: "geo",
  ip: "ip",
  ip_list: "ip",
  certificate: "mtls",
  common_name: "mtls",
  common_names: "mtls",
  service_token: "service-token",
  any_valid_service_token: "service-token",
  group: "idp-group",
  azure_ad: "idp-group",
  github_organization: "idp-group",
  gsuite: "idp-group",
  okta: "idp-group",
  saml: "idp-group",
  login_method: "idp",
  oidc: "idp",
  email: "email",
  email_list: "email",
  email_domain: "email-domain",
  everyone: "everyone",
};

/** The rule type of an Access-policy rule (its single object key). */
export function ruleType(rule: Record<string, unknown>): string {
  const keys = Object.keys(rule ?? {});
  return keys.length > 0 ? keys[0] : "unknown";
}

/** Raw Access policy as returned by the Cloudflare API. */
export interface RawAccessPolicy {
  /** Policy id. */
  id: string;
  /** Human-readable policy name. */
  name?: string;
  /** `allow`, `deny`, `bypass`, or `non_identity`. */
  decision?: string;
  /** `include` rules — at least one must match. */
  include?: Record<string, unknown>[];
  /** `require` rules — all must match. */
  require?: Record<string, unknown>[];
  /** `exclude` rules — none may match. */
  exclude?: Record<string, unknown>[];
}

/**
 * Normalize a raw Access policy: collapse the `include` / `require` / `exclude`
 * rule sets into rule-type lists, derive the set of conditional-access factors,
 * and decide whether the policy effectively admits everyone.
 *
 * `allowsEveryone` is true when an `everyone` include rule is present with no
 * `require` rule constraining it.
 */
export function normalizeAccessPolicy(
  raw: RawAccessPolicy,
  accountId: string,
  appId: string | null,
): CfAccessPolicy {
  const include = (raw.include ?? []).map(ruleType);
  const require = (raw.require ?? []).map(ruleType);
  const exclude = (raw.exclude ?? []).map(ruleType);

  const factors = new Set<string>();
  for (const type of [...include, ...require]) {
    const factor = RULE_FACTOR[type] ?? type;
    if (factor !== "everyone") factors.add(factor);
  }
  const allowsEveryone = include.includes("everyone") && require.length === 0;

  return {
    accountId,
    appId,
    policyId: raw.id,
    name: raw.name ?? "",
    decision: raw.decision ?? "allow",
    includeRuleTypes: include,
    requireRuleTypes: require,
    excludeRuleTypes: exclude,
    factors: [...factors].sort(),
    allowsEveryone,
    observedAt: new Date().toISOString(),
  };
}

/**
 * Days between a service token's creation and expiry. Returns null when the
 * token has no expiry (never expires) or the timestamps cannot be parsed.
 */
export function computeDurationDays(
  createdAt: string | null,
  expiresAt: string | null,
): number | null {
  if (!expiresAt) return null;
  const expiry = Date.parse(expiresAt);
  if (!Number.isFinite(expiry)) return null;
  const created = createdAt ? Date.parse(createdAt) : Date.now();
  const start = Number.isFinite(created) ? created : Date.now();
  return Math.round((expiry - start) / 86_400_000);
}
