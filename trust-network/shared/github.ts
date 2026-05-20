/**
 * `@mccormick/trust-network` — GitHub response-parsing helpers.
 *
 * Pure functions shared by the `github` model and its tests: a cloud-credential
 * name classifier and the OIDC subject-claim normalizer.
 *
 * @module
 */
import { GITHUB_ACTIONS_ISSUER, type GithubOidcSubject } from "./schema.ts";

/** Result of classifying a secret or variable name. */
export interface SecretClassification {
  /** True when the name matches a known long-lived cloud-credential pattern. */
  looksLikeCloudCredential: boolean;
  /** Identifier of the matched pattern, or null when nothing matched. */
  matchedPattern: string | null;
}

/**
 * High-signal name patterns for long-lived cloud credentials. Deliberately
 * narrow — `AWS_REGION` and other config names must not match.
 */
const CLOUD_CREDENTIAL_PATTERNS: ReadonlyArray<{ id: string; re: RegExp }> = [
  {
    id: "aws-key",
    re: /AWS_?(ACCESS_KEY_ID|SECRET_ACCESS_KEY|SESSION_TOKEN)/i,
  },
  { id: "aws-key", re: /AWS.*(ACCESS_KEY|SECRET_KEY|SECRET_ACCESS)/i },
  {
    id: "gcp-key",
    re:
      /(GCP|GOOGLE|GCLOUD).*(SA_KEY|SERVICE_ACCOUNT|CREDENTIALS|APPLICATION_CREDENTIALS|_KEY|_JSON)/i,
  },
  {
    id: "azure-credential",
    re: /AZURE.*(CLIENT_SECRET|CREDENTIALS?|PASSWORD)/i,
  },
  { id: "service-account-key", re: /SERVICE_ACCOUNT.*(KEY|JSON|CREDENTIAL)/i },
  { id: "private-key", re: /PRIVATE_KEY/i },
];

/**
 * Classify a secret or variable name against known cloud-credential patterns.
 * A match means the name looks like a static, long-lived cloud credential —
 * a candidate for replacement by OIDC federation.
 */
export function classifySecretName(name: string): SecretClassification {
  for (const { id, re } of CLOUD_CREDENTIAL_PATTERNS) {
    if (re.test(name)) {
      return { looksLikeCloudCredential: true, matchedPattern: id };
    }
  }
  return { looksLikeCloudCredential: false, matchedPattern: null };
}

/** Raw shape of a GitHub OIDC subject-claim customization response. */
export interface OidcSubjectBody {
  /** Whether the default `sub` claim format is in effect (repository scope). */
  use_default?: boolean;
  /** Claim keys composing the custom `sub` template. */
  include_claim_keys?: string[] | null;
}

/**
 * Normalize a GitHub OIDC subject-claim customization response. At repository
 * scope GitHub returns `use_default`; at org scope it does not, so an empty
 * `include_claim_keys` is treated as "default in effect".
 */
export function parseOidcSubject(
  body: OidcSubjectBody,
  scope: "org" | "repository",
  org: string,
  repository: string | null,
): GithubOidcSubject {
  const includeClaimKeys = Array.isArray(body.include_claim_keys)
    ? body.include_claim_keys
    : [];
  const useDefault = scope === "repository"
    ? body.use_default === true
    : includeClaimKeys.length === 0;
  return {
    scope,
    org,
    repository,
    useDefault,
    includeClaimKeys,
    issuer: GITHUB_ACTIONS_ISSUER,
    observedAt: new Date().toISOString(),
  };
}
