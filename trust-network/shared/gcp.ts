/**
 * `@mccormick/trust-network` — Google Cloud helpers.
 *
 * Two concerns: resolving a short-lived access token (no key material is ever
 * stored), and pure parsing of IAM API responses shared by the `gcp` model
 * and its tests.
 *
 * @module
 */
import { redactSecrets } from "./http.ts";
import { type GcpWifProvider } from "./schema.ts";

// ---------------------------------------------------------------------------
// Access token
// ---------------------------------------------------------------------------

/** Process-lifetime memo — one model run resolves the token at most once. */
let cachedToken: string | null = null;

/**
 * Resolve a Google Cloud OAuth2 access token. Prefers `GCP_ACCESS_TOKEN`;
 * falls back to `gcloud auth print-access-token`. Memoized for the process.
 */
export async function gcpAccessToken(): Promise<string> {
  if (cachedToken) return cachedToken;

  const fromEnv = Deno.env.get("GCP_ACCESS_TOKEN");
  if (fromEnv && fromEnv.trim()) {
    cachedToken = fromEnv.trim();
    return cachedToken;
  }

  let output: Deno.CommandOutput;
  try {
    output = await new Deno.Command("gcloud", {
      args: ["auth", "print-access-token"],
      stdout: "piped",
      stderr: "piped",
    }).output();
  } catch (err) {
    throw new Error(
      "could not run `gcloud` — install the Google Cloud CLI and run " +
        "`gcloud auth login`, or set the GCP_ACCESS_TOKEN environment " +
        `variable. (${err instanceof Error ? err.message : String(err)})`,
    );
  }

  if (!output.success) {
    const stderr = redactSecrets(
      new TextDecoder().decode(output.stderr).trim(),
    );
    throw new Error(
      "`gcloud auth print-access-token` failed — run `gcloud auth login` " +
        `or set GCP_ACCESS_TOKEN. ${stderr}`,
    );
  }

  const token = new TextDecoder().decode(output.stdout).trim();
  if (!token) {
    throw new Error(
      "`gcloud auth print-access-token` returned an empty token — run " +
        "`gcloud auth login` or set GCP_ACCESS_TOKEN.",
    );
  }
  cachedToken = token;
  return token;
}

/** Clear the memoized token. Intended for unit tests. */
export function resetGcpTokenCache(): void {
  cachedToken = null;
}

// ---------------------------------------------------------------------------
// IAM response parsing
// ---------------------------------------------------------------------------

/**
 * IAM roles that let a principal act as, or mint tokens for, a service
 * account — the binding side of a federation trust edge.
 */
const IMPERSONATION_ROLES: ReadonlySet<string> = new Set([
  "roles/iam.workloadIdentityUser",
  "roles/iam.serviceAccountTokenCreator",
  "roles/iam.serviceAccountOpenIdTokenCreator",
  "roles/iam.serviceAccountUser",
]);

/** Last `/`-separated segment of a GCP resource name. */
export function lastSegment(resourceName: string): string {
  const parts = resourceName.split("/").filter(Boolean);
  return parts.length > 0 ? parts[parts.length - 1] : resourceName;
}

/** Raw Workload Identity Pool Provider as returned by the IAM API. */
export interface RawProvider {
  /** Full resource name. */
  name: string;
  /** Human-readable display name. */
  displayName?: string;
  /** Lifecycle state (`ACTIVE`, `DELETED`). */
  state?: string;
  /** Whether the provider is disabled. */
  disabled?: boolean;
  /** `assertion.*` → `attribute.*` mapping. */
  attributeMapping?: Record<string, string>;
  /** CEL gate on incoming assertions. */
  attributeCondition?: string;
  /** OIDC configuration block, when an OIDC provider. */
  oidc?: { issuerUri?: string; allowedAudiences?: string[] };
  /** AWS configuration block, when an AWS provider. */
  aws?: { accountId?: string };
  /** SAML configuration block, when a SAML provider. */
  saml?: Record<string, unknown>;
  /** X.509 configuration block, when an X.509 provider. */
  x509?: Record<string, unknown>;
}

/**
 * Normalize a raw Workload Identity Pool Provider, detecting its kind from
 * whichever of the `oidc` / `aws` / `saml` / `x509` blocks is present.
 */
export function parseWifProvider(
  raw: RawProvider,
  project: string,
  poolId: string,
): GcpWifProvider {
  let providerKind: GcpWifProvider["providerKind"] = "unknown";
  let issuerUri: string | null = null;
  let allowedAudiences: string[] = [];
  let awsAccountId: string | null = null;
  if (raw.oidc) {
    providerKind = "oidc";
    issuerUri = raw.oidc.issuerUri ?? null;
    allowedAudiences = raw.oidc.allowedAudiences ?? [];
  } else if (raw.aws) {
    providerKind = "aws";
    awsAccountId = raw.aws.accountId ?? null;
  } else if (raw.saml) {
    providerKind = "saml";
  } else if (raw.x509) {
    providerKind = "x509";
  }
  return {
    project,
    poolId,
    providerId: lastSegment(raw.name),
    name: raw.name,
    displayName: raw.displayName ?? null,
    state: raw.state ?? null,
    disabled: raw.disabled === true,
    providerKind,
    issuerUri,
    allowedAudiences,
    awsAccountId,
    attributeMapping: raw.attributeMapping ?? {},
    attributeCondition: raw.attributeCondition && raw.attributeCondition.trim()
      ? raw.attributeCondition
      : null,
    observedAt: new Date().toISOString(),
  };
}

/** An IAM policy as returned by `serviceAccounts.getIamPolicy`. */
export interface IamPolicy {
  /** Role-to-members bindings. */
  bindings?: { role: string; members?: string[] }[];
}

/** A principal granted an impersonation role on a service account. */
export interface Impersonator {
  /** `principal://` / `principalSet://` / `serviceAccount:` member string. */
  member: string;
  /** The IAM role granted. */
  role: string;
}

/**
 * Extract the `(member, role)` pairs from an IAM policy whose role lets the
 * member impersonate the service account.
 */
export function extractImpersonators(policy: IamPolicy): Impersonator[] {
  const out: Impersonator[] = [];
  for (const binding of policy.bindings ?? []) {
    if (!IMPERSONATION_ROLES.has(binding.role)) continue;
    for (const member of binding.members ?? []) {
      out.push({ member, role: binding.role });
    }
  }
  return out;
}
