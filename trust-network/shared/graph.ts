/**
 * `@mccormick/trust-network` — trust-graph construction and rendering.
 *
 * Pure functions shared by the `graph` model, the `posture` report, and their
 * tests: per-provider edge derivation, the cross-provider inventory roll-up,
 * the finding catalog, and the posture-report renderer.
 *
 * @module
 */
import { z } from "npm:zod@4";
import {
  type CfAccessApp,
  type CfAccessPolicy,
  type CfIdentityProvider,
  type CfServiceToken,
  type Finding,
  type GcpSaKey,
  type GcpServiceAccount,
  type GcpWifPool,
  type GcpWifProvider,
  GITHUB_ACTIONS_ISSUER,
  type GithubActionsSecret,
  type GithubOidcSubject,
  type Severity,
  STATIC_ISSUER,
  type TrustDomain,
  type TrustEdge,
  trustEdgeId,
  type TrustInventory,
} from "./schema.ts";

/** Synthetic domain for an unresolved external party (key holder, target cloud). */
export const EXTERNAL_UNKNOWN_DOMAIN_ID = "external:unknown";
/** Domain for the GitHub Actions OIDC issuer when no specific org is pinned. */
export const GITHUB_ACTIONS_DOMAIN_ID = "github:actions";
/** Conditional-access factors that count as strong (device posture / MFA). */
const STRONG_FACTORS: ReadonlySet<string> = new Set(["device-posture", "mfa"]);
/** A Cloudflare service token lasting longer than this (days) is "long-lived". */
const LONG_TOKEN_DAYS = 365;

// ---------------------------------------------------------------------------
// Finding catalog
// ---------------------------------------------------------------------------

/** Metadata for every finding code the graph can emit. */
const FINDING_CATALOG: Readonly<
  Record<string, { severity: Severity; title: string; recommendation: string }>
> = {
  GITHUB_STATIC_CLOUD_CREDENTIAL: {
    severity: "high",
    title: "Static cloud credential stored in GitHub Actions",
    recommendation:
      "Replace the secret with OIDC workload-identity federation, then delete it.",
  },
  WIF_NO_ATTRIBUTE_CONDITION: {
    severity: "critical",
    title: "Workload Identity provider has no attribute condition",
    recommendation: "Add an attributeCondition that pins the workload (e.g. " +
      "`assertion.repository_owner`) so only intended tokens are accepted.",
  },
  WIF_GITHUB_NO_ORG_PIN: {
    severity: "high",
    title: "GitHub-trusting Workload Identity provider does not pin an org",
    recommendation:
      "Add `assertion.repository_owner == '<org>'` to the attribute " +
      "condition so only your organization's repositories can federate.",
  },
  GCP_USER_MANAGED_SA_KEY: {
    severity: "high",
    title: "User-managed service-account key",
    recommendation:
      "Delete the key and use Workload Identity Federation or short-lived " +
      "impersonation instead.",
  },
  CF_ACCESS_POLICY_ALLOW_ALL: {
    severity: "high",
    title: "Access application admits everyone or bypasses authentication",
    recommendation:
      "Replace the allow-everyone / bypass policy with one that requires an " +
      "identity, group, or device-posture check.",
  },
  CF_ACCESS_NO_POSTURE: {
    severity: "medium",
    title: "Access application requires no device posture or MFA",
    recommendation:
      "Add a device-posture or MFA `require` rule to the application's " +
      "Access policy.",
  },
  CF_SERVICE_TOKEN_NO_EXPIRY: {
    severity: "medium",
    title: "Cloudflare service token is long-lived or never expires",
    recommendation:
      "Set a short duration on the service token and rotate it regularly.",
  },
};

/** Build a {@link Finding} from a catalog code and a context-specific detail. */
export function makeFinding(code: string, detail: string): Finding {
  const meta = FINDING_CATALOG[code] ??
    { severity: "info" as Severity, title: code, recommendation: "" };
  return {
    code,
    severity: meta.severity,
    title: meta.title,
    detail,
    recommendation: meta.recommendation,
  };
}

// ---------------------------------------------------------------------------
// Input coercion
// ---------------------------------------------------------------------------

/**
 * Unwrap a `data.findBySpec` item. Swamp resource records carry the written
 * data under `attributes`; a bare object is returned unchanged.
 */
function unwrap(item: unknown): unknown {
  if (item && typeof item === "object" && "attributes" in item) {
    const attrs = (item as { attributes: unknown }).attributes;
    if (attrs && typeof attrs === "object") return attrs;
  }
  return item;
}

/**
 * Validate each input item against `schema`, dropping (and noting) any that do
 * not conform — a malformed resource never aborts the build.
 */
export function coerceInputs<T>(
  items: unknown[],
  schema: z.ZodType<T>,
  label: string,
  notes: string[],
): T[] {
  const out: T[] = [];
  for (const item of items) {
    const parsed = schema.safeParse(unwrap(item));
    if (parsed.success) {
      out.push(parsed.data);
    } else {
      notes.push(
        `skipped malformed ${label}: ${
          parsed.error.issues[0]?.message ?? "schema mismatch"
        }`,
      );
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Domain helpers
// ---------------------------------------------------------------------------

/** Trust-domain id for a GitHub organization. */
export function githubOrgDomainId(org: string): string {
  return `github:org/${org}`;
}

/** Trust-domain id for a GCP project. */
export function gcpProjectDomainId(project: string): string {
  return `gcp:project/${project}`;
}

/** Trust-domain id for a Cloudflare account. */
export function cloudflareAccountDomainId(accountId: string): string {
  return `cloudflare:account/${accountId}`;
}

/** Add a domain to the map if not already present; return its id. */
function ensureDomain(
  domains: Map<string, TrustDomain>,
  domain: TrustDomain,
): string {
  if (!domains.has(domain.id)) domains.set(domain.id, domain);
  return domain.id;
}

/** Host of a URL, or the raw string when it does not parse. */
function urlHost(raw: string): string {
  try {
    return new URL(raw).host;
  } catch {
    return raw;
  }
}

/** A slice of the trust graph contributed by one provider. */
export interface GraphSlice {
  /** Trust domains discovered by the slice. */
  domains: TrustDomain[];
  /** Trust edges discovered by the slice. */
  edges: TrustEdge[];
}

// ---------------------------------------------------------------------------
// GitHub slice
// ---------------------------------------------------------------------------

/** Human-readable location of a GitHub secret. */
function secretLocation(secret: GithubActionsSecret): string {
  const base = secret.repository
    ? `repo ${secret.repository}`
    : `org ${secret.org}`;
  return secret.environment ? `${base} env ${secret.environment}` : base;
}

/**
 * Derive the GitHub portion of the trust graph: an org domain per
 * organization, and a non-ephemeral `github-secret` edge per Actions secret
 * that looks like a static cloud credential.
 */
export function deriveGithubSlice(
  oidcSubjects: GithubOidcSubject[],
  secrets: GithubActionsSecret[],
  now: string,
): GraphSlice {
  const domains = new Map<string, TrustDomain>();
  const edges: TrustEdge[] = [];

  const ensureOrg = (org: string): string =>
    ensureDomain(domains, {
      id: githubOrgDomainId(org),
      platform: "github",
      kind: "org",
      displayName: `GitHub org ${org}`,
      issuerUri: GITHUB_ACTIONS_ISSUER,
      discoveredAt: now,
    });

  for (const subject of oidcSubjects) ensureOrg(subject.org);

  for (const secret of secrets) {
    const sourceDomainId = ensureOrg(secret.org);
    if (!secret.looksLikeCloudCredential) continue;

    ensureDomain(domains, {
      id: EXTERNAL_UNKNOWN_DOMAIN_ID,
      platform: "external",
      kind: "external",
      displayName: "Unresolved external party",
      issuerUri: null,
      discoveredAt: now,
    });

    const sourceLabel = secretLocation(secret);
    const targetLabel = `${secret.kind} "${secret.name}"`;
    edges.push({
      id: trustEdgeId({
        sourceDomainId,
        sourceLabel,
        targetLabel,
        sourceIssuer: STATIC_ISSUER,
        credentialType: "github-secret",
      }),
      sourceDomainId,
      sourceLabel,
      sourceIssuer: STATIC_ISSUER,
      targetDomainId: EXTERNAL_UNKNOWN_DOMAIN_ID,
      targetLabel,
      audience: [],
      subjectPattern: null,
      claimConditions: null,
      credentialType: "github-secret",
      ephemeral: false,
      conditionalAccess: { present: false, factors: [] },
      permissions: [],
      findings: [
        makeFinding(
          "GITHUB_STATIC_CLOUD_CREDENTIAL",
          `${sourceLabel} holds ${secret.kind} "${secret.name}" ` +
            `(matched pattern: ${secret.matchedPattern ?? "unknown"}).`,
        ),
      ],
      discoveredAt: now,
    });
  }

  return { domains: [...domains.values()], edges };
}

// ---------------------------------------------------------------------------
// GCP slice
// ---------------------------------------------------------------------------

/**
 * Extract the GitHub organizations a GCP `attributeCondition` pins, from the
 * common CEL forms (`repository_owner == 'x'`, `repository_owner in [...]`,
 * `repository == 'owner/repo'`, `repository.startsWith('owner/')`).
 */
export function extractRepoOwners(condition: string | null): string[] {
  if (!condition) return [];
  const owners = new Set<string>();
  for (
    const m of condition.matchAll(/repository_owner\s*==\s*['"]([^'"]+)['"]/g)
  ) owners.add(m[1]);
  for (
    const m of condition.matchAll(
      /['"]([^'"]+)['"]\s*==\s*assertion\.repository_owner/g,
    )
  ) owners.add(m[1]);
  for (const m of condition.matchAll(/repository_owner\s+in\s+\[([^\]]+)\]/g)) {
    for (const q of m[1].matchAll(/['"]([^'"]+)['"]/g)) owners.add(q[1]);
  }
  for (
    const m of condition.matchAll(
      /repository\s*==\s*['"]([^'"/]+)\/[^'"]+['"]/g,
    )
  ) owners.add(m[1]);
  for (
    const m of condition.matchAll(
      /repository\s*\.\s*startsWith\(\s*['"]([^'"/]+)\//g,
    )
  ) owners.add(m[1]);
  return [...owners];
}

/** Does an IAM member string reference the given Workload Identity pool? */
function memberReferencesPool(member: string, poolId: string): boolean {
  return member.includes(`/workloadIdentityPools/${poolId}/`) ||
    member.endsWith(`/workloadIdentityPools/${poolId}`);
}

/**
 * Derive the GCP portion of the trust graph: a project domain per project, an
 * `oidc-federation` edge per Workload Identity provider (to each service
 * account its pool can impersonate), and a `sa-key` edge per user-managed key.
 */
export function deriveGcpSlice(
  pools: GcpWifPool[],
  providers: GcpWifProvider[],
  serviceAccounts: GcpServiceAccount[],
  saKeys: GcpSaKey[],
  now: string,
): GraphSlice {
  const domains = new Map<string, TrustDomain>();
  const edges: TrustEdge[] = [];

  const ensureProject = (project: string): string =>
    ensureDomain(domains, {
      id: gcpProjectDomainId(project),
      platform: "gcp",
      kind: "project",
      displayName: `GCP project ${project}`,
      issuerUri: null,
      discoveredAt: now,
    });

  for (const pool of pools) ensureProject(pool.project);
  for (const sa of serviceAccounts) ensureProject(sa.project);

  for (const provider of providers) {
    const projectDomainId = ensureProject(provider.project);
    const owners = extractRepoOwners(provider.attributeCondition);
    const isGithub = provider.issuerUri === GITHUB_ACTIONS_ISSUER;

    let sourceDomainId: string;
    let sourceIssuer: string;
    if (isGithub) {
      sourceIssuer = GITHUB_ACTIONS_ISSUER;
      sourceDomainId = owners.length === 1
        ? ensureDomain(domains, {
          id: githubOrgDomainId(owners[0]),
          platform: "github",
          kind: "org",
          displayName: `GitHub org ${owners[0]}`,
          issuerUri: GITHUB_ACTIONS_ISSUER,
          discoveredAt: now,
        })
        : ensureDomain(domains, {
          id: GITHUB_ACTIONS_DOMAIN_ID,
          platform: "github",
          kind: "idp",
          displayName: "GitHub Actions OIDC",
          issuerUri: GITHUB_ACTIONS_ISSUER,
          discoveredAt: now,
        });
    } else if (provider.issuerUri) {
      sourceIssuer = provider.issuerUri;
      sourceDomainId = ensureDomain(domains, {
        id: `external:${urlHost(provider.issuerUri)}`,
        platform: "external",
        kind: "idp",
        displayName: `External IdP ${urlHost(provider.issuerUri)}`,
        issuerUri: provider.issuerUri,
        discoveredAt: now,
      });
    } else {
      sourceIssuer = provider.awsAccountId
        ? `aws:${provider.awsAccountId}`
        : STATIC_ISSUER;
      sourceDomainId = ensureDomain(domains, {
        id: provider.awsAccountId
          ? `external:aws-${provider.awsAccountId}`
          : EXTERNAL_UNKNOWN_DOMAIN_ID,
        platform: "external",
        kind: provider.awsAccountId ? "account" : "external",
        displayName: provider.awsAccountId
          ? `AWS account ${provider.awsAccountId}`
          : "Unresolved external party",
        issuerUri: null,
        discoveredAt: now,
      });
    }

    const findings: Finding[] = [];
    const providerRef = `${provider.poolId}/${provider.providerId}`;
    if (!provider.attributeCondition) {
      findings.push(
        makeFinding(
          "WIF_NO_ATTRIBUTE_CONDITION",
          `Provider ${providerRef} in project ${provider.project} accepts ` +
            `any token from ${provider.issuerUri ?? "its issuer"}.`,
        ),
      );
    }
    if (isGithub && owners.length === 0) {
      findings.push(
        makeFinding(
          "WIF_GITHUB_NO_ORG_PIN",
          `Provider ${providerRef} trusts GitHub Actions without pinning ` +
            `repository_owner — any GitHub repository can federate.`,
        ),
      );
    }

    const boundAccounts = serviceAccounts.filter((sa) =>
      sa.project === provider.project &&
      sa.impersonators.some((imp) =>
        memberReferencesPool(imp.member, provider.poolId)
      )
    );

    const targets = boundAccounts.length > 0
      ? boundAccounts.map((sa) => ({
        label: `service account ${sa.email}`,
        permissions: sa.impersonators
          .filter((imp) => memberReferencesPool(imp.member, provider.poolId))
          .map((imp) => imp.role),
      }))
      : [{
        label: `pool ${provider.poolId} (no service account bound)`,
        permissions: [] as string[],
      }];

    const sourceLabel = isGithub && owners.length === 1
      ? `GitHub org ${owners[0]}`
      : isGithub
      ? "GitHub Actions workloads"
      : `issuer ${provider.issuerUri ?? sourceIssuer}`;

    for (const target of targets) {
      edges.push({
        id: trustEdgeId({
          sourceDomainId,
          sourceLabel,
          targetLabel: target.label,
          sourceIssuer,
          credentialType: "oidc-federation",
        }),
        sourceDomainId,
        sourceLabel,
        sourceIssuer,
        targetDomainId: projectDomainId,
        targetLabel: target.label,
        audience: provider.allowedAudiences,
        subjectPattern: `workloadIdentityPools/${provider.poolId}`,
        claimConditions: provider.attributeCondition,
        credentialType: "oidc-federation",
        ephemeral: true,
        conditionalAccess: {
          present: provider.attributeCondition !== null,
          factors: provider.attributeCondition ? ["attribute-condition"] : [],
        },
        permissions: target.permissions,
        findings,
        discoveredAt: now,
      });
    }
  }

  for (const key of saKeys) {
    if (key.keyType !== "USER_MANAGED") continue;
    const projectDomainId = ensureProject(key.project);
    ensureDomain(domains, {
      id: EXTERNAL_UNKNOWN_DOMAIN_ID,
      platform: "external",
      kind: "external",
      displayName: "Unresolved external party",
      issuerUri: null,
      discoveredAt: now,
    });
    const sourceLabel = `holder of SA key ${key.keyId}`;
    const targetLabel = `service account ${key.serviceAccountEmail}`;
    edges.push({
      id: trustEdgeId({
        sourceDomainId: EXTERNAL_UNKNOWN_DOMAIN_ID,
        sourceLabel,
        targetLabel,
        sourceIssuer: STATIC_ISSUER,
        credentialType: "sa-key",
      }),
      sourceDomainId: EXTERNAL_UNKNOWN_DOMAIN_ID,
      sourceLabel,
      sourceIssuer: STATIC_ISSUER,
      targetDomainId: projectDomainId,
      targetLabel,
      audience: [],
      subjectPattern: null,
      claimConditions: null,
      credentialType: "sa-key",
      ephemeral: false,
      conditionalAccess: { present: false, factors: [] },
      permissions: [],
      findings: [
        makeFinding(
          "GCP_USER_MANAGED_SA_KEY",
          `Service account ${key.serviceAccountEmail} has user-managed key ` +
            `${key.keyId} (valid ${key.validAfter ?? "?"} – ` +
            `${key.validBefore ?? "?"}).`,
        ),
      ],
      discoveredAt: now,
    });
  }

  return { domains: [...domains.values()], edges };
}

// ---------------------------------------------------------------------------
// Cloudflare slice
// ---------------------------------------------------------------------------

/**
 * Derive the Cloudflare One portion of the trust graph: an account domain per
 * account, a federation edge per identity provider, a session edge per Access
 * application (carrying its policies' conditional-access posture), and a
 * non-ephemeral `cf-service-token` edge per service token.
 */
export function deriveCloudflareSlice(
  apps: CfAccessApp[],
  policies: CfAccessPolicy[],
  idps: CfIdentityProvider[],
  tokens: CfServiceToken[],
  now: string,
): GraphSlice {
  const domains = new Map<string, TrustDomain>();
  const edges: TrustEdge[] = [];

  const ensureAccount = (accountId: string): string =>
    ensureDomain(domains, {
      id: cloudflareAccountDomainId(accountId),
      platform: "cloudflare",
      kind: "account",
      displayName: `Cloudflare account ${accountId}`,
      issuerUri: null,
      discoveredAt: now,
    });

  for (const idp of idps) {
    const accountDomainId = ensureAccount(idp.accountId);
    const sourceDomainId = ensureDomain(domains, {
      id: `external:cf-idp-${idp.idpId}`,
      platform: "external",
      kind: "idp",
      displayName: `${idp.type} IdP ${idp.name}`,
      issuerUri: idp.issuerUri,
      discoveredAt: now,
    });
    const sourceLabel = `${idp.type} IdP ${idp.name}`;
    const targetLabel = `Cloudflare account ${idp.accountId}`;
    edges.push({
      id: trustEdgeId({
        sourceDomainId,
        sourceLabel,
        targetLabel,
        sourceIssuer: idp.issuerUri ?? idp.type,
        credentialType: "oidc-federation",
      }),
      sourceDomainId,
      sourceLabel,
      sourceIssuer: idp.issuerUri ?? idp.type,
      targetDomainId: accountDomainId,
      targetLabel,
      audience: [],
      subjectPattern: null,
      claimConditions: null,
      credentialType: "oidc-federation",
      ephemeral: true,
      conditionalAccess: { present: false, factors: [] },
      permissions: [],
      findings: [],
      discoveredAt: now,
    });
  }

  for (const app of apps) {
    const accountDomainId = ensureAccount(app.accountId);
    const appPolicies = policies.filter((p) =>
      p.accountId === app.accountId && p.appId === app.appId
    );
    const allowPolicies = appPolicies.filter((p) => p.decision === "allow");
    const wideOpen = appPolicies.some((p) =>
      (p.decision === "allow" && p.allowsEveryone) || p.decision === "bypass"
    );
    const factors = [...new Set(allowPolicies.flatMap((p) => p.factors))]
      .sort();
    const hasStrongFactor = factors.some((f) => STRONG_FACTORS.has(f));

    const findings: Finding[] = [];
    if (wideOpen) {
      findings.push(
        makeFinding(
          "CF_ACCESS_POLICY_ALLOW_ALL",
          `Access app "${app.name}" has a policy that admits everyone or ` +
            `bypasses authentication.`,
        ),
      );
    } else if (appPolicies.length > 0 && !hasStrongFactor) {
      findings.push(
        makeFinding(
          "CF_ACCESS_NO_POSTURE",
          `Access app "${app.name}" policies require no device-posture or ` +
            `MFA factor.`,
        ),
      );
    }

    const sourceLabel = "Access-authenticated users";
    const targetLabel = `Access app ${app.name}`;
    edges.push({
      id: trustEdgeId({
        sourceDomainId: accountDomainId,
        sourceLabel,
        targetLabel,
        sourceIssuer: "cloudflare-access",
        credentialType: "oidc-federation",
      }),
      sourceDomainId: accountDomainId,
      sourceLabel,
      sourceIssuer: "cloudflare-access",
      targetDomainId: accountDomainId,
      targetLabel,
      audience: app.domain ? [app.domain] : [],
      subjectPattern: null,
      claimConditions: appPolicies.map((p) => p.name).join("; ") || null,
      credentialType: "oidc-federation",
      ephemeral: true,
      conditionalAccess: {
        present: !wideOpen && factors.length > 0,
        factors,
      },
      permissions: [],
      findings,
      discoveredAt: now,
    });
  }

  for (const token of tokens) {
    const accountDomainId = ensureAccount(token.accountId);
    const longLived = token.durationDays === null ||
      token.durationDays > LONG_TOKEN_DAYS;
    const sourceLabel = `holder of service token ${token.name}`;
    const targetLabel = `Cloudflare account ${token.accountId}`;
    edges.push({
      id: trustEdgeId({
        sourceDomainId: EXTERNAL_UNKNOWN_DOMAIN_ID,
        sourceLabel,
        targetLabel,
        sourceIssuer: STATIC_ISSUER,
        credentialType: "cf-service-token",
      }),
      sourceDomainId: ensureDomain(domains, {
        id: EXTERNAL_UNKNOWN_DOMAIN_ID,
        platform: "external",
        kind: "external",
        displayName: "Unresolved external party",
        issuerUri: null,
        discoveredAt: now,
      }),
      sourceLabel,
      sourceIssuer: STATIC_ISSUER,
      targetDomainId: accountDomainId,
      targetLabel,
      audience: [],
      subjectPattern: token.clientId,
      claimConditions: null,
      credentialType: "cf-service-token",
      ephemeral: false,
      conditionalAccess: { present: false, factors: [] },
      permissions: [],
      findings: longLived
        ? [
          makeFinding(
            "CF_SERVICE_TOKEN_NO_EXPIRY",
            `Service token "${token.name}" ` +
              (token.durationDays === null
                ? "has no expiry."
                : `lasts ${token.durationDays} days.`),
          ),
        ]
        : [],
      discoveredAt: now,
    });
  }

  return { domains: [...domains.values()], edges };
}

// ---------------------------------------------------------------------------
// Inventory
// ---------------------------------------------------------------------------

/** Tally domains and edges into the {@link TrustInventory} scorecard. */
export function computeInventory(
  domains: TrustDomain[],
  edges: TrustEdge[],
  notes: string[],
  now: string,
): TrustInventory {
  const byCredentialType: Record<string, number> = {};
  const byPlatform: Record<string, number> = {};
  const findingsBySeverity: Record<string, number> = {};
  let ephemeralEdgeCount = 0;
  let conditionalAccessEdgeCount = 0;

  for (const domain of domains) {
    byPlatform[domain.platform] = (byPlatform[domain.platform] ?? 0) + 1;
  }
  for (const edge of edges) {
    byCredentialType[edge.credentialType] =
      (byCredentialType[edge.credentialType] ?? 0) + 1;
    if (edge.ephemeral) ephemeralEdgeCount++;
    if (edge.conditionalAccess.present) conditionalAccessEdgeCount++;
    for (const finding of edge.findings) {
      findingsBySeverity[finding.severity] =
        (findingsBySeverity[finding.severity] ?? 0) + 1;
    }
  }

  const edgeCount = edges.length;
  const pct = (n: number): number =>
    edgeCount === 0 ? 100 : Math.round((100 * n) / edgeCount);

  return {
    domainCount: domains.length,
    edgeCount,
    byCredentialType,
    byPlatform,
    ephemeralEdgeCount,
    ephemeralPct: pct(ephemeralEdgeCount),
    conditionalAccessEdgeCount,
    conditionalAccessPct: pct(conditionalAccessEdgeCount),
    findingsBySeverity,
    notes,
    builtAt: now,
  };
}

// ---------------------------------------------------------------------------
// Posture report rendering
// ---------------------------------------------------------------------------

/** Severities in display order, most urgent first. */
const SEVERITY_ORDER: readonly Severity[] = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
];

/** A finding flattened with the edge it was raised against. */
export interface ReportFinding {
  /** Stable machine code. */
  code: string;
  /** Finding severity. */
  severity: Severity;
  /** Short finding title. */
  title: string;
  /** Context-specific detail. */
  detail: string;
  /** Recommended remediation. */
  recommendation: string;
  /** Human-readable source of the edge the finding was raised against. */
  source: string;
  /** Human-readable target of the edge the finding was raised against. */
  target: string;
}

/** The machine-readable half of the posture report. */
export interface PostureJson {
  /** When the trust graph was built. */
  builtAt: string;
  /** Headline counts and percentages. */
  scorecard: {
    domainCount: number;
    edgeCount: number;
    ephemeralPct: number;
    ephemeralEdgeCount: number;
    conditionalAccessPct: number;
    conditionalAccessEdgeCount: number;
  };
  /** Every finding, flattened and tagged with its edge. */
  findings: ReportFinding[];
  /** Finding counts keyed by severity. */
  findingsBySeverity: Record<string, number>;
  /** Edge counts keyed by credential type. */
  byCredentialType: Record<string, number>;
  /** Domain counts keyed by platform. */
  byPlatform: Record<string, number>;
}

/** Collect every finding across all edges, tagged with its edge endpoints. */
function collectFindings(edges: TrustEdge[]): ReportFinding[] {
  const findings: ReportFinding[] = [];
  for (const edge of edges) {
    for (const finding of edge.findings) {
      findings.push({
        code: finding.code,
        severity: finding.severity,
        title: finding.title,
        detail: finding.detail,
        recommendation: finding.recommendation,
        source: edge.sourceLabel,
        target: edge.targetLabel,
      });
    }
  }
  return findings;
}

/**
 * Render the posture report — markdown and JSON — from a trust graph. Pure: it
 * takes the graph data and returns both report halves.
 */
export function renderPosture(
  inventory: TrustInventory,
  edges: TrustEdge[],
  domains: TrustDomain[],
): { markdown: string; json: PostureJson } {
  const findings = collectFindings(edges);
  const lines: string[] = [];

  lines.push("# Trust Network Posture", "");
  lines.push(`Trust graph built \`${inventory.builtAt}\`.`, "");

  lines.push("## Scorecard", "");
  lines.push(`- **Trust domains:** ${inventory.domainCount}`);
  lines.push(`- **Trust edges:** ${inventory.edgeCount}`);
  lines.push(
    `- **Ephemeral credentials:** ${inventory.ephemeralPct}% ` +
      `(${inventory.ephemeralEdgeCount}/${inventory.edgeCount} edges)`,
  );
  lines.push(
    `- **Conditional access:** ${inventory.conditionalAccessPct}% ` +
      `(${inventory.conditionalAccessEdgeCount}/${inventory.edgeCount} edges)`,
  );
  lines.push("");

  lines.push(`## Findings (${findings.length})`, "");
  if (findings.length === 0) {
    lines.push(
      "No findings — every trust edge is ephemeral and conditioned.",
      "",
    );
  } else {
    for (const severity of SEVERITY_ORDER) {
      const group = findings.filter((f) => f.severity === severity);
      if (group.length === 0) continue;
      lines.push(`### ${severity.toUpperCase()} (${group.length})`, "");
      for (const f of group) {
        lines.push(`- **${f.code}** — ${f.detail}`);
        lines.push(`  - Edge: \`${f.source}\` → \`${f.target}\``);
        if (f.recommendation) lines.push(`  - Fix: ${f.recommendation}`);
      }
      lines.push("");
    }
  }

  const credTypes = Object.entries(inventory.byCredentialType).sort();
  if (credTypes.length > 0) {
    lines.push("## Edges by credential type", "");
    lines.push("| Credential type | Count |", "| --- | --- |");
    for (const [type, count] of credTypes) {
      lines.push(`| ${type} | ${count} |`);
    }
    lines.push("");
  }

  if (domains.length > 0) {
    lines.push("## Trust domains", "");
    lines.push("| Platform | Domain | Acts as issuer |", "| --- | --- | --- |");
    for (const d of [...domains].sort((a, b) => a.id.localeCompare(b.id))) {
      lines.push(
        `| ${d.platform} | ${d.displayName} | ${d.issuerUri ?? "—"} |`,
      );
    }
    lines.push("");
  }

  if (inventory.notes.length > 0) {
    lines.push("## Scan notes", "");
    for (const note of inventory.notes) lines.push(`- ${note}`);
    lines.push("");
  }

  const json: PostureJson = {
    builtAt: inventory.builtAt,
    scorecard: {
      domainCount: inventory.domainCount,
      edgeCount: inventory.edgeCount,
      ephemeralPct: inventory.ephemeralPct,
      ephemeralEdgeCount: inventory.ephemeralEdgeCount,
      conditionalAccessPct: inventory.conditionalAccessPct,
      conditionalAccessEdgeCount: inventory.conditionalAccessEdgeCount,
    },
    findings,
    findingsBySeverity: inventory.findingsBySeverity,
    byCredentialType: inventory.byCredentialType,
    byPlatform: inventory.byPlatform,
  };
  return { markdown: lines.join("\n"), json };
}
