/**
 * `@mccormick/trust-network/graph` — normalize provider scans into a trust
 * graph.
 *
 * The three provider models discover raw configuration; this model reads their
 * output and normalizes it into a single graph of **trust domains** (nodes)
 * and **trust edges** (directed credential relationships), each edge annotated
 * with its credential type, whether it is ephemeral, its conditional-access
 * factors, and severity-rated findings. A `TrustInventory` roll-up scores the
 * graph.
 *
 * Provider data is supplied to `build` as method arguments; the inventory
 * workflow wires them with CEL `data.findBySpec(...)` expressions so each run
 * re-reads the latest scans. The derivation logic lives in
 * [`shared/graph.ts`](./shared/graph.ts).
 *
 * @module
 */
import { z } from "npm:zod@4";
import {
  CfAccessAppSchema,
  CfAccessPolicySchema,
  CfIdentityProviderSchema,
  CfServiceTokenSchema,
  GcpSaKeySchema,
  GcpServiceAccountSchema,
  GcpWifPoolSchema,
  GcpWifProviderSchema,
  GithubActionsSecretSchema,
  GithubOidcSubjectSchema,
  sanitizeInstanceName,
  type TrustDomain,
  TrustDomainSchema,
  type TrustEdge,
  TrustEdgeSchema,
  TrustInventorySchema,
} from "./shared/schema.ts";
import {
  coerceInputs,
  computeInventory,
  deriveCloudflareSlice,
  deriveGcpSlice,
  deriveGithubSlice,
} from "./shared/graph.ts";

/** This model takes no global configuration — all input is per-`build`. */
const GlobalArgs = z.object({});

// Minimal structural typings for the method context, declared locally rather
// than imported from the swamp testing package so the registry scorer's
// `deno doc` never needs to resolve a JSR dependency (the convention the pulled
// `@stateless/proxmox` model follows). The testing package is still used in
// `*_test.ts`, which the scorer does not document.
interface DataHandle {
  name: string;
  specName: string;
  kind: string;
  dataId: string;
  version: number;
}
interface MethodContext {
  globalArgs: z.infer<typeof GlobalArgs>;
  logger: {
    info(message: string, props?: Record<string, unknown>): void;
    warn(message: string, props?: Record<string, unknown>): void;
  };
  writeResource(
    specName: string,
    name: string,
    data: Record<string, unknown>,
  ): Promise<DataHandle>;
  readResource?(
    instanceName: string,
    version?: number,
  ): Promise<Record<string, unknown> | null>;
}
interface MethodResult {
  dataHandles: DataHandle[];
}

/**
 * Arguments for `build` — the provider scan output. The inventory workflow
 * wires these with CEL `data.findBySpec(...)`; for a standalone run pass them
 * with `--input <name>:json=[...]`. Each defaults to an empty list so a
 * partial run (one provider scanned) still builds a graph.
 */
const BuildArgs = z.object({
  githubOidcSubjects: z.array(z.unknown()).default([]).describe(
    "GitHub `oidc_subject` resources from the github scan",
  ),
  githubSecrets: z.array(z.unknown()).default([]).describe(
    "GitHub `actions_secret` resources from the github scan",
  ),
  gcpWifPools: z.array(z.unknown()).default([]).describe(
    "GCP `wif_pool` resources from the gcp scan",
  ),
  gcpWifProviders: z.array(z.unknown()).default([]).describe(
    "GCP `wif_provider` resources from the gcp scan",
  ),
  gcpServiceAccounts: z.array(z.unknown()).default([]).describe(
    "GCP `service_account` resources from the gcp scan",
  ),
  gcpSaKeys: z.array(z.unknown()).default([]).describe(
    "GCP `sa_key` resources from the gcp scan",
  ),
  cfAccessApps: z.array(z.unknown()).default([]).describe(
    "Cloudflare `access_app` resources from the cloudflare scan",
  ),
  cfAccessPolicies: z.array(z.unknown()).default([]).describe(
    "Cloudflare `access_policy` resources from the cloudflare scan",
  ),
  cfIdentityProviders: z.array(z.unknown()).default([]).describe(
    "Cloudflare `identity_provider` resources from the cloudflare scan",
  ),
  cfServiceTokens: z.array(z.unknown()).default([]).describe(
    "Cloudflare `service_token` resources from the cloudflare scan",
  ),
});

/**
 * Thresholds for `assert_posture`. Each defaults to the most permissive value,
 * so a bare `assert_posture` run always passes — callers opt into strictness
 * per environment via method arguments (no `globalArguments` change).
 */
const AssertPostureArgs = z.object({
  maxCritical: z.number().int().min(0).default(0).describe(
    "Maximum allowed `critical` findings",
  ),
  maxHigh: z.number().int().min(0).default(0).describe(
    "Maximum allowed `high` findings",
  ),
  maxMedium: z.number().int().min(0).default(Number.MAX_SAFE_INTEGER).describe(
    "Maximum allowed `medium` findings (unbounded by default)",
  ),
  minEphemeralPct: z.number().min(0).max(100).default(0).describe(
    "Minimum required ephemeral-credential coverage, 0-100",
  ),
  minConditionalAccessPct: z.number().min(0).max(100).default(0).describe(
    "Minimum required conditional-access coverage, 0-100",
  ),
});

/**
 * `@mccormick/trust-network/graph` — builds the normalized trust graph from
 * the provider scans. Read-only aggregation; writes `trust_domain`,
 * `trust_edge`, and one `inventory` roll-up.
 */
export const model = {
  type: "@mccormick/trust-network/graph",
  version: "2026.06.09.1",
  upgrades: [
    {
      toVersion: "2026.05.21.2",
      description:
        "Cloudflare slice: Access apps as trust domains and targetDomainId " +
        "in edge ids. No globalArguments change.",
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
  ],
  reports: ["@mccormick/trust-network/posture"],
  globalArguments: GlobalArgs,
  resources: {
    trust_domain: {
      description: "A node in the trust graph (org, project, account, issuer)",
      schema: TrustDomainSchema,
      lifetime: "7d",
      garbageCollection: 20,
    },
    trust_edge: {
      description: "A directed trust/credential relationship",
      schema: TrustEdgeSchema,
      lifetime: "7d",
      garbageCollection: 20,
    },
    inventory: {
      description: "Trust-graph roll-up and scorecard",
      schema: TrustInventorySchema,
      lifetime: "7d",
      garbageCollection: 20,
    },
  },
  methods: {
    build: {
      description:
        "Normalize the provider scans into a trust graph of domains and " +
        "credential edges, with a scored inventory roll-up.",
      arguments: BuildArgs,
      execute: async (
        rawArgs: unknown,
        context: MethodContext,
      ): Promise<MethodResult> => {
        const a = BuildArgs.parse(rawArgs);
        const now = new Date().toISOString();
        const notes: string[] = [];

        const github = deriveGithubSlice(
          coerceInputs(
            a.githubOidcSubjects,
            GithubOidcSubjectSchema,
            "github oidc subject",
            notes,
          ),
          coerceInputs(
            a.githubSecrets,
            GithubActionsSecretSchema,
            "github secret",
            notes,
          ),
          now,
        );
        const gcp = deriveGcpSlice(
          coerceInputs(a.gcpWifPools, GcpWifPoolSchema, "gcp wif pool", notes),
          coerceInputs(
            a.gcpWifProviders,
            GcpWifProviderSchema,
            "gcp wif provider",
            notes,
          ),
          coerceInputs(
            a.gcpServiceAccounts,
            GcpServiceAccountSchema,
            "gcp service account",
            notes,
          ),
          coerceInputs(
            a.gcpSaKeys,
            GcpSaKeySchema,
            "gcp service-account key",
            notes,
          ),
          now,
        );
        const cloudflare = deriveCloudflareSlice(
          coerceInputs(
            a.cfAccessApps,
            CfAccessAppSchema,
            "cloudflare access app",
            notes,
          ),
          coerceInputs(
            a.cfAccessPolicies,
            CfAccessPolicySchema,
            "cloudflare access policy",
            notes,
          ),
          coerceInputs(
            a.cfIdentityProviders,
            CfIdentityProviderSchema,
            "cloudflare identity provider",
            notes,
          ),
          coerceInputs(
            a.cfServiceTokens,
            CfServiceTokenSchema,
            "cloudflare service token",
            notes,
          ),
          now,
        );

        const domainMap = new Map<string, TrustDomain>();
        const edges: TrustEdge[] = [];
        for (const slice of [github, gcp, cloudflare]) {
          for (const domain of slice.domains) domainMap.set(domain.id, domain);
          edges.push(...slice.edges);
        }

        const domains = [...domainMap.values()];
        const inventory = computeInventory(domains, edges, notes, now);

        const handles = [];
        for (const domain of domains) {
          handles.push(
            await context.writeResource(
              "trust_domain",
              `domain-${sanitizeInstanceName(domain.id)}`,
              domain,
            ),
          );
        }
        for (const edge of edges) {
          handles.push(
            await context.writeResource("trust_edge", edge.id, edge),
          );
        }
        handles.push(
          await context.writeResource("inventory", "current", inventory),
        );

        context.logger.info(
          "graph: built {domains} domains, {edges} edges — " +
            "{ephemeral}% ephemeral, {ca}% conditional-access",
          {
            domains: domains.length,
            edges: edges.length,
            ephemeral: inventory.ephemeralPct,
            ca: inventory.conditionalAccessPct,
          },
        );
        return { dataHandles: handles };
      },
    },
    assert_posture: {
      description:
        "Fail when the trust-graph posture breaches configured thresholds. " +
        "Reads the `inventory` roll-up that `build` wrote and throws a " +
        "violation list when findings or coverage are worse than allowed. " +
        "The CI enforcement gate — writes no data.",
      arguments: AssertPostureArgs,
      execute: async (
        rawArgs: unknown,
        context: MethodContext,
      ): Promise<MethodResult> => {
        const a = AssertPostureArgs.parse(rawArgs);

        const raw = await context.readResource!("current");
        if (raw === null) {
          throw new Error(
            "no trust-graph inventory found — run `graph build` first",
          );
        }
        const inv = TrustInventorySchema.parse(raw);

        const critical = inv.findingsBySeverity.critical ?? 0;
        const high = inv.findingsBySeverity.high ?? 0;
        const medium = inv.findingsBySeverity.medium ?? 0;

        const violations: string[] = [];
        if (critical > a.maxCritical) {
          violations.push(
            `critical findings: ${critical} (max ${a.maxCritical})`,
          );
        }
        if (high > a.maxHigh) {
          violations.push(`high findings: ${high} (max ${a.maxHigh})`);
        }
        if (medium > a.maxMedium) {
          violations.push(`medium findings: ${medium} (max ${a.maxMedium})`);
        }
        if (inv.ephemeralPct < a.minEphemeralPct) {
          violations.push(
            `ephemeral-credential coverage: ${inv.ephemeralPct}% ` +
              `(min ${a.minEphemeralPct}%)`,
          );
        }
        if (inv.conditionalAccessPct < a.minConditionalAccessPct) {
          violations.push(
            `conditional-access coverage: ${inv.conditionalAccessPct}% ` +
              `(min ${a.minConditionalAccessPct}%)`,
          );
        }

        if (violations.length > 0) {
          throw new Error(
            `trust posture gate FAILED — ${violations.length} ` +
              `threshold(s) breached:\n` +
              violations.map((v) => `  - ${v}`).join("\n") +
              `\ngraph built ${inv.builtAt}; ${inv.edgeCount} edges`,
          );
        }

        context.logger.info(
          "trust posture gate PASSED — {critical} critical, {high} high, " +
            "{medium} medium; {ephemeral}% ephemeral, " +
            "{ca}% conditional-access",
          {
            critical,
            high,
            medium,
            ephemeral: inv.ephemeralPct,
            ca: inv.conditionalAccessPct,
          },
        );
        return { dataHandles: [] };
      },
    },
  },
};
