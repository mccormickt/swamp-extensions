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
import type { ModelDefinition } from "jsr:@systeminit/swamp-testing@0.20260519.14";
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
 * `@mccormick/trust-network/graph` — builds the normalized trust graph from
 * the provider scans. Read-only aggregation; writes `trust_domain`,
 * `trust_edge`, and one `inventory` roll-up.
 */
export const model = {
  type: "@mccormick/trust-network/graph",
  version: "2026.05.19.1",
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
      execute: async (args, context) => {
        const a = BuildArgs.parse(args);
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
  },
} satisfies ModelDefinition<typeof GlobalArgs>;
