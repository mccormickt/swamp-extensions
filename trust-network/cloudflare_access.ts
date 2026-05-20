/**
 * `@mccormick/trust-network/cloudflare` — Cloudflare One / Zero Trust Access
 * discovery.
 *
 * Cloudflare One is both a relying party and an identity provider. Access
 * applications are gated by Access policies — `include` / `require` / `exclude`
 * rule sets that are the platform's conditional-access mechanism. Configured
 * identity providers are the OIDC/SAML logins Cloudflare trusts; service
 * tokens are machine credentials with an expiry; mTLS certificates anchor
 * certificate-based access.
 *
 * This model inventories, per account: Access applications, their policies
 * (rules normalized into conditional-access factors), identity providers,
 * service tokens, and mTLS certificates. The `scan` method fans out across
 * every configured account; a per-account or per-app failure is recorded in
 * the summary's `notes` and never aborts the run.
 *
 * @module
 */
import { z } from "npm:zod@4";
import type { ModelDefinition } from "jsr:@systeminit/swamp-testing@0.20260519.14";
import {
  CfAccessAppSchema,
  CfAccessPolicySchema,
  CfIdentityProviderSchema,
  CfMtlsCertSchema,
  CfServiceTokenSchema,
  sanitizeInstanceName,
  ScanSummarySchema,
} from "./shared/schema.ts";
import {
  assertHttpsUrl,
  bearerHeaders,
  fetchCloudflarePaginated,
  HttpError,
} from "./shared/http.ts";
import {
  computeDurationDays,
  normalizeAccessPolicy,
  type RawAccessPolicy,
} from "./shared/cloudflare.ts";

/** Global arguments for the Cloudflare One scanner. */
const GlobalArgs = z.object({
  accountIds: z.array(z.string()).default([]).describe(
    "Cloudflare account IDs to scan",
  ),
  cloudflareToken: z.string().describe(
    "Cloudflare API token; supply via " +
      '${{ vault.get("trust-network", "CLOUDFLARE_TOKEN") }}',
  ).meta({ sensitive: true }),
  apiBaseUrl: z.string().default("https://api.cloudflare.com/client/v4")
    .describe("Cloudflare API v4 base URL"),
});

/** Render an unknown error as a redaction-safe, single-line string. */
function errMsg(err: unknown): string {
  if (err instanceof HttpError || err instanceof Error) return err.message;
  return String(err);
}

/** Raw Access application as returned by the Cloudflare API. */
interface RawApp {
  id: string;
  name?: string;
  domain?: string;
  type?: string;
  allowed_idps?: string[];
  saas_app?: { auth_type?: string };
}

/** Raw identity provider as returned by the Cloudflare API. */
interface RawIdp {
  id: string;
  name?: string;
  type?: string;
  config?: { issuer_url?: string };
}

/** Raw service token as returned by the Cloudflare API. */
interface RawServiceToken {
  id: string;
  name?: string;
  client_id?: string;
  created_at?: string;
  expires_at?: string;
}

/** Raw mTLS certificate as returned by the Cloudflare API. */
interface RawCertificate {
  id: string;
  name?: string;
  fingerprint?: string;
  expires_on?: string;
  associated_hostnames?: string[];
}

/**
 * `@mccormick/trust-network/cloudflare` — discovers Cloudflare One / Zero Trust
 * Access applications, policies, identity providers, service tokens, and mTLS
 * certificates across the configured accounts. Read-only.
 */
export const model = {
  type: "@mccormick/trust-network/cloudflare",
  version: "2026.05.19.1",
  globalArguments: GlobalArgs,
  resources: {
    access_app: {
      description: "A Cloudflare Access application",
      schema: CfAccessAppSchema,
      lifetime: "7d",
      garbageCollection: 20,
    },
    access_policy: {
      description: "A Cloudflare Access policy (conditional-access ruleset)",
      schema: CfAccessPolicySchema,
      lifetime: "7d",
      garbageCollection: 20,
    },
    identity_provider: {
      description: "A configured Cloudflare Access identity provider",
      schema: CfIdentityProviderSchema,
      lifetime: "7d",
      garbageCollection: 20,
    },
    service_token: {
      description: "A Cloudflare Access service token (machine credential)",
      schema: CfServiceTokenSchema,
      lifetime: "7d",
      garbageCollection: 20,
    },
    mtls_cert: {
      description: "A Cloudflare Access mTLS CA certificate",
      schema: CfMtlsCertSchema,
      lifetime: "7d",
      garbageCollection: 20,
    },
    access_summary: {
      description: "Roll-up of one Cloudflare One scan",
      schema: ScanSummarySchema,
      lifetime: "7d",
      garbageCollection: 20,
    },
  },
  methods: {
    scan: {
      description:
        "Fan-out scan of Cloudflare One Access applications, policies, " +
        "identity providers, service tokens, and mTLS certificates.",
      arguments: z.object({}),
      execute: async (_args, context) => {
        const g = context.globalArgs;
        const base = assertHttpsUrl(g.apiBaseUrl, "apiBaseUrl");
        if (g.accountIds.length > 0 && !g.cloudflareToken) {
          throw new Error("cloudflareToken is required to scan accounts");
        }
        const headers = bearerHeaders(g.cloudflareToken);

        const handles = [];
        const notes: string[] = [];
        const counts: Record<string, number> = {
          access_app: 0,
          access_policy: 0,
          identity_provider: 0,
          service_token: 0,
          mtls_cert: 0,
        };
        let targetsScanned = 0;
        let targetsFailed = 0;

        for (const accountId of g.accountIds) {
          try {
            const acct = `${base}/accounts/${accountId}/access`;

            const apps = await fetchCloudflarePaginated<RawApp>(
              `${acct}/apps`,
              { headers },
            );
            for (const app of apps) {
              handles.push(
                await context.writeResource(
                  "access_app",
                  `app-${sanitizeInstanceName(`${accountId}/${app.id}`)}`,
                  {
                    accountId,
                    appId: app.id,
                    name: app.name ?? "",
                    domain: app.domain ?? null,
                    type: app.type ?? null,
                    saasAuthType: app.saas_app?.auth_type ?? null,
                    allowedIdps: app.allowed_idps ?? [],
                    observedAt: new Date().toISOString(),
                  },
                ),
              );
              counts.access_app++;

              try {
                const policies = await fetchCloudflarePaginated<
                  RawAccessPolicy
                >(`${acct}/apps/${app.id}/policies`, { headers });
                for (const raw of policies) {
                  const policy = normalizeAccessPolicy(raw, accountId, app.id);
                  handles.push(
                    await context.writeResource(
                      "access_policy",
                      `pol-${
                        sanitizeInstanceName(
                          `${accountId}/${app.id}/${policy.policyId}`,
                        )
                      }`,
                      policy,
                    ),
                  );
                  counts.access_policy++;
                }
              } catch (err) {
                notes.push(`app ${app.id} policies: ${errMsg(err)}`);
              }
            }

            const idps = await fetchCloudflarePaginated<RawIdp>(
              `${acct}/identity_providers`,
              { headers },
            );
            for (const idp of idps) {
              handles.push(
                await context.writeResource(
                  "identity_provider",
                  `idp-${sanitizeInstanceName(`${accountId}/${idp.id}`)}`,
                  {
                    accountId,
                    idpId: idp.id,
                    name: idp.name ?? "",
                    type: idp.type ?? "unknown",
                    issuerUri: idp.config?.issuer_url ?? null,
                    observedAt: new Date().toISOString(),
                  },
                ),
              );
              counts.identity_provider++;
            }

            const tokens = await fetchCloudflarePaginated<RawServiceToken>(
              `${acct}/service_tokens`,
              { headers },
            );
            for (const token of tokens) {
              const createdAt = token.created_at ?? null;
              const expiresAt = token.expires_at ?? null;
              handles.push(
                await context.writeResource(
                  "service_token",
                  `tok-${sanitizeInstanceName(`${accountId}/${token.id}`)}`,
                  {
                    accountId,
                    tokenId: token.id,
                    name: token.name ?? "",
                    clientId: token.client_id ?? null,
                    createdAt,
                    expiresAt,
                    durationDays: computeDurationDays(createdAt, expiresAt),
                    observedAt: new Date().toISOString(),
                  },
                ),
              );
              counts.service_token++;
            }

            const certs = await fetchCloudflarePaginated<RawCertificate>(
              `${acct}/certificates`,
              { headers },
            );
            for (const cert of certs) {
              handles.push(
                await context.writeResource(
                  "mtls_cert",
                  `cert-${sanitizeInstanceName(`${accountId}/${cert.id}`)}`,
                  {
                    accountId,
                    certId: cert.id,
                    name: cert.name ?? "",
                    fingerprint: cert.fingerprint ?? null,
                    expiresOn: cert.expires_on ?? null,
                    associatedHostnames: cert.associated_hostnames ?? [],
                    observedAt: new Date().toISOString(),
                  },
                ),
              );
              counts.mtls_cert++;
            }

            targetsScanned++;
            context.logger.info(
              "cloudflare: account {account} — {apps} apps, {idps} idps, " +
                "{tokens} tokens",
              {
                account: accountId,
                apps: apps.length,
                idps: idps.length,
                tokens: tokens.length,
              },
            );
          } catch (err) {
            targetsFailed++;
            notes.push(`account ${accountId}: ${errMsg(err)}`);
          }
        }

        const summary = {
          platform: "cloudflare" as const,
          targetsScanned,
          targetsFailed,
          resourceCounts: counts,
          notes,
          scannedAt: new Date().toISOString(),
        };
        handles.push(
          await context.writeResource("access_summary", "summary", summary),
        );
        context.logger.info(
          "cloudflare: scan complete — {scanned} accounts, {failed} failed",
          { scanned: targetsScanned, failed: targetsFailed },
        );
        return { dataHandles: handles };
      },
    },
  },
} satisfies ModelDefinition<typeof GlobalArgs>;
