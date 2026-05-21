/**
 * `@mccormick/cloudflare/zerotrust` — Cloudflare One / Zero Trust Access
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
 * Transport is the official `cloudflare` TypeScript SDK — authentication,
 * retry/backoff, and pagination are handled by the SDK.
 *
 * @module
 */
import { z } from "npm:zod@4";
import type { ModelDefinition } from "jsr:@systeminit/swamp-testing@0.20260519.14";
import Cloudflare from "npm:cloudflare@6.2.0";
import {
  CfAccessAppSchema,
  CfAccessPolicySchema,
  CfIdentityProviderSchema,
  CfMtlsCertSchema,
  CfServiceTokenSchema,
  sanitizeInstanceName,
  ScanSummarySchema,
} from "./schema.ts";
import {
  computeDurationDays,
  normalizeAccessPolicy,
  type RawAccessPolicy,
} from "./policy.ts";
import { assertHttpsUrl, redactSecrets } from "./util.ts";

/** Global arguments for the Cloudflare One scanner. */
const GlobalArgs = z.object({
  accountIds: z.array(z.string()).default([]).describe(
    "Cloudflare account IDs to scan",
  ),
  cloudflareToken: z.string().describe(
    "Cloudflare API token; supply via " +
      '${{ vault.get("cloudflare", "CLOUDFLARE_TOKEN") }}',
  ).meta({ sensitive: true }),
  apiBaseUrl: z.string().default("https://api.cloudflare.com/client/v4")
    .describe("Cloudflare API v4 base URL"),
});

/** The `fetch` implementation type the Cloudflare SDK client accepts. */
type CloudflareFetch = NonNullable<
  NonNullable<ConstructorParameters<typeof Cloudflare>[0]>["fetch"]
>;

/**
 * Test seam: an injected `fetch` the Cloudflare SDK client is built with. In
 * production it stays `undefined` and the SDK uses its default; tests install
 * a stub via {@link __setCloudflareFetch}.
 */
let testFetch: CloudflareFetch | undefined;

/**
 * Test-only: override the `fetch` the SDK client is constructed with. Pass
 * `undefined` to restore the default. The `as unknown` cast bridges a cosmetic
 * difference between Deno's global `fetch` type and the SDK's `Fetch` type —
 * the two are interchangeable at runtime.
 */
export function __setCloudflareFetch(f: typeof fetch | undefined): void {
  testFetch = f as unknown as CloudflareFetch | undefined;
}

/** Render an unknown error as a redaction-safe, single-line string. */
function errMsg(err: unknown): string {
  return redactSecrets(err instanceof Error ? err.message : String(err));
}

/** Raw Access application — the subset of fields this model reads. */
interface RawApp {
  id: string;
  name?: string;
  domain?: string;
  type?: string;
  allowed_idps?: string[];
  saas_app?: { auth_type?: string };
}

/** Raw identity provider — the subset of fields this model reads. */
interface RawIdp {
  id: string;
  name?: string;
  type?: string;
  config?: { issuer_url?: string };
}

/** Raw service token — the subset of fields this model reads. */
interface RawServiceToken {
  id: string;
  name?: string;
  client_id?: string;
  created_at?: string;
  expires_at?: string;
}

/** Raw mTLS certificate — the subset of fields this model reads. */
interface RawCertificate {
  id: string;
  name?: string;
  fingerprint?: string;
  expires_on?: string;
  associated_hostnames?: string[];
}

/**
 * `@mccormick/cloudflare/zerotrust` — discovers Cloudflare One / Zero Trust
 * Access applications, policies, identity providers, service tokens, and mTLS
 * certificates across the configured accounts. Read-only.
 */
export const model = {
  type: "@mccormick/cloudflare/zerotrust",
  version: "2026.05.21.1",
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
        const client = new Cloudflare({
          apiToken: g.cloudflareToken,
          baseURL: base,
          maxRetries: 4,
          fetch: testFetch,
        });

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
            let apps = 0;
            let idps = 0;
            let tokens = 0;

            for await (
              const item of client.zeroTrust.access.applications.list({
                account_id: accountId,
              })
            ) {
              const app = item as unknown as RawApp;
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
              apps++;

              try {
                for await (
                  const rawItem of client.zeroTrust.access.applications
                    .policies.list(app.id, { account_id: accountId })
                ) {
                  const policy = normalizeAccessPolicy(
                    rawItem as unknown as RawAccessPolicy,
                    accountId,
                    app.id,
                  );
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

            for await (
              const item of client.zeroTrust.identityProviders.list({
                account_id: accountId,
              })
            ) {
              const idp = item as unknown as RawIdp;
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
              idps++;
            }

            for await (
              const item of client.zeroTrust.access.serviceTokens.list({
                account_id: accountId,
              })
            ) {
              const token = item as unknown as RawServiceToken;
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
              tokens++;
            }

            for await (
              const item of client.zeroTrust.access.certificates.list({
                account_id: accountId,
              })
            ) {
              const cert = item as unknown as RawCertificate;
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
              { account: accountId, apps, idps, tokens },
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
