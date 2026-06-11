/**
 * `@mccormick/trust-network/gcp` — Google Cloud Workload Identity Federation
 * discovery.
 *
 * GCP is a relying party: a Workload Identity Pool Provider trusts an external
 * OIDC (or AWS/SAML) issuer, and a service account grants
 * `roles/iam.workloadIdentityUser` to principals from the pool. The federation
 * trust is only as tight as the provider's `attributeCondition` — a provider
 * with no condition accepts every token its issuer mints.
 *
 * This model inventories, per project: Workload Identity Pools and Providers,
 * service accounts (with the federated principals allowed to assume each), and
 * user-managed service-account keys — the long-lived credential the federation
 * model exists to replace.
 *
 * Authentication is a short-lived `gcloud` access token (see `shared/gcp.ts`);
 * no key material is stored. The `scan` method fans out across every
 * configured project; a per-project or per-account failure is recorded in the
 * summary's `notes` and never aborts the run.
 *
 * @module
 */
import { z } from "npm:zod@4";
import {
  type GcpSaKey,
  GcpSaKeySchema,
  type GcpServiceAccount,
  GcpServiceAccountSchema,
  GcpWifPoolSchema,
  GcpWifProviderSchema,
  sanitizeInstanceName,
  ScanSummarySchema,
} from "./shared/schema.ts";
import {
  assertHttpsUrl,
  bearerHeaders,
  fetchGcpPaginated,
  fetchJson,
  HttpError,
} from "./shared/http.ts";
import {
  extractImpersonators,
  gcpAccessToken,
  type IamPolicy,
  lastSegment,
  parseWifProvider,
  type RawProvider,
} from "./shared/gcp.ts";

/** Global arguments for the GCP federation scanner. */
const GlobalArgs = z.object({
  projects: z.array(z.string()).default([]).describe(
    "GCP project IDs to scan",
  ),
  iamBaseUrl: z.string().default("https://iam.googleapis.com").describe(
    "Google Cloud IAM API base URL",
  ),
});

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
}
interface MethodResult {
  dataHandles: DataHandle[];
}

/** Render an unknown error as a redaction-safe, single-line string. */
function errMsg(err: unknown): string {
  if (err instanceof HttpError || err instanceof Error) return err.message;
  return String(err);
}

/** Raw Workload Identity Pool as returned by the IAM API. */
interface RawPool {
  name: string;
  displayName?: string;
  state?: string;
  disabled?: boolean;
}

/** Raw service account as returned by the IAM API. */
interface RawServiceAccount {
  email?: string;
  uniqueId?: string;
  displayName?: string;
  disabled?: boolean;
}

/** Raw service-account key as returned by the IAM API. */
interface RawSaKey {
  name: string;
  keyType?: string;
  keyOrigin?: string;
  validAfterTime?: string;
  validBeforeTime?: string;
  disabled?: boolean;
}

/**
 * `@mccormick/trust-network/gcp` — discovers Workload Identity Federation
 * pools, providers, service accounts, and user-managed keys across the
 * configured GCP projects. Read-only.
 */
export const model = {
  type: "@mccormick/trust-network/gcp",
  version: "2026.06.09.1",
  globalArguments: GlobalArgs,
  resources: {
    wif_pool: {
      description: "A Workload Identity Pool",
      schema: GcpWifPoolSchema,
      lifetime: "7d",
      garbageCollection: 20,
    },
    wif_provider: {
      description:
        "A Workload Identity Pool Provider — the federation trust config",
      schema: GcpWifProviderSchema,
      lifetime: "7d",
      garbageCollection: 20,
    },
    service_account: {
      description:
        "A service account and the federated principals allowed to assume it",
      schema: GcpServiceAccountSchema,
      lifetime: "7d",
      garbageCollection: 20,
    },
    sa_key: {
      description: "A user-managed service-account key (long-lived credential)",
      schema: GcpSaKeySchema,
      lifetime: "7d",
      garbageCollection: 20,
    },
    federation_summary: {
      description: "Roll-up of one GCP federation scan",
      schema: ScanSummarySchema,
      lifetime: "7d",
      garbageCollection: 20,
    },
  },
  methods: {
    scan: {
      description:
        "Fan-out scan of Workload Identity Federation pools/providers, " +
        "service accounts, and user-managed keys across every project.",
      arguments: z.object({}),
      execute: async (
        _rawArgs: unknown,
        context: MethodContext,
      ): Promise<MethodResult> => {
        const g = context.globalArgs;
        const iamBase = assertHttpsUrl(g.iamBaseUrl, "iamBaseUrl");
        // Only resolve a token when there is something to scan, so an empty
        // run needs no `gcloud` session.
        const token = g.projects.length > 0 ? await gcpAccessToken() : "";
        const headers = bearerHeaders(token);

        const handles = [];
        const notes: string[] = [];
        const counts: Record<string, number> = {
          wif_pool: 0,
          wif_provider: 0,
          service_account: 0,
          sa_key: 0,
        };
        let targetsScanned = 0;
        let targetsFailed = 0;

        /** Scan one service account: keys and impersonation bindings. */
        const scanServiceAccount = async (
          project: string,
          email: string,
          raw: { uniqueId?: string; displayName?: string; disabled?: boolean },
        ): Promise<void> => {
          const encoded = encodeURIComponent(email);
          let impersonators: GcpServiceAccount["impersonators"] = [];
          try {
            const policy = await fetchJson<IamPolicy>(
              `${iamBase}/v1/projects/${project}/serviceAccounts/${encoded}:getIamPolicy`,
              {
                method: "POST",
                headers,
                body: { options: { requestedPolicyVersion: 3 } },
              },
            );
            impersonators = extractImpersonators(policy ?? {});
          } catch (err) {
            notes.push(`sa ${email} iam policy: ${errMsg(err)}`);
          }

          try {
            const keyResp = await fetchJson<{ keys?: RawSaKey[] }>(
              `${iamBase}/v1/projects/${project}/serviceAccounts/${encoded}/keys?keyTypes=USER_MANAGED`,
              { headers },
            );
            for (const key of keyResp?.keys ?? []) {
              const keyId = lastSegment(key.name);
              const record = {
                project,
                serviceAccountEmail: email,
                keyId,
                name: key.name,
                keyType: key.keyType ?? "USER_MANAGED",
                keyOrigin: key.keyOrigin ?? null,
                validAfter: key.validAfterTime ?? null,
                validBefore: key.validBeforeTime ?? null,
                disabled: key.disabled === true,
                observedAt: new Date().toISOString(),
              } satisfies GcpSaKey;
              handles.push(
                await context.writeResource(
                  "sa_key",
                  `key-${sanitizeInstanceName(`${email}/${keyId}`)}`,
                  record,
                ),
              );
              counts.sa_key++;
            }
          } catch (err) {
            notes.push(`sa ${email} keys: ${errMsg(err)}`);
          }

          const account = {
            project,
            email,
            uniqueId: raw.uniqueId ?? null,
            displayName: raw.displayName ?? null,
            disabled: raw.disabled === true,
            impersonators,
            observedAt: new Date().toISOString(),
          } satisfies GcpServiceAccount;
          handles.push(
            await context.writeResource(
              "service_account",
              `sa-${sanitizeInstanceName(email)}`,
              account,
            ),
          );
          counts.service_account++;
        };

        for (const project of g.projects) {
          try {
            const pools = await fetchGcpPaginated<RawPool>(
              `${iamBase}/v1/projects/${project}/locations/global/workloadIdentityPools`,
              "workloadIdentityPools",
              { headers },
            );
            for (const pool of pools) {
              const poolId = lastSegment(pool.name);
              const poolRecord = {
                project,
                poolId,
                name: pool.name,
                displayName: pool.displayName ?? null,
                state: pool.state ?? null,
                disabled: pool.disabled === true,
                observedAt: new Date().toISOString(),
              };
              handles.push(
                await context.writeResource(
                  "wif_pool",
                  `pool-${sanitizeInstanceName(`${project}/${poolId}`)}`,
                  poolRecord,
                ),
              );
              counts.wif_pool++;

              try {
                const providers = await fetchGcpPaginated<RawProvider>(
                  `${iamBase}/v1/${pool.name}/providers`,
                  "workloadIdentityPoolProviders",
                  { headers },
                );
                for (const raw of providers) {
                  const provider = parseWifProvider(raw, project, poolId);
                  handles.push(
                    await context.writeResource(
                      "wif_provider",
                      `prov-${
                        sanitizeInstanceName(
                          `${project}/${poolId}/${provider.providerId}`,
                        )
                      }`,
                      provider,
                    ),
                  );
                  counts.wif_provider++;
                }
              } catch (err) {
                notes.push(`pool ${poolId} providers: ${errMsg(err)}`);
              }
            }

            const accounts = await fetchGcpPaginated<RawServiceAccount>(
              `${iamBase}/v1/projects/${project}/serviceAccounts`,
              "accounts",
              { headers },
            );
            for (const sa of accounts) {
              if (!sa.email) continue;
              await scanServiceAccount(project, sa.email, sa);
            }

            targetsScanned++;
            context.logger.info(
              "gcp: project {project} — {pools} pools, {sas} service accounts",
              { project, pools: pools.length, sas: accounts.length },
            );
          } catch (err) {
            targetsFailed++;
            notes.push(`project ${project}: ${errMsg(err)}`);
          }
        }

        const summary = {
          platform: "gcp" as const,
          targetsScanned,
          targetsFailed,
          resourceCounts: counts,
          notes,
          scannedAt: new Date().toISOString(),
        };
        handles.push(
          await context.writeResource(
            "federation_summary",
            "summary",
            summary,
          ),
        );
        context.logger.info(
          "gcp: scan complete — {scanned} projects, {failed} failed, " +
            "{keys} user-managed keys",
          {
            scanned: targetsScanned,
            failed: targetsFailed,
            keys: counts.sa_key,
          },
        );
        return { dataHandles: handles };
      },
    },
  },
};
