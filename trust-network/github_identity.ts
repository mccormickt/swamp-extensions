/**
 * `@mccormick/trust-network/github` — GitHub Actions OIDC and Actions-secret
 * discovery.
 *
 * GitHub Actions is an OIDC identity provider: it mints short-lived tokens for
 * workflow runs at `https://token.actions.githubusercontent.com`. This model
 * inventories two things downstream relying parties depend on:
 *
 *   - **OIDC subject customization** — the `include_claim_keys` template that
 *     decides how narrowly a relying party can match a `sub` claim, at both
 *     organization and repository scope.
 *   - **Actions secrets and variables** — names and metadata only (the API
 *     never exposes secret values), each classified against known long-lived
 *     cloud-credential patterns.
 *
 * The `scan` method fans out across every configured organization and
 * repository in a single call. A failure on one target is recorded in the
 * summary's `notes` and never aborts the run.
 *
 * @module
 */
import { z } from "npm:zod@4";
import type { ModelDefinition } from "jsr:@systeminit/swamp-testing@0.20260519.14";
import {
  type GithubActionsSecret,
  GithubActionsSecretSchema,
  type GithubOidcSubject,
  GithubOidcSubjectSchema,
  sanitizeInstanceName,
  ScanSummarySchema,
} from "./shared/schema.ts";
import {
  assertHttpsUrl,
  fetchGithubPaginated,
  fetchJson,
  githubHeaders,
  HttpError,
} from "./shared/http.ts";
import {
  classifySecretName,
  type OidcSubjectBody,
  parseOidcSubject,
} from "./shared/github.ts";

/** Global arguments for the GitHub identity scanner. */
const GlobalArgs = z.object({
  orgs: z.array(z.string()).default([]).describe(
    "GitHub organizations to scan in full",
  ),
  repos: z.array(z.string()).default([]).describe(
    "Explicit `owner/repo` entries to scan in addition to the orgs",
  ),
  githubToken: z.string().describe(
    'GitHub token; supply via ${{ vault.get("trust-network", "GITHUB_TOKEN") }}',
  ).meta({ sensitive: true }),
  apiBaseUrl: z.string().default("https://api.github.com").describe(
    "GitHub REST API base URL (override for GitHub Enterprise Server)",
  ),
  includeArchived: z.boolean().default(false).describe(
    "Include archived repositories in org scans",
  ),
  scanEnvironments: z.boolean().default(true).describe(
    "Also enumerate per-environment secrets and variables",
  ),
});

/** Render an unknown error as a redaction-safe, single-line string. */
function errMsg(err: unknown): string {
  if (err instanceof HttpError || err instanceof Error) return err.message;
  return String(err);
}

type Headers = Record<string, string>;

/** Fetch and normalize an org- or repo-scope OIDC subject customization. */
async function gatherOidcSubject(
  base: string,
  headers: Headers,
  scope: "org" | "repository",
  owner: string,
  repo: string | null,
): Promise<GithubOidcSubject> {
  const url = scope === "org"
    ? `${base}/orgs/${owner}/actions/oidc/customization/sub`
    : `${base}/repos/${owner}/${repo}/actions/oidc/customization/sub`;
  const body = await fetchJson<OidcSubjectBody>(url, { headers });
  return parseOidcSubject(body ?? {}, scope, owner, repo);
}

/** Fetch Actions secrets or variables for one scope and classify each name. */
async function gatherSecrets(
  base: string,
  headers: Headers,
  kind: "secret" | "variable",
  scope: "org" | "repository" | "environment",
  org: string,
  repo: string | null,
  environment: string | null,
): Promise<GithubActionsSecret[]> {
  const itemsKey = kind === "secret" ? "secrets" : "variables";
  let url: string;
  if (scope === "org") {
    url = `${base}/orgs/${org}/actions/${itemsKey}?per_page=100`;
  } else if (scope === "repository") {
    url = `${base}/repos/${org}/${repo}/actions/${itemsKey}?per_page=100`;
  } else {
    url = `${base}/repos/${org}/${repo}/environments/${
      encodeURIComponent(environment ?? "")
    }/${itemsKey}?per_page=100`;
  }
  const raw = await fetchGithubPaginated<
    { name: string; created_at?: string; updated_at?: string }
  >(url, { headers }, itemsKey);
  const now = new Date().toISOString();
  return raw.map((entry) => {
    const cls = classifySecretName(entry.name);
    return {
      scope,
      org,
      repository: repo,
      environment,
      kind,
      name: entry.name,
      looksLikeCloudCredential: cls.looksLikeCloudCredential,
      matchedPattern: cls.matchedPattern,
      createdAt: entry.created_at ?? null,
      updatedAt: entry.updated_at ?? null,
      observedAt: now,
    } satisfies GithubActionsSecret;
  });
}

/**
 * `@mccormick/trust-network/github` — discovers GitHub Actions OIDC subject
 * customization and Actions secrets/variables across the configured orgs and
 * repositories. Read-only; secret values are never requested or stored.
 */
export const model = {
  type: "@mccormick/trust-network/github",
  version: "2026.05.19.1",
  globalArguments: GlobalArgs,
  resources: {
    oidc_subject: {
      description:
        "GitHub Actions OIDC subject-claim customization at org or repo scope",
      schema: GithubOidcSubjectSchema,
      lifetime: "7d",
      garbageCollection: 20,
    },
    actions_secret: {
      description:
        "An Actions secret or variable (name and metadata only), classified " +
        "against cloud-credential patterns",
      schema: GithubActionsSecretSchema,
      lifetime: "7d",
      garbageCollection: 20,
    },
    identity_summary: {
      description: "Roll-up of one GitHub identity scan",
      schema: ScanSummarySchema,
      lifetime: "7d",
      garbageCollection: 20,
    },
  },
  methods: {
    scan: {
      description: "Fan-out scan of GitHub Actions OIDC config and Actions " +
        "secrets/variables across every configured org and repository.",
      arguments: z.object({}),
      execute: async (_args, context) => {
        const g = context.globalArgs;
        const base = assertHttpsUrl(g.apiBaseUrl, "apiBaseUrl");
        if ((g.orgs.length > 0 || g.repos.length > 0) && !g.githubToken) {
          throw new Error("githubToken is required to scan orgs or repos");
        }
        const headers = githubHeaders(g.githubToken);

        const handles = [];
        const notes: string[] = [];
        const counts: Record<string, number> = {
          oidc_subject: 0,
          actions_secret: 0,
        };
        let targetsScanned = 0;
        let targetsFailed = 0;

        /** Write one OIDC-subject resource; tolerate per-target failure. */
        const writeOidc = async (
          scope: "org" | "repository",
          owner: string,
          repo: string | null,
        ): Promise<void> => {
          try {
            const subject = await gatherOidcSubject(
              base,
              headers,
              scope,
              owner,
              repo,
            );
            const name = scope === "org"
              ? `oidc-org-${sanitizeInstanceName(owner)}`
              : `oidc-repo-${sanitizeInstanceName(`${owner}/${repo}`)}`;
            handles.push(
              await context.writeResource("oidc_subject", name, subject),
            );
            counts.oidc_subject++;
          } catch (err) {
            notes.push(
              `oidc subject (${scope} ${owner}${repo ? `/${repo}` : ""}): ${
                errMsg(err)
              }`,
            );
          }
        };

        /** Write all secret/variable resources for one scope. */
        const writeSecrets = async (
          kind: "secret" | "variable",
          scope: "org" | "repository" | "environment",
          org: string,
          repo: string | null,
          environment: string | null,
        ): Promise<void> => {
          try {
            const secrets = await gatherSecrets(
              base,
              headers,
              kind,
              scope,
              org,
              repo,
              environment,
            );
            for (const secret of secrets) {
              const composite = [org, repo, environment, secret.name]
                .filter((p): p is string => Boolean(p))
                .join("/");
              const name = `secret-${kind}-${scope}-${
                sanitizeInstanceName(composite)
              }`;
              handles.push(
                await context.writeResource("actions_secret", name, secret),
              );
              counts.actions_secret++;
            }
          } catch (err) {
            const where = [org, repo, environment].filter(Boolean).join("/");
            notes.push(`${kind}s (${scope} ${where}): ${errMsg(err)}`);
          }
        };

        /** Scan a single repository: OIDC config, secrets, variables, envs. */
        const scanRepo = async (
          owner: string,
          repo: string,
        ): Promise<boolean> => {
          try {
            await writeOidc("repository", owner, repo);
            await writeSecrets("secret", "repository", owner, repo, null);
            await writeSecrets("variable", "repository", owner, repo, null);
            if (g.scanEnvironments) {
              const envs = await fetchGithubPaginated<{ name: string }>(
                `${base}/repos/${owner}/${repo}/environments?per_page=100`,
                { headers },
                "environments",
              );
              for (const env of envs) {
                await writeSecrets(
                  "secret",
                  "environment",
                  owner,
                  repo,
                  env.name,
                );
                await writeSecrets(
                  "variable",
                  "environment",
                  owner,
                  repo,
                  env.name,
                );
              }
            }
            return true;
          } catch (err) {
            notes.push(`repo ${owner}/${repo}: ${errMsg(err)}`);
            return false;
          }
        };

        for (const org of g.orgs) {
          try {
            await writeOidc("org", org, null);
            await writeSecrets("secret", "org", org, null, null);
            await writeSecrets("variable", "org", org, null, null);
            const repos = await fetchGithubPaginated<
              { name: string; archived?: boolean }
            >(`${base}/orgs/${org}/repos?per_page=100&type=all`, { headers });
            context.logger.info(
              "github: org {org} has {count} repositories",
              { org, count: repos.length },
            );
            for (const repo of repos) {
              if (repo.archived && !g.includeArchived) continue;
              if (await scanRepo(org, repo.name)) targetsScanned++;
              else targetsFailed++;
            }
          } catch (err) {
            targetsFailed++;
            notes.push(`org ${org}: ${errMsg(err)}`);
          }
        }

        for (const ownerRepo of g.repos) {
          const slash = ownerRepo.indexOf("/");
          if (slash <= 0 || slash === ownerRepo.length - 1) {
            notes.push(`repo "${ownerRepo}": not in owner/repo form`);
            targetsFailed++;
            continue;
          }
          const owner = ownerRepo.slice(0, slash);
          const repo = ownerRepo.slice(slash + 1);
          if (await scanRepo(owner, repo)) targetsScanned++;
          else targetsFailed++;
        }

        const summary = {
          platform: "github" as const,
          targetsScanned,
          targetsFailed,
          resourceCounts: counts,
          notes,
          scannedAt: new Date().toISOString(),
        };
        handles.push(
          await context.writeResource("identity_summary", "summary", summary),
        );
        context.logger.info(
          "github: scan complete — {scanned} targets, {failed} failed, " +
            "{oidc} oidc, {secrets} secrets/variables",
          {
            scanned: targetsScanned,
            failed: targetsFailed,
            oidc: counts.oidc_subject,
            secrets: counts.actions_secret,
          },
        );
        return { dataHandles: handles };
      },
    },
  },
} satisfies ModelDefinition<typeof GlobalArgs>;
