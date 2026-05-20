/**
 * Unit tests for `@mccormick/trust-network/github`.
 *
 * Covers the pure classifiers (`classifySecretName`, `parseOidcSubject`) and an
 * end-to-end `scan` exercised against a stubbed `fetch`.
 */
import { assertEquals } from "jsr:@std/assert@1";
import { createModelTestContext } from "jsr:@systeminit/swamp-testing@0.20260519.14";
import { model } from "./github_identity.ts";
import { classifySecretName, parseOidcSubject } from "./shared/github.ts";

/**
 * `createModelTestContext` returns a loosely-typed context; the model's
 * `execute` is narrowed by `satisfies ModelDefinition<...>`. This is the exact
 * second-parameter type of `scan.execute` — used to bridge the two.
 */
type ScanCtx = Parameters<typeof model.methods.scan.execute>[1];

// ---------------------------------------------------------------------------
// classifySecretName
// ---------------------------------------------------------------------------

Deno.test("classifySecretName flags cloud-credential names", () => {
  for (const name of [
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "GCP_SA_KEY",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "AZURE_CLIENT_SECRET",
    "DEPLOY_PRIVATE_KEY",
  ]) {
    assertEquals(
      classifySecretName(name).looksLikeCloudCredential,
      true,
      `${name} should be flagged`,
    );
  }
});

Deno.test("classifySecretName ignores config and non-credential names", () => {
  for (const name of [
    "AWS_REGION",
    "AWS_DEFAULT_REGION",
    "NPM_TOKEN",
    "SLACK_WEBHOOK_URL",
    "FEATURE_FLAG_API",
    "NODE_ENV",
  ]) {
    assertEquals(
      classifySecretName(name).looksLikeCloudCredential,
      false,
      `${name} should not be flagged`,
    );
  }
});

// ---------------------------------------------------------------------------
// parseOidcSubject
// ---------------------------------------------------------------------------

Deno.test("parseOidcSubject treats empty org claim keys as default", () => {
  const subject = parseOidcSubject({ include_claim_keys: [] }, "org", "acme", null);
  assertEquals(subject.useDefault, true);
  assertEquals(subject.repository, null);
  assertEquals(subject.issuer, "https://token.actions.githubusercontent.com");
});

Deno.test("parseOidcSubject honors repository use_default", () => {
  const customized = parseOidcSubject(
    { use_default: false, include_claim_keys: ["repo", "environment"] },
    "repository",
    "acme",
    "web",
  );
  assertEquals(customized.useDefault, false);
  assertEquals(customized.includeClaimKeys, ["repo", "environment"]);

  const defaulted = parseOidcSubject(
    { use_default: true, include_claim_keys: ["repo", "context"] },
    "repository",
    "acme",
    "web",
  );
  assertEquals(defaulted.useDefault, true);
});

// ---------------------------------------------------------------------------
// fetch stub
// ---------------------------------------------------------------------------

interface Route {
  path: string;
  status?: number;
  body: unknown;
}

/** Install a `fetch` stub that routes by URL pathname; returns a restore fn. */
function stubFetch(routes: Route[]): () => void {
  const original = globalThis.fetch;
  globalThis.fetch = ((input: string | URL | Request): Promise<Response> => {
    const href = typeof input === "string"
      ? input
      : input instanceof URL
      ? input.href
      : input.url;
    const path = new URL(href).pathname;
    const route = routes.find((r) => r.path === path);
    if (!route) {
      return Promise.resolve(new Response("no route", { status: 404 }));
    }
    return Promise.resolve(
      new Response(JSON.stringify(route.body), {
        status: route.status ?? 200,
        headers: { "content-type": "application/json" },
      }),
    );
  }) as typeof fetch;
  return () => {
    globalThis.fetch = original;
  };
}

const HAPPY_ROUTES: Route[] = [
  {
    path: "/orgs/acme/actions/oidc/customization/sub",
    body: { include_claim_keys: ["repo", "context"] },
  },
  {
    path: "/orgs/acme/actions/secrets",
    body: {
      total_count: 1,
      secrets: [{
        name: "ORG_DOCKER_TOKEN",
        created_at: "2026-01-01T00:00:00Z",
        updated_at: "2026-01-02T00:00:00Z",
      }],
    },
  },
  { path: "/orgs/acme/actions/variables", body: { total_count: 0, variables: [] } },
  {
    path: "/orgs/acme/repos",
    body: [
      { name: "web", archived: false },
      { name: "legacy", archived: true },
    ],
  },
  {
    path: "/repos/acme/web/actions/oidc/customization/sub",
    body: { use_default: false, include_claim_keys: ["repo", "environment"] },
  },
  {
    path: "/repos/acme/web/actions/secrets",
    body: {
      total_count: 2,
      secrets: [{ name: "AWS_ACCESS_KEY_ID" }, { name: "FEATURE_FLAG_API" }],
    },
  },
  { path: "/repos/acme/web/actions/variables", body: { total_count: 0, variables: [] } },
  {
    path: "/repos/acme/web/environments",
    body: { total_count: 1, environments: [{ name: "prod" }] },
  },
  {
    path: "/repos/acme/web/environments/prod/secrets",
    body: { total_count: 1, secrets: [{ name: "GCP_SA_KEY" }] },
  },
  {
    path: "/repos/acme/web/environments/prod/variables",
    body: { total_count: 0, variables: [] },
  },
];

const GLOBAL_ARGS = {
  orgs: ["acme"],
  repos: [],
  githubToken: "ghp_testtoken",
  apiBaseUrl: "https://api.github.com",
  includeArchived: false,
  scanEnvironments: true,
};

// ---------------------------------------------------------------------------
// scan
// ---------------------------------------------------------------------------

Deno.test("scan discovers OIDC config and classified secrets", async () => {
  const restore = stubFetch(HAPPY_ROUTES);
  try {
    const { context, getWrittenResources } = createModelTestContext({
      globalArgs: GLOBAL_ARGS,
    });
    await model.methods.scan.execute({}, context as ScanCtx);
    const written = getWrittenResources();

    const oidc = written.filter((r) => r.specName === "oidc_subject");
    const secrets = written.filter((r) => r.specName === "actions_secret");
    const summaries = written.filter((r) => r.specName === "identity_summary");

    // Archived `legacy` repo is skipped — org + `web` only.
    assertEquals(oidc.length, 2);
    // org token + 2 repo secrets + 1 env secret.
    assertEquals(secrets.length, 4);
    assertEquals(summaries.length, 1);

    const awsKey = secrets.find((r) => r.data.name === "AWS_ACCESS_KEY_ID");
    assertEquals(awsKey?.data.looksLikeCloudCredential, true);
    const gcpKey = secrets.find((r) => r.data.name === "GCP_SA_KEY");
    assertEquals(gcpKey?.data.looksLikeCloudCredential, true);
    assertEquals(gcpKey?.data.scope, "environment");
    const flag = secrets.find((r) => r.data.name === "FEATURE_FLAG_API");
    assertEquals(flag?.data.looksLikeCloudCredential, false);

    const summary = summaries[0].data;
    assertEquals(summary.targetsScanned, 1);
    assertEquals(summary.targetsFailed, 0);
    assertEquals((summary.notes as string[]).length, 0);
  } finally {
    restore();
  }
});

Deno.test("scan records a note and continues when a sub-fetch fails", async () => {
  const routes = HAPPY_ROUTES.map((r) =>
    r.path === "/repos/acme/web/actions/secrets"
      ? { ...r, status: 404, body: { message: "Not Found" } }
      : r
  );
  const restore = stubFetch(routes);
  try {
    const { context, getWrittenResources } = createModelTestContext({
      globalArgs: GLOBAL_ARGS,
    });
    await model.methods.scan.execute({}, context as ScanCtx);
    const written = getWrittenResources();
    const summary = written.find((r) => r.specName === "identity_summary")!.data;

    // The repo was still scanned; only its repo-level secrets failed.
    assertEquals(summary.targetsScanned, 1);
    assertEquals(summary.targetsFailed, 0);
    assertEquals((summary.notes as string[]).length >= 1, true);
  } finally {
    restore();
  }
});
