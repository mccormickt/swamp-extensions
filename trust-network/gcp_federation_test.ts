/**
 * Unit tests for `@mccormick/trust-network/gcp`.
 *
 * Covers the pure helpers (`lastSegment`, `parseWifProvider`,
 * `extractImpersonators`) and an end-to-end `scan` against a stubbed `fetch`,
 * with `GCP_ACCESS_TOKEN` set so no `gcloud` subprocess is spawned.
 */
import { assertEquals } from "jsr:@std/assert@1";
import { createModelTestContext } from "jsr:@systeminit/swamp-testing@0.20260519.14";
import { model } from "./gcp_federation.ts";
import {
  extractImpersonators,
  lastSegment,
  parseWifProvider,
  resetGcpTokenCache,
} from "./shared/gcp.ts";

type ScanCtx = Parameters<typeof model.methods.scan.execute>[1];

// ---------------------------------------------------------------------------
// lastSegment
// ---------------------------------------------------------------------------

Deno.test("lastSegment returns the final path component", () => {
  assertEquals(
    lastSegment("projects/123/locations/global/workloadIdentityPools/gh"),
    "gh",
  );
  assertEquals(lastSegment("gh-provider"), "gh-provider");
  assertEquals(lastSegment("a/b/c/"), "c");
});

// ---------------------------------------------------------------------------
// parseWifProvider
// ---------------------------------------------------------------------------

Deno.test("parseWifProvider detects an OIDC provider", () => {
  const provider = parseWifProvider(
    {
      name: "projects/1/locations/global/workloadIdentityPools/p/providers/gh",
      oidc: {
        issuerUri: "https://token.actions.githubusercontent.com",
        allowedAudiences: ["//iam.googleapis.com/x"],
      },
      attributeCondition: "assertion.repository_owner == 'acme'",
      attributeMapping: { "google.subject": "assertion.sub" },
    },
    "proj-1",
    "p",
  );
  assertEquals(provider.providerKind, "oidc");
  assertEquals(provider.issuerUri, "https://token.actions.githubusercontent.com");
  assertEquals(provider.providerId, "gh");
  assertEquals(provider.attributeCondition, "assertion.repository_owner == 'acme'");
});

Deno.test("parseWifProvider detects an AWS provider", () => {
  const provider = parseWifProvider(
    {
      name: "projects/1/locations/global/workloadIdentityPools/p/providers/aws",
      aws: { accountId: "123456789012" },
    },
    "proj-1",
    "p",
  );
  assertEquals(provider.providerKind, "aws");
  assertEquals(provider.awsAccountId, "123456789012");
  assertEquals(provider.issuerUri, null);
});

Deno.test("parseWifProvider normalizes a blank attributeCondition to null", () => {
  for (const condition of ["", "   ", undefined]) {
    const provider = parseWifProvider(
      {
        name: "projects/1/locations/global/workloadIdentityPools/p/providers/x",
        oidc: { issuerUri: "https://issuer.example" },
        attributeCondition: condition,
      },
      "proj-1",
      "p",
    );
    assertEquals(provider.attributeCondition, null);
  }
});

// ---------------------------------------------------------------------------
// extractImpersonators
// ---------------------------------------------------------------------------

Deno.test("extractImpersonators keeps only impersonation-granting roles", () => {
  const impersonators = extractImpersonators({
    bindings: [
      {
        role: "roles/iam.workloadIdentityUser",
        members: [
          "principalSet://iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/attribute.repository/acme/web",
        ],
      },
      { role: "roles/viewer", members: ["user:someone@example.com"] },
      {
        role: "roles/iam.serviceAccountTokenCreator",
        members: ["serviceAccount:other@proj.iam.gserviceaccount.com"],
      },
    ],
  });
  assertEquals(impersonators.length, 2);
  assertEquals(impersonators[0].role, "roles/iam.workloadIdentityUser");
  assertEquals(impersonators[1].role, "roles/iam.serviceAccountTokenCreator");
});

Deno.test("extractImpersonators tolerates an empty policy", () => {
  assertEquals(extractImpersonators({}).length, 0);
  assertEquals(extractImpersonators({ bindings: [] }).length, 0);
});

// ---------------------------------------------------------------------------
// fetch stub
// ---------------------------------------------------------------------------

interface Route {
  match: (path: string) => boolean;
  status?: number;
  body: unknown;
}

/** Install a `fetch` stub routed by a pathname predicate; returns a restore fn. */
function stubFetch(routes: Route[]): () => void {
  const original = globalThis.fetch;
  globalThis.fetch = ((input: string | URL | Request): Promise<Response> => {
    const href = typeof input === "string"
      ? input
      : input instanceof URL
      ? input.href
      : input.url;
    const path = new URL(href).pathname;
    const route = routes.find((r) => r.match(path));
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

const SA_EMAIL = "deployer@proj-1.iam.gserviceaccount.com";
const POOL_NAME =
  "projects/123/locations/global/workloadIdentityPools/gh-pool";

const SCAN_ROUTES: Route[] = [
  {
    match: (p) => p.endsWith(":getIamPolicy"),
    body: {
      version: 3,
      bindings: [{
        role: "roles/iam.workloadIdentityUser",
        members: [
          `principalSet://iam.googleapis.com/${POOL_NAME}/attribute.repository_owner/acme`,
        ],
      }],
    },
  },
  {
    match: (p) => p.endsWith("/keys"),
    body: {
      keys: [{
        name: `projects/proj-1/serviceAccounts/${SA_EMAIL}/keys/key-abc123`,
        keyType: "USER_MANAGED",
        keyOrigin: "GOOGLE_PROVIDED",
        validAfterTime: "2026-01-01T00:00:00Z",
        validBeforeTime: "2027-01-01T00:00:00Z",
      }],
    },
  },
  {
    match: (p) => p.endsWith("/providers"),
    body: {
      workloadIdentityPoolProviders: [{
        name: `${POOL_NAME}/providers/gh-provider`,
        state: "ACTIVE",
        oidc: {
          issuerUri: "https://token.actions.githubusercontent.com",
          allowedAudiences: ["//iam.googleapis.com/x"],
        },
        attributeCondition: "assertion.repository_owner == 'acme'",
        attributeMapping: { "google.subject": "assertion.sub" },
      }],
    },
  },
  {
    match: (p) => p.endsWith("/workloadIdentityPools"),
    body: {
      workloadIdentityPools: [{
        name: POOL_NAME,
        displayName: "GitHub Pool",
        state: "ACTIVE",
        disabled: false,
      }],
    },
  },
  {
    match: (p) => p.endsWith("/serviceAccounts"),
    body: {
      accounts: [{
        email: SA_EMAIL,
        uniqueId: "111111111",
        displayName: "Deployer",
        disabled: false,
      }],
    },
  },
];

// ---------------------------------------------------------------------------
// scan
// ---------------------------------------------------------------------------

Deno.test("scan discovers pools, providers, service accounts, and keys", async () => {
  Deno.env.set("GCP_ACCESS_TOKEN", "test-access-token");
  resetGcpTokenCache();
  const restore = stubFetch(SCAN_ROUTES);
  try {
    const { context, getWrittenResources } = createModelTestContext({
      globalArgs: { projects: ["proj-1"], iamBaseUrl: "https://iam.googleapis.com" },
    });
    await model.methods.scan.execute({}, context as unknown as ScanCtx);
    const written = getWrittenResources();

    const bySpec = (spec: string) =>
      written.filter((r) => r.specName === spec);
    assertEquals(bySpec("wif_pool").length, 1);
    assertEquals(bySpec("wif_provider").length, 1);
    assertEquals(bySpec("service_account").length, 1);
    assertEquals(bySpec("sa_key").length, 1);
    assertEquals(bySpec("federation_summary").length, 1);

    const provider = bySpec("wif_provider")[0].data;
    assertEquals(
      provider.issuerUri,
      "https://token.actions.githubusercontent.com",
    );
    assertEquals(provider.attributeCondition, "assertion.repository_owner == 'acme'");

    const sa = bySpec("service_account")[0].data;
    assertEquals((sa.impersonators as unknown[]).length, 1);

    const key = bySpec("sa_key")[0].data;
    assertEquals(key.keyType, "USER_MANAGED");

    const summary = bySpec("federation_summary")[0].data;
    assertEquals(summary.targetsScanned, 1);
    assertEquals(summary.targetsFailed, 0);
  } finally {
    restore();
    Deno.env.delete("GCP_ACCESS_TOKEN");
    resetGcpTokenCache();
  }
});

Deno.test("scan records a note when a project is inaccessible", async () => {
  Deno.env.set("GCP_ACCESS_TOKEN", "test-access-token");
  resetGcpTokenCache();
  const restore = stubFetch([
    {
      match: (p) => p.endsWith("/workloadIdentityPools"),
      status: 403,
      body: { error: { message: "permission denied" } },
    },
  ]);
  try {
    const { context, getWrittenResources } = createModelTestContext({
      globalArgs: { projects: ["proj-1"], iamBaseUrl: "https://iam.googleapis.com" },
    });
    await model.methods.scan.execute({}, context as unknown as ScanCtx);
    const summary = getWrittenResources()
      .find((r) => r.specName === "federation_summary")!.data;
    assertEquals(summary.targetsScanned, 0);
    assertEquals(summary.targetsFailed, 1);
    assertEquals((summary.notes as string[]).length, 1);
  } finally {
    restore();
    Deno.env.delete("GCP_ACCESS_TOKEN");
    resetGcpTokenCache();
  }
});
