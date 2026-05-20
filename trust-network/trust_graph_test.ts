/**
 * Unit tests for `@mccormick/trust-network/graph` — GitHub slice.
 *
 * Covers `coerceInputs`, `deriveGithubSlice`, `computeInventory`, and an
 * end-to-end `build` via the in-memory model test context.
 */
import {
  assertEquals,
  assertRejects,
  assertStringIncludes,
} from "jsr:@std/assert@1";
import { createModelTestContext } from "jsr:@systeminit/swamp-testing@0.20260519.14";
import { model } from "./trust_graph.ts";
import {
  coerceInputs,
  computeInventory,
  deriveCloudflareSlice,
  deriveGcpSlice,
  deriveGithubSlice,
  extractRepoOwners,
} from "./shared/graph.ts";
import {
  type CfAccessApp,
  type CfAccessPolicy,
  type CfIdentityProvider,
  type CfServiceToken,
  type GcpSaKey,
  type GcpServiceAccount,
  type GcpWifProvider,
  type GithubActionsSecret,
  GithubActionsSecretSchema,
  type GithubOidcSubject,
  type TrustEdge,
  type TrustInventory,
} from "./shared/schema.ts";

type BuildCtx = Parameters<typeof model.methods.build.execute>[1];
type AssertCtx = Parameters<typeof model.methods.assert_posture.execute>[1];
const NOW = "2026-05-19T00:00:00Z";

/** A GitHub secret resource with overridable fields. */
function secret(over: Partial<GithubActionsSecret>): GithubActionsSecret {
  return {
    scope: "repository",
    org: "acme",
    repository: "acme/web",
    environment: null,
    kind: "secret",
    name: "SOME_SECRET",
    looksLikeCloudCredential: false,
    matchedPattern: null,
    createdAt: null,
    updatedAt: null,
    observedAt: NOW,
    ...over,
  };
}

/** An OIDC subject resource with overridable fields. */
function oidc(over: Partial<GithubOidcSubject>): GithubOidcSubject {
  return {
    scope: "org",
    org: "acme",
    repository: null,
    useDefault: true,
    includeClaimKeys: [],
    issuer: "https://token.actions.githubusercontent.com",
    observedAt: NOW,
    ...over,
  };
}

/** A trust edge with overridable fields. */
function edge(over: Partial<TrustEdge>): TrustEdge {
  return {
    id: "edge-test",
    sourceDomainId: "d",
    sourceLabel: "src",
    sourceIssuer: "static",
    targetDomainId: "t",
    targetLabel: "tgt",
    audience: [],
    subjectPattern: null,
    claimConditions: null,
    credentialType: "static",
    ephemeral: false,
    conditionalAccess: { present: false, factors: [] },
    permissions: [],
    findings: [],
    discoveredAt: NOW,
    ...over,
  };
}

// ---------------------------------------------------------------------------
// coerceInputs
// ---------------------------------------------------------------------------

Deno.test("coerceInputs accepts valid items and unwraps `attributes`", () => {
  const notes: string[] = [];
  const valid = secret({ name: "A" });
  const result = coerceInputs(
    [valid, { attributes: secret({ name: "B" }) }],
    GithubActionsSecretSchema,
    "github secret",
    notes,
  );
  assertEquals(result.length, 2);
  assertEquals(result.map((r) => r.name).sort(), ["A", "B"]);
  assertEquals(notes.length, 0);
});

Deno.test("coerceInputs drops and notes malformed items", () => {
  const notes: string[] = [];
  const result = coerceInputs(
    [secret({ name: "ok" }), { not: "a secret" }],
    GithubActionsSecretSchema,
    "github secret",
    notes,
  );
  assertEquals(result.length, 1);
  assertEquals(notes.length, 1);
});

// ---------------------------------------------------------------------------
// deriveGithubSlice
// ---------------------------------------------------------------------------

Deno.test("deriveGithubSlice builds org domains and static-credential edges", () => {
  const { domains, edges } = deriveGithubSlice(
    [oidc({ org: "acme" })],
    [
      secret({
        org: "acme",
        name: "AWS_ACCESS_KEY_ID",
        looksLikeCloudCredential: true,
        matchedPattern: "aws-key",
      }),
      secret({ org: "acme", name: "NPM_TOKEN", looksLikeCloudCredential: false }),
    ],
    NOW,
  );
  // acme org + the external unknown-cloud sink.
  assertEquals(domains.length, 2);
  assertEquals(domains.some((d) => d.id === "github:org/acme"), true);
  // Only the cloud-credential secret produces an edge.
  assertEquals(edges.length, 1);
  assertEquals(edges[0].credentialType, "github-secret");
  assertEquals(edges[0].ephemeral, false);
  assertEquals(edges[0].findings[0].code, "GITHUB_STATIC_CLOUD_CREDENTIAL");
});

Deno.test("deriveGithubSlice produces no external domain without cloud secrets", () => {
  const { domains, edges } = deriveGithubSlice(
    [],
    [secret({ name: "NPM_TOKEN", looksLikeCloudCredential: false })],
    NOW,
  );
  assertEquals(edges.length, 0);
  assertEquals(domains.some((d) => d.id === "external:unknown-cloud"), false);
});

// ---------------------------------------------------------------------------
// computeInventory
// ---------------------------------------------------------------------------

Deno.test("computeInventory scores ephemeral and conditional-access shares", () => {
  const inventory = computeInventory(
    [],
    [
      edge({ id: "e1", ephemeral: true }),
      edge({ id: "e2", ephemeral: true }),
      edge({ id: "e3", conditionalAccess: { present: true, factors: ["mfa"] } }),
      edge({ id: "e4" }),
    ],
    [],
    NOW,
  );
  assertEquals(inventory.edgeCount, 4);
  assertEquals(inventory.ephemeralPct, 50);
  assertEquals(inventory.conditionalAccessPct, 25);
});

Deno.test("computeInventory reports 100% for an empty graph", () => {
  const inventory = computeInventory([], [], [], NOW);
  assertEquals(inventory.edgeCount, 0);
  assertEquals(inventory.ephemeralPct, 100);
  assertEquals(inventory.conditionalAccessPct, 100);
});

// ---------------------------------------------------------------------------
// build
// ---------------------------------------------------------------------------

Deno.test("build writes domains, edges, and a scored inventory", async () => {
  const { context, getWrittenResources } = createModelTestContext({});
  await model.methods.build.execute(
    {
      githubOidcSubjects: [oidc({ org: "acme" })],
      githubSecrets: [
        secret({
          org: "acme",
          name: "GCP_SA_KEY",
          looksLikeCloudCredential: true,
          matchedPattern: "gcp-key",
        }),
      ],
    },
    context as BuildCtx,
  );
  const written = getWrittenResources();

  assertEquals(written.filter((r) => r.specName === "trust_domain").length, 2);
  assertEquals(written.filter((r) => r.specName === "trust_edge").length, 1);

  const inventory = written.find((r) => r.specName === "inventory")!.data;
  assertEquals(inventory.edgeCount, 1);
  assertEquals(inventory.ephemeralPct, 0);
  assertEquals((inventory.byCredentialType as Record<string, number>)["github-secret"], 1);
});

// ---------------------------------------------------------------------------
// extractRepoOwners
// ---------------------------------------------------------------------------

Deno.test("extractRepoOwners parses the common attribute-condition forms", () => {
  assertEquals(
    extractRepoOwners("assertion.repository_owner == 'acme'"),
    ["acme"],
  );
  assertEquals(
    extractRepoOwners("assertion.repository_owner in ['acme', 'beta']").sort(),
    ["acme", "beta"],
  );
  assertEquals(
    extractRepoOwners("assertion.repository == 'acme/web'"),
    ["acme"],
  );
  assertEquals(extractRepoOwners("assertion.aud == 'sts'"), []);
  assertEquals(extractRepoOwners(null), []);
});

// ---------------------------------------------------------------------------
// deriveGcpSlice
// ---------------------------------------------------------------------------

function wifProvider(over: Partial<GcpWifProvider>): GcpWifProvider {
  return {
    project: "proj-1",
    poolId: "gh-pool",
    providerId: "gh-provider",
    name:
      "projects/1/locations/global/workloadIdentityPools/gh-pool/providers/gh-provider",
    displayName: null,
    state: "ACTIVE",
    disabled: false,
    providerKind: "oidc",
    issuerUri: "https://token.actions.githubusercontent.com",
    allowedAudiences: [],
    awsAccountId: null,
    attributeMapping: {},
    attributeCondition: "assertion.repository_owner == 'acme'",
    observedAt: NOW,
    ...over,
  };
}

function serviceAccount(over: Partial<GcpServiceAccount>): GcpServiceAccount {
  return {
    project: "proj-1",
    email: "deployer@proj-1.iam.gserviceaccount.com",
    uniqueId: "111",
    displayName: null,
    disabled: false,
    impersonators: [],
    observedAt: NOW,
    ...over,
  };
}

function saKey(over: Partial<GcpSaKey>): GcpSaKey {
  return {
    project: "proj-1",
    serviceAccountEmail: "deployer@proj-1.iam.gserviceaccount.com",
    keyId: "key-abc",
    name: "projects/proj-1/serviceAccounts/deployer/keys/key-abc",
    keyType: "USER_MANAGED",
    keyOrigin: null,
    validAfter: null,
    validBefore: null,
    disabled: false,
    observedAt: NOW,
    ...over,
  };
}

const POOL_MEMBER =
  "principalSet://iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/gh-pool/attribute.repository_owner/acme";

Deno.test("deriveGcpSlice correlates a GitHub-conditioned WIF edge to an org", () => {
  const { domains, edges } = deriveGcpSlice(
    [],
    [wifProvider({})],
    [
      serviceAccount({
        impersonators: [
          { member: POOL_MEMBER, role: "roles/iam.workloadIdentityUser" },
        ],
      }),
    ],
    [],
    NOW,
  );
  assertEquals(edges.length, 1);
  const edge = edges[0];
  assertEquals(edge.credentialType, "oidc-federation");
  assertEquals(edge.ephemeral, true);
  assertEquals(edge.sourceDomainId, "github:org/acme");
  assertEquals(edge.conditionalAccess.present, true);
  assertEquals(edge.findings.length, 0);
  assertEquals(domains.some((d) => d.id === "github:org/acme"), true);
  assertEquals(domains.some((d) => d.id === "gcp:project/proj-1"), true);
});

Deno.test("deriveGcpSlice flags a WIF provider with no attribute condition", () => {
  const { edges } = deriveGcpSlice(
    [],
    [wifProvider({ attributeCondition: null })],
    [],
    [],
    NOW,
  );
  assertEquals(edges.length, 1);
  const codes = edges[0].findings.map((f) => f.code).sort();
  assertEquals(codes, ["WIF_GITHUB_NO_ORG_PIN", "WIF_NO_ATTRIBUTE_CONDITION"]);
  assertEquals(edges[0].conditionalAccess.present, false);
});

Deno.test("deriveGcpSlice emits a sa-key edge for a user-managed key", () => {
  const { edges } = deriveGcpSlice([], [], [], [saKey({})], NOW);
  assertEquals(edges.length, 1);
  assertEquals(edges[0].credentialType, "sa-key");
  assertEquals(edges[0].ephemeral, false);
  assertEquals(edges[0].findings[0].code, "GCP_USER_MANAGED_SA_KEY");
});

Deno.test("build correlates GitHub and GCP into one graph", async () => {
  const { context, getWrittenResources } = createModelTestContext({});
  await model.methods.build.execute(
    {
      gcpWifProviders: [wifProvider({})],
      gcpServiceAccounts: [
        serviceAccount({
          impersonators: [
            { member: POOL_MEMBER, role: "roles/iam.workloadIdentityUser" },
          ],
        }),
      ],
      gcpSaKeys: [saKey({})],
    },
    context as BuildCtx,
  );
  const inventory = getWrittenResources()
    .find((r) => r.specName === "inventory")!.data;
  assertEquals(inventory.edgeCount, 2);
  // One ephemeral oidc-federation edge of two total.
  assertEquals(inventory.ephemeralPct, 50);
});

// ---------------------------------------------------------------------------
// deriveCloudflareSlice
// ---------------------------------------------------------------------------

function cfApp(over: Partial<CfAccessApp>): CfAccessApp {
  return {
    accountId: "acct-1",
    appId: "app-1",
    name: "Internal Wiki",
    domain: "wiki.acme.com",
    type: "self_hosted",
    saasAuthType: null,
    allowedIdps: [],
    observedAt: NOW,
    ...over,
  };
}

function cfPolicy(over: Partial<CfAccessPolicy>): CfAccessPolicy {
  return {
    accountId: "acct-1",
    appId: "app-1",
    policyId: "pol-1",
    name: "Staff",
    decision: "allow",
    includeRuleTypes: [],
    requireRuleTypes: [],
    excludeRuleTypes: [],
    factors: [],
    allowsEveryone: false,
    observedAt: NOW,
    ...over,
  };
}

function cfIdp(over: Partial<CfIdentityProvider>): CfIdentityProvider {
  return {
    accountId: "acct-1",
    idpId: "idp-1",
    name: "Google Workspace",
    type: "google",
    issuerUri: null,
    observedAt: NOW,
    ...over,
  };
}

function cfToken(over: Partial<CfServiceToken>): CfServiceToken {
  return {
    accountId: "acct-1",
    tokenId: "tok-1",
    name: "CI deploy",
    clientId: "client-1",
    createdAt: NOW,
    expiresAt: null,
    durationDays: null,
    observedAt: NOW,
    ...over,
  };
}

Deno.test("deriveCloudflareSlice creates a federation edge per identity provider", () => {
  const { edges } = deriveCloudflareSlice([], [], [cfIdp({})], [], NOW);
  assertEquals(edges.length, 1);
  assertEquals(edges[0].credentialType, "oidc-federation");
  assertEquals(edges[0].ephemeral, true);
});

Deno.test("deriveCloudflareSlice flags an allow-everyone Access app", () => {
  const { edges } = deriveCloudflareSlice(
    [cfApp({})],
    [cfPolicy({ allowsEveryone: true })],
    [],
    [],
    NOW,
  );
  const appEdge = edges.find((e) => e.targetLabel.startsWith("Access app"))!;
  assertEquals(appEdge.findings[0].code, "CF_ACCESS_POLICY_ALLOW_ALL");
  assertEquals(appEdge.conditionalAccess.present, false);
});

Deno.test("deriveCloudflareSlice flags an Access app lacking a posture factor", () => {
  const { edges } = deriveCloudflareSlice(
    [cfApp({})],
    [cfPolicy({ factors: ["email-domain"] })],
    [],
    [],
    NOW,
  );
  const appEdge = edges.find((e) => e.targetLabel.startsWith("Access app"))!;
  assertEquals(appEdge.findings[0].code, "CF_ACCESS_NO_POSTURE");
});

Deno.test("deriveCloudflareSlice recognizes a posture-gated Access app", () => {
  const { edges } = deriveCloudflareSlice(
    [cfApp({})],
    [cfPolicy({ factors: ["device-posture", "mfa"] })],
    [],
    [],
    NOW,
  );
  const appEdge = edges.find((e) => e.targetLabel.startsWith("Access app"))!;
  assertEquals(appEdge.findings.length, 0);
  assertEquals(appEdge.conditionalAccess.present, true);
});

Deno.test("deriveCloudflareSlice flags a long-lived service token", () => {
  const open = deriveCloudflareSlice([], [], [], [cfToken({ durationDays: null })], NOW);
  assertEquals(open.edges[0].credentialType, "cf-service-token");
  assertEquals(open.edges[0].findings[0].code, "CF_SERVICE_TOKEN_NO_EXPIRY");

  const short = deriveCloudflareSlice([], [], [], [cfToken({ durationDays: 30 })], NOW);
  assertEquals(short.edges[0].findings.length, 0);
});

// ---------------------------------------------------------------------------
// assert_posture
// ---------------------------------------------------------------------------

/** A trust-graph inventory with overridable fields; clean by default. */
function inventory(over: Partial<TrustInventory>): TrustInventory {
  return {
    domainCount: 1,
    edgeCount: 4,
    byCredentialType: {},
    byPlatform: {},
    ephemeralEdgeCount: 4,
    ephemeralPct: 100,
    conditionalAccessEdgeCount: 4,
    conditionalAccessPct: 100,
    findingsBySeverity: {},
    notes: [],
    builtAt: NOW,
    ...over,
  };
}

Deno.test("assert_posture passes a clean inventory with default thresholds", async () => {
  const { context } = createModelTestContext({
    storedResources: { current: inventory({}) },
  });
  const result = await model.methods.assert_posture.execute(
    {},
    context as AssertCtx,
  );
  assertEquals(result, { dataHandles: [] });
});

Deno.test("assert_posture fails on a critical finding", async () => {
  const { context } = createModelTestContext({
    storedResources: {
      current: inventory({ findingsBySeverity: { critical: 1 } }),
    },
  });
  const err = await assertRejects(
    () => model.methods.assert_posture.execute({}, context as AssertCtx),
    Error,
  );
  assertStringIncludes(err.message, "critical findings: 1");
});

Deno.test("assert_posture fails on a high finding", async () => {
  const { context } = createModelTestContext({
    storedResources: {
      current: inventory({ findingsBySeverity: { high: 2 } }),
    },
  });
  const err = await assertRejects(
    () => model.methods.assert_posture.execute({}, context as AssertCtx),
    Error,
  );
  assertStringIncludes(err.message, "high findings: 2");
});

Deno.test("assert_posture fails when ephemeral coverage is below the floor", async () => {
  const { context } = createModelTestContext({
    storedResources: { current: inventory({ ephemeralPct: 40 }) },
  });
  const err = await assertRejects(
    () =>
      model.methods.assert_posture.execute(
        { minEphemeralPct: 80 },
        context as AssertCtx,
      ),
    Error,
  );
  assertStringIncludes(err.message, "ephemeral-credential coverage: 40%");
});

Deno.test("assert_posture fails when conditional-access coverage is below the floor", async () => {
  const { context } = createModelTestContext({
    storedResources: { current: inventory({ conditionalAccessPct: 50 }) },
  });
  const err = await assertRejects(
    () =>
      model.methods.assert_posture.execute(
        { minConditionalAccessPct: 90 },
        context as AssertCtx,
      ),
    Error,
  );
  assertStringIncludes(err.message, "conditional-access coverage: 50%");
});

Deno.test("assert_posture lists every breach when multiple thresholds fail", async () => {
  const { context } = createModelTestContext({
    storedResources: {
      current: inventory({
        findingsBySeverity: { critical: 2, high: 1 },
        ephemeralPct: 10,
      }),
    },
  });
  const err = await assertRejects(
    () =>
      model.methods.assert_posture.execute(
        { minEphemeralPct: 50 },
        context as AssertCtx,
      ),
    Error,
  );
  assertStringIncludes(err.message, "3 threshold(s) breached");
  assertStringIncludes(err.message, "critical findings: 2");
  assertStringIncludes(err.message, "high findings: 1");
  assertStringIncludes(err.message, "ephemeral-credential coverage: 10%");
});

Deno.test("assert_posture throws when no inventory has been built", async () => {
  const { context } = createModelTestContext({});
  const err = await assertRejects(
    () => model.methods.assert_posture.execute({}, context as AssertCtx),
    Error,
  );
  assertStringIncludes(err.message, "run `graph build` first");
});

Deno.test("assert_posture honors the maxMedium threshold", async () => {
  // Mediums pass by default — maxMedium is unbounded.
  const lenient = createModelTestContext({
    storedResources: {
      current: inventory({ findingsBySeverity: { medium: 5 } }),
    },
  });
  assertEquals(
    await model.methods.assert_posture.execute({}, lenient.context as AssertCtx),
    { dataHandles: [] },
  );
  // ...but fail once maxMedium is tightened below the count.
  const strict = createModelTestContext({
    storedResources: {
      current: inventory({ findingsBySeverity: { medium: 5 } }),
    },
  });
  const err = await assertRejects(
    () =>
      model.methods.assert_posture.execute(
        { maxMedium: 2 },
        strict.context as AssertCtx,
      ),
    Error,
  );
  assertStringIncludes(err.message, "medium findings: 5");
});
