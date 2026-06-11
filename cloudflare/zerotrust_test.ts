/**
 * Unit tests for `@mccormick/cloudflare/zerotrust`.
 *
 * Covers the pure helpers (`ruleType`, `normalizeAccessPolicy`,
 * `computeDurationDays`) and an end-to-end `scan` against a stubbed `fetch`
 * injected into the Cloudflare SDK client.
 */
import { assertEquals } from "jsr:@std/assert@1";
import { createModelTestContext } from "jsr:@systeminit/swamp-testing@0.20260519.14";
import { __setCloudflareFetch, model } from "./zerotrust.ts";
import {
  computeDurationDays,
  normalizeAccessPolicy,
  ruleType,
} from "./policy.ts";

type ScanCtx = Parameters<typeof model.methods.scan.execute>[1];

// ---------------------------------------------------------------------------
// ruleType
// ---------------------------------------------------------------------------

Deno.test("ruleType returns the rule's single key", () => {
  assertEquals(ruleType({ everyone: {} }), "everyone");
  assertEquals(ruleType({ email: { email: "x@y.com" } }), "email");
  assertEquals(ruleType({}), "unknown");
});

// ---------------------------------------------------------------------------
// normalizeAccessPolicy
// ---------------------------------------------------------------------------

Deno.test("normalizeAccessPolicy flags an unrestricted allow-everyone policy", () => {
  const policy = normalizeAccessPolicy(
    { id: "p1", name: "Open", decision: "allow", include: [{ everyone: {} }] },
    "acct-1",
    "app-1",
  );
  assertEquals(policy.allowsEveryone, true);
  assertEquals(policy.factors, []);
});

Deno.test("normalizeAccessPolicy is not allow-everyone when a require rule constrains it", () => {
  const policy = normalizeAccessPolicy(
    {
      id: "p2",
      name: "Posture",
      decision: "allow",
      include: [{ everyone: {} }],
      require: [{ device_posture: { integration_uid: "x" } }],
    },
    "acct-1",
    "app-1",
  );
  assertEquals(policy.allowsEveryone, false);
  assertEquals(policy.factors, ["device-posture"]);
});

Deno.test("normalizeAccessPolicy maps rule types to conditional-access factors", () => {
  const policy = normalizeAccessPolicy(
    {
      id: "p3",
      name: "Staff",
      decision: "allow",
      include: [{ email_domain: { domain: "acme.com" } }],
      require: [{ auth_method: { auth_method: "mfa" } }],
    },
    "acct-1",
    "app-1",
  );
  assertEquals(policy.allowsEveryone, false);
  assertEquals(policy.factors, ["email-domain", "mfa"]);
  assertEquals(policy.includeRuleTypes, ["email_domain"]);
  assertEquals(policy.requireRuleTypes, ["auth_method"]);
});

// ---------------------------------------------------------------------------
// computeDurationDays
// ---------------------------------------------------------------------------

Deno.test("computeDurationDays measures token lifetime", () => {
  assertEquals(
    computeDurationDays("2026-01-01T00:00:00Z", "2027-01-01T00:00:00Z"),
    365,
  );
});

Deno.test("computeDurationDays returns null for a non-expiring token", () => {
  assertEquals(computeDurationDays("2026-01-01T00:00:00Z", null), null);
  assertEquals(computeDurationDays(null, null), null);
  assertEquals(computeDurationDays("2026-01-01T00:00:00Z", "not-a-date"), null);
});

// ---------------------------------------------------------------------------
// fetch stub
// ---------------------------------------------------------------------------

interface Route {
  match: (path: string) => boolean;
  body: unknown;
}

/** Wrap a result array in the Cloudflare API v4 envelope. */
function envelope(result: unknown[]): unknown {
  return {
    success: true,
    errors: [],
    messages: [],
    result,
    result_info: {
      page: 1,
      per_page: 1000,
      count: result.length,
      total_count: result.length,
      total_pages: 1,
    },
  };
}

function jsonResponse(body: unknown, status: number): Promise<Response> {
  return Promise.resolve(
    new Response(JSON.stringify(body), {
      status,
      headers: { "content-type": "application/json" },
    }),
  );
}

/** A `fetch` stub routed by a pathname predicate; install via `__setCloudflareFetch`. */
function stubFetch(routes: Route[]): typeof fetch {
  return ((input: string | URL | Request): Promise<Response> => {
    const href = typeof input === "string"
      ? input
      : input instanceof URL
      ? input.href
      : input.url;
    const url = new URL(href);
    // The SDK auto-paginates; serve an empty page beyond page 1 to terminate.
    if (Number(url.searchParams.get("page") ?? "1") > 1) {
      return jsonResponse(envelope([]), 200);
    }
    const route = routes.find((r) => r.match(url.pathname));
    if (!route) {
      return jsonResponse(
        { success: false, errors: [{ code: 7003, message: "no route" }] },
        404,
      );
    }
    return jsonResponse(route.body, 200);
  }) as typeof fetch;
}

const SCAN_ROUTES: Route[] = [
  {
    match: (p) => p.endsWith("/policies"),
    body: envelope([
      { id: "pol-open", name: "Open", decision: "allow", include: [{ everyone: {} }] },
      {
        id: "pol-staff",
        name: "Staff",
        decision: "allow",
        include: [{ email_domain: { domain: "acme.com" } }],
        require: [{ auth_method: { auth_method: "mfa" } }],
      },
    ]),
  },
  {
    match: (p) => p.endsWith("/apps"),
    body: envelope([
      {
        id: "app-1",
        name: "Internal Wiki",
        domain: "wiki.acme.com",
        type: "self_hosted",
      },
    ]),
  },
  {
    match: (p) => p.endsWith("/identity_providers"),
    body: envelope([{ id: "idp-1", name: "Google Workspace", type: "google" }]),
  },
  {
    match: (p) => p.endsWith("/service_tokens"),
    body: envelope([
      {
        id: "tok-1",
        name: "CI deploy",
        client_id: "client-1",
        created_at: "2026-01-01T00:00:00Z",
        expires_at: "2027-01-01T00:00:00Z",
      },
      { id: "tok-2", name: "Legacy", created_at: "2026-01-01T00:00:00Z" },
    ]),
  },
  { match: (p) => p.endsWith("/certificates"), body: envelope([]) },
];

// ---------------------------------------------------------------------------
// scan
// ---------------------------------------------------------------------------

Deno.test("scan discovers apps, policies, idps, and service tokens", async () => {
  __setCloudflareFetch(stubFetch(SCAN_ROUTES));
  try {
    const { context, getWrittenResources } = createModelTestContext({
      globalArgs: {
        accountIds: ["acct-1"],
        cloudflareToken: "cf-token",
        apiBaseUrl: "https://api.cloudflare.com/client/v4",
      },
    });
    await model.methods.scan.execute({}, context as unknown as ScanCtx);
    const written = getWrittenResources();
    const bySpec = (spec: string) => written.filter((r) => r.specName === spec);

    assertEquals(bySpec("access_app").length, 1);
    assertEquals(bySpec("access_policy").length, 2);
    assertEquals(bySpec("identity_provider").length, 1);
    assertEquals(bySpec("service_token").length, 2);
    assertEquals(bySpec("mtls_cert").length, 0);
    assertEquals(bySpec("access_summary").length, 1);

    const open = bySpec("access_policy").find((r) => r.data.policyId === "pol-open");
    assertEquals(open?.data.allowsEveryone, true);

    const ci = bySpec("service_token").find((r) => r.data.tokenId === "tok-1");
    assertEquals(ci?.data.durationDays, 365);
    const legacy = bySpec("service_token").find((r) => r.data.tokenId === "tok-2");
    assertEquals(legacy?.data.durationDays, null);

    const summary = bySpec("access_summary")[0].data;
    assertEquals(summary.targetsScanned, 1);
    assertEquals(summary.targetsFailed, 0);
  } finally {
    __setCloudflareFetch(undefined);
  }
});

Deno.test("scan records a note when an account is inaccessible", async () => {
  __setCloudflareFetch(stubFetch([])); // every request 404s
  try {
    const { context, getWrittenResources } = createModelTestContext({
      globalArgs: {
        accountIds: ["acct-x"],
        cloudflareToken: "cf-token",
        apiBaseUrl: "https://api.cloudflare.com/client/v4",
      },
    });
    await model.methods.scan.execute({}, context as unknown as ScanCtx);
    const summary = getWrittenResources()
      .find((r) => r.specName === "access_summary")!.data;
    assertEquals(summary.targetsScanned, 0);
    assertEquals(summary.targetsFailed, 1);
    assertEquals((summary.notes as string[]).length, 1);
  } finally {
    __setCloudflareFetch(undefined);
  }
});
