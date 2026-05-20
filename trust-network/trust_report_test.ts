/**
 * Unit tests for `@mccormick/trust-network/posture`.
 *
 * Exercises the pure `renderPosture` renderer; the thin `execute` wrapper is
 * verified end-to-end in the swamp smoke test.
 */
import { assertEquals, assertStringIncludes } from "jsr:@std/assert@1";
import { renderPosture } from "./shared/graph.ts";
import {
  type TrustDomain,
  type TrustEdge,
  type TrustInventory,
} from "./shared/schema.ts";

const NOW = "2026-05-19T00:00:00Z";

function inventory(over: Partial<TrustInventory>): TrustInventory {
  return {
    domainCount: 0,
    edgeCount: 0,
    byCredentialType: {},
    byPlatform: {},
    ephemeralEdgeCount: 0,
    ephemeralPct: 100,
    conditionalAccessEdgeCount: 0,
    conditionalAccessPct: 100,
    findingsBySeverity: {},
    notes: [],
    builtAt: NOW,
    ...over,
  };
}

function edge(over: Partial<TrustEdge>): TrustEdge {
  return {
    id: "edge-1",
    sourceDomainId: "github:org/acme",
    sourceLabel: "repo acme/web",
    sourceIssuer: "static",
    targetDomainId: "external:unknown-cloud",
    targetLabel: 'secret "AWS_ACCESS_KEY_ID"',
    audience: [],
    subjectPattern: null,
    claimConditions: null,
    credentialType: "github-secret",
    ephemeral: false,
    conditionalAccess: { present: false, factors: [] },
    permissions: [],
    findings: [],
    discoveredAt: NOW,
    ...over,
  };
}

const DOMAIN: TrustDomain = {
  id: "github:org/acme",
  platform: "github",
  kind: "org",
  displayName: "GitHub org acme",
  issuerUri: "https://token.actions.githubusercontent.com",
  discoveredAt: NOW,
};

Deno.test("renderPosture renders the scorecard and grouped findings", () => {
  const edges = [
    edge({
      findings: [{
        code: "GITHUB_STATIC_CLOUD_CREDENTIAL",
        severity: "high",
        title: "Static cloud credential stored in GitHub Actions",
        detail: "repo acme/web holds a static credential.",
        recommendation: "Replace with OIDC federation.",
      }],
    }),
  ];
  const { markdown, json } = renderPosture(
    inventory({
      domainCount: 2,
      edgeCount: 1,
      byCredentialType: { "github-secret": 1 },
      byPlatform: { github: 1, external: 1 },
      ephemeralPct: 0,
      conditionalAccessPct: 0,
      findingsBySeverity: { high: 1 },
    }),
    edges,
    [DOMAIN],
  );

  assertStringIncludes(markdown, "# Trust Network Posture");
  assertStringIncludes(markdown, "## Scorecard");
  assertStringIncludes(markdown, "Ephemeral credentials:** 0%");
  assertStringIncludes(markdown, "## Findings (1)");
  assertStringIncludes(markdown, "### HIGH (1)");
  assertStringIncludes(markdown, "GITHUB_STATIC_CLOUD_CREDENTIAL");
  assertStringIncludes(markdown, "repo acme/web");

  assertEquals(json.scorecard.edgeCount, 1);
  assertEquals(json.scorecard.ephemeralPct, 0);
  assertEquals(json.findings.length, 1);
  assertEquals(json.findings[0].code, "GITHUB_STATIC_CLOUD_CREDENTIAL");
  assertEquals(json.findings[0].source, "repo acme/web");
});

Deno.test("renderPosture handles a clean, empty graph", () => {
  const { markdown, json } = renderPosture(inventory({}), [], []);
  assertStringIncludes(markdown, "No findings");
  assertEquals(json.scorecard.edgeCount, 0);
  assertEquals(json.findings.length, 0);
});

Deno.test("renderPosture surfaces correlation notes", () => {
  const { markdown } = renderPosture(
    inventory({ notes: ["skipped malformed github secret: schema mismatch"] }),
    [],
    [],
  );
  assertStringIncludes(markdown, "## Scan notes");
  assertStringIncludes(markdown, "skipped malformed github secret");
});
