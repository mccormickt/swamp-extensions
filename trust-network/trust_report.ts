/**
 * `@mccormick/trust-network/posture` — trust-graph posture report.
 *
 * A model-scope report keyed to the `graph` model's `build` method: it scores
 * the graph `build` produces — reading the `inventory`, `trust_edge`, and
 * `trust_domain` resources `build` wrote — into a scorecard of ephemeral- and
 * conditional-access coverage plus a severity-grouped finding list. The graph
 * model also carries the `assert_posture` gate method, which produces no
 * graph; after any method other than `build` the report returns a brief
 * not-applicable note. Rendering lives in
 * [`shared/graph.ts`](./shared/graph.ts).
 *
 * @module
 */
import {
  type TrustDomain,
  type TrustEdge,
  type TrustInventory,
} from "./shared/schema.ts";
import { renderPosture } from "./shared/graph.ts";

// Minimal structural typings for the model report context, declared locally
// rather than imported from the swamp testing package so the registry scorer's
// `deno doc` never needs to resolve a JSR dependency (the convention the pulled
// `@stateless/proxmox` model follows). The testing package is still used in
// `*_test.ts`, which the scorer does not document.
interface ReportDataHandle {
  specName: string;
  name: string;
  version: number;
}
interface ModelReportContext {
  modelType: string;
  modelId: string;
  methodName: string;
  dataHandles: ReportDataHandle[];
  dataRepository: {
    getContent(
      modelType: string,
      modelId: string,
      name: string,
      version: number,
    ): Promise<Uint8Array | null>;
  };
}

type DataHandle = ModelReportContext["dataHandles"][number];

/** Read and JSON-parse one resource referenced by a data handle. */
async function readHandle(
  context: ModelReportContext,
  handle: DataHandle,
): Promise<Record<string, unknown> | null> {
  const raw = await context.dataRepository.getContent(
    context.modelType,
    context.modelId,
    handle.name,
    handle.version,
  );
  if (!raw) return null;
  try {
    return JSON.parse(new TextDecoder().decode(raw)) as Record<string, unknown>;
  } catch {
    return null;
  }
}

/**
 * `@mccormick/trust-network/posture` — scores the trust graph produced by the
 * `graph` model and lists findings by severity.
 */
export const report = {
  name: "@mccormick/trust-network/posture",
  description:
    "Scores the trust graph: share of edges using ephemeral credentials, " +
    "share gated by conditional access, and a severity-ranked finding list.",
  scope: "model",
  labels: ["security", "identity", "trust", "audit"],
  execute: async (
    context: ModelReportContext,
  ): Promise<{ markdown: string; json: unknown }> => {
    // Posture scoring applies only to the `build` method's output. The graph
    // model also carries the `assert_posture` gate, which produces no graph —
    // skip cleanly so the report is, in effect, scoped to `build`.
    if (context.methodName !== "build") {
      const method = context.methodName || "(no method)";
      return {
        markdown: "# Trust Network Posture\n\n" +
          "This report scores the trust graph produced by " +
          "`@mccormick/trust-network/graph build`. It does not apply to " +
          `\`${method}\`.`,
        json: { skipped: true, methodName: context.methodName },
      };
    }

    const handles = context.dataHandles ?? [];
    const inventoryHandle = handles.find((h) => h.specName === "inventory");
    if (!inventoryHandle) {
      return {
        markdown:
          "# Trust Network Posture\n\nNo trust-graph inventory found — " +
          "run `@mccormick/trust-network/graph build` first.",
        json: { error: "no inventory" },
      };
    }

    const inventory = await readHandle(context, inventoryHandle) as
      | TrustInventory
      | null;
    if (!inventory) {
      return {
        markdown:
          "# Trust Network Posture\n\nInventory resource was unreadable.",
        json: { error: "inventory unreadable" },
      };
    }

    const edges: TrustEdge[] = [];
    for (const handle of handles.filter((h) => h.specName === "trust_edge")) {
      const edge = await readHandle(context, handle);
      if (edge) edges.push(edge as unknown as TrustEdge);
    }
    const domains: TrustDomain[] = [];
    for (const handle of handles.filter((h) => h.specName === "trust_domain")) {
      const domain = await readHandle(context, handle);
      if (domain) domains.push(domain as unknown as TrustDomain);
    }

    return renderPosture(inventory, edges, domains);
  },
};
