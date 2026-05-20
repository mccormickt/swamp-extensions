/**
 * `@mccormick/trust-network/posture` — trust-graph posture report.
 *
 * A model-scope report: it runs after `@mccormick/trust-network/graph build`
 * and reads the `inventory`, `trust_edge`, and `trust_domain` resources that
 * `build` just wrote. It produces a scorecard — the share of trust edges
 * backed by ephemeral credentials and the share gated by conditional access —
 * and a severity-grouped list of findings. Rendering lives in
 * [`shared/graph.ts`](./shared/graph.ts).
 *
 * @module
 */
import type { ModelReportContext } from "jsr:@systeminit/swamp-testing@0.20260519.14";
import {
  type TrustDomain,
  type TrustEdge,
  type TrustInventory,
} from "./shared/schema.ts";
import { renderPosture } from "./shared/graph.ts";

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
