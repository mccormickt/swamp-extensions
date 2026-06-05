/**
 * `@mccormick/fleet/inventory` — cross-hypervisor fleet report.
 *
 * A workflow-scoped report that joins the per-hypervisor inventory steps of a
 * fleet workflow into one view. It reads each step's written resources by spec
 * name — `node` (Omni/Talos), `guest` (Proxmox QEMU), and `vm` (TrueNAS) —
 * normalizes them onto flat rows sharing the `name`/`state`/`vcpus`/`memoryMib`
 * contract, and renders a markdown table plus JSON totals. Steps that failed or
 * produced only `summary`/`cluster`/`exec` resources contribute nothing.
 *
 * Normalization and rendering live in [`render.ts`](./render.ts).
 *
 * @module
 */
import type { WorkflowReportContext } from "jsr:@systeminit/swamp-testing@0.20260519.14";
import {
  type FleetRow,
  renderFleet,
  rowFor,
  SPEC_TO_HYPERVISOR,
} from "./render.ts";

type StepExecution = WorkflowReportContext["stepExecutions"][number];
type DataHandle = StepExecution["dataHandles"][number];

/** Read and JSON-parse one resource produced by a workflow step. */
async function readHandle(
  context: WorkflowReportContext,
  step: StepExecution,
  handle: DataHandle,
): Promise<Record<string, unknown> | null> {
  const raw = await context.dataRepository.getContent(
    step.modelType,
    step.modelId,
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
 * `@mccormick/fleet/inventory` — renders a cross-hypervisor VM table from the
 * inventory steps of a fleet workflow.
 */
export const report = {
  name: "@mccormick/fleet/inventory",
  description:
    "Cross-hypervisor VM inventory: joins Omni (Talos), Proxmox, and TrueNAS " +
    "guest resources from a fleet workflow into one markdown table and JSON " +
    "totals.",
  scope: "workflow",
  labels: ["inventory", "fleet", "virtualization"],
  execute: async (
    context: WorkflowReportContext,
  ): Promise<{ markdown: string; json: Record<string, unknown> }> => {
    const rows: FleetRow[] = [];
    let skippedSteps = 0;

    for (const step of context.stepExecutions) {
      if (step.status !== "succeeded") {
        skippedSteps += 1;
        continue;
      }
      for (const handle of step.dataHandles) {
        const specName = handle.specName;
        if (!(specName in SPEC_TO_HYPERVISOR)) continue;
        const data = await readHandle(context, step, handle);
        if (!data) continue;
        const row = rowFor(specName, data, step.modelType);
        if (row) rows.push(row);
      }
    }

    const { markdown, json } = renderFleet(rows);
    return {
      markdown,
      json: {
        ...json,
        workflow: context.workflowName,
        workflowStatus: context.workflowStatus,
        skippedSteps,
      },
    };
  },
};
