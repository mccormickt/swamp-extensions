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
import {
  type FleetRow,
  renderFleet,
  rowFor,
  SPEC_TO_HYPERVISOR,
} from "./render.ts";

// Minimal structural typings for the workflow report context, declared locally
// rather than imported from the swamp testing package so the registry scorer's
// `deno doc` never needs to resolve a JSR dependency (the convention the pulled
// `@stateless/proxmox` model follows). The testing package is still used in
// `*_test.ts`, which the scorer does not document.
interface ReportDataHandle {
  specName: string;
  name: string;
  version: number;
}
interface StepExecution {
  status: string;
  modelType: string;
  modelId: string;
  dataHandles: ReportDataHandle[];
}
interface WorkflowReportContext {
  workflowName: string;
  workflowStatus: string;
  stepExecutions: StepExecution[];
  dataRepository: {
    getContent(
      modelType: string,
      modelId: string,
      name: string,
      version: number,
    ): Promise<Uint8Array | null>;
  };
}

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
