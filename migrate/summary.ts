/**
 * `@mccormick/migrate/summary` — migration run report.
 *
 * A workflow-scoped report `reports.require`'d by the `migrate-vm` workflow. It
 * reads, by spec name, the resources the run produced across all its steps —
 * the Proxmox `vm_spec`, the TrueNAS `zvol`/`vm_instance`/`vm_device`, the
 * `transfer`, the `guest_netprep`/`guest_disk_edit`, and the `verify` — and
 * renders a markdown report plus a JSON roll-up so the outcome is captured from
 * whatever succeeded, even on a partial run.
 *
 * Joining and rendering live in [`summary_render.ts`](./summary_render.ts).
 *
 * @module
 */
import type { WorkflowReportContext } from "jsr:@systeminit/swamp-testing@0.20260519.14";
import {
  type Collected,
  emptyCollected,
  renderMigrationSummary,
} from "./summary_render.ts";

type StepExecution = WorkflowReportContext["stepExecutions"][number];
type DataHandle = StepExecution["dataHandles"][number];

/** Spec names this report consumes. */
const COLLECT: Record<string, keyof Collected | "vm_spec"> = {
  vm_spec: "vm_spec",
  zvol: "zvols",
  vm_instance: "vmInstances",
  vm_device: "vmDevices",
  transfer: "transfers",
  guest_netprep: "netpreps",
  guest_disk_edit: "diskEdits",
  verify: "verifies",
};

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

/** `@mccormick/migrate/summary` — renders a VM migration run summary. */
export const report = {
  name: "@mccormick/migrate/summary",
  description:
    "VM migration run summary: joins the Proxmox vm_spec, TrueNAS zvol/VM/" +
    "device, disk transfer, network-prep, and verify resources into a " +
    "markdown report (source→target, firmware, bytes verified, MAC preserved, " +
    "reachability, rollback hint).",
  scope: "workflow",
  labels: ["migration", "virtualization", "summary"],
  execute: async (
    context: WorkflowReportContext,
  ): Promise<{ markdown: string; json: Record<string, unknown> }> => {
    const c = emptyCollected();
    for (const step of context.stepExecutions) {
      if (step.status !== "succeeded") continue;
      for (const handle of step.dataHandles) {
        const target = COLLECT[handle.specName];
        if (!target) continue;
        const data = await readHandle(context, step, handle);
        if (!data) continue;
        if (target === "vm_spec") {
          c.vmSpec = data; // last writer wins (one spec per run)
        } else {
          (c[target] as Record<string, unknown>[]).push(data);
        }
      }
    }
    return renderMigrationSummary(c, {
      workflow: context.workflowName,
      workflowStatus: context.workflowStatus,
    });
  },
};
