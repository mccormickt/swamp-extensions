/**
 * `@mccormick/migrate/summary` — pure rendering of a migration run report.
 *
 * Joins the resources a `migrate-vm` run produces — the Proxmox `vm_spec`, the
 * TrueNAS `zvol`/`vm_instance`/`vm_device`, the `transfer`, the `guest_netprep`
 * or `guest_disk_edit`, and the `verify` — into a markdown report and JSON
 * roll-up: source→target, firmware mapping, bytes streamed/verified, MAC
 * preserved, net-prep method, reachability, and a rollback hint. Pure (no I/O),
 * so it is unit-tested directly; the report shell does the resource reads.
 *
 * @module
 */

/** The resources collected from a migration run, grouped by spec. */
export interface Collected {
  vmSpec: Record<string, unknown> | null;
  zvols: Record<string, unknown>[];
  vmInstances: Record<string, unknown>[];
  vmDevices: Record<string, unknown>[];
  transfers: Record<string, unknown>[];
  netpreps: Record<string, unknown>[];
  diskEdits: Record<string, unknown>[];
  verifies: Record<string, unknown>[];
}

/** An empty {@link Collected} to accumulate into. */
export function emptyCollected(): Collected {
  return {
    vmSpec: null,
    zvols: [],
    vmInstances: [],
    vmDevices: [],
    transfers: [],
    netpreps: [],
    diskEdits: [],
    verifies: [],
  };
}

function s(v: unknown): string | null {
  return typeof v === "string" && v !== "" ? v : null;
}
function n(v: unknown): number | null {
  return typeof v === "number" && Number.isFinite(v) ? v : null;
}
function yesNo(v: unknown): string {
  return v === true ? "yes" : v === false ? "no" : "—";
}
function cell(v: unknown): string {
  if (v === null || v === undefined || v === "") return "—";
  return String(v);
}
function fmtBytes(bytes: number | null): string {
  if (bytes === null) return "—";
  const gib = bytes / 1024 ** 3;
  return gib >= 1 ? `${gib.toFixed(1)} GiB (${bytes} B)` : `${bytes} B`;
}

/** The expected TrueNAS bootloader for a Proxmox firmware value. */
export function firmwareToBootloader(firmware: string | null): string {
  return firmware === "ovmf" ? "UEFI" : "UEFI_CSM";
}

/** Render a migration run into markdown + a JSON roll-up. */
export function renderMigrationSummary(
  c: Collected,
  meta: { workflow?: string; workflowStatus?: string } = {},
): { markdown: string; json: Record<string, unknown> } {
  const spec = c.vmSpec ?? {};
  const vmInstance = c.vmInstances[0] ?? {};
  const transfer = c.transfers[0] ?? {};
  const netprep = c.netpreps[0] ?? {};
  const diskEdit = c.diskEdits[0] ?? {};
  const verify = c.verifies[0] ?? {};

  const srcName = s(spec.name) ?? "—";
  const srcNode = s(spec.node) ?? "—";
  const targetName = s(vmInstance.name) ?? s(transfer.dstHost) ?? "—";
  const srcMac = (() => {
    const nics = Array.isArray(spec.nics) ? spec.nics : [];
    const first = nics[0] as Record<string, unknown> | undefined;
    return first ? s(first.mac) : null;
  })();
  const targetMac = (() => {
    const nic = c.vmDevices.find((d) => s(d.kind) === "NIC");
    return nic ? s(nic.mac) : null;
  })();
  const macPreserved = srcMac !== null && targetMac !== null &&
    srcMac.toLowerCase() === targetMac.toLowerCase();

  const firmware = s(spec.firmware);
  const bootloader = s(vmInstance.bootloader);
  const expectedBootloader = firmwareToBootloader(firmware);

  const bytesWritten = n(transfer.bytesWritten);
  const expectedBytes = n(transfer.expectedBytes);
  const transferVerified = transfer.verified === true;

  // Net-prep: agent path (netprep.applied) wins; else the offline disk edit.
  const netMethod = netprep.applied === true
    ? `agent (${s(netprep.method) ?? "agent"})`
    : diskEdit.applied === true
    ? `offline (${s(diskEdit.mode) ?? "nbd"})`
    : netprep.agentPresent === false
    ? "none applied (agent absent)"
    : "none applied";

  const reachable = verify.reachable === true;
  const verifyKnown = c.verifies.length > 0;

  const lines: string[] = [];
  lines.push("# VM Migration Summary");
  lines.push("");
  if (meta.workflow) {
    lines.push(
      `Workflow **${meta.workflow}** — status **${
        meta.workflowStatus ?? "unknown"
      }**.`,
    );
    lines.push("");
  }
  lines.push("| Field | Value |");
  lines.push("| ----- | ----- |");
  lines.push(
    `| Source | ${cell(srcName)} (vmid ${cell(n(spec.vmid))} on ${
      cell(srcNode)
    }) |`,
  );
  lines.push(`| Target | ${cell(targetName)} |`);
  lines.push(
    `| vCPUs / Memory | ${cell(n(spec.vcpus))} / ${
      cell(n(spec.memoryMib))
    } MiB |`,
  );
  lines.push(
    `| Firmware → Bootloader | ${cell(firmware)} → ${cell(bootloader)} ` +
      `(expected ${expectedBootloader}) |`,
  );
  lines.push(
    `| EFI vars disk | ${yesNo(spec.hasEfiDisk)}${
      spec.hasEfiDisk ? " ⚠ stream/recreate efidisk0" : ""
    } |`,
  );
  lines.push(
    `| Disk streamed | ${fmtBytes(bytesWritten)} of ${
      fmtBytes(expectedBytes)
    } ` +
      `(${cell(s(transfer.mode))} mode) |`,
  );
  lines.push(`| Bytes verified | ${yesNo(transferVerified)} |`);
  lines.push(
    `| MAC preserved | ${yesNo(macPreserved)} (${cell(srcMac)} → ${
      cell(targetMac)
    }) |`,
  );
  lines.push(`| Network prep | ${cell(netMethod)} |`);
  lines.push(
    `| Reachable | ${verifyKnown ? yesNo(reachable) : "not checked"}` +
      `${verifyKnown ? ` (${cell(s(verify.ip))})` : ""} |`,
  );
  lines.push("");

  // Findings / warnings.
  const warnings: string[] = [];
  if (firmware && bootloader && bootloader !== expectedBootloader) {
    warnings.push(
      `Bootloader ${bootloader} does not match the expected ${expectedBootloader} ` +
        `for firmware ${firmware} (a firmwareOverride may have been used).`,
    );
  }
  if (!macPreserved) {
    warnings.push(
      "Source and target MAC differ — the cutover is NOT same-IP; a DNS flip " +
        "may be required.",
    );
  }
  if (c.transfers.length > 0 && !transferVerified) {
    warnings.push("Disk transfer byte verification did not pass.");
  }
  if (verifyKnown && !reachable) {
    warnings.push("Target did not become reachable within the verify timeout.");
  }
  if (spec.hasEfiDisk === true) {
    warnings.push(
      "Source has an efidisk0 (UEFI) — its EFI vars volume must also be " +
        "streamed/recreated or the target may not boot.",
    );
  }

  if (warnings.length > 0) {
    lines.push("## Warnings");
    lines.push("");
    for (const w of warnings) lines.push(`- ⚠ ${w}`);
    lines.push("");
  }

  lines.push("## Rollback");
  lines.push("");
  lines.push(
    "The source VM is left **stopped** (not deleted). To roll back: start the " +
      "source again on its hypervisor" +
      (macPreserved ? "" : ", and revert any DNS flip") +
      ". On a failed run the workflow's cleanup job removes the half-built " +
      "target VM and zvol.",
  );

  const json: Record<string, unknown> = {
    workflow: meta.workflow ?? null,
    workflowStatus: meta.workflowStatus ?? null,
    source: { name: srcName, node: srcNode, vmid: n(spec.vmid) },
    target: { name: targetName },
    vcpus: n(spec.vcpus),
    memoryMib: n(spec.memoryMib),
    firmware,
    bootloader,
    expectedBootloader,
    hasEfiDisk: spec.hasEfiDisk === true,
    bytesWritten,
    expectedBytes,
    transferMode: s(transfer.mode),
    transferVerified,
    srcMac,
    targetMac,
    macPreserved,
    networkPrep: netMethod,
    reachable: verifyKnown ? reachable : null,
    warnings,
  };
  return { markdown: lines.join("\n"), json };
}
