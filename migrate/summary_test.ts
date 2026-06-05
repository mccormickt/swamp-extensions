/**
 * Unit tests for the migration-summary render.
 */
import { assertEquals, assertStringIncludes } from "jsr:@std/assert@1";
import {
  type Collected,
  emptyCollected,
  firmwareToBootloader,
  renderMigrationSummary,
} from "./summary_render.ts";

const GIB = 1024 ** 3;

function fullRun(): Collected {
  const c = emptyCollected();
  c.vmSpec = {
    vmid: 104,
    name: "omni",
    node: "aphrodite",
    vcpus: 4,
    memoryMib: 8192,
    firmware: "seabios",
    hasEfiDisk: false,
    nics: [{ mac: "bc:24:11:68:d6:09" }],
  };
  c.vmInstances = [{ name: "omni", bootloader: "UEFI_CSM" }];
  c.vmDevices = [
    { kind: "NIC", mac: "bc:24:11:68:d6:09" },
    { kind: "DISK", path: "/dev/zvol/Main/omni" },
  ];
  c.transfers = [{
    mode: "relay",
    dstHost: "truenas",
    bytesWritten: 250 * GIB,
    expectedBytes: 250 * GIB,
    verified: true,
  }];
  c.netpreps = [{ applied: true, method: "agent", agentPresent: true }];
  c.verifies = [{ reachable: true, ip: "10.0.0.59" }];
  return c;
}

Deno.test("firmwareToBootloader maps ovmf→UEFI, else UEFI_CSM", () => {
  assertEquals(firmwareToBootloader("ovmf"), "UEFI");
  assertEquals(firmwareToBootloader("seabios"), "UEFI_CSM");
  assertEquals(firmwareToBootloader(null), "UEFI_CSM");
});

Deno.test("summary renders a clean same-IP run with no warnings", () => {
  const { markdown, json } = renderMigrationSummary(fullRun(), {
    workflow: "migrate-vm",
    workflowStatus: "succeeded",
  });
  assertStringIncludes(markdown, "# VM Migration Summary");
  assertStringIncludes(markdown, "omni");
  assertStringIncludes(markdown, "MAC preserved | yes");
  assertStringIncludes(markdown, "Bytes verified | yes");
  assertStringIncludes(markdown, "Reachable | yes");
  assertStringIncludes(markdown, "left **stopped**");
  // a clean run has no warnings section
  assertEquals(markdown.includes("## Warnings"), false);
  assertEquals(json.macPreserved, true);
  assertEquals(json.reachable, true);
  assertEquals(json.transferVerified, true);
  assertEquals((json.warnings as string[]).length, 0);
});

Deno.test("summary flags a different MAC, unverified bytes, and unreachable", () => {
  const c = fullRun();
  c.vmDevices = [{ kind: "NIC", mac: "00:11:22:33:44:55" }]; // differs
  c.transfers = [{ mode: "direct", bytesWritten: 1, expectedBytes: 250 * GIB, verified: false }];
  c.verifies = [{ reachable: false, ip: "10.0.0.59" }];
  const { markdown, json } = renderMigrationSummary(c);
  assertStringIncludes(markdown, "## Warnings");
  assertStringIncludes(markdown, "NOT same-IP");
  assertEquals(json.macPreserved, false);
  assertEquals(json.reachable, false);
  assertEquals((json.warnings as string[]).length >= 3, true);
});

Deno.test("summary uses the offline edit when the agent path did not apply", () => {
  const c = fullRun();
  c.netpreps = [{ applied: false, agentPresent: false }];
  c.diskEdits = [{ applied: true, mode: "nbd" }];
  const { json } = renderMigrationSummary(c);
  assertStringIncludes(String(json.networkPrep), "offline");
});

Deno.test("summary flags an efidisk that must be streamed too", () => {
  const c = fullRun();
  (c.vmSpec as Record<string, unknown>).hasEfiDisk = true;
  const { markdown, json } = renderMigrationSummary(c);
  assertStringIncludes(markdown, "efidisk0");
  assertEquals(json.hasEfiDisk, true);
});
