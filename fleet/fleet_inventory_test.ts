/**
 * Unit tests for the `@mccormick/fleet/inventory` render module.
 *
 * Covers per-provider normalization, the spec dispatch, and table/JSON
 * rendering — all pure, no live data required.
 */
import { assertEquals, assertStringIncludes } from "jsr:@std/assert@1";
import {
  dedupeRows,
  normalizeGuest,
  normalizeNode,
  normalizeVm,
  normalizeVmSpec,
  renderFleet,
  rowFor,
} from "./render.ts";

Deno.test("normalizeNode maps an Omni node onto a fleet row", () => {
  const row = normalizeNode({
    hostname: "talos-cp-a",
    stage: "running",
    connected: true,
    cpuCores: 4,
    memoryMib: 8192,
    nodeIps: ["192.168.0.54"],
    addresses: ["192.168.0.54/24"],
  }, "@mccormick/omni/inventory");
  assertEquals(row.hypervisor, "talos");
  assertEquals(row.name, "talos-cp-a");
  assertEquals(row.state, "running");
  assertEquals(row.vcpus, 4);
  assertEquals(row.memoryMib, 8192);
  assertEquals(row.ips, ["192.168.0.54"]); // deduped, CIDR stripped
});

Deno.test("normalizeGuest maps a Proxmox guest (no cpu/memory)", () => {
  const row = normalizeGuest({
    vmid: 100,
    name: "omni",
    status: "running",
    ipv4: "192.168.0.40",
  }, "@stateless/proxmox/qemu");
  assertEquals(row.hypervisor, "proxmox");
  assertEquals(row.name, "omni");
  assertEquals(row.state, "running");
  assertEquals(row.vcpus, null);
  assertEquals(row.memoryMib, null);
  assertEquals(row.ips, ["192.168.0.40"]);
});

Deno.test("normalizeVm maps a TrueNAS vm with macs", () => {
  const row = normalizeVm({
    name: "talos-test",
    state: "stopped",
    vcpus: 2,
    memoryMib: 4096,
    macs: ["00:16:3e:11:22:33"],
  }, "@mccormick/truenas/inventory");
  assertEquals(row.hypervisor, "truenas");
  assertEquals(row.vcpus, 2);
  assertEquals(row.macs, ["00:16:3e:11:22:33"]);
});

Deno.test("normalizeVmSpec maps a Proxmox vm_spec with cpu/mem/macs", () => {
  const row = normalizeVmSpec({
    vmid: 104,
    name: "omni",
    status: "running",
    vcpus: 4,
    memoryMib: 8192,
    primaryIp: "10.0.0.59",
    nics: [{ mac: "bc:24:11:68:d6:09", ip: "10.0.0.59" }],
  }, "@mccormick/proxmox-migrate");
  assertEquals(row.hypervisor, "proxmox");
  assertEquals(row.name, "omni");
  assertEquals(row.vcpus, 4);
  assertEquals(row.memoryMib, 8192);
  assertEquals(row.macs, ["bc:24:11:68:d6:09"]);
  assertEquals(row.ips, ["10.0.0.59"]); // deduped
});

Deno.test("rowFor dispatches by spec and skips non-guest specs", () => {
  assertEquals(rowFor("summary", {}, "x"), null);
  assertEquals(rowFor("cluster", {}, "x"), null);
  assertEquals(rowFor("exec", {}, "x"), null);
  assertEquals(rowFor("node", { hostname: "h" }, "x")?.hypervisor, "talos");
  assertEquals(rowFor("vm_spec", { name: "v" }, "x")?.hypervisor, "proxmox");
});

Deno.test("dedupeRows keeps the richer of a guest + vm_spec for one VM", () => {
  const guest = normalizeGuest({ vmid: 104, name: "omni", status: "running" }, "proxmox");
  const spec = normalizeVmSpec(
    { vmid: 104, name: "omni", status: "running", vcpus: 4, memoryMib: 8192 },
    "proxmox-migrate",
  );
  const deduped = dedupeRows([guest, spec]);
  assertEquals(deduped.length, 1);
  assertEquals(deduped[0].vcpus, 4); // the richer vm_spec row wins
});

Deno.test("renderFleet builds a table and per-hypervisor totals", () => {
  const rows = [
    normalizeNode({ hostname: "talos-cp-a", stage: "running", cpuCores: 4, memoryMib: 8192 }, "omni"),
    normalizeGuest({ vmid: 100, name: "omni", status: "running" }, "proxmox"),
    normalizeVm({ name: "tn-vm", state: "running", vcpus: 2, memoryMib: 4096, macs: [] }, "truenas"),
  ];
  const { markdown, json } = renderFleet(rows);

  assertStringIncludes(markdown, "| Hypervisor | Name | State |");
  assertStringIncludes(markdown, "talos-cp-a");
  assertStringIncludes(markdown, "## Totals");

  assertEquals(json.totalGuests, 3);
  const byHv = json.byHypervisor as Record<string, { count: number; vcpus: number; memoryMib: number }>;
  assertEquals(byHv.talos.count, 1);
  assertEquals(byHv.talos.vcpus, 4);
  assertEquals(byHv.proxmox.count, 1);
  assertEquals(byHv.proxmox.vcpus, 0); // proxmox reports no cpu
  assertEquals(byHv.truenas.memoryMib, 4096);
});

Deno.test("renderFleet handles an empty fleet", () => {
  const { markdown, json } = renderFleet([]);
  assertEquals(json.totalGuests, 0);
  assertStringIncludes(markdown, "no guests discovered");
});
