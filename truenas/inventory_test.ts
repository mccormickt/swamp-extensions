/**
 * Unit tests for `@mccormick/truenas/inventory`.
 *
 * Covers the numeric parsers, state normalization, the pure `buildInventory`
 * fold for both the incus and libvirt shapes, and an end-to-end `discover` run
 * against a stubbed transport — no live TrueNAS and no WebSocket required.
 */
import { assertEquals, assertRejects } from "jsr:@std/assert@1";
import { createModelTestContext } from "jsr:@systeminit/swamp-testing@0.20260519.14";
import {
  buildInventory,
  normalizeState,
  parseCpuCount,
  parseMemoryToMib,
  type TruenasRawInventory,
} from "./parse.ts";
import { __setTruenasRunner } from "./client.ts";
import { model } from "./inventory.ts";

type DiscoverCtx = Parameters<typeof model.methods.discover.execute>[1];

const NOW = "2026-06-04T00:00:00.000Z";

// ---------------------------------------------------------------------------
// Canned TrueNAS guests.
// ---------------------------------------------------------------------------

/** Two Incus instances as `virt.instance.query` returns them (with `raw`). */
const INCUS_INSTANCES: unknown[] = [
  {
    id: "omni",
    name: "omni",
    type: "VM",
    status: "RUNNING",
    cpu: "4",
    memory: 8589934592,
    autostart: true,
    raw: {
      config: {
        "limits.cpu": "4",
        "limits.memory": "8GiB",
        "boot.autostart": "true",
        "volatile.eth0.hwaddr": "00:16:3e:aa:bb:cc",
        "user.description": "Omni control plane",
      },
      devices: {
        eth0: { type: "nic", network: "br0", nictype: "bridged" },
        root: { type: "disk", pool: "tank", size: "50GiB" },
      },
    },
  },
  {
    id: "talos-test",
    name: "talos-test",
    type: "VM",
    status: "STOPPED",
    raw: {
      config: {
        "limits.cpu": "0-1",
        "limits.memory": "4096MiB",
      },
      devices: {
        eth0: { type: "nic", hwaddr: "00:16:3E:11:22:33", parent: "br0" },
      },
    },
  },
];

const SYSTEM_INFO = { version: "TrueNAS-24.10.2", hostname: "truenas" };

// ---------------------------------------------------------------------------
// parseCpuCount
// ---------------------------------------------------------------------------

Deno.test("parseCpuCount handles counts, ranges, sets, and relative values", () => {
  assertEquals(parseCpuCount("4"), 4);
  assertEquals(parseCpuCount(2), 2);
  assertEquals(parseCpuCount("0-3"), 4);
  assertEquals(parseCpuCount("0,2,4"), 3);
  assertEquals(parseCpuCount("0-1,4"), 3);
  assertEquals(parseCpuCount("50%"), null);
  assertEquals(parseCpuCount(""), null);
  assertEquals(parseCpuCount(undefined), null);
});

// ---------------------------------------------------------------------------
// parseMemoryToMib
// ---------------------------------------------------------------------------

Deno.test("parseMemoryToMib handles binary, decimal, byte, and relative inputs", () => {
  assertEquals(parseMemoryToMib("8GiB"), 8192);
  assertEquals(parseMemoryToMib("4096MiB"), 4096);
  assertEquals(parseMemoryToMib(8589934592), 8192); // bytes
  assertEquals(parseMemoryToMib("512MB"), Math.round(512 * 1000 * 1000 / (1024 * 1024)));
  assertEquals(parseMemoryToMib("50%"), null);
  assertEquals(parseMemoryToMib(""), null);
});

// ---------------------------------------------------------------------------
// normalizeState
// ---------------------------------------------------------------------------

Deno.test("normalizeState maps TrueNAS statuses", () => {
  assertEquals(normalizeState("RUNNING"), "running");
  assertEquals(normalizeState("STOPPED"), "stopped");
  assertEquals(normalizeState("FROZEN"), "suspended");
  assertEquals(normalizeState("BOOTING"), "unknown");
});

// ---------------------------------------------------------------------------
// buildInventory — incus
// ---------------------------------------------------------------------------

Deno.test("buildInventory folds incus instances into vms + summary", () => {
  const raw: TruenasRawInventory = {
    instances: INCUS_INSTANCES,
    systemInfo: SYSTEM_INFO,
  };
  const { vms, summary } = buildInventory(
    raw,
    "truenas.example.net",
    "incus",
    NOW,
  );

  // Sorted by name.
  assertEquals(vms.map((v) => v.name), ["omni", "talos-test"]);

  const omni = vms[0];
  assertEquals(omni.state, "running");
  assertEquals(omni.vcpus, 4);
  assertEquals(omni.memoryMib, 8192);
  assertEquals(omni.autostart, true);
  assertEquals(omni.macs, ["00:16:3e:aa:bb:cc"]);
  assertEquals(omni.nics.length, 1);
  assertEquals(omni.nics[0].bridge, "br0");
  assertEquals(omni.disks.length, 1);
  assertEquals(omni.disks[0].source, "tank");
  assertEquals(omni.disks[0].sizeBytes, 50 * 1024 ** 3);
  assertEquals(omni.description, "Omni control plane");
  assertEquals(omni.notes, []);

  const talos = vms[1];
  assertEquals(talos.state, "stopped");
  assertEquals(talos.vcpus, 2); // "0-1" → 2
  assertEquals(talos.memoryMib, 4096);
  assertEquals(talos.autostart, false);
  assertEquals(talos.macs, ["00:16:3e:11:22:33"]); // lowercased

  assertEquals(summary.host, "truenas");
  assertEquals(summary.truenasVersion, "TrueNAS-24.10.2");
  assertEquals(summary.backend, "incus");
  assertEquals(summary.totalVms, 2);
  assertEquals(summary.runningCount, 1);
  assertEquals(summary.stoppedCount, 1);
  assertEquals(summary.totalVcpus, 6);
  assertEquals(summary.totalMemoryMib, 12288);
  assertEquals(summary.notes, []);
});

Deno.test("buildInventory notes a missing system.info and unset limits", () => {
  const raw: TruenasRawInventory = {
    instances: [{ id: "bare", name: "bare", status: "RUNNING" }],
    systemInfo: null,
  };
  const { vms, summary } = buildInventory(raw, "truenas.example.net", "incus", NOW);
  assertEquals(vms[0].vcpus, null);
  assertEquals(vms[0].memoryMib, null);
  assertEquals(vms[0].notes.length >= 1, true);
  assertEquals(summary.host, "truenas.example.net"); // endpoint fallback
  assertEquals(summary.truenasVersion, "unknown");
  assertEquals(summary.notes.length, 1);
});

// ---------------------------------------------------------------------------
// buildInventory — libvirt
// ---------------------------------------------------------------------------

Deno.test("buildInventory folds legacy vm.query instances", () => {
  const raw: TruenasRawInventory = {
    instances: [
      {
        id: 12,
        name: "legacy",
        status: { state: "RUNNING" },
        vcpus: 2,
        memory: 4096, // MiB on legacy vm.query
        autostart: true,
        devices: [
          {
            dtype: "NIC",
            id: "nic0",
            attributes: { type: "VIRTIO", mac: "00:A0:98:11:22:33", nic_attach: "br0" },
          },
          { dtype: "DISK", id: "disk0", attributes: { type: "AHCI", path: "/dev/zvol/tank/legacy" } },
        ],
      },
    ],
    systemInfo: { version: "TrueNAS-22.12.0", hostname: "old" },
  };
  const { vms, summary } = buildInventory(raw, "old.example.net", "libvirt", NOW);
  assertEquals(vms[0].vcpus, 2);
  assertEquals(vms[0].memoryMib, 4096);
  assertEquals(vms[0].macs, ["00:a0:98:11:22:33"]);
  assertEquals(vms[0].disks[0].source, "/dev/zvol/tank/legacy");
  assertEquals(summary.backend, "libvirt");
  assertEquals(summary.totalVcpus, 2);
});

// ---------------------------------------------------------------------------
// discover (end-to-end with a stubbed transport)
// ---------------------------------------------------------------------------

const GLOBAL_ARGS = {
  endpoint: "truenas.example.net",
  apiKey: "fake-api-key",
  insecureSkipTlsVerify: false,
  backend: "auto",
  timeoutSecs: 30,
};

Deno.test("discover writes a vm per guest and a summary", async () => {
  __setTruenasRunner(() =>
    Promise.resolve({ instances: INCUS_INSTANCES, systemInfo: SYSTEM_INFO })
  );
  try {
    const { context, getWrittenResources } = createModelTestContext({
      globalArgs: GLOBAL_ARGS,
    });
    await model.methods.discover.execute({}, context as DiscoverCtx);
    const written = getWrittenResources();
    const bySpec = (spec: string) => written.filter((r) => r.specName === spec);

    assertEquals(bySpec("vm").length, 2);
    assertEquals(bySpec("summary").length, 1);

    const summary = bySpec("summary")[0].data;
    assertEquals(summary.totalVms, 2);
    assertEquals(summary.runningCount, 1);

    const omni = bySpec("vm").find((r) => r.data.name === "omni");
    assertEquals(omni?.data.vcpus, 4);
  } finally {
    __setTruenasRunner(undefined);
  }
});

Deno.test("discover propagates a transport failure before writing data", async () => {
  __setTruenasRunner(() =>
    Promise.reject(new Error("TrueNAS api-key login rejected"))
  );
  try {
    const { context, getWrittenResources } = createModelTestContext({
      globalArgs: GLOBAL_ARGS,
    });
    await assertRejects(
      () => model.methods.discover.execute({}, context as DiscoverCtx),
      Error,
      "login rejected",
    );
    assertEquals(getWrittenResources().length, 0);
  } finally {
    __setTruenasRunner(undefined);
  }
});
