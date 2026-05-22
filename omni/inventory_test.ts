/**
 * Unit tests for `@mccormick/omni/inventory`.
 *
 * Covers the `omnictl` output parser, the pure enum/merge transforms, and an
 * end-to-end `discover` run against a stubbed `omnictl` runner — no live Omni
 * and no `omnictl` binary required.
 */
import { assertEquals, assertRejects } from "jsr:@std/assert@1";
import { createModelTestContext } from "jsr:@systeminit/swamp-testing@0.20260519.14";
import { __setOmnictlRunner, type CosiResource, parseOmnictlJson } from "./omnictl.ts";
import { decodeRole, decodeStage, mergeInventory, roleFromLabels } from "./transform.ts";
import { model } from "./inventory.ts";

type DiscoverCtx = Parameters<typeof model.methods.discover.execute>[1];

const NOW = "2026-05-21T00:00:00.000Z";

// ---------------------------------------------------------------------------
// Canned Omni COSI resources — a 2-machine "linguine" cluster.
// ---------------------------------------------------------------------------

const MACHINE_STATUSES: CosiResource[] = [
  {
    metadata: {
      id: "aaaaaaaa-0000-0000-0000-000000000001",
      labels: {
        "omni.sidero.dev/cluster": "linguine",
        "omni.sidero.dev/role-controlplane": null,
        "omni.sidero.dev/machine-set": "linguine-control-planes",
        "omni.sidero.dev/arch": "amd64",
        "omni.sidero.dev/talos-version": "v1.12.7",
      },
    },
    spec: {
      cluster: "linguine",
      connected: true,
      maintenance: false,
      role: 1,
      talosversion: "v1.12.7",
      managementaddress: "fdae:41e4:649b:9303::a",
      lasterror: "",
      network: { hostname: "talos-cp-a", addresses: ["192.168.0.54/24"] },
      hardware: {
        arch: "amd64",
        processors: [{ corecount: 2, threadcount: 2, description: "QEMU vCPU" }],
        memorymodules: [{ sizemb: 8192 }],
        blockdevices: [{
          linuxname: "/dev/sda",
          model: "QEMU HARDDISK",
          type: "SSD",
          transport: "virtio",
          size: 34359738368,
          systemdisk: true,
        }],
      },
      securitystate: { secureboot: false, bootedwithuki: false },
      schematic: { extensions: ["siderolabs/iscsi-tools"] },
    },
  },
  {
    metadata: {
      id: "bbbbbbbb-0000-0000-0000-000000000002",
      labels: {
        "omni.sidero.dev/cluster": "linguine",
        "omni.sidero.dev/role-worker": null,
        "omni.sidero.dev/machine-set": "linguine-workers",
        "omni.sidero.dev/arch": "amd64",
        "omni.sidero.dev/talos-version": "v1.12.7",
      },
    },
    spec: {
      cluster: "linguine",
      connected: false,
      maintenance: false,
      role: 2,
      talosversion: "v1.12.7",
      managementaddress: "fdae:41e4:649b:9303::b",
      lasterror: "",
      network: { hostname: "talos-wk-b", addresses: ["192.168.0.82/24"] },
      hardware: {
        arch: "amd64",
        processors: [{ corecount: 4, threadcount: 4, description: "QEMU vCPU" }],
        memorymodules: [{ sizemb: 16384 }],
        blockdevices: [],
      },
      securitystate: { secureboot: false, bootedwithuki: false },
      schematic: { extensions: [] },
    },
  },
];

const CLUSTER_MACHINE_STATUSES: CosiResource[] = [
  {
    metadata: {
      id: "aaaaaaaa-0000-0000-0000-000000000001",
      labels: { "omni.sidero.dev/role-controlplane": null },
    },
    spec: { stage: 4, ready: true, apidavailable: true },
  },
  {
    metadata: {
      id: "bbbbbbbb-0000-0000-0000-000000000002",
      labels: { "omni.sidero.dev/role-worker": null },
    },
    spec: { stage: 4, ready: true, apidavailable: false },
  },
];

const CLUSTER_MACHINE_IDENTITIES: CosiResource[] = [
  {
    metadata: { id: "aaaaaaaa-0000-0000-0000-000000000001" },
    spec: { nodename: "talos-cp-a", nodeips: ["192.168.0.54"] },
  },
  {
    metadata: { id: "bbbbbbbb-0000-0000-0000-000000000002" },
    spec: { nodename: "talos-wk-b", nodeips: ["192.168.0.82"] },
  },
];

const CLUSTERS: CosiResource[] = [
  {
    metadata: { id: "linguine" },
    spec: { kubernetesversion: "1.34.8", talosversion: "1.12.7" },
  },
];

/** Resources keyed by the `omnictl` type the model asks for. */
const CANNED: Record<string, CosiResource[]> = {
  machinestatus: MACHINE_STATUSES,
  clustermachinestatus: CLUSTER_MACHINE_STATUSES,
  clustermachineidentity: CLUSTER_MACHINE_IDENTITIES,
  cluster: CLUSTERS,
};

// ---------------------------------------------------------------------------
// parseOmnictlJson
// ---------------------------------------------------------------------------

Deno.test("parseOmnictlJson splits concatenated pretty-printed objects", () => {
  const stdout = MACHINE_STATUSES
    .map((r) => JSON.stringify(r, null, 4))
    .join("\n");
  const parsed = parseOmnictlJson(stdout);
  assertEquals(parsed.length, 2);
  assertEquals(parsed[0].metadata.id, "aaaaaaaa-0000-0000-0000-000000000001");
  assertEquals(parsed[1].spec.cluster, "linguine");
});

Deno.test("parseOmnictlJson returns empty array for empty output", () => {
  assertEquals(parseOmnictlJson(""), []);
  assertEquals(parseOmnictlJson("   \n  "), []);
});

Deno.test("parseOmnictlJson is not confused by braces inside strings", () => {
  const stdout = JSON.stringify({
    metadata: { id: "x" },
    spec: { note: "a } that is { not structural" },
  });
  const parsed = parseOmnictlJson(stdout);
  assertEquals(parsed.length, 1);
  assertEquals(parsed[0].spec.note, "a } that is { not structural");
});

// ---------------------------------------------------------------------------
// decodeRole / decodeStage / roleFromLabels
// ---------------------------------------------------------------------------

Deno.test("decodeRole maps Omni role integers", () => {
  assertEquals(decodeRole(1), "controlplane");
  assertEquals(decodeRole(2), "worker");
  assertEquals(decodeRole(0), "none");
  assertEquals(decodeRole(99), "role-99");
  assertEquals(decodeRole(undefined), "none");
});

Deno.test("decodeStage maps Omni stage integers", () => {
  assertEquals(decodeStage(4), "running");
  assertEquals(decodeStage(1), "booting");
  assertEquals(decodeStage(42), "stage-42");
});

Deno.test("roleFromLabels prefers the role label over the spec integer", () => {
  assertEquals(
    roleFromLabels({ "omni.sidero.dev/role-worker": null }, 1),
    "worker",
  );
  assertEquals(roleFromLabels({}, 1), "controlplane");
  assertEquals(roleFromLabels(undefined, 2), "worker");
});

// ---------------------------------------------------------------------------
// mergeInventory
// ---------------------------------------------------------------------------

Deno.test("mergeInventory folds Omni resources into nodes, clusters, summary", () => {
  const { nodes, clusters, summary } = mergeInventory({
    endpoint: "https://omni.example.net",
    machineStatuses: MACHINE_STATUSES,
    clusterMachineStatuses: CLUSTER_MACHINE_STATUSES,
    clusterMachineIdentities: CLUSTER_MACHINE_IDENTITIES,
    clusters: CLUSTERS,
  }, NOW);

  // Nodes are sorted by hostname.
  assertEquals(nodes.map((n) => n.hostname), ["talos-cp-a", "talos-wk-b"]);

  const cp = nodes[0];
  assertEquals(cp.role, "controlplane");
  assertEquals(cp.cluster, "linguine");
  assertEquals(cp.stage, "running");
  assertEquals(cp.ready, true);
  assertEquals(cp.connected, true);
  assertEquals(cp.cpuCores, 2);
  assertEquals(cp.memoryMib, 8192);
  assertEquals(cp.blockDevices.length, 1);
  assertEquals(cp.blockDevices[0].name, "/dev/sda");
  assertEquals(cp.blockDevices[0].systemDisk, true);
  assertEquals(cp.kubernetesNodeName, "talos-cp-a");
  assertEquals(cp.talosExtensions, ["siderolabs/iscsi-tools"]);

  const wk = nodes[1];
  assertEquals(wk.role, "worker");
  assertEquals(wk.connected, false);
  assertEquals(wk.cpuCores, 4);

  assertEquals(clusters.length, 1);
  assertEquals(clusters[0].name, "linguine");
  assertEquals(clusters[0].machineCount, 2);
  assertEquals(clusters[0].controlPlaneCount, 1);
  assertEquals(clusters[0].workerCount, 1);
  assertEquals(clusters[0].connectedCount, 1);

  assertEquals(summary.totalNodes, 2);
  assertEquals(summary.connectedCount, 1);
  assertEquals(summary.clusterCount, 1);
  assertEquals(summary.byCluster, { linguine: 2 });
  assertEquals(summary.byRole, { controlplane: 1, worker: 1 });
  assertEquals(summary.byTalosVersion, { "v1.12.7": 2 });
  assertEquals(summary.notes, []);
});

Deno.test("mergeInventory records a note for a machine on an unknown cluster", () => {
  const orphan: CosiResource = {
    metadata: { id: "cccccccc-0000-0000-0000-000000000003", labels: {} },
    spec: {
      cluster: "ghost",
      connected: true,
      role: 2,
      network: { hostname: "talos-orphan", addresses: [] },
      hardware: {},
    },
  };
  const { summary } = mergeInventory({
    endpoint: "https://omni.example.net",
    machineStatuses: [orphan],
    clusterMachineStatuses: [],
    clusterMachineIdentities: [],
    clusters: CLUSTERS,
  }, NOW);
  assertEquals(summary.notes.length, 2); // unknown cluster + missing CMS
  assertEquals(summary.totalNodes, 1);
});

// ---------------------------------------------------------------------------
// discover (end-to-end with a stubbed omnictl runner)
// ---------------------------------------------------------------------------

const GLOBAL_ARGS = {
  endpoint: "https://omni.example.net",
  serviceAccountKey: "fake-service-account-key",
  insecureSkipTlsVerify: false,
  omnictlPath: "omnictl",
};

Deno.test("discover writes a node per machine, a cluster, and a summary", async () => {
  __setOmnictlRunner((type) => Promise.resolve(CANNED[type] ?? []));
  try {
    const { context, getWrittenResources } = createModelTestContext({
      globalArgs: GLOBAL_ARGS,
    });
    await model.methods.discover.execute({}, context as DiscoverCtx);
    const written = getWrittenResources();
    const bySpec = (spec: string) => written.filter((r) => r.specName === spec);

    assertEquals(bySpec("node").length, 2);
    assertEquals(bySpec("cluster").length, 1);
    assertEquals(bySpec("summary").length, 1);

    const summary = bySpec("summary")[0].data;
    assertEquals(summary.totalNodes, 2);
    assertEquals(summary.connectedCount, 1);
    assertEquals(summary.endpoint, "https://omni.example.net");

    const cp = bySpec("node").find((r) => r.data.role === "controlplane");
    assertEquals(cp?.data.hostname, "talos-cp-a");
  } finally {
    __setOmnictlRunner(undefined);
  }
});

Deno.test("discover throws when an Omni query fails, before writing data", async () => {
  __setOmnictlRunner((type) => {
    if (type === "clustermachinestatus") {
      return Promise.reject(new Error("omnictl get clustermachinestatus failed"));
    }
    return Promise.resolve(CANNED[type] ?? []);
  });
  try {
    const { context, getWrittenResources } = createModelTestContext({
      globalArgs: GLOBAL_ARGS,
    });
    await assertRejects(
      () => model.methods.discover.execute({}, context as DiscoverCtx),
      Error,
      "clustermachinestatus",
    );
    assertEquals(getWrittenResources().length, 0);
  } finally {
    __setOmnictlRunner(undefined);
  }
});

Deno.test("discover rejects a non-https endpoint", async () => {
  __setOmnictlRunner((type) => Promise.resolve(CANNED[type] ?? []));
  try {
    const { context } = createModelTestContext({
      globalArgs: { ...GLOBAL_ARGS, endpoint: "http://omni.example.net" },
    });
    await assertRejects(
      () => model.methods.discover.execute({}, context as DiscoverCtx),
      Error,
      "https",
    );
  } finally {
    __setOmnictlRunner(undefined);
  }
});
