/**
 * Unit tests for `@mccormick/truenas/vm`.
 *
 * Covers the pure provisioning helpers (param building, idempotency lookups,
 * the swamp marker) and an end-to-end run of every method against a stubbed
 * JSON-RPC session — no live TrueNAS and no WebSocket required.
 */
import { assertEquals, assertRejects } from "jsr:@std/assert@1";
import { createModelTestContext } from "jsr:@systeminit/swamp-testing@0.20260519.14";
import type { TruenasSession } from "./client.ts";
import { __setTruenasSessionFactory, model } from "./vm.ts";
import {
  diskDeviceParams,
  findDiskDevice,
  findNicDevice,
  gibToBytes,
  isSwampManaged,
  nicDeviceParams,
  parseVolsizeBytes,
  SWAMP_MARKER,
  vmCreateParams,
  vmStatusString,
  withSwampMarker,
  zvolCreateParams,
  zvolDevPath,
  zvolFullName,
} from "./vm_parse.ts";

const GLOBAL_ARGS = {
  endpoint: "truenas.example.net",
  apiKey: "fake-api-key",
  insecureSkipTlsVerify: false,
  timeoutSecs: 30,
};

type AnyCtx = Parameters<typeof model.methods.create_zvol.execute>[1];

interface Recorded {
  method: string;
  params: unknown[];
}

/** A stubbed session that dispatches calls to `handler` and records them. */
function fakeSession(
  handler: (method: string, params: unknown[]) => unknown,
): { calls: Recorded[]; install: () => void } {
  const calls: Recorded[] = [];
  const session: TruenasSession = {
    call(method, params) {
      calls.push({ method, params });
      return Promise.resolve(handler(method, params));
    },
    close() {},
  };
  return {
    calls,
    install: () => __setTruenasSessionFactory(() => Promise.resolve(session)),
  };
}

interface Written {
  specName: string;
  name: string;
  // deno-lint-ignore no-explicit-any
  data: Record<string, any>;
}

function run<M extends keyof typeof model.methods>(
  methodName: M,
  args: Record<string, unknown>,
): Promise<Written[]> {
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs: GLOBAL_ARGS,
  });
  // deno-lint-ignore no-explicit-any
  const exec = (model.methods[methodName] as any).execute;
  return exec(args, context as AnyCtx).then(
    () => getWrittenResources() as unknown as Written[],
  );
}

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

Deno.test("zvol naming + sizing", () => {
  assertEquals(zvolFullName("Main", "omni"), "Main/omni");
  assertEquals(zvolDevPath("Main", "omni"), "/dev/zvol/Main/omni");
  assertEquals(gibToBytes(1), 1024 ** 3);
  assertEquals(gibToBytes(250), 250 * 1024 ** 3);
});

Deno.test("parseVolsizeBytes handles composite and bare shapes", () => {
  assertEquals(parseVolsizeBytes({ volsize: { parsed: 1234 } }), 1234);
  assertEquals(parseVolsizeBytes({ volsize: { rawvalue: "5678" } }), 5678);
  assertEquals(parseVolsizeBytes({ volsize: 42 }), 42);
  assertEquals(parseVolsizeBytes({}), null);
});

Deno.test("swamp marker round-trips and is idempotent", () => {
  assertEquals(withSwampMarker(), SWAMP_MARKER);
  assertEquals(withSwampMarker("hi"), `hi ${SWAMP_MARKER}`);
  assertEquals(withSwampMarker(`hi ${SWAMP_MARKER}`), `hi ${SWAMP_MARKER}`);
  assertEquals(isSwampManaged(`x ${SWAMP_MARKER}`), true);
  assertEquals(isSwampManaged("plain"), false);
  assertEquals(isSwampManaged(null), false);
});

Deno.test("zvolCreateParams shapes a VOLUME with bytes volsize", () => {
  const p = zvolCreateParams({
    pool: "Main",
    name: "omni",
    sizeBytes: 100,
    sparse: true,
    blocksize: "16K",
  });
  assertEquals(p.name, "Main/omni");
  assertEquals(p.type, "VOLUME");
  assertEquals(p.volsize, 100);
  assertEquals(p.sparse, true);
  assertEquals(p.volblocksize, "16K");
});

Deno.test("device param builders nest dtype in attributes", () => {
  const disk = diskDeviceParams({ vmId: 1, zvolPath: "/dev/zvol/Main/x", bus: "VIRTIO" });
  assertEquals(disk.vm, 1);
  assertEquals((disk.attributes as Record<string, unknown>).dtype, "DISK");
  assertEquals((disk.attributes as Record<string, unknown>).path, "/dev/zvol/Main/x");

  const nic = nicDeviceParams({ vmId: 1, mac: "BC:24:11:68:D6:09", bridge: "br0", model: "VIRTIO" });
  const attrs = nic.attributes as Record<string, unknown>;
  assertEquals(attrs.dtype, "NIC");
  assertEquals(attrs.mac, "BC:24:11:68:D6:09");
  assertEquals(attrs.nic_attach, "br0");
});

Deno.test("device idempotency lookups are tolerant of nesting and case", () => {
  const devices = [
    { id: 5, attributes: { dtype: "DISK", path: "/dev/zvol/Main/omni" } },
    { id: 6, dtype: "NIC", attributes: { mac: "bc:24:11:68:d6:09" } },
  ];
  assertEquals(findDiskDevice(devices, "/dev/zvol/Main/omni")?.id, 5);
  assertEquals(findDiskDevice(devices, "/dev/zvol/Main/other"), null);
  assertEquals(findNicDevice(devices, "BC:24:11:68:D6:09")?.id, 6);
  assertEquals(findNicDevice(devices, "00:00:00:00:00:00"), null);
});

Deno.test("vmStatusString reads object and string status shapes", () => {
  assertEquals(vmStatusString({ status: { state: "RUNNING" } }), "running");
  assertEquals(vmStatusString({ status: "STOPPED" }), "stopped");
  assertEquals(vmStatusString({ state: "running" }), "running");
  assertEquals(vmStatusString({}), "unknown");
});

Deno.test("vmCreateParams stamps the marker and maps fields", () => {
  const p = vmCreateParams({
    name: "omni",
    vcpus: 4,
    coresPerSocket: 2,
    memoryMib: 8192,
    bootloader: "UEFI_CSM",
    autostart: false,
  });
  assertEquals(p.name, "omni");
  assertEquals(p.memory, 8192);
  assertEquals(p.cores, 2);
  assertEquals(p.bootloader, "UEFI_CSM");
  assertEquals(p.description, SWAMP_MARKER);
});

// ---------------------------------------------------------------------------
// create_zvol
// ---------------------------------------------------------------------------

Deno.test("create_zvol creates a new sparse volume", async () => {
  const fake = fakeSession((m) => (m === "pool.dataset.query" ? [] : {}));
  fake.install();
  try {
    const written = await run("create_zvol", { pool: "Main", name: "omni", sizeGib: 250 });
    const z = written.find((r) => r.specName === "zvol")!;
    assertEquals(z.data.exists, false);
    assertEquals(z.data.devPath, "/dev/zvol/Main/omni");
    assertEquals(z.data.sizeBytes, 250 * 1024 ** 3);
    assertEquals(fake.calls.some((c) => c.method === "pool.dataset.create"), true);
  } finally {
    __setTruenasSessionFactory(undefined);
  }
});

Deno.test("create_zvol is a no-op when an equal/larger volume exists", async () => {
  const fake = fakeSession((m) =>
    m === "pool.dataset.query"
      ? [{ id: "Main/omni", volsize: { parsed: 300 * 1024 ** 3 } }]
      : {}
  );
  fake.install();
  try {
    const written = await run("create_zvol", { pool: "Main", name: "omni", sizeGib: 250 });
    const z = written.find((r) => r.specName === "zvol")!;
    assertEquals(z.data.exists, true);
    assertEquals(fake.calls.some((c) => c.method === "pool.dataset.create"), false);
  } finally {
    __setTruenasSessionFactory(undefined);
  }
});

Deno.test("create_zvol refuses to grow a smaller existing volume", async () => {
  const fake = fakeSession((m) =>
    m === "pool.dataset.query"
      ? [{ id: "Main/omni", volsize: { parsed: 10 * 1024 ** 3 } }]
      : {}
  );
  fake.install();
  try {
    await assertRejects(
      () => run("create_zvol", { pool: "Main", name: "omni", sizeGib: 250 }),
      Error,
      "smaller than requested",
    );
  } finally {
    __setTruenasSessionFactory(undefined);
  }
});

// ---------------------------------------------------------------------------
// create_vm
// ---------------------------------------------------------------------------

Deno.test("create_vm creates a VM and stamps the marker", async () => {
  let created: Record<string, unknown> | null = null;
  const fake = fakeSession((m, params) => {
    if (m === "vm.query") return [];
    if (m === "vm.create") {
      created = (params[0] as Record<string, unknown>);
      return { id: 42, ...created };
    }
    return {};
  });
  fake.install();
  try {
    const written = await run("create_vm", {
      name: "omni",
      vcpus: 4,
      memoryMib: 8192,
      bootloader: "UEFI_CSM",
    });
    const vm = written.find((r) => r.specName === "vm_instance")!;
    assertEquals(vm.data.id, 42);
    assertEquals(vm.data.swampManaged, true);
    assertEquals((created!).description, SWAMP_MARKER);
  } finally {
    __setTruenasSessionFactory(undefined);
  }
});

Deno.test("create_vm is idempotent on name", async () => {
  const fake = fakeSession((m) =>
    m === "vm.query"
      ? [{ id: 7, name: "omni", bootloader: "UEFI_CSM", description: SWAMP_MARKER }]
      : {}
  );
  fake.install();
  try {
    const written = await run("create_vm", {
      name: "omni",
      vcpus: 4,
      memoryMib: 8192,
      bootloader: "UEFI_CSM",
    });
    assertEquals(written.find((r) => r.specName === "vm_instance")!.data.id, 7);
    assertEquals(fake.calls.some((c) => c.method === "vm.create"), false);
  } finally {
    __setTruenasSessionFactory(undefined);
  }
});

// ---------------------------------------------------------------------------
// attach_disk / attach_nic
// ---------------------------------------------------------------------------

Deno.test("attach_disk creates a DISK device when absent", async () => {
  const fake = fakeSession((m) =>
    m === "vm.device.query" ? [] : { id: 99 }
  );
  fake.install();
  try {
    const written = await run("attach_disk", {
      vmId: 42,
      zvolPath: "/dev/zvol/Main/omni",
    });
    const d = written.find((r) => r.specName === "vm_device")!;
    assertEquals(d.data.kind, "DISK");
    assertEquals(d.data.existed, false);
    assertEquals(d.data.deviceId, 99);
  } finally {
    __setTruenasSessionFactory(undefined);
  }
});

Deno.test("attach_nic is idempotent on MAC and never re-creates", async () => {
  const fake = fakeSession((m) =>
    m === "vm.device.query"
      ? [{ id: 5, attributes: { dtype: "NIC", mac: "bc:24:11:68:d6:09" } }]
      : {}
  );
  fake.install();
  try {
    const written = await run("attach_nic", {
      vmId: 42,
      mac: "BC:24:11:68:D6:09",
      bridge: "br0",
    });
    const d = written.find((r) => r.specName === "vm_device")!;
    assertEquals(d.data.existed, true);
    assertEquals(fake.calls.some((c) => c.method === "vm.device.create"), false);
  } finally {
    __setTruenasSessionFactory(undefined);
  }
});

// ---------------------------------------------------------------------------
// delete (safety gate + cleanup)
// ---------------------------------------------------------------------------

Deno.test("delete removes a swamp-managed VM", async () => {
  const fake = fakeSession((m) =>
    m === "vm.query"
      ? [{ id: 42, name: "omni", description: `omni ${SWAMP_MARKER}` }]
      : {}
  );
  fake.install();
  try {
    const written = await run("delete", { vmId: 42 });
    assertEquals(written.find((r) => r.specName === "vm_instance")!.data.status, "deleted");
    assertEquals(fake.calls.some((c) => c.method === "vm.delete"), true);
  } finally {
    __setTruenasSessionFactory(undefined);
  }
});

Deno.test("delete refuses a non-swamp VM without force", async () => {
  const fake = fakeSession((m) =>
    m === "vm.query" ? [{ id: 42, name: "prod", description: "hands off" }] : {}
  );
  fake.install();
  try {
    await assertRejects(
      () => run("delete", { vmId: 42 }),
      Error,
      "not swamp-managed",
    );
  } finally {
    __setTruenasSessionFactory(undefined);
  }
});

Deno.test("delete removes a dangling zvol even when the VM is gone", async () => {
  const fake = fakeSession((m) => (m === "vm.query" ? [] : {}));
  fake.install();
  try {
    await run("delete", {
      name: "omni",
      deleteZvol: true,
      zvolPath: "/dev/zvol/Main/omni",
    });
    const del = fake.calls.find((c) => c.method === "pool.dataset.delete");
    assertEquals(del?.params[0], "Main/omni");
  } finally {
    __setTruenasSessionFactory(undefined);
  }
});
