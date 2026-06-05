/**
 * `@mccormick/truenas/vm` — TrueNAS SCALE VM provisioning for swamp.
 *
 * The read-only `inventory` sibling discovers guests; this model *provisions*
 * them. It stands a VM up from a ZFS zvol over the same JSON-RPC WebSocket API
 * (`pool.dataset.create`, `vm.create`, `vm.device.create`, `vm.start`, …) and is
 * the TrueNAS half of the `migrate-vm` workflow: create the target zvol, create
 * the VM, attach the streamed disk and a NIC carrying the *source* MAC (the
 * same-IP cutover), then start it. Every method is idempotent — it queries
 * before it writes, so a re-run of a half-finished migration is safe.
 *
 * Targets the libvirt `vm.*` surface (SCALE 25.04 "Fangtooth", REST removed),
 * matching the `backend: libvirt` host the manual migration used. The API key is
 * supplied through a vault, marked sensitive, and redacted from logs/errors.
 *
 * Safety: `create_vm` stamps a `[swamp-managed]` marker into the VM description
 * (TrueNAS libvirt VMs have no tags field), and `delete` refuses to remove a VM
 * that lacks the marker unless `force` is set — so swamp never destroys a
 * hand-managed VM by accident.
 *
 * @module
 */
import { z } from "npm:zod@4";
import type { ModelDefinition } from "jsr:@systeminit/swamp-testing@0.20260519.14";
import {
  openTruenasSession,
  type TruenasConnectOptions,
  type TruenasSession,
} from "./client.ts";
// Re-export so the public SessionFactory test seam references public types.
export type { TruenasConnectOptions, TruenasSession } from "./client.ts";
import {
  VmDeviceSchema,
  VmInstanceSchema,
  type Zvol,
  ZvolSchema,
} from "./vm_schema.ts";
import { sanitizeInstanceName } from "./schema.ts";
import {
  asNumber,
  asString,
  deviceId,
  diskDeviceParams,
  findDataset,
  findDiskDevice,
  findNicDevice,
  findVmById,
  findVmByName,
  gibToBytes,
  isSwampManaged,
  nicDeviceParams,
  parseVolsizeBytes,
  vmCreateParams,
  vmStatusString,
  zvolCreateParams,
  zvolDevPath,
  zvolFullName,
} from "./vm_parse.ts";

/** Global arguments for the TrueNAS provisioning model (mirrors inventory). */
const GlobalArgs = z.object({
  endpoint: z.string().describe(
    "TrueNAS host or base URL, e.g. truenas.example.net",
  ),
  apiKey: z.string().meta({ sensitive: true }).describe(
    "TrueNAS API key (read-write — provisioning mutates VMs and datasets); " +
      'supply via ${{ vault.get("fleet", "TrueNAS API Key/credential") }}',
  ),
  insecureSkipTlsVerify: z.boolean().default(false).describe(
    "Skip TLS verification (limited over WebSocket — prefer a trusted CA)",
  ),
  timeoutSecs: z.number().int().positive().default(60).describe(
    "Per-call WebSocket timeout in seconds",
  ),
});

// A VM name TrueNAS will accept: alphanumeric (learned the hard way — the
// middleware rejects non-alnum names on vm.create).
const VmName = z.string().regex(
  /^[A-Za-z0-9]+$/,
  "TrueNAS VM names must be alphanumeric (no spaces, dashes, or dots)",
);

// A ZFS-safe dataset component.
const ZvolName = z.string().regex(
  /^[A-Za-z0-9][A-Za-z0-9_.-]*$/,
  "zvol name must be a valid ZFS dataset component",
);

const CreateZvolArgs = z.object({
  pool: z.string().min(1).describe("ZFS pool (e.g. Main)"),
  name: ZvolName.describe("Volume name within the pool"),
  sizeGib: z.number().positive().describe("Provisioned size in GiB"),
  sparse: z.boolean().default(true).describe("Thin-provision the volume"),
  blocksize: z.string().optional().describe(
    "volblocksize (e.g. 16K); omit for the pool default",
  ),
});

const CreateVmArgs = z.object({
  name: VmName.describe("New VM name (alphanumeric)"),
  vcpus: z.number().int().positive().describe("Virtual CPU count"),
  coresPerSocket: z.number().int().positive().optional(),
  memoryMib: z.number().int().positive().describe("Memory in MiB"),
  bootloader: z.enum(["UEFI", "UEFI_CSM"]).describe(
    "UEFI for ovmf guests; UEFI_CSM for legacy-BIOS/GRUB guests",
  ),
  autostart: z.boolean().default(false),
  description: z.string().optional(),
});

const AttachDiskArgs = z.object({
  vmId: z.number().int().describe("Owning VM id"),
  zvolPath: z.string().min(1).describe(
    "Backing device, /dev/zvol/<pool>/<name>",
  ),
  bus: z.enum(["VIRTIO", "AHCI"]).default("VIRTIO"),
  order: z.number().int().optional().describe("Boot/attach order, if needed"),
});

const AttachNicArgs = z.object({
  vmId: z.number().int().describe("Owning VM id"),
  mac: z.string().regex(
    /^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/,
    "mac must be a colon-separated 6-octet address",
  ).describe("MAC address (pass the source VM's MAC for a same-IP cutover)"),
  bridge: z.string().min(1).describe("Host bridge to attach to (e.g. br0)"),
  model: z.enum(["VIRTIO", "E1000"]).default("VIRTIO"),
});

const VmRefArgs = z.object({
  vmId: z.number().int().optional(),
  name: z.string().optional(),
}).refine((a) => a.vmId !== undefined || a.name !== undefined, {
  message: "Provide vmId or name",
});

const StopArgs = z.object({
  vmId: z.number().int().optional(),
  name: z.string().optional(),
  force: z.boolean().default(false).describe("Hard power-off after graceful"),
}).refine((a) => a.vmId !== undefined || a.name !== undefined, {
  message: "Provide vmId or name",
});

const DeleteArgs = z.object({
  vmId: z.number().int().optional(),
  name: z.string().optional(),
  deleteZvol: z.boolean().default(false).describe(
    "Also delete the VM's zvols (attached, and zvolPath if given)",
  ),
  zvolPath: z.string().optional().describe(
    "A dangling zvol device path to remove even if the VM is already gone",
  ),
  force: z.boolean().default(false).describe(
    "Override the safety gate: delete even a VM lacking the swamp marker",
  ),
}).refine((a) => a.vmId !== undefined || a.name !== undefined, {
  message: "Provide vmId or name",
});

// --- Test seam -------------------------------------------------------------

/** Session opener; replaced in tests via {@link __setTruenasSessionFactory}. */
export type SessionFactory = (
  opts: TruenasConnectOptions,
) => Promise<TruenasSession>;

let sessionFactory: SessionFactory = openTruenasSession;

/** Test-only: override the session opener. Pass undefined to restore. */
export function __setTruenasSessionFactory(
  f: SessionFactory | undefined,
): void {
  sessionFactory = f ?? openTruenasSession;
}

// --- Helpers ---------------------------------------------------------------

type MethodContext = Parameters<
  ModelDefinition<typeof GlobalArgs>["methods"][string]["execute"]
>[1];

function connectOpts(g: z.infer<typeof GlobalArgs>): TruenasConnectOptions {
  if (!g.apiKey) throw new Error("apiKey is required to provision TrueNAS");
  return {
    endpoint: g.endpoint,
    apiKey: g.apiKey,
    insecureSkipTlsVerify: g.insecureSkipTlsVerify,
    timeoutMs: g.timeoutSecs * 1000,
  };
}

/** Resolve a VM reference (id or name) to a concrete record via vm.query. */
async function resolveVm(
  session: TruenasSession,
  ref: { vmId?: number; name?: string },
): Promise<Record<string, unknown> | null> {
  if (ref.vmId !== undefined) {
    return findVmById(
      await session.call("vm.query", [[["id", "=", ref.vmId]]]),
      ref.vmId,
    ) ??
      findVmById(await session.call("vm.query", [[]]), ref.vmId);
  }
  return findVmByName(
    await session.call("vm.query", [[["name", "=", ref.name]]]),
    ref.name!,
  );
}

/** The ZFS dataset id implied by a `/dev/zvol/<pool>/<name>` device path. */
function datasetFromDevPath(devPath: string): string | null {
  const m = devPath.match(/^\/dev\/zvol\/(.+)$/);
  return m ? m[1] : null;
}

/** Shape a vm.query/vm.create record into a vm_instance resource. */
function toVmInstance(
  record: Record<string, unknown>,
  lastOperation: string,
  now: string,
): Record<string, unknown> {
  return VmInstanceSchema.parse({
    id: asNumber(record.id) ?? 0,
    name: asString(record.name) ?? "unknown",
    bootloader: asString(record.bootloader) ?? "unknown",
    vcpus: asNumber(record.vcpus),
    coresPerSocket: asNumber(record.cores),
    memoryMib: asNumber(record.memory),
    autostart: record.autostart === true,
    status: vmStatusString(record),
    swampManaged: isSwampManaged(record.description),
    description: asString(record.description),
    lastOperation,
    recordedAt: now,
  });
}

// --- Model -----------------------------------------------------------------

/** TrueNAS SCALE VM provisioning model (libvirt backend). */
export const model = {
  type: "@mccormick/truenas/vm",
  version: "2026.06.07.2",
  globalArguments: GlobalArgs,
  resources: {
    zvol: {
      description: "A ZFS volume backing a guest disk",
      schema: ZvolSchema,
      lifetime: "infinite",
      garbageCollection: 20,
    },
    vm_instance: {
      description: "A TrueNAS libvirt VM created or observed by this model",
      schema: VmInstanceSchema,
      lifetime: "infinite",
      garbageCollection: 20,
    },
    vm_device: {
      description: "A disk or NIC device attached to a VM",
      schema: VmDeviceSchema,
      lifetime: "infinite",
      garbageCollection: 20,
    },
  },
  checks: {
    connectable: {
      description:
        "TrueNAS accepts the API key over the WebSocket before any mutating " +
        "provisioning operation runs.",
      labels: ["live"],
      appliesTo: [
        "create_zvol",
        "create_vm",
        "attach_disk",
        "attach_nic",
        "start",
        "stop",
        "delete",
      ],
      execute: async (
        context,
      ): Promise<{ pass: boolean; errors?: string[] }> => {
        try {
          const session = await sessionFactory(connectOpts(context.globalArgs));
          session.close();
          return { pass: true };
        } catch (err) {
          return {
            pass: false,
            errors: [
              `TrueNAS pre-flight (api-key login) failed: ${
                err instanceof Error ? err.message : String(err)
              }`,
            ],
          };
        }
      },
    },
  },
  methods: {
    create_zvol: {
      description:
        "Create a sparse/thick ZFS volume to back a guest disk (idempotent; " +
        "refuses to shrink an existing larger volume).",
      arguments: CreateZvolArgs,
      execute: async (rawArgs, context) => {
        const a = CreateZvolArgs.parse(rawArgs);
        const now = new Date().toISOString();
        const fullName = zvolFullName(a.pool, a.name);
        const devPath = zvolDevPath(a.pool, a.name);
        const wantBytes = gibToBytes(a.sizeGib);
        const session = await sessionFactory(connectOpts(context.globalArgs));
        try {
          const existing = findDataset(
            await session.call("pool.dataset.query", [[["id", "=", fullName]]]),
            fullName,
          );
          let exists = false;
          let sizeBytes = wantBytes;
          if (existing) {
            const haveBytes = parseVolsizeBytes(existing);
            if (haveBytes !== null && haveBytes < wantBytes) {
              throw new Error(
                `zvol ${fullName} exists but is smaller than requested ` +
                  `(${haveBytes} < ${wantBytes} bytes); refusing to grow it here`,
              );
            }
            exists = true;
            sizeBytes = haveBytes ?? wantBytes;
            context.logger.info("create_zvol: {name} already present", {
              name: fullName,
            });
          } else {
            await session.call("pool.dataset.create", [
              zvolCreateParams({
                pool: a.pool,
                name: a.name,
                sizeBytes: wantBytes,
                sparse: a.sparse,
                blocksize: a.blocksize,
              }),
            ]);
            context.logger.info("create_zvol: created {name} ({gib} GiB)", {
              name: fullName,
              gib: a.sizeGib,
            });
          }
          const zvol: Zvol = ZvolSchema.parse({
            pool: a.pool,
            name: a.name,
            fullName,
            sizeBytes,
            sparse: a.sparse,
            blocksize: a.blocksize ?? null,
            devPath,
            exists,
            recordedAt: now,
          });
          const handle = await context.writeResource(
            "zvol",
            `zvol-${sanitizeInstanceName(fullName)}`,
            zvol,
          );
          return { dataHandles: [handle] };
        } finally {
          session.close();
        }
      },
    },

    create_vm: {
      description:
        "Create a libvirt VM (idempotent on name). Stamps the swamp marker " +
        "into the description so delete can protect non-swamp VMs.",
      arguments: CreateVmArgs,
      execute: async (rawArgs, context) => {
        const a = CreateVmArgs.parse(rawArgs);
        const now = new Date().toISOString();
        const session = await sessionFactory(connectOpts(context.globalArgs));
        try {
          let record = findVmByName(
            await session.call("vm.query", [[["name", "=", a.name]]]),
            a.name,
          );
          if (record) {
            context.logger.info("create_vm: {name} already present (id {id})", {
              name: a.name,
              id: asNumber(record.id),
            });
          } else {
            const created = await session.call("vm.create", [
              vmCreateParams({
                name: a.name,
                vcpus: a.vcpus,
                coresPerSocket: a.coresPerSocket,
                memoryMib: a.memoryMib,
                bootloader: a.bootloader,
                autostart: a.autostart,
                description: a.description,
              }),
            ]);
            // vm.create returns the created record (with id); re-query if it
            // returned only an id so the resource carries full state.
            record = (typeof created === "object" && created !== null &&
                !Array.isArray(created))
              ? created as Record<string, unknown>
              : null;
            const newId = asNumber((record ?? {}).id) ?? asNumber(created);
            if (!record && newId !== null) {
              record = findVmById(
                await session.call("vm.query", [[["id", "=", newId]]]),
                newId,
              );
            }
            if (!record) {
              throw new Error("vm.create did not return a VM record");
            }
            context.logger.info("create_vm: created {name} (id {id})", {
              name: a.name,
              id: asNumber(record.id),
            });
          }
          const handle = await context.writeResource(
            "vm_instance",
            `vm-${sanitizeInstanceName(a.name)}`,
            toVmInstance(record, "create_vm", now),
          );
          return { dataHandles: [handle] };
        } finally {
          session.close();
        }
      },
    },

    attach_disk: {
      description:
        "Attach a zvol to a VM as a DISK device (idempotent on the device path).",
      arguments: AttachDiskArgs,
      execute: async (rawArgs, context) => {
        const a = AttachDiskArgs.parse(rawArgs);
        const now = new Date().toISOString();
        const session = await sessionFactory(connectOpts(context.globalArgs));
        try {
          const devices = await session.call("vm.device.query", [[[
            "vm",
            "=",
            a.vmId,
          ]]]);
          const existing = findDiskDevice(devices, a.zvolPath);
          let existed = true;
          let id = existing ? deviceId(existing) : null;
          if (!existing) {
            existed = false;
            const created = await session.call("vm.device.create", [
              diskDeviceParams({
                vmId: a.vmId,
                zvolPath: a.zvolPath,
                bus: a.bus,
                order: a.order,
              }),
            ]);
            id = asNumber((created as Record<string, unknown> | null)?.id);
            context.logger.info("attach_disk: {path} -> vm {vm}", {
              path: a.zvolPath,
              vm: a.vmId,
            });
          } else {
            context.logger.info(
              "attach_disk: {path} already attached to vm {vm}",
              {
                path: a.zvolPath,
                vm: a.vmId,
              },
            );
          }
          const handle = await context.writeResource(
            "vm_device",
            `dev-${a.vmId}-disk-${sanitizeInstanceName(a.zvolPath)}`,
            VmDeviceSchema.parse({
              vmId: a.vmId,
              deviceId: id,
              kind: "DISK",
              path: a.zvolPath,
              bus: a.bus,
              mac: null,
              bridge: null,
              model: null,
              existed,
              recordedAt: now,
            }),
          );
          return { dataHandles: [handle] };
        } finally {
          session.close();
        }
      },
    },

    attach_nic: {
      description:
        "Attach a NIC to a VM with a fixed MAC (idempotent on the MAC). Pass " +
        "the source VM's MAC for a same-IP cutover.",
      arguments: AttachNicArgs,
      execute: async (rawArgs, context) => {
        const a = AttachNicArgs.parse(rawArgs);
        const now = new Date().toISOString();
        const session = await sessionFactory(connectOpts(context.globalArgs));
        try {
          const devices = await session.call("vm.device.query", [[[
            "vm",
            "=",
            a.vmId,
          ]]]);
          const existing = findNicDevice(devices, a.mac);
          let existed = true;
          let id = existing ? deviceId(existing) : null;
          if (!existing) {
            existed = false;
            const created = await session.call("vm.device.create", [
              nicDeviceParams({
                vmId: a.vmId,
                mac: a.mac,
                bridge: a.bridge,
                model: a.model,
              }),
            ]);
            id = asNumber((created as Record<string, unknown> | null)?.id);
            context.logger.info("attach_nic: {mac} on {bridge} -> vm {vm}", {
              mac: a.mac,
              bridge: a.bridge,
              vm: a.vmId,
            });
          } else {
            context.logger.info("attach_nic: {mac} already on vm {vm}", {
              mac: a.mac,
              vm: a.vmId,
            });
          }
          const handle = await context.writeResource(
            "vm_device",
            `dev-${a.vmId}-nic-${sanitizeInstanceName(a.mac)}`,
            VmDeviceSchema.parse({
              vmId: a.vmId,
              deviceId: id,
              kind: "NIC",
              path: null,
              bus: null,
              mac: a.mac,
              bridge: a.bridge,
              model: a.model,
              existed,
              recordedAt: now,
            }),
          );
          return { dataHandles: [handle] };
        } finally {
          session.close();
        }
      },
    },

    start: {
      description: "Start a VM and poll briefly for the running state.",
      arguments: VmRefArgs,
      execute: async (rawArgs, context) => {
        const a = VmRefArgs.parse(rawArgs);
        const now = new Date().toISOString();
        const session = await sessionFactory(connectOpts(context.globalArgs));
        try {
          const record = await resolveVm(session, a);
          if (!record) throw new Error(`no VM matching ${a.name ?? a.vmId}`);
          const id = asNumber(record.id)!;
          context.logger.info("start: vm {id}", { id });
          await session.call("vm.start", [id]);
          // Best-effort: re-read so the resource reflects the new status.
          const after = findVmById(
            await session.call("vm.query", [[["id", "=", id]]]),
            id,
          ) ?? record;
          const handle = await context.writeResource(
            "vm_instance",
            `vm-${sanitizeInstanceName(asString(after.name) ?? String(id))}`,
            toVmInstance(after, "start", now),
          );
          return { dataHandles: [handle] };
        } finally {
          session.close();
        }
      },
    },

    stop: {
      description: "Stop a VM (graceful, then force when requested).",
      arguments: StopArgs,
      execute: async (rawArgs, context) => {
        const a = StopArgs.parse(rawArgs);
        const now = new Date().toISOString();
        const session = await sessionFactory(connectOpts(context.globalArgs));
        try {
          const record = await resolveVm(session, a);
          if (!record) throw new Error(`no VM matching ${a.name ?? a.vmId}`);
          const id = asNumber(record.id)!;
          context.logger.info("stop: vm {id} (force={force})", {
            id,
            force: a.force,
          });
          await session.call("vm.stop", [id, { force: a.force }]);
          const after = findVmById(
            await session.call("vm.query", [[["id", "=", id]]]),
            id,
          ) ?? record;
          const handle = await context.writeResource(
            "vm_instance",
            `vm-${sanitizeInstanceName(asString(after.name) ?? String(id))}`,
            toVmInstance(after, "stop", now),
          );
          return { dataHandles: [handle] };
        } finally {
          session.close();
        }
      },
    },

    status: {
      description: "Read a VM's current state (read-only).",
      arguments: VmRefArgs,
      execute: async (rawArgs, context) => {
        const a = VmRefArgs.parse(rawArgs);
        const now = new Date().toISOString();
        const session = await sessionFactory(connectOpts(context.globalArgs));
        try {
          const record = await resolveVm(session, a);
          if (!record) throw new Error(`no VM matching ${a.name ?? a.vmId}`);
          const id = asNumber(record.id)!;
          const handle = await context.writeResource(
            "vm_instance",
            `vm-${sanitizeInstanceName(asString(record.name) ?? String(id))}`,
            toVmInstance(record, "status", now),
          );
          return { dataHandles: [handle] };
        } finally {
          session.close();
        }
      },
    },

    delete: {
      description:
        "Delete a VM (and optionally its zvols). Refuses a VM lacking the " +
        "swamp marker unless force. 'Already gone' is a clean no-op.",
      arguments: DeleteArgs,
      execute: async (rawArgs, context) => {
        const a = DeleteArgs.parse(rawArgs);
        const now = new Date().toISOString();
        const session = await sessionFactory(connectOpts(context.globalArgs));
        try {
          const record = await resolveVm(session, a);
          const handles = [];
          if (record) {
            const id = asNumber(record.id)!;
            if (!a.force && !isSwampManaged(record.description)) {
              throw new Error(
                `🐊 delete: VM ${id} is not swamp-managed (description lacks ` +
                  `the marker) — refusing. Pass force=true to override.`,
              );
            }
            context.logger.info("delete: vm {id} (zvols={z})", {
              id,
              z: a.deleteZvol,
            });
            await session.call("vm.delete", [id, { zvols: a.deleteZvol }]);
            handles.push(
              await context.writeResource(
                "vm_instance",
                `vm-${
                  sanitizeInstanceName(asString(record.name) ?? String(id))
                }`,
                VmInstanceSchema.parse({
                  ...toVmInstance(record, "delete", now),
                  status: "deleted",
                }),
              ),
            );
          } else {
            context.logger.info("delete: {ref} not present — already gone", {
              ref: a.name ?? a.vmId,
            });
          }
          // Remove a dangling zvol by path even when the VM is already gone.
          if (a.deleteZvol && a.zvolPath) {
            const dataset = datasetFromDevPath(a.zvolPath);
            if (dataset) {
              try {
                await session.call("pool.dataset.delete", [dataset, {
                  recursive: false,
                }]);
                context.logger.info("delete: removed dangling zvol {ds}", {
                  ds: dataset,
                });
              } catch (err) {
                context.logger.warn("delete: zvol {ds} removal skipped: {e}", {
                  ds: dataset,
                  e: err instanceof Error ? err.message : String(err),
                });
              }
            }
          }
          return { dataHandles: handles };
        } finally {
          session.close();
        }
      },
    },
  },
} satisfies ModelDefinition<typeof GlobalArgs>;
