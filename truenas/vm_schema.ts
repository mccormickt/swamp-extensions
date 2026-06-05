/**
 * `@mccormick/truenas/vm` — provisioning resource schemas.
 *
 * The `vm` model writes three resource kinds as it stands up a guest from a
 * zvol: a `zvol` (the backing block volume), a `vm_instance` (the libvirt VM),
 * and one `vm_device` per attached disk/NIC. These are the data contract the
 * migration workflow wires together with CEL (`data.latest("truenas-vm",
 * "zvol").attributes.devPath`, …) and the migration-summary report reads, so the
 * field shapes are kept explicit and stable.
 *
 * Sibling to the read-only `inventory` model; the two share `client.ts` and the
 * `sanitizeInstanceName` helper from `schema.ts`.
 *
 * @module
 */
import { z } from "npm:zod@4";

/**
 * A ZFS volume (zvol) created to back a guest disk. `devPath` is the stable
 * `/dev/zvol/<pool>/<name>` path libvirt attaches and the disk streamer writes.
 */
export const ZvolSchema = z.object({
  pool: z.string().describe("ZFS pool the volume lives in (e.g. Main)"),
  name: z.string().describe("Volume name within the pool"),
  fullName: z.string().describe("ZFS dataset id: <pool>/<name>"),
  sizeBytes: z.number().int().describe("Provisioned volsize in bytes"),
  sparse: z.boolean().describe(
    "Whether the volume is sparse (thin) provisioned",
  ),
  blocksize: z.string().nullable().describe(
    "volblocksize if explicitly set, else null",
  ),
  devPath: z.string().describe("Block device path: /dev/zvol/<pool>/<name>"),
  exists: z.boolean().describe(
    "True when the create was a no-op because the zvol already existed",
  ),
  recordedAt: z.iso.datetime().describe("When this record was written"),
});
/** {@link ZvolSchema} */
export type Zvol = z.infer<typeof ZvolSchema>;

/** A TrueNAS libvirt VM created/observed by the provisioning model. */
export const VmInstanceSchema = z.object({
  id: z.number().int().describe("libvirt VM id assigned by TrueNAS"),
  name: z.string().describe("VM name (alphanumeric — TrueNAS rejects others)"),
  bootloader: z.string().describe("UEFI or UEFI_CSM"),
  vcpus: z.number().int().nullable().describe("Virtual CPU count, if known"),
  coresPerSocket: z.number().int().nullable().describe(
    "Cores per socket, if set",
  ),
  memoryMib: z.number().int().nullable().describe("Memory in MiB, if known"),
  autostart: z.boolean().describe("Whether the VM boots with the host"),
  status: z.string().describe(
    "Lifecycle state: running, stopped, unknown, ...",
  ),
  swampManaged: z.boolean().describe(
    "Whether the description carries the swamp marker",
  ),
  description: z.string().nullable().describe("VM description, if set"),
  lastOperation: z.string().describe("The method that produced this record"),
  recordedAt: z.iso.datetime().describe("When this record was written"),
});
/** {@link VmInstanceSchema} */
export type VmInstance = z.infer<typeof VmInstanceSchema>;

/** A disk or NIC device attached to a VM. */
export const VmDeviceSchema = z.object({
  vmId: z.number().int().describe("Owning VM id"),
  deviceId: z.number().int().nullable().describe(
    "TrueNAS device id, or null when reused/unknown",
  ),
  kind: z.enum(["DISK", "NIC"]).describe("Device kind"),
  path: z.string().nullable().describe("DISK: backing zvol device path"),
  bus: z.string().nullable().describe("DISK: IO bus (VIRTIO, AHCI)"),
  mac: z.string().nullable().describe("NIC: MAC address"),
  bridge: z.string().nullable().describe("NIC: host bridge it attaches to"),
  model: z.string().nullable().describe("NIC: device model (VIRTIO, E1000)"),
  existed: z.boolean().describe(
    "True when attach was a no-op because the device already existed",
  ),
  recordedAt: z.iso.datetime().describe("When this record was written"),
});
/** {@link VmDeviceSchema} */
export type VmDevice = z.infer<typeof VmDeviceSchema>;
