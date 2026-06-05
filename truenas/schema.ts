/**
 * `@mccormick/truenas` — Incus/VM inventory resource schemas.
 *
 * The `inventory` model writes two resource kinds: one `vm` per guest TrueNAS
 * manages (Incus instance on SCALE 24.10+, or a legacy libvirt VM), and a
 * single `summary` roll-up. Downstream models, the `inventory-fleet` workflow,
 * and the fleet report read these by spec name, so the field shapes are a data
 * contract — keep them stable and carry the common minimal set
 * (`name`, `state`, `vcpus`, `memoryMib`, `macs`) every hypervisor provider
 * shares.
 *
 * @module
 */
import { z } from "npm:zod@4";

/**
 * FNV-1a 32-bit hash, returned as zero-padded 8-char hex. Deterministic and
 * synchronous — used to keep long sanitized instance names unique.
 */
function stableHash(input: string): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < input.length; i++) {
    h ^= input.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return (h >>> 0).toString(16).padStart(8, "0");
}

/**
 * Normalize an arbitrary string into a safe `writeResource` instance name:
 * lowercase, non-alphanumeric runs collapsed to `-`, trimmed. `writeResource`
 * instance names are global across specs, so callers must still prefix with a
 * spec discriminator. Long inputs are truncated with a hash suffix to keep
 * uniqueness.
 */
export function sanitizeInstanceName(raw: string): string {
  const cleaned = raw
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
  if (cleaned.length === 0) return "unnamed";
  if (cleaned.length <= 100) return cleaned;
  return `${cleaned.slice(0, 91)}-${stableHash(raw)}`;
}

// ---------------------------------------------------------------------------
// vm — one per guest
// ---------------------------------------------------------------------------

/** A normalized guest lifecycle state shared across hypervisor providers. */
export const VmStateSchema = z.enum([
  "running",
  "stopped",
  "suspended",
  "unknown",
]);
/** {@link VmStateSchema} */
export type VmState = z.infer<typeof VmStateSchema>;

/** A disk attached to a guest. */
export const DiskSchema = z.object({
  name: z.string().describe("Device name within the guest config"),
  source: z.string().nullable().describe(
    "Backing source: storage pool/volume, dataset, or host path",
  ),
  sizeBytes: z.number().nullable().describe("Disk capacity in bytes, if known"),
  bus: z.string().nullable().describe("IO bus, e.g. virtio-blk, nvme, ahci"),
});
/** {@link DiskSchema} */
export type Disk = z.infer<typeof DiskSchema>;

/** A network interface attached to a guest. */
export const NicSchema = z.object({
  name: z.string().describe("Device name within the guest config"),
  mac: z.string().nullable().describe("MAC address, if assigned"),
  model: z.string().nullable().describe(
    "NIC kind: bridged, macvlan, virtio, e1000, ...",
  ),
  bridge: z.string().nullable().describe(
    "Host bridge / parent interface / network the NIC attaches to",
  ),
});
/** {@link NicSchema} */
export type Nic = z.infer<typeof NicSchema>;

/**
 * A guest managed by TrueNAS — an Incus instance of `type: VM` on SCALE
 * 24.10+, or a legacy libvirt VM. Fields are declared explicitly (never bare
 * passthrough) because this schema is the report/workflow data contract.
 */
export const VmSchema = z.object({
  id: z.string().describe("Stable guest id (Incus instance id or VM id)"),
  name: z.string().describe("Guest name"),
  state: VmStateSchema.describe("Normalized lifecycle state"),
  rawStatus: z.string().describe(
    "Raw status string from TrueNAS before normalization",
  ),
  vcpus: z.number().int().nullable().describe(
    "Virtual CPU count, or null when the limit is unset/relative",
  ),
  memoryMib: z.number().int().nullable().describe(
    "Memory allocation in MiB, or null when unset/relative",
  ),
  autostart: z.boolean().describe("Whether the guest boots with the host"),
  disks: z.array(DiskSchema).default([]).describe("Attached disks"),
  nics: z.array(NicSchema).default([]).describe("Attached network interfaces"),
  macs: z.array(z.string()).default([]).describe(
    "All MAC addresses observed for the guest (for cross-layer correlation)",
  ),
  description: z.string().nullable().describe("Guest description, if set"),
  observedAt: z.iso.datetime().describe("When this record was discovered"),
  notes: z.array(z.string()).default([]).describe(
    "Per-guest non-fatal parse notes (fields TrueNAS did not report)",
  ),
});
/** {@link VmSchema} */
export type Vm = z.infer<typeof VmSchema>;

// ---------------------------------------------------------------------------
// summary — emitted once per discovery run
// ---------------------------------------------------------------------------

/**
 * Roll-up of one inventory run. `notes` records run-level non-fatal issues
 * (e.g. `system.info` was unreachable so the version is unknown) so an oddity
 * never aborts the discovery.
 */
export const SummarySchema = z.object({
  host: z.string().describe("TrueNAS host the inventory was taken from"),
  truenasVersion: z.string().describe(
    "TrueNAS version string, or 'unknown' when system.info was unavailable",
  ),
  backend: z.string().describe("Resolved guest backend: incus or libvirt"),
  totalVms: z.number().int().describe("Total guests discovered"),
  runningCount: z.number().int().describe("Guests in the running state"),
  stoppedCount: z.number().int().describe("Guests in the stopped state"),
  otherCount: z.number().int().describe(
    "Guests in suspended/unknown states",
  ),
  totalVcpus: z.number().int().describe(
    "Sum of vcpus across guests with a concrete count",
  ),
  totalMemoryMib: z.number().int().describe(
    "Sum of memoryMib across guests with a concrete allocation",
  ),
  notes: z.array(z.string()).default([]).describe(
    "Non-fatal issues observed during discovery",
  ),
  observedAt: z.iso.datetime().describe("When this run completed"),
});
/** {@link SummarySchema} */
export type Summary = z.infer<typeof SummarySchema>;
