/**
 * `@mccormick/omni` — Talos node inventory resource schemas.
 *
 * The `inventory` model writes three resource kinds: one `node` per machine
 * Omni manages, one `cluster` per cluster, and a single `summary` roll-up.
 * Downstream models and workflows read these by spec name, so the field shapes
 * are a data contract — keep them stable.
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
// node — one per machine
// ---------------------------------------------------------------------------

/** A block device attached to a Talos machine. */
export const BlockDeviceSchema = z.object({
  name: z.string().describe("Linux device name, e.g. /dev/sda"),
  model: z.string().describe("Device model string"),
  type: z.string().describe("Device type: SSD, HDD, CD, NVME, ..."),
  transport: z.string().describe(
    "Bus transport: virtio, iscsi, ata, nvme, ...",
  ),
  sizeBytes: z.number().describe("Device capacity in bytes"),
  systemDisk: z.boolean().describe("True for the Talos system disk"),
});
/** {@link BlockDeviceSchema} */
export type BlockDevice = z.infer<typeof BlockDeviceSchema>;

/** An Omni-managed Talos machine and its current cluster membership. */
export const NodeSchema = z.object({
  id: z.string().describe("Omni machine UUID"),
  hostname: z.string().describe("Machine network hostname"),
  cluster: z.string().nullable().describe(
    "Cluster the machine belongs to, or null when unassigned",
  ),
  role: z.string().describe(
    "Machine role: controlplane, worker, none, or role-<n> when unknown",
  ),
  machineSet: z.string().nullable().describe("Omni machine set, if assigned"),
  connected: z.boolean().describe("Whether Omni currently reaches the machine"),
  maintenance: z.boolean().describe("True when booted in maintenance mode"),
  stage: z.string().describe(
    "Cluster-machine stage: running, booting, installing, unassigned, ...",
  ),
  ready: z.boolean().describe("Cluster-machine readiness"),
  apidAvailable: z.boolean().describe("Whether the Talos apid is reachable"),
  talosVersion: z.string().describe("Running Talos version"),
  kubernetesNodeName: z.string().nullable().describe(
    "Kubernetes node name, or null when the machine has not joined a cluster",
  ),
  nodeIps: z.array(z.string()).default([]).describe("Kubernetes node IPs"),
  addresses: z.array(z.string()).default([]).describe(
    "All network addresses reported for the machine",
  ),
  managementAddress: z.string().nullable().describe(
    "Omni SideroLink management address",
  ),
  arch: z.string().describe("CPU architecture, e.g. amd64 or arm64"),
  cpuCores: z.number().int().describe("Total CPU cores across all processors"),
  cpuThreads: z.number().int().describe(
    "Total CPU threads across all processors",
  ),
  cpuDescription: z.string().describe("CPU model description"),
  memoryMib: z.number().int().describe("Total installed memory in MiB"),
  blockDevices: z.array(BlockDeviceSchema).default([]).describe(
    "Block devices attached to the machine",
  ),
  secureBoot: z.boolean().describe(
    "Whether the machine booted with SecureBoot",
  ),
  bootedWithUki: z.boolean().describe(
    "Whether the machine booted from a Unified Kernel Image",
  ),
  talosExtensions: z.array(z.string()).default([]).describe(
    "Talos system extensions installed via the machine's schematic",
  ),
  lastError: z.string().nullable().describe("Last machine error, if any"),
  discoveredAt: z.iso.datetime().describe("When this record was discovered"),
});
/** {@link NodeSchema} */
export type NodeData = z.infer<typeof NodeSchema>;

// ---------------------------------------------------------------------------
// cluster — one per cluster
// ---------------------------------------------------------------------------

/** A Talos cluster managed by Omni, with rolled-up machine counts. */
export const ClusterSchema = z.object({
  name: z.string().describe("Cluster name"),
  kubernetesVersion: z.string().describe("Kubernetes version"),
  talosVersion: z.string().describe("Cluster default Talos version"),
  machineCount: z.number().int().describe("Total machines in the cluster"),
  controlPlaneCount: z.number().int().describe("Control-plane machine count"),
  workerCount: z.number().int().describe("Worker machine count"),
  connectedCount: z.number().int().describe("Machines Omni currently reaches"),
  discoveredAt: z.iso.datetime().describe("When this record was discovered"),
});
/** {@link ClusterSchema} */
export type ClusterData = z.infer<typeof ClusterSchema>;

// ---------------------------------------------------------------------------
// summary — emitted once per discovery run
// ---------------------------------------------------------------------------

/**
 * Roll-up of one inventory run. `notes` records non-fatal inconsistencies
 * (e.g. a machine assigned to a cluster Omni did not return) so an oddity in
 * one resource never aborts the discovery.
 */
export const SummarySchema = z.object({
  endpoint: z.string().describe("Omni endpoint the inventory was taken from"),
  totalNodes: z.number().int().describe("Total machines discovered"),
  connectedCount: z.number().int().describe("Machines Omni currently reaches"),
  clusterCount: z.number().int().describe("Total clusters discovered"),
  byCluster: z.record(z.string(), z.number().int()).default({}).describe(
    "Node count keyed by cluster name ('(unassigned)' for free machines)",
  ),
  byRole: z.record(z.string(), z.number().int()).default({}).describe(
    "Node count keyed by role",
  ),
  byTalosVersion: z.record(z.string(), z.number().int()).default({}).describe(
    "Node count keyed by running Talos version",
  ),
  notes: z.array(z.string()).default([]).describe(
    "Non-fatal inconsistencies observed during discovery",
  ),
  discoveredAt: z.iso.datetime().describe("When this run completed"),
});
/** {@link SummarySchema} */
export type SummaryData = z.infer<typeof SummarySchema>;
