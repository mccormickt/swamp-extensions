/**
 * `@mccormick/omni` — pure transforms that fold Omni's COSI resources into the
 * inventory schema.
 *
 * Omni splits one machine's state across several resources: `MachineStatus`
 * (hardware, network, Talos version), `ClusterMachineStatus` (stage, readiness,
 * role labels), and `ClusterMachineIdentity` (the Kubernetes node name). These
 * functions index those resources by machine UUID and merge them into the flat
 * {@link NodeData} / {@link ClusterData} / {@link SummaryData} records the
 * model writes. They are deliberately free of I/O so they can be unit-tested
 * directly.
 *
 * @module
 */
import type { CosiResource } from "./omnictl.ts";
import type { ClusterData, NodeData, SummaryData } from "./schema.ts";

/** Omni `MachineStatusSpec.Role` enum values. */
const ROLE_NAMES: Record<number, string> = {
  0: "none",
  1: "controlplane",
  2: "worker",
};

/** Omni `ClusterMachineStatusSpec.Stage` enum values. */
const STAGE_NAMES: Record<number, string> = {
  0: "unknown",
  1: "booting",
  2: "installing",
  3: "configuring",
  4: "running",
  5: "upgrading",
  6: "rebooting",
  7: "shutting-down",
  8: "before-destroy",
  9: "destroying",
  10: "powering-on",
  11: "powered-off",
};

/** Map a `MachineStatusSpec.Role` integer to a name, with a `role-<n>` fallback. */
export function decodeRole(role: unknown): string {
  if (typeof role === "number" && role in ROLE_NAMES) return ROLE_NAMES[role];
  return typeof role === "number" ? `role-${role}` : "none";
}

/** Map a `ClusterMachineStatusSpec.Stage` integer to a name, with a fallback. */
export function decodeStage(stage: unknown): string {
  if (typeof stage === "number" && stage in STAGE_NAMES) {
    return STAGE_NAMES[stage];
  }
  return typeof stage === "number" ? `stage-${stage}` : "unknown";
}

/**
 * Resolve a machine's role. Omni's `ClusterMachineStatus` carries an
 * unambiguous `omni.sidero.dev/role-controlplane` / `role-worker` label key;
 * prefer it, and fall back to decoding the `MachineStatus` role integer for
 * machines not yet in a cluster.
 */
export function roleFromLabels(
  labels: Record<string, unknown> | undefined,
  specRole: unknown,
): string {
  if (labels) {
    if ("omni.sidero.dev/role-controlplane" in labels) return "controlplane";
    if ("omni.sidero.dev/role-worker" in labels) return "worker";
  }
  return decodeRole(specRole);
}

/** Index a list of COSI resources by `metadata.id`. */
function indexById(resources: CosiResource[]): Map<string, CosiResource> {
  const map = new Map<string, CosiResource>();
  for (const r of resources) {
    if (r.metadata?.id) map.set(r.metadata.id, r);
  }
  return map;
}

/** Coerce an unknown value to a string, falling back to `fallback`. */
function asString(value: unknown, fallback = ""): string {
  return typeof value === "string" ? value : fallback;
}

/** Coerce an unknown value to a finite number, falling back to `0`. */
function asNumber(value: unknown): number {
  return typeof value === "number" && Number.isFinite(value) ? value : 0;
}

/** Coerce an unknown value to a string array, dropping non-string entries. */
function asStringArray(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter((v): v is string => typeof v === "string")
    : [];
}

/** The raw resource lists one discovery run pulls from Omni. */
export interface RawInventory {
  /** Omni endpoint the resources were read from. */
  endpoint: string;
  /** `MachineStatuses.omni.sidero.dev`. */
  machineStatuses: CosiResource[];
  /** `ClusterMachineStatuses.omni.sidero.dev`. */
  clusterMachineStatuses: CosiResource[];
  /** `ClusterMachineIdentities.omni.sidero.dev`. */
  clusterMachineIdentities: CosiResource[];
  /** `Clusters.omni.sidero.dev`. */
  clusters: CosiResource[];
}

/** The merged inventory: per-node and per-cluster records plus a summary. */
export interface MergedInventory {
  /** One record per machine, sorted by hostname. */
  nodes: NodeData[];
  /** One record per cluster, sorted by name. */
  clusters: ClusterData[];
  /** The single roll-up record. */
  summary: SummaryData;
}

/** Build one {@link NodeData} from a `MachineStatus` and its related resources. */
function buildNode(
  machineStatus: CosiResource,
  clusterMachineStatus: CosiResource | undefined,
  identity: CosiResource | undefined,
  discoveredAt: string,
): NodeData {
  const id = machineStatus.metadata.id;
  const labels = machineStatus.metadata.labels ?? {};
  const spec = machineStatus.spec;
  const network = (spec.network ?? {}) as Record<string, unknown>;
  const hardware = (spec.hardware ?? {}) as Record<string, unknown>;
  const securityState = (spec.securitystate ?? {}) as Record<string, unknown>;
  const schematic = (spec.schematic ?? {}) as Record<string, unknown>;
  const cmsLabels = clusterMachineStatus?.metadata.labels;
  const cmsSpec = clusterMachineStatus?.spec;
  const idSpec = identity?.spec;

  const processors = Array.isArray(hardware.processors)
    ? hardware.processors as Record<string, unknown>[]
    : [];
  const memoryModules = Array.isArray(hardware.memorymodules)
    ? hardware.memorymodules as Record<string, unknown>[]
    : [];
  const blockDevices = Array.isArray(hardware.blockdevices)
    ? hardware.blockdevices as Record<string, unknown>[]
    : [];

  const cluster = asString(spec.cluster) || null;

  return {
    id,
    hostname: asString(network.hostname) ||
      asString(labels["omni.sidero.dev/hostname"]),
    cluster,
    role: roleFromLabels(cmsLabels ?? labels, spec.role),
    machineSet: asString(labels["omni.sidero.dev/machine-set"]) || null,
    connected: spec.connected === true,
    maintenance: spec.maintenance === true,
    stage: cmsSpec ? decodeStage(cmsSpec.stage) : "unassigned",
    ready: cmsSpec?.ready === true,
    apidAvailable: cmsSpec?.apidavailable === true,
    talosVersion: asString(spec.talosversion) ||
      asString(labels["omni.sidero.dev/talos-version"]),
    kubernetesNodeName: idSpec ? asString(idSpec.nodename) || null : null,
    nodeIps: asStringArray(idSpec?.nodeips),
    addresses: asStringArray(network.addresses),
    managementAddress: asString(spec.managementaddress) || null,
    arch: asString(hardware.arch) || asString(labels["omni.sidero.dev/arch"]),
    cpuCores: processors.reduce((sum, p) => sum + asNumber(p.corecount), 0),
    cpuThreads: processors.reduce((sum, p) => sum + asNumber(p.threadcount), 0),
    cpuDescription: asString(processors[0]?.description),
    memoryMib: memoryModules.reduce((sum, m) => sum + asNumber(m.sizemb), 0),
    blockDevices: blockDevices.map((d) => ({
      name: asString(d.linuxname),
      model: asString(d.model),
      type: asString(d.type),
      transport: asString(d.transport),
      sizeBytes: asNumber(d.size),
      systemDisk: d.systemdisk === true,
    })),
    secureBoot: securityState.secureboot === true,
    bootedWithUki: securityState.bootedwithuki === true,
    talosExtensions: asStringArray(schematic.extensions),
    lastError: asString(spec.lasterror) || null,
    discoveredAt,
  };
}

/**
 * Fold Omni's COSI resources into the inventory schema. Each `MachineStatus`
 * becomes a node; each `Cluster` becomes a cluster with rolled-up machine
 * counts; a single summary aggregates the run. Inconsistencies — a machine
 * assigned to a cluster Omni did not return, or a machine with a cluster but no
 * `ClusterMachineStatus` — are recorded in `summary.notes` and never throw.
 */
export function mergeInventory(
  raw: RawInventory,
  discoveredAt: string,
): MergedInventory {
  const cmsById = indexById(raw.clusterMachineStatuses);
  const identityById = indexById(raw.clusterMachineIdentities);
  const clusterNames = new Set(
    raw.clusters.map((c) => c.metadata.id).filter((id) => id.length > 0),
  );
  const notes: string[] = [];

  const nodes = raw.machineStatuses
    .map((ms) =>
      buildNode(
        ms,
        cmsById.get(ms.metadata.id),
        identityById.get(ms.metadata.id),
        discoveredAt,
      )
    )
    .sort((a, b) => a.hostname.localeCompare(b.hostname));

  for (const node of nodes) {
    if (node.cluster && !clusterNames.has(node.cluster)) {
      notes.push(
        `machine ${node.id} references cluster "${node.cluster}" which Omni did not return`,
      );
    }
    if (node.cluster && node.stage === "unassigned") {
      notes.push(
        `machine ${node.id} is in cluster "${node.cluster}" but has no ClusterMachineStatus`,
      );
    }
  }

  const clusters: ClusterData[] = raw.clusters
    .map((c) => {
      const name = c.metadata.id;
      const spec = c.spec;
      const members = nodes.filter((n) => n.cluster === name);
      return {
        name,
        kubernetesVersion: asString(spec.kubernetesversion),
        talosVersion: asString(spec.talosversion),
        machineCount: members.length,
        controlPlaneCount: members.filter((n) =>
          n.role === "controlplane"
        ).length,
        workerCount: members.filter((n) => n.role === "worker").length,
        connectedCount: members.filter((n) => n.connected).length,
        discoveredAt,
      };
    })
    .sort((a, b) => a.name.localeCompare(b.name));

  const byCluster: Record<string, number> = {};
  const byRole: Record<string, number> = {};
  const byTalosVersion: Record<string, number> = {};
  for (const node of nodes) {
    const clusterKey = node.cluster ?? "(unassigned)";
    byCluster[clusterKey] = (byCluster[clusterKey] ?? 0) + 1;
    byRole[node.role] = (byRole[node.role] ?? 0) + 1;
    const talosKey = node.talosVersion || "(unknown)";
    byTalosVersion[talosKey] = (byTalosVersion[talosKey] ?? 0) + 1;
  }

  return {
    nodes,
    clusters,
    summary: {
      endpoint: raw.endpoint,
      totalNodes: nodes.length,
      connectedCount: nodes.filter((n) => n.connected).length,
      clusterCount: clusters.length,
      byCluster,
      byRole,
      byTalosVersion,
      notes,
      discoveredAt,
    },
  };
}
