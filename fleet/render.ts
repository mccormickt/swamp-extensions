/**
 * `@mccormick/fleet` — pure normalization and rendering of a cross-hypervisor
 * VM inventory.
 *
 * Joins independent inventory providers onto flat rows by spec name — `node`
 * (Omni/Talos), `guest` (Proxmox QEMU, `@stateless/proxmox`), `vm_spec` (a
 * richer Proxmox row from `@mccormick/proxmox-migrate`), and `vm` (TrueNAS,
 * `@mccormick/truenas`) — sharing the common `name`/`state`/`vcpus`/`memoryMib`
 * contract, dedupes rows that describe the same guest (keeping the richest), and
 * renders one markdown table plus JSON totals. Everything here is pure (no I/O),
 * so it is unit-tested directly; the report does the resource reads and hands
 * the parsed objects in.
 *
 * @module
 */

/** A normalized guest row spanning every hypervisor layer. */
export interface FleetRow {
  /** Hypervisor/layer label: talos, proxmox, truenas. */
  hypervisor: string;
  /** Source model type, for provenance. */
  modelType: string;
  /** Guest name. */
  name: string;
  /** Provider-reported lifecycle state (free-form, lower-cased). */
  state: string;
  /** vCPU count, or null when the provider does not report it. */
  vcpus: number | null;
  /** Memory in MiB, or null when the provider does not report it. */
  memoryMib: number | null;
  /** Known IP addresses (CIDR suffixes stripped). */
  ips: string[];
  /** Known MAC addresses (for cross-layer correlation). */
  macs: string[];
}

/** Spec name → hypervisor label. Keys are the providers' resource contracts. */
export const SPEC_TO_HYPERVISOR: Record<string, string> = {
  node: "talos",
  guest: "proxmox",
  vm: "truenas",
  // @mccormick/proxmox-migrate `inspect` writes a richer Proxmox row (with
  // vcpus/memory/macs) than the lifecycle-only `guest` resource.
  vm_spec: "proxmox",
};

function str(v: unknown): string | null {
  return typeof v === "string" && v !== "" ? v : null;
}

function intOrNull(v: unknown): number | null {
  return typeof v === "number" && Number.isFinite(v) ? Math.trunc(v) : null;
}

function strArray(v: unknown): string[] {
  return Array.isArray(v)
    ? v.filter((x): x is string => typeof x === "string")
    : [];
}

function stripCidr(addr: string): string {
  return addr.split("/")[0];
}

/** Normalize an Omni `node` resource. */
export function normalizeNode(
  data: Record<string, unknown>,
  modelType: string,
): FleetRow {
  const ips = [...strArray(data.nodeIps), ...strArray(data.addresses)]
    .map(stripCidr);
  const state = str(data.stage) ??
    (data.connected === true ? "connected" : "disconnected");
  return {
    hypervisor: "talos",
    modelType,
    name: str(data.hostname) ?? str(data.id) ?? "unknown",
    state,
    vcpus: intOrNull(data.cpuCores),
    memoryMib: intOrNull(data.memoryMib),
    ips: [...new Set(ips)],
    macs: [],
  };
}

/** Normalize a Proxmox `guest` resource (`@stateless/proxmox/qemu`). */
export function normalizeGuest(
  data: Record<string, unknown>,
  modelType: string,
): FleetRow {
  const vmid = intOrNull(data.vmid);
  const ipv4 = str(data.ipv4);
  return {
    hypervisor: "proxmox",
    modelType,
    name: str(data.name) ?? (vmid !== null ? `vm-${vmid}` : "unknown"),
    state: str(data.status) ?? "unknown",
    // @stateless/proxmox's `guest` is lifecycle-only, so cpu/memory are usually
    // absent (read defensively in case a richer producer ever fills them). The
    // vcpus/memory "—" gap is closed by the vm_spec row below.
    vcpus: intOrNull(data.vcpus),
    memoryMib: intOrNull(data.memoryMib),
    ips: ipv4 ? [stripCidr(ipv4)] : [],
    macs: [],
  };
}

/** Normalize a Proxmox `vm_spec` resource (`@mccormick/proxmox-migrate`). */
export function normalizeVmSpec(
  data: Record<string, unknown>,
  modelType: string,
): FleetRow {
  const vmid = intOrNull(data.vmid);
  const nics = Array.isArray(data.nics) ? data.nics : [];
  const macs: string[] = [];
  const ips: string[] = [];
  for (const raw of nics) {
    if (raw && typeof raw === "object") {
      const nic = raw as Record<string, unknown>;
      const mac = str(nic.mac);
      if (mac) macs.push(mac);
      const ip = str(nic.ip);
      if (ip) ips.push(stripCidr(ip));
    }
  }
  const primaryIp = str(data.primaryIp);
  if (primaryIp) ips.push(stripCidr(primaryIp));
  return {
    hypervisor: "proxmox",
    modelType,
    name: str(data.name) ?? (vmid !== null ? `vm-${vmid}` : "unknown"),
    state: str(data.status) ?? "unknown",
    vcpus: intOrNull(data.vcpus),
    memoryMib: intOrNull(data.memoryMib),
    ips: [...new Set(ips)],
    macs: [...new Set(macs)],
  };
}

/** Normalize a TrueNAS `vm` resource (`@mccormick/truenas`). */
export function normalizeVm(
  data: Record<string, unknown>,
  modelType: string,
): FleetRow {
  return {
    hypervisor: "truenas",
    modelType,
    name: str(data.name) ?? str(data.id) ?? "unknown",
    state: str(data.state) ?? "unknown",
    vcpus: intOrNull(data.vcpus),
    memoryMib: intOrNull(data.memoryMib),
    ips: [],
    macs: strArray(data.macs),
  };
}

/**
 * Dispatch a resource to its normalizer by spec name. Returns null for spec
 * names that are not guest rows (`summary`, `cluster`, `exec`, …).
 */
export function rowFor(
  specName: string,
  data: Record<string, unknown>,
  modelType: string,
): FleetRow | null {
  switch (specName) {
    case "node":
      return normalizeNode(data, modelType);
    case "guest":
      return normalizeGuest(data, modelType);
    case "vm_spec":
      return normalizeVmSpec(data, modelType);
    case "vm":
      return normalizeVm(data, modelType);
    default:
      return null;
  }
}

/** A row's information richness — used to pick a winner when deduping. */
function richness(r: FleetRow): number {
  return (r.vcpus !== null ? 1 : 0) + (r.memoryMib !== null ? 1 : 0) +
    (r.ips.length > 0 ? 1 : 0) + (r.macs.length > 0 ? 1 : 0);
}

/**
 * Collapse rows that describe the same guest on the same hypervisor (e.g. a
 * Proxmox VM appearing as both a lifecycle-only `guest` and a richer `vm_spec`),
 * keeping the most informative one. Rows with no name are never merged.
 */
export function dedupeRows(rows: FleetRow[]): FleetRow[] {
  const best = new Map<string, FleetRow>();
  const passthrough: FleetRow[] = [];
  for (const r of rows) {
    if (r.name === "unknown" || r.name === "") {
      passthrough.push(r);
      continue;
    }
    const key = `${r.hypervisor}::${r.name}`;
    const cur = best.get(key);
    if (!cur || richness(r) > richness(cur)) best.set(key, r);
  }
  return [...best.values(), ...passthrough];
}

function cell(v: string | number | null): string {
  if (v === null || v === "") return "—";
  return String(v);
}

/** Render fleet rows into a markdown table + JSON totals. */
export function renderFleet(
  rows: FleetRow[],
): { markdown: string; json: Record<string, unknown> } {
  const sorted = [...dedupeRows(rows)].sort((a, b) =>
    a.hypervisor === b.hypervisor
      ? a.name.localeCompare(b.name)
      : a.hypervisor.localeCompare(b.hypervisor)
  );

  const lines: string[] = [];
  lines.push("# Fleet Inventory");
  lines.push("");
  lines.push(
    `Cross-hypervisor VM inventory: ${sorted.length} guests across ` +
      `Talos (Omni), Proxmox, and TrueNAS.`,
  );
  lines.push("");
  lines.push("| Hypervisor | Name | State | vCPUs | Memory (MiB) | Address |");
  lines.push("| ---------- | ---- | ----- | ----- | ------------ | ------- |");

  const byHypervisor: Record<
    string,
    { count: number; vcpus: number; memoryMib: number }
  > = {};
  for (const r of sorted) {
    const addr = r.ips[0] ?? r.macs[0] ?? null;
    lines.push(
      `| ${r.hypervisor} | ${r.name} | ${r.state} | ${cell(r.vcpus)} | ` +
        `${cell(r.memoryMib)} | ${cell(addr)} |`,
    );
    const agg = byHypervisor[r.hypervisor] ??
      { count: 0, vcpus: 0, memoryMib: 0 };
    agg.count += 1;
    if (r.vcpus !== null) agg.vcpus += r.vcpus;
    if (r.memoryMib !== null) agg.memoryMib += r.memoryMib;
    byHypervisor[r.hypervisor] = agg;
  }

  if (sorted.length === 0) {
    lines.push("| — | (no guests discovered) | — | — | — | — |");
  }

  lines.push("");
  lines.push("## Totals");
  lines.push("");
  lines.push("| Hypervisor | Guests | vCPUs | Memory (MiB) |");
  lines.push("| ---------- | ------ | ----- | ------------ |");
  for (const [hv, agg] of Object.entries(byHypervisor).sort()) {
    lines.push(`| ${hv} | ${agg.count} | ${agg.vcpus} | ${agg.memoryMib} |`);
  }

  const json: Record<string, unknown> = {
    totalGuests: sorted.length,
    byHypervisor,
    rows: sorted,
  };
  return { markdown: lines.join("\n"), json };
}
