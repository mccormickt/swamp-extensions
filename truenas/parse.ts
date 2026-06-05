/**
 * `@mccormick/truenas` — pure parsing of TrueNAS guest inventory.
 *
 * Turns the raw result of the TrueNAS middleware `virt.instance.query` (Incus,
 * SCALE 24.10+) or the legacy `vm.query` (libvirt) into normalized {@link Vm}
 * records plus a {@link Summary} roll-up. Everything here is pure — no I/O, no
 * WebSocket — so it is unit-tested directly with canned fixtures, mirroring the
 * `transform.ts`/`inventory_test.ts` split in `@mccormick/omni`.
 *
 * Field paths are best-effort and defensive: TrueNAS shapes drift across
 * releases (and the Incus `raw` block is only present on some query options),
 * so a missing field becomes a `notes` entry, never a thrown error. Confirm the
 * exact shape against the live host during a probe and tighten as needed.
 *
 * @module
 */
import type { Disk, Nic, Summary, Vm, VmState } from "./schema.ts";

/** Raw inventory as returned by {@link collectInventory}. */
export interface TruenasRawInventory {
  /** Result of `virt.instance.query` (incus) or `vm.query` (libvirt). */
  instances: unknown[];
  /** Result of `system.info`, or null when the call failed. */
  systemInfo: Record<string, unknown> | null;
}

/** Which TrueNAS guest backend produced {@link TruenasRawInventory.instances}. */
export type ResolvedBackend = "incus" | "libvirt";

const MIB = 1024 * 1024;

// ---------------------------------------------------------------------------
// Loose-value accessors — tolerate the unknown shape without throwing.
// ---------------------------------------------------------------------------

function asRecord(v: unknown): Record<string, unknown> | null {
  return typeof v === "object" && v !== null && !Array.isArray(v)
    ? v as Record<string, unknown>
    : null;
}

function asString(v: unknown): string | null {
  if (typeof v === "string") return v;
  if (typeof v === "number" && Number.isFinite(v)) return String(v);
  return null;
}

function asNumber(v: unknown): number | null {
  if (typeof v === "number" && Number.isFinite(v)) return v;
  if (typeof v === "string" && v.trim() !== "" && Number.isFinite(Number(v))) {
    return Number(v);
  }
  return null;
}

function asBoolean(v: unknown): boolean | null {
  if (typeof v === "boolean") return v;
  if (typeof v === "string") {
    const s = v.trim().toLowerCase();
    if (["true", "1", "yes", "on"].includes(s)) return true;
    if (["false", "0", "no", "off"].includes(s)) return false;
  }
  return null;
}

// ---------------------------------------------------------------------------
// Numeric parsers (exported for unit tests).
// ---------------------------------------------------------------------------

/**
 * Parse a CPU limit into a whole vCPU count. Accepts a plain count (`2`,
 * `"2"`), a pinned range (`"0-3"` → 4), or a CPU set (`"0,2,4"` → 3). Returns
 * null for unset, relative (`"50%"`), or unparseable values.
 */
export function parseCpuCount(v: unknown): number | null {
  if (typeof v === "number") {
    return Number.isFinite(v) && v > 0 ? Math.trunc(v) : null;
  }
  if (typeof v !== "string") return null;
  const s = v.trim();
  if (s === "" || s.endsWith("%")) return null;
  if (/^\d+$/.test(s)) return Number(s) > 0 ? Number(s) : null;
  // Comma-separated set, where each token is a single id or an inclusive range.
  let total = 0;
  for (const tok of s.split(",")) {
    const t = tok.trim();
    if (/^\d+$/.test(t)) {
      total += 1;
    } else {
      const m = t.match(/^(\d+)-(\d+)$/);
      if (!m) return null;
      const lo = Number(m[1]);
      const hi = Number(m[2]);
      if (hi < lo) return null;
      total += hi - lo + 1;
    }
  }
  return total > 0 ? total : null;
}

/**
 * Parse an Incus-style memory limit into MiB. Accepts a byte count (a number,
 * or a unit-less numeric string treated as bytes) or a suffixed string
 * (`"2GiB"`, `"512MiB"`, `"1.5GB"`). Binary (GiB/MiB) and decimal (GB/MB)
 * units are both honored. Returns null for unset or relative (`"50%"`) values.
 */
export function parseMemoryToMib(v: unknown): number | null {
  if (typeof v === "number") {
    return Number.isFinite(v) && v > 0 ? Math.round(v / MIB) : null;
  }
  if (typeof v !== "string") return null;
  const s = v.trim();
  if (s === "" || s.endsWith("%")) return null;
  const m = s.match(/^(\d+(?:\.\d+)?)\s*([KMGTP]i?B|B)?$/i);
  if (!m) return null;
  const value = Number(m[1]);
  if (!Number.isFinite(value) || value <= 0) return null;
  const unit = (m[2] ?? "B").toUpperCase();
  const factors: Record<string, number> = {
    "B": 1,
    "KB": 1000,
    "MB": 1000 * 1000,
    "GB": 1000 * 1000 * 1000,
    "TB": 1000 ** 4,
    "PB": 1000 ** 5,
    "KIB": 1024,
    "MIB": 1024 * 1024,
    "GIB": 1024 ** 3,
    "TIB": 1024 ** 4,
    "PIB": 1024 ** 5,
  };
  const bytes = value * (factors[unit] ?? 1);
  return Math.round(bytes / MIB);
}

/** Map a raw TrueNAS/Incus status string onto a normalized {@link VmState}. */
export function normalizeState(rawStatus: string): VmState {
  switch (rawStatus.trim().toUpperCase()) {
    case "RUNNING":
      return "running";
    case "STOPPED":
      return "stopped";
    case "FROZEN":
    case "SUSPENDED":
    case "PAUSED":
      return "suspended";
    default:
      return "unknown";
  }
}

// ---------------------------------------------------------------------------
// Incus: virt.instance.query
// ---------------------------------------------------------------------------

function parseIncusDevices(
  devices: Record<string, unknown>,
): { disks: Disk[]; nics: Nic[]; macs: string[] } {
  const disks: Disk[] = [];
  const nics: Nic[] = [];
  const macs: string[] = [];
  for (const [name, rawDev] of Object.entries(devices)) {
    const dev = asRecord(rawDev);
    if (!dev) continue;
    const type = (asString(dev.type) ?? "").toLowerCase();
    if (type === "nic") {
      const mac = asString(dev.hwaddr);
      if (mac) macs.push(mac.toLowerCase());
      nics.push({
        name,
        mac: mac ? mac.toLowerCase() : null,
        model: asString(dev.nictype) ?? (dev.network ? "bridged" : null),
        bridge: asString(dev.network) ?? asString(dev.parent),
      });
    } else if (type === "disk") {
      disks.push({
        name,
        source: asString(dev.source) ?? asString(dev.pool),
        sizeBytes: parseSizeBytes(dev.size),
        bus: asString(dev["io.bus"]) ?? asString(dev.bus),
      });
    }
  }
  return { disks, nics, macs };
}

function parseSizeBytes(v: unknown): number | null {
  const mib = parseMemoryToMib(v);
  return mib === null ? null : mib * MIB;
}

/** Collect volatile MACs (`volatile.<iface>.hwaddr`) from an Incus config map. */
function macsFromConfig(config: Record<string, unknown>): string[] {
  const macs: string[] = [];
  for (const [key, val] of Object.entries(config)) {
    if (/^volatile\..+\.hwaddr$/.test(key)) {
      const mac = asString(val);
      if (mac) macs.push(mac.toLowerCase());
    }
  }
  return macs;
}

function parseIncusInstance(raw: unknown, observedAt: string): Vm {
  const notes: string[] = [];
  const inst = asRecord(raw) ?? {};
  const id = asString(inst.id) ?? asString(inst.name) ?? "unknown";
  const name = asString(inst.name) ?? id;
  const rawStatus = asString(inst.status) ?? "UNKNOWN";
  const state = normalizeState(rawStatus);

  const rawBlock = asRecord(inst.raw) ?? {};
  const config = asRecord(rawBlock.config) ?? {};
  const devices = asRecord(rawBlock.devices) ?? asRecord(inst.devices) ?? {};

  const vcpus = parseCpuCount(config["limits.cpu"]) ?? parseCpuCount(inst.cpu);
  if (vcpus === null) notes.push("vcpus: no concrete limits.cpu reported");

  const memoryMib = parseMemoryToMib(config["limits.memory"]) ??
    parseMemoryToMib(inst.memory);
  if (memoryMib === null) {
    notes.push("memory: no concrete limits.memory reported");
  }

  const autostart = asBoolean(config["boot.autostart"]) ??
    asBoolean(inst.autostart) ?? false;

  const { disks, nics, macs } = parseIncusDevices(devices);
  const allMacs = [...new Set([...macs, ...macsFromConfig(config)])];
  if (allMacs.length === 0) notes.push("nics: no MAC addresses resolved");

  const description = asString(config["user.description"]) ??
    asString(inst.description);

  return {
    id,
    name,
    state,
    rawStatus,
    vcpus,
    memoryMib,
    autostart,
    disks,
    nics,
    macs: allMacs,
    description,
    observedAt,
    notes,
  };
}

// ---------------------------------------------------------------------------
// libvirt: vm.query (legacy TrueNAS, pre-24.10)
// ---------------------------------------------------------------------------

function parseLibvirtVm(raw: unknown, observedAt: string): Vm {
  const notes: string[] = [];
  const vm = asRecord(raw) ?? {};
  const id = asString(vm.id) ?? asString(vm.name) ?? "unknown";
  const name = asString(vm.name) ?? id;
  // status is `{ state, pid, domain_state }` on legacy vm.query.
  const statusRec = asRecord(vm.status);
  const rawStatus = asString(statusRec?.state) ?? asString(vm.status) ??
    "UNKNOWN";
  const state = normalizeState(rawStatus);

  const vcpus = asNumber(vm.vcpus);
  // Legacy vm.query reports `memory` already in MiB.
  const memoryMib = asNumber(vm.memory);
  const autostart = asBoolean(vm.autostart) ?? false;

  const disks: Disk[] = [];
  const nics: Nic[] = [];
  const macs: string[] = [];
  const devices = Array.isArray(vm.devices) ? vm.devices : [];
  for (const rawDev of devices) {
    const dev = asRecord(rawDev);
    if (!dev) continue;
    const dtype = (asString(dev.dtype) ?? asString(dev.attributes_type) ?? "")
      .toUpperCase();
    const attrs = asRecord(dev.attributes) ?? {};
    if (dtype === "NIC") {
      const mac = asString(attrs.mac);
      if (mac) macs.push(mac.toLowerCase());
      nics.push({
        name: asString(dev.id) ?? "nic",
        mac: mac ? mac.toLowerCase() : null,
        model: asString(attrs.type),
        bridge: asString(attrs.nic_attach),
      });
    } else if (dtype === "DISK") {
      disks.push({
        name: asString(dev.id) ?? "disk",
        source: asString(attrs.path),
        sizeBytes: null,
        bus: asString(attrs.type),
      });
    }
  }
  if (vcpus === null) notes.push("vcpus: not reported by vm.query");

  return {
    id,
    name,
    state,
    rawStatus,
    vcpus,
    memoryMib,
    autostart,
    disks,
    nics,
    macs: [...new Set(macs)],
    description: asString(vm.description),
    observedAt,
    notes,
  };
}

// ---------------------------------------------------------------------------
// Roll-up
// ---------------------------------------------------------------------------

function hostFromSystemInfo(
  systemInfo: Record<string, unknown> | null,
  fallback: string,
): string {
  return asString(systemInfo?.hostname) ?? fallback;
}

function versionFromSystemInfo(
  systemInfo: Record<string, unknown> | null,
): string {
  return asString(systemInfo?.version) ?? "unknown";
}

/** Fold raw TrueNAS inventory into normalized guests + a summary roll-up. */
export function buildInventory(
  raw: TruenasRawInventory,
  endpoint: string,
  backend: ResolvedBackend,
  observedAt: string,
): { vms: Vm[]; summary: Summary } {
  const notes: string[] = [];
  const parseOne = backend === "libvirt" ? parseLibvirtVm : parseIncusInstance;
  const vms = raw.instances
    .map((inst) => parseOne(inst, observedAt))
    .sort((a, b) => a.name.localeCompare(b.name));

  if (raw.systemInfo === null) {
    notes.push(
      "system.info unavailable; host/version fall back to the endpoint",
    );
  }

  let runningCount = 0;
  let stoppedCount = 0;
  let otherCount = 0;
  let totalVcpus = 0;
  let totalMemoryMib = 0;
  for (const vm of vms) {
    if (vm.state === "running") runningCount++;
    else if (vm.state === "stopped") stoppedCount++;
    else otherCount++;
    if (vm.vcpus !== null) totalVcpus += vm.vcpus;
    if (vm.memoryMib !== null) totalMemoryMib += vm.memoryMib;
  }

  const summary: Summary = {
    host: hostFromSystemInfo(raw.systemInfo, endpoint),
    truenasVersion: versionFromSystemInfo(raw.systemInfo),
    backend,
    totalVms: vms.length,
    runningCount,
    stoppedCount,
    otherCount,
    totalVcpus,
    totalMemoryMib,
    notes,
    observedAt,
  };
  return { vms, summary };
}
