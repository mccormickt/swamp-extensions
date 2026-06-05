/**
 * `@mccormick/truenas/vm` — pure helpers for the provisioning model.
 *
 * Everything here is side-effect-free: building the JSON-RPC parameter bags for
 * `pool.dataset.create` / `vm.create` / `vm.device.create`, deriving zvol device
 * paths, and the idempotency decisions (does this zvol/VM/device already exist?).
 * Keeping them pure means the provisioning logic is unit-tested with canned
 * middleware shapes, mirroring the `parse.ts`/`inventory_test.ts` split the
 * read-only inventory model uses. The WebSocket framing in `client.ts` is the
 * only part that needs a live host.
 *
 * @module
 */

const GIB = 1024 * 1024 * 1024;

/**
 * Marker stamped into a VM's `description` so `delete` can refuse to remove a
 * VM swamp did not provision. TrueNAS libvirt VMs have no tags field, so the
 * description is the closest durable, queryable marker (the Proxmox model uses a
 * `swamp` tag for the same purpose).
 */
export const SWAMP_MARKER = "[swamp-managed]";

// ---------------------------------------------------------------------------
// Loose-value accessors (tolerate the drifting middleware shape).
// ---------------------------------------------------------------------------

/** Narrow an unknown to a plain record, else null. */
export function asRecord(v: unknown): Record<string, unknown> | null {
  return typeof v === "object" && v !== null && !Array.isArray(v)
    ? v as Record<string, unknown>
    : null;
}

/** Coerce a string or finite number to a string, else null. */
export function asString(v: unknown): string | null {
  if (typeof v === "string") return v;
  if (typeof v === "number" && Number.isFinite(v)) return String(v);
  return null;
}

/** Coerce a finite number or numeric string to a number, else null. */
export function asNumber(v: unknown): number | null {
  if (typeof v === "number" && Number.isFinite(v)) return v;
  if (typeof v === "string" && v.trim() !== "" && Number.isFinite(Number(v))) {
    return Number(v);
  }
  return null;
}

// ---------------------------------------------------------------------------
// zvol naming + sizing
// ---------------------------------------------------------------------------

/** The ZFS dataset id of a zvol: `<pool>/<name>`. */
export function zvolFullName(pool: string, name: string): string {
  return `${pool}/${name}`;
}

/** The block device path libvirt attaches: `/dev/zvol/<pool>/<name>`. */
export function zvolDevPath(pool: string, name: string): string {
  return `/dev/zvol/${pool}/${name}`;
}

/** GiB → bytes. */
export function gibToBytes(gib: number): number {
  return Math.round(gib * GIB);
}

/**
 * Read a dataset's `volsize` in bytes from a `pool.dataset.query` record.
 * TrueNAS reports composite properties as `{parsed, rawvalue, value}`; older
 * shapes use a bare number. Returns null when absent/unparseable.
 */
export function parseVolsizeBytes(
  record: Record<string, unknown>,
): number | null {
  const v = record.volsize;
  const rec = asRecord(v);
  if (rec) return asNumber(rec.parsed) ?? asNumber(rec.rawvalue);
  return asNumber(v);
}

/** Build the `pool.dataset.create` params for a sparse/thick VOLUME. */
export function zvolCreateParams(args: {
  pool: string;
  name: string;
  sizeBytes: number;
  sparse: boolean;
  blocksize?: string;
}): Record<string, unknown> {
  const params: Record<string, unknown> = {
    name: zvolFullName(args.pool, args.name),
    type: "VOLUME",
    volsize: args.sizeBytes,
    sparse: args.sparse,
  };
  if (args.blocksize) params.volblocksize = args.blocksize;
  return params;
}

/**
 * Find an existing zvol by full name in a `pool.dataset.query` result. Returns
 * the record (for size comparison) or null.
 */
export function findDataset(
  queryResult: unknown,
  fullName: string,
): Record<string, unknown> | null {
  if (!Array.isArray(queryResult)) return null;
  for (const raw of queryResult) {
    const rec = asRecord(raw);
    if (
      rec && (asString(rec.id) === fullName || asString(rec.name) === fullName)
    ) {
      return rec;
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// VM create / query
// ---------------------------------------------------------------------------

/** Append the swamp marker to a description (idempotent). */
export function withSwampMarker(description?: string): string {
  const base = (description ?? "").trim();
  if (base.includes(SWAMP_MARKER)) return base;
  return base.length > 0 ? `${base} ${SWAMP_MARKER}` : SWAMP_MARKER;
}

/** True when a VM description carries the swamp marker. */
export function isSwampManaged(description: unknown): boolean {
  const s = asString(description);
  return s !== null && s.includes(SWAMP_MARKER);
}

/** Build the `vm.create` params bag. */
export function vmCreateParams(args: {
  name: string;
  vcpus: number;
  coresPerSocket?: number;
  memoryMib: number;
  bootloader: "UEFI" | "UEFI_CSM";
  autostart: boolean;
  description?: string;
}): Record<string, unknown> {
  const params: Record<string, unknown> = {
    name: args.name,
    vcpus: args.vcpus,
    memory: args.memoryMib,
    bootloader: args.bootloader,
    autostart: args.autostart,
    description: withSwampMarker(args.description),
  };
  if (args.coresPerSocket !== undefined) params.cores = args.coresPerSocket;
  return params;
}

/** Find a VM by exact name in a `vm.query` result, else null. */
export function findVmByName(
  queryResult: unknown,
  name: string,
): Record<string, unknown> | null {
  if (!Array.isArray(queryResult)) return null;
  for (const raw of queryResult) {
    const rec = asRecord(raw);
    if (rec && asString(rec.name) === name) return rec;
  }
  return null;
}

/** Find a VM by id in a `vm.query` result, else null. */
export function findVmById(
  queryResult: unknown,
  id: number,
): Record<string, unknown> | null {
  if (!Array.isArray(queryResult)) return null;
  for (const raw of queryResult) {
    const rec = asRecord(raw);
    if (rec && asNumber(rec.id) === id) return rec;
  }
  return null;
}

/**
 * Normalize a VM's runtime state from a `vm.query`/`vm.status` record into a
 * lowercase string (`running`/`stopped`/...). TrueNAS reports it as
 * `status.state` (an object) or a bare `state`/`status` string.
 */
export function vmStatusString(record: Record<string, unknown>): string {
  const statusRec = asRecord(record.status);
  const raw = asString(statusRec?.state) ?? asString(record.status) ??
    asString(record.state) ?? "unknown";
  return raw.toLowerCase();
}

// ---------------------------------------------------------------------------
// Devices (disk / nic) — create params + idempotency lookups
// ---------------------------------------------------------------------------

/** Read a device's type (DISK/NIC) from either nesting the middleware uses. */
export function deviceType(device: Record<string, unknown>): string | null {
  const attrs = asRecord(device.attributes);
  const t = asString(attrs?.dtype) ?? asString(device.dtype) ??
    asString(device.attributes_type);
  return t ? t.toUpperCase() : null;
}

/** Build `vm.device.create` params for a DISK device pointing at a zvol path. */
export function diskDeviceParams(args: {
  vmId: number;
  zvolPath: string;
  bus: "VIRTIO" | "AHCI";
  order?: number;
}): Record<string, unknown> {
  const params: Record<string, unknown> = {
    vm: args.vmId,
    attributes: { dtype: "DISK", path: args.zvolPath, type: args.bus },
  };
  if (args.order !== undefined) params.order = args.order;
  return params;
}

/** Build `vm.device.create` params for a NIC device with a fixed MAC. */
export function nicDeviceParams(args: {
  vmId: number;
  mac: string;
  bridge: string;
  model: "VIRTIO" | "E1000";
}): Record<string, unknown> {
  return {
    vm: args.vmId,
    attributes: {
      dtype: "NIC",
      type: args.model,
      mac: args.mac,
      nic_attach: args.bridge,
    },
  };
}

/** Find a DISK device already pointing at `zvolPath` (idempotency), else null. */
export function findDiskDevice(
  devices: unknown,
  zvolPath: string,
): Record<string, unknown> | null {
  if (!Array.isArray(devices)) return null;
  for (const raw of devices) {
    const rec = asRecord(raw);
    if (!rec || deviceType(rec) !== "DISK") continue;
    const attrs = asRecord(rec.attributes) ?? {};
    if (asString(attrs.path) === zvolPath) return rec;
  }
  return null;
}

/** Find a NIC device already carrying `mac` (idempotency), else null. */
export function findNicDevice(
  devices: unknown,
  mac: string,
): Record<string, unknown> | null {
  const want = mac.toLowerCase();
  if (!Array.isArray(devices)) return null;
  for (const raw of devices) {
    const rec = asRecord(raw);
    if (!rec || deviceType(rec) !== "NIC") continue;
    const attrs = asRecord(rec.attributes) ?? {};
    if ((asString(attrs.mac) ?? "").toLowerCase() === want) return rec;
  }
  return null;
}

/** Read the numeric device id from a device record, else null. */
export function deviceId(device: Record<string, unknown>): number | null {
  return asNumber(device.id);
}
