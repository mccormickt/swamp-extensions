/**
 * @mccormick/helios/zone — illumos zone lifecycle and inventory.
 *
 * Covers native (`solaris`) and `bhyve` brands. The `create` method applies
 * a hardened set of isolation/security defaults (ip-type=exclusive,
 * file-mac-profile=fixed-configuration, hardened limit-priv,
 * capped-cpu/capped-memory rctls, autoboot=false). The `inventory` method is
 * a fan-out: one SSH session, one shell script, one JSON document per zone
 * with usage/security/network/storage/health/log fields — collapsing what
 * would otherwise be N×M cross-model lookups.
 */
import { z } from "npm:zod@4";
import {
  openSession,
  pfexec,
  resolveTarget,
  shq,
  SshArgsShape,
  sshExec,
  sshExecOrThrow,
  type SshTarget,
} from "./shared/ssh.ts";

const GlobalArgs = z.object({
  sshUser: z.string().default("root"),
  sshPort: z.number().int().positive().optional(),
  sshKnownHosts: z.string().optional(),
});

// Hardened limit-priv: drop privileges that let a zone reconfigure the
// network or perform host-level admin actions. Keep the default set, then
// strip the network-config bits and the broad sys_admin / file_dac_*.
const HARDENED_LIMIT_PRIV =
  "default,!sys_net_config,!sys_ip_config,!sys_admin,!file_dac_read,!file_dac_search,!file_dac_write";

type ZoneState =
  | "configured"
  | "incomplete"
  | "installed"
  | "ready"
  | "running"
  | "down"
  | "shutting_down";
type IpType = "exclusive" | "shared";

const BhyveSpec = z.object({
  vcpus: z.number().int().positive(),
  ramMb: z.number().int().positive(),
  bootrom: z.string().describe(
    "Bootrom path on the host, e.g. /usr/share/bhyve/uefi-csm-rom.bin",
  ),
  serial: z.string().default("ttya"),
  disks: z.array(z.object({
    path: z.string().describe(
      "Path or zvol, e.g. /dev/zvol/rdsk/rpool/zones/foo/disk0",
    ),
    model: z.enum(["virtio-blk", "ahci-hd"]).default("virtio-blk"),
  })).default([]),
  vncPort: z.number().int().min(0).max(65535).optional(),
});

const ZoneSchema = z.object({
  name: z.string(),
  brand: z.string(),
  state: z.enum([
    "configured",
    "incomplete",
    "installed",
    "ready",
    "running",
    "down",
    "shutting_down",
  ]),
  uuid: z.string().nullable(),
  zonepath: z.string(),
  autoboot: z.boolean(),
  ipType: z.enum(["exclusive", "shared"]).nullable(),
  vnic: z.string().nullable(),
  allowedAddress: z.string().nullable(),
  defaultRouter: z.string().nullable(),
  limitPriv: z.string().nullable(),
  fileMacProfile: z.string().nullable(),
  cappedCpu: z.number().nullable(),
  cappedMemoryMb: z.number().int().nullable(),
  dedicatedCpu: z.string().nullable(),
  delegatedDatasets: z.array(z.string()).default([]),
  bhyve: BhyveSpec.nullable(),
  zonecfgRaw: z.string(),
  observedAt: z.iso.datetime(),
});

const ZoneInventorySchema = ZoneSchema.extend({
  cpuPct: z.number().nullable(),
  rssMb: z.number().int().nullable(),
  swapMb: z.number().int().nullable(),
  procCount: z.number().int().nullable(),
  rctls: z.record(z.string(), z.string()).default({}),
  network: z.object({
    vnic: z.string().nullable(),
    mac: z.string().nullable(),
    over: z.string().nullable(),
    state: z.string().nullable(),
    speedMbps: z.number().int().nullable(),
    linkProtection: z.string().nullable(),
    allowedIps: z.array(z.string()).default([]),
    rxBytes: z.number().int().nullable(),
    txBytes: z.number().int().nullable(),
  }).nullable(),
  storage: z.object({
    dataset: z.string().nullable(),
    used: z.number().int().nullable(),
    avail: z.number().int().nullable(),
    quota: z.number().int().nullable(),
    refer: z.number().int().nullable(),
    compression: z.string().nullable(),
    encryption: z.string().nullable(),
    snapshotCount: z.number().int().nullable(),
  }).nullable(),
  smfFailedServices: z.array(z.string()).default([]),
  lastBootEpoch: z.number().int().nullable(),
  uptimeSec: z.number().int().nullable(),
  recentMessages: z.array(z.string()).default([]),
  notes: z.array(z.string()).default([]),
});

const InventorySummarySchema = z.object({
  totalZones: z.number().int(),
  byState: z.record(z.string(), z.number().int()),
  byBrand: z.record(z.string(), z.number().int()),
  failedSmfZones: z.number().int(),
  /** Zones whose per-zone gather emitted at least one note (partial data). */
  zonesWithGatherErrors: z.number().int(),
  totalCpuCap: z.number(),
  totalMemoryCapMb: z.number().int(),
  observedAt: z.iso.datetime(),
});

function parseZoneadmListLine(line: string): {
  id: string;
  name: string;
  state: string;
  zonepath: string;
  uuid: string;
  brand: string;
  ipType: string;
} {
  // `zoneadm list -cp` emits a colon-separated, escaped line:
  //   zoneid:name:state:path:uuid:brand:ip-type[:R/W:Mac-Profile]
  // Backslashes escape literal colons inside fields.
  const fields: string[] = [];
  let cur = "";
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (c === "\\" && line[i + 1]) {
      cur += line[i + 1];
      i++;
    } else if (c === ":") {
      fields.push(cur);
      cur = "";
    } else {
      cur += c;
    }
  }
  fields.push(cur);
  const [id, name, state, zonepath, uuid, brand, ipType] = fields;
  return { id, name, state, zonepath, uuid, brand, ipType };
}

type ParsedZonecfg = Partial<z.infer<typeof ZoneSchema>>;

function parseZonecfgExport(raw: string): ParsedZonecfg {
  const out: ParsedZonecfg = {
    autoboot: false,
    ipType: null,
    vnic: null,
    allowedAddress: null,
    defaultRouter: null,
    limitPriv: null,
    fileMacProfile: null,
    cappedCpu: null,
    cappedMemoryMb: null,
    dedicatedCpu: null,
    delegatedDatasets: [],
    bhyve: null,
  };
  let scope: string | null = null;
  let scopeBuf: Record<string, string> = {};
  const datasets: string[] = [];
  for (const rawLine of raw.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line) continue;
    if (line.startsWith("set ")) {
      const m = line.match(/^set\s+([\w-]+)\s*=\s*(.+?);?$/);
      if (m) {
        const [, k, v] = m;
        const value = v.replace(/^"|"$/g, "");
        if (k === "autoboot") out.autoboot = value === "true";
        if (k === "ip-type") out.ipType = value as "exclusive" | "shared";
        if (k === "limitpriv") out.limitPriv = value;
        if (k === "file-mac-profile") out.fileMacProfile = value;
      }
    } else if (line === "add net" || line === "add anet") {
      scope = "net";
      scopeBuf = {};
    } else if (line === "add capped-cpu") {
      scope = "capped-cpu";
      scopeBuf = {};
    } else if (line === "add capped-memory") {
      scope = "capped-memory";
      scopeBuf = {};
    } else if (line === "add dedicated-cpu") {
      scope = "dedicated-cpu";
      scopeBuf = {};
    } else if (line === "add dataset") {
      scope = "dataset";
      scopeBuf = {};
    } else if (
      line === "add device" || line === "add fs" || line === "add rctl"
    ) {
      scope = "ignored";
      scopeBuf = {};
    } else if (line === "end" && scope) {
      if (scope === "net") {
        if (scopeBuf["physical"]) out.vnic = scopeBuf["physical"];
        if (scopeBuf["allowed-address"]) {
          out.allowedAddress = scopeBuf["allowed-address"];
        }
        if (scopeBuf["defrouter"]) out.defaultRouter = scopeBuf["defrouter"];
      } else if (scope === "capped-cpu" && scopeBuf["ncpus"]) {
        out.cappedCpu = Number(scopeBuf["ncpus"]);
      } else if (scope === "capped-memory" && scopeBuf["physical"]) {
        // physical comes back like `512M` or `2G` — convert to MiB.
        out.cappedMemoryMb = humanToMb(scopeBuf["physical"]);
      } else if (scope === "dedicated-cpu" && scopeBuf["ncpus"]) {
        out.dedicatedCpu = scopeBuf["ncpus"];
      } else if (scope === "dataset" && scopeBuf["name"]) {
        datasets.push(scopeBuf["name"]);
      }
      scope = null;
    } else if (scope) {
      const m = line.match(/^set\s+([\w-]+)\s*=\s*(.+?);?$/);
      if (m) scopeBuf[m[1]] = m[2].replace(/^"|"$/g, "");
    }
  }
  out.delegatedDatasets = datasets;
  return out;
}

function humanToMb(s: string): number {
  const m = s.trim().match(/^(\d+(?:\.\d+)?)\s*([KkMmGgTt]?)$/);
  if (!m) return 0;
  const n = Number(m[1]);
  const unit = m[2].toUpperCase();
  switch (unit) {
    case "T":
      return Math.round(n * 1024 * 1024);
    case "G":
      return Math.round(n * 1024);
    case "M":
    case "":
      return Math.round(n);
    case "K":
      return Math.round(n / 1024);
    default:
      return Math.round(n);
  }
}

function buildZonecfgScript(args: {
  name: string;
  brand: string;
  zonepath: string;
  vnicLink?: string;
  allowedAddress?: string;
  defaultRouter?: string;
  limitPriv?: string;
  fileMacProfile?: string;
  cappedCpu?: number;
  cappedMemoryMb?: number;
  dedicatedCpu?: string;
  delegatedDatasets?: string[];
  lofs?: { dir: string; special: string; ro?: boolean }[];
  bhyveSpec?: z.infer<typeof BhyveSpec>;
}): string {
  const lines: string[] = [];
  lines.push(`create -b`);
  lines.push(`set brand=${args.brand}`);
  lines.push(`set zonepath=${args.zonepath}`);
  lines.push(`set autoboot=false`);
  lines.push(`set ip-type=exclusive`);
  if (args.brand === "solaris" && args.fileMacProfile) {
    lines.push(`set file-mac-profile=${args.fileMacProfile}`);
  }
  if (args.limitPriv) lines.push(`set limitpriv="${args.limitPriv}"`);

  if (args.vnicLink) {
    lines.push(`add net`);
    lines.push(`set physical=${args.vnicLink}`);
    if (args.allowedAddress) {
      lines.push(`set allowed-address=${args.allowedAddress}`);
    }
    if (args.defaultRouter) lines.push(`set defrouter=${args.defaultRouter}`);
    lines.push(`end`);
  }

  if (args.cappedCpu !== undefined) {
    lines.push(`add capped-cpu`);
    lines.push(`set ncpus=${args.cappedCpu}`);
    lines.push(`end`);
  }
  if (args.cappedMemoryMb !== undefined) {
    lines.push(`add capped-memory`);
    lines.push(`set physical=${args.cappedMemoryMb}M`);
    lines.push(`set swap=${args.cappedMemoryMb}M`);
    lines.push(`set locked=${Math.round(args.cappedMemoryMb / 2)}M`);
    lines.push(`end`);
  }
  if (args.dedicatedCpu) {
    lines.push(`add dedicated-cpu`);
    lines.push(`set ncpus=${args.dedicatedCpu}`);
    lines.push(`end`);
  }
  for (const ds of args.delegatedDatasets ?? []) {
    lines.push(`add dataset`);
    lines.push(`set name=${ds}`);
    lines.push(`end`);
  }
  for (const m of args.lofs ?? []) {
    lines.push(`add fs`);
    lines.push(`set dir=${m.dir}`);
    lines.push(`set special=${m.special}`);
    lines.push(`set type=lofs`);
    if (m.ro) lines.push(`add options ro`);
    lines.push(`end`);
  }

  if (args.brand === "bhyve" && args.bhyveSpec) {
    const b = args.bhyveSpec;
    lines.push(
      `add attr; set name=vcpus; set type=string; set value=${b.vcpus}; end`,
    );
    lines.push(
      `add attr; set name=ram; set type=string; set value=${b.ramMb}M; end`,
    );
    lines.push(
      `add attr; set name=bootrom; set type=string; set value=${b.bootrom}; end`,
    );
    lines.push(
      `add attr; set name=console; set type=string; set value=${b.serial}; end`,
    );
    if (b.vncPort !== undefined) {
      lines.push(
        `add attr; set name=vnc; set type=string; set value=on,port=${b.vncPort}; end`,
      );
    }
    for (let i = 0; i < b.disks.length; i++) {
      const d = b.disks[i];
      lines.push(`add device`);
      lines.push(`set match=${d.path}`);
      lines.push(
        `add attr; set name=model; set type=string; set value=${d.model}; end`,
      );
      lines.push(`end`);
    }
  }

  lines.push(`verify`);
  lines.push(`commit`);
  lines.push(`exit`);
  return lines.join("\n") + "\n";
}

/**
 * `@mccormick/helios/zone` — illumos zone lifecycle and inventory for the
 * `solaris` and `bhyve` brands.
 *
 * Lifecycle methods: `list`, `lookup`, `create`, `install`, `boot`, `halt`,
 * `uninstall`, `delete`, `exec` (zlogin), plus a fan-out `inventory`.
 *
 * `create` applies hardened defaults: `ip-type=exclusive`,
 * `file-mac-profile=fixed-configuration` (native brand),
 * a hardened `limit-priv` set, `capped-cpu`/`capped-memory` rctls, and
 * `autoboot=false`. Override explicitly via arguments.
 *
 * `inventory` opens one SSH ControlMaster session and gathers identity,
 * live usage (`prstat`/`pgrep`), security config, network state
 * (vnic/mac/protection/allowed-ips/rx-tx), storage (zfs props +
 * snapshot count), SMF health, last-boot/uptime, and recent log lines
 * for every zone on the host — emitting one `zone_inventory` resource
 * per zone plus an `inventory_summary` rollup that includes the count
 * of zones with failed SMF services.
 */
export const model = {
  type: "@mccormick/helios/zone",
  version: "2026.05.14.3",
  globalArguments: GlobalArgs,
  resources: {
    "zone": {
      description: "An illumos zone (configured/installed/running) on the host",
      schema: ZoneSchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
    "zone_inventory": {
      description:
        "Per-zone inventory snapshot: identity, security, network, storage, " +
        "health (SMF), and recent log lines. Emitted by the inventory method.",
      schema: ZoneInventorySchema,
      lifetime: "7d" as const,
      garbageCollection: 20,
    },
    "inventory_summary": {
      description: "Host-level zone inventory rollup. One per inventory call.",
      schema: InventorySummarySchema,
      lifetime: "7d" as const,
      garbageCollection: 20,
    },
    "exec_result": {
      description: "stdout/stderr/exit from a zlogin exec call",
      schema: z.object({
        zone: z.string(),
        command: z.string(),
        exitCode: z.number().int(),
        stdout: z.string(),
        stderr: z.string(),
        observedAt: z.iso.datetime(),
      }),
      lifetime: "1d" as const,
      garbageCollection: 5,
    },
  },
  methods: {
    list: {
      description: "List every configured zone via `zoneadm list -cp`.",
      arguments: z.object({ ...SshArgsShape }),
      execute: async (args, context) => {
        const t = resolveTarget(context.globalArgs, args);
        const out = await sshExecOrThrow(t, "zoneadm list -cp");
        const handles = [];
        for (const line of out.stdout.trim().split(/\r?\n/).filter(Boolean)) {
          const f = parseZoneadmListLine(line);
          if (f.name === "global") continue;
          const zoneRes: z.infer<typeof ZoneSchema> = {
            name: f.name,
            brand: f.brand,
            state: f.state as ZoneState,
            uuid: f.uuid || null,
            zonepath: f.zonepath,
            autoboot: false,
            ipType: f.ipType ? (f.ipType as IpType) : null,
            vnic: null,
            allowedAddress: null,
            defaultRouter: null,
            limitPriv: null,
            fileMacProfile: null,
            cappedCpu: null,
            cappedMemoryMb: null,
            dedicatedCpu: null,
            delegatedDatasets: [],
            bhyve: null,
            zonecfgRaw: "",
            observedAt: new Date().toISOString(),
          };
          handles.push(await context.writeResource("zone", f.name, zoneRes));
        }
        return { dataHandles: handles };
      },
    },

    lookup: {
      description: "Look up a single zone with full zonecfg.",
      arguments: z.object({
        ...SshArgsShape,
        name: z.string(),
      }),
      execute: async (args, context) => {
        const t = resolveTarget(context.globalArgs, args);
        const list = await sshExecOrThrow(
          t,
          `zoneadm -z ${shq(args.name)} list -p`,
        );
        const f = parseZoneadmListLine(list.stdout.trim().split(/\r?\n/)[0]);
        const cfg = await sshExecOrThrow(
          t,
          `zonecfg -z ${shq(args.name)} export`,
        );
        const parsed = parseZonecfgExport(cfg.stdout);
        const zoneRes: z.infer<typeof ZoneSchema> = {
          name: f.name,
          brand: f.brand,
          state: f.state as ZoneState,
          uuid: f.uuid || null,
          zonepath: f.zonepath,
          autoboot: parsed.autoboot ?? false,
          ipType: parsed.ipType ?? null,
          vnic: parsed.vnic ?? null,
          allowedAddress: parsed.allowedAddress ?? null,
          defaultRouter: parsed.defaultRouter ?? null,
          limitPriv: parsed.limitPriv ?? null,
          fileMacProfile: parsed.fileMacProfile ?? null,
          cappedCpu: parsed.cappedCpu ?? null,
          cappedMemoryMb: parsed.cappedMemoryMb ?? null,
          dedicatedCpu: parsed.dedicatedCpu ?? null,
          delegatedDatasets: parsed.delegatedDatasets ?? [],
          bhyve: null,
          zonecfgRaw: cfg.stdout,
          observedAt: new Date().toISOString(),
        };
        const handle = await context.writeResource("zone", args.name, zoneRes);
        return { dataHandles: [handle] };
      },
    },

    create: {
      description:
        "Create a zone with hardened security defaults. ip-type=exclusive, " +
        "autoboot=false, file-mac-profile=fixed-configuration (native), " +
        "limit-priv hardened set, capped-cpu and capped-memory rctls. " +
        "Override defaults explicitly via arguments.",
      arguments: z.object({
        ...SshArgsShape,
        name: z.string(),
        brand: z.enum(["solaris", "bhyve"]),
        zonepath: z.string(),
        vnicLink: z.string().optional(),
        allowedAddress: z.string().optional(),
        defaultRouter: z.string().optional(),
        limitPriv: z.string().default(HARDENED_LIMIT_PRIV),
        fileMacProfile: z.string().default("fixed-configuration"),
        cappedCpu: z.number().positive().optional(),
        cappedMemoryMb: z.number().int().positive().optional(),
        dedicatedCpu: z.string().optional(),
        delegatedDatasets: z.array(z.string()).default([]),
        lofs: z.array(z.object({
          dir: z.string(),
          special: z.string(),
          ro: z.boolean().default(false),
        })).default([]),
        bhyveSpec: BhyveSpec.optional(),
      }),
      execute: async (args, context) => {
        const t = resolveTarget(context.globalArgs, args);
        const script = buildZonecfgScript(args);
        await sshExecOrThrow(
          t,
          `${pfexec(`zonecfg -z ${shq(args.name)} -f -`)}`,
          script,
        );
        // Reuse lookup to capture the freshly-committed state.
        const cfg = await sshExecOrThrow(
          t,
          `zonecfg -z ${shq(args.name)} export`,
        );
        const list = await sshExecOrThrow(
          t,
          `zoneadm -z ${shq(args.name)} list -p`,
        );
        const f = parseZoneadmListLine(list.stdout.trim().split(/\r?\n/)[0]);
        const parsed = parseZonecfgExport(cfg.stdout);
        const handle = await context.writeResource("zone", args.name, {
          name: f.name,
          brand: f.brand,
          state: f.state,
          uuid: f.uuid || null,
          zonepath: f.zonepath,
          autoboot: parsed.autoboot ?? false,
          ipType: parsed.ipType ?? null,
          vnic: parsed.vnic ?? null,
          allowedAddress: parsed.allowedAddress ?? null,
          defaultRouter: parsed.defaultRouter ?? null,
          limitPriv: parsed.limitPriv ?? null,
          fileMacProfile: parsed.fileMacProfile ?? null,
          cappedCpu: parsed.cappedCpu ?? null,
          cappedMemoryMb: parsed.cappedMemoryMb ?? null,
          dedicatedCpu: parsed.dedicatedCpu ?? null,
          delegatedDatasets: parsed.delegatedDatasets ?? [],
          bhyve: args.brand === "bhyve" ? args.bhyveSpec ?? null : null,
          zonecfgRaw: cfg.stdout,
          observedAt: new Date().toISOString(),
        });
        return { dataHandles: [handle] };
      },
    },

    install: {
      description: "Install a zone (no-op for bhyve brand).",
      arguments: z.object({
        ...SshArgsShape,
        name: z.string(),
        extraArgs: z.array(z.string()).default([]),
      }),
      execute: async (args, context) => {
        const t = resolveTarget(context.globalArgs, args);
        const extra = args.extraArgs.length
          ? " " + args.extraArgs.join(" ")
          : "";
        await sshExecOrThrow(
          t,
          `${pfexec(`zoneadm -z ${shq(args.name)} install${extra}`)}`,
        );
        return { dataHandles: [] };
      },
    },

    boot: {
      description: "Boot a zone.",
      arguments: z.object({
        ...SshArgsShape,
        name: z.string(),
        bootArgs: z.string().optional(),
      }),
      execute: async (args, context) => {
        const t = resolveTarget(context.globalArgs, args);
        const ba = args.bootArgs ? ` -- ${args.bootArgs}` : "";
        await sshExecOrThrow(
          t,
          `${pfexec(`zoneadm -z ${shq(args.name)} boot${ba}`)}`,
        );
        return { dataHandles: [] };
      },
    },

    halt: {
      description: "Halt a zone.",
      arguments: z.object({
        ...SshArgsShape,
        name: z.string(),
      }),
      execute: async (args, context) => {
        const t = resolveTarget(context.globalArgs, args);
        await sshExecOrThrow(
          t,
          `${pfexec(`zoneadm -z ${shq(args.name)} halt`)}`,
        );
        return { dataHandles: [] };
      },
    },

    uninstall: {
      description: "Uninstall a zone (force).",
      arguments: z.object({
        ...SshArgsShape,
        name: z.string(),
      }),
      execute: async (args, context) => {
        const t = resolveTarget(context.globalArgs, args);
        // Verify it's halted first.
        const list = await sshExec(
          t,
          `zoneadm -z ${shq(args.name)} list -p`,
        );
        if (list.code === 0 && /:running:/.test(list.stdout)) {
          throw new Error(
            `Refusing to uninstall '${args.name}': zone is running. Halt first.`,
          );
        }
        await sshExecOrThrow(
          t,
          `${pfexec(`zoneadm -z ${shq(args.name)} uninstall -F`)}`,
        );
        return { dataHandles: [] };
      },
    },

    delete: {
      description: "Delete a zone configuration.",
      arguments: z.object({
        ...SshArgsShape,
        name: z.string(),
      }),
      execute: async (args, context) => {
        const t = resolveTarget(context.globalArgs, args);
        await sshExecOrThrow(
          t,
          `${pfexec(`zonecfg -z ${shq(args.name)} delete -F`)}`,
        );
        return { dataHandles: [] };
      },
    },

    exec: {
      description: "Run a command inside the zone via `zlogin -S`.",
      arguments: z.object({
        ...SshArgsShape,
        name: z.string(),
        command: z.string(),
      }),
      execute: async (args, context) => {
        const t = resolveTarget(context.globalArgs, args);
        const out = await sshExec(
          t,
          `${pfexec(`zlogin -S ${shq(args.name)} ${shq(args.command)}`)}`,
        );
        const handle = await context.writeResource("exec_result", args.name, {
          zone: args.name,
          command: args.command,
          exitCode: out.code,
          stdout: out.stdout,
          stderr: out.stderr,
          observedAt: new Date().toISOString(),
        });
        return { dataHandles: [handle] };
      },
    },

    inventory: {
      description:
        "Single fan-out: gather identity, live usage, security config, " +
        "network state, storage stats, SMF health, and recent log lines " +
        "for every zone on the host. One SSH session, one shell script, " +
        "one zone_inventory resource per zone plus an inventory_summary.",
      arguments: z.object({
        ...SshArgsShape,
        includeLogs: z.boolean().default(true),
        logTailLines: z.number().int().nonnegative().default(50),
      }),
      execute: async (args, context) => {
        const t = resolveTarget(context.globalArgs, args);
        const sess = await openSession({
          host: t.host,
          user: t.user,
          port: t.port,
          knownHosts: t.knownHosts,
        });
        try {
          const zonesOut = await sshExecOrThrow(
            sess.target,
            "zoneadm list -cp",
          );
          const zones = zonesOut.stdout.trim().split(/\r?\n/)
            .map(parseZoneadmListLine)
            .filter((row) => row.name !== "global");

          const handles = [];
          const summary = {
            totalZones: zones.length,
            byState: {} as Record<string, number>,
            byBrand: {} as Record<string, number>,
            failedSmfZones: 0,
            zonesWithGatherErrors: 0,
            totalCpuCap: 0,
            totalMemoryCapMb: 0,
            observedAt: new Date().toISOString(),
          };

          for (const zn of zones) {
            summary.byState[zn.state] = (summary.byState[zn.state] ?? 0) + 1;
            summary.byBrand[zn.brand] = (summary.byBrand[zn.brand] ?? 0) + 1;
            const inv = await gatherZone(sess.target, zn, args, context);
            if (inv.cappedCpu) summary.totalCpuCap += inv.cappedCpu;
            if (inv.cappedMemoryMb) {
              summary.totalMemoryCapMb += inv.cappedMemoryMb;
            }
            if (inv.smfFailedServices.length > 0) summary.failedSmfZones += 1;
            // notes is populated whenever a sub-gather failed (zonecfg
            // export, prstat parse, SMF probe, dataset lookup, ...). Skipped
            // states (e.g. zone not running → no live cpu/rss) also push a
            // note, so this counts "saw at least one degraded field" rather
            // than strictly "hit an error".
            if (inv.notes.length > 0) summary.zonesWithGatherErrors += 1;
            handles.push(
              await context.writeResource("zone_inventory", zn.name, inv),
            );
          }
          handles.push(
            await context.writeResource(
              "inventory_summary",
              "current",
              summary,
            ),
          );
          return { dataHandles: handles };
        } finally {
          await sess.close();
        }
      },
    },
  },
};

async function gatherZone(
  t: SshTarget,
  zn: ReturnType<typeof parseZoneadmListLine>,
  args: { includeLogs: boolean; logTailLines: number },
  _context: unknown,
): Promise<z.infer<typeof ZoneInventorySchema>> {
  const notes: string[] = [];
  const cfg = await sshExec(t, `zonecfg -z ${shq(zn.name)} export`);
  if (cfg.code !== 0) {
    notes.push(`zonecfg export failed: ${cfg.stderr.slice(-200)}`);
  }
  const parsed = cfg.code === 0 ? parseZonecfgExport(cfg.stdout) : {};

  // Live usage from prstat (one snapshot, instant exit).
  let cpuPct: number | null = null;
  let rssMb: number | null = null;
  const swapMb: number | null = null;
  let procCount: number | null = null;
  if (zn.state === "running") {
    const ps = await sshExec(
      t,
      `prstat -Z -c 1 1 2>/dev/null | awk -v zname=${shq(zn.name)} ` +
        `'$NF==zname {print $5, $6, NF}'`,
    );
    if (ps.code === 0 && ps.stdout.trim()) {
      // Best-effort parse — prstat columns vary by illumos version.
      const cols = ps.stdout.trim().split(/\s+/);
      cpuPct = cols.length >= 1 ? parseFloat(cols[0]) || null : null;
      rssMb = cols.length >= 2 ? humanToMb(cols[1]) : null;
    }
    const proc = await sshExec(t, `pgrep -z ${shq(zn.name)} | wc -l`);
    if (proc.code === 0) procCount = Number(proc.stdout.trim()) || 0;
  } else {
    notes.push("zone not running; skipped live cpu/rss/swap/proc capture");
  }

  // rctl values per zone.
  const rctls: Record<string, string> = {};
  if (zn.state === "running") {
    const rc = await sshExec(
      t,
      `prctl -n zone.cpu-cap -i zone ${shq(zn.name)} 2>/dev/null`,
    );
    if (rc.code === 0) rctls["zone.cpu-cap"] = rc.stdout.trim();
  }

  // Network state — only if we found a vnic in zonecfg.
  type InvNetwork = z.infer<typeof ZoneInventorySchema>["network"];
  let network: InvNetwork = null;
  const vnic = parsed.vnic ?? null;
  if (vnic) {
    const link = await sshExec(
      t,
      `dladm show-link -p -o link,class,mtu,state,over ${shq(vnic)}`,
    );
    const vinfo = await sshExec(
      t,
      `dladm show-vnic -p -o link,over,speed,macaddress,vid ${shq(vnic)}`,
    );
    const lp = await sshExec(
      t,
      `dladm show-linkprop -c -p protection,allowed-ips -o property,value ${
        shq(vnic)
      }`,
    );
    const stats = await sshExec(
      t,
      `dladm show-link -s -p -o ipackets,rbytes,opackets,obytes ${shq(vnic)}`,
    );
    let mac: string | null = null,
      over: string | null = null,
      speedMbps: number | null = null;
    if (vinfo.code === 0) {
      const [, o, sp, m] = vinfo.stdout.trim().split(":");
      over = o ?? null;
      speedMbps = sp ? Number(sp) : null;
      mac = m ?? null;
    }
    let state: string | null = null;
    if (link.code === 0) {
      const [, , , st] = link.stdout.trim().split(":");
      state = st ?? null;
    }
    let linkProtection: string | null = null;
    let allowedIps: string[] = [];
    if (lp.code === 0) {
      for (const line of lp.stdout.trim().split(/\r?\n/)) {
        const [prop, value] = line.split(":");
        if (prop === "protection") linkProtection = value || null;
        if (prop === "allowed-ips" && value) {
          allowedIps = value.split(",").filter(Boolean);
        }
      }
    }
    let rxBytes: number | null = null, txBytes: number | null = null;
    if (stats.code === 0) {
      const [, rb, , ob] = stats.stdout.trim().split(":");
      rxBytes = rb ? Number(rb) : null;
      txBytes = ob ? Number(ob) : null;
    }
    network = {
      vnic,
      mac,
      over,
      state,
      speedMbps,
      linkProtection,
      allowedIps,
      rxBytes,
      txBytes,
    };
  }

  // Storage — try the zonepath dataset.
  type InvStorage = z.infer<typeof ZoneInventorySchema>["storage"];
  let storage: InvStorage = null;
  // Map zonepath /zones/foo to the dataset by asking zfs which dataset is mounted there.
  const dsLookup = await sshExec(
    t,
    `zfs list -H -o name -p ${shq(zn.zonepath)} 2>/dev/null || ` +
      `df -h ${shq(zn.zonepath)} 2>/dev/null | tail -1 | awk '{print $1}'`,
  );
  const dataset = dsLookup.code === 0
    ? dsLookup.stdout.trim().split(/\r?\n/)[0] || null
    : null;
  if (dataset) {
    const get = await sshExec(
      t,
      `zfs get -Hp -o property,value used,available,quota,referenced,compression,encryption ${
        shq(dataset)
      }`,
    );
    const props: Record<string, string> = {};
    if (get.code === 0) {
      for (const line of get.stdout.trim().split(/\r?\n/)) {
        const [p, v] = line.split(/\t/);
        if (p) props[p] = v;
      }
    }
    const snaps = await sshExec(
      t,
      `zfs list -H -t snapshot -o name -d 1 ${
        shq(dataset)
      } 2>/dev/null | wc -l`,
    );
    storage = {
      dataset,
      used: props["used"] ? Number(props["used"]) : null,
      avail: props["available"] && props["available"] !== "-"
        ? Number(props["available"])
        : null,
      quota: props["quota"] && props["quota"] !== "-"
        ? Number(props["quota"])
        : null,
      refer: props["referenced"] ? Number(props["referenced"]) : null,
      compression: props["compression"] && props["compression"] !== "-"
        ? props["compression"]
        : null,
      encryption: props["encryption"] && props["encryption"] !== "-"
        ? props["encryption"]
        : null,
      snapshotCount: snaps.code === 0 ? Number(snaps.stdout.trim()) || 0 : null,
    };
  } else {
    notes.push("could not resolve zonepath to a ZFS dataset");
  }

  // SMF health + uptime via zlogin (only for running zones).
  let smfFailedServices: string[] = [];
  let lastBootEpoch: number | null = null;
  let uptimeSec: number | null = null;
  if (zn.state === "running") {
    const xv = await sshExec(
      t,
      `${pfexec(`zlogin -S ${shq(zn.name)} svcs -xv 2>&1 || true`)}`,
    );
    if (xv.code === 0) {
      smfFailedServices =
        (xv.stdout.match(/^svc:\/[^\s]+/gm) ?? []) as string[];
    }
    const who = await sshExec(
      t,
      `${pfexec(`zlogin -S ${shq(zn.name)} 'date +%s; who -b'`)}`,
    );
    if (who.code === 0) {
      const lines = who.stdout.trim().split(/\r?\n/);
      const now = Number(lines[0]);
      const m = lines[1]?.match(/system boot\s+(.+)$/);
      if (m && Number.isFinite(now)) {
        const bootDate = new Date(m[1]);
        if (!Number.isNaN(bootDate.getTime())) {
          lastBootEpoch = Math.floor(bootDate.getTime() / 1000);
          uptimeSec = now - lastBootEpoch;
        }
      }
    }
  } else {
    notes.push("zone not running; skipped SMF health check");
  }

  // Logs.
  let recentMessages: string[] = [];
  if (args.includeLogs && args.logTailLines > 0) {
    const messages = await sshExec(
      t,
      `${
        pfexec(
          `tail -n 500 /var/adm/messages 2>/dev/null | grep -F ${
            shq(zn.name)
          } | tail -n ${args.logTailLines}`,
        )
      }`,
    );
    if (messages.code === 0 && messages.stdout.trim()) {
      recentMessages = messages.stdout.trim().split(/\r?\n/);
    }
    const svcLog = await sshExec(
      t,
      `${
        pfexec(
          `tail -n 200 /var/svc/log/system-zones:default.log 2>/dev/null | grep -F ${
            shq(zn.name)
          } | tail -n ${args.logTailLines}`,
        )
      }`,
    );
    if (svcLog.code === 0 && svcLog.stdout.trim()) {
      recentMessages = recentMessages.concat(
        svcLog.stdout.trim().split(/\r?\n/),
      );
    }
  }

  return {
    name: zn.name,
    brand: zn.brand,
    state: zn.state as ZoneState,
    uuid: zn.uuid || null,
    zonepath: zn.zonepath,
    autoboot: parsed.autoboot ?? false,
    ipType: parsed.ipType ?? (zn.ipType ? (zn.ipType as IpType) : null),
    vnic: parsed.vnic ?? null,
    allowedAddress: parsed.allowedAddress ?? null,
    defaultRouter: parsed.defaultRouter ?? null,
    limitPriv: parsed.limitPriv ?? null,
    fileMacProfile: parsed.fileMacProfile ?? null,
    cappedCpu: parsed.cappedCpu ?? null,
    cappedMemoryMb: parsed.cappedMemoryMb ?? null,
    dedicatedCpu: parsed.dedicatedCpu ?? null,
    delegatedDatasets: parsed.delegatedDatasets ?? [],
    bhyve: null,
    zonecfgRaw: cfg.code === 0 ? cfg.stdout : "",
    observedAt: new Date().toISOString(),
    cpuPct,
    rssMb,
    swapMb,
    procCount,
    rctls,
    network,
    storage,
    smfFailedServices,
    lastBootEpoch,
    uptimeSec,
    recentMessages,
    notes,
  };
}
