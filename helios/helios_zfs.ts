/**
 * @mccormick/helios/zfs — remote ZFS dataset and pool ops on a Helios host.
 *
 * Methods are scoped tightly to what zone provisioning needs plus a few
 * housekeeping ops (snapshots, scrub, status). All commands run via SSH
 * with `pfexec` so the model can run as a non-root user with the
 * "ZFS Storage Management" RBAC profile.
 */
import { z } from "npm:zod@4";
import {
  pfexec,
  resolveTarget,
  shq,
  SshArgsShape,
  sshExec,
  sshExecOrThrow,
} from "./shared/ssh.ts";

const GlobalArgs = z.object({
  sshUser: z.string().default("root"),
  sshPort: z.number().int().positive().optional(),
  sshKnownHosts: z.string().optional(),
});

const DatasetSchema = z.object({
  name: z.string(),
  type: z.enum(["filesystem", "volume", "snapshot"]),
  used: z.number().int().nonnegative(),
  avail: z.number().int().nonnegative().nullable(),
  refer: z.number().int().nonnegative(),
  mountpoint: z.string().nullable(),
  quota: z.number().int().nullable(),
  reservation: z.number().int().nullable(),
  compression: z.string().nullable(),
  encryption: z.string().nullable(),
  recordsize: z.number().int().nullable(),
  zoned: z.boolean(),
  delegatedTo: z.string().nullable(),
  observedAt: z.iso.datetime(),
});

const PoolSchema = z.object({
  name: z.string(),
  size: z.number().int().nonnegative(),
  alloc: z.number().int().nonnegative(),
  free: z.number().int().nonnegative(),
  health: z.string(),
  scrubInProgress: z.boolean(),
  rawStatus: z.string(),
  observedAt: z.iso.datetime(),
});

const SnapshotSchema = z.object({
  name: z.string(),
  used: z.number().int().nonnegative(),
  refer: z.number().int().nonnegative(),
  observedAt: z.iso.datetime(),
});

function parseProp(
  raw: string | undefined,
  asNum: boolean = false,
): string | number | null {
  if (!raw || raw === "-" || raw === "none") return null;
  if (asNum) {
    const n = Number(raw);
    return Number.isFinite(n) ? n : null;
  }
  return raw;
}

function parseDatasetGet(
  out: string,
  name: string,
): z.infer<typeof DatasetSchema> {
  // `zfs get -Hp -o property,value all <name>` → tab-separated lines.
  const props: Record<string, string> = {};
  for (const line of out.trim().split(/\r?\n/)) {
    const [, prop, value] = line.split(/\t/);
    // The `-Hp -o property,value` flags emit `name<TAB>prop<TAB>value`
    // — but with `-o property,value` swap: name is suppressed. Handle both.
    if (prop === undefined) {
      // Fallback: 2-column form `prop<TAB>value`
      const cols = line.split(/\t/);
      if (cols.length >= 2) props[cols[0]] = cols[1];
    } else {
      props[prop] = value;
    }
  }
  return {
    name,
    type: (props["type"] as "filesystem" | "volume" | "snapshot" | undefined) ??
      "filesystem",
    used: Number(props["used"] ?? 0),
    avail: props["available"] === "-" ? null : Number(props["available"] ?? 0),
    refer: Number(props["referenced"] ?? 0),
    mountpoint: props["mountpoint"] === "none" || props["mountpoint"] === "-"
      ? null
      : (props["mountpoint"] ?? null),
    quota: parseProp(props["quota"], true),
    reservation: parseProp(props["reservation"], true),
    compression: parseProp(props["compression"]) as string | null,
    encryption: parseProp(props["encryption"]) as string | null,
    recordsize: parseProp(props["recordsize"], true),
    zoned: props["zoned"] === "on",
    delegatedTo: null,
    observedAt: new Date().toISOString(),
  };
}

/**
 * `@mccormick/helios/zfs` — ZFS dataset, pool, and snapshot operations on a
 * Helios host.
 *
 * Methods: `dataset_list`, `dataset_lookup`, `dataset_create`,
 * `dataset_destroy`, `snapshot_create`, `snapshot_destroy`, `delegate`
 * (zone delegation), `pool_status`, `pool_scrub`. All privileged commands
 * run via `pfexec` so a non-root user with the "ZFS Storage Management"
 * RBAC profile can drive the model.
 *
 * Encryption: pass `encryption` + `encryptionPassphrase` to `dataset_create`
 * to provision an encrypted dataset. The passphrase is sent over stdin to
 * `zfs create` with `keyformat=passphrase keylocation=prompt`; it is never
 * interpolated into a command line and is redacted from error messages.
 */
export const model = {
  type: "@mccormick/helios/zfs",
  version: "2026.05.14.3",
  globalArguments: GlobalArgs,
  resources: {
    "dataset": {
      description: "A ZFS filesystem or volume on the Helios host",
      schema: DatasetSchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
    "pool": {
      description: "A ZFS pool on the Helios host",
      schema: PoolSchema,
      lifetime: "infinite" as const,
      garbageCollection: 5,
    },
    "snapshot": {
      description: "A ZFS snapshot on the Helios host",
      schema: SnapshotSchema,
      lifetime: "infinite" as const,
      garbageCollection: 20,
    },
  },
  methods: {
    dataset_list: {
      description: "List all filesystem and volume datasets on the host.",
      arguments: z.object({ ...SshArgsShape }),
      execute: async (args, context) => {
        const t = resolveTarget(context.globalArgs, args);
        const out = await sshExecOrThrow(
          t,
          "zfs list -H -p -t filesystem,volume " +
            "-o name,used,available,referenced,mountpoint,type",
        );
        const handles = [];
        for (const line of out.stdout.trim().split(/\r?\n/).filter(Boolean)) {
          const [name, used, avail, refer, mountpoint, type] = line.split(/\t/);
          const ds: z.infer<typeof DatasetSchema> = {
            name,
            type: type as "filesystem" | "volume" | "snapshot",
            used: Number(used ?? 0),
            avail: avail === "-" ? null : Number(avail),
            refer: Number(refer ?? 0),
            mountpoint: mountpoint === "none" || mountpoint === "-"
              ? null
              : mountpoint,
            quota: null,
            reservation: null,
            compression: null,
            encryption: null,
            recordsize: null,
            zoned: false,
            delegatedTo: null,
            observedAt: new Date().toISOString(),
          };
          handles.push(await context.writeResource("dataset", name, ds));
        }
        return { dataHandles: handles };
      },
    },

    dataset_lookup: {
      description: "Look up one dataset's full property set.",
      arguments: z.object({
        ...SshArgsShape,
        name: z.string(),
      }),
      execute: async (args, context) => {
        const t = resolveTarget(context.globalArgs, args);
        const out = await sshExecOrThrow(
          t,
          `zfs get -Hp -o property,value all ${shq(args.name)}`,
        );
        const ds = parseDatasetGet(out.stdout, args.name);
        const handle = await context.writeResource("dataset", args.name, ds);
        return { dataHandles: [handle] };
      },
    },

    dataset_create: {
      description:
        "Create a ZFS filesystem with optional quota, reservation, " +
        "compression (default zstd), encryption (default aes-256-gcm; " +
        "passphrase argument supplied at call time), recordsize, mountpoint.",
      arguments: z.object({
        ...SshArgsShape,
        name: z.string(),
        quota: z.string().optional().describe("e.g. 10G; omit for unlimited"),
        reservation: z.string().optional(),
        compression: z.string().default("zstd"),
        encryption: z.string().optional().describe(
          "e.g. aes-256-gcm. Omit to disable encryption.",
        ),
        encryptionPassphrase: z.string().optional().meta({ sensitive: true })
          .describe(
            "Passphrase for keyformat=passphrase keylocation=prompt. " +
              "Required when encryption is set.",
          ),
        recordsize: z.string().optional(),
        mountpoint: z.string().optional(),
        canmount: z.enum(["on", "off", "noauto"]).optional(),
      }),
      execute: async (args, context) => {
        const t = resolveTarget(context.globalArgs, args);
        const opts: string[] = [`-o compression=${args.compression}`];
        if (args.quota) opts.push(`-o quota=${args.quota}`);
        if (args.reservation) opts.push(`-o reservation=${args.reservation}`);
        if (args.recordsize) opts.push(`-o recordsize=${args.recordsize}`);
        if (args.mountpoint) opts.push(`-o mountpoint=${shq(args.mountpoint)}`);
        if (args.canmount) opts.push(`-o canmount=${args.canmount}`);

        if (args.encryption) {
          if (!args.encryptionPassphrase) {
            throw new Error(
              "encryptionPassphrase is required when encryption is set",
            );
          }
          opts.push(
            `-o encryption=${args.encryption}`,
            `-o keyformat=passphrase`,
            `-o keylocation=prompt`,
          );
        }

        const cmd = `${
          pfexec(`zfs create ${opts.join(" ")} ${shq(args.name)}`)
        }`;
        // Pipe the passphrase twice (zfs create with keylocation=prompt asks
        // for it then a confirmation). Redact from any thrown error so the
        // secret doesn't leak via stderr capture.
        const stdin = args.encryption
          ? `${args.encryptionPassphrase}\n${args.encryptionPassphrase}\n`
          : undefined;
        const redact = args.encryptionPassphrase
          ? [args.encryptionPassphrase]
          : undefined;
        await sshExecOrThrow(t, cmd, stdin, { redact });

        // Read back the created dataset.
        const out = await sshExecOrThrow(
          t,
          `zfs get -Hp -o property,value all ${shq(args.name)}`,
        );
        const ds = parseDatasetGet(out.stdout, args.name);
        const handle = await context.writeResource("dataset", args.name, ds);
        return { dataHandles: [handle] };
      },
    },

    dataset_destroy: {
      description: "Destroy a dataset (recursive optional).",
      arguments: z.object({
        ...SshArgsShape,
        name: z.string(),
        recursive: z.boolean().default(false),
        force: z.boolean().default(false),
      }),
      execute: async (args, context) => {
        const t = resolveTarget(context.globalArgs, args);
        // Verify the dataset exists before destroying.
        const probe = await sshExec(
          t,
          `zfs list -H -o name ${shq(args.name)}`,
        );
        if (probe.code !== 0) {
          throw new Error(
            `Refusing to destroy '${args.name}': dataset does not exist (zfs list exit ${probe.code})`,
          );
        }
        const flags = `${args.recursive ? "-r" : ""}${args.force ? " -f" : ""}`
          .trim();
        await sshExecOrThrow(
          t,
          `${pfexec(`zfs destroy ${flags} ${shq(args.name)}`)}`,
        );
        return { dataHandles: [] };
      },
    },

    snapshot_create: {
      description: "Create a snapshot pool/dataset@name.",
      arguments: z.object({
        ...SshArgsShape,
        name: z.string().describe(
          "Fully-qualified e.g. rpool/zones/foo@2026-05-14",
        ),
        recursive: z.boolean().default(false),
      }),
      execute: async (args, context) => {
        const t = resolveTarget(context.globalArgs, args);
        const flags = args.recursive ? "-r" : "";
        await sshExecOrThrow(
          t,
          `${pfexec(`zfs snapshot ${flags} ${shq(args.name)}`)}`,
        );
        const out = await sshExecOrThrow(
          t,
          `zfs list -H -p -t snapshot -o name,used,referenced ${
            shq(args.name)
          }`,
        );
        const [name, used, refer] = out.stdout.trim().split(/\t/);
        const handle = await context.writeResource("snapshot", name, {
          name,
          used: Number(used ?? 0),
          refer: Number(refer ?? 0),
          observedAt: new Date().toISOString(),
        });
        return { dataHandles: [handle] };
      },
    },

    snapshot_destroy: {
      description: "Destroy a snapshot.",
      arguments: z.object({
        ...SshArgsShape,
        name: z.string(),
      }),
      execute: async (args, context) => {
        const t = resolveTarget(context.globalArgs, args);
        await sshExecOrThrow(
          t,
          `${pfexec(`zfs destroy ${shq(args.name)}`)}`,
        );
        return { dataHandles: [] };
      },
    },

    delegate: {
      description:
        "Delegate a dataset into a zone: `zfs zone <dataset> <zone>`. " +
        "Requires the zone to be in configured state and the dataset to " +
        "have `zoned=on` after delegation.",
      arguments: z.object({
        ...SshArgsShape,
        dataset: z.string(),
        zone: z.string(),
      }),
      execute: async (args, context) => {
        const t = resolveTarget(context.globalArgs, args);
        await sshExecOrThrow(
          t,
          `${pfexec(`zfs zone ${shq(args.zone)} ${shq(args.dataset)}`)}`,
        );
        const out = await sshExecOrThrow(
          t,
          `zfs get -Hp -o property,value all ${shq(args.dataset)}`,
        );
        const ds = parseDatasetGet(out.stdout, args.dataset);
        ds.delegatedTo = args.zone;
        const handle = await context.writeResource("dataset", args.dataset, ds);
        return { dataHandles: [handle] };
      },
    },

    pool_status: {
      description: "Capture pool size/usage and zpool status output.",
      arguments: z.object({
        ...SshArgsShape,
        pool: z.string(),
      }),
      execute: async (args, context) => {
        const t = resolveTarget(context.globalArgs, args);
        const list = await sshExecOrThrow(
          t,
          `zpool list -H -p -o name,size,alloc,free,health ${shq(args.pool)}`,
        );
        const [name, size, alloc, free, health] = list.stdout.trim().split(
          /\t/,
        );
        const status = await sshExecOrThrow(
          t,
          `zpool status ${shq(args.pool)}`,
        );
        const handle = await context.writeResource("pool", name, {
          name,
          size: Number(size ?? 0),
          alloc: Number(alloc ?? 0),
          free: Number(free ?? 0),
          health,
          scrubInProgress: /scan: scrub in progress/.test(status.stdout),
          rawStatus: status.stdout,
          observedAt: new Date().toISOString(),
        });
        return { dataHandles: [handle] };
      },
    },

    pool_scrub: {
      description: "Start a scrub on a pool.",
      arguments: z.object({
        ...SshArgsShape,
        pool: z.string(),
      }),
      execute: async (args, context) => {
        const t = resolveTarget(context.globalArgs, args);
        await sshExecOrThrow(
          t,
          `${pfexec(`zpool scrub ${shq(args.pool)}`)}`,
        );
        return { dataHandles: [] };
      },
    },
  },
};
