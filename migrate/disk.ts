/**
 * `@mccormick/migrate/disk` — host-to-host disk migration primitives.
 *
 * The hypervisor-neutral middle of the `migrate-vm` workflow: it belongs to
 * neither Proxmox nor TrueNAS, so it is its own model. Three methods:
 *
 *   - `stream` — copy a powered-off source block device to a destination block
 *     device over an encrypted, compressed pipe (`dd | zstd | ssh "zstd -dc |
 *     dd conv=sparse"`), either **direct** (source→dest, needs trust) or
 *     **relay** (bridged through the swamp host, the safe default), with `auto`
 *     probing which is possible. Verifies the written byte count.
 *   - `edit_guest_disk` — the agent-absent fallback: mount the guest's LVM root
 *     over qemu-nbd (or locally) on a tool host, rewrite netplan to match by the
 *     target MAC, disable cloud-init networking, and tear it all down in a trap.
 *   - `verify` — poll a cutover IP for TCP/ICMP reachability.
 *
 * This is the justified case for SSH inside an extension (vs. the repo's
 * "command/shell is ad-hoc only" rule): a reusable, parameterized integration
 * with two transfer topologies, sparse targets, and byte-count verification —
 * not a one-off shell line. SSH lives in `ssh.ts`; the command strings it runs
 * are assembled (and unit-tested) in `build.ts`.
 *
 * @module
 */
import { z } from "npm:zod@4";
import type { ModelDefinition } from "jsr:@systeminit/swamp-testing@0.20260519.14";
import { GuestDiskEditSchema, TransferSchema, VerifySchema } from "./schema.ts";
import { relayStream, sshExec, sshExecOrThrow, type SshTarget } from "./ssh.ts";
import {
  blockSizeBytes,
  buildEditGuestDiskScript,
  bytesVerified,
  directSrcCommand,
  type InnerSshOpts,
  parseDdBytes,
  probeCommand,
  relayDstCommand,
  relaySrcCommand,
  type StreamParams,
} from "./build.ts";

/** Global arguments for the disk-migration model. */
const GlobalArgs = z.object({
  sshUser: z.string().default("root").describe(
    "Default SSH user for src/dst/tool hosts (overridable per call)",
  ),
  sshPort: z.number().int().positive().optional().describe(
    "Default SSH port (omit for 22)",
  ),
  migrationKeyPath: z.string().optional().describe(
    "Private key path *on the source host* for direct-mode inner ssh; when " +
      "unset, direct mode forwards the swamp host's agent (ssh -A)",
  ),
  connectTimeoutSec: z.number().int().positive().default(15),
  taskTimeoutSec: z.number().int().positive().default(7200).describe(
    "Max seconds for a stream/edit (disk copies are long)",
  ),
});

const StreamArgs = z.object({
  srcHost: z.string().min(1),
  srcUser: z.string().optional(),
  dstHost: z.string().min(1),
  dstUser: z.string().optional(),
  srcDevPath: z.string().min(1),
  dstDevPath: z.string().min(1),
  expectedBytes: z.number().int().positive().optional(),
  mode: z.enum(["direct", "relay", "auto"]).default("auto"),
  blockSize: z.string().default("4M"),
  zstdLevel: z.number().int().min(1).max(19).default(3),
  zstdThreads: z.number().int().min(0).default(0),
  sparse: z.boolean().default(true),
});

const EditGuestDiskArgs = z.object({
  toolHost: z.string().min(1),
  toolUser: z.string().optional(),
  targetMode: z.enum(["local", "nbd"]),
  nbdHost: z.string().optional(),
  nbdPort: z.number().int().positive().default(10809),
  nbdDevice: z.string().default("/dev/nbd0"),
  localDevPath: z.string().optional(),
  vgName: z.string().min(1),
  lvName: z.string().min(1).default("ubuntu-lv"),
  mountPoint: z.string().default("/mnt/swamp-migrate"),
  lvmGlobalFilter: z.string().default("a|.*|"),
  targetMac: z.string().regex(
    /^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/,
    "targetMac must be a colon-separated 6-octet address",
  ),
  useDhcp: z.boolean().default(true),
  staticCidr: z.string().optional(),
  gateway: z.string().optional(),
}).refine((a) => a.targetMode === "local" ? !!a.localDevPath : !!a.nbdHost, {
  message: "local mode needs localDevPath; nbd mode needs nbdHost",
});

const VerifyArgs = z.object({
  ip: z.string().min(1),
  port: z.number().int().positive().default(22),
  mode: z.enum(["tcp", "ping"]).default("tcp"),
  expectReachable: z.boolean().default(true),
  timeoutSec: z.number().int().positive().default(300),
  pollIntervalSec: z.number().int().positive().default(5),
});

// --- Reachability probe (test seam) ----------------------------------------

/** A single reachability attempt; replaced in tests. */
export type ReachabilityProbe = (
  mode: "tcp" | "ping",
  ip: string,
  port: number,
  timeoutMs: number,
) => Promise<boolean>;

const defaultProbe: ReachabilityProbe = async (mode, ip, port, timeoutMs) => {
  if (mode === "ping") {
    const proc = new Deno.Command("ping", {
      args: ["-c", "1", "-W", "1", ip],
      stdout: "null",
      stderr: "null",
    });
    try {
      const { code } = await proc.output();
      return code === 0;
    } catch {
      return false;
    }
  }
  // tcp connect with a bounded wait
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const conn = await Promise.race([
      Deno.connect({ hostname: ip, port }),
      new Promise<never>((_, reject) => {
        timer = setTimeout(
          () => reject(new Error("connect timeout")),
          timeoutMs,
        );
      }),
    ]);
    (conn as Deno.Conn).close();
    return true;
  } catch {
    return false;
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
};

let reachabilityProbe: ReachabilityProbe = defaultProbe;

/** Test-only: override the reachability probe. Pass undefined to restore. */
export function __setReachabilityProbe(p: ReachabilityProbe | undefined): void {
  reachabilityProbe = p ?? defaultProbe;
}

// --- Helpers ---------------------------------------------------------------

function sanitize(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "") ||
    "x";
}

function target(
  host: string,
  user: string,
  g: z.infer<typeof GlobalArgs>,
  extra?: Partial<SshTarget>,
): SshTarget {
  return {
    host,
    user,
    port: g.sshPort,
    connectTimeoutSec: g.connectTimeoutSec,
    ...extra,
  };
}

// --- Model -----------------------------------------------------------------

/** Host-to-host disk migration primitives. */
export const model = {
  type: "@mccormick/migrate/disk",
  version: "2026.06.07.2",
  globalArguments: GlobalArgs,
  resources: {
    transfer: {
      description: "Result of one host-to-host disk stream",
      schema: TransferSchema,
      lifetime: "infinite",
      garbageCollection: 20,
    },
    guest_disk_edit: {
      description: "Result of an offline guest-disk edit",
      schema: GuestDiskEditSchema,
      lifetime: "infinite",
      garbageCollection: 20,
    },
    verify: {
      description: "Result of a post-cutover reachability check",
      schema: VerifySchema,
      lifetime: "infinite",
      garbageCollection: 20,
    },
  },
  checks: {
    "ssh-available": {
      description:
        "The local ssh client is runnable (and migrationKeyPath, if set, " +
        "exists) before a stream/edit — the per-host targets are method args, " +
        "so this validates the shared local prerequisites.",
      labels: ["live"],
      appliesTo: ["stream", "edit_guest_disk"],
      execute: async (
        context,
      ): Promise<{ pass: boolean; errors?: string[] }> => {
        const errors: string[] = [];
        try {
          const out = await new Deno.Command("ssh", {
            args: ["-V"],
            stdout: "null",
            stderr: "null",
          }).output();
          if (out.code !== 0) errors.push("`ssh -V` exited non-zero");
        } catch (err) {
          errors.push(
            `local ssh client not runnable: ${
              err instanceof Error ? err.message : String(err)
            }`,
          );
        }
        const key = context.globalArgs.migrationKeyPath;
        if (key) {
          try {
            await Deno.stat(key);
          } catch {
            errors.push(`migrationKeyPath not found on the swamp host: ${key}`);
          }
        }
        return errors.length > 0 ? { pass: false, errors } : { pass: true };
      },
    },
  },
  methods: {
    stream: {
      description:
        "Stream a powered-off source block device to a destination block " +
        "device (dd|zstd|ssh), direct or relay (auto-probed), verifying bytes.",
      arguments: StreamArgs,
      execute: async (rawArgs, context) => {
        const a = StreamArgs.parse(rawArgs);
        const g = context.globalArgs;
        const srcUser = a.srcUser ?? g.sshUser;
        const dstUser = a.dstUser ?? g.sshUser;
        const params: StreamParams = {
          srcDevPath: a.srcDevPath,
          dstDevPath: a.dstDevPath,
          blockSize: a.blockSize,
          zstdLevel: a.zstdLevel,
          zstdThreads: a.zstdThreads,
          sparse: a.sparse,
        };
        const inner: InnerSshOpts = {
          dstHost: a.dstHost,
          dstUser,
          connectTimeoutSec: g.connectTimeoutSec,
          migrationKeyPath: g.migrationKeyPath,
        };

        // Resolve the topology.
        let mode: "direct" | "relay";
        if (a.mode === "auto") {
          context.logger.info("stream: probing src→dst reachability", {});
          const probe = await sshExec(
            target(a.srcHost, srcUser, g),
            probeCommand(inner),
            { timeoutMs: (g.connectTimeoutSec + 5) * 1000 },
          );
          mode = probe.code === 0 ? "direct" : "relay";
          context.logger.info("stream: auto-selected {mode} mode", { mode });
        } else {
          mode = a.mode;
        }

        const startedAt = new Date();
        let bytesWritten: number | null = null;
        if (mode === "direct") {
          const srcTarget = target(a.srcHost, srcUser, g, {
            agentForward: !g.migrationKeyPath,
          });
          const remote = directSrcCommand(params, inner);
          context.logger.info("stream: direct {src} → {dst}", {
            src: a.srcDevPath,
            dst: a.dstDevPath,
          });
          const r = await sshExecOrThrow(srcTarget, remote, {
            timeoutMs: g.taskTimeoutSec * 1000,
            redact: g.migrationKeyPath ? [g.migrationKeyPath] : [],
          });
          bytesWritten = parseDdBytes(r.stderr);
        } else {
          context.logger.info("stream: relay {src} → {dst} via swamp host", {
            src: a.srcDevPath,
            dst: a.dstDevPath,
          });
          const r = await relayStream(
            target(a.srcHost, srcUser, g),
            relaySrcCommand(params),
            target(a.dstHost, dstUser, g),
            relayDstCommand(params),
            { timeoutMs: g.taskTimeoutSec * 1000 },
          );
          if (r.dstCode !== 0 || r.srcCode !== 0) {
            throw new Error(
              `stream: relay failed (src exit ${r.srcCode}, dst exit ` +
                `${r.dstCode}): ${r.dstStderr.slice(-400)}`,
            );
          }
          bytesWritten = parseDdBytes(r.dstStderr);
        }
        const finishedAt = new Date();

        const verified = a.expectedBytes !== undefined
          ? (bytesWritten !== null &&
            bytesVerified(
              bytesWritten,
              a.expectedBytes,
              blockSizeBytes(a.blockSize),
            ))
          : bytesWritten !== null;
        if (!verified) {
          throw new Error(
            `stream: byte verification failed (wrote ${bytesWritten}, ` +
              `expected ${a.expectedBytes ?? "unknown"})`,
          );
        }
        context.logger.info("stream: wrote {bytes} bytes ({mode})", {
          bytes: bytesWritten,
          mode,
        });

        const handle = await context.writeResource(
          "transfer",
          `xfer-${sanitize(a.srcHost)}-${sanitize(a.dstHost)}`,
          {
            srcHost: a.srcHost,
            dstHost: a.dstHost,
            srcDevPath: a.srcDevPath,
            dstDevPath: a.dstDevPath,
            mode,
            requestedMode: a.mode,
            bytesWritten,
            expectedBytes: a.expectedBytes ?? null,
            verified,
            zstdLevel: a.zstdLevel,
            zstdThreads: a.zstdThreads,
            sparse: a.sparse,
            startedAt: startedAt.toISOString(),
            finishedAt: finishedAt.toISOString(),
            durationSec: (finishedAt.getTime() - startedAt.getTime()) / 1000,
          },
        );
        return { dataHandles: [handle] };
      },
    },

    edit_guest_disk: {
      description:
        "Offline netplan fix: mount the guest LVM root over qemu-nbd/local on " +
        "a tool host (qemu-nbd + lvm2), rewrite to match-by-MAC, teardown in a " +
        "trap. The agent-absent fallback; LVM2 + ext4 roots only.",
      arguments: EditGuestDiskArgs,
      execute: async (rawArgs, context) => {
        const a = EditGuestDiskArgs.parse(rawArgs);
        const g = context.globalArgs;
        const toolUser = a.toolUser ?? g.sshUser;
        const script = buildEditGuestDiskScript({
          targetMode: a.targetMode,
          nbdHost: a.nbdHost,
          nbdPort: a.nbdPort,
          nbdDevice: a.nbdDevice,
          localDevPath: a.localDevPath,
          vgName: a.vgName,
          lvName: a.lvName,
          mountPoint: a.mountPoint,
          lvmGlobalFilter: a.lvmGlobalFilter,
          targetMac: a.targetMac,
          useDhcp: a.useDhcp,
          staticCidr: a.staticCidr,
          gateway: a.gateway,
        });
        context.logger.info(
          "edit_guest_disk: {mode} edit on {host} ({vg}/{lv})",
          { mode: a.targetMode, host: a.toolHost, vg: a.vgName, lv: a.lvName },
        );
        const r = await sshExecOrThrow(
          target(a.toolHost, toolUser, g),
          script,
          { timeoutMs: g.taskTimeoutSec * 1000 },
        );
        const applied = r.stdout.includes("swamp-edit-ok");
        if (!applied) {
          throw new Error(
            `edit_guest_disk: marker not seen — edit may be incomplete:\n` +
              r.stdout.slice(-300),
          );
        }
        const handle = await context.writeResource(
          "guest_disk_edit",
          `edit-${sanitize(a.toolHost)}-${sanitize(a.vgName)}`,
          {
            toolHost: a.toolHost,
            mode: a.targetMode,
            nbdHost: a.nbdHost ?? null,
            vg: a.vgName,
            lv: a.lvName,
            targetMac: a.targetMac,
            netMode: a.useDhcp ? "dhcp" : "static",
            applied,
            recordedAt: new Date().toISOString(),
          },
        );
        return { dataHandles: [handle] };
      },
    },

    verify: {
      description:
        "Poll an IP for TCP/ICMP reachability after cutover. Fails if the " +
        "expected reachability is not reached within the timeout.",
      arguments: VerifyArgs,
      execute: async (rawArgs, context) => {
        const a = VerifyArgs.parse(rawArgs);
        const deadline = Date.now() + a.timeoutSec * 1000;
        let attempts = 0;
        let reachable = false;
        while (Date.now() < deadline) {
          attempts++;
          reachable = await reachabilityProbe(a.mode, a.ip, a.port, 3000);
          if (reachable === a.expectReachable) break;
          await new Promise((r) => setTimeout(r, a.pollIntervalSec * 1000));
        }
        context.logger.info(
          "verify: {ip} reachable={reachable} after {n} attempt(s)",
          { ip: a.ip, reachable, n: attempts },
        );
        const handle = await context.writeResource(
          "verify",
          `verify-${sanitize(a.ip)}`,
          {
            ip: a.ip,
            port: a.mode === "tcp" ? a.port : null,
            mode: a.mode,
            reachable,
            expectReachable: a.expectReachable,
            attempts,
            recordedAt: new Date().toISOString(),
          },
        );
        if (reachable !== a.expectReachable) {
          throw new Error(
            `verify: ${a.ip} expected reachable=${a.expectReachable} but got ` +
              `${reachable} after ${attempts} attempt(s)`,
          );
        }
        return { dataHandles: [handle] };
      },
    },
  },
} satisfies ModelDefinition<typeof GlobalArgs>;
