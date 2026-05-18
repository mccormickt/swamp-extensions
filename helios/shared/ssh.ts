// SSH execution helper shared across all @mccormick/helios models.
//
// Assumes the SSH key is provided by the user's ssh-agent (e.g. 1Password's
// SSH agent). The helios models pass `host`/`user`/`port` from their global
// arguments. For the inventory fan-out, ControlMaster multiplexing keeps a
// single TCP session open across the multiple commands the script issues.

import { z } from "npm:zod@4";

/** Resolved SSH connection target for a single host. */
export interface SshTarget {
  host: string;
  user: string;
  port?: number;
  knownHosts?: string;
  controlPath?: string;
}

/**
 * Per-method connection fields. Models include these in every method's
 * argument schema. `sshHost` is required on every call — making it required
 * keeps invocations unambiguous (no silent fallback to a stale `globalArgs`
 * host). `sshUser`/`sshPort`/`sshKnownHosts` may still default from the
 * model's `globalArguments`.
 */
export interface SshArgs {
  sshHost: string;
  sshUser?: string;
  sshPort?: number;
  sshKnownHosts?: string;
}

/** Connection defaults declared on each helios model's `globalArguments`. */
export interface SshGlobalArgs {
  sshUser?: string;
  sshPort?: number;
  sshKnownHosts?: string;
}

/**
 * Zod object-shape for per-method SSH connection arguments. Spread into
 * each method's `arguments: z.object({ ...SshArgsShape, ... })` so the four
 * helios models share the same wire-format and validation rules without
 * duplicating the literal four times.
 */
export const SshArgsShape = {
  sshHost: z.string().describe("Target Helios host (FQDN or IP)."),
  sshUser: z.string().optional(),
  sshPort: z.number().int().positive().optional(),
  sshKnownHosts: z.string().optional(),
};

/** Convenience: `SshArgsShape` wrapped as a `z.object(...)`. */
export const SshArgsSchema = z.object(SshArgsShape);

/**
 * Merge `globalArgs` (model defaults) with `methodArgs` (per-call inputs)
 * into a fully-resolved {@link SshTarget}. Throws if `sshHost` is missing.
 */
export function resolveTarget(
  globalArgs: SshGlobalArgs,
  methodArgs: SshArgs,
): SshTarget {
  if (!methodArgs.sshHost) {
    throw new Error(
      "sshHost is required on every method call (e.g. " +
        "--input sshHost=helios.example.com).",
    );
  }
  return {
    host: methodArgs.sshHost,
    user: methodArgs.sshUser ?? globalArgs.sshUser ?? "root",
    port: methodArgs.sshPort ?? globalArgs.sshPort,
    knownHosts: methodArgs.sshKnownHosts ?? globalArgs.sshKnownHosts,
  };
}

/** Outcome of a single `sshExec` call. */
export interface SshExecResult {
  code: number;
  stdout: string;
  stderr: string;
}

/** Options accepted by {@link sshExec} and {@link sshExecOrThrow}. */
export interface SshExecOptions {
  /**
   * Cancellation deadline for the remote command, in milliseconds. Pass
   * `null` to disable the timeout. Default 120000 (2 minutes). On timeout
   * the spawned `ssh` is killed, the returned {@link SshExecResult} has
   * `code: 124` and `stderr` records `"<timeout after Nms>"`.
   */
  timeoutMs?: number | null;
  /**
   * Secret values that should be replaced with `***` before appearing in
   * any thrown error message from {@link sshExecOrThrow}. Pass passphrases
   * or other sensitive values you sent via `stdin`.
   */
  redact?: string[];
}

const DEFAULT_TIMEOUT_MS = 120_000;

function baseArgs(t: SshTarget): string[] {
  const args = ["-o", "ConnectTimeout=10", "-o", "BatchMode=yes"];
  if (t.knownHosts) {
    args.push("-o", `UserKnownHostsFile=${t.knownHosts}`);
  } else {
    args.push("-o", "StrictHostKeyChecking=accept-new");
  }
  if (t.port) args.push("-p", String(t.port));
  if (t.controlPath) {
    args.push(
      "-o",
      `ControlPath=${t.controlPath}`,
      "-o",
      "ControlMaster=auto",
      "-o",
      "ControlPersist=60s",
    );
  }
  return args;
}

/**
 * Run a single shell command on `t.host` over SSH.
 *
 * The command runs under the remote user's login shell (`ssh user@host
 * <command>`). Quote arguments with {@link shq} before interpolating
 * untrusted values — there is no automatic escaping. `stdin`, if supplied,
 * is written verbatim and the writer is closed (so the remote process sees
 * EOF and can finish reading).
 *
 * Bounded by `opts.timeoutMs` (default 120s). On timeout the subprocess is
 * killed with `SIGKILL` and the returned result carries `code: 124` plus a
 * synthetic stderr; callers do not need to catch a thrown error.
 */
export async function sshExec(
  t: SshTarget,
  command: string,
  stdin?: string,
  opts?: SshExecOptions,
): Promise<SshExecResult> {
  const timeoutMs = opts?.timeoutMs === null
    ? null
    : (opts?.timeoutMs ?? DEFAULT_TIMEOUT_MS);
  // @ts-ignore - Deno API
  const proc = new Deno.Command("ssh", {
    args: [...baseArgs(t), `${t.user}@${t.host}`, command],
    stdin: stdin === undefined ? "null" : "piped",
    stdout: "piped",
    stderr: "piped",
  });
  const child = proc.spawn();
  if (stdin !== undefined) {
    const writer = child.stdin.getWriter();
    await writer.write(new TextEncoder().encode(stdin));
    await writer.close();
  }
  let timer: number | undefined;
  let timedOut = false;
  if (timeoutMs !== null) {
    // @ts-ignore - Deno setTimeout returns number
    timer = setTimeout(() => {
      timedOut = true;
      try {
        child.kill("SIGKILL");
      } catch (_) { /* already exited */ }
    }, timeoutMs);
  }
  try {
    const result = await child.output();
    if (timedOut) {
      return {
        code: 124,
        stdout: new TextDecoder().decode(result.stdout),
        stderr: `<timeout after ${timeoutMs}ms>`,
      };
    }
    return {
      code: result.code,
      stdout: new TextDecoder().decode(result.stdout),
      stderr: new TextDecoder().decode(result.stderr),
    };
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

function redactString(s: string, redact?: string[]): string {
  if (!redact || redact.length === 0) return s;
  let out = s;
  for (const secret of redact) {
    if (secret && secret.length > 0) {
      // Plain split/join so we don't have to escape regex metacharacters.
      out = out.split(secret).join("***");
    }
  }
  return out;
}

/**
 * Like {@link sshExec} but throws on non-zero exit. Use when a failed
 * command should fail the whole method.
 *
 * Any string in `opts.redact` is replaced with `***` in the thrown error
 * message (both the command and the captured stderr) — pass passphrases
 * here when running encrypted-dataset operations or any other call that
 * could echo a secret back in failure output.
 */
export async function sshExecOrThrow(
  t: SshTarget,
  command: string,
  stdin?: string,
  opts?: SshExecOptions,
): Promise<SshExecResult> {
  const r = await sshExec(t, command, stdin, opts);
  if (r.code !== 0) {
    const cmd = command.length > 200 ? command.slice(0, 200) + "..." : command;
    const tail = r.stderr.slice(-500);
    throw new Error(
      `ssh ${t.user}@${t.host}: command failed (exit ${r.code})\n` +
        `  cmd: ${redactString(cmd, opts?.redact)}\n` +
        `  stderr: ${redactString(tail, opts?.redact)}`,
    );
  }
  return r;
}

/**
 * Wrap a command with `pfexec` so non-root users with the appropriate
 * Solaris RBAC profile (Zone Management, ZFS Storage Management, Network
 * Management, etc.) can run privileged operations.
 */
export function pfexec(cmd: string): string {
  return `pfexec ${cmd}`;
}

/**
 * Quote a single shell argument with single-quote escaping. Safe to embed
 * in a remote command string built for {@link sshExec}.
 */
export function shq(s: string): string {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}

/**
 * Open a ControlMaster session for a sequence of commands. Returns a
 * target pre-configured with a unique `controlPath` plus a `close()`
 * callback that tears the master connection down and removes the temp
 * directory. Each `sshExec` against the returned target reuses the
 * existing TCP connection — large fan-outs (zone inventory, health check)
 * avoid the per-command auth round-trip.
 */
export async function openSession(
  t: Omit<SshTarget, "controlPath">,
): Promise<{ target: SshTarget; close: () => Promise<void> }> {
  const tmp = await Deno.makeTempDir({ prefix: "swamp-helios-" });
  const controlPath = `${tmp}/cm-%C`;
  const target: SshTarget = { ...t, controlPath };
  // Open the master connection.
  await sshExecOrThrow(target, "true");
  return {
    target,
    close: async (): Promise<void> => {
      // @ts-ignore - Deno API
      const proc = new Deno.Command("ssh", {
        args: [...baseArgs(target), "-O", "exit", `${t.user}@${t.host}`],
        stdout: "null",
        stderr: "null",
      });
      await proc.output();
      try {
        await Deno.remove(tmp, { recursive: true });
      } catch (_) { /* best effort */ }
    },
  };
}
