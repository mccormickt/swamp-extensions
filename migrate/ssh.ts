/**
 * `@mccormick/migrate/disk` — SSH execution + relay-pipe helper.
 *
 * Adapted from the `@mccormick/helios` `shared/ssh.ts` pattern (spawning
 * `Deno.Command("ssh")` directly, never `sh -c` locally) but self-contained so
 * the migrate extension has no cross-extension import. Two shapes are needed:
 *
 *   - {@link sshExec} — run one command on one host (direct stream, the auto
 *     probe, and the offline disk edit all use this);
 *   - {@link relayStream} — spawn `ssh src '<read|zstd>'` and
 *     `ssh dst '<zstd|write>'` on the swamp host and pipe the first's stdout
 *     into the second's stdin (the relay transfer topology).
 *
 * Every interpolated path is quoted with `shq` (see `build.ts`) before it
 * reaches a remote command string; secrets passed in `redact` are masked from
 * thrown errors.
 *
 * @module
 */

/** Resolved SSH connection target for one host. */
export interface SshTarget {
  host: string;
  user: string;
  port?: number;
  /** Forward the swamp host's agent (`ssh -A`) — direct mode without a key. */
  agentForward?: boolean;
  /** Identity file on the swamp host for the outer connection. */
  identityFile?: string;
  connectTimeoutSec?: number;
}

/** Outcome of a single `sshExec`. */
export interface SshExecResult {
  code: number;
  stdout: string;
  stderr: string;
  timedOut: boolean;
}

const DEFAULT_TIMEOUT_MS = 3_600_000; // 1h — disk streams are long.

/** Build the shared `ssh` option/flag list for a target. */
export function baseArgs(t: SshTarget): string[] {
  const args = [
    "-o",
    `ConnectTimeout=${t.connectTimeoutSec ?? 15}`,
    "-o",
    "BatchMode=yes",
    "-o",
    "StrictHostKeyChecking=accept-new",
  ];
  if (t.agentForward) args.push("-A");
  if (t.identityFile) args.push("-i", t.identityFile);
  if (t.port) args.push("-p", String(t.port));
  return args;
}

function redactString(s: string, redact?: string[]): string {
  if (!redact) return s;
  let out = s;
  for (const secret of redact) {
    if (secret && secret.length > 0) out = out.split(secret).join("***");
  }
  return out;
}

const dec = new TextDecoder();

/** Run one command on `t.host` over SSH, bounded by `timeoutMs`. */
export async function sshExec(
  t: SshTarget,
  command: string,
  opts?: { timeoutMs?: number | null },
): Promise<SshExecResult> {
  const timeoutMs = opts?.timeoutMs === null
    ? null
    : (opts?.timeoutMs ?? DEFAULT_TIMEOUT_MS);
  const proc = new Deno.Command("ssh", {
    args: [...baseArgs(t), `${t.user}@${t.host}`, command],
    stdin: "null",
    stdout: "piped",
    stderr: "piped",
  });
  const child = proc.spawn();
  let timer: ReturnType<typeof setTimeout> | undefined;
  let timedOut = false;
  if (timeoutMs !== null) {
    timer = setTimeout(() => {
      timedOut = true;
      try {
        child.kill("SIGKILL");
      } catch { /* already exited */ }
    }, timeoutMs);
  }
  try {
    const out = await child.output();
    return {
      code: timedOut ? 124 : out.code,
      stdout: dec.decode(out.stdout),
      stderr: timedOut
        ? `<timeout after ${timeoutMs}ms>`
        : dec.decode(out.stderr),
      timedOut,
    };
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

/** Like {@link sshExec} but throws (redacted) on non-zero exit. */
export async function sshExecOrThrow(
  t: SshTarget,
  command: string,
  opts?: { timeoutMs?: number | null; redact?: string[] },
): Promise<SshExecResult> {
  const r = await sshExec(t, command, opts);
  if (r.code !== 0) {
    const cmd = command.length > 200 ? command.slice(0, 200) + "..." : command;
    throw new Error(
      `ssh ${t.user}@${t.host}: command failed (exit ${r.code})\n` +
        `  cmd: ${redactString(cmd, opts?.redact)}\n` +
        `  stderr: ${redactString(r.stderr.slice(-500), opts?.redact)}`,
    );
  }
  return r;
}

/** Outcome of a relay transfer (two joined ssh legs). */
export interface RelayResult {
  /** Exit code of the destination (write) leg. */
  dstCode: number;
  /** Exit code of the source (read) leg. */
  srcCode: number;
  dstStderr: string;
  srcStderr: string;
  timedOut: boolean;
}

/**
 * Relay a stream through the swamp host: `ssh src '<srcCommand>'` whose stdout
 * is piped into `ssh dst '<dstCommand>'`'s stdin. Both legs use the swamp host's
 * own credentials, so no source→dest trust is required (the safe default when
 * the auto probe finds the hosts can't reach each other directly).
 */
export async function relayStream(
  src: SshTarget,
  srcCommand: string,
  dst: SshTarget,
  dstCommand: string,
  opts?: { timeoutMs?: number | null },
): Promise<RelayResult> {
  const timeoutMs = opts?.timeoutMs === null
    ? null
    : (opts?.timeoutMs ?? DEFAULT_TIMEOUT_MS);
  const srcProc = new Deno.Command("ssh", {
    args: [...baseArgs(src), `${src.user}@${src.host}`, srcCommand],
    stdin: "null",
    stdout: "piped",
    stderr: "piped",
  }).spawn();
  const dstProc = new Deno.Command("ssh", {
    args: [...baseArgs(dst), `${dst.user}@${dst.host}`, dstCommand],
    stdin: "piped",
    stdout: "piped",
    stderr: "piped",
  }).spawn();

  let timedOut = false;
  let timer: ReturnType<typeof setTimeout> | undefined;
  if (timeoutMs !== null) {
    timer = setTimeout(() => {
      timedOut = true;
      try {
        srcProc.kill("SIGKILL");
      } catch { /* gone */ }
      try {
        dstProc.kill("SIGKILL");
      } catch { /* gone */ }
    }, timeoutMs);
  }
  try {
    // Pipe the compressed stream from src into dst; closes dst's stdin at EOF.
    const piping = srcProc.stdout.pipeTo(dstProc.stdin).catch(() => {});
    const [srcOut, dstOut] = await Promise.all([
      srcProc.output(),
      dstProc.output(),
    ]);
    await piping;
    return {
      srcCode: timedOut ? 124 : srcOut.code,
      dstCode: timedOut ? 124 : dstOut.code,
      srcStderr: dec.decode(srcOut.stderr),
      dstStderr: timedOut
        ? `<timeout after ${timeoutMs}ms>`
        : dec.decode(dstOut.stderr),
      timedOut,
    };
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}
