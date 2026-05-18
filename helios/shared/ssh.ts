// SSH execution helper shared across all @mccormick/helios models.
//
// Assumes the SSH key is provided by the user's ssh-agent (e.g. 1Password's
// SSH agent). The helios models pass `host`/`user`/`port` from their global
// arguments. For the inventory fan-out, ControlMaster multiplexing keeps a
// single TCP session open across the multiple commands the script issues.

export interface SshTarget {
  host: string;
  user: string;
  port?: number;
  knownHosts?: string;
  controlPath?: string;
}

// Required per-method connection fields. Models include these in every
// method's argument schema. The host is the verb's target — making it
// required keeps invocations unambiguous (no silent fallback to a
// stale globalArgs host). User/port/knownHosts may still default from
// the model's globalArguments.
export interface SshArgs {
  sshHost: string;
  sshUser?: string;
  sshPort?: number;
  sshKnownHosts?: string;
}

export interface SshGlobalArgs {
  sshUser?: string;
  sshPort?: number;
  sshKnownHosts?: string;
}

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

export interface SshExecResult {
  code: number;
  stdout: string;
  stderr: string;
}

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

export async function sshExec(
  t: SshTarget,
  command: string,
  stdin?: string,
): Promise<SshExecResult> {
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
  const result = await child.output();
  return {
    code: result.code,
    stdout: new TextDecoder().decode(result.stdout),
    stderr: new TextDecoder().decode(result.stderr),
  };
}

// Throws on non-zero exit. Use when you want the method to fail.
export async function sshExecOrThrow(
  t: SshTarget,
  command: string,
  stdin?: string,
): Promise<SshExecResult> {
  const r = await sshExec(t, command, stdin);
  if (r.code !== 0) {
    throw new Error(
      `ssh ${t.user}@${t.host}: command failed (exit ${r.code})\n` +
        `  cmd: ${
          command.length > 200 ? command.slice(0, 200) + "..." : command
        }\n` +
        `  stderr: ${r.stderr.slice(-500)}`,
    );
  }
  return r;
}

// Run a command with `pfexec` so non-root users with the right RBAC profile
// can perform privileged operations.
export function pfexec(cmd: string): string {
  return `pfexec ${cmd}`;
}

// Quote a single shell argument safely (single-quote escaping).
export function shq(s: string): string {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}

// Open a ControlMaster session for a sequence of commands; returns a target
// pre-configured with controlPath plus a cleanup callback.
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
    close: async () => {
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
