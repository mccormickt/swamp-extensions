// Subprocess wrapper around `aer`, the CLI for the aurae runtime daemon
// (auraed). The driver speaks to auraed only through this module, so the
// rest of the package can stay ignorant of two awkward facts:
//
//   1. `aer` has no --endpoint/--cert flags. It loads its connection from
//      ~/.aurae/config (then /etc/aurae/config, /var/lib/aurae/config) via
//      `AuraeConfig::try_default()`. To target a remote auraed, point a
//      per-host config dir and run `aer` with HOME set to that dir.
//
//   2. `aer` prints every gRPC response with Rust's pretty-debug format
//      (`println!("{res:#?}")`) and exits 0 even on errors. The exit code
//      from `aer` is therefore not a reliable success signal — a missing
//      expected field or any text on stderr is.
//
// The shape mirrors `extensions/shared/ssh.ts`: a small Deno.Command wrapper
// plus a couple of pure parsers.

/** Configuration for an {@link AerClient}. */
export interface AerConfig {
  /** Path to the `aer` binary (or just `"aer"` to use `$PATH`). */
  binary: string;
  /**
   * Directory containing the aurae `config` file. When set, the driver runs
   * `aer` with `HOME=configHome` so `~/.aurae/config` resolves to the
   * correct cert + socket for a per-host auraed.
   */
  configHome?: string;
  /** Additional environment variables to pass through to `aer`. */
  env?: Record<string, string>;
}

/** Result of a one-shot `aer` invocation. */
export interface AerExecResult {
  code: number;
  stdout: string;
  stderr: string;
}

/** A single LogItem.line extracted from `aer observe`, tagged with channel. */
export interface ObserveLine {
  line: string;
  /** 1 = stdout, 2 = stderr. Matches `aer observe`'s channel argument. */
  channel: 1 | 2;
}

/**
 * Thin subprocess wrapper around the `aer` CLI. The rest of the driver
 * speaks to auraed only through this class so it can stay ignorant of
 * `aer`'s quirks: no `--endpoint` flag (config is HOME-based), gRPC
 * responses pretty-printed with Rust's debug formatter, and exit code 0
 * even on protocol errors. Methods return the parsed result; callers
 * inspect stderr and the parsed stdout to decide success.
 */
export class AerClient {
  constructor(readonly config: AerConfig) {}

  private envFor(): Record<string, string> {
    const base: Record<string, string> = {};
    if (this.config.configHome) base.HOME = this.config.configHome;
    if (this.config.env) Object.assign(base, this.config.env);
    return base;
  }

  /**
   * Run a single `aer` subcommand to completion. Each argv element is
   * passed as-is — no shell interpolation. The caller checks `stderr` and
   * `code` plus the parsed stdout to decide success (see {@link AerConfig}).
   *
   * `timeoutMs`, if supplied, hard-bounds the call so a hung auraed (e.g.
   * `cell free` blocked on stuck observe streams) can't wedge the driver.
   * On timeout the subprocess is killed and the returned result carries a
   * synthetic stderr.
   */
  async exec(args: string[], timeoutMs?: number): Promise<AerExecResult> {
    // @ts-ignore - Deno API
    const proc = new Deno.Command(this.config.binary, {
      args,
      env: this.envFor(),
      stdin: "null",
      stdout: "piped",
      stderr: "piped",
    }).spawn();

    let timer: number | undefined;
    let timedOut = false;
    if (timeoutMs !== undefined) {
      // @ts-ignore - Deno setTimeout returns number
      timer = setTimeout(() => {
        timedOut = true;
        try {
          proc.kill("SIGKILL");
        } catch (_) { /* already exited */ }
      }, timeoutMs);
    }

    try {
      const out = await proc.output();
      return {
        code: out.code,
        stdout: new TextDecoder().decode(out.stdout),
        stderr: timedOut
          ? `aer ${args.join(" ")}: timed out after ${timeoutMs}ms`
          : new TextDecoder().decode(out.stderr),
      };
    } finally {
      if (timer !== undefined) clearTimeout(timer);
    }
  }

  /**
   * Stream `aer observe get-sub-process-stream <pid> <channel>` and yield
   * one entry per parsed `LogItem.line`. The subprocess's stdout EOF —
   * which auraed sends when the cell process exits — terminates the
   * generator. The caller is responsible for awaiting both channels
   * concurrently.
   *
   * `cellName` is required when the process was started inside a cell:
   * auraed routes the observe RPC to that cell's nested daemon, which is
   * where the stdout/stderr channels were registered. Omit it only for
   * executables started at the root level (none, currently).
   *
   * `signal` lets the caller abort the underlying subprocess (e.g. when
   * the driver's wall-clock timer fires) so cleanup can still run.
   */
  async *observe(
    pid: number,
    channel: 1 | 2,
    cellName?: string,
    signal?: AbortSignal,
  ): AsyncGenerator<ObserveLine> {
    const args = ["observe", "get-sub-process-stream"];
    if (cellName !== undefined) args.push("--cell-name", cellName);
    args.push(String(pid), String(channel));
    // @ts-ignore - Deno API
    const proc = new Deno.Command(this.config.binary, {
      args,
      env: this.envFor(),
      stdin: "null",
      stdout: "piped",
      stderr: "piped",
    }).spawn();

    // Kill the subprocess on abort. We use SIGKILL because aer's gRPC
    // client doesn't always honor SIGTERM promptly when blocked in a
    // streaming RPC.
    const onAbort = () => {
      try {
        proc.kill("SIGKILL");
      } catch (_) { /* already exited */ }
    };
    signal?.addEventListener("abort", onAbort, { once: true });

    try {
      const reader = proc.stdout
        .pipeThrough(new TextDecoderStream())
        .getReader();
      let buffer = "";
      while (true) {
        if (signal?.aborted) break;
        const { done, value } = await reader.read();
        if (done) break;
        buffer += value;
        const cut = lastStanzaEnd(buffer);
        if (cut === 0) continue;
        for (const line of extractLogLines(buffer.slice(0, cut))) {
          yield { line, channel };
        }
        buffer = buffer.slice(cut);
      }
      // Flush any trailing stanza that closed with EOF instead of `\n}\n`.
      for (const line of extractLogLines(buffer)) {
        yield { line, channel };
      }
    } finally {
      signal?.removeEventListener("abort", onAbort);
      try {
        proc.kill("SIGKILL");
      } catch (_) { /* already exited */ }
      await proc.status.catch(() => {});
    }
  }
}

/**
 * Parse the `pid: <int>` field out of a `CellServiceStartResponse` printed
 * in Rust pretty-debug format. Returns the first match, or throws if no
 * `pid` field is found in `stdout`.
 *
 * Example stdout:
 * ```
 *   CellServiceStartResponse {
 *       pid: 12345,
 *       uid: 0,
 *       gid: 0,
 *   }
 * ```
 */
export function parseStartPid(stdout: string): number {
  const m = stdout.match(/\bpid:\s*(\d+)/);
  if (!m) {
    throw new Error(
      `aer cell start: no pid in response\n--- stdout ---\n${stdout}`,
    );
  }
  return Number(m[1]);
}

/**
 * Yield every `line: "..."` string found in `text`, in order, with Rust
 * debug-string escapes (`\\`, `\"`, `\n`, `\t`, `\r`, `\0`) unescaped to
 * their literal characters. Used to pull `LogItem.line` out of
 * `aer observe`'s pretty-debug output stream.
 */
export function* extractLogLines(text: string): Iterable<string> {
  // The Rust Debug impl for `String` uses `\"` for double quotes and `\\`
  // for backslashes; everything else is left literal in pretty mode unless
  // it's a control character (\n, \t, \r, \0 get their escape forms).
  const re = /\bline:\s*"((?:[^"\\]|\\.)*)"/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    yield unescapeRustDebugString(m[1]);
  }
}

function unescapeRustDebugString(s: string): string {
  let out = "";
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c !== "\\") {
      out += c;
      continue;
    }
    const next = s[++i];
    switch (next) {
      case "n":
        out += "\n";
        break;
      case "t":
        out += "\t";
        break;
      case "r":
        out += "\r";
        break;
      case "0":
        out += "\0";
        break;
      case "\\":
      case '"':
      case "'":
        out += next;
        break;
      default:
        // Unknown escape — preserve verbatim so we never lose data.
        out += "\\" + (next ?? "");
        break;
    }
  }
  return out;
}

// Byte offset just past the last `}` at column 0 in `buffer`. Coarse
// boundary between completed pretty-debug stanzas and any in-progress
// trailing one — safe because aer always prints stanzas terminated with a
// top-level `}` followed by `\n`.
function lastStanzaEnd(buffer: string): number {
  const m = buffer.match(/[\s\S]*\n\}\n/);
  return m ? m[0].length : 0;
}
