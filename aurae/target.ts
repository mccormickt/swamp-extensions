// The isolation boundary `mod.ts` runs a method inside of. CellTarget uses
// `aer cell {allocate,start,stop,free}`; VmTarget will be a sibling class
// here that swaps to `aer vm ...` and keeps the driver orchestrator
// unchanged.

import { AerClient, parseStartPid } from "./aer.ts";

export interface TargetSpec {
  name: string;
  command: string;
  executableName: string;
  uid?: number;
  gid?: number;
}

export interface RunResult {
  pid: number;
  stdout: string[];
  stderr: string[];
  // No exit code is available — auraed/aer don't surface one for an
  // executable. `success` is true unless aer itself reported failure or
  // a configured failureMarker regex matched any stderr line.
  success: boolean;
  // First failure reason, if any, for the driver to surface.
  reason?: string;
}

export interface ExecutionTarget {
  readonly kind: "cell" | "vm";
  run(
    aer: AerClient,
    spec: TargetSpec,
    onLog: (line: string) => void,
    options?: {
      failureMarker?: RegExp;
      signal?: AbortSignal;
      cleanupTimeoutMs?: number;
    },
  ): Promise<RunResult>;
}

export interface CellLimits {
  cpuWeight?: number;
  cpuMax?: string;
  cpuPeriod?: string;
  cpusetCpus?: string;
  cpusetMems?: string;
  memoryMin?: string;
  memoryLow?: string;
  memoryHigh?: string;
  memoryMax?: string;
  isolateProcess?: boolean;
  isolateNetwork?: boolean;
}

export class CellTarget implements ExecutionTarget {
  readonly kind = "cell" as const;
  constructor(readonly limits: CellLimits) {}

  async run(
    aer: AerClient,
    spec: TargetSpec,
    onLog: (line: string) => void,
    options?: {
      failureMarker?: RegExp;
      signal?: AbortSignal;
      cleanupTimeoutMs?: number;
    },
  ): Promise<RunResult> {
    const failureMarker = options?.failureMarker;
    const signal = options?.signal;
    const cleanupTimeoutMs = options?.cleanupTimeoutMs ?? 5000;
    let allocated = false;
    let started = false;
    const stdout: string[] = [];
    const stderr: string[] = [];
    let pid = 0;
    let reason: string | undefined;
    const failResult = (msg: string): RunResult => ({
      pid,
      stdout,
      stderr,
      success: false,
      reason: msg,
    });

    try {
      // 1. Allocate the cell (cgroup + optional namespaces).
      const allocArgs = buildAllocateArgs(spec.name, this.limits);
      const alloc = await aer.exec(allocArgs);
      if (alloc.stderr.trim() !== "") {
        return failResult(
          `aer cell allocate failed: ${alloc.stderr.trim()}`,
        );
      }
      allocated = true;
      onLog(`[aurae] allocated cell ${spec.name}`);

      // 2. Start the executable inside the cell. The command is passed as a
      //    single argv element to `aer` — no shell here. (auraed itself runs
      //    it via sh -c on the remote side; that's outside our trust scope.)
      const startArgs: string[] = [
        "cell",
        "start",
        spec.name,
        spec.executableName,
        "-c",
        spec.command,
      ];
      if (spec.uid !== undefined) startArgs.push("--uid", String(spec.uid));
      if (spec.gid !== undefined) startArgs.push("--gid", String(spec.gid));
      const start = await aer.exec(startArgs);
      if (start.stderr.trim() !== "") {
        return failResult(`aer cell start failed: ${start.stderr.trim()}`);
      }
      try {
        pid = parseStartPid(start.stdout);
      } catch (e) {
        return failResult(String(e));
      }
      started = true;
      onLog(`[aurae] started ${spec.executableName} pid=${pid}`);

      // 3. Concurrently consume both log channels until each subprocess EOFs
      //    (which happens when the cell process exits). Routed via
      //    `--cell-name` so observe queries the cell's nested daemon, which
      //    is where stdout/stderr channels were registered at start time.
      //    `signal` lets the caller (mod.ts wall-clock timeout) abort the
      //    observe subprocesses so cleanup can still run.
      const consume = async (channel: 1 | 2, sink: string[]) => {
        for await (const item of aer.observe(pid, channel, spec.name, signal)) {
          sink.push(item.line);
          onLog(`[${channel === 1 ? "stdout" : "stderr"}] ${item.line}`);
          if (
            channel === 2 && failureMarker && failureMarker.test(item.line) &&
            reason === undefined
          ) {
            reason = `stderr matched failure marker: ${item.line}`;
          }
        }
      };
      await Promise.all([consume(1, stdout), consume(2, stderr)]);
      if (signal?.aborted && reason === undefined) {
        reason = "aborted (wall-clock timeout)";
      }

      return {
        pid,
        stdout,
        stderr,
        success: reason === undefined,
        reason,
      };
    } finally {
      // Best-effort cleanup: stop the executable, then free the cell. We
      // log failures but never re-throw — the run's outcome is what the
      // caller cares about. Each call is hard-bounded by
      // `cleanupTimeoutMs` so a stuck auraed can't wedge the driver.
      if (started) {
        const stop = await aer.exec([
          "cell",
          "stop",
          spec.name,
          spec.executableName,
        ], cleanupTimeoutMs);
        if (stop.stderr.trim() !== "") {
          onLog(`[aurae] warn: cell stop: ${stop.stderr.trim()}`);
        }
      }
      if (allocated) {
        const free = await aer.exec(
          ["cell", "free", spec.name],
          cleanupTimeoutMs,
        );
        if (free.stderr.trim() !== "") {
          onLog(`[aurae] warn: cell free: ${free.stderr.trim()}`);
        }
      }
    }
  }
}

// Map CellLimits → `aer cell allocate` flags. Names match the live aer
// CLI (`aer cell allocate --help`), which prefixes everything with
// `--cell-`. The isolate flags are bare booleans (no value).
export function buildAllocateArgs(
  cellName: string,
  limits: CellLimits,
): string[] {
  const args = ["cell", "allocate", cellName];
  if (limits.cpuWeight !== undefined) {
    args.push("--cell-cpu-weight", String(limits.cpuWeight));
  }
  if (limits.cpuMax !== undefined) args.push("--cell-cpu-max", limits.cpuMax);
  if (limits.cpuPeriod !== undefined) {
    args.push("--cell-cpu-period", limits.cpuPeriod);
  }
  if (limits.cpusetCpus !== undefined) {
    args.push("--cell-cpuset-cpus", limits.cpusetCpus);
  }
  if (limits.cpusetMems !== undefined) {
    args.push("--cell-cpuset-mems", limits.cpusetMems);
  }
  if (limits.memoryMin !== undefined) {
    args.push("--cell-memory-min", limits.memoryMin);
  }
  if (limits.memoryLow !== undefined) {
    args.push("--cell-memory-low", limits.memoryLow);
  }
  if (limits.memoryHigh !== undefined) {
    args.push("--cell-memory-high", limits.memoryHigh);
  }
  if (limits.memoryMax !== undefined) {
    args.push("--cell-memory-max", limits.memoryMax);
  }
  if (limits.isolateProcess) args.push("--cell-isolate-process");
  if (limits.isolateNetwork) args.push("--cell-isolate-network");
  return args;
}
