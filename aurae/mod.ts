// Swamp execution driver for the aurae runtime daemon (auraed).
//
// Allocates an aurae cell, runs `methodArgs.run` inside it via `aer`,
// streams stdout/stderr back through the driver callbacks, and tears the
// cell down. The orchestration lives here; subprocess-level concerns
// (parsing aer's Rust-debug output, HOME-overridden config lookup) are in
// ./aer.ts, and the isolation surface itself is in ./target.ts so a
// sibling VmTarget can slot in without changes here.

import { z } from "npm:zod@4";
import { AerClient } from "./aer.ts";
import { CellTarget, ExecutionTarget, RunResult } from "./target.ts";

const ConfigSchema = z.object({
  // Directory containing the aurae `config` file. Set this per-host to
  // target a remote auraed; the driver invokes `aer` with HOME=configHome
  // so `~/.aurae/config` resolves to the right cert+socket. Default
  // (undefined) lets `aer` use the caller's HOME, matching local use.
  configHome: z.string().optional(),
  aerBinary: z.string().default("aer"),
  target: z.enum(["cell"]).default("cell"),
  cellNamePrefix: z.string().default("swamp"),
  timeoutSecs: z.number().positive().default(300),
  cell: z.object({
    cpuWeight: z.number().int().positive().optional(),
    cpuMax: z.string().optional(),
    cpuPeriod: z.string().optional(),
    cpusetCpus: z.string().optional(),
    cpusetMems: z.string().optional(),
    memoryMin: z.string().optional(),
    memoryLow: z.string().optional(),
    memoryHigh: z.string().optional(),
    memoryMax: z.string().optional(),
    isolateProcess: z.boolean().default(false),
    isolateNetwork: z.boolean().default(false),
  }).default({}),
  // Regex (string). If any stderr line matches, RunResult.success becomes
  // false even when the process exited normally. Compensates for aurae
  // not surfacing an exit code.
  failureMarker: z.string().optional(),
  // Resource spec to attribute the captured stdout to. Should match a
  // dataOutputSpecs entry on the model being driven. Defaults to "result"
  // because most shell-style models (e.g. command/shell) use that name.
  outputSpecName: z.string().default("result"),
});

type ExecutionRequest = {
  protocolVersion: number;
  modelType: string;
  modelId: string;
  methodName: string;
  globalArgs: Record<string, unknown>;
  methodArgs: Record<string, unknown>;
  definitionMeta: {
    id: string;
    name: string;
    version: number;
    tags: Record<string, string>;
  };
  resourceSpecs?: Record<string, unknown>;
  fileSpecs?: Record<string, unknown>;
  bundle?: Uint8Array;
};

type ExecutionCallbacks = {
  onLog?: (line: string) => void;
};

/**
 * Swamp `ExecutionDriver` that runs a method's `run` command inside an
 * aurae cell via the `aer` CLI.
 *
 * Lifecycle per method invocation: allocate a cell → start the executable →
 * stream stdout/stderr through `aer observe` → stop + free the cell. A
 * wall-clock timeout (`config.timeoutSecs`) aborts the run and still allows
 * cleanup to complete. The orchestrator delegates the isolation primitive
 * to an `ExecutionTarget` (currently `CellTarget`) so a VM target can be
 * added without changing this driver.
 *
 * @see ConfigSchema for the configuration accepted via `.swamp.yaml`.
 */
export const driver = {
  type: "@mccormick/aurae",
  name: "Aurae Cell Driver",
  description:
    "Executes the method's `run` command inside an aurae cell via aer; " +
    "extensible to micro-VMs.",
  configSchema: ConfigSchema,

  createDriver: (raw: Record<string, unknown>) => {
    const cfg = ConfigSchema.parse(raw);
    const aer = new AerClient({
      binary: cfg.aerBinary,
      configHome: cfg.configHome,
    });
    const target: ExecutionTarget = new CellTarget(cfg.cell);
    const failureMarker = cfg.failureMarker
      ? new RegExp(cfg.failureMarker)
      : undefined;

    return {
      type: "@mccormick/aurae",

      execute: async (
        request: ExecutionRequest,
        callbacks?: ExecutionCallbacks,
      ) => {
        const start = performance.now();
        const logs: string[] = [];
        const log = (line: string) => {
          logs.push(line);
          callbacks?.onLog?.(line);
        };

        const run = request.methodArgs.run as string | undefined;
        if (typeof run !== "string" || run.length === 0) {
          return errorResult(
            "driver requires methodArgs.run (a non-empty string)",
            start,
            logs,
          );
        }

        const spec = {
          name: `${cfg.cellNamePrefix}-${request.methodName}-${
            crypto.randomUUID().slice(0, 8)
          }`,
          command: run,
          executableName: (request.methodArgs.executableName as
            | string
            | undefined) ?? `swamp-${request.methodName}`,
          uid: request.methodArgs.uid as number | undefined,
          gid: request.methodArgs.gid as number | undefined,
        };

        const controller = new AbortController();
        try {
          const result = await withTimeout(
            target.run(aer, spec, log, {
              failureMarker,
              signal: controller.signal,
            }),
            cfg.timeoutSecs * 1000,
            spec.name,
            controller,
          );

          if (!result.success) {
            return {
              status: "error" as const,
              error: result.reason ?? "execution failed",
              outputs: [],
              logs,
              durationMs: performance.now() - start,
            };
          }

          return {
            status: "success" as const,
            outputs: [{
              kind: "pending" as const,
              specName: cfg.outputSpecName,
              name: request.methodName,
              type: "resource" as const,
              content: new TextEncoder().encode(result.stdout.join("\n")),
              metadata: {
                pid: result.pid,
                stderrLines: result.stderr.length,
                cellName: spec.name,
                target: target.kind,
              },
            }],
            logs,
            durationMs: performance.now() - start,
          };
        } catch (e) {
          return errorResult(String(e), start, logs);
        }
      },
    };
  },
};

function errorResult(error: string, start: number, logs: string[]): {
  status: "error";
  error: string;
  outputs: never[];
  logs: string[];
  durationMs: number;
} {
  return {
    status: "error" as const,
    error,
    outputs: [],
    logs,
    durationMs: performance.now() - start,
  };
}

// Race the run promise against a wall-clock deadline. On timeout, fires
// the AbortController so the target's observe subprocesses get killed and
// its finally block (cell stop + free, also time-bounded) can run, then
// awaits the original promise so we don't return until cleanup is done.
async function withTimeout(
  p: Promise<RunResult>,
  ms: number,
  cellName: string,
  controller: AbortController,
): Promise<RunResult> {
  let timer: number | undefined;
  let didTimeout = false;
  const timeout = new Promise<RunResult>((resolve) => {
    // @ts-ignore - Deno's setTimeout returns number
    timer = setTimeout(() => {
      didTimeout = true;
      controller.abort();
      resolve({
        pid: 0,
        stdout: [],
        stderr: [],
        success: false,
        reason: `timed out after ${ms}ms (cell ${cellName})`,
      });
    }, ms);
  });
  try {
    const winner = await Promise.race([p, timeout]);
    if (!didTimeout) return winner;
    // Drain the underlying run so cleanup completes before we return.
    // Prefer its richer RunResult (real pid + captured stdout/stderr,
    // possibly a failureMarker-derived reason) over the synthetic
    // timeout result.
    const real = await p.catch(() => null);
    return real ?? winner;
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}
