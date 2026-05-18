# @mccormick/aurae

A [swamp](https://github.com/systeminit/swamp) execution driver that runs a
method's `run` command inside an [aurae](https://github.com/aurae-runtime/aurae)
cell via the `aer` CLI. The driver allocates the cell, starts the executable,
streams stdout/stderr back through `aer observe`, and tears the cell down — all
behind swamp's standard `ExecutionDriver` interface, so any `command/shell`-style
model can be retargeted to aurae just by selecting this driver.

The orchestrator (`mod.ts`) is target-polymorphic: `target.ts` defines
`ExecutionTarget` and ships a `CellTarget`. A sibling `VmTarget` for micro-VMs
slots in without changes to the driver itself.

## Prerequisites

- A running `auraed` daemon, locally or reachable over its socket.
- The `aer` binary on `PATH` (override with `aerBinary`).
- A populated aurae config dir — typically `~/.aurae/config` with cert + socket.
  For a remote auraed, point `configHome` at a per-host config directory; the
  driver runs `aer` with `HOME=configHome` so `~/.aurae/config` resolves
  correctly.
- A method that supplies `methodArgs.run` (the shell command to execute inside
  the cell).

Runtime: Deno (the swamp extension host).

## Wire it into a definition

Select the driver per-method, per-job, per-workflow, or as the definition
default. Minimal example, attaching it to the built-in `command/shell` model:

```yaml
type: command/shell
name: hello-from-cell
spec:
  run: "echo hello && hostname"
driver:
  type: '@mccormick/aurae'
  config:
    cellNamePrefix: hello
    timeoutSecs: 60
    cell:
      isolateProcess: true
      isolateNetwork: true
      memoryHigh: 256M
```

Then run it:

```sh
swamp model method run command/shell run hello-from-cell
```

## Configuration

All keys are optional; defaults shown.

| Key               | Default        | Notes                                                                                                                            |
| ----------------- | -------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| `aerBinary`       | `aer`          | Path to the `aer` executable.                                                                                                    |
| `configHome`      | _(unset)_      | Sets `HOME=<configHome>` for `aer` so it picks up a per-host `~/.aurae/config`. Omit for local default.                          |
| `target`          | `cell`         | Currently only `cell` is implemented; the field is the seam for a future `vm` target.                                            |
| `cellNamePrefix`  | `swamp`        | Cell name = `<prefix>-<methodName>-<8 hex>`.                                                                                     |
| `timeoutSecs`     | `300`          | Wall-clock cap for the whole run. On timeout the cell is killed and cleanup still runs.                                          |
| `failureMarker`   | _(unset)_      | Regex (string). If any stderr line matches, `success=false` even when the process exited normally — see "Known limitations".    |
| `outputSpecName`  | `result`       | The model resource spec to attribute captured stdout to.                                                                         |
| `cell.cpuWeight`  | _(unset)_      | Passed to `aer cell allocate --cell-cpu-weight`.                                                                                 |
| `cell.cpuMax`     | _(unset)_      | `--cell-cpu-max`.                                                                                                                |
| `cell.cpuPeriod`  | _(unset)_      | `--cell-cpu-period`.                                                                                                             |
| `cell.cpusetCpus` | _(unset)_      | `--cell-cpuset-cpus`.                                                                                                            |
| `cell.cpusetMems` | _(unset)_      | `--cell-cpuset-mems`.                                                                                                            |
| `cell.memoryMin` / `Low` / `High` / `Max` | _(unset)_ | `--cell-memory-{min,low,high,max}`.                                                                                  |
| `cell.isolateProcess` | `false`    | `--cell-isolate-process` (PID namespace).                                                                                        |
| `cell.isolateNetwork` | `false`    | `--cell-isolate-network` (network namespace).                                                                                    |

## How it works

The cell lifecycle on each run:

1. **Allocate** — `aer cell allocate <name>` plus the configured limits and
   namespace flags. Idempotent within a run; the cell name embeds a UUID slice.
2. **Start** — `aer cell start <name> <executable> -c "<run>"` (plus optional
   `--uid`/`--gid` if the method supplies them). The driver parses the response
   PID from `aer`'s Rust-debug stdout.
3. **Observe** — two concurrent `aer observe get-sub-process-stream` calls,
   one per channel (stdout, stderr), routed via `--cell-name` to the cell's
   nested daemon. Lines flow back through `callbacks.onLog`. If
   `failureMarker` is set, each stderr line is tested against it.
4. **Stop + free** — best-effort, in `finally`, each capped by
   `cleanupTimeoutMs` (5s) so a stuck auraed can't wedge the driver.

The wall-clock timeout (`timeoutSecs`) is enforced by an `AbortController`
in the driver; on timeout the observe subprocesses are killed and the
underlying run's `finally` block performs cleanup before the driver returns.

## Known limitations

- **No exit code.** `aer` always exits 0 and prints every gRPC response with
  Rust's pretty-debug formatter. A non-empty stderr from `aer` itself is
  treated as failure; for the executable inside the cell, the only failure
  signal is `failureMarker` (set this if your tooling prints a recognisable
  failure line).
- **Best-effort cleanup.** If `aer cell stop` or `aer cell free` times out,
  the driver logs and continues — it never re-throws. Use `aer cell list`
  out-of-band to spot orphans.
- **Single target.** Only `target: cell` is wired today. `VmTarget` is a
  planned sibling; the driver orchestrator and `aer.ts` are already polymorphic.

## License

MIT — see [LICENSE.md](./LICENSE.md).
