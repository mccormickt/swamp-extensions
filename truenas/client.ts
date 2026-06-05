/**
 * `@mccormick/truenas` — JSON-RPC-over-WebSocket transport.
 *
 * TrueNAS SCALE serves a JSON-RPC 2.0 API over a WebSocket at
 * `wss://<host>/api/current`. This module logs in with an API key
 * (`auth.login_with_api_key`) and issues calls against it. It targets the
 * WebSocket API deliberately: it is the durable surface across 24.10 (REST-era)
 * and 25.04 ("Fangtooth", REST removed).
 *
 * Two consumers share one transport:
 *
 *   - the read-only `inventory` model collects guest state through
 *     {@link collectInventory} (a single connect → query → close);
 *   - the `vm` provisioning model opens a longer-lived multi-call write session
 *     through {@link openTruenasSession} and issues several `vm.*` /
 *     `vm.device.*` / `pool.dataset.*` calls before closing.
 *
 * A single injectable seam — {@link __setTruenasRunner} — lets the inventory
 * tests supply canned instances without a live host, mirroring `omnictl.ts` in
 * `@mccormick/omni`. The pure parsing lives in `parse.ts` and is unit-tested
 * directly; the WebSocket framing here is exercised only against a live host.
 *
 * @module
 */
import type { ResolvedBackend, TruenasRawInventory } from "./parse.ts";
import { redactSecret } from "./util.ts";

/** Connection options for a TrueNAS inventory collection. */
export interface TruenasOptions {
  /** Host name or `wss://`/`https://` base URL, e.g. `truenas.example.net`. */
  endpoint: string;
  /** TrueNAS API key (read-only is sufficient). */
  apiKey: string;
  /** Skip TLS verification — see README; bare WebSocket support is limited. */
  insecureSkipTlsVerify: boolean;
  /** Resolved guest backend selecting the query method. */
  backend: ResolvedBackend;
  /** Per-collection timeout in milliseconds. */
  timeoutMs: number;
}

/**
 * Collects raw inventory for one TrueNAS host. The default implementation opens
 * a WebSocket; {@link __setTruenasRunner} replaces it in tests.
 */
export type TruenasRunner = (
  opts: TruenasOptions,
) => Promise<TruenasRawInventory>;

/** Test-installed runner; `undefined` in production. */
let testRunner: TruenasRunner | undefined;

/**
 * Test-only: override the transport used by {@link collectInventory}. Pass
 * `undefined` to restore the real WebSocket runner.
 */
export function __setTruenasRunner(runner: TruenasRunner | undefined): void {
  testRunner = runner;
}

/** Build the `wss://<host>/api/current` URL from an operator-supplied endpoint. */
export function websocketUrl(endpoint: string): string {
  let raw = endpoint.trim();
  if (!/^[a-z]+:\/\//i.test(raw)) raw = `wss://${raw}`;
  const u = new URL(raw);
  if (u.protocol === "https:") u.protocol = "wss:";
  else if (u.protocol === "http:") u.protocol = "ws:";
  if (u.protocol !== "wss:" && u.protocol !== "ws:") {
    throw new Error(`endpoint must be ws(s)/http(s): ${endpoint}`);
  }
  if (u.pathname === "/" || u.pathname === "") u.pathname = "/api/current";
  return u.toString();
}

/** The query method name for a resolved backend. */
function queryMethod(backend: ResolvedBackend): string {
  return backend === "libvirt" ? "vm.query" : "virt.instance.query";
}

/** Filters passed to the query call to scope results to VMs. */
function queryParams(backend: ResolvedBackend): unknown[] {
  if (backend === "libvirt") return [[]];
  return [[["type", "=", "VM"]], {}];
}

/**
 * Minimal JSON-RPC 2.0 client over a single WebSocket connection. Tracks
 * pending calls by id and resolves them as responses arrive. Read-only usage.
 */
class JsonRpcSocket {
  #ws: WebSocket;
  #nextId = 1;
  #pending = new Map<
    number,
    { resolve: (v: unknown) => void; reject: (e: Error) => void }
  >();
  #closed: Error | null = null;
  readonly #apiKey: string;
  readonly ready: Promise<void>;

  constructor(url: string, apiKey: string) {
    this.#apiKey = apiKey;
    this.#ws = new WebSocket(url);
    this.ready = new Promise((resolve, reject) => {
      this.#ws.onopen = () => resolve();
      this.#ws.onerror = () =>
        reject(new Error("TrueNAS WebSocket connection failed"));
    });
    this.#ws.onmessage = (ev) => this.#onMessage(ev);
    this.#ws.onclose = () => this.#fail(new Error("WebSocket closed"));
  }

  #onMessage(ev: MessageEvent): void {
    let msg: Record<string, unknown>;
    try {
      msg = JSON.parse(typeof ev.data === "string" ? ev.data : "");
    } catch {
      return; // tolerate non-JSON / job-progress noise
    }
    const id = msg.id;
    if (typeof id !== "number") return; // notifications/progress — ignore
    const waiter = this.#pending.get(id);
    if (!waiter) return;
    this.#pending.delete(id);
    if (msg.error) {
      const detail = redactSecret(JSON.stringify(msg.error), this.#apiKey);
      waiter.reject(new Error(`TrueNAS JSON-RPC error: ${detail}`));
    } else {
      waiter.resolve(msg.result);
    }
  }

  #fail(err: Error): void {
    if (this.#closed) return;
    this.#closed = err;
    for (const waiter of this.#pending.values()) waiter.reject(err);
    this.#pending.clear();
  }

  call(method: string, params: unknown[]): Promise<unknown> {
    if (this.#closed) return Promise.reject(this.#closed);
    const id = this.#nextId++;
    const frame = JSON.stringify({ jsonrpc: "2.0", id, method, params });
    return new Promise((resolve, reject) => {
      this.#pending.set(id, { resolve, reject });
      try {
        this.#ws.send(frame);
      } catch (err) {
        this.#pending.delete(id);
        reject(err instanceof Error ? err : new Error(String(err)));
      }
    });
  }

  close(): void {
    try {
      this.#ws.close();
    } catch {
      // already closing
    }
  }
}

/** Connection inputs shared by the inventory runner and the write session. */
export interface TruenasConnectOptions {
  /** Host name or `wss://`/`https://` base URL, e.g. `truenas.example.net`. */
  endpoint: string;
  /** TrueNAS API key. */
  apiKey: string;
  /** Skip TLS verification — see README; bare WebSocket support is limited. */
  insecureSkipTlsVerify: boolean;
  /** Per-call timeout in milliseconds (applied to each `call`, not the total). */
  timeoutMs: number;
}

/**
 * An authenticated TrueNAS JSON-RPC session that survives across several calls.
 * Returned by {@link openTruenasSession}; the caller must {@link close} it
 * (typically in a `finally`). Every {@link call} is bounded by `timeoutMs` and
 * has the API key redacted from any error it throws.
 */
export interface TruenasSession {
  /** Issue one JSON-RPC call, bounded by the per-call timeout. */
  call(method: string, params: unknown[]): Promise<unknown>;
  /** Close the underlying WebSocket. Safe to call more than once. */
  close(): void;
}

/** Race a promise against a cleared timeout so no timer leaks past resolution. */
function withTimeout<T>(
  p: Promise<T>,
  timeoutMs: number,
  label: string,
): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(
      () =>
        reject(new Error(`TrueNAS ${label} timed out after ${timeoutMs}ms`)),
      timeoutMs,
    );
  });
  return Promise.race([p, timeout]).finally(() => {
    if (timer !== undefined) clearTimeout(timer);
  });
}

/**
 * Open an authenticated write session. Connects the WebSocket, logs in with the
 * API key, and returns a {@link TruenasSession} for issuing arbitrary calls.
 * Throws (key redacted) if the connection or login fails; on a login failure
 * the socket is closed before the error propagates.
 */
export async function openTruenasSession(
  opts: TruenasConnectOptions,
): Promise<TruenasSession> {
  const url = websocketUrl(opts.endpoint);
  const sock = new JsonRpcSocket(url, opts.apiKey);
  try {
    await withTimeout(sock.ready, opts.timeoutMs, "connection");
    const authed = await withTimeout(
      sock.call("auth.login_with_api_key", [opts.apiKey]),
      opts.timeoutMs,
      "login",
    );
    if (authed !== true) throw new Error("TrueNAS api-key login rejected");
  } catch (err) {
    sock.close();
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(redactSecret(msg, opts.apiKey));
  }
  return {
    async call(method, params) {
      try {
        return await withTimeout(
          sock.call(method, params),
          opts.timeoutMs,
          `call ${method}`,
        );
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        throw new Error(redactSecret(msg, opts.apiKey));
      }
    },
    close() {
      sock.close();
    },
  };
}

const defaultRunner: TruenasRunner = async (opts) => {
  const session = await openTruenasSession(opts);
  try {
    const instancesRaw = await session.call(
      queryMethod(opts.backend),
      queryParams(opts.backend),
    );
    const instances = Array.isArray(instancesRaw) ? instancesRaw : [];

    // system.info is best-effort: a failure must not abort the inventory.
    let systemInfo: Record<string, unknown> | null = null;
    try {
      const info = await session.call("system.info", []);
      if (info && typeof info === "object" && !Array.isArray(info)) {
        systemInfo = info as Record<string, unknown>;
      }
    } catch {
      systemInfo = null;
    }

    return { instances, systemInfo };
  } finally {
    session.close();
  }
};

/**
 * Collect raw VM inventory from a TrueNAS host. Routes through the test runner
 * when one is installed, otherwise opens a WebSocket.
 */
export function collectInventory(
  opts: TruenasOptions,
): Promise<TruenasRawInventory> {
  return (testRunner ?? defaultRunner)(opts);
}
