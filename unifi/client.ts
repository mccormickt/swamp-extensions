/**
 * `@mccormick/unifi` — local Network controller HTTP transport.
 *
 * Talks to a local UniFi OS console's internal Network API
 * (`https://<gateway>/proxy/network/v2/api/site/<site>/...`) with an
 * `X-API-KEY` header. Static-DNS records live on this v2 surface — NOT the
 * cloud Site Manager API (`api.ui.com`), which cannot edit DNS. The controller
 * ships a self-signed certificate, so a CA cert is supplied via `caCert` to
 * trust it.
 *
 * A single injectable seam — {@link __setUnifiTransport} — lets the model's
 * list/upsert logic be unit-tested without a live controller.
 *
 * @module
 */
import { assertHttpsUrl, redactSecret } from "./util.ts";

/** Connection options for a UniFi local-controller request. */
export interface UnifiOptions {
  /** Controller base URL, e.g. `https://192.0.2.1`. */
  controllerUrl: string;
  /** Local controller API key (`X-API-KEY`). */
  apiKey: string;
  /** Network site name, usually `default`. */
  site: string;
  /** PEM CA certificate to trust the controller's self-signed cert. */
  caCert?: string;
  /** Best-effort skip of TLS verification (limited; prefer `caCert`). */
  insecureSkipTlsVerify: boolean;
}

/** A single controller request. */
export interface UnifiRequest {
  method: string;
  /** Absolute path beginning with `/proxy/network/...`. */
  path: string;
  body?: unknown;
}

/** A controller response. */
export interface UnifiResponse {
  status: number;
  json: unknown;
}

/** Transport function; the default uses `fetch`. */
export type UnifiTransport = (
  opts: UnifiOptions,
  req: UnifiRequest,
) => Promise<UnifiResponse>;

let testTransport: UnifiTransport | undefined;

/**
 * Test-only: override the transport used by {@link unifiRequest}. Pass
 * `undefined` to restore the real `fetch` transport.
 */
export function __setUnifiTransport(t: UnifiTransport | undefined): void {
  testTransport = t;
}

/** The v2 static-DNS base path for a site. */
export function staticDnsPath(site: string): string {
  return `/proxy/network/v2/api/site/${encodeURIComponent(site)}/static-dns`;
}

const defaultTransport: UnifiTransport = async (opts, req) => {
  const base = assertHttpsUrl(opts.controllerUrl, "controllerUrl");
  const url = `${base}${req.path}`;
  const headers: Record<string, string> = {
    "X-API-KEY": opts.apiKey,
    "Accept": "application/json",
  };
  const init: RequestInit & { client?: Deno.HttpClient } = {
    method: req.method,
    headers,
  };
  if (req.body !== undefined) {
    headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(req.body);
  }

  let client: Deno.HttpClient | undefined;
  if (opts.caCert) {
    client = Deno.createHttpClient({ caCerts: [opts.caCert] });
    init.client = client;
  }

  try {
    const resp = await fetch(url, init);
    const text = await resp.text();
    let json: unknown = null;
    if (text) {
      try {
        json = JSON.parse(text);
      } catch {
        json = text;
      }
    }
    return { status: resp.status, json };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(redactSecret(msg, opts.apiKey));
  } finally {
    client?.close();
  }
};

/** Issue one request to the controller via the active transport. */
export function unifiRequest(
  opts: UnifiOptions,
  req: UnifiRequest,
): Promise<UnifiResponse> {
  return (testTransport ?? defaultTransport)(opts, req);
}

/**
 * Issue a request and throw on a non-2xx status, redacting the api key from any
 * error text and surfacing the controller's response body when present.
 */
export async function unifiRequestOk(
  opts: UnifiOptions,
  req: UnifiRequest,
): Promise<unknown> {
  const resp = await unifiRequest(opts, req);
  if (resp.status < 200 || resp.status >= 300) {
    const body = redactSecret(JSON.stringify(resp.json), opts.apiKey);
    throw new Error(
      `UniFi ${req.method} ${req.path} failed (HTTP ${resp.status}): ${body}`,
    );
  }
  return resp.json;
}
