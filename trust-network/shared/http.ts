/**
 * `@mccormick/trust-network` — HTTP helper for the provider models.
 *
 * Bearer-authenticated JSON requests with a per-attempt timeout, retry/backoff
 * on 429 and 5xx (honoring `Retry-After` and GitHub rate-limit headers),
 * pagination for the GitHub and GCP providers' conventions, and secret
 * redaction in error output.
 *
 * @module
 */

const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_MAX_RETRIES = 4;
const RETRY_BASE_MS = 1_000;
const RETRY_MAX_DELAY_MS = 20_000;
/** Beyond this, a rate-limit reset is too far away to wait out in a scan. */
const MAX_RATE_LIMIT_WAIT_MS = 90_000;
/** Hard cap on pages followed, to bound a runaway pagination loop. */
const MAX_PAGES = 200;

/** Token-shaped substrings masked from any text that may reach logs/errors. */
const SECRET_PATTERNS: readonly RegExp[] = [
  /gh[oprsu]_[A-Za-z0-9]{20,}/g, // GitHub PAT / OAuth / app / refresh tokens
  /github_pat_[A-Za-z0-9_]{20,}/g, // GitHub fine-grained PAT
  /ya29\.[A-Za-z0-9._\-]{10,}/g, // Google OAuth2 access token
  /\b[Bb]earer\s+[A-Za-z0-9._\-]{10,}/g, // any bearer token in text
];

/**
 * Mask credential-shaped substrings. Applied to every response snippet and
 * network-error string before it is placed in a thrown error.
 */
export function redactSecrets(text: string): string {
  let out = text;
  for (const pattern of SECRET_PATTERNS) {
    out = out.replace(pattern, "[REDACTED]");
  }
  return out.replace(
    /"(access_token|client_secret|token|private_key|key)"\s*:\s*"[^"]*"/g,
    '"$1":"[REDACTED]"',
  );
}

/** Origin + path of a URL, query string dropped — safe for log/error output. */
function stripUrl(raw: string): string {
  try {
    const u = new URL(raw);
    return `${u.origin}${u.pathname}`;
  } catch {
    return raw.split("?")[0];
  }
}

/**
 * Validate an operator-supplied API base URL. Requires `https:` — a minimal
 * SSRF guard against a base URL pointing at an internal `http://` service.
 */
export function assertHttpsUrl(raw: string, label: string): string {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new Error(`${label} is not a valid URL: ${raw}`);
  }
  if (u.protocol !== "https:") {
    throw new Error(`${label} must use https (got ${u.protocol}): ${raw}`);
  }
  return raw.replace(/\/+$/, "");
}

/** Error thrown for a non-2xx response once retries are exhausted. */
export class HttpError extends Error {
  constructor(
    readonly status: number,
    readonly url: string,
    readonly bodySnippet: string,
  ) {
    super(`HTTP ${status} for ${stripUrl(url)} — ${bodySnippet}`);
    this.name = "HttpError";
  }
}

/** Options for {@link fetchJson} and the pagination helpers. */
export interface FetchJsonOptions {
  /** HTTP method (default `GET`). */
  method?: string;
  /** Request headers — typically from {@link githubHeaders} / {@link bearerHeaders}. */
  headers?: Record<string, string>;
  /** Request body; JSON-encoded when present. */
  body?: unknown;
  /** Per-attempt timeout in ms (default 30000). */
  timeoutMs?: number;
  /** Max retry attempts for 429/5xx/network failures (default 4). */
  maxRetries?: number;
  /** Notified on each retry with a redaction-safe message. */
  onRetry?: (message: string) => void;
}

/** Authorization headers for the GitHub REST API. */
export function githubHeaders(token: string): Record<string, string> {
  return {
    "Authorization": `Bearer ${token}`,
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": "swamp-trust-network",
  };
}

/** Generic bearer + JSON headers for the GCP and Cloudflare APIs. */
export function bearerHeaders(
  token: string,
  extra?: Record<string, string>,
): Record<string, string> {
  return {
    "Authorization": `Bearer ${token}`,
    "Accept": "application/json",
    ...extra,
  };
}

/** Promise-based sleep. */
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** Exponential backoff with jitter for retry attempt `n` (n >= 1). */
function retryDelay(attempt: number): number {
  const base = Math.min(RETRY_MAX_DELAY_MS, RETRY_BASE_MS * 2 ** (attempt - 1));
  return base + Math.floor(Math.random() * 250);
}

/** Wait implied by `Retry-After` / GitHub rate-limit headers, in ms, or null. */
function rateLimitWait(headers: Headers): number | null {
  const retryAfter = headers.get("retry-after");
  if (retryAfter) {
    const secs = Number(retryAfter);
    if (Number.isFinite(secs)) return Math.max(0, secs * 1000);
    const when = Date.parse(retryAfter);
    if (Number.isFinite(when)) return Math.max(0, when - Date.now());
  }
  if (headers.get("x-ratelimit-remaining") === "0") {
    const reset = Number(headers.get("x-ratelimit-reset"));
    if (Number.isFinite(reset)) return Math.max(0, reset * 1000 - Date.now());
  }
  return null;
}

interface RawResponse {
  status: number;
  headers: Headers;
  body: string;
}

/** Core request with timeout + retry. Returns the 2xx response, or throws. */
async function requestRaw(
  url: string,
  opts: FetchJsonOptions,
): Promise<RawResponse> {
  const maxRetries = opts.maxRetries ?? DEFAULT_MAX_RETRIES;
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    let res: Response;
    try {
      res = await fetch(url, {
        method: opts.method ?? "GET",
        headers: opts.headers,
        body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch (err) {
      // Network failure or timeout — transient, retry with backoff.
      if (attempt < maxRetries) {
        const delay = retryDelay(attempt + 1);
        opts.onRetry?.(
          `network error for ${stripUrl(url)}; retry ${
            attempt + 1
          }/${maxRetries} in ${delay}ms`,
        );
        await sleep(delay);
        continue;
      }
      throw new Error(
        `request to ${stripUrl(url)} failed: ${redactSecrets(String(err))}`,
      );
    }

    if (res.ok) {
      return {
        status: res.status,
        headers: res.headers,
        body: await res.text(),
      };
    }

    const snippet = redactSecrets(
      (await res.text().catch(() => "")).slice(0, 300),
    );
    const retryable = res.status === 429 || res.status >= 500 ||
      (res.status === 403 && res.headers.get("x-ratelimit-remaining") === "0");

    if (retryable && attempt < maxRetries) {
      const rlWait = rateLimitWait(res.headers);
      if (rlWait !== null && rlWait > MAX_RATE_LIMIT_WAIT_MS) {
        throw new HttpError(
          res.status,
          url,
          `rate limited; resets in ~${
            Math.round(rlWait / 1000)
          }s — retry the scan later`,
        );
      }
      const wait = rlWait ?? retryDelay(attempt + 1);
      opts.onRetry?.(
        `HTTP ${res.status} for ${stripUrl(url)}; retry ${
          attempt + 1
        }/${maxRetries} in ${Math.round(wait / 1000)}s`,
      );
      await sleep(wait);
      continue;
    }
    throw new HttpError(res.status, url, snippet);
  }
  // Unreachable: the loop either returns or throws.
  throw new HttpError(0, url, "request exhausted retries");
}

/** Fetch and parse a JSON response. Throws {@link HttpError} on failure. */
export async function fetchJson<T = unknown>(
  url: string,
  opts: FetchJsonOptions = {},
): Promise<T> {
  const raw = await requestRaw(url, opts);
  if (!raw.body) return undefined as T;
  try {
    return JSON.parse(raw.body) as T;
  } catch {
    throw new HttpError(raw.status, url, "response body was not valid JSON");
  }
}

/** Extract the `rel="next"` target from an RFC 5988 `Link` header. */
function parseNextLink(linkHeader: string | null): string | null {
  if (!linkHeader) return null;
  for (const part of linkHeader.split(",")) {
    const m = part.match(/<([^>]+)>;\s*rel="next"/);
    if (m) return m[1];
  }
  return null;
}

/**
 * Follow GitHub `Link`-header pagination, flattening every page into one array.
 * `itemsKey` extracts the array from an envelope (e.g. `secrets`); omit it for
 * endpoints that return a bare array.
 */
export async function fetchGithubPaginated<T = unknown>(
  url: string,
  opts: FetchJsonOptions = {},
  itemsKey?: string,
): Promise<T[]> {
  const out: T[] = [];
  let next: string | null = url;
  for (let page = 0; next && page < MAX_PAGES; page++) {
    const raw: RawResponse = await requestRaw(next, opts);
    const body = raw.body ? JSON.parse(raw.body) : (itemsKey ? {} : []);
    const items = itemsKey ? body?.[itemsKey] : body;
    if (Array.isArray(items)) out.push(...(items as T[]));
    next = parseNextLink(raw.headers.get("link"));
  }
  return out;
}

/**
 * Follow GCP `nextPageToken` pagination. `listKey` is the response field
 * holding the page array (e.g. `workloadIdentityPools`, `accounts`).
 */
export async function fetchGcpPaginated<T = unknown>(
  url: string,
  listKey: string,
  opts: FetchJsonOptions = {},
): Promise<T[]> {
  const out: T[] = [];
  let pageToken: string | undefined;
  for (let page = 0; page < MAX_PAGES; page++) {
    const u = new URL(url);
    if (pageToken) u.searchParams.set("pageToken", pageToken);
    const body = await fetchJson<Record<string, unknown>>(u.toString(), opts);
    const items = body?.[listKey];
    if (Array.isArray(items)) out.push(...(items as T[]));
    pageToken = typeof body?.nextPageToken === "string"
      ? body.nextPageToken
      : undefined;
    if (!pageToken) break;
  }
  return out;
}
