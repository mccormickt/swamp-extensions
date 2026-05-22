/**
 * `@mccormick/omni` — `omnictl` subprocess transport.
 *
 * The inventory model reads Omni's COSI resources through the `omnictl` CLI
 * (`omnictl get <type> -o json`). This module spawns that process with
 * service-account credentials, parses its output, and exposes a single
 * injectable seam — {@link __setOmnictlRunner} — so tests can supply canned
 * resources without a live Omni or an `omnictl` binary.
 *
 * @module
 */
import { redactSecret } from "./util.ts";

/**
 * A COSI resource as emitted by `omnictl get -o json`: every Omni resource is
 * a `{ metadata, spec }` pair. Fields are intentionally loose — callers narrow
 * what they read in `transform.ts`.
 */
export interface CosiResource {
  metadata: {
    id: string;
    namespace?: string;
    type?: string;
    labels?: Record<string, unknown>;
    [key: string]: unknown;
  };
  spec: Record<string, unknown>;
}

/** Connection options for an `omnictl` invocation. */
export interface OmnictlOptions {
  /** Omni API endpoint, e.g. `https://omni.example.net`. */
  endpoint: string;
  /** Omni service-account key (`OMNI_SERVICE_ACCOUNT_KEY`). */
  serviceAccountKey: string;
  /** Skip TLS verification for the Omni API. */
  insecureSkipTlsVerify: boolean;
  /** Path to (or name of) the `omnictl` binary. */
  omnictlPath: string;
}

/**
 * Fetches every resource of one Omni type. The default implementation spawns
 * `omnictl`; {@link __setOmnictlRunner} replaces it in tests.
 */
export type OmnictlRunner = (
  resourceType: string,
  opts: OmnictlOptions,
) => Promise<CosiResource[]>;

/** Test-installed runner; `undefined` in production. */
let testRunner: OmnictlRunner | undefined;

/**
 * Test-only: override the transport used by {@link getResources}. Pass
 * `undefined` to restore the real `omnictl` subprocess runner.
 */
export function __setOmnictlRunner(runner: OmnictlRunner | undefined): void {
  testRunner = runner;
}

/**
 * Parse `omnictl get -o json` output. `omnictl` emits one pretty-printed JSON
 * object per resource, concatenated with no array wrapper, so this scans for
 * top-level object boundaries while respecting strings and escapes. An empty
 * input (no resources) yields an empty array; a leading `[` is treated as a
 * single JSON array for forward compatibility.
 */
export function parseOmnictlJson(stdout: string): CosiResource[] {
  const text = stdout.trim();
  if (text.length === 0) return [];
  if (text.startsWith("[")) {
    const parsed = JSON.parse(text);
    return Array.isArray(parsed) ? parsed : [parsed];
  }

  const objects: CosiResource[] = [];
  let depth = 0;
  let start = -1;
  let inString = false;
  let escaped = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (inString) {
      if (escaped) escaped = false;
      else if (ch === "\\") escaped = true;
      else if (ch === '"') inString = false;
      continue;
    }
    if (ch === '"') {
      inString = true;
    } else if (ch === "{") {
      if (depth === 0) start = i;
      depth++;
    } else if (ch === "}") {
      depth--;
      if (depth === 0 && start >= 0) {
        objects.push(JSON.parse(text.slice(start, i + 1)) as CosiResource);
        start = -1;
      } else if (depth < 0) {
        throw new Error("omnictl JSON output has an unbalanced closing brace");
      }
    }
  }
  if (depth !== 0) {
    throw new Error("omnictl JSON output ended with unbalanced braces");
  }
  return objects;
}

/**
 * Default runner: `omnictl get <resourceType> -o json`. Authentication is
 * passed through the environment (`OMNI_ENDPOINT` + `OMNI_SERVICE_ACCOUNT_KEY`)
 * so `omnictl` never touches an on-disk omniconfig or opens a browser. The
 * service-account key is redacted from any error text.
 */
const defaultRunner: OmnictlRunner = async (resourceType, opts) => {
  const args = ["get", resourceType, "-o", "json"];
  if (opts.insecureSkipTlsVerify) args.push("--insecure-skip-tls-verify");

  const command = new Deno.Command(opts.omnictlPath, {
    args,
    env: {
      ...Deno.env.toObject(),
      OMNI_ENDPOINT: opts.endpoint,
      OMNI_SERVICE_ACCOUNT_KEY: opts.serviceAccountKey,
    },
    stdout: "piped",
    stderr: "piped",
  });

  let output: Deno.CommandOutput;
  try {
    output = await command.output();
  } catch (err) {
    if (err instanceof Deno.errors.NotFound) {
      throw new Error(
        `omnictl binary not found (omnictlPath="${opts.omnictlPath}"); ` +
          "install omnictl or set globalArguments.omnictlPath",
      );
    }
    throw err;
  }

  if (!output.success) {
    const stderr = redactSecret(
      new TextDecoder().decode(output.stderr).trim(),
      opts.serviceAccountKey,
    );
    throw new Error(
      `omnictl get ${resourceType} failed (exit ${output.code}): ` +
        (stderr || "no stderr output"),
    );
  }
  return parseOmnictlJson(new TextDecoder().decode(output.stdout));
};

/**
 * Fetch every resource of `resourceType` from Omni. Routes through the
 * test runner when one is installed, otherwise spawns `omnictl`.
 */
export function getResources(
  resourceType: string,
  opts: OmnictlOptions,
): Promise<CosiResource[]> {
  return (testRunner ?? defaultRunner)(resourceType, opts);
}
