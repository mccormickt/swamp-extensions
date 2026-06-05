/**
 * `@mccormick/unifi/dns` — custom/static DNS records on a local UniFi Network
 * controller.
 *
 * A small, composable primitive: `list_records` reads every custom DNS record
 * into typed swamp resources, `upsert_record` creates or updates a single record
 * (find by key+type, PUT in place when it exists, else POST), and
 * `delete_record` removes one (idempotent — succeeds if already absent). This
 * turns a cutover DNS flip — e.g. repointing `omni.example.net` at a new host —
 * into a reusable model method instead of a one-off curl. The mutating methods
 * are gated by a `live` pre-flight check that confirms the controller is
 * reachable and the key is accepted before any write.
 *
 * Targets the local controller's internal v2 API
 * (`/proxy/network/v2/api/site/<site>/static-dns`) with an `X-API-KEY` header.
 * The cloud Site Manager API cannot edit DNS — use a key issued on the local
 * UniFi OS console (Settings → Control Plane → Integrations). The api key is
 * supplied through a vault, marked sensitive, and redacted from logs and errors.
 *
 * @module
 */
import { z } from "npm:zod@4";
import type { ModelDefinition } from "jsr:@systeminit/swamp-testing@0.20260519.14";
import { DnsRecordSchema, sanitizeInstanceName } from "./schema.ts";
import {
  staticDnsPath,
  type UnifiOptions,
  unifiRequest,
  unifiRequestOk,
} from "./client.ts";
import {
  findExisting,
  normalizeRecord,
  normalizeRecords,
  rawList,
} from "./parse.ts";
import { redactSecret } from "./util.ts";

/** Global arguments for the UniFi DNS model. */
const GlobalArgs = z.object({
  controllerUrl: z.string().describe(
    "Local UniFi OS controller base URL, e.g. https://192.0.2.1",
  ),
  apiKey: z.string().describe(
    "Local controller API key (X-API-KEY); supply via " +
      '${{ vault.get("fleet", "UniFi - Local Controller Key/credential") }}',
  ).meta({ sensitive: true }),
  site: z.string().default("default").describe(
    "UniFi Network site name (usually 'default')",
  ),
  caCert: z.string().optional().describe(
    "PEM CA certificate to trust the controller's self-signed cert",
  ),
  insecureSkipTlsVerify: z.boolean().default(false).describe(
    "Best-effort skip of TLS verification (limited; prefer caCert)",
  ),
});

/** Arguments for {@link model.methods.upsert_record}. */
const UpsertArgs = z.object({
  key: z.string().describe("Record name/host, e.g. omni.example.net"),
  recordType: z.string().default("A").describe(
    "DNS record type, e.g. A, AAAA, CNAME, TXT",
  ),
  value: z.string().describe("Record value, e.g. the target IP"),
  enabled: z.boolean().default(true).describe(
    "Whether the controller should serve the record",
  ),
});

/** Arguments for {@link model.methods.delete_record}. */
const DeleteArgs = z.object({
  key: z.string().describe("Record name/host to delete, e.g. omni.example.net"),
  recordType: z.string().default("A").describe(
    "DNS record type, e.g. A, AAAA, CNAME, TXT",
  ),
});

/** Build {@link UnifiOptions} from validated global arguments. */
function optionsFrom(g: z.infer<typeof GlobalArgs>): UnifiOptions {
  return {
    controllerUrl: g.controllerUrl,
    apiKey: g.apiKey,
    site: g.site,
    caCert: g.caCert,
    insecureSkipTlsVerify: g.insecureSkipTlsVerify,
  };
}

/** A stable instance name for a record, discriminated by type and key. */
function recordInstanceName(recordType: string, key: string): string {
  return `dns-${sanitizeInstanceName(`${recordType}-${key}`)}`;
}

/**
 * `@mccormick/unifi/dns` — read and upsert custom DNS records on a local UniFi
 * Network controller.
 */
export const model = {
  type: "@mccormick/unifi/dns",
  version: "2026.06.04.2",
  globalArguments: GlobalArgs,
  resources: {
    dns_record: {
      description: "A custom/static DNS record on the UniFi controller",
      schema: DnsRecordSchema,
      lifetime: "infinite",
      garbageCollection: 10,
    },
  },
  methods: {
    list_records: {
      description:
        "Read every custom/static DNS record from the controller and write " +
        "one dns_record resource per record. Read-only.",
      arguments: z.object({}),
      execute: async (_args, context) => {
        const g = context.globalArgs;
        if (!g.apiKey) throw new Error("apiKey is required to query UniFi");
        const opts = optionsFrom(g);
        const now = new Date().toISOString();

        const json = await unifiRequestOk(opts, {
          method: "GET",
          path: staticDnsPath(g.site),
        });
        const records = normalizeRecords(json, now);

        const handles = [];
        for (const rec of records) {
          handles.push(
            await context.writeResource(
              "dns_record",
              recordInstanceName(rec.recordType, rec.key),
              rec,
            ),
          );
        }
        context.logger.info("unifi: read {count} custom DNS records", {
          count: records.length,
        });
        return { dataHandles: handles };
      },
    },
    upsert_record: {
      description:
        "Create or update a single custom DNS record: find it by key+type, " +
        "update in place when it exists, otherwise create it. Writes the " +
        "resulting dns_record.",
      arguments: UpsertArgs,
      execute: async (rawArgs, context) => {
        const args = UpsertArgs.parse(rawArgs);
        const g = context.globalArgs;
        if (!g.apiKey) throw new Error("apiKey is required to update UniFi");
        const opts = optionsFrom(g);
        const now = new Date().toISOString();
        const recordType = args.recordType.toUpperCase();
        const dnsPath = staticDnsPath(g.site);

        // Verify-before-write: read current records and look for a match.
        const listJson = await unifiRequestOk(opts, {
          method: "GET",
          path: dnsPath,
        });
        const existing = findExisting(
          normalizeRecords(listJson, now),
          args.key,
          recordType,
        );

        let resultJson: unknown;
        if (existing?.id) {
          const rawRec = rawList(listJson).find(
            (r) => String(r._id) === existing.id,
          ) ?? {};
          context.logger.info(
            "unifi: updating {type} {key} -> {value} (id {id})",
            {
              type: recordType,
              key: args.key,
              value: args.value,
              id: existing.id,
            },
          );
          resultJson = await unifiRequestOk(opts, {
            method: "PUT",
            path: `${dnsPath}/${existing.id}`,
            body: {
              ...rawRec,
              key: args.key,
              record_type: recordType,
              value: args.value,
              enabled: args.enabled,
            },
          });
        } else {
          context.logger.info("unifi: creating {type} {key} -> {value}", {
            type: recordType,
            key: args.key,
            value: args.value,
          });
          resultJson = await unifiRequestOk(opts, {
            method: "POST",
            path: dnsPath,
            body: {
              key: args.key,
              record_type: recordType,
              value: args.value,
              enabled: args.enabled,
            },
          });
        }

        // The controller echoes the record as an object or `{ data: [...] }`.
        const normalized = normalizeRecords(resultJson, now);
        const rec = normalized[0] ?? normalizeRecord(resultJson, now);
        const handle = await context.writeResource(
          "dns_record",
          recordInstanceName(rec.recordType, rec.key),
          rec,
        );
        return { dataHandles: [handle] };
      },
    },
    delete_record: {
      description:
        "Delete a single custom DNS record by key+type. Idempotent: succeeds " +
        "if the record is already absent. Writes a tombstone dns_record " +
        "(id null, enabled false) recording the removal.",
      arguments: DeleteArgs,
      execute: async (rawArgs, context) => {
        const args = DeleteArgs.parse(rawArgs);
        const g = context.globalArgs;
        if (!g.apiKey) throw new Error("apiKey is required to update UniFi");
        const opts = optionsFrom(g);
        const now = new Date().toISOString();
        const recordType = args.recordType.toUpperCase();
        const dnsPath = staticDnsPath(g.site);

        // Verify-before-write: read current records and look for a match.
        const listJson = await unifiRequestOk(opts, {
          method: "GET",
          path: dnsPath,
        });
        const existing = findExisting(
          normalizeRecords(listJson, now),
          args.key,
          recordType,
        );

        if (!existing?.id) {
          context.logger.info(
            "unifi: {type} {key} already absent — nothing to delete " +
              "(idempotent)",
            { type: recordType, key: args.key },
          );
        } else {
          context.logger.info("unifi: deleting {type} {key} (id {id})", {
            type: recordType,
            key: args.key,
            id: existing.id,
          });
          await unifiRequestOk(opts, {
            method: "DELETE",
            path: `${dnsPath}/${existing.id}`,
          });
        }

        // Tombstone the record's removed state for an audit trail.
        const tombstone = {
          id: null,
          recordType,
          key: args.key,
          value: existing?.value ?? "",
          enabled: false,
          observedAt: now,
        };
        const handle = await context.writeResource(
          "dns_record",
          recordInstanceName(recordType, args.key),
          tombstone,
        );
        return { dataHandles: [handle] };
      },
    },
  },
  checks: {
    "controller-reachable": {
      description:
        "Confirm the UniFi controller is reachable and the API key is " +
        "accepted before mutating DNS.",
      labels: ["live"],
      appliesTo: ["upsert_record", "delete_record"],
      execute: async (context) => {
        const g = GlobalArgs.parse(context.globalArgs);
        try {
          const resp = await unifiRequest(optionsFrom(g), {
            method: "GET",
            path: staticDnsPath(g.site),
          });
          if (resp.status < 200 || resp.status >= 300) {
            return {
              pass: false,
              errors: [
                `UniFi static-dns GET returned HTTP ${resp.status} — check ` +
                "controllerUrl, the local-controller apiKey, and site.",
              ],
            };
          }
          return { pass: true };
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err);
          return { pass: false, errors: [redactSecret(msg, g.apiKey)] };
        }
      },
    },
  },
} satisfies ModelDefinition<typeof GlobalArgs>;
