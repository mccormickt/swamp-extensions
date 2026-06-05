/**
 * `@mccormick/truenas/inventory` — hypervisor-layer VM discovery for swamp.
 *
 * TrueNAS SCALE 24.10+ runs guest VMs as Incus instances; earlier releases use
 * libvirt. This model asks TrueNAS for that guest state over its JSON-RPC
 * WebSocket API and turns it into a typed swamp inventory — one `vm` resource
 * per guest plus a single `summary` roll-up. It complements the Talos-layer
 * inventory `@mccormick/omni` produces and the Proxmox QEMU inventory
 * `@stateless/proxmox` produces, sharing the common `name`/`state`/`vcpus`/
 * `memoryMib`/`macs` contract so a workflow report can join all three.
 *
 * Strictly read-only: it issues only `query` and `system.info` calls and never
 * mutates TrueNAS state. The API key is supplied through a vault, marked
 * sensitive, and redacted from logs and error text.
 *
 * @module
 */
import { z } from "npm:zod@4";
import type { ModelDefinition } from "jsr:@systeminit/swamp-testing@0.20260519.14";
import { sanitizeInstanceName, SummarySchema, VmSchema } from "./schema.ts";
import { collectInventory, type TruenasOptions } from "./client.ts";
import { buildInventory, type ResolvedBackend } from "./parse.ts";

/** Global arguments for the TrueNAS inventory model. */
const GlobalArgs = z.object({
  endpoint: z.string().describe(
    "TrueNAS host or base URL, e.g. truenas.example.net or " +
      "https://truenas.example.net",
  ),
  apiKey: z.string().meta({ sensitive: true }).describe(
    "TrueNAS API key (read-only is sufficient); supply via " +
      '${{ vault.get("fleet", "TrueNAS API Key/credential") }}',
  ),
  insecureSkipTlsVerify: z.boolean().default(false).describe(
    "Skip TLS verification (limited support over WebSocket — prefer a " +
      "trusted CA; see README)",
  ),
  backend: z.enum(["auto", "incus", "libvirt"]).default("auto").describe(
    "Guest backend: 'incus' (SCALE 24.10+), 'libvirt' (legacy), or 'auto' " +
      "(resolves to incus)",
  ),
  timeoutSecs: z.number().int().positive().default(30).describe(
    "Per-discovery WebSocket timeout in seconds",
  ),
});

/** Resolve the `auto` backend default to the concrete query backend. */
function resolveBackend(backend: string): ResolvedBackend {
  return backend === "libvirt" ? "libvirt" : "incus";
}

/**
 * `@mccormick/truenas/inventory` — discovers every VM guest a TrueNAS host
 * manages and writes them as typed swamp resources. Read-only.
 */
export const model = {
  type: "@mccormick/truenas/inventory",
  version: "2026.06.07.2",
  globalArguments: GlobalArgs,
  resources: {
    vm: {
      description: "A TrueNAS-managed guest VM (Incus instance or libvirt VM)",
      schema: VmSchema,
      lifetime: "30d",
      garbageCollection: 20,
    },
    summary: {
      description: "Roll-up of one TrueNAS inventory run",
      schema: SummarySchema,
      lifetime: "30d",
      garbageCollection: 20,
    },
  },
  methods: {
    discover: {
      description:
        "Query TrueNAS for every guest VM in one call and write one vm " +
        "resource per guest plus a summary roll-up. Read-only.",
      arguments: z.object({}),
      execute: async (_args, context) => {
        const g = context.globalArgs;
        if (!g.apiKey) {
          throw new Error("apiKey is required to query TrueNAS");
        }
        const backend = resolveBackend(g.backend);
        const opts: TruenasOptions = {
          endpoint: g.endpoint,
          apiKey: g.apiKey,
          insecureSkipTlsVerify: g.insecureSkipTlsVerify,
          backend,
          timeoutMs: g.timeoutSecs * 1000,
        };

        context.logger.info(
          "truenas: discovering {backend} guests at {endpoint}",
          { backend, endpoint: g.endpoint },
        );

        const raw = await collectInventory(opts);
        const { vms, summary } = buildInventory(
          raw,
          g.endpoint,
          backend,
          new Date().toISOString(),
        );

        const handles = [];
        for (const vm of vms) {
          handles.push(
            await context.writeResource(
              "vm",
              `vm-${sanitizeInstanceName(vm.id)}`,
              vm,
            ),
          );
        }
        handles.push(
          await context.writeResource("summary", "current", summary),
        );

        context.logger.info(
          "truenas: discovered {total} guests ({running} running) on {host}",
          {
            total: summary.totalVms,
            running: summary.runningCount,
            host: summary.host,
          },
        );
        for (const note of summary.notes) {
          context.logger.warn("truenas: {note}", { note });
        }
        return { dataHandles: handles };
      },
    },
  },
} satisfies ModelDefinition<typeof GlobalArgs>;
