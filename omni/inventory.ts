/**
 * `@mccormick/omni/inventory` — Talos node discovery for swamp.
 *
 * Omni (https://omni.siderolabs.com) is the control plane for fleets of Talos
 * Linux machines: it registers every machine, assigns machines to clusters, and
 * tracks their health. This model asks Omni for that fleet state and turns it
 * into a typed swamp inventory — one `node` resource per machine, one `cluster`
 * resource per cluster, and a single `summary` roll-up.
 *
 * Transport is the `omnictl` CLI (`omnictl get <type> -o json`) authenticated
 * with an Omni service account passed through the environment. The model is
 * strictly read-only: it issues `get` calls and never mutates Omni state. The
 * service-account key is supplied through a vault, marked sensitive, and
 * redacted from logs and error text.
 *
 * @module
 */
import { z } from "npm:zod@4";
import type { ModelDefinition } from "jsr:@systeminit/swamp-testing@0.20260519.14";
import {
  ClusterSchema,
  NodeSchema,
  sanitizeInstanceName,
  SummarySchema,
} from "./schema.ts";
import { getResources, type OmnictlOptions } from "./omnictl.ts";
import { mergeInventory } from "./transform.ts";
import { assertHttpsUrl } from "./util.ts";

/** Global arguments for the Omni inventory model. */
const GlobalArgs = z.object({
  endpoint: z.string().describe(
    "Omni API endpoint, e.g. https://omni.example.net",
  ),
  serviceAccountKey: z.string().describe(
    "Omni service-account key (OMNI_SERVICE_ACCOUNT_KEY); supply via " +
      '${{ vault.get("omni", "OMNI_SERVICE_ACCOUNT_KEY") }}',
  ).meta({ sensitive: true }),
  insecureSkipTlsVerify: z.boolean().default(false).describe(
    "Skip TLS verification for the Omni API (use only for self-signed certs)",
  ),
  omnictlPath: z.string().default("omnictl").describe(
    "Path to the omnictl binary; override when it is not on PATH",
  ),
});

/**
 * `@mccormick/omni/inventory` — discovers every Talos machine and cluster an
 * Omni instance manages and writes them as typed swamp resources. Read-only.
 */
export const model = {
  type: "@mccormick/omni/inventory",
  version: "2026.05.21.1",
  globalArguments: GlobalArgs,
  resources: {
    node: {
      description: "An Omni-managed Talos machine",
      schema: NodeSchema,
      lifetime: "30d",
      garbageCollection: 20,
    },
    cluster: {
      description: "A Talos cluster managed by Omni",
      schema: ClusterSchema,
      lifetime: "30d",
      garbageCollection: 20,
    },
    summary: {
      description: "Roll-up of one Omni inventory run",
      schema: SummarySchema,
      lifetime: "30d",
      garbageCollection: 20,
    },
  },
  methods: {
    discover: {
      description:
        "Query Omni for every managed Talos machine and cluster and write " +
        "one node resource per machine, one cluster resource per cluster, " +
        "and a summary roll-up.",
      arguments: z.object({}),
      execute: async (_args, context) => {
        const g = context.globalArgs;
        const endpoint = assertHttpsUrl(g.endpoint, "endpoint");
        if (!g.serviceAccountKey) {
          throw new Error("serviceAccountKey is required to query Omni");
        }
        const opts: OmnictlOptions = {
          endpoint,
          serviceAccountKey: g.serviceAccountKey,
          insecureSkipTlsVerify: g.insecureSkipTlsVerify,
          omnictlPath: g.omnictlPath,
        };

        context.logger.info("omni: discovering machines at {endpoint}", {
          endpoint,
        });

        // Read-only COSI queries — independent, so fetched concurrently. Any
        // failure rejects here, before a single resource is written.
        const [
          machineStatuses,
          clusterMachineStatuses,
          clusterMachineIdentities,
          clusters,
        ] = await Promise.all([
          getResources("machinestatus", opts),
          getResources("clustermachinestatus", opts),
          getResources("clustermachineidentity", opts),
          getResources("cluster", opts),
        ]);

        const merged = mergeInventory({
          endpoint,
          machineStatuses,
          clusterMachineStatuses,
          clusterMachineIdentities,
          clusters,
        }, new Date().toISOString());

        const handles = [];
        for (const node of merged.nodes) {
          handles.push(
            await context.writeResource(
              "node",
              `node-${sanitizeInstanceName(node.id)}`,
              node,
            ),
          );
        }
        for (const cluster of merged.clusters) {
          handles.push(
            await context.writeResource(
              "cluster",
              `cluster-${sanitizeInstanceName(cluster.name)}`,
              cluster,
            ),
          );
        }
        handles.push(
          await context.writeResource("summary", "summary", merged.summary),
        );

        context.logger.info(
          "omni: discovered {nodes} nodes across {clusters} clusters " +
            "({connected} connected)",
          {
            nodes: merged.summary.totalNodes,
            clusters: merged.summary.clusterCount,
            connected: merged.summary.connectedCount,
          },
        );
        for (const note of merged.summary.notes) {
          context.logger.warn("omni: {note}", { note });
        }
        return { dataHandles: handles };
      },
    },
  },
} satisfies ModelDefinition<typeof GlobalArgs>;
