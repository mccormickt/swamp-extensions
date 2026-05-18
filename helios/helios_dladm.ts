/**
 * @mccormick/helios/dladm — datalink and VNIC management on a Helios host.
 *
 * Used by zone provisioning to create exclusive-IP VNICs with link-protection
 * (mac-nospoof, ip-nospoof, dhcp-nospoof, restricted) and per-zone allowed-ips
 * pinning. All commands run via pfexec.
 */
import { z } from "npm:zod@4";
import {
  pfexec,
  resolveTarget,
  shq,
  sshExec,
  sshExecOrThrow,
  type SshTarget,
} from "./shared/ssh.ts";

const GlobalArgs = z.object({
  sshUser: z.string().default("root"),
  sshPort: z.number().int().positive().optional(),
  sshKnownHosts: z.string().optional(),
});

// Required on every method — the host is the verb's target.
const SshArgsShape = {
  sshHost: z.string().describe("Target Helios host (FQDN or IP)."),
  sshUser: z.string().optional(),
  sshPort: z.number().int().positive().optional(),
  sshKnownHosts: z.string().optional(),
};

const LinkSchema = z.object({
  link: z.string(),
  class: z.string(),
  mtu: z.number().int().nullable(),
  state: z.string(),
  over: z.string().nullable(),
  observedAt: z.iso.datetime(),
});

const PhysSchema = z.object({
  link: z.string(),
  media: z.string(),
  state: z.string(),
  speedMbps: z.number().int().nullable(),
  duplex: z.string().nullable(),
  device: z.string().nullable(),
  observedAt: z.iso.datetime(),
});

const VnicSchema = z.object({
  link: z.string(),
  over: z.string(),
  speedMbps: z.number().int().nullable(),
  macAddress: z.string(),
  vlanId: z.number().int().nullable(),
  protection: z.string().nullable().describe(
    "Comma-separated link-protection flags",
  ),
  allowedIps: z.array(z.string()).default([]),
  observedAt: z.iso.datetime(),
});

const EtherstubSchema = z.object({
  link: z.string(),
  observedAt: z.iso.datetime(),
});

async function lookupVnic(
  t: SshTarget,
  link: string,
): Promise<z.infer<typeof VnicSchema>> {
  const show = await sshExecOrThrow(
    t,
    `dladm show-vnic -p -o link,over,speed,macaddress,vid ${shq(link)}`,
  );
  const [, over, speed, mac, vid] = show.stdout.trim().split(":");
  // Parse `protection` and `allowed-ips` linkprops separately.
  const protOut = await sshExec(
    t,
    `dladm show-linkprop -c -p protection,allowed-ips -o property,value ${
      shq(link)
    }`,
  );
  let protection: string | null = null;
  let allowedIps: string[] = [];
  if (protOut.code === 0) {
    for (const line of protOut.stdout.trim().split(/\r?\n/)) {
      const [prop, value] = line.split(":");
      if (prop === "protection") protection = value || null;
      if (prop === "allowed-ips" && value) {
        allowedIps = value.split(",").filter(Boolean);
      }
    }
  }
  return {
    link,
    over: over ?? "",
    speedMbps: speed ? Number(speed) : null,
    macAddress: mac ?? "",
    vlanId: vid && vid !== "0" ? Number(vid) : null,
    protection,
    allowedIps,
    observedAt: new Date().toISOString(),
  };
}

export const model = {
  type: "@mccormick/helios/dladm",
  version: "2026.05.14.3",
  globalArguments: GlobalArgs,
  resources: {
    "link": {
      description: "A datalink",
      schema: LinkSchema,
      lifetime: "infinite" as const,
      garbageCollection: 5,
    },
    "phys": {
      description: "A physical NIC",
      schema: PhysSchema,
      lifetime: "infinite" as const,
      garbageCollection: 5,
    },
    "vnic": {
      description: "A VNIC, with mac, vlan, link-protection, allowed-ips",
      schema: VnicSchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
    "etherstub": {
      description: "An etherstub",
      schema: EtherstubSchema,
      lifetime: "infinite" as const,
      garbageCollection: 5,
    },
  },
  methods: {
    link_list: {
      description: "List every datalink (phys, vnic, aggr, etherstub).",
      arguments: z.object({ ...SshArgsShape }),
      execute: async (args, context) => {
        const t = resolveTarget(context.globalArgs, args);
        const out = await sshExecOrThrow(
          t,
          "dladm show-link -p -o link,class,mtu,state,over",
        );
        const handles = [];
        for (const line of out.stdout.trim().split(/\r?\n/).filter(Boolean)) {
          const [link, klass, mtu, state, over] = line.split(":");
          handles.push(
            await context.writeResource("link", link, {
              link,
              class: klass,
              mtu: mtu ? Number(mtu) : null,
              state,
              over: over || null,
              observedAt: new Date().toISOString(),
            }),
          );
        }
        return { dataHandles: handles };
      },
    },

    phys_list: {
      description: "List physical NICs (`dladm show-phys`).",
      arguments: z.object({ ...SshArgsShape }),
      execute: async (args, context) => {
        const t = resolveTarget(context.globalArgs, args);
        const out = await sshExecOrThrow(
          t,
          "dladm show-phys -p -o link,media,state,speed,duplex,device",
        );
        const handles = [];
        for (const line of out.stdout.trim().split(/\r?\n/).filter(Boolean)) {
          const [link, media, state, speed, duplex, device] = line.split(":");
          handles.push(
            await context.writeResource("phys", link, {
              link,
              media,
              state,
              speedMbps: speed ? Number(speed) : null,
              duplex: duplex || null,
              device: device || null,
              observedAt: new Date().toISOString(),
            }),
          );
        }
        return { dataHandles: handles };
      },
    },

    etherstub_create: {
      description: "Create an etherstub.",
      arguments: z.object({
        ...SshArgsShape,
        name: z.string(),
      }),
      execute: async (args, context) => {
        const t = resolveTarget(context.globalArgs, args);
        await sshExecOrThrow(
          t,
          `${pfexec(`dladm create-etherstub ${shq(args.name)}`)}`,
        );
        const handle = await context.writeResource("etherstub", args.name, {
          link: args.name,
          observedAt: new Date().toISOString(),
        });
        return { dataHandles: [handle] };
      },
    },

    etherstub_destroy: {
      description: "Destroy an etherstub.",
      arguments: z.object({
        ...SshArgsShape,
        name: z.string(),
      }),
      execute: async (args, context) => {
        const t = resolveTarget(context.globalArgs, args);
        await sshExecOrThrow(
          t,
          `${pfexec(`dladm delete-etherstub ${shq(args.name)}`)}`,
        );
        return { dataHandles: [] };
      },
    },

    vnic_create: {
      description:
        "Create a VNIC over `over` (phys/etherstub/aggr) and immediately " +
        "set link-protection=mac-nospoof,ip-nospoof,dhcp-nospoof,restricted " +
        "and allowed-ips. macAddress defaults to a random factory address.",
      arguments: z.object({
        ...SshArgsShape,
        name: z.string(),
        over: z.string(),
        macAddress: z.string().optional(),
        vlanId: z.number().int().min(1).max(4094).optional(),
        allowedIps: z.array(z.string()).default([]).describe(
          "CIDR list to pin via the allowed-ips linkprop. Required for " +
            "anti-spoof to be effective; empty == no IP pinning.",
        ),
      }),
      execute: async (args, context) => {
        const t = resolveTarget(context.globalArgs, args);
        const macFlag = args.macAddress
          ? `-m ${shq(args.macAddress)}`
          : "-m factory";
        const vlanFlag = args.vlanId ? `-v ${args.vlanId}` : "";
        const create = `${
          pfexec(
            `dladm create-vnic ${macFlag} ${vlanFlag} -l ${shq(args.over)} ${
              shq(args.name)
            }`,
          )
        }`;
        await sshExecOrThrow(t, create);

        // Apply link-protection in the same call so the VNIC is never visible
        // to the network without anti-spoof on.
        await sshExecOrThrow(
          t,
          `${
            pfexec(
              `dladm set-linkprop -p protection=mac-nospoof,ip-nospoof,dhcp-nospoof,restricted ${
                shq(args.name)
              }`,
            )
          }`,
        );
        if (args.allowedIps.length > 0) {
          await sshExecOrThrow(
            t,
            `${
              pfexec(
                `dladm set-linkprop -p allowed-ips=${
                  args.allowedIps.join(",")
                } ${shq(args.name)}`,
              )
            }`,
          );
        }

        const v = await lookupVnic(t, args.name);
        const handle = await context.writeResource("vnic", args.name, v);
        return { dataHandles: [handle] };
      },
    },

    vnic_destroy: {
      description: "Destroy a VNIC.",
      arguments: z.object({
        ...SshArgsShape,
        name: z.string(),
      }),
      execute: async (args, context) => {
        const t = resolveTarget(context.globalArgs, args);
        await sshExecOrThrow(
          t,
          `${pfexec(`dladm delete-vnic ${shq(args.name)}`)}`,
        );
        return { dataHandles: [] };
      },
    },
  },
};
