# @mccormick/fleet

Cross-hypervisor fleet VM inventory report for
[swamp](https://github.com/systeminit/swamp).

A single workflow-scoped report that joins three independent inventory providers
into one cross-hypervisor table:

- **Talos / Omni** — `node` resources from
  [`@mccormick/omni`](../omni)
- **Proxmox QEMU** — `guest` resources from
  [`@stateless/proxmox`](https://swamp-club.com)
- **TrueNAS Incus** — `vm` resources from [`@mccormick/truenas`](../truenas)

## What it does

`@mccormick/fleet/inventory` (scope: `workflow`) reads each workflow step's
written resources, picks out the guest specs (`node`, `guest`, `vm`), normalizes
them onto flat rows sharing the `name`/`state`/`vcpus`/`memoryMib` contract, and
renders:

- a markdown table — one row per guest across all hypervisors, plus a per-
  hypervisor totals table;
- JSON totals — `totalGuests`, `byHypervisor` (count, vcpus, memoryMib), and the
  full normalized `rows` (including `ips`/`macs` for downstream correlation).

It keys on **resource spec names**, not model instance names, so any workflow
that wires the three providers can require it. Failed steps and non-guest specs
(`summary`, `cluster`, `exec`) contribute nothing.

## Field coverage by provider

| Provider | Spec    | name | state | vCPUs | memory | ips | macs |
| -------- | ------- | ---- | ----- | ----- | ------ | --- | ---- |
| Omni     | `node`  | ✓    | stage | ✓     | ✓      | ✓   | —    |
| Proxmox  | `guest` | ✓    | ✓     | —¹    | —¹     | ipv4| —    |
| TrueNAS  | `vm`    | ✓    | ✓     | ✓     | ✓      | —   | ✓    |

¹ `@stateless/proxmox` tracks lifecycle state, not cpu/memory, so those cells are
blank for Proxmox guests. The report shows what each provider reports and leaves
gaps as `—`.

## Usage

Add the report to a fleet workflow's report selection so it runs after the
inventory steps complete:

```yaml
# in the workflow definition
reports:
  require:
    - '@mccormick/fleet/inventory'
```

Then run the workflow; the report renders from whatever the steps produced:

```sh
swamp workflow run inventory-fleet --input proxmoxNode=pve
# the @mccormick/fleet/inventory report renders after the steps complete
```

## License

MIT — see [LICENSE.md](./LICENSE.md).
