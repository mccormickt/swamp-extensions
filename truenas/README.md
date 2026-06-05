# @mccormick/truenas

Hypervisor-layer VM **inventory and provisioning** for
[swamp](https://github.com/systeminit/swamp), via the
[TrueNAS SCALE](https://www.truenas.com/truenas-scale/) JSON-RPC WebSocket API.

TrueNAS SCALE 24.10+ runs guest VMs as Incus instances; earlier releases (and
25.04 "Fangtooth") use libvirt. This extension asks TrueNAS for that guest state
(read-only `inventory`) and can stand new guests up from a ZFS zvol
(read-write `vm`). The two are deliberately separate models so the inventory
safety story — "only ever reads" — stays intact.

## Models

### `@mccormick/truenas/inventory` (read-only)

Discovers, from one TrueNAS host:

- **`vm`** — one resource per guest: normalized `state`
  (running/stopped/suspended/unknown), `rawStatus`, `vcpus`, `memoryMib`,
  `autostart`, `disks[]`, `nics[]`, all observed `macs[]`, and a `description`.
- **`summary`** — a single roll-up: host, TrueNAS version, resolved backend,
  total / running / stopped / other counts, total vCPUs and memory, and any
  non-fatal `notes`.

The `discover` method fans out across every guest in **one**
`virt.instance.query` call (incus) or `vm.query` call (libvirt) — no per-VM loop
— and writes a `vm` per guest plus the `summary`. A field TrueNAS does not
report becomes a per-guest or run-level `notes` entry and never aborts the run.

### `@mccormick/truenas/vm` (provisioning)

Stands a libvirt guest up from a ZFS zvol — the TrueNAS half of the `migrate-vm`
workflow. Methods (all idempotent — each queries before it writes):

| Method        | Does                                                                     |
| ------------- | ----------------------------------------------------------------------- |
| `create_zvol` | `pool.dataset.create` a sparse/thick VOLUME; no-op if it already exists, refuses to grow a smaller one. Writes `zvol` (with `devPath`). |
| `create_vm`   | `vm.create` a VM (alphanumeric name); stamps a `[swamp-managed]` marker into the description. Writes `vm_instance`. |
| `attach_disk` | `vm.device.create` a DISK pointing at a zvol; idempotent on the path. Writes `vm_device`. |
| `attach_nic`  | `vm.device.create` a NIC with a fixed MAC; idempotent on the MAC — pass the **source** MAC for a same-IP cutover. Writes `vm_device`. |
| `start` / `stop` / `status` | lifecycle; write `vm_instance`. |
| `delete`      | `vm.delete` (and optionally its zvols); **refuses a VM lacking the swamp marker unless `force`**. "Already gone" is a clean no-op. |

Safety: TrueNAS libvirt VMs have no tags field, so the swamp marker lives in the
VM `description`; `delete` reads it back to avoid destroying a hand-managed VM.

## Field contract

The `vm` schema deliberately carries the same minimal field set
(`name`, `state`, `vcpus`, `memoryMib`, `macs`) as the Proxmox and Omni
inventory providers, so a workflow-scoped report can normalize all three onto
flat rows and (optionally) correlate a Talos node to its hypervisor VM by MAC.

## Credential-safe

Both models authenticate over the JSON-RPC WebSocket API
(`wss://<host>/api/current`) with `auth.login_with_api_key`. The API key is
supplied through a vault, marked sensitive in the schema, and redacted from logs
and error messages. `inventory` issues only `query` / `system.info` calls (a
read-only API key suffices); `vm` mutates VMs and datasets, so it needs a
read-write key.

## Prerequisites

### TrueNAS API key

Create an API key in the TrueNAS UI (**Credentials → API Keys**). A read-only key
is sufficient for `inventory`; the `vm` provisioning model needs a read-write key.

### Vault

Store the API key in a swamp vault:

```sh
swamp vault create @swamp/1password fleet
# then reference it as ${{ vault.get("fleet", "TrueNAS API Key/credential") }}
```

Any vault backend works — `local_encryption`, `@swamp/1password`, etc.

## Quick start

```sh
# Install the extension (or load locally via swamp extension source add).
swamp extension pull @mccormick/truenas

# Create a model instance — set globalArguments on the definition.
swamp model create @mccormick/truenas/inventory truenas \
  --global-arg endpoint=truenas.example.net \
  --global-arg 'apiKey=${{ vault.get("fleet", "TrueNAS API Key/credential") }}'

# Run the discovery.
swamp model method run truenas discover
```

Inspect the results with `swamp data query 'modelName=="truenas" && specName=="vm"' --json`.

### Provisioning a guest from a zvol

```sh
swamp model create @mccormick/truenas/vm truenas-vm \
  --global-arg endpoint=truenas.example.net \
  --global-arg 'apiKey=${{ vault.get("fleet", "TrueNAS API Key/credential") }}'

swamp model method run truenas-vm create_zvol --input pool=Main --input name=omni --input sizeGib=250
swamp model method run truenas-vm create_vm --input name=omni --input vcpus=4 --input memoryMib=8192 --input bootloader=UEFI_CSM
# attach the streamed disk and a NIC carrying the source VM's MAC (same-IP cutover)
swamp model method run truenas-vm attach_disk --input vmId=1 --input zvolPath=/dev/zvol/Main/omni
swamp model method run truenas-vm attach_nic --input vmId=1 --input mac=bc:24:11:68:d6:09 --input bridge=br0
swamp model method run truenas-vm start --input vmId=1
```

## Configuration

| Global argument         | Required | Default | Description                                                        |
| ----------------------- | -------- | ------- | ------------------------------------------------------------------ |
| `endpoint`              | yes      | —       | TrueNAS host or base URL, e.g. `truenas.example.net`               |
| `apiKey`                | yes      | —       | TrueNAS API key; supply via a vault expression                     |
| `insecureSkipTlsVerify` | no       | `false` | Skip TLS verification (see TLS note below)                         |
| `backend`               | no       | `auto`  | Guest backend: `incus` (24.10+), `libvirt` (legacy), or `auto`     |
| `timeoutSecs`           | no       | `30`    | Per-discovery WebSocket timeout in seconds                         |

## TLS note

The model connects over `wss://`. Deno's WebSocket honors the system / Deno CA
store but does **not** expose a per-connection "skip verification" switch, so for
a self-signed TrueNAS certificate the most reliable path is to trust the
controller's CA on the swamp host rather than rely on `insecureSkipTlsVerify`.
A TrueNAS host reachable over a valid (or LAN-trusted) certificate needs no
special handling.

## Consuming the data

```yaml
# All discovered guests
allVms: ${{ data.findBySpec("truenas", "vm") }}
# Fleet totals
runningVms: ${{ data.latest("truenas", "summary").attributes.runningCount }}
```

## Known limitations

- **Single host.** One model instance targets one TrueNAS host.
- **libvirt provisioning.** `vm` targets the libvirt `vm.*` surface (SCALE 25.04);
  it does not provision Incus instances.
- **Shape drift.** TrueNAS middleware field shapes vary across releases; the
  parsers are defensive and record gaps in `notes` rather than failing. Confirm
  the `vm.*` / `vm.device.*` parameter shapes against your host before a
  production migration and tighten if needed.

## License

MIT — see [LICENSE.md](./LICENSE.md).
