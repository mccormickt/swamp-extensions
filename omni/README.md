# @mccormick/omni

Talos node discovery for [swamp](https://github.com/systeminit/swamp), via
[Sidero Omni](https://omni.siderolabs.com).

Omni is the control plane for fleets of Talos Linux machines: it registers every
machine, assigns machines to clusters, and tracks their health. This extension
asks Omni for that fleet state and turns it into a typed swamp inventory so it
can be audited, wired into workflows, or fed into a wider infrastructure graph.

## Model

`@mccormick/omni/inventory` — discovers, from one Omni instance:

- **`node`** — one resource per managed machine: hostname, cluster and role,
  connection and readiness state, Talos version, Kubernetes node name and IPs,
  network addresses, CPU / memory / block devices, SecureBoot state, and
  installed Talos extensions.
- **`cluster`** — one resource per cluster: Kubernetes and Talos versions, plus
  rolled-up machine, control-plane, worker, and connected counts.
- **`summary`** — a single roll-up: total and connected node counts, breakdowns
  by cluster, role, and Talos version, and any non-fatal `notes`.

The `discover` method fans out across Omni's COSI resources — `MachineStatus`,
`ClusterMachineStatus`, `ClusterMachineIdentity`, and `Cluster` — and merges
them by machine UUID in a single execution. An inconsistency (a machine
assigned to a cluster Omni did not return) is recorded in `summary.notes` and
never aborts the run.

## Read-only and credential-safe

The model only **reads** Omni — it issues `omnictl get` calls and nothing else.
Transport is the [`omnictl`](https://omni.siderolabs.com/reference/omnictl) CLI
authenticated with an Omni service account passed through the environment, so
`omnictl` never touches an on-disk omniconfig and never opens a browser. The
service-account key is supplied through a vault, marked sensitive in the schema,
and redacted from logs and error messages.

## Prerequisites

### omnictl

The `omnictl` binary must be on `PATH` (or set `omnictlPath`). Install it from
the Omni UI's downloads page or via your package manager.

### Omni service account

Create a service account so discovery runs unattended:

```sh
omnictl serviceaccount create swamp-omni-inventory
```

This prints `OMNI_ENDPOINT` and `OMNI_SERVICE_ACCOUNT_KEY`. A read-only role is
sufficient — the model never writes to Omni.

### Vault

Store the service-account key in a swamp vault:

```sh
swamp vault create local_encryption omni
swamp vault put omni OMNI_SERVICE_ACCOUNT_KEY
```

Any vault backend works — `local_encryption`, `@swamp/1password`, etc.

## Quick start

```sh
# Install the extension.
swamp extension pull @mccormick/omni

# Create a model instance — set globalArguments on the definition.
swamp model create @mccormick/omni/inventory omni
#   endpoint: https://omni.example.net
#   serviceAccountKey: ${{ vault.get("omni", "OMNI_SERVICE_ACCOUNT_KEY") }}

# Run the discovery.
swamp model method run omni discover
```

`discover` writes one `node` resource per machine, one `cluster` resource per
cluster, and a single `summary`. Inspect them with `swamp model output get omni
--json` or `swamp data list --model omni`.

## Configuration

| Global argument         | Required | Default    | Description                                              |
| ----------------------- | -------- | ---------- | -------------------------------------------------------- |
| `endpoint`              | yes      | —          | Omni API endpoint, e.g. `https://omni.example.net`       |
| `serviceAccountKey`     | yes      | —          | `OMNI_SERVICE_ACCOUNT_KEY`; supply via a vault expression |
| `insecureSkipTlsVerify` | no       | `false`    | Skip TLS verification (self-signed certs only)           |
| `omnictlPath`           | no       | `omnictl`  | Path to the `omnictl` binary                             |

## Consuming the data

Each resource is a typed swamp data artifact. Wire it into other models or
workflows by spec name:

```yaml
# All discovered nodes
allNodes: ${{ data.findBySpec("omni", "node") }}
# Fleet totals
totalNodes: ${{ data.latest("omni", "summary").attributes.totalNodes }}
```

## Known limitations

- **Single Omni instance.** One model instance inventories one Omni endpoint.
- **Read-only.** The model discovers state; it does not provision, patch, or
  upgrade machines.
- **Enum decoding.** Role and stage integers are decoded against Omni's current
  enum values, with a `role-<n>` / `stage-<n>` fallback if Omni adds new ones.

## License

MIT — see [LICENSE.md](./LICENSE.md).
