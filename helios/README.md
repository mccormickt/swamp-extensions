# @mccormick/helios

Four [swamp](https://github.com/systeminit/swamp) models that manage an
[illumos](https://illumos.org)/[Helios](https://github.com/oxidecomputer/helios)
host over SSH:

- `@mccormick/helios/host` — connection profile, identity/capacity probe, and
  read-only host-level diagnostics (thermal, load, faults, kernel messages,
  combined `health_check` verdict).
- `@mccormick/helios/zfs` — remote ZFS dataset/pool/snapshot operations.
- `@mccormick/helios/dladm` — datalink and exclusive-IP VNIC management,
  including link-protection (`mac-nospoof,ip-nospoof,dhcp-nospoof,restricted`)
  and per-zone `allowed-ips`.
- `@mccormick/helios/zone` — zonecfg/zoneadm lifecycle for the `solaris` and
  `bhyve` brands with hardened defaults (`ip-type=exclusive`,
  `file-mac-profile=fixed-configuration`, hardened `limit-priv`,
  `capped-cpu`/`capped-memory`), plus an `inventory` fan-out that gathers
  live usage, security, network, storage, SMF health, and recent log lines
  for every zone in a single SSH session.

The models compose: `zfs` makes a dataset, `dladm` makes a VNIC, then
`zone create` references both. No model writes secrets to the wire — SSH key
material lives only in the user's `ssh-agent`.

## Prerequisites

- **SSH agent.** An ssh-agent with the host's key loaded (the 1Password SSH
  agent works). The extension never sees or stores key material.
- **Solaris RBAC profiles.** Recommended setup is a non-root user with the
  profiles needed for `pfexec` to escalate per command:
  - "Zone Management" — for zonecfg/zoneadm.
  - "ZFS Storage Management" — for zfs/zpool.
  - "Network Management" — for dladm.
  - "Fault Management" — for fmadm.

  Root will also work; non-root + RBAC is the safer default.
- **`sshKnownHosts`.** Strongly recommended. The default `StrictHostKeyChecking`
  policy is `accept-new` (TOFU) — convenient for first contact, vulnerable to
  MITM on the very first connection. Pin a known_hosts file by passing
  `sshKnownHosts=/path/to/known_hosts` either as a global argument or per
  call.
- **`pfexec`.** Used to wrap every privileged command. With a non-root user,
  pfexec only succeeds for commands authorised by the assigned RBAC profile.

## Quick start — provision one zone end-to-end

```sh
# 1. Probe the host and stash a host_info resource.
swamp model method run @mccormick/helios/host lookup \
  --input sshHost=helios.example.com \
  --input sshUser=ops \
  --input sshKnownHosts=$HOME/.ssh/known_hosts_helios

# 2. Create a backing ZFS dataset for the zone.
swamp model method run @mccormick/helios/zfs dataset_create \
  --input sshHost=helios.example.com \
  --input name=rpool/zones/web1 \
  --input quota=20G \
  --input mountpoint=/zones/web1

# 3. Create an exclusive-IP VNIC over phys0 with anti-spoof and IP pinning.
swamp model method run @mccormick/helios/dladm vnic_create \
  --input sshHost=helios.example.com \
  --input name=web1_vnic0 \
  --input over=phys0 \
  --input 'allowedIps=["10.0.0.5/32"]'

# 4. Configure, install, boot the zone.
swamp model method run @mccormick/helios/zone create \
  --input sshHost=helios.example.com \
  --input name=web1 \
  --input brand=solaris \
  --input zonepath=/zones/web1 \
  --input vnicLink=web1_vnic0 \
  --input allowedAddress=10.0.0.5/32 \
  --input defaultRouter=10.0.0.1 \
  --input cappedCpu=2 \
  --input cappedMemoryMb=2048

swamp model method run @mccormick/helios/zone install \
  --input sshHost=helios.example.com --input name=web1
swamp model method run @mccormick/helios/zone boot \
  --input sshHost=helios.example.com --input name=web1
```

`sshUser` and `sshKnownHosts` can be set once as `globalArguments` in the
definition and omitted from per-method inputs; `sshHost` is required on every
call so the verb's target is always explicit.

## `zone.inventory` — fan-out snapshot

```sh
swamp model method run @mccormick/helios/zone inventory \
  --input sshHost=helios.example.com \
  --input includeLogs=true \
  --input logTailLines=50
```

One SSH session (ControlMaster-multiplexed), one `zone_inventory` resource per
zone, plus an `inventory_summary` rollup. Each entry includes identity,
state, network (vnic/mac/allowed-ips/rx-tx), storage
(dataset/used/avail/quota/snapshots), SMF failed-services, last-boot/uptime,
and recent matching messages. The `notes` array records per-zone partial
failures (e.g. a zone where `zonecfg export` failed); the summary surfaces
the failed-SMF zone count.

## `host.health_check` — one-shot host verdict

```sh
swamp model method run @mccormick/helios/host health_check \
  --input sshHost=helios.example.com
```

Single SSH session gathers thermal sensors (prtdiag + kstat + ipmitool when
available), load (uptime + prstat + mpstat + iostat + vmstat), faults
(fmadm + fmdump), and filtered messages, then writes an `audit` resource with
one of: `healthy`, `workload_driven`, `scrub_in_progress`, `thermal_alarm`,
`fault_present`, `unknown` — plus a reason string citing the evidence.

## Known limitations

- **`zonecfg`/`zoneadm` output parsers are version-sensitive.** Tested against
  Helios stable; expect to revisit `parseZonecfgExport` / `parseZoneadmListLine`
  if illumos changes the colon-escaping or scope syntax.
- **Per-command SSH timeout.** Default 120s; passes via the `sshExec` helper's
  optional `timeoutMs`. A hung remote will time out cleanly rather than
  wedging the model run.
- **Inventory is best-effort per zone.** A failed zone's entry has notes
  recorded and the summary's counts include it; the run does not abort.
- **TOFU on first contact.** With no `sshKnownHosts`, the default
  `StrictHostKeyChecking=accept-new` records the host key on first connect.
  Pin known_hosts in production.
- **Secrets in arguments.** Encryption passphrases for `dataset_create` go to
  the remote via stdin (never on the command line). Error messages from
  `sshExecOrThrow` are redacted of values passed in the call's `redact` list;
  callers can opt into this for additional sensitive fields.

## License

MIT — see [LICENSE.md](./LICENSE.md).
