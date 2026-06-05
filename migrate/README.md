# @mccormick/migrate

Host-to-host VM **disk migration primitives** for
[swamp](https://github.com/systeminit/swamp) — the hypervisor-neutral middle of
a VM lift-and-shift (e.g. Proxmox ⇄ TrueNAS), paired with
[`@mccormick/truenas/vm`](../truenas) provisioning and a Proxmox inspect step.

## Model

`@mccormick/migrate/disk`:

| Method            | Does                                                                         |
| ----------------- | --------------------------------------------------------------------------- |
| `stream`          | Copy a **powered-off** source block device to a destination block device over an encrypted, compressed pipe (`dd \| zstd \| ssh "zstd -dc \| dd conv=sparse"`). `direct` (source→dest), `relay` (bridged through the swamp host), or `auto` (probe and pick). Verifies the written byte count against `expectedBytes`. Writes `transfer`. |
| `edit_guest_disk` | Agent-absent network fallback: mount the guest's LVM root over qemu-nbd (or a local device) on a tool host, rewrite netplan to **match by the target MAC**, disable cloud-init networking, and tear it all down in a `trap`. Writes `guest_disk_edit`. |
| `verify`          | Poll a cutover IP for TCP/ICMP reachability; fails if the expected state isn't reached within the timeout. Writes `verify`. |

## Transfer topologies

- **relay** (default, always works): the swamp host bridges two ssh legs —
  `ssh src 'dd | zstd'` piped into `ssh dst 'zstd -dc | dd conv=sparse'`. Both
  legs use the swamp host's own credentials, so no source→dest trust is needed.
  Bytes cross the swamp host (bandwidth/latency cost).
- **direct** (faster, needs trust): the source pipes straight into an inner ssh
  to the dest. Authorize it with either a forwarded agent (`ssh -A` from the
  swamp host, the default when no key is set) or `migrationKeyPath` — a private
  key **present on the source host** passed to the inner ssh with `-i`.
- **auto**: probe `ssh src "ssh -o BatchMode -o ConnectTimeout=5 dst true"`;
  exit 0 → direct, else relay.

Both legs are ssh, so the stream is encrypted on the wire; `zstd` is for
throughput, not secrecy. The relay pipeline the swamp host runs looks like:

```sh
ssh src 'dd if=/dev/VM-Storage/vm-104-disk-0 bs=4M status=progress | zstd -T0 -3' \
  | ssh dst 'zstd -dc | dd of=/dev/zvol/Main/omni bs=4M conv=sparse status=progress'
```

`stream` then parses the destination `dd`'s "N bytes copied" line and checks it
against `expectedBytes` (tolerating one block of rounding).

## Offline guest-disk edit

When the source guest has **no qemu-guest-agent**, its network config can't be
fixed in-guest before shutdown, so `edit_guest_disk` fixes the streamed image
afterward. It runs on a **tool host that has `qemu-nbd` + `lvm2`** — the Proxmox
node, never TrueNAS (which lacks LVM2 userspace). It defeats Proxmox's nbd-hiding
`global_filter` with `--config 'devices{global_filter=["a|.*|"]}'` and tears down
(`umount`, `vgchange -an`, `qemu-nbd -d`) in a trap so a failure never leaves the
LV active or the nbd device connected.

**Limits:** LVM2 + a mountable (ext4) root only. It does **not** handle
ZFS-on-root, LUKS, or plain-partition (no-LVM) roots — use the agent path for
those.

## Configuration

| Global argument     | Required | Default | Description                                               |
| ------------------- | -------- | ------- | --------------------------------------------------------- |
| `sshUser`           | no       | `root`  | Default SSH user for src/dst/tool hosts                   |
| `sshPort`           | no       | `22`    | Default SSH port                                          |
| `migrationKeyPath`  | no       | —       | Private key **on the source host** for direct-mode inner ssh; otherwise `ssh -A` is used |
| `connectTimeoutSec` | no       | `15`    | SSH connect timeout                                       |
| `taskTimeoutSec`    | no       | `7200`  | Max seconds for a stream/edit (disk copies are long)      |

## Quick start

```sh
swamp extension source add ./migrate     # local development
swamp model create @mccormick/migrate/disk migrate-disk

# Stream a powered-off disk (source must be shut down first).
swamp model method run migrate-disk stream \
  --input srcHost=pve.example.net --input dstHost=truenas.example.net \
  --input srcDevPath=/dev/VM-Storage/vm-104-disk-0 \
  --input dstDevPath=/dev/zvol/Main/omni \
  --input expectedBytes=268435456000 --input mode=auto

# Verify the cutover IP came up.
swamp model method run migrate-disk verify --input ip=192.0.2.59 --input mode=tcp
```

## Safety

SSH is spawned directly (`Deno.Command("ssh")`, never `sh -c` locally) and every
interpolated device path is POSIX single-quote escaped. `migrationKeyPath` is
redacted from any error text. The streamed source disk must be **powered off**
first — the `migrate-vm` workflow enforces shutdown before `stream`, so the
shared MAC/IP is never live on two NICs at once.

## License

MIT — see [LICENSE.md](./LICENSE.md).
