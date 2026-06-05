/**
 * `@mccormick/migrate/disk` — pure command + script assembly.
 *
 * The disk mover is all shell pipelines (`dd | zstd | ssh "zstd -dc | dd"`) and
 * an offline qemu-nbd/LVM/netplan edit script. Assembling those strings — with
 * every interpolated path POSIX-quoted — is the part most likely to go wrong, so
 * it is factored here, free of any I/O, and unit-tested directly. The `ssh.ts`
 * helper runs the strings this module builds; `disk.ts` wires them together.
 *
 * @module
 */

/** POSIX single-quote escape so a value is one literal shell token. */
export function shq(s: string): string {
  return `'${s.replace(/'/g, "'\\''")}'`;
}

/** Connection options shared by the inner/probe ssh invocations on a remote. */
export interface InnerSshOpts {
  dstHost: string;
  dstUser: string;
  connectTimeoutSec: number;
  /** Private key path *on the source host* for direct-mode inner ssh, if any. */
  migrationKeyPath?: string;
}

function innerSshFlags(o: InnerSshOpts): string[] {
  const flags = [
    "-o",
    "BatchMode=yes",
    "-o",
    `ConnectTimeout=${o.connectTimeoutSec}`,
    "-o",
    "StrictHostKeyChecking=accept-new",
  ];
  if (o.migrationKeyPath) flags.push("-i", shq(o.migrationKeyPath));
  return flags;
}

/** zstd flags string: `-T<threads> -<level>`. */
export function zstdFlags(threads: number, level: number): string {
  return `-T${threads} -${level}`;
}

/** The `dd` read side: `dd if=<dev> bs=<bs> status=progress`. */
export function ddReadCommand(devPath: string, blockSize: string): string {
  return `dd if=${shq(devPath)} bs=${shq(blockSize)} status=progress`;
}

/** The `dd` write side: `dd of=<dev> bs=<bs> [conv=sparse] status=progress`. */
export function ddWriteCommand(
  devPath: string,
  blockSize: string,
  sparse: boolean,
): string {
  const conv = sparse ? " conv=sparse" : "";
  return `dd of=${shq(devPath)} bs=${shq(blockSize)}${conv} status=progress`;
}

/** Compression/decompression endpoints of the pipe. */
export function zstdCompress(threads: number, level: number): string {
  return `zstd ${zstdFlags(threads, level)}`;
}
export function zstdDecompress(): string {
  return "zstd -dc";
}

export interface StreamParams {
  srcDevPath: string;
  dstDevPath: string;
  blockSize: string;
  zstdLevel: number;
  zstdThreads: number;
  sparse: boolean;
}

/** The relay read leg, run on the source host (stdout is the compressed stream). */
export function relaySrcCommand(p: StreamParams): string {
  return `${ddReadCommand(p.srcDevPath, p.blockSize)} | ${
    zstdCompress(p.zstdThreads, p.zstdLevel)
  }`;
}

/** The relay write leg, run on the dest host (stdin is the compressed stream). */
export function relayDstCommand(p: StreamParams): string {
  return `${zstdDecompress()} | ${
    ddWriteCommand(p.dstDevPath, p.blockSize, p.sparse)
  }`;
}

/**
 * The single command run on the source host in **direct** mode: read+compress
 * locally, then pipe straight into an inner ssh to the dest that decompresses
 * and writes. Needs source→dest trust (a forwarded agent on the outer ssh, or
 * `migrationKeyPath` present on the source).
 */
export function directSrcCommand(p: StreamParams, inner: InnerSshOpts): string {
  const remoteWrite = relayDstCommand(p); // zstd -dc | dd of=...
  const sshInner = [
    "ssh",
    ...innerSshFlags(inner),
    `${inner.dstUser}@${inner.dstHost}`,
  ]
    .join(" ");
  return `${ddReadCommand(p.srcDevPath, p.blockSize)} | ${
    zstdCompress(p.zstdThreads, p.zstdLevel)
  } | ${sshInner} ${shq(remoteWrite)}`;
}

/**
 * The reachability probe run on the source host in **auto** mode: can the
 * source reach the dest over ssh at all? Exit 0 ⇒ use direct, else relay.
 */
export function probeCommand(inner: InnerSshOpts): string {
  const flags = innerSshFlags(inner).join(" ");
  return `ssh ${flags} ${inner.dstUser}@${inner.dstHost} true`;
}

/**
 * Parse the total bytes written from `dd`'s stderr summary
 * (`... 1073741824 bytes (1.1 GB, 1.0 GiB) copied ...`). Returns the largest
 * `N bytes` figure (the final total, never a record count), or null.
 */
export function parseDdBytes(stderr: string): number | null {
  const matches = [...stderr.matchAll(/(\d+)\s+bytes\b/g)].map((m) =>
    Number(m[1])
  );
  if (matches.length === 0) return null;
  return Math.max(...matches);
}

/**
 * Decide whether a written byte count satisfies the expectation, allowing for
 * `dd` rounding the final block up to `blockSize`. Returns true when
 * `written >= expected` or the shortfall is under one block.
 */
export function bytesVerified(
  written: number,
  expected: number,
  blockSizeBytes: number,
): boolean {
  if (written >= expected) return true;
  return expected - written < blockSizeBytes;
}

/** Parse a `dd` block-size token (`4M`, `1M`, `512K`, bare bytes) into bytes. */
export function blockSizeBytes(bs: string): number {
  const m = bs.trim().match(/^(\d+)\s*([KMGT]?)$/i);
  if (!m) return 1;
  const factor: Record<string, number> = {
    "": 1,
    K: 1024,
    M: 1024 ** 2,
    G: 1024 ** 3,
    T: 1024 ** 4,
  };
  return Number(m[1]) * (factor[(m[2] || "").toUpperCase()] ?? 1);
}

// ---------------------------------------------------------------------------
// Offline guest-disk edit (qemu-nbd + LVM + netplan), run on a tool host.
// ---------------------------------------------------------------------------

/** Build the in-image netplan body (match-by-MAC; dhcp or static). */
export function netplanBody(args: {
  targetMac: string;
  useDhcp: boolean;
  staticCidr?: string;
  gateway?: string;
}): string {
  const lines = [
    "network:",
    "  version: 2",
    "  ethernets:",
    "    primary:",
    "      match:",
    `        macaddress: ${args.targetMac}`,
    "      set-name: net0",
  ];
  if (args.useDhcp) {
    lines.push("      dhcp4: true");
  } else {
    lines.push("      dhcp4: false");
    if (args.staticCidr) {
      lines.push("      addresses:", `        - ${args.staticCidr}`);
    }
    if (args.gateway) {
      lines.push(
        "      routes:",
        "        - to: default",
        `          via: ${args.gateway}`,
      );
    }
  }
  return lines.join("\n");
}

export interface EditGuestDiskParams {
  targetMode: "local" | "nbd";
  nbdHost?: string;
  nbdPort: number;
  nbdDevice: string;
  localDevPath?: string;
  vgName: string;
  lvName: string;
  mountPoint: string;
  lvmGlobalFilter: string;
  targetMac: string;
  useDhcp: boolean;
  staticCidr?: string;
  gateway?: string;
}

/**
 * Build the self-contained bash script that mounts a guest's LVM root over
 * qemu-nbd (or a local device), rewrites netplan to match by the target MAC,
 * disables cloud-init networking, and **tears everything down in a trap** so a
 * failure never leaves the LV active or the nbd device connected. Run on a tool
 * host that has `qemu-nbd` + `lvm2` (the Proxmox node — TrueNAS lacks LVM2
 * userspace). LVM2 + a mountable (ext4) root only.
 */
export function buildEditGuestDiskScript(p: EditGuestDiskParams): string {
  const cfg = `devices{global_filter=[${p.lvmGlobalFilter}]}`;
  const lvPath = `/dev/${p.vgName}/${p.lvName}`;
  const netplan = netplanBody(p);
  const teardownNbd = p.targetMode === "nbd"
    ? `qemu-nbd -d ${shq(p.nbdDevice)} 2>/dev/null || true`
    : "true";
  const setupDev = p.targetMode === "nbd"
    ? [
      "modprobe nbd max_part=8",
      `qemu-nbd -c ${shq(p.nbdDevice)} ${
        shq(`nbd://${p.nbdHost}:${p.nbdPort}`)
      } -f raw`,
    ].join("\n")
    : `test -b ${shq(p.localDevPath ?? "")}`;
  return [
    "set -e",
    `MNT=${shq(p.mountPoint)}`,
    "cleanup() {",
    '  umount "$MNT" 2>/dev/null || true',
    `  vgchange -an ${shq(p.vgName)} --config ${shq(cfg)} 2>/dev/null || true`,
    `  ${teardownNbd}`,
    "}",
    "trap cleanup EXIT",
    setupDev,
    `vgchange -ay ${shq(p.vgName)} --config ${shq(cfg)}`,
    'mkdir -p "$MNT"',
    `mount ${shq(lvPath)} "$MNT"`,
    'mkdir -p "$MNT/etc/netplan" "$MNT/etc/cloud/cloud.cfg.d"',
    `cat > "$MNT/etc/netplan/99-swamp-migrate.yaml" <<'SWAMP_NETPLAN'`,
    netplan,
    "SWAMP_NETPLAN",
    `chmod 600 "$MNT/etc/netplan/99-swamp-migrate.yaml"`,
    `printf 'network: {config: disabled}\\n' > "$MNT/etc/cloud/cloud.cfg.d/99-disable-network-config.cfg"`,
    "sync",
    "echo swamp-edit-ok",
  ].join("\n");
}
