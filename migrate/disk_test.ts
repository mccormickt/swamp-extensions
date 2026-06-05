/**
 * Unit tests for `@mccormick/migrate/disk`.
 *
 * The shell-pipeline and offline-edit script assembly (the high-risk string
 * building) is tested directly; `verify` is exercised through the reachability
 * probe seam so the poll loop is covered without touching the network.
 */
import { assertEquals, assertRejects, assertStringIncludes } from "jsr:@std/assert@1";
import { createModelTestContext } from "jsr:@systeminit/swamp-testing@0.20260519.14";
import {
  blockSizeBytes,
  buildEditGuestDiskScript,
  bytesVerified,
  directSrcCommand,
  parseDdBytes,
  probeCommand,
  relayDstCommand,
  relaySrcCommand,
  shq,
  type StreamParams,
} from "./build.ts";
import { __setReachabilityProbe, model } from "./disk.ts";

const PARAMS: StreamParams = {
  srcDevPath: "/dev/VM-Storage/vm-104-disk-0",
  dstDevPath: "/dev/zvol/Main/omni",
  blockSize: "4M",
  zstdLevel: 3,
  zstdThreads: 0,
  sparse: true,
};

// ---------------------------------------------------------------------------
// Pure command assembly
// ---------------------------------------------------------------------------

Deno.test("shq escapes single quotes", () => {
  assertEquals(shq("/dev/zvol/Main/omni"), "'/dev/zvol/Main/omni'");
  assertEquals(shq("a'b"), "'a'\\''b'");
});

Deno.test("relay legs build dd|zstd and zstd|dd conv=sparse", () => {
  assertEquals(
    relaySrcCommand(PARAMS),
    "dd if='/dev/VM-Storage/vm-104-disk-0' bs='4M' status=progress | zstd -T0 -3",
  );
  assertEquals(
    relayDstCommand(PARAMS),
    "zstd -dc | dd of='/dev/zvol/Main/omni' bs='4M' conv=sparse status=progress",
  );
});

Deno.test("relayDstCommand omits conv=sparse when sparse is false", () => {
  const cmd = relayDstCommand({ ...PARAMS, sparse: false });
  assertStringIncludes(cmd, "dd of='/dev/zvol/Main/omni' bs='4M' status=progress");
  assertEquals(cmd.includes("conv=sparse"), false);
});

Deno.test("directSrcCommand nests an inner ssh and uses -A path (no key)", () => {
  const cmd = directSrcCommand(PARAMS, {
    dstHost: "truenas",
    dstUser: "root",
    connectTimeoutSec: 15,
  });
  assertStringIncludes(cmd, "dd if='/dev/VM-Storage/vm-104-disk-0'");
  assertStringIncludes(cmd, "| zstd -T0 -3 |");
  assertStringIncludes(cmd, "ssh -o BatchMode=yes -o ConnectTimeout=15");
  assertStringIncludes(cmd, "root@truenas");
  // inner write command is quoted as one token
  assertStringIncludes(cmd, "'zstd -dc | dd of=");
  assertEquals(cmd.includes("-i "), false); // no migration key → no -i
});

Deno.test("directSrcCommand uses -i when a migration key is set", () => {
  const cmd = directSrcCommand(PARAMS, {
    dstHost: "truenas",
    dstUser: "root",
    connectTimeoutSec: 15,
    migrationKeyPath: "/root/.ssh/migrate",
  });
  assertStringIncludes(cmd, "-i '/root/.ssh/migrate'");
});

Deno.test("probeCommand pings dst over ssh", () => {
  const cmd = probeCommand({ dstHost: "truenas", dstUser: "root", connectTimeoutSec: 5 });
  assertEquals(
    cmd,
    "ssh -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=accept-new root@truenas true",
  );
});

// ---------------------------------------------------------------------------
// dd byte parsing + verification
// ---------------------------------------------------------------------------

Deno.test("parseDdBytes reads the copied total, not record counts", () => {
  const stderr = [
    "256+0 records in",
    "256+0 records out",
    "1073741824 bytes (1.1 GB, 1.0 GiB) copied, 5.2 s, 206 MB/s",
  ].join("\n");
  assertEquals(parseDdBytes(stderr), 1073741824);
  assertEquals(parseDdBytes("no bytes here"), null);
});

Deno.test("blockSizeBytes + bytesVerified tolerate one-block rounding", () => {
  assertEquals(blockSizeBytes("4M"), 4 * 1024 ** 2);
  assertEquals(blockSizeBytes("512K"), 512 * 1024);
  // exact
  assertEquals(bytesVerified(1000, 1000, 4 * 1024 ** 2), true);
  // short by under a block → ok
  assertEquals(bytesVerified(1000 - 10, 1000, 4 * 1024 ** 2), true);
  // short by more than a block → fail
  assertEquals(bytesVerified(1000, 1000 + 5 * 1024 ** 2, 4 * 1024 ** 2), false);
});

// ---------------------------------------------------------------------------
// edit_guest_disk script assembly
// ---------------------------------------------------------------------------

Deno.test("edit script (nbd) connects, mounts, rewrites, and traps teardown", () => {
  const s = buildEditGuestDiskScript({
    targetMode: "nbd",
    nbdHost: "truenas",
    nbdPort: 10809,
    nbdDevice: "/dev/nbd0",
    vgName: "ubuntu-vg",
    lvName: "ubuntu-lv",
    mountPoint: "/mnt/swamp-migrate",
    lvmGlobalFilter: "a|.*|",
    targetMac: "bc:24:11:68:d6:09",
    useDhcp: true,
  });
  assertStringIncludes(s, "trap cleanup EXIT");
  assertStringIncludes(s, "modprobe nbd max_part=8");
  assertStringIncludes(s, "qemu-nbd -c '/dev/nbd0' 'nbd://truenas:10809' -f raw");
  assertStringIncludes(s, "vgchange -ay 'ubuntu-vg'");
  assertStringIncludes(s, "global_filter=[a|.*|]");
  assertStringIncludes(s, "mount '/dev/ubuntu-vg/ubuntu-lv'");
  assertStringIncludes(s, "macaddress: bc:24:11:68:d6:09");
  assertStringIncludes(s, "qemu-nbd -d '/dev/nbd0'");
  assertStringIncludes(s, "echo swamp-edit-ok");
});

Deno.test("edit script (local) uses the local device, not qemu-nbd", () => {
  const s = buildEditGuestDiskScript({
    targetMode: "local",
    nbdPort: 10809,
    nbdDevice: "/dev/nbd0",
    localDevPath: "/dev/VM-Storage/vm-104-disk-0",
    vgName: "ubuntu-vg",
    lvName: "ubuntu-lv",
    mountPoint: "/mnt/x",
    lvmGlobalFilter: "a|.*|",
    targetMac: "bc:24:11:68:d6:09",
    useDhcp: false,
    staticCidr: "10.0.0.59/24",
    gateway: "10.0.0.1",
  });
  assertStringIncludes(s, "test -b '/dev/VM-Storage/vm-104-disk-0'");
  assertEquals(s.includes("qemu-nbd -c"), false);
  assertStringIncludes(s, "- 10.0.0.59/24");
  assertStringIncludes(s, "via: 10.0.0.1");
});

// ---------------------------------------------------------------------------
// verify (via probe seam)
// ---------------------------------------------------------------------------

const GLOBALS = { sshUser: "root", connectTimeoutSec: 15, taskTimeoutSec: 7200 };
type VerifyCtx = Parameters<typeof model.methods.verify.execute>[1];

Deno.test("verify succeeds once the probe reports reachable", async () => {
  let calls = 0;
  __setReachabilityProbe(() => Promise.resolve(++calls >= 2));
  try {
    const { context, getWrittenResources } = createModelTestContext({
      globalArgs: GLOBALS,
    });
    await model.methods.verify.execute(
      { ip: "10.0.0.59", pollIntervalSec: 1, timeoutSec: 30 },
      context as VerifyCtx,
    );
    const v = getWrittenResources().find((r) => r.specName === "verify");
    assertEquals(v?.data.reachable, true);
    assertEquals((v?.data as { attempts: number }).attempts, 2);
  } finally {
    __setReachabilityProbe(undefined);
  }
});

Deno.test("verify throws when the IP never becomes reachable", async () => {
  __setReachabilityProbe(() => Promise.resolve(false));
  try {
    const { context } = createModelTestContext({ globalArgs: GLOBALS });
    await assertRejects(
      () =>
        model.methods.verify.execute(
          { ip: "10.0.0.59", pollIntervalSec: 1, timeoutSec: 2 },
          context as VerifyCtx,
        ),
      Error,
      "expected reachable",
    );
  } finally {
    __setReachabilityProbe(undefined);
  }
});
