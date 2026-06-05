/**
 * `@mccormick/migrate/disk` — resource schemas.
 *
 * Three resources record the host-to-host primitives: `transfer` (one disk
 * stream, with the verified byte count), `guest_disk_edit` (the offline
 * qemu-nbd/LVM/netplan edit), and `verify` (post-cutover reachability). The
 * migration-summary report reads these by spec name, so the shapes are a stable
 * contract.
 *
 * @module
 */
import { z } from "npm:zod@4";

/** Result of one host-to-host disk stream. */
export const TransferSchema = z.object({
  srcHost: z.string(),
  dstHost: z.string(),
  srcDevPath: z.string(),
  dstDevPath: z.string(),
  mode: z.enum(["direct", "relay"]).describe("Topology actually used"),
  requestedMode: z.enum(["direct", "relay", "auto"]),
  bytesWritten: z.number().int().nullable().describe(
    "Bytes dd reported writing on the destination, or null if unparsed",
  ),
  expectedBytes: z.number().int().nullable(),
  verified: z.boolean().describe(
    "Whether bytesWritten satisfied expectedBytes (within one block)",
  ),
  zstdLevel: z.number().int(),
  zstdThreads: z.number().int(),
  sparse: z.boolean(),
  startedAt: z.iso.datetime(),
  finishedAt: z.iso.datetime(),
  durationSec: z.number(),
});
/** {@link TransferSchema} */
export type Transfer = z.infer<typeof TransferSchema>;

/** Result of an offline guest-disk edit (qemu-nbd + LVM + netplan rewrite). */
export const GuestDiskEditSchema = z.object({
  toolHost: z.string(),
  mode: z.enum(["local", "nbd"]),
  nbdHost: z.string().nullable(),
  vg: z.string(),
  lv: z.string(),
  targetMac: z.string(),
  netMode: z.enum(["dhcp", "static"]),
  applied: z.boolean(),
  recordedAt: z.iso.datetime(),
});
/** {@link GuestDiskEditSchema} */
export type GuestDiskEdit = z.infer<typeof GuestDiskEditSchema>;

/** Result of a post-cutover reachability check. */
export const VerifySchema = z.object({
  ip: z.string(),
  port: z.number().int().nullable(),
  mode: z.enum(["tcp", "ping"]),
  reachable: z.boolean(),
  expectReachable: z.boolean(),
  attempts: z.number().int(),
  recordedAt: z.iso.datetime(),
});
/** {@link VerifySchema} */
export type Verify = z.infer<typeof VerifySchema>;
