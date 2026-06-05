/**
 * `@mccormick/unifi` — static-DNS resource schema.
 *
 * The `dns` model writes one `dns_record` resource per custom/static DNS entry
 * on a local UniFi Network controller. The `id` (the controller's `_id`) is the
 * handle `upsert_record` uses to update an existing record in place.
 *
 * @module
 */
import { z } from "npm:zod@4";

/**
 * Normalize an arbitrary string into a safe `writeResource` instance name:
 * lowercase, non-alphanumeric runs collapsed to `-`, trimmed. Instance names
 * are global across specs, so callers prefix with a spec discriminator.
 */
export function sanitizeInstanceName(raw: string): string {
  const cleaned = raw
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
  return cleaned.length === 0 ? "unnamed" : cleaned.slice(0, 100);
}

/** A custom/static DNS record on a UniFi Network controller. */
export const DnsRecordSchema = z.object({
  id: z.string().nullable().describe(
    "Controller record id (_id); null for a record not yet persisted",
  ),
  recordType: z.string().describe("DNS record type, e.g. A, AAAA, CNAME, TXT"),
  key: z.string().describe("Record name/host, e.g. omni.example.net"),
  value: z.string().describe("Record value, e.g. an IP for an A record"),
  enabled: z.boolean().describe("Whether the controller serves this record"),
  observedAt: z.iso.datetime().describe("When this record was read or written"),
});
/** {@link DnsRecordSchema} */
export type DnsRecord = z.infer<typeof DnsRecordSchema>;
