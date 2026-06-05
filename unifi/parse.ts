/**
 * `@mccormick/unifi` — pure normalization of static-DNS records.
 *
 * Turns a raw UniFi v2 `static-dns` record object into a normalized
 * {@link DnsRecord}, and finds an existing record by key+type so
 * `upsert_record` can decide between create and update. Pure — no I/O — so it
 * is unit-tested directly.
 *
 * @module
 */
import type { DnsRecord } from "./schema.ts";

function asString(v: unknown): string | null {
  if (typeof v === "string") return v;
  if (typeof v === "number" && Number.isFinite(v)) return String(v);
  return null;
}

/** Normalize one raw UniFi static-DNS record into a {@link DnsRecord}. */
export function normalizeRecord(raw: unknown, observedAt: string): DnsRecord {
  const rec = (typeof raw === "object" && raw !== null)
    ? raw as Record<string, unknown>
    : {};
  return {
    id: asString(rec._id),
    recordType: asString(rec.record_type) ?? "A",
    key: asString(rec.key) ?? "",
    value: asString(rec.value) ?? "",
    enabled: typeof rec.enabled === "boolean" ? rec.enabled : true,
    observedAt,
  };
}

/** Extract the raw record array from a list payload (array or `{ data: [...] }`). */
export function rawList(raw: unknown): Record<string, unknown>[] {
  const list = Array.isArray(raw)
    ? raw
    : (typeof raw === "object" && raw !== null &&
        Array.isArray((raw as Record<string, unknown>).data))
    ? (raw as { data: unknown[] }).data
    : [];
  return list.filter(
    (r): r is Record<string, unknown> => typeof r === "object" && r !== null,
  );
}

/** Normalize a list payload (array, or `{ data: [...] }`) into records. */
export function normalizeRecords(
  raw: unknown,
  observedAt: string,
): DnsRecord[] {
  return rawList(raw).map((r) => normalizeRecord(r, observedAt));
}

/**
 * Find a record matching `key` (case-insensitive) and `recordType`
 * (case-insensitive). Returns the matched normalized record or null.
 */
export function findExisting(
  records: DnsRecord[],
  key: string,
  recordType: string,
): DnsRecord | null {
  const k = key.trim().toLowerCase();
  const t = recordType.trim().toUpperCase();
  return records.find(
    (r) =>
      r.key.trim().toLowerCase() === k &&
      r.recordType.trim().toUpperCase() === t,
  ) ?? null;
}
