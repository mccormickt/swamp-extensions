/**
 * Unit tests for `@mccormick/unifi/dns`.
 *
 * Covers the pure record normalization/lookup and an end-to-end `list_records`
 * and `upsert_record` run against a stubbed transport — no live controller.
 */
import { assertEquals } from "jsr:@std/assert@1";
import { createModelTestContext } from "jsr:@systeminit/swamp-testing@0.20260519.14";
import {
  __setUnifiTransport,
  type UnifiRequest,
  type UnifiResponse,
} from "./client.ts";
import { findExisting, normalizeRecords, rawList } from "./parse.ts";
import { model } from "./dns.ts";

type ListCtx = Parameters<typeof model.methods.list_records.execute>[1];
type UpsertCtx = Parameters<typeof model.methods.upsert_record.execute>[1];
type DeleteCtx = Parameters<typeof model.methods.delete_record.execute>[1];
type CheckCtx = Parameters<typeof model.checks["controller-reachable"]["execute"]>[0];

const NOW = "2026-06-04T00:00:00.000Z";

const RECORDS = [
  {
    _id: "aaa111",
    key: "omni.example.net",
    value: "192.168.0.40",
    record_type: "A",
    enabled: true,
  },
  {
    _id: "bbb222",
    key: "nas.example.net",
    value: "192.168.0.50",
    record_type: "A",
    enabled: true,
  },
];

const GLOBAL_ARGS = {
  controllerUrl: "https://192.168.0.1",
  apiKey: "fake-key",
  site: "default",
  insecureSkipTlsVerify: false,
};

// ---------------------------------------------------------------------------
// pure helpers
// ---------------------------------------------------------------------------

Deno.test("normalizeRecords reads both array and {data:[]} payloads", () => {
  assertEquals(normalizeRecords(RECORDS, NOW).length, 2);
  assertEquals(normalizeRecords({ data: RECORDS }, NOW).length, 2);
  assertEquals(normalizeRecords(null, NOW), []);
});

Deno.test("findExisting matches key+type case-insensitively", () => {
  const recs = normalizeRecords(RECORDS, NOW);
  assertEquals(findExisting(recs, "OMNI.example.net", "a")?.id, "aaa111");
  assertEquals(findExisting(recs, "absent.example.net", "A"), null);
  assertEquals(findExisting(recs, "omni.example.net", "CNAME"), null);
});

Deno.test("rawList keeps the underlying objects for in-place updates", () => {
  const raws = rawList({ data: RECORDS });
  assertEquals(raws[0]._id, "aaa111");
});

// ---------------------------------------------------------------------------
// list_records (end-to-end with a stubbed transport)
// ---------------------------------------------------------------------------

Deno.test("list_records writes one dns_record per record", async () => {
  __setUnifiTransport(
    (_opts, _req): Promise<UnifiResponse> =>
      Promise.resolve({ status: 200, json: { data: RECORDS } }),
  );
  try {
    const { context, getWrittenResources } = createModelTestContext({
      globalArgs: GLOBAL_ARGS,
    });
    await model.methods.list_records.execute({}, context as unknown as ListCtx);
    const written = getWrittenResources().filter((r) => r.specName === "dns_record");
    assertEquals(written.length, 2);
    assertEquals(
      written.some((r) => r.data.key === "omni.example.net"),
      true,
    );
  } finally {
    __setUnifiTransport(undefined);
  }
});

// ---------------------------------------------------------------------------
// upsert_record — update path
// ---------------------------------------------------------------------------

Deno.test("upsert_record updates an existing record in place (PUT)", async () => {
  const calls: UnifiRequest[] = [];
  __setUnifiTransport((_opts, req): Promise<UnifiResponse> => {
    calls.push(req);
    if (req.method === "GET") {
      return Promise.resolve({ status: 200, json: { data: RECORDS } });
    }
    // PUT echoes the updated record.
    return Promise.resolve({
      status: 200,
      json: {
        _id: "aaa111",
        key: "omni.example.net",
        value: "192.168.0.99",
        record_type: "A",
        enabled: true,
      },
    });
  });
  try {
    const { context, getWrittenResources } = createModelTestContext({
      globalArgs: GLOBAL_ARGS,
    });
    await model.methods.upsert_record.execute(
      { key: "omni.example.net", recordType: "A", value: "192.168.0.99", enabled: true },
      context as unknown as UpsertCtx,
    );
    // GET then PUT to the existing id.
    assertEquals(calls.length, 2);
    assertEquals(calls[1].method, "PUT");
    assertEquals(
      calls[1].path,
      "/proxy/network/v2/api/site/default/static-dns/aaa111",
    );
    const written = getWrittenResources().filter((r) => r.specName === "dns_record");
    assertEquals(written.length, 1);
    assertEquals(written[0].data.value, "192.168.0.99");
  } finally {
    __setUnifiTransport(undefined);
  }
});

// ---------------------------------------------------------------------------
// upsert_record — create path
// ---------------------------------------------------------------------------

Deno.test("upsert_record creates a new record (POST) when none matches", async () => {
  const calls: UnifiRequest[] = [];
  __setUnifiTransport((_opts, req): Promise<UnifiResponse> => {
    calls.push(req);
    if (req.method === "GET") {
      return Promise.resolve({ status: 200, json: { data: RECORDS } });
    }
    return Promise.resolve({
      status: 200,
      json: {
        _id: "ccc333",
        key: "new.example.net",
        value: "192.168.0.77",
        record_type: "A",
        enabled: true,
      },
    });
  });
  try {
    const { context, getWrittenResources } = createModelTestContext({
      globalArgs: GLOBAL_ARGS,
    });
    await model.methods.upsert_record.execute(
      { key: "new.example.net", recordType: "A", value: "192.168.0.77", enabled: true },
      context as unknown as UpsertCtx,
    );
    assertEquals(calls.length, 2);
    assertEquals(calls[1].method, "POST");
    assertEquals(calls[1].path, "/proxy/network/v2/api/site/default/static-dns");
    const written = getWrittenResources().filter((r) => r.specName === "dns_record");
    assertEquals(written.length, 1);
    assertEquals(written[0].data.key, "new.example.net");
  } finally {
    __setUnifiTransport(undefined);
  }
});

// ---------------------------------------------------------------------------
// delete_record
// ---------------------------------------------------------------------------

Deno.test("delete_record deletes an existing record (DELETE) and tombstones", async () => {
  const calls: UnifiRequest[] = [];
  __setUnifiTransport((_opts, req): Promise<UnifiResponse> => {
    calls.push(req);
    if (req.method === "GET") {
      return Promise.resolve({ status: 200, json: { data: RECORDS } });
    }
    return Promise.resolve({ status: 200, json: {} });
  });
  try {
    const { context, getWrittenResources } = createModelTestContext({
      globalArgs: GLOBAL_ARGS,
    });
    await model.methods.delete_record.execute(
      { key: "omni.example.net", recordType: "A" },
      context as unknown as DeleteCtx,
    );
    assertEquals(calls.length, 2);
    assertEquals(calls[1].method, "DELETE");
    assertEquals(
      calls[1].path,
      "/proxy/network/v2/api/site/default/static-dns/aaa111",
    );
    const written = getWrittenResources().filter((r) => r.specName === "dns_record");
    assertEquals(written.length, 1);
    assertEquals(written[0].data.id, null);
    assertEquals(written[0].data.enabled, false);
    assertEquals(written[0].data.key, "omni.example.net");
  } finally {
    __setUnifiTransport(undefined);
  }
});

Deno.test("delete_record is idempotent when the record is absent (no DELETE)", async () => {
  const calls: UnifiRequest[] = [];
  __setUnifiTransport((_opts, req): Promise<UnifiResponse> => {
    calls.push(req);
    return Promise.resolve({ status: 200, json: { data: RECORDS } });
  });
  try {
    const { context, getWrittenResources } = createModelTestContext({
      globalArgs: GLOBAL_ARGS,
    });
    await model.methods.delete_record.execute(
      { key: "absent.example.net", recordType: "A" },
      context as unknown as DeleteCtx,
    );
    // Only the GET ran — no DELETE for a record that doesn't exist.
    assertEquals(calls.length, 1);
    assertEquals(calls[0].method, "GET");
    const written = getWrittenResources().filter((r) => r.specName === "dns_record");
    assertEquals(written.length, 1);
    assertEquals(written[0].data.enabled, false);
  } finally {
    __setUnifiTransport(undefined);
  }
});

// ---------------------------------------------------------------------------
// controller-reachable pre-flight check
// ---------------------------------------------------------------------------

Deno.test("controller-reachable check passes on a 2xx response", async () => {
  __setUnifiTransport((): Promise<UnifiResponse> =>
    Promise.resolve({ status: 200, json: { data: RECORDS } })
  );
  try {
    const { context } = createModelTestContext({ globalArgs: GLOBAL_ARGS });
    const result = await model.checks["controller-reachable"].execute(
      context as unknown as CheckCtx,
    );
    assertEquals(result.pass, true);
  } finally {
    __setUnifiTransport(undefined);
  }
});

Deno.test("controller-reachable check fails on a non-2xx response", async () => {
  __setUnifiTransport((): Promise<UnifiResponse> =>
    Promise.resolve({ status: 401, json: { error: "unauthorized" } })
  );
  try {
    const { context } = createModelTestContext({ globalArgs: GLOBAL_ARGS });
    const result = await model.checks["controller-reachable"].execute(
      context as unknown as CheckCtx,
    );
    assertEquals(result.pass, false);
    assertEquals((result.errors?.length ?? 0) > 0, true);
  } finally {
    __setUnifiTransport(undefined);
  }
});
