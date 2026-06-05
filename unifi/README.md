# @mccormick/unifi

Custom/static DNS records on a local [UniFi](https://ui.com) Network controller,
for [swamp](https://github.com/systeminit/swamp).

UniFi's "Custom DNS" (static DNS) records live on the local controller's
internal v2 API — not the cloud Site Manager API, which cannot edit DNS. This
extension reads and upserts those records so a cutover DNS flip becomes a
composable model method instead of a one-off curl.

## Model

`@mccormick/unifi/dns`:

- **`list_records`** (read-only) — reads every custom DNS record and writes one
  `dns_record` resource per entry (`id`, `recordType`, `key`, `value`,
  `enabled`).
- **`upsert_record`** `{ key, recordType=A, value, enabled=true }` — finds a
  record by key+type and updates it in place (`PUT`), or creates it (`POST`)
  when none matches. Writes the resulting `dns_record`.
- **`delete_record`** `{ key, recordType=A }` — removes a record by key+type.
  Idempotent: succeeds when the record is already absent. Writes a tombstone
  `dns_record` (`id` null, `enabled` false) recording the removal.

The mutating methods (`upsert_record`, `delete_record`) are gated by a
`controller-reachable` pre-flight check (label `live`) that confirms the
controller responds and the API key is accepted before any write. Skip it with
`--skip-check-label live` when needed.

## Local key, not cloud

Static DNS is only reachable on the **local** controller API
(`https://<gateway>/proxy/network/v2/api/site/<site>/static-dns`,
`X-API-KEY` header). Issue the key on the local UniFi OS console:
**Settings → Control Plane → Integrations → Create API Key**. A cloud
Site Manager key from unifi.ui.com returns a generic 401 here and cannot edit
DNS. The api key is supplied through a vault, marked sensitive, and redacted
from logs and error text.

## TLS

The controller ships a self-signed certificate. Provide its CA via `caCert` so
the model trusts it. (Deno's `fetch` does not expose a per-request "skip
verification" switch, so `insecureSkipTlsVerify` is best-effort; prefer
`caCert`.)

## Quick start

```sh
swamp model create @mccormick/unifi/dns unifi \
  --global-arg controllerUrl=https://192.0.2.1 \
  --global-arg 'apiKey=${{ vault.get("fleet", "UniFi - Local Controller Key/credential") }}'

# Read current records.
swamp model method run unifi list_records

# Repoint a hostname (cutover).
swamp model method run unifi upsert_record \
  --input key=omni.example.net --input recordType=A --input value=192.0.2.99

# Remove a record.
swamp model method run unifi delete_record \
  --input key=stale.example.net --input recordType=A
```

## Configuration

| Global argument         | Required | Default   | Description                                            |
| ----------------------- | -------- | --------- | ------------------------------------------------------ |
| `controllerUrl`         | yes      | —         | Local controller base URL, e.g. `https://192.0.2.1`    |
| `apiKey`                | yes      | —         | Local controller API key; supply via a vault expression |
| `site`                  | no       | `default` | UniFi Network site name                                |
| `caCert`                | no       | —         | PEM CA cert to trust the controller's self-signed cert |
| `insecureSkipTlsVerify` | no       | `false`   | Best-effort TLS skip (limited; prefer `caCert`)        |

## Consuming the data

Each record is a typed swamp data artifact; reference it by spec name:

```yaml
# All custom DNS records
records: ${{ data.findBySpec("unifi", "dns_record") }}
```

## Known limitations

- **Path drift.** The static-DNS path is internal and undocumented; it has
  shifted across Network app versions. Confirm with `list_records` against your
  controller and inspect the web UI's request if it changes.
- **One controller.** One model instance manages one controller's records.

## License

MIT — see [LICENSE.md](./LICENSE.md).
