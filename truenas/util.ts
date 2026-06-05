/**
 * `@mccormick/truenas` — secret-redaction helper.
 *
 * The inventory model authenticates with a TrueNAS API key. This helper masks
 * that key from any text — WebSocket error payloads, JSON-RPC error objects,
 * log lines — before it can leak, mirroring `util.ts` in `@mccormick/omni`.
 *
 * @module
 */

/**
 * Mask every occurrence of `secret` in `text` with `[REDACTED]`. A TrueNAS API
 * key is a long opaque token, so exact-substring replacement is sufficient and
 * complete. An empty `secret` is a no-op.
 */
export function redactSecret(text: string, secret: string): string {
  if (!secret) return text;
  return text.split(secret).join("[REDACTED]");
}
