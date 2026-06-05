/**
 * `@mccormick/unifi` — URL validation and secret-redaction helpers.
 *
 * @module
 */

/**
 * Validate the controller base URL. Requires `https:` (the local UniFi OS
 * controller always serves TLS) and returns it with trailing slashes trimmed.
 */
export function assertHttpsUrl(raw: string, label: string): string {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new Error(`${label} is not a valid URL: ${raw}`);
  }
  if (u.protocol !== "https:") {
    throw new Error(`${label} must use https (got ${u.protocol}): ${raw}`);
  }
  return raw.replace(/\/+$/, "");
}

/**
 * Mask every occurrence of `secret` in `text` with `[REDACTED]`. A UniFi API
 * key is a fixed-length opaque token, so exact-substring replacement is
 * sufficient. An empty `secret` is a no-op.
 */
export function redactSecret(text: string, secret: string): string {
  if (!secret) return text;
  return text.split(secret).join("[REDACTED]");
}
