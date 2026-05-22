/**
 * `@mccormick/omni` — URL validation and secret-redaction helpers.
 *
 * The `inventory` model shells out to `omnictl`; these helpers cover what the
 * subprocess boundary does not: validating the operator-supplied Omni endpoint
 * URL, and masking the service-account key from any text — `omnictl` stderr,
 * log lines, the scan summary — before it can leak.
 *
 * @module
 */

/**
 * Validate an operator-supplied URL. Requires `https:` — Omni's API is always
 * served over TLS, and rejecting `http:` is a minimal guard against an endpoint
 * pointing at an unintended plaintext service. The returned value has any
 * trailing slashes trimmed.
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
 * Mask every occurrence of `secret` in `text` with `[REDACTED]`. The Omni
 * service-account key is a long opaque base64 string, so exact-substring
 * replacement is both sufficient and complete. An empty `secret` is a no-op.
 */
export function redactSecret(text: string, secret: string): string {
  if (!secret) return text;
  return text.split(secret).join("[REDACTED]");
}
