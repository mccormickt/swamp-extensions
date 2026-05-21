/**
 * `@mccormick/cloudflare` — SSRF and secret-redaction helpers.
 *
 * The `zerotrust` model uses the official Cloudflare SDK for transport; these
 * two helpers cover what the SDK does not: validating the operator-supplied API
 * base URL, and masking credential-shaped substrings from error text before it
 * reaches logs or the scan summary's `notes`.
 *
 * @module
 */

/** Token-shaped substrings masked from any text that may reach logs/errors. */
const SECRET_PATTERNS: readonly RegExp[] = [
  /gh[oprsu]_[A-Za-z0-9]{20,}/g, // GitHub PAT / OAuth / app / refresh tokens
  /github_pat_[A-Za-z0-9_]{20,}/g, // GitHub fine-grained PAT
  /ya29\.[A-Za-z0-9._\-]{10,}/g, // Google OAuth2 access token
  /\b[Bb]earer\s+[A-Za-z0-9._\-]{10,}/g, // any bearer token in text
];

/**
 * Mask credential-shaped substrings. Applied to every network-error string
 * before it is placed in a thrown error or the scan summary.
 */
export function redactSecrets(text: string): string {
  let out = text;
  for (const pattern of SECRET_PATTERNS) {
    out = out.replace(pattern, "[REDACTED]");
  }
  return out.replace(
    /"(access_token|client_secret|token|private_key|key)"\s*:\s*"[^"]*"/g,
    '"$1":"[REDACTED]"',
  );
}

/**
 * Validate an operator-supplied API base URL. Requires `https:` — a minimal
 * SSRF guard against a base URL pointing at an internal `http://` service.
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
