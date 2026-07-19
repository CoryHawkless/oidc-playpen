// Shared helpers for the OIDC test interface.

/** Redact sensitive values from header maps before display/export. */
const SENSITIVE_HEADER_KEYS = new Set([
  'authorization',
  'cookie',
  'set-cookie',
  'x-api-key',
  'proxy-authorization',
]);

export function redactHeaders(headers: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) {
    out[k] = SENSITIVE_HEADER_KEYS.has(k.toLowerCase()) ? '[REDACTED]' : v;
  }
  return out;
}

/** Copy text to clipboard with a legacy fallback. Resolves true/false. */
export async function copyText(text: string): Promise<boolean> {
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch {
    // fall through to legacy path
  }
  try {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.setAttribute('readonly', '');
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    const ok = document.execCommand('copy');
    document.body.removeChild(ta);
    return ok;
  } catch {
    return false;
  }
}

/** Decode a JWT (3-part dot-separated) into { header, payload, signature }, or null. */
export function decodeJwt(token: string): { header: Record<string, unknown>; payload: Record<string, unknown>; signature: string } | null {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  try {
    const decodeBase64Url = (str: string) => {
      const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
      const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
      return atob(padded);
    };
    return {
      header: JSON.parse(decodeBase64Url(parts[0])),
      payload: JSON.parse(decodeBase64Url(parts[1])),
      signature: parts[2],
    };
  } catch {
    return null;
  }
}

/** Returns true if the value looks like a JWT. */
export function isJwtLike(value: unknown): value is string {
  return typeof value === 'string' && value.split('.').length === 3;
}

/** Format an ISO date for compact display. */
export function formatTime(d: Date): string {
  return d.toLocaleTimeString(undefined, { hour12: false });
}
