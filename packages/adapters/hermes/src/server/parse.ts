export type HermesLoginRequiredReason =
  | "invalid_grant"
  | "unauthorized"
  | "expired_grant"
  | "missing_grant";

export type HermesLoginRequiredSource =
  | "local_cli_output"
  | "gateway_terminal_payload"
  | "gateway_http_body";

export type HermesLoginRequiredResult = {
  requiresLogin: boolean;
  provider: "xai-oauth" | null;
  reason: HermesLoginRequiredReason | null;
  source: HermesLoginRequiredSource | null;
  loginUrl: null;
  redactedMessage: string | null;
};

export type HermesLoginRequiredInput = {
  adapterType: "hermes_local" | "hermes_gateway";
  provider?: string | null;
  stdout?: string;
  stderr?: string;
  parsed?: Record<string, unknown> | null;
  httpStatus?: number | null;
  responseBody?: unknown;
};

const SENSITIVE_KEY_PATTERN =
  /(^|[_-])(auth|authorization|token|secret|password|api[_-]?key|private[_-]?key|refresh[_-]?token|access[_-]?token|oauth[_-]?code|authorization[_-]?code)([_-]|$)/i;
const BEARER_TOKEN_PATTERN = /Bearer\s+["']?[^"'\s,;)}\]\[]+/gi;
const HERMES_SESSION_KEY_HEADER_PATTERN = /(X-Hermes-Session-Key\s*[:=]\s*)([^\s,;]+)/gi;
const PAPERCLIP_SESSION_KEY_PATTERN =
  /\bpaperclip:(?:company:[A-Za-z0-9-]+:agent:[A-Za-z0-9-]+(?::(?:issue|run):[A-Za-z0-9-]+)?|run:[A-Za-z0-9-]+)\b/gi;
const OAUTH_CODE_PATTERN = /\b(code|oauth_code|authorization_code)=([A-Za-z0-9._~+/=-]{12,})\b/gi;

const XAI_OAUTH_CONTEXT_RE =
  /\b(?:xai|x\.ai|grok)[-_\s]?oauth\b|\b(?:xai|x\.ai|grok)\b.{0,80}\boauth\b|\boauth\b.{0,80}\b(?:xai|x\.ai|grok)\b/i;
const HERMES_OAUTH_CONTEXT_RE =
  /\b(?:hermes|profile)\b.{0,80}\boauth\b|\boauth\b.{0,80}\b(?:hermes|profile)\b/i;

const INVALID_GRANT_RE = /\binvalid[_\s-]?grant\b/i;
const EXPIRED_GRANT_RE = /\bexpired\s+grant\b|\bgrant\s+expired\b|\boauth\b.{0,80}\bexpired\b|\bexpired\b.{0,80}\boauth\b/i;
const MISSING_GRANT_RE = /\bnot\s+logged\s+in\b|\blogin\s+required\b|\bmissing\b.{0,40}\bgrant\b|\bno\b.{0,40}\boauth\b.{0,40}\bgrant\b/i;
const UNAUTHORIZED_RE = /\b401\b|\bunauthorized\b|\bunauthenticated\b|\bauthentication\s+required\b/i;

function redactSensitiveText(value: string): string {
  return value
    .replace(BEARER_TOKEN_PATTERN, "Bearer [redacted]")
    .replace(HERMES_SESSION_KEY_HEADER_PATTERN, "$1[redacted]")
    .replace(PAPERCLIP_SESSION_KEY_PATTERN, "[redacted-session-key]")
    .replace(OAUTH_CODE_PATTERN, "$1=[redacted]");
}

function redactUnknown(value: unknown, keyPath: string[] = [], depth = 0): unknown {
  const key = keyPath[keyPath.length - 1] ?? "";
  if (typeof value === "string") {
    if (SENSITIVE_KEY_PATTERN.test(key)) return `[redacted len=${value.length}]`;
    return redactSensitiveText(value);
  }
  if (value == null || typeof value === "number" || typeof value === "boolean") return value;
  if (Array.isArray(value)) {
    if (depth > 5) return "[array-truncated]";
    return value.slice(0, 40).map((entry, index) => redactUnknown(entry, [...keyPath, String(index)], depth + 1));
  }
  if (typeof value === "object") {
    if (depth > 5) return "[object-truncated]";
    const out: Record<string, unknown> = {};
    for (const [entryKey, entryValue] of Object.entries(value as Record<string, unknown>).slice(0, 80)) {
      out[entryKey] = redactUnknown(entryValue, [...keyPath, entryKey], depth + 1);
    }
    return out;
  }
  return redactSensitiveText(String(value));
}

function stringifyUnknown(value: unknown): string {
  if (value == null) return "";
  if (typeof value === "string") return redactSensitiveText(value);
  try {
    return JSON.stringify(redactUnknown(value));
  } catch {
    return redactSensitiveText(String(value));
  }
}

function compactMessage(value: string): string | null {
  const compact = redactSensitiveText(value)
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .join(" ")
    .replace(/\s{2,}/g, " ")
    .trim();
  if (!compact) return null;
  return compact.length > 1_000 ? `${compact.slice(0, 1_000)}... [truncated ${compact.length - 1_000} chars]` : compact;
}

function normalizeProvider(value: string | null | undefined): string | null {
  if (!value) return null;
  return value.trim().toLowerCase().replace(/_/g, "-") || null;
}

function detectReason(text: string): HermesLoginRequiredReason | null {
  if (INVALID_GRANT_RE.test(text)) return "invalid_grant";
  if (EXPIRED_GRANT_RE.test(text)) return "expired_grant";
  if (MISSING_GRANT_RE.test(text)) return "missing_grant";
  if (UNAUTHORIZED_RE.test(text)) return "unauthorized";
  return null;
}

function detectSource(input: HermesLoginRequiredInput): HermesLoginRequiredSource {
  if (input.adapterType === "hermes_local") return "local_cli_output";
  return input.responseBody !== undefined || input.httpStatus != null
    ? "gateway_http_body"
    : "gateway_terminal_payload";
}

function collectText(input: HermesLoginRequiredInput): string {
  const parts = [
    input.stdout ?? "",
    input.stderr ?? "",
    stringifyUnknown(input.parsed),
    stringifyUnknown(input.responseBody),
    input.httpStatus != null ? `HTTP ${input.httpStatus}` : "",
  ];
  return parts.filter((part) => part.trim().length > 0).join("\n");
}

export function detectHermesLoginRequired(input: HermesLoginRequiredInput): HermesLoginRequiredResult {
  const text = collectText(input);
  const normalizedProvider = normalizeProvider(input.provider);
  const hasXaiProvider = normalizedProvider === "xai-oauth";
  const hasXaiContext = hasXaiProvider || XAI_OAUTH_CONTEXT_RE.test(text) || HERMES_OAUTH_CONTEXT_RE.test(text);
  const reason = detectReason(text);

  if (!hasXaiContext || !reason) {
    return {
      requiresLogin: false,
      provider: null,
      reason: null,
      source: null,
      loginUrl: null,
      redactedMessage: null,
    };
  }

  return {
    requiresLogin: true,
    provider: "xai-oauth",
    reason,
    source: detectSource(input),
    loginUrl: null,
    redactedMessage: compactMessage(text),
  };
}

export function buildHermesAuthRequiredErrorMeta(
  result: Pick<HermesLoginRequiredResult, "provider" | "reason">,
): Record<string, unknown> {
  return {
    provider: result.provider ?? "xai-oauth",
    reason: result.reason ?? "unauthorized",
    login: {
      supported: true,
      route: "/api/agents/{id}/hermes-login",
    },
  };
}
