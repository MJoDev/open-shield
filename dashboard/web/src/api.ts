import type {
  EventsPage,
  IPRule,
  RuleConfig,
  Stats,
  VerifyResult,
} from "./types";

/**
 * Thrown for any failed request, carrying the API's own error message.
 *
 * `status` is the HTTP status, or 0 when no response arrived at all — the
 * server did not answer in time (`timedOut`) or could not be reached.
 */
export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly timedOut = false,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

/** True for a request the caller cancelled itself; never worth showing. */
export function isAbort(err: unknown): boolean {
  return err instanceof DOMException && err.name === "AbortError";
}

export interface RequestOptions {
  /** Cancels the request, e.g. when the parameters it was made for changed. */
  signal?: AbortSignal;
  /** Overrides DEFAULT_TIMEOUT_MS for calls known to be slow. */
  timeoutMs?: number;
}

// A spinner that never ends is worse than an error. Every read the dashboard
// makes is a bounded query; fifteen seconds is far past a healthy answer and
// short enough that an operator is not left staring at a dead screen.
export const DEFAULT_TIMEOUT_MS = 15_000;

// Walking the whole chain recomputes every hash, so it scales with the log.
export const VERIFY_TIMEOUT_MS = 10 * 60_000;

let onUnauthorized: (() => void) | null = null;

/**
 * Registers what happens when a signed-in call answers 401: the session
 * expired or was revoked, and the only useful response is the sign-in screen.
 * Sign-in and the initial session probe are excluded — a 401 there is an
 * answer, not an expiry.
 */
export function setUnauthorizedHandler(handler: (() => void) | null): void {
  onUnauthorized = handler;
}

const UNAUTHORIZED_IS_AN_ANSWER = new Set(["/api/v1/login", "/api/v1/session"]);

async function request<T>(
  path: string,
  init?: RequestInit,
  options: RequestOptions = {},
): Promise<T> {
  const controller = new AbortController();
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, options.timeoutMs ?? DEFAULT_TIMEOUT_MS);

  const forward = () => controller.abort();
  if (options.signal?.aborted) controller.abort();
  options.signal?.addEventListener("abort", forward);

  try {
    let response: Response;
    try {
      response = await fetch(path, {
        // The session lives in an HttpOnly cookie, so it has to be sent
        // explicitly — and it is never readable from here, which is the point.
        credentials: "same-origin",
        headers: init?.body
          ? { "Content-Type": "application/json" }
          : undefined,
        ...init,
        signal: controller.signal,
      });
    } catch (err) {
      throw translateTransportError(err, timedOut, options.timeoutMs);
    }

    if (response.status === 401 && !UNAUTHORIZED_IS_AN_ANSWER.has(path)) {
      onUnauthorized?.();
    }

    if (response.status === 204) {
      return undefined as T;
    }

    const body = await response.json().catch(() => null);
    if (!response.ok) {
      const message =
        body && typeof body.error === "string"
          ? body.error
          : `La petición falló (${response.status})`;
      throw new ApiError(message, response.status);
    }
    return body as T;
  } finally {
    clearTimeout(timer);
    options.signal?.removeEventListener("abort", forward);
  }
}

function translateTransportError(
  err: unknown,
  timedOut: boolean,
  timeoutMs = DEFAULT_TIMEOUT_MS,
): unknown {
  if (timedOut) {
    return new ApiError(
      `sin respuesta tras ${Math.round(timeoutMs / 1000)} s`,
      0,
      true,
    );
  }
  // A caller's own cancellation passes through untouched, so it can be told
  // apart from a failure and ignored.
  if (isAbort(err)) return err;
  return new ApiError("no se pudo contactar con el servidor", 0);
}

function query(params: Record<string, string | number | undefined>): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== "") search.set(key, String(value));
  }
  const encoded = search.toString();
  return encoded ? `?${encoded}` : "";
}

export const api = {
  session: () => request<{ user: string }>("/api/v1/session"),

  login: (user: string, password: string) =>
    request<{ user: string; expires_in: number }>("/api/v1/login", {
      method: "POST",
      body: JSON.stringify({ user, password }),
    }),

  logout: () =>
    request<{ status: string }>("/api/v1/logout", { method: "POST" }),

  events: (
    params: {
      kind?: string;
      verdict?: string;
      ip?: string;
      rule?: string;
      limit?: number;
      offset?: number;
    },
    options?: RequestOptions,
  ) =>
    request<EventsPage>(`/api/v1/events${query(params)}`, undefined, options),

  stats: (window: string, options?: RequestOptions) =>
    request<Stats>(`/api/v1/stats${query({ window })}`, undefined, options),

  verify: (params: { from?: string; to?: string }, options?: RequestOptions) =>
    request<VerifyResult>(`/api/v1/audit/verify${query(params)}`, undefined, {
      timeoutMs: VERIFY_TIMEOUT_MS,
      ...options,
    }),

  rules: () => request<{ rules: RuleConfig[] }>("/api/v1/rules"),

  setRuleEnabled: (name: string, enabled: boolean) =>
    request<RuleConfig>(`/api/v1/rules/${encodeURIComponent(name)}`, {
      method: "PATCH",
      body: JSON.stringify({ enabled }),
    }),

  ipRules: () => request<{ rules: IPRule[] }>("/api/v1/ipblock"),

  addIPRule: (rule: IPRule) =>
    request<IPRule>("/api/v1/ipblock", {
      method: "POST",
      body: JSON.stringify(rule),
    }),

  deleteIPRule: (cidr: string) =>
    request<void>(`/api/v1/ipblock${query({ cidr })}`, { method: "DELETE" }),

  status: () => request<Record<string, unknown>>("/api/v1/status"),
};
