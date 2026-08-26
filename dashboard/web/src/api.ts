import type {
  EventsPage,
  IPRule,
  RuleConfig,
  Stats,
  VerifyResult,
} from "./types";

/** Thrown for any non-2xx response, carrying the API's own error message. */
export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    // The session lives in an HttpOnly cookie, so it has to be sent explicitly
    // — and it is never readable from here, which is the point.
    credentials: "same-origin",
    headers: init?.body ? { "Content-Type": "application/json" } : undefined,
    ...init,
  });

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

  logout: () => request<{ status: string }>("/api/v1/logout", { method: "POST" }),

  events: (params: {
    kind?: string;
    verdict?: string;
    ip?: string;
    rule?: string;
    limit?: number;
    offset?: number;
  }) => request<EventsPage>(`/api/v1/events${query(params)}`),

  stats: (window: string) =>
    request<Stats>(`/api/v1/stats${query({ window })}`),

  verify: (params: { from?: string; to?: string }) =>
    request<VerifyResult>(`/api/v1/audit/verify${query(params)}`),

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
