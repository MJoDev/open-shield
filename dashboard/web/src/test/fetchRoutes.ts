import { vi } from "vitest";

type Handler = (
  url: URL,
  init?: RequestInit,
) =>
  | { status: number; body?: unknown }
  | Promise<{ status: number; body?: unknown }>;

/**
 * Stubs fetch with a table of path → handler, so a view test says what the
 * API answers without caring about the order of calls. An unrouted path fails
 * the test loudly instead of hanging.
 */
export function routeFetch(routes: Record<string, Handler>) {
  const fetch = vi.fn(async (input: string, init?: RequestInit) => {
    const url = new URL(input, "http://localhost");
    const handler = routes[`${init?.method ?? "GET"} ${url.pathname}`];
    if (!handler)
      throw new Error(
        `unrouted request: ${init?.method ?? "GET"} ${url.pathname}`,
      );
    const { status, body } = await handler(url, init);
    return {
      ok: status >= 200 && status < 300,
      status,
      json: async () => body,
    } as unknown as Response;
  });
  vi.stubGlobal("fetch", fetch);
  return fetch;
}
