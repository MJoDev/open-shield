import { describe, expect, it, vi } from "vitest";
import { api, ApiError, isAbort, setUnauthorizedHandler } from "./api";

// This module is the whole surface between the dashboard and its API. Two
// things about it are load-bearing and neither is obvious from reading it: the
// session cookie has to be sent on every request, and a non-2xx response has to
// arrive at the caller as an error carrying the API's own message rather than
// as a resolved promise holding an error object.

function stubFetch(status: number, body: unknown, init: { json?: boolean } = {}) {
  const fetch = vi.fn(async () =>
    ({
      ok: status >= 200 && status < 300,
      status,
      json: async () => {
        if (init.json === false) throw new Error("not json");
        return body;
      },
    }) as unknown as Response,
  );
  vi.stubGlobal("fetch", fetch);
  return fetch;
}

describe("api", () => {
  it("sends the session cookie on every request", async () => {
    const fetch = stubFetch(200, { user: "admin" });

    await api.session();

    const [, init] = fetch.mock.calls[0] as unknown as [string, RequestInit];
    // The session lives in an HttpOnly cookie — unreadable from here, which is
    // the point — so it only travels if credentials are asked for explicitly.
    expect(init.credentials).toBe("same-origin");
  });

  it("raises the API's own message on a failure", async () => {
    stubFetch(401, { error: "invalid credentials" });

    await expect(api.login("admin", "guess")).rejects.toThrow(ApiError);
    await expect(api.login("admin", "guess")).rejects.toThrow("invalid credentials");
  });

  it("carries the status code on the error", async () => {
    stubFetch(503, { error: "the change was not applied" });

    // 503 is what the dashboard answers when a change could not be recorded in
    // the audit log. The screen has to be able to tell that apart from a
    // rejected input, so the status has to survive.
    await expect(api.setRuleEnabled("sqli", false)).rejects.toMatchObject({
      status: 503,
      message: "the change was not applied",
    });
  });

  it("falls back to a readable message when the body is not JSON", async () => {
    stubFetch(500, null, { json: false });

    await expect(api.status()).rejects.toThrow(/500/);
  });

  it("treats 204 as success with no body", async () => {
    stubFetch(204, undefined);

    // Deleting an access-list entry answers 204. Parsing that as JSON would
    // throw, and the entry would look like it had failed to delete when it had
    // not.
    await expect(api.deleteIPRule("203.0.113.0/24")).resolves.toBeUndefined();
  });

  it("omits empty filters from the query string", async () => {
    const fetch = stubFetch(200, { entries: [], total: 0, limit: 50, offset: 0 });

    await api.events({ verdict: "block", ip: "", rule: undefined, limit: 25 });

    const [url] = fetch.mock.calls[0] as unknown as [string];
    expect(url).toContain("verdict=block");
    expect(url).toContain("limit=25");
    // An empty filter must not become ip= — the API would read that as a
    // filter for the empty string and return nothing.
    expect(url).not.toContain("ip=");
    expect(url).not.toContain("rule=");
  });

  it("builds no query string when there is nothing to filter by", async () => {
    const fetch = stubFetch(200, { entries: [], total: 0, limit: 50, offset: 0 });

    await api.events({});

    const [url] = fetch.mock.calls[0] as unknown as [string];
    expect(url).toBe("/api/v1/events");
  });

  it("escapes a rule name in the path", async () => {
    const fetch = stubFetch(200, { name: "sqli", enabled: false });

    await api.setRuleEnabled("../admin", false);

    const [url] = fetch.mock.calls[0] as unknown as [string];
    // The name reaches a path segment. Leaving it unescaped would let a value
    // from the rules list rewrite which endpoint is called.
    expect(url).not.toContain("../");
    expect(url).toContain("%2F");
  });

  it("passes the CIDR as a parameter rather than a path segment", async () => {
    const fetch = stubFetch(204, undefined);

    await api.deleteIPRule("203.0.113.0/24");

    const [url] = fetch.mock.calls[0] as unknown as [string];
    // A CIDR contains a slash, which is why this endpoint takes a query
    // parameter at all.
    expect(url).toContain("cidr=203.0.113.0%2F24");
  });

  it("sets the JSON content type only when there is a body", async () => {
    const withBody = stubFetch(200, {});
    await api.login("admin", "x");
    const [, init] = withBody.mock.calls[0] as unknown as [string, RequestInit];
    expect(init.headers).toMatchObject({ "Content-Type": "application/json" });

    const withoutBody = stubFetch(200, {});
    await api.rules();
    const [, getInit] = withoutBody.mock.calls[0] as unknown as [string, RequestInit];
    expect(getInit.headers).toBeUndefined();
  });

  // A request the server never answers must end. A spinner that never stops
  // is indistinguishable from a working one, and hides the outage.
  it("gives up after the timeout and says so", async () => {
    vi.useFakeTimers();
    vi.stubGlobal("fetch", hangingFetch());

    const call = api.rules();
    const assertion = expect(call).rejects.toMatchObject({
      status: 0,
      timedOut: true,
    });
    await vi.advanceTimersByTimeAsync(15_000);
    await assertion;
    vi.useRealTimers();
  });

  it("passes a caller's own cancellation through as an abort", async () => {
    vi.stubGlobal("fetch", hangingFetch());
    const controller = new AbortController();

    const call = api.events({}, { signal: controller.signal });
    controller.abort();

    // An abort is how a view drops a stale request; it must be recognisable
    // so the view can ignore it rather than report it as a failure.
    const err = await call.catch((e: unknown) => e);
    expect(isAbort(err)).toBe(true);
  });

  it("reports an unreachable server as status 0, not as a thrown TypeError", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new TypeError("Failed to fetch");
      }),
    );

    await expect(api.rules()).rejects.toMatchObject({ status: 0, timedOut: false });
  });

  // An expired session must send the operator to the sign-in screen from
  // anywhere, instead of each screen showing "no session".
  it("reports an expired session on a signed-in call", async () => {
    const expired = vi.fn();
    setUnauthorizedHandler(expired);
    stubFetch(401, { error: "no session" });

    await expect(api.rules()).rejects.toThrow(ApiError);
    expect(expired).toHaveBeenCalledOnce();
    setUnauthorizedHandler(null);
  });

  // On these two a 401 is the answer itself — wrong password, or not signed in
  // yet — and treating it as an expiry would show "session expired" to
  // someone who never had one.
  it("does not treat a failed sign-in or session probe as an expiry", async () => {
    const expired = vi.fn();
    setUnauthorizedHandler(expired);
    stubFetch(401, { error: "invalid credentials" });

    await expect(api.login("admin", "guess")).rejects.toThrow();
    await expect(api.session()).rejects.toThrow();
    expect(expired).not.toHaveBeenCalled();
    setUnauthorizedHandler(null);
  });
});

/** A fetch that never answers, but honours its abort signal like the real one. */
function hangingFetch() {
  return vi.fn(
    (_url: string, init?: RequestInit) =>
      new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () =>
          reject(new DOMException("The operation was aborted.", "AbortError")),
        );
      }),
  );
}
