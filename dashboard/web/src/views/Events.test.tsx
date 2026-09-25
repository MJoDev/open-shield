import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Events } from "./Events";
import { routeFetch } from "../test/fetchRoutes";
import type { AuditEntry } from "../types";

function entry(id: string, ip = "203.0.113.7"): AuditEntry {
  return {
    id,
    request_id: `req-${id}`,
    timestamp: "2026-08-25T12:00:00Z",
    kind: "traffic",
    payload: { ip, method: "GET", path: `/p/${id}`, verdict: "allow" },
    prev_hash: "0".repeat(64),
    hash: `hash-${id}`,
  };
}

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe("Events", () => {
  it("never shows the empty message while the first page is loading", async () => {
    let answer: (value: { status: number; body: unknown }) => void = () => {};
    routeFetch({
      "GET /api/v1/events": () => new Promise((resolve) => (answer = resolve)),
    });

    render(<Events />);

    // Empty ≠ loading: "the log is empty" before the answer is a false claim.
    expect(screen.queryByText(/está vacío/)).not.toBeInTheDocument();
    expect(
      screen.getByRole("region", { name: "Entradas del registro" }),
    ).toHaveAttribute("aria-busy", "true");

    answer({
      status: 200,
      body: { entries: [entry("a")], total: 1, limit: 50, offset: 0 },
    });
    expect(await screen.findByText("GET /p/a")).toBeInTheDocument();
  });

  it("offers to clear the filters when they match nothing", async () => {
    const user = userEvent.setup();
    const fetch = routeFetch({
      "GET /api/v1/events": (url) => ({
        status: 200,
        body: url.searchParams.get("verdict")
          ? { entries: [], total: 0, limit: 50, offset: 0 }
          : { entries: [entry("a")], total: 1, limit: 50, offset: 0 },
      }),
    });

    render(<Events />);
    await screen.findByText("GET /p/a");

    await user.selectOptions(screen.getByLabelText("Resultado"), "block");
    expect(
      await screen.findByText("Ninguna entrada coincide con estos filtros."),
    ).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Limpiar filtros" }));
    expect(await screen.findByText("GET /p/a")).toBeInTheDocument();
    expect(fetch).toHaveBeenCalledTimes(3);
  });

  // One request per keystroke is a small denial of service against the
  // operator's own API, and the answers can land out of order.
  it("waits for the IP filter to settle before querying", async () => {
    const user = userEvent.setup();
    const fetch = routeFetch({
      "GET /api/v1/events": () => ({
        status: 200,
        body: { entries: [], total: 0, limit: 50, offset: 0 },
      }),
    });

    render(<Events />);
    await waitFor(() => expect(fetch).toHaveBeenCalledTimes(1));

    await user.type(screen.getByLabelText("IP de origen"), "203.0.113.7");
    await waitFor(() => expect(fetch).toHaveBeenCalledTimes(2));

    const [url] = fetch.mock.calls[1] as unknown as [string];
    expect(url).toContain("ip=203.0.113.7");
  });

  it("keeps the last page on screen when a refresh fails, and offers a retry", async () => {
    const user = userEvent.setup();
    let fail = false;
    routeFetch({
      "GET /api/v1/events": () =>
        fail
          ? { status: 500, body: { error: "list events failed" } }
          : {
              status: 200,
              body: { entries: [entry("a")], total: 1, limit: 50, offset: 0 },
            },
    });

    render(<Events />);
    await screen.findByText("GET /p/a");

    fail = true;
    await user.click(screen.getByRole("button", { name: "Actualizar" }));

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(
      "No se pudo cargar el registro de auditoría.",
    );
    expect(alert).toHaveTextContent("list events failed (HTTP 500)");
    expect(screen.getByText("GET /p/a")).toBeInTheDocument();

    fail = false;
    await user.click(screen.getByRole("button", { name: "Reintentar" }));
    await waitFor(() =>
      expect(screen.queryByRole("alert")).not.toBeInTheDocument(),
    );
  });
});
