import { act, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Live } from "./Live";
import { routeFetch } from "../test/fetchRoutes";
import { FakeSocket, installFakeSocket } from "../test/fakeSocket";

beforeEach(() => {
  installFakeSocket();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("Live", () => {
  // Before the first answer the numbers are unknown, not zero. "0 peticiones"
  // and "sin tráfico" on a slow load would tell the operator the site is dead.
  it("does not show zeros or an empty chart before the stats arrive", () => {
    routeFetch({ "GET /api/v1/stats": () => new Promise(() => {}) });

    const { container } = render(<Live />);

    // The feed counter legitimately reads 0; the stat tiles must read nothing.
    expect(container.querySelectorAll(".tile-value")).toHaveLength(0);
    expect(
      screen.queryByText(/Sin tráfico registrado/),
    ).not.toBeInTheDocument();
    expect(screen.queryByText(/Ninguna IP bloqueada/)).not.toBeInTheDocument();
  });

  it("shows the stats once they arrive", async () => {
    routeFetch({
      "GET /api/v1/stats": () => ({
        status: 200,
        body: {
          window: "1h",
          total: 1200,
          allowed: 1000,
          blocked: 200,
          top_ips: [],
          top_rules: [],
          series: [],
        },
      }),
    });

    render(<Live />);

    expect(await screen.findByText("16,7 %")).toBeInTheDocument();
    expect(
      screen.getByText("Ninguna IP bloqueada en la última hora."),
    ).toBeInTheDocument();
  });

  // An empty feed means "connecting", "idle" or "broken", and only one of
  // those is good news.
  it("says why the live feed is empty", () => {
    routeFetch({ "GET /api/v1/stats": () => new Promise(() => {}) });

    render(<Live />);
    expect(
      screen.getByText("Conectando con el feed en vivo…"),
    ).toBeInTheDocument();

    act(() => FakeSocket.latest().open());
    expect(
      screen.getByText("Conectado. Esperando tráfico…"),
    ).toBeInTheDocument();

    act(() => FakeSocket.latest().drop());
    expect(
      screen.getByText("Sin conexión con el feed en vivo. Reintentando…"),
    ).toBeInTheDocument();
    expect(screen.getByRole("status")).toHaveTextContent("Reconectando…");
  });
});
