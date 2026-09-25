import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Rules } from "./Rules";
import { routeFetch } from "../test/fetchRoutes";

const RULES = {
  rules: [
    { name: "sqli", enabled: true, updated_at: "2026-08-25T12:00:00Z" },
    { name: "xss", enabled: true, updated_at: "2026-08-25T12:00:00Z" },
  ],
};

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("Rules", () => {
  it("does not claim the access list is empty before it has loaded", () => {
    routeFetch({
      "GET /api/v1/rules": () => new Promise(() => {}),
      "GET /api/v1/ipblock": () => new Promise(() => {}),
    });

    render(<Rules />);

    expect(screen.queryByText(/La lista está vacía/)).not.toBeInTheDocument();
  });

  // The API logs an administrative change before applying it and refuses with
  // 503 when it cannot (§6.1). The toggle must stay where the server left it,
  // and the screen must say the change did not happen.
  it("keeps a refused toggle in its confirmed state and says why", async () => {
    const user = userEvent.setup();
    let release: () => void = () => {};
    routeFetch({
      "GET /api/v1/rules": () => ({ status: 200, body: RULES }),
      "GET /api/v1/ipblock": () => ({ status: 200, body: { rules: [] } }),
      "PATCH /api/v1/rules/sqli": () =>
        new Promise((resolve) => {
          release = () =>
            resolve({
              status: 503,
              body: {
                error:
                  "the change was not applied because it could not be recorded",
              },
            });
        }),
    });

    render(<Rules />);
    const toggle = await screen.findByRole("button", { name: "Regla sqli" });
    expect(toggle).toHaveAttribute("aria-pressed", "true");

    await user.click(toggle);

    // In flight: busy, and still showing the confirmed state — not optimistic.
    expect(toggle).toBeDisabled();
    expect(toggle).toHaveTextContent("Guardando…");
    expect(toggle).toHaveAttribute("aria-pressed", "true");

    release();

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "El cambio no se aplicó: no se pudo registrar en la auditoría.",
    );
    await waitFor(() => expect(toggle).not.toBeDisabled());
    expect(toggle).toHaveAttribute("aria-pressed", "true");
    expect(toggle).toHaveTextContent("Activa");
  });

  it("shows the state the server confirmed after a toggle", async () => {
    const user = userEvent.setup();
    routeFetch({
      "GET /api/v1/rules": () => ({ status: 200, body: RULES }),
      "GET /api/v1/ipblock": () => ({ status: 200, body: { rules: [] } }),
      "PATCH /api/v1/rules/xss": () => ({
        status: 200,
        body: {
          name: "xss",
          enabled: false,
          updated_at: "2026-08-25T12:05:00Z",
          updated_by: "admin",
        },
      }),
    });

    render(<Rules />);
    const toggle = await screen.findByRole("button", { name: "Regla xss" });
    await user.click(toggle);

    await waitFor(() =>
      expect(toggle).toHaveAttribute("aria-pressed", "false"),
    );
    expect(screen.getByText("xss desactivada.")).toHaveAttribute(
      "role",
      "status",
    );
    expect(screen.getByText(/Modificada por admin/)).toBeInTheDocument();
  });

  it("names the target of an unblock for assistive technology", async () => {
    routeFetch({
      "GET /api/v1/rules": () => ({ status: 200, body: RULES }),
      "GET /api/v1/ipblock": () => ({
        status: 200,
        body: { rules: [{ cidr: "203.0.113.0/24", action: "deny" }] },
      }),
    });

    render(<Rules />);

    const button = await screen.findByRole("button", {
      name: "Desbloquear 203.0.113.0/24",
    });
    expect(button).toHaveTextContent("Desbloquear");
  });
});
