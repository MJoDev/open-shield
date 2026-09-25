import { fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Forensics } from "./Forensics";
import { routeFetch } from "../test/fetchRoutes";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("Forensics", () => {
  it("refuses a range that ends before it starts", () => {
    render(<Forensics />);

    fireEvent.change(screen.getByLabelText("Desde (opcional)"), {
      target: { value: "2026-08-25T12:00" },
    });
    fireEvent.change(screen.getByLabelText("Hasta (opcional)"), {
      target: { value: "2026-08-24T12:00" },
    });

    expect(screen.getByRole("alert")).toHaveTextContent(
      "«Desde» es posterior a «Hasta»",
    );
    expect(
      screen.getByRole("button", { name: "Verificar cadena" }),
    ).toBeDisabled();
  });

  // "Broken" alone is not actionable. The first question is *where*.
  it("reports where a broken chain broke", async () => {
    const user = userEvent.setup();
    routeFetch({
      "GET /api/v1/audit/verify": () => ({
        status: 200,
        body: {
          ok: false,
          checked: 1200,
          broken_at: "0f8fad5b-d9cb-469f-a165-70867728950e",
          position: 412,
          detail: "hash mismatch",
        },
      }),
    });

    render(<Forensics />);
    await user.click(screen.getByRole("button", { name: "Verificar cadena" }));

    expect(await screen.findByText("Cadena rota")).toBeInTheDocument();
    expect(
      screen.getByText("0f8fad5b-d9cb-469f-a165-70867728950e"),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Copiar ID de la entrada afectada" }),
    ).toBeInTheDocument();
  });
});
