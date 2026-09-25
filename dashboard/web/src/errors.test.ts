import { describe, expect, it } from "vitest";
import { ApiError } from "./api";
import { describeError } from "./errors";

describe("describeError", () => {
  // §6.1: an administrative change whose audit entry cannot be written is
  // refused. The operator has to read "it did not happen", not a generic
  // failure they might retry assuming half of it went through.
  it("names a refused administrative change for what it is", () => {
    const problem = describeError(
      new ApiError(
        "the change was not applied because it could not be recorded",
        503,
      ),
      "No se pudo cambiar la regla sqli.",
      { mutation: true },
    );

    expect(problem.title).toBe(
      "El cambio no se aplicó: no se pudo registrar en la auditoría.",
    );
    expect(problem.detail).toContain("HTTP 503");
  });

  it("does not claim a change was refused when a read failed", () => {
    const problem = describeError(
      new ApiError("engine unavailable", 503),
      "No se pudieron cargar las reglas.",
    );

    expect(problem.title).toBe("No se pudieron cargar las reglas.");
    expect(problem.detail).toBe("engine unavailable (HTTP 503)");
  });

  it("puts the human sentence first and the API's message after", () => {
    const problem = describeError(
      new ApiError("list failed", 500),
      "Algo falló.",
    );

    expect(problem).toEqual({
      title: "Algo falló.",
      detail: "list failed (HTTP 500)",
    });
  });

  it("says a timeout is a timeout", () => {
    const problem = describeError(
      new ApiError("sin respuesta tras 15 s", 0, true),
      "No se pudo cargar.",
    );

    expect(problem.detail).toMatch(/no respondió a tiempo/);
  });
});
