import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { EventTable } from "./EventTable";
import type { AuditEntry } from "../types";

// This table is where an operator reads the forensic log. Two things it does
// are worth protecting: it renders payloads that are attacker-controlled, and
// it is the only place the hashes of an entry are visible — which is what makes
// a "chain broken at X" report something a person can act on.

function traffic(over: Partial<AuditEntry> = {}): AuditEntry {
  return {
    id: "0f8fad5b-d9cb-469f-a165-70867728950e",
    request_id: "req-1",
    timestamp: "2026-08-25T12:00:00Z",
    kind: "traffic",
    payload: {
      ip: "203.0.113.7",
      method: "GET",
      path: "/buscar",
      query: "q=zapatos",
      verdict: "block",
      rule: "sqli",
      reason: 'sqli signature "union_select" matched in query',
    },
    prev_hash: "a".repeat(64),
    hash: "b".repeat(64),
    ...over,
  };
}

describe("EventTable", () => {
  it("says so when there is nothing to show", () => {
    render(<EventTable entries={[]} />);

    // An empty table with headers reads as "loading" or "broken". A sentence
    // reads as "nothing happened", which is usually the truth.
    expect(screen.getByText("Sin registros.")).toBeInTheDocument();
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
  });

  it("accepts a caller's own empty message", () => {
    render(<EventTable entries={[]} empty="Sin bloqueos en esta ventana." />);

    expect(screen.getByText("Sin bloqueos en esta ventana.")).toBeInTheDocument();
  });

  it("renders a blocked request with its source and rule", () => {
    render(<EventTable entries={[traffic()]} />);

    expect(screen.getByText("203.0.113.7")).toBeInTheDocument();
    expect(screen.getByText("bloqueada")).toBeInTheDocument();
    expect(screen.getByText("sqli")).toBeInTheDocument();
    expect(screen.getByText("GET /buscar?q=zapatos")).toBeInTheDocument();
  });

  it("renders an allowed request without a rule", () => {
    const allowed = traffic({
      id: "allowed-1",
      payload: { ip: "198.51.100.4", method: "GET", path: "/", verdict: "allow" },
    });

    render(<EventTable entries={[allowed]} />);

    expect(screen.getByText("permitida")).toBeInTheDocument();
    expect(screen.queryByText("sqli")).not.toBeInTheDocument();
  });

  // §6.1 puts administrative access on the same chain as traffic, so the table
  // has to render an entry that has no method, no path and no verdict without
  // showing "undefined undefined".
  it("renders an administrative entry", () => {
    const admin = traffic({
      id: "admin-1",
      kind: "admin",
      payload: { actor: "admin", action: "rule.set_enabled", rule: "xss" },
    });

    render(<EventTable entries={[admin]} />);

    expect(screen.getByText("admin")).toBeInTheDocument();
    // The action stands in for both the request line and the verdict, so it
    // legitimately appears in two cells.
    expect(screen.getAllByText("rule.set_enabled").length).toBeGreaterThan(0);
    expect(screen.queryByText(/undefined/)).not.toBeInTheDocument();
  });

  it("does not render undefined for a payload with nothing in it", () => {
    const bare = traffic({ id: "bare-1", payload: {} });

    render(<EventTable entries={[bare]} />);

    expect(screen.queryByText(/undefined/)).not.toBeInTheDocument();
    expect(screen.queryByText(/NaN/)).not.toBeInTheDocument();
  });

  // The hashes are the reason this is a forensic log rather than a list. When
  // verification reports "broken at <id>", this row is where the operator
  // confirms what it is pointing at.
  it("shows the hashes and the request id when a row is expanded", async () => {
    const user = userEvent.setup();
    render(<EventTable entries={[traffic()]} />);

    expect(screen.queryByText("b".repeat(64))).not.toBeInTheDocument();

    await user.click(screen.getByText("GET /buscar?q=zapatos"));

    expect(screen.getByText("b".repeat(64))).toBeInTheDocument();
    expect(screen.getByText("a".repeat(64))).toBeInTheDocument();
    expect(screen.getByText("req-1")).toBeInTheDocument();
  });

  it("collapses a row that is clicked again", async () => {
    const user = userEvent.setup();
    render(<EventTable entries={[traffic()]} />);

    const row = screen.getByText("GET /buscar?q=zapatos");
    await user.click(row);
    expect(screen.getByText("b".repeat(64))).toBeInTheDocument();

    await user.click(row);
    expect(screen.queryByText("b".repeat(64))).not.toBeInTheDocument();
  });

  it("keeps only one row expanded at a time", async () => {
    const user = userEvent.setup();
    const first = traffic({ id: "first", hash: "1".repeat(64) });
    const second = traffic({
      id: "second",
      hash: "2".repeat(64),
      payload: { ...traffic().payload, path: "/productos" },
    });

    render(<EventTable entries={[first, second]} />);

    await user.click(screen.getByText("GET /buscar?q=zapatos"));
    expect(screen.getByText("1".repeat(64))).toBeInTheDocument();

    await user.click(screen.getByText("GET /productos?q=zapatos"));
    expect(screen.getByText("2".repeat(64))).toBeInTheDocument();
    expect(screen.queryByText("1".repeat(64))).not.toBeInTheDocument();
  });

  // The single most important property of this component. Every row carries
  // strings an attacker chose: paths, query strings, the excerpt of the payload
  // that triggered the block. React escapes them, and this is the test that
  // notices the day somebody reaches for dangerouslySetInnerHTML.
  it("renders an attacker's payload as text, never as markup", async () => {
    const user = userEvent.setup();
    const xss = traffic({
      id: "xss-1",
      payload: {
        ip: "203.0.113.7",
        method: "GET",
        path: "/buscar",
        query: "q=<script>alert(1)</script>",
        verdict: "block",
        rule: "xss",
        reason: '<img src=x onerror="alert(1)">',
      },
    });

    const { container } = render(<EventTable entries={[xss]} />);

    expect(container.querySelector("script")).toBeNull();
    expect(container.querySelector("img")).toBeNull();
    expect(
      screen.getByText("GET /buscar?q=<script>alert(1)</script>"),
    ).toBeInTheDocument();

    await user.click(screen.getByText("GET /buscar?q=<script>alert(1)</script>"));
    expect(container.querySelector("script")).toBeNull();
    expect(container.querySelector("img")).toBeNull();
  });

  // A row that opens only on a mouse click locks keyboard users out of the
  // hashes and the request ID — the forensic half of the table.
  it("expands a row from the keyboard", async () => {
    const user = userEvent.setup();
    render(<EventTable entries={[traffic()]} />);

    const row = screen.getByText("GET /buscar?q=zapatos").closest("tr")!;
    expect(row).toHaveAttribute("aria-expanded", "false");

    row.focus();
    await user.keyboard("{Enter}");
    expect(row).toHaveAttribute("aria-expanded", "true");
    expect(screen.getByText("b".repeat(64))).toBeInTheDocument();

    await user.keyboard(" ");
    expect(screen.queryByText("b".repeat(64))).not.toBeInTheDocument();
  });

  it("offers the request id for copying without collapsing the row", async () => {
    const user = userEvent.setup();
    render(<EventTable entries={[traffic()]} />);

    await user.click(screen.getByText("GET /buscar?q=zapatos"));
    await user.click(screen.getByRole("button", { name: "Copiar ID de petición" }));

    expect(screen.getByText("req-1")).toBeInTheDocument();
    expect(await screen.findByText("Copiado")).toBeInTheDocument();
  });
});
