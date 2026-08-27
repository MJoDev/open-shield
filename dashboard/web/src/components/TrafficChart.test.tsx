import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { TrafficChart } from "./TrafficChart";
import type { Bucket } from "../types";

// The chart is the overview screen's headline. Its failure modes are quiet:
// an empty series that renders as a blank rectangle looks like a broken
// dashboard, and a chart with no table view is unreadable to anyone using a
// screen reader — which for a tool an operator lives in is not a detail.

function bucket(start: string, allowed: number, blocked: number): Bucket {
  return { start, allowed, blocked };
}

const series = [
  bucket("2026-08-25T11:00:00Z", 120, 4),
  bucket("2026-08-25T11:05:00Z", 98, 0),
  bucket("2026-08-25T11:10:00Z", 143, 21),
];

describe("TrafficChart", () => {
  it("says so when there is no traffic instead of drawing an empty box", () => {
    render(<TrafficChart series={[]} window="1h" />);

    expect(screen.getByText(/Sin tráfico registrado/)).toBeInTheDocument();
    expect(screen.queryByRole("img")).not.toBeInTheDocument();
  });

  it("draws the series with an accessible description", () => {
    render(<TrafficChart series={series} window="1h" />);

    const chart = screen.getByRole("img");
    expect(chart).toHaveAttribute("aria-label", expect.stringContaining("1h"));
  });

  it("labels both series", () => {
    render(<TrafficChart series={series} window="1h" />);

    // Colour alone never carries identity here: blue and red were chosen over
    // green and red for deuteranopia, and the legend carries it regardless.
    expect(screen.getByText("Permitidas")).toBeInTheDocument();
    expect(screen.getByText("Bloqueadas")).toBeInTheDocument();
  });

  it("offers the same data as a table", async () => {
    const user = userEvent.setup();
    render(<TrafficChart series={series} window="1h" />);

    await user.click(screen.getByRole("button", { name: "Ver tabla" }));

    const table = screen.getByRole("table");
    expect(table).toBeInTheDocument();
    expect(screen.getByText("143")).toBeInTheDocument();
    expect(screen.getByText("21")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Ver gráfico" }));
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
  });

  // A window in which nothing happened is a normal state for a freshly
  // installed proxy, and dividing by a zero maximum would render NaN
  // coordinates that silently produce an invisible chart.
  it("renders a series that is entirely zeroes", () => {
    const quiet = [bucket("2026-08-25T11:00:00Z", 0, 0), bucket("2026-08-25T11:05:00Z", 0, 0)];

    const { container } = render(<TrafficChart series={quiet} window="1h" />);

    expect(screen.getByRole("img")).toBeInTheDocument();
    expect(container.innerHTML).not.toContain("NaN");
  });

  it("renders a single bucket", () => {
    const { container } = render(
      <TrafficChart series={[bucket("2026-08-25T11:00:00Z", 5, 1)]} window="5m" />,
    );

    expect(screen.getByRole("img")).toBeInTheDocument();
    expect(container.innerHTML).not.toContain("NaN");
    expect(container.innerHTML).not.toContain("Infinity");
  });

  it("survives a spike without producing invalid geometry", () => {
    const spike = [
      bucket("2026-08-25T11:00:00Z", 1, 0),
      bucket("2026-08-25T11:05:00Z", 0, 250_000),
    ];

    const { container } = render(<TrafficChart series={spike} window="1h" />);

    expect(container.innerHTML).not.toContain("NaN");
    expect(container.innerHTML).not.toContain("-Infinity");
  });
});
