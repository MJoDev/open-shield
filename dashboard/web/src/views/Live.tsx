import { useEffect, useState } from "react";
import { api } from "../api";
import { EventTable } from "../components/EventTable";
import { TrafficChart } from "../components/TrafficChart";
import { useLiveEvents } from "../useLiveEvents";
import type { Stats } from "../types";

const WINDOWS = [
  { value: "1h", label: "1 hora" },
  { value: "6h", label: "6 horas" },
  { value: "24h", label: "24 horas" },
];

export function Live() {
  const { events, state } = useLiveEvents(true);
  const [stats, setStats] = useState<Stats | null>(null);
  const [window, setWindow] = useState("1h");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    const load = async () => {
      try {
        const next = await api.stats(window);
        if (!cancelled) {
          setStats(next);
          setError(null);
        }
      } catch (err) {
        if (!cancelled) setError((err as Error).message);
      }
    };

    load();
    // The live feed updates the event list instantly; the aggregates behind it
    // only need to be roughly current.
    const timer = setInterval(load, 15_000);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [window]);

  const blockedShare =
    stats && stats.total > 0
      ? ((stats.blocked / stats.total) * 100).toFixed(1)
      : "0.0";

  return (
    <div className="view">
      <div className="view-head">
        <h2>En vivo</h2>
        <div className="controls">
          <ConnectionPill state={state} />
          <select
            value={window}
            onChange={(e) => setWindow(e.target.value)}
            aria-label="Ventana de tiempo"
          >
            {WINDOWS.map((w) => (
              <option key={w.value} value={w.value}>
                {w.label}
              </option>
            ))}
          </select>
        </div>
      </div>

      {error && <p className="error-banner">{error}</p>}

      <div className="tiles">
        <Tile label="Peticiones" value={stats?.total ?? 0} />
        <Tile label="Permitidas" value={stats?.allowed ?? 0} tone="allow" />
        <Tile label="Bloqueadas" value={stats?.blocked ?? 0} tone="block" />
        <Tile label="Tasa de bloqueo" value={`${blockedShare}%`} />
      </div>

      <section className="panel">
        <h3>Tráfico</h3>
        <TrafficChart
          series={stats?.series ?? []}
          window={WINDOWS.find((w) => w.value === window)?.label ?? window}
        />
      </section>

      <div className="two-column">
        <section className="panel">
          <h3>IP más bloqueadas</h3>
          <RankList rows={stats?.top_ips ?? []} empty="Ninguna todavía." />
        </section>
        <section className="panel">
          <h3>Reglas que más disparan</h3>
          <RankList rows={stats?.top_rules ?? []} empty="Ninguna todavía." />
        </section>
      </div>

      <section className="panel">
        <h3>
          Decisiones en tiempo real
          <span className="counter">{events.length}</span>
        </h3>
        <EventTable
          entries={events}
          empty={
            state === "open"
              ? "Conectado. Esperando tráfico…"
              : "Sin conexión con el feed en vivo."
          }
        />
      </section>
    </div>
  );
}

function Tile({
  label,
  value,
  tone,
}: {
  label: string;
  value: number | string;
  tone?: "allow" | "block";
}) {
  return (
    <div className={`tile${tone ? ` tile-${tone}` : ""}`}>
      <span className="tile-label">{label}</span>
      <span className="tile-value">
        {typeof value === "number" ? value.toLocaleString("es-VE") : value}
      </span>
    </div>
  );
}

function RankList({
  rows,
  empty,
}: {
  rows: { label: string; count: number }[];
  empty: string;
}) {
  if (rows.length === 0) return <p className="muted">{empty}</p>;

  const max = Math.max(...rows.map((r) => r.count));
  return (
    <ul className="rank-list">
      {rows.map((row) => (
        <li key={row.label}>
          <span className="rank-label mono">{row.label}</span>
          <span className="rank-bar">
            <span
              className="rank-fill"
              style={{ width: `${(row.count / max) * 100}%` }}
            />
          </span>
          <span className="rank-count num">{row.count}</span>
        </li>
      ))}
    </ul>
  );
}

function ConnectionPill({ state }: { state: "connecting" | "open" | "closed" }) {
  const label =
    state === "open"
      ? "Conectado"
      : state === "connecting"
        ? "Conectando…"
        : "Reconectando…";
  return (
    <span className={`pill pill-${state}`}>
      <span className="pill-dot" aria-hidden="true" />
      {label}
    </span>
  );
}
