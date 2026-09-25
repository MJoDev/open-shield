import { useEffect, useState } from "react";
import { api, isAbort } from "../api";
import { EventTable } from "../components/EventTable";
import {
  ErrorBanner,
  InlineStatus,
  LoadingText,
  Skeleton,
} from "../components/Feedback";
import { TrafficChart } from "../components/TrafficChart";
import { describeError, type Problem } from "../errors";
import { useLoadPhase } from "../hooks";
import { useLiveEvents, type ConnectionState } from "../useLiveEvents";
import type { Stats } from "../types";

// `span` is the window as it reads inside a sentence: "en la última hora",
// not "en las últimas 1 hora".
const WINDOWS = [
  { value: "1h", label: "1 hora", span: "la última hora" },
  { value: "6h", label: "6 horas", span: "las últimas 6 horas" },
  { value: "24h", label: "24 horas", span: "las últimas 24 horas" },
];

// The live feed updates the event list instantly; the aggregates behind it
// only need to be roughly current.
const STATS_POLL_MS = 15_000;

export function Live() {
  const { events, state } = useLiveEvents(true);
  const [stats, setStats] = useState<Stats | null>(null);
  const [range, setRange] = useState("1h");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<Problem | null>(null);
  const [reloads, setReloads] = useState(0);

  useEffect(() => {
    let controller: AbortController | null = null;

    // Only a load the operator caused — first paint, a new window, a retry —
    // dims the screen. The background poll replaces numbers silently; dimming
    // the whole view every fifteen seconds would read as constant trouble.
    const load = async (visible: boolean) => {
      controller?.abort();
      const current = new AbortController();
      controller = current;
      if (visible) setLoading(true);

      try {
        const next = await api.stats(range, { signal: current.signal });
        setStats(next);
        setError(null);
      } catch (err) {
        if (isAbort(err)) return;
        setError(describeError(err, "No se pudieron cargar las estadísticas."));
      } finally {
        if (!current.signal.aborted) setLoading(false);
      }
    };

    load(true);
    const timer = setInterval(() => load(false), STATS_POLL_MS);
    return () => {
      controller?.abort();
      clearInterval(timer);
    };
  }, [range, reloads]);

  const phase = useLoadPhase(loading, stats !== null);
  const rangeSpan = WINDOWS.find((w) => w.value === range)?.span ?? range;

  const blockedShare =
    stats && stats.total > 0
      ? `${((stats.blocked / stats.total) * 100).toLocaleString("es-VE", {
          minimumFractionDigits: 1,
          maximumFractionDigits: 1,
        })} %`
      : "0 %";

  // Every region fed by the stats call shares one loading treatment.
  const region = [
    "refreshable",
    phase.refreshing && "is-refreshing",
    phase.placeholder && !phase.skeleton && "is-pending",
  ]
    .filter(Boolean)
    .join(" ");

  return (
    <div className="view">
      <div className="view-head">
        <h2>En vivo</h2>
        <div className="controls">
          {phase.refreshing && <InlineStatus>Actualizando…</InlineStatus>}
          <ConnectionPill state={state} />
          <select
            value={range}
            onChange={(e) => setRange(e.target.value)}
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

      {error && (
        <ErrorBanner problem={error} onRetry={() => setReloads((n) => n + 1)} />
      )}

      <div className={`tiles ${region}`} aria-busy={loading}>
        {phase.placeholder && <LoadingText>Cargando estadísticas…</LoadingText>}
        <Tile label="Peticiones" value={stats?.total} />
        <Tile label="Permitidas" value={stats?.allowed} tone="allow" />
        <Tile label="Bloqueadas" value={stats?.blocked} tone="block" />
        <Tile
          label="Tasa de bloqueo"
          value={stats ? blockedShare : undefined}
        />
      </div>

      <section className={`panel ${region}`} aria-busy={loading}>
        <h3>Tráfico</h3>
        {stats ? (
          <TrafficChart series={stats.series ?? []} window={rangeSpan} />
        ) : phase.placeholder ? (
          // Same rows as the real chart — legend, then plot — so nothing
          // below it moves when the data lands.
          <div className="chart" aria-hidden="true">
            <div className="chart-head chart-head-pending">
              <Skeleton className="skeleton-inline" />
            </div>
            <Skeleton className="skeleton-chart" />
          </div>
        ) : (
          <p className="chart-empty">Estadísticas no disponibles.</p>
        )}
      </section>

      <div className="two-column">
        <section className={`panel ${region}`} aria-busy={loading}>
          <h3>IP más bloqueadas</h3>
          <RankList
            rows={stats?.top_ips}
            loading={phase.placeholder}
            empty={`Ninguna IP bloqueada en ${rangeSpan}.`}
          />
        </section>
        <section className={`panel ${region}`} aria-busy={loading}>
          <h3>Reglas que más disparan</h3>
          <RankList
            rows={stats?.top_rules}
            loading={phase.placeholder}
            empty={`Ninguna regla ha bloqueado en ${rangeSpan}.`}
          />
        </section>
      </div>

      <section className="panel" aria-label="Decisiones en tiempo real">
        <h3>
          Decisiones en tiempo real
          <span className="counter">{events.length}</span>
        </h3>
        <EventTable entries={events} empty={FEED_EMPTY[state]} />
      </section>
    </div>
  );
}

// An empty feed means three different things, and only one of them is "no
// traffic". Saying which is the whole point of the connection state.
const FEED_EMPTY: Record<ConnectionState, string> = {
  connecting: "Conectando con el feed en vivo…",
  open: "Conectado. Esperando tráfico…",
  closed: "Sin conexión con el feed en vivo. Reintentando…",
};

function Tile({
  label,
  value,
  tone,
}: {
  label: string;
  value: number | string | undefined;
  tone?: "allow" | "block";
}) {
  return (
    <div className={`tile${tone ? ` tile-${tone}` : ""}`}>
      <span className="tile-label">{label}</span>
      {value === undefined ? (
        <Skeleton className="skeleton-value" />
      ) : (
        <span className="tile-value">
          {typeof value === "number" ? value.toLocaleString("es-VE") : value}
        </span>
      )}
    </div>
  );
}

function RankList({
  rows,
  loading,
  empty,
}: {
  rows: { label: string; count: number }[] | null | undefined;
  loading: boolean;
  empty: string;
}) {
  if (!rows && loading) {
    return (
      <ul className="rank-list" aria-hidden="true">
        {[70, 45, 30].map((width) => (
          <li key={width}>
            <Skeleton />
            <span className="rank-bar">
              <span
                className="rank-fill rank-fill-pending"
                style={{ width: `${width}%` }}
              />
            </span>
            <Skeleton />
          </li>
        ))}
      </ul>
    );
  }

  if (!rows || rows.length === 0) return <p className="muted">{empty}</p>;

  const max = Math.max(...rows.map((r) => r.count));
  return (
    <ul className="rank-list">
      {rows.map((row) => (
        <li key={row.label}>
          <span className="rank-label mono" title={row.label}>
            {row.label}
          </span>
          <span className="rank-bar" aria-hidden="true">
            <span
              className="rank-fill"
              style={{ width: `${(row.count / max) * 100}%` }}
            />
          </span>
          <span className="rank-count num">
            {row.count.toLocaleString("es-VE")}
          </span>
        </li>
      ))}
    </ul>
  );
}

function ConnectionPill({ state }: { state: ConnectionState }) {
  const label =
    state === "open"
      ? "Conectado"
      : state === "connecting"
        ? "Conectando…"
        : "Reconectando…";
  // role="status": a dropped feed is announced, not just recoloured.
  return (
    <span className={`pill pill-${state}`} role="status">
      <span className="pill-dot" aria-hidden="true" />
      {label}
    </span>
  );
}
