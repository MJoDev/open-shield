import { useEffect, useRef, useState } from "react";
import { api, isAbort } from "../api";
import { EVENT_COLUMNS, EventTable } from "../components/EventTable";
import {
  ErrorBanner,
  InlineStatus,
  Skeleton,
  SkeletonTable,
} from "../components/Feedback";
import { describeError, type Problem } from "../errors";
import { useDebounced, useLoadPhase } from "../hooks";
import type { EventsPage } from "../types";

const PAGE = 50;

export function Events() {
  const [data, setData] = useState<EventsPage | null>(null);
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<Problem | null>(null);
  const [reloads, setReloads] = useState(0);

  const [kind, setKind] = useState("");
  const [verdict, setVerdict] = useState("");
  const [ip, setIp] = useState("");
  // One request when the operator stops typing, not one per keystroke.
  const ipFilter = useDebounced(ip.trim(), 300);
  const firstFilter = useRef<HTMLSelectElement>(null);

  useEffect(() => {
    // Aborting the previous request is what stops a slow answer for an old
    // filter from overwriting the answer for the current one.
    const controller = new AbortController();
    setLoading(true);

    api
      .events(
        {
          kind: kind || undefined,
          verdict: verdict || undefined,
          ip: ipFilter || undefined,
          limit: PAGE,
          offset,
        },
        { signal: controller.signal },
      )
      .then((page) => {
        setData(page);
        setError(null);
      })
      .catch((err) => {
        if (isAbort(err)) return;
        setError(
          describeError(err, "No se pudo cargar el registro de auditoría."),
        );
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });

    return () => controller.abort();
  }, [kind, verdict, ipFilter, offset, reloads]);

  const phase = useLoadPhase(loading, data !== null);
  const reload = () => setReloads((n) => n + 1);

  // Any filter change invalidates the current page number.
  const changeFilter = (apply: () => void) => {
    setOffset(0);
    apply();
  };

  const filtered = kind !== "" || verdict !== "" || ip.trim() !== "";
  const clearFilters = () => {
    changeFilter(() => {
      setKind("");
      setVerdict("");
      setIp("");
    });
    // The button that was just pressed disappears with the empty state;
    // without this, keyboard focus falls back to the top of the page.
    firstFilter.current?.focus();
  };

  const total = data?.total ?? 0;
  const page = Math.floor(offset / PAGE) + 1;
  const pages = Math.max(1, Math.ceil(total / PAGE));

  return (
    <div className="view">
      <div className="view-head">
        <div className="view-title">
          <h2>Registro de auditoría</h2>
          {data ? (
            <span className="muted num">
              {total.toLocaleString("es-VE")}{" "}
              {total === 1 ? "entrada" : "entradas"}
            </span>
          ) : (
            <Skeleton className="skeleton-inline" />
          )}
        </div>
        {phase.refreshing && <InlineStatus>Actualizando…</InlineStatus>}
      </div>

      <div className="filters">
        <label>
          Tipo
          <select
            ref={firstFilter}
            value={kind}
            onChange={(e) => changeFilter(() => setKind(e.target.value))}
          >
            <option value="">Todos</option>
            <option value="traffic">Tráfico</option>
            <option value="admin">Administración</option>
            <option value="system">Sistema</option>
          </select>
        </label>

        <label>
          Resultado
          <select
            value={verdict}
            onChange={(e) => changeFilter(() => setVerdict(e.target.value))}
          >
            <option value="">Todos</option>
            <option value="block">Bloqueadas</option>
            <option value="allow">Permitidas</option>
          </select>
        </label>

        <label>
          IP de origen
          <input
            type="text"
            inputMode="decimal"
            value={ip}
            placeholder="203.0.113.7"
            onChange={(e) => changeFilter(() => setIp(e.target.value))}
          />
        </label>

        {/* Not disabled while loading: most loads finish in a few ms and a
            button that greys out on every one of them flickers. A second click
            just supersedes the first request. */}
        <button type="button" onClick={reload} className="secondary">
          Actualizar
        </button>
      </div>

      {error && <ErrorBanner problem={error} onRetry={reload} />}

      <section
        className={
          phase.refreshing
            ? "panel refreshable is-refreshing"
            : "panel refreshable"
        }
        aria-busy={loading}
        aria-label="Entradas del registro"
      >
        {data === null ? (
          phase.placeholder ? (
            <SkeletonTable columns={EVENT_COLUMNS} pending={!phase.skeleton} />
          ) : (
            <p className="muted">No hay datos que mostrar.</p>
          )
        ) : (
          <EventTable
            entries={data.entries}
            empty={
              filtered ? (
                <div className="controls">
                  <span>Ninguna entrada coincide con estos filtros.</span>
                  <button
                    type="button"
                    className="link-button"
                    onClick={clearFilters}
                  >
                    Limpiar filtros
                  </button>
                </div>
              ) : (
                "El registro está vacío: todavía no ha pasado tráfico por el proxy."
              )
            }
          />
        )}
      </section>

      {total > PAGE && (
        <nav className="pager" aria-label="Paginación">
          <button
            type="button"
            className="secondary"
            disabled={offset === 0}
            onClick={() => setOffset(Math.max(0, offset - PAGE))}
          >
            Anterior
          </button>
          <span className="muted num">
            Página {page} de {pages}
          </span>
          <button
            type="button"
            className="secondary"
            disabled={offset + PAGE >= total}
            onClick={() => setOffset(offset + PAGE)}
          >
            Siguiente
          </button>
        </nav>
      )}
    </div>
  );
}
