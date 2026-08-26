import { useCallback, useEffect, useState } from "react";
import { api } from "../api";
import { EventTable } from "../components/EventTable";
import type { AuditEntry } from "../types";

const PAGE = 50;

export function Events() {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [kind, setKind] = useState("");
  const [verdict, setVerdict] = useState("");
  const [ip, setIp] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const page = await api.events({
        kind: kind || undefined,
        verdict: verdict || undefined,
        ip: ip.trim() || undefined,
        limit: PAGE,
        offset,
      });
      setEntries(page.entries);
      setTotal(page.total);
      setError(null);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  }, [kind, verdict, ip, offset]);

  useEffect(() => {
    load();
  }, [load]);

  // Any filter change invalidates the current page number.
  const changeFilter = (apply: () => void) => {
    setOffset(0);
    apply();
  };

  const page = Math.floor(offset / PAGE) + 1;
  const pages = Math.max(1, Math.ceil(total / PAGE));

  return (
    <div className="view">
      <div className="view-head">
        <h2>Registro de auditoría</h2>
        <span className="muted">
          {total.toLocaleString("es-VE")} entradas
        </span>
      </div>

      <div className="filters">
        <label>
          Tipo
          <select
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
            value={ip}
            placeholder="203.0.113.7"
            onChange={(e) => changeFilter(() => setIp(e.target.value))}
          />
        </label>

        <button type="button" onClick={load} className="secondary">
          Actualizar
        </button>
      </div>

      {error && <p className="error-banner">{error}</p>}

      <section className="panel">
        {loading && entries.length === 0 ? (
          <p className="muted">Cargando…</p>
        ) : (
          <EventTable
            entries={entries}
            empty="Ninguna entrada coincide con estos filtros."
          />
        )}
      </section>

      <div className="pager">
        <button
          type="button"
          className="secondary"
          disabled={offset === 0}
          onClick={() => setOffset(Math.max(0, offset - PAGE))}
        >
          Anterior
        </button>
        <span className="muted">
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
      </div>
    </div>
  );
}
