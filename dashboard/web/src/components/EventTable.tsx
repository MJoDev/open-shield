import { Fragment, useState } from "react";
import { field, verdictOf, type AuditEntry } from "../types";

interface Props {
  entries: AuditEntry[];
  empty?: string;
}

/** The audit log rendered as rows, with one expandable detail per entry. */
export function EventTable({ entries, empty = "Sin registros." }: Props) {
  const [open, setOpen] = useState<string | null>(null);

  if (entries.length === 0) {
    return <p className="muted">{empty}</p>;
  }

  return (
    <table className="data-table">
      <thead>
        <tr>
          <th scope="col">Hora</th>
          <th scope="col">Tipo</th>
          <th scope="col">Origen</th>
          <th scope="col">Petición</th>
          <th scope="col">Resultado</th>
        </tr>
      </thead>
      <tbody>
        {entries.map((entry) => {
          const verdict = verdictOf(entry);
          const expanded = open === entry.id;

          return (
            <Fragment key={entry.id}>
              <tr
                className="row-clickable"
                onClick={() => setOpen(expanded ? null : entry.id)}
              >
                <td className="num">{formatTime(entry.timestamp)}</td>
                <td>
                  <KindBadge kind={entry.kind} />
                </td>
                <td className="num">{field(entry, "ip") || "—"}</td>
                <td className="truncate" title={requestLine(entry)}>
                  {requestLine(entry)}
                </td>
                <td>
                  {verdict ? (
                    <VerdictBadge verdict={verdict} rule={field(entry, "rule")} />
                  ) : (
                    <span className="muted">{field(entry, "action") || "—"}</span>
                  )}
                </td>
              </tr>
              {expanded && (
                <tr className="row-detail">
                  <td colSpan={5}>
                    <dl className="detail-grid">
                      <dt>ID de petición</dt>
                      <dd className="mono">{entry.request_id || "—"}</dd>
                      <dt>Entrada</dt>
                      <dd className="mono">{entry.id}</dd>
                      <dt>Hash</dt>
                      <dd className="mono break">{entry.hash}</dd>
                      <dt>Hash anterior</dt>
                      <dd className="mono break">{entry.prev_hash}</dd>
                      <dt>Contenido</dt>
                      <dd>
                        <pre className="payload">
                          {JSON.stringify(entry.payload, null, 2)}
                        </pre>
                      </dd>
                    </dl>
                  </td>
                </tr>
              )}
            </Fragment>
          );
        })}
      </tbody>
    </table>
  );
}

export function VerdictBadge({
  verdict,
  rule,
}: {
  verdict: "allow" | "block";
  rule?: string;
}) {
  if (verdict === "allow") {
    return <span className="badge badge-allow">permitida</span>;
  }
  return (
    <span className="badge badge-block">
      bloqueada{rule ? <span className="badge-rule">{rule}</span> : null}
    </span>
  );
}

function KindBadge({ kind }: { kind: string }) {
  const label =
    kind === "traffic" ? "tráfico" : kind === "admin" ? "admin" : "sistema";
  return <span className={`badge badge-kind badge-${kind}`}>{label}</span>;
}

function requestLine(entry: AuditEntry): string {
  if (entry.kind !== "traffic") {
    const action = field(entry, "action") || field(entry, "event");
    return action || "—";
  }
  const method = field(entry, "method");
  const path = field(entry, "path");
  const query = field(entry, "query");
  return `${method} ${path}${query ? `?${query}` : ""}`.trim();
}

function formatTime(iso: string): string {
  return new Date(iso).toLocaleTimeString("es-VE", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}
