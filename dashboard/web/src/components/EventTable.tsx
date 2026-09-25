import { Fragment, useState, type ReactNode } from "react";
import { field, verdictOf, type AuditEntry } from "../types";
import { CopyButton } from "./Feedback";

interface Props {
  entries: AuditEntry[];
  empty?: ReactNode;
}

export const EVENT_COLUMNS = [
  "Hora",
  "Tipo",
  "Origen",
  "Petición",
  "Resultado",
];

/** The audit log rendered as rows, with one expandable detail per entry. */
export function EventTable({ entries, empty = "Sin registros." }: Props) {
  const [open, setOpen] = useState<string | null>(null);

  if (entries.length === 0) {
    return <div className="muted">{empty}</div>;
  }

  return (
    <div className="table-scroll">
      <table className="data-table">
        <thead>
          <tr>
            {EVENT_COLUMNS.map((column) => (
              <th key={column} scope="col">
                {column}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {entries.map((entry) => {
            const verdict = verdictOf(entry);
            const expanded = open === entry.id;
            const toggle = () => setOpen(expanded ? null : entry.id);

            return (
              <Fragment key={entry.id}>
                {/* The row is the target, so it also has to be reachable and
                  operable from the keyboard, and say whether it is open. */}
                <tr
                  className={
                    expanded ? "row-clickable row-expanded" : "row-clickable"
                  }
                  tabIndex={0}
                  aria-expanded={expanded}
                  onClick={toggle}
                  onKeyDown={(event) => {
                    if (event.target !== event.currentTarget) return;
                    if (event.key === "Enter" || event.key === " ") {
                      event.preventDefault();
                      toggle();
                    }
                  }}
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
                      <VerdictBadge
                        verdict={verdict}
                        rule={field(entry, "rule")}
                      />
                    ) : (
                      <span className="muted">
                        {field(entry, "action") || "—"}
                      </span>
                    )}
                  </td>
                </tr>
                {expanded && (
                  <tr className="row-detail">
                    <td colSpan={5}>
                      <dl className="detail-grid">
                        <dt>ID de petición</dt>
                        <dd>
                          {entry.request_id ? (
                            <span className="copyable">
                              <span className="mono break">
                                {entry.request_id}
                              </span>
                              <CopyButton
                                value={entry.request_id}
                                label="Copiar ID de petición"
                              />
                            </span>
                          ) : (
                            "—"
                          )}
                        </dd>
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
    </div>
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
