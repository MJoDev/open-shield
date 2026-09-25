import { useCallback, useEffect, useState } from "react";
import { api } from "../api";
import {
  ErrorBanner,
  LoadingText,
  Skeleton,
  SkeletonTable,
} from "../components/Feedback";
import { describeError, type Problem } from "../errors";
import { useLoadPhase } from "../hooks";
import type { IPRule, RuleConfig } from "../types";

const DESCRIPTIONS: Record<string, string> = {
  ipblock: "Listas de permitidos y bloqueados por dirección o rango (CIDR).",
  ratelimit: "Límite de peticiones por IP en una ventana de tiempo (RF-05).",
  sqli: "Firmas de inyección SQL sobre ruta, query, cabeceras y cuerpo.",
  xss: "Firmas de scripting entre sitios sobre los mismos campos.",
};

const IP_COLUMNS = ["Rango", "Acción", "Nota", "Añadida por", ""];

// Keys in the busy set: a rule name, a CIDR, or this one for the add form.
const ADDING = "ipblock:add";

type Scope = "rules" | "ip";
interface Feedback {
  error: Problem | null;
  notice: string;
}
const NO_FEEDBACK: Feedback = { error: null, notice: "" };

/**
 * Rule and access-list administration.
 *
 * Nothing here is optimistic. The API writes the audit entry for a change
 * *before* applying it and refuses with 503 when that entry cannot be
 * confirmed (§6.1), so the only honest state to show is the one the server
 * answered with. A toggle that flips on click and flips back on a 503 would,
 * for a moment, tell the operator a protection was off when it was not.
 */
export function Rules() {
  const [rules, setRules] = useState<RuleConfig[] | null>(null);
  const [ipRules, setIpRules] = useState<IPRule[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<Problem | null>(null);
  // Feedback lives with the panel whose control caused it: a confirmation or a
  // refusal printed in the other panel, or above the fold, is not read.
  const [feedback, setFeedback] = useState<Record<Scope, Feedback>>({
    rules: NO_FEEDBACK,
    ip: NO_FEEDBACK,
  });
  const [busy, setBusy] = useState<ReadonlySet<string>>(new Set());

  const [cidr, setCidr] = useState("");
  const [action, setAction] = useState<"deny" | "allow">("deny");
  const [note, setNote] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [ruleList, ipList] = await Promise.all([
        api.rules(),
        api.ipRules(),
      ]);
      setRules(ruleList.rules);
      setIpRules(ipList.rules);
      setLoadError(null);
    } catch (err) {
      setLoadError(describeError(err, "No se pudieron cargar las reglas."));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const say = (scope: Scope, next: Feedback) =>
    setFeedback((current) => ({ ...current, [scope]: next }));

  // A confirmation is read once and then gets out of the way. Errors stay
  // until the next action: a refusal is something to act on.
  const notices = `${feedback.rules.notice}|${feedback.ip.notice}`;
  useEffect(() => {
    if (notices === "|") return;
    const timer = setTimeout(
      () =>
        setFeedback((current) => ({
          rules: { ...current.rules, notice: "" },
          ip: { ...current.ip, notice: "" },
        })),
      5000,
    );
    return () => clearTimeout(timer);
  }, [notices]);

  const phase = useLoadPhase(loading, rules !== null);

  /** Runs one administrative change with its busy key and error handling. */
  const change = async (
    scope: Scope,
    key: string,
    failure: string,
    run: () => Promise<string>,
  ) => {
    setBusy((current) => new Set(current).add(key));
    say(scope, NO_FEEDBACK);
    try {
      say(scope, { error: null, notice: await run() });
    } catch (err) {
      say(scope, {
        error: describeError(err, failure, { mutation: true }),
        notice: "",
      });
    } finally {
      setBusy((current) => {
        const next = new Set(current);
        next.delete(key);
        return next;
      });
    }
  };

  const toggle = (rule: RuleConfig) =>
    change(
      "rules",
      rule.name,
      `No se pudo cambiar la regla ${rule.name}.`,
      async () => {
        const updated = await api.setRuleEnabled(rule.name, !rule.enabled);
        // The server's answer is the confirmed state; merge it rather than
        // refetching both lists for one field.
        setRules((current) =>
          (current ?? []).map((r) =>
            r.name === rule.name ? { ...r, ...updated } : r,
          ),
        );
        return `${rule.name} ${(updated.enabled ?? !rule.enabled) ? "activada" : "desactivada"}.`;
      },
    );

  const refreshIPs = async () => {
    const ipList = await api.ipRules();
    setIpRules(ipList.rules);
  };

  const addIP = (event: React.FormEvent) => {
    event.preventDefault();
    const target = cidr.trim();
    change(
      "ip",
      ADDING,
      `No se pudo añadir ${target} a la lista.`,
      async () => {
        await api.addIPRule({ cidr: target, action, note: note.trim() });
        setCidr("");
        setNote("");
        await refreshIPs();
        return `${target} añadida: ${action === "deny" ? "bloqueada" : "permitida"}.`;
      },
    );
  };

  const removeIP = (entry: IPRule) =>
    change(
      "ip",
      entry.cidr,
      `No se pudo quitar ${entry.cidr} de la lista.`,
      async () => {
        await api.deleteIPRule(entry.cidr);
        await refreshIPs();
        return `${entry.cidr} quitada de la lista.`;
      },
    );

  return (
    <div className="view">
      <div className="view-head">
        <h2>Reglas</h2>
      </div>

      {loadError && <ErrorBanner problem={loadError} onRetry={load} />}

      <p className="note">
        Cada cambio queda registrado en el log de auditoría antes de aplicarse.
        Si la entrada no puede escribirse, el cambio no ocurre.
      </p>

      <section
        className={
          phase.placeholder && !phase.skeleton ? "panel is-pending" : "panel"
        }
        aria-busy={phase.placeholder}
      >
        <h3>Cadena de evaluación</h3>
        <p className="muted">
          Se evalúan en este orden y gana el primer bloqueo.
        </p>

        {rules === null ? (
          phase.placeholder ? (
            <>
              <LoadingText />
              <ul className="rule-list" aria-hidden="true">
                {Object.keys(DESCRIPTIONS).map((name) => (
                  <li key={name} className="rule-pending">
                    <div className="rule-info">
                      <Skeleton className="skeleton-inline" />
                      <Skeleton />
                    </div>
                    <Skeleton className="skeleton-toggle" />
                  </li>
                ))}
              </ul>
            </>
          ) : (
            <p className="muted">No hay datos que mostrar.</p>
          )
        ) : (
          <ul className="rule-list">
            {rules.map((rule) => {
              const saving = busy.has(rule.name);
              return (
                <li key={rule.name}>
                  <div className="rule-info">
                    <span className="rule-name mono">{rule.name}</span>
                    <span className="muted">
                      {DESCRIPTIONS[rule.name] ?? "Regla personalizada."}
                    </span>
                    {rule.updated_by && (
                      <span className="muted small">
                        Modificada por {rule.updated_by} el{" "}
                        {new Date(rule.updated_at).toLocaleString("es-VE")}
                      </span>
                    )}
                  </div>
                  <button
                    type="button"
                    className={rule.enabled ? "toggle toggle-on" : "toggle"}
                    disabled={saving}
                    aria-busy={saving}
                    onClick={() => toggle(rule)}
                    aria-pressed={rule.enabled}
                    aria-label={`Regla ${rule.name}`}
                  >
                    {saving ? (
                      <>
                        <span className="spinner" aria-hidden="true" />
                        Guardando…
                      </>
                    ) : rule.enabled ? (
                      "Activa"
                    ) : (
                      "Inactiva"
                    )}
                  </button>
                </li>
              );
            })}
          </ul>
        )}
        <PanelFeedback feedback={feedback.rules} />
      </section>

      <section className="panel">
        <h3>Lista de acceso por IP</h3>
        <p className="muted">
          Una entrada <code>allow</code> gana sobre una <code>deny</code>, así
          que puedes bloquear un rango y dejar pasar una dirección concreta
          dentro de él. Se acepta una IP suelta o un CIDR.
        </p>

        <form className="filters" onSubmit={addIP}>
          <label>
            Dirección o rango
            <input
              type="text"
              required
              value={cidr}
              placeholder="203.0.113.0/24"
              onChange={(e) => setCidr(e.target.value)}
            />
          </label>
          <label>
            Acción
            <select
              value={action}
              onChange={(e) => setAction(e.target.value as "deny" | "allow")}
            >
              <option value="deny">Bloquear</option>
              <option value="allow">Permitir</option>
            </select>
          </label>
          <label>
            Nota
            <input
              type="text"
              value={note}
              placeholder="Motivo, fecha del incidente…"
              onChange={(e) => setNote(e.target.value)}
            />
          </label>
          <button
            type="submit"
            className="button-fixed"
            disabled={busy.has(ADDING)}
            aria-busy={busy.has(ADDING)}
          >
            {busy.has(ADDING) ? (
              <>
                <span className="spinner" aria-hidden="true" />
                Añadiendo…
              </>
            ) : (
              "Añadir"
            )}
          </button>
        </form>

        <PanelFeedback feedback={feedback.ip} />

        {ipRules === null ? (
          phase.placeholder ? (
            <SkeletonTable
              columns={IP_COLUMNS}
              rows={3}
              pending={!phase.skeleton}
            />
          ) : null
        ) : ipRules.length === 0 ? (
          <p className="muted">
            La lista está vacía: ninguna dirección está bloqueada ni exceptuada.
          </p>
        ) : (
          <div className="table-scroll">
            <table className="data-table">
              <thead>
                <tr>
                  {IP_COLUMNS.map((column, i) => (
                    <th key={i} scope="col">
                      {column || <span className="sr-only">Acciones</span>}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {ipRules.map((entry) => {
                  const removing = busy.has(entry.cidr);
                  const verb =
                    entry.action === "deny"
                      ? "Desbloquear"
                      : "Quitar excepción";
                  return (
                    <tr key={entry.cidr}>
                      <td className="mono">{entry.cidr}</td>
                      <td>
                        <span
                          className={
                            entry.action === "deny"
                              ? "badge badge-block"
                              : "badge badge-allow"
                          }
                        >
                          {entry.action === "deny" ? "bloquear" : "permitir"}
                        </span>
                      </td>
                      <td>{entry.note || "—"}</td>
                      <td className="muted">{entry.created_by || "—"}</td>
                      <td className="cell-action">
                        {/* The visible verb says what happens; the accessible
                            name also says to what, since the button is read
                            out of its row. */}
                        <button
                          type="button"
                          className="link-button danger"
                          disabled={removing}
                          aria-busy={removing}
                          aria-label={`${verb} ${entry.cidr}`}
                          onClick={() => removeIP(entry)}
                        >
                          {removing ? "Quitando…" : verb}
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}

/**
 * The outcome of the last change made in a panel. The status line keeps its
 * height while empty, so a confirmation appearing does not push the panel's
 * content around; an error takes its place rather than stacking under it.
 */
function PanelFeedback({ feedback }: { feedback: Feedback }) {
  if (feedback.error) return <ErrorBanner problem={feedback.error} />;
  return (
    <p className="status-line" role="status">
      {feedback.notice}
    </p>
  );
}
