import { useEffect, useState } from "react";
import { api } from "../api";
import type { IPRule, RuleConfig } from "../types";

const DESCRIPTIONS: Record<string, string> = {
  ipblock: "Listas de permitidos y bloqueados por dirección o rango (CIDR).",
  ratelimit: "Límite de peticiones por IP en una ventana de tiempo (RF-05).",
  sqli: "Firmas de inyección SQL sobre ruta, query, cabeceras y cuerpo.",
  xss: "Firmas de scripting entre sitios sobre los mismos campos.",
};

export function Rules() {
  const [rules, setRules] = useState<RuleConfig[]>([]);
  const [ipRules, setIpRules] = useState<IPRule[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  const [cidr, setCidr] = useState("");
  const [action, setAction] = useState<"deny" | "allow">("deny");
  const [note, setNote] = useState("");

  const load = async () => {
    try {
      const [ruleList, ipList] = await Promise.all([api.rules(), api.ipRules()]);
      setRules(ruleList.rules);
      setIpRules(ipList.rules);
      setError(null);
    } catch (err) {
      setError((err as Error).message);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const toggle = async (rule: RuleConfig) => {
    setBusy(rule.name);
    try {
      await api.setRuleEnabled(rule.name, !rule.enabled);
      await load();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(null);
    }
  };

  const addIP = async (event: React.FormEvent) => {
    event.preventDefault();
    setBusy("ipblock");
    try {
      await api.addIPRule({ cidr: cidr.trim(), action, note: note.trim() });
      setCidr("");
      setNote("");
      await load();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(null);
    }
  };

  const removeIP = async (entry: IPRule) => {
    setBusy(entry.cidr);
    try {
      await api.deleteIPRule(entry.cidr);
      await load();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="view">
      <div className="view-head">
        <h2>Reglas</h2>
      </div>

      {error && <p className="error-banner">{error}</p>}

      <p className="note">
        Cada cambio queda registrado en el log de auditoría antes de aplicarse.
        Si la entrada no puede escribirse, el cambio no ocurre.
      </p>

      <section className="panel">
        <h3>Cadena de evaluación</h3>
        <p className="muted">
          Se evalúan en este orden y gana el primer bloqueo.
        </p>
        <ul className="rule-list">
          {rules.map((rule) => (
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
                disabled={busy === rule.name}
                onClick={() => toggle(rule)}
                aria-pressed={rule.enabled}
              >
                {rule.enabled ? "Activa" : "Inactiva"}
              </button>
            </li>
          ))}
        </ul>
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
          <button type="submit" disabled={busy === "ipblock"}>
            Añadir
          </button>
        </form>

        {ipRules.length === 0 ? (
          <p className="muted">La lista está vacía.</p>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th scope="col">Rango</th>
                <th scope="col">Acción</th>
                <th scope="col">Nota</th>
                <th scope="col">Añadida por</th>
                <th scope="col" />
              </tr>
            </thead>
            <tbody>
              {ipRules.map((entry) => (
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
                  <td>
                    <button
                      type="button"
                      className="link-button danger"
                      disabled={busy === entry.cidr}
                      onClick={() => removeIP(entry)}
                    >
                      Quitar
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </div>
  );
}
