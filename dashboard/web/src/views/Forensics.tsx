import { useState } from "react";
import { api } from "../api";
import type { VerifyResult } from "../types";

/**
 * Chain verification: the operator-facing form of §6.2.
 *
 * Walking the log and recomputing every hash either confirms the history is
 * intact or names the exact entry where it stopped being so.
 */
export function Forensics() {
  const [result, setResult] = useState<VerifyResult | null>(null);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");

  const verify = async () => {
    setRunning(true);
    setError(null);
    try {
      setResult(
        await api.verify({
          from: from ? new Date(from).toISOString() : undefined,
          to: to ? new Date(to).toISOString() : undefined,
        }),
      );
    } catch (err) {
      setError((err as Error).message);
      setResult(null);
    } finally {
      setRunning(false);
    }
  };

  return (
    <div className="view">
      <div className="view-head">
        <h2>Verificación forense</h2>
      </div>

      <p className="note">
        Cada entrada del log guarda el hash de la entrada anterior. Verificar
        consiste en recorrer la cadena y recalcular cada hash: si alguno no
        coincide, se identifica el punto exacto de la manipulación. Un registro
        borrado tampoco pasa desapercibido — rompe el enlace con el siguiente.
      </p>

      <section className="panel">
        <div className="filters">
          <label>
            Desde (opcional)
            <input
              type="datetime-local"
              value={from}
              onChange={(e) => setFrom(e.target.value)}
            />
          </label>
          <label>
            Hasta (opcional)
            <input
              type="datetime-local"
              value={to}
              onChange={(e) => setTo(e.target.value)}
            />
          </label>
          <button type="button" onClick={verify} disabled={running}>
            {running ? "Verificando…" : "Verificar cadena"}
          </button>
        </div>

        <p className="muted small">
          Sin fechas se verifica el histórico completo. Un rango se ancla en la
          entrada inmediatamente anterior, de modo que una primera entrada
          reescrita tampoco pasa la verificación.
        </p>
      </section>

      {error && <p className="error-banner">{error}</p>}

      {result && (
        <section className={`panel result ${result.ok ? "result-ok" : "result-broken"}`}>
          <h3>
            {result.ok ? "Cadena íntegra" : "Cadena rota"}
          </h3>

          <p>
            Se verificaron{" "}
            <strong>{result.checked.toLocaleString("es-VE")}</strong> entradas
            {result.from && <> desde {formatStamp(result.from)}</>}
            {result.to && <> hasta {formatStamp(result.to)}</>}.
          </p>

          {result.ok ? (
            <p className="muted">
              Ningún registro fue alterado ni eliminado en el intervalo
              verificado.
            </p>
          ) : (
            <dl className="detail-grid">
              <dt>Entrada afectada</dt>
              <dd className="mono">{result.broken_at}</dd>
              <dt>Posición en el intervalo</dt>
              <dd className="num">{result.position}</dd>
              <dt>Marca de tiempo</dt>
              <dd className="mono">
                {result.timestamp ? formatStamp(result.timestamp) : "—"}
              </dd>
              <dt>Detalle</dt>
              <dd>{result.detail}</dd>
            </dl>
          )}
        </section>
      )}
    </div>
  );
}

function formatStamp(iso: string): string {
  return new Date(iso).toLocaleString("es-VE");
}
