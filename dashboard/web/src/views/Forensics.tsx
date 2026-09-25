import { useEffect, useRef, useState } from "react";
import { api, isAbort } from "../api";
import { CopyButton, ErrorBanner, InlineStatus } from "../components/Feedback";
import { describeError, type Problem } from "../errors";
import { useDelayedFlag, useElapsedSeconds } from "../hooks";
import type { VerifyResult } from "../types";

// Past this, a walk is long enough that the operator deserves a way out.
const OFFER_CANCEL_AFTER_S = 3;

/**
 * Chain verification: the operator-facing form of §6.2.
 *
 * Walking the log and recomputing every hash either confirms the history is
 * intact or names the exact entry where it stopped being so.
 */
export function Forensics() {
  const [result, setResult] = useState<VerifyResult | null>(null);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<Problem | null>(null);
  const [cancelled, setCancelled] = useState(false);
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const controllerRef = useRef<AbortController | null>(null);

  const showProgress = useDelayedFlag(running);
  const elapsed = useElapsedSeconds(running);

  // Leaving the tab mid-walk must not leave a request resolving into an
  // unmounted view.
  useEffect(() => () => controllerRef.current?.abort(), []);

  const rangeInvalid =
    from !== "" && to !== "" && new Date(from) > new Date(to);

  const verify = async () => {
    const controller = new AbortController();
    controllerRef.current = controller;
    setRunning(true);
    setError(null);
    setCancelled(false);
    // A previous verdict is cleared, not kept under the new attempt. Every
    // other screen keeps its last good data on a failure; this one must not,
    // because an old "Cadena íntegra" beside a failed re-check reads as a
    // current guarantee that nobody has just established.
    setResult(null);
    try {
      setResult(
        await api.verify(
          {
            from: from ? new Date(from).toISOString() : undefined,
            to: to ? new Date(to).toISOString() : undefined,
          },
          { signal: controller.signal },
        ),
      );
    } catch (err) {
      // Cancelling is the operator's own decision, not a failure: it is
      // acknowledged, not reported in red.
      if (isAbort(err)) setCancelled(true);
      else
        setError(describeError(err, "No se pudo completar la verificación."));
    } finally {
      if (controllerRef.current === controller) controllerRef.current = null;
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
        <form
          className="filters"
          onSubmit={(event) => {
            event.preventDefault();
            if (!running && !rangeInvalid) verify();
          }}
        >
          <label>
            Desde (opcional)
            <input
              type="datetime-local"
              value={from}
              max={to || undefined}
              aria-invalid={rangeInvalid}
              aria-describedby={rangeInvalid ? "range-error" : undefined}
              onChange={(e) => setFrom(e.target.value)}
            />
          </label>
          <label>
            Hasta (opcional)
            <input
              type="datetime-local"
              value={to}
              min={from || undefined}
              aria-invalid={rangeInvalid}
              aria-describedby={rangeInvalid ? "range-error" : undefined}
              onChange={(e) => setTo(e.target.value)}
            />
          </label>
          <button
            type="submit"
            className="button-fixed"
            disabled={running || rangeInvalid}
            aria-busy={running}
          >
            {running ? (
              <>
                <span className="spinner" aria-hidden="true" />
                Verificando…
              </>
            ) : (
              "Verificar cadena"
            )}
          </button>
          {running && elapsed >= OFFER_CANCEL_AFTER_S && (
            <button
              type="button"
              className="secondary"
              onClick={() => controllerRef.current?.abort()}
            >
              Cancelar
            </button>
          )}
        </form>

        {rangeInvalid && (
          <p id="range-error" className="field-error" role="alert">
            «Desde» es posterior a «Hasta»: el intervalo no contiene ninguna
            entrada.
          </p>
        )}

        <p className="muted small">
          Sin fechas se verifica el histórico completo. Un rango se ancla en la
          entrada inmediatamente anterior, de modo que una primera entrada
          reescrita tampoco pasa la verificación.
        </p>

        {showProgress && (
          <InlineStatus>
            Recorriendo la cadena y recalculando cada hash…
            {elapsed > 0 && <span className="num muted">{elapsed} s</span>}
          </InlineStatus>
        )}
      </section>

      {/* One polite region for the outcome, so a verdict that arrives while
          the operator is looking elsewhere is still announced. */}
      <div aria-live="polite" className="view">
        {cancelled && (
          <p className="muted">
            Verificación cancelada. No se obtuvo ningún resultado.
          </p>
        )}
        {error && (
          <ErrorBanner problem={error} onRetry={running ? undefined : verify} />
        )}

        {result && (
          <section
            className={`panel result ${result.ok ? "result-ok" : "result-broken"}`}
          >
            <h3>{result.ok ? "Cadena íntegra" : "Cadena rota"}</h3>

            <p>
              {result.checked === 1 ? "Se verificó" : "Se verificaron"}{" "}
              <strong className="num">
                {result.checked.toLocaleString("es-VE")}
              </strong>{" "}
              {result.checked === 1 ? "entrada" : "entradas"}
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
                <dd>
                  {result.broken_at ? (
                    <span className="copyable">
                      <span className="mono break">{result.broken_at}</span>
                      <CopyButton
                        value={result.broken_at}
                        label="Copiar ID de la entrada afectada"
                      />
                    </span>
                  ) : (
                    "—"
                  )}
                </dd>
                <dt>Posición en el intervalo</dt>
                <dd className="num">
                  {result.position !== undefined
                    ? result.position.toLocaleString("es-VE")
                    : "—"}
                </dd>
                <dt>Marca de tiempo</dt>
                <dd className="mono">
                  {result.timestamp ? formatStamp(result.timestamp) : "—"}
                </dd>
                <dt>Detalle</dt>
                <dd>{result.detail || "—"}</dd>
              </dl>
            )}
          </section>
        )}
      </div>
    </div>
  );
}

function formatStamp(iso: string): string {
  return new Date(iso).toLocaleString("es-VE");
}
