import { useEffect, useState, type ReactNode } from "react";
import type { Problem } from "../errors";

/**
 * A failure, sentence first. `onRetry` is offered only where retrying the
 * same call can plausibly succeed — never for a rejected input.
 */
export function ErrorBanner({
  problem,
  onRetry,
}: {
  problem: Problem;
  onRetry?: () => void;
}) {
  return (
    <div className="error-banner" role="alert">
      <strong>{problem.title}</strong>
      {problem.detail && <span className="error-detail">{problem.detail}</span>}
      {onRetry && (
        <button type="button" className="link-button" onClick={onRetry}>
          Reintentar
        </button>
      )}
    </div>
  );
}

/** A skeleton block. Decorative: the container announces the loading. */
export function Skeleton({ className = "" }: { className?: string }) {
  return <span className={`skeleton ${className}`.trim()} aria-hidden="true" />;
}

/**
 * The one thing a screen reader hears while a region loads. The region itself
 * carries aria-busy.
 */
export function LoadingText({
  children = "Cargando…",
}: {
  children?: ReactNode;
}) {
  return <span className="sr-only">{children}</span>;
}

/** Table-shaped skeleton: same columns, same row height as the real table. */
export function SkeletonTable({
  columns,
  rows = 6,
  pending = false,
}: {
  columns: string[];
  rows?: number;
  pending?: boolean;
}) {
  return (
    <div className={pending ? "table-scroll is-pending" : "table-scroll"}>
      <LoadingText />
      <table className="data-table" aria-hidden="true">
        <thead>
          <tr>
            {columns.map((column, i) => (
              <th key={i} scope="col">
                {column}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {Array.from({ length: rows }, (_, row) => (
            <tr key={row} className="skeleton-row">
              {columns.map((_, col) => (
                <td key={col}>
                  <Skeleton />
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** Small inline "work in progress" marker, for refreshes of data on screen. */
export function InlineStatus({ children }: { children: ReactNode }) {
  return (
    <span className="inline-status">
      <span className="spinner" aria-hidden="true" />
      {children}
    </span>
  );
}

/**
 * Copies a value and confirms in place. The request ID is how an operator
 * follows one request across proxy, engine and backend, so it has to leave
 * this screen without being retyped.
 */
export function CopyButton({ value, label }: { value: string; label: string }) {
  const [state, setState] = useState<"idle" | "copied" | "failed">("idle");

  useEffect(() => {
    if (state === "idle") return;
    const timer = setTimeout(() => setState("idle"), 1800);
    return () => clearTimeout(timer);
  }, [state]);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setState("copied");
    } catch {
      setState("failed");
    }
  };

  return (
    <button
      type="button"
      className="link-button"
      onClick={(event) => {
        // The button sits inside a clickable row; copying must not collapse it.
        event.stopPropagation();
        copy();
      }}
      aria-label={label}
    >
      <span aria-live="polite">
        {state === "copied"
          ? "Copiado"
          : state === "failed"
            ? "No se pudo copiar"
            : "Copiar"}
      </span>
    </button>
  );
}
