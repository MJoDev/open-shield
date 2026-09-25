import { ApiError } from "./api";

/** An error as the operator reads it: what went wrong, then the evidence. */
export interface Problem {
  title: string;
  detail?: string;
}

/**
 * Translates a failed call into a Problem.
 *
 * The API's own messages are English and technical, which is right for a log
 * and wrong as the first thing an operator reads. `title` is the Spanish
 * sentence for what did not happen; the API's message and status follow as
 * detail, because they are what gets pasted into a bug report.
 *
 * `mutation` marks an administrative change. For those a 503 has one specific
 * meaning (§6.1): the change was refused because its audit entry could not be
 * written — so it did not happen, and the screen must say exactly that.
 */
export function describeError(
  err: unknown,
  title: string,
  { mutation = false }: { mutation?: boolean } = {},
): Problem {
  if (!(err instanceof ApiError)) {
    return { title, detail: err instanceof Error ? err.message : undefined };
  }

  if (mutation && err.status === 503) {
    return {
      title: "El cambio no se aplicó: no se pudo registrar en la auditoría.",
      detail: `${err.message} (HTTP 503)`,
    };
  }

  if (err.timedOut) {
    return {
      title,
      detail: `El servidor no respondió a tiempo: ${err.message}.`,
    };
  }

  if (err.status === 0) {
    return { title, detail: `Sin conexión con el panel: ${err.message}.` };
  }

  return { title, detail: `${err.message} (HTTP ${err.status})` };
}
