import { useMemo, useRef, useState } from "react";
import type { Bucket } from "../types";

/**
 * Allowed vs blocked traffic over the selected window.
 *
 * Colour: blue for allowed, red for blocked. Green/red would be the obvious
 * choice for "good/bad" and is the wrong one — that pair separates by only
 * ΔE 4.1 under deuteranopia, so for roughly one man in twelve the two series
 * would be the same colour. Blue against red clears every check in both light
 * and dark mode. Identity never rests on hue alone anyway: the legend and the
 * table view carry it too.
 */

const W = 800;
const H = 220;
const PAD = { top: 14, right: 14, bottom: 26, left: 48 };

const PLOT_W = W - PAD.left - PAD.right;
const PLOT_H = H - PAD.top - PAD.bottom;

interface Props {
  series: Bucket[];
  window: string;
}

export function TrafficChart({ series, window: windowLabel }: Props) {
  const [hover, setHover] = useState<number | null>(null);
  const [showTable, setShowTable] = useState(false);
  const svgRef = useRef<SVGSVGElement>(null);

  const max = useMemo(
    () => Math.max(1, ...series.map((b) => b.allowed + b.blocked)),
    [series],
  );
  const ticks = useMemo(() => niceTicks(max), [max]);
  const scaleY = (value: number) => (value / ticks.max) * PLOT_H;

  if (series.length === 0) {
    return (
      <div className="chart-empty">
        Sin tráfico registrado en las últimas {windowLabel}.
      </div>
    );
  }

  const slot = PLOT_W / series.length;
  const barW = Math.max(2, Math.min(slot - 2, 26));

  const onMove = (event: React.MouseEvent<SVGSVGElement>) => {
    const rect = svgRef.current?.getBoundingClientRect();
    if (!rect) return;
    // The SVG scales to its container, so client pixels have to be mapped back
    // into viewBox units before they mean anything.
    const x = ((event.clientX - rect.left) / rect.width) * W - PAD.left;
    const index = Math.floor(x / slot);
    setHover(index >= 0 && index < series.length ? index : null);
  };

  const active = hover !== null ? series[hover] : undefined;

  return (
    <figure className="chart">
      <figcaption className="chart-head">
        <div className="legend">
          <span className="legend-item">
            <span className="swatch swatch-allowed" aria-hidden="true" />
            Permitidas
          </span>
          <span className="legend-item">
            <span className="swatch swatch-blocked" aria-hidden="true" />
            Bloqueadas
          </span>
        </div>
        <button
          type="button"
          className="link-button"
          onClick={() => setShowTable((v) => !v)}
        >
          {showTable ? "Ver gráfico" : "Ver tabla"}
        </button>
      </figcaption>

      {showTable ? (
        <table className="data-table chart-table">
          <caption className="sr-only">
            Peticiones permitidas y bloqueadas por intervalo
          </caption>
          <thead>
            <tr>
              <th scope="col">Intervalo</th>
              <th scope="col">Permitidas</th>
              <th scope="col">Bloqueadas</th>
            </tr>
          </thead>
          <tbody>
            {series.map((bucket) => (
              <tr key={bucket.start}>
                <td>{formatTime(bucket.start)}</td>
                <td className="num">{bucket.allowed}</td>
                <td className="num">{bucket.blocked}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <div className="chart-plot">
          <svg
            ref={svgRef}
            viewBox={`0 0 ${W} ${H}`}
            role="img"
            aria-label={`Tráfico permitido y bloqueado durante las últimas ${windowLabel}`}
            onMouseMove={onMove}
            onMouseLeave={() => setHover(null)}
          >
            {ticks.values.map((value) => {
              const y = PAD.top + PLOT_H - scaleY(value);
              return (
                <g key={value}>
                  <line
                    className="gridline"
                    x1={PAD.left}
                    x2={W - PAD.right}
                    y1={y}
                    y2={y}
                  />
                  <text className="axis-label" x={PAD.left - 8} y={y + 4} textAnchor="end">
                    {compact(value)}
                  </text>
                </g>
              );
            })}

            {series.map((bucket, i) => {
              const x = PAD.left + i * slot + (slot - barW) / 2;
              const allowedH = scaleY(bucket.allowed);
              const blockedH = scaleY(bucket.blocked);
              const base = PAD.top + PLOT_H;

              // A 2px surface gap keeps the two segments from reading as one
              // mark when both are present.
              const gap = allowedH > 0 && blockedH > 0 ? 2 : 0;
              const allowedTop = base - allowedH;
              const blockedTop = allowedTop - gap - blockedH;

              return (
                <g key={bucket.start} className={hover === i ? "bar hovered" : "bar"}>
                  {allowedH > 0 && (
                    <path
                      className="mark-allowed"
                      d={
                        blockedH > 0
                          ? rect(x, allowedTop, barW, allowedH)
                          : roundedTop(x, allowedTop, barW, allowedH, 4)
                      }
                    />
                  )}
                  {blockedH > 0 && (
                    <path
                      className="mark-blocked"
                      d={roundedTop(x, blockedTop, barW, blockedH, 4)}
                    />
                  )}
                  {/* An invisible full-height target: the hit area must be
                      easier to hit than the mark, especially for a 1px bar. */}
                  <rect
                    x={PAD.left + i * slot}
                    y={PAD.top}
                    width={slot}
                    height={PLOT_H}
                    fill="transparent"
                  />
                </g>
              );
            })}

            <line
              className="baseline"
              x1={PAD.left}
              x2={W - PAD.right}
              y1={PAD.top + PLOT_H}
              y2={PAD.top + PLOT_H}
            />

            {hover !== null && (
              <line
                className="crosshair"
                x1={PAD.left + hover * slot + slot / 2}
                x2={PAD.left + hover * slot + slot / 2}
                y1={PAD.top}
                y2={PAD.top + PLOT_H}
              />
            )}

            <text className="axis-label" x={PAD.left} y={H - 8}>
              {formatTime(series[0]!.start)}
            </text>
            <text
              className="axis-label"
              x={W - PAD.right}
              y={H - 8}
              textAnchor="end"
            >
              {formatTime(series[series.length - 1]!.start)}
            </text>
          </svg>

          {active && (
            <div
              className="chart-tooltip"
              style={{
                left: `${((PAD.left + hover! * slot + slot / 2) / W) * 100}%`,
              }}
            >
              <strong>{formatTime(active.start)}</strong>
              <span>
                <span className="swatch swatch-allowed" aria-hidden="true" />
                Permitidas <b>{active.allowed}</b>
              </span>
              <span>
                <span className="swatch swatch-blocked" aria-hidden="true" />
                Bloqueadas <b>{active.blocked}</b>
              </span>
            </div>
          )}
        </div>
      )}
    </figure>
  );
}

function rect(x: number, y: number, w: number, h: number): string {
  return `M${x} ${y}h${w}v${h}h${-w}Z`;
}

/** A bar with its top corners rounded and its base square on the axis. */
function roundedTop(x: number, y: number, w: number, h: number, r: number): string {
  const radius = Math.min(r, w / 2, h);
  return (
    `M${x} ${y + h}` +
    `V${y + radius}` +
    `a${radius} ${radius} 0 0 1 ${radius} ${-radius}` +
    `h${w - radius * 2}` +
    `a${radius} ${radius} 0 0 1 ${radius} ${radius}` +
    `V${y + h}Z`
  );
}

function niceTicks(max: number): { max: number; values: number[] } {
  const magnitude = 10 ** Math.floor(Math.log10(max));
  const step = Math.ceil(max / (magnitude * 4)) * magnitude;
  const top = step * 4;
  return { max: top, values: [0, step, step * 2, step * 3, top] };
}

function compact(value: number): string {
  return value >= 1000 ? `${(value / 1000).toFixed(1)}k` : String(value);
}

function formatTime(iso: string): string {
  return new Date(iso).toLocaleTimeString("es-VE", {
    hour: "2-digit",
    minute: "2-digit",
  });
}
