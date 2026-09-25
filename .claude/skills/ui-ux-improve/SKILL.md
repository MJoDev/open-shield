---
name: ui-ux-improve
description: UI/UX rules for the open-shield dashboard (dashboard/web, React + plain CSS) — spacing scale, loading states and skeletons, wait-time thresholds, debouncing, empty/error states, feedback on admin actions, motion and accessibility. Use when building or changing any dashboard view or component, when asked to "improve", "polish" or review the UI/UX, or when adding loading, empty or error states.
---

# UI/UX improve — open-shield dashboard

Rules for `dashboard/web/src`. The stack is React 18 + TypeScript + one
hand-written `styles.css` with role-based colour tokens — **no UI library, no
CSS framework**. Keep it that way: add classes and tokens to `styles.css`,
don't pull in dependencies for spinners, skeletons or toasts.

UI copy is **Spanish** (`es-VE` for number/date formatting). Code, comments
and class names are English.

## Workflow

1. Read the view/component and the relevant section of `styles.css` first.
2. Walk the checklist at the end against it; list what fails.
3. Fix in small steps. Prefer extending an existing class over a new one.
4. Verify: `make test-web` (typecheck + vitest) must pass. For visual
   changes run `cd dashboard/web && npm run dev` against a running stack
   (`make up`) and check light **and** dark mode, and a ~375px width.
5. Update or add vitest tests when a state is added (loading, empty, error).

---

## 1. Spacing

Use a 4px-based scale. Every `gap`, `padding` and `margin` should land on it:

| Token        | Value     | Use                                             |
|--------------|-----------|-------------------------------------------------|
| `--space-1`  | 0.25rem   | icon ↔ label, badge padding                     |
| `--space-2`  | 0.5rem    | tight groups, legend items, label ↔ input       |
| `--space-3`  | 0.75rem   | controls in a row, table cell padding           |
| `--space-4`  | 1rem      | tile padding, filter bar gaps                   |
| `--space-5`  | 1.25rem   | panel padding, gap between sections of a view   |
| `--space-6`  | 1.5rem    | page gutter, topbar horizontal padding          |
| `--space-8`  | 2rem      | card padding (login), large empty states        |

- If the tokens are not yet in `:root`, add them the first time you touch
  spacing, and migrate the rules you are already editing. Off-scale values
  (`0.85rem`, `1.1rem`, `0.45rem`, `0.15rem`…) get rounded to the nearest step
  when touched — don't do a repo-wide sweep unless asked.
- **Proximity expresses grouping**: space *inside* a group is smaller than
  space *between* groups. Label↔field < field↔field < section↔section.
- Vertical rhythm inside a view comes from `.view { gap }` — don't add ad-hoc
  `margin-top` to children.
- Page gutter: `--space-6` on desktop, `--space-4` under 40rem. No horizontal
  page scroll at 375px; wide tables scroll inside their panel.
- Minimum interactive target: 32px tall on desktop, 40px on touch
  (`@media (pointer: coarse)`). Text links in tables count too.

## 2. Wait-time thresholds

Perceived latency, not real latency, is what the operator feels. Apply by
expected duration:

| Duration      | What to show                                                       |
|---------------|--------------------------------------------------------------------|
| < 100 ms      | Nothing. Feels instant.                                            |
| 100 – 300 ms  | Nothing new — **delay** any indicator ~300 ms so fast responses never flash it. |
| 300 ms – 1 s  | Inline indicator: button busy state, dimmed stale content.         |
| 1 – 10 s      | Skeleton (first load) or progress text ("Verificando 12 400 entradas…"). |
| > 10 s        | Determinate progress if knowable, plus a way to cancel or leave.   |

- **Anti-flicker**: once an indicator is shown, keep it at least ~400 ms so it
  doesn't blink. Implement with a small `useDelayedFlag(flag, {delay: 300,
  minVisible: 400})` hook — write it once in `src/`, reuse everywhere.
- **Debounce free-text filters** (e.g. the IP filter in `Events.tsx`) by
  250–400 ms. Selects and toggles apply immediately.
- Cancel superseded requests (`AbortController`) so a slow old response can't
  overwrite a newer one. At minimum, ignore responses whose params no longer
  match current state.
- Every fetch has a timeout. A spinner that never ends is worse than an error.

## 3. Loading states and skeletons

- **First load** (no data yet): skeleton shaped like the final content — same
  row heights, same tile sizes, same column count. Never a bare "Cargando…"
  inside a panel that will become a table; the layout must not jump when data
  arrives.
- **Refresh with data already on screen** (pagination, filter change, manual
  "Actualizar"): keep the stale data visible, dim it (`opacity: .6`,
  `aria-busy="true"` on the container) and show a small inline indicator.
  Don't swap the table for a skeleton.
- **Boot / session check** (`App.tsx`): a centered brand mark with a delayed
  indicator is fine; skip it entirely if the check resolves under 300 ms.
- Skeleton CSS — add once to `styles.css`:

  ```css
  .skeleton {
    background: var(--surface-2);
    border-radius: 4px;
    position: relative;
    overflow: hidden;
  }
  .skeleton::after {
    content: "";
    position: absolute;
    inset: 0;
    transform: translateX(-100%);
    background: linear-gradient(90deg, transparent, var(--border), transparent);
    animation: shimmer 1.4s ease-in-out infinite;
  }
  @keyframes shimmer { to { transform: translateX(100%); } }
  @media (prefers-reduced-motion: reduce) {
    .skeleton::after { animation: none; }
  }
  ```

- Skeleton blocks are `aria-hidden="true"`; the container carries
  `aria-busy="true"` and one visually hidden "Cargando…" for screen readers.
- Numbers that update live (tiles, counters) use `.num` (tabular figures) so
  widths don't jitter.

## 4. Feedback on actions

- A button that triggers a request goes **busy** immediately: disabled,
  label changes to the gerund ("Guardando…", "Verificando…"), width stays
  fixed (set `min-width` or keep the label length similar) so the row doesn't
  shift.
- **No optimistic updates for admin changes** (rule toggles, IP blocks). The
  engine logs the change *before* applying it and refuses with **503** if the
  audit entry cannot be confirmed — the UI must show the confirmed state only,
  and surface a 503 as "El cambio no se aplicó: no se pudo registrar en la
  auditoría." Optimism is fine only for purely local UI state.
- Success confirmation: brief, inline, near the control (e.g. the toggle
  settles into its new state; a new IP appears in the list). Toasts only for
  things that happen off-screen.
- Destructive actions (removing an IP block) name the target in the label: "Desbloquear 203.0.113.0/24", not "Eliminar". No `window.confirm`.
- Forensic verification is long-running: show progress text, keep the button
  disabled, and render the result with the *where* (`VerifyResult` gives the
  first broken seq) — never just "falló".

## 5. Empty and error states

- **Empty ≠ loading ≠ error.** Each has its own rendering; never show "no hay
  datos" while a request is in flight.
- Empty states say *why* and *what next*: "Ninguna entrada coincide con estos
  filtros." + a "Limpiar filtros" link-button when filters are active.
- Errors: use `.error-banner`, human sentence first, technical detail after
  (status code, request ID if present). Offer "Reintentar" when retrying can
  help. Keep the last good data visible under the banner.
- WebSocket (`/ws/live`): the connection pill reflects state; on disconnect,
  reconnect with backoff and say so ("Reconectando…"), don't clear the feed.
- 401 from any call → back to login with a short "Sesión expirada" note, not a
  raw error.

## 6. Motion

- Durations: 120–150 ms for hover/press, 200–250 ms for enter/exit, never
  above 300 ms for UI chrome. Ease-out for entering, ease-in for leaving.
- Animate `opacity` and `transform` only.
- New rows in the live feed may fade/slide in; cap it so a burst of traffic
  doesn't turn into a continuous animation.
- Everything respects `prefers-reduced-motion: reduce`.

## 7. Accessibility and consistency

- Colour comes from the role tokens in `:root` (`--allowed`, `--blocked`,
  `--muted`…). Never hard-code a hex in a component; if a new role is needed,
  add it to **both** the light and dark blocks.
- Allowed/blocked is never conveyed by colour alone — pair it with the badge
  text or an icon.
- Text contrast ≥ 4.5:1 (≥ 3:1 for large text and UI borders). `--muted` is
  for secondary text only, never for anything the operator must read to act.
- Every control is keyboard-reachable with a visible `:focus-visible` ring
  (already defined — don't remove outlines). Clickable table rows need a
  keyboard path (button inside the row, or `tabIndex` + Enter handler).
- Status changes that happen without user action (live feed, reconnect,
  verification finished) go through an `aria-live="polite"` region.
- Tabs in the top bar use `aria-current`; keep that pattern for any new nav.

## 8. Security-relevant UI rules

This is a security product; the UI must not undo the backend's guarantees.

- Never render request bodies, `Cookie` or `Authorization` values — the backend
  doesn't store them; don't add fields that would suggest it does.
- Render the matched fragment and any attacker-supplied string as **text**,
  never via `dangerouslySetInnerHTML`. Use `.mono .break` for long payloads.
- Always show the `X-Request-ID` in event detail, copyable — it is how an
  operator follows a request across proxy, engine and backend.

---

## Checklist

For each view/component touched:

- [ ] All spacing on the 4px scale; groups tighter inside than between.
- [ ] No layout shift between skeleton → data, or idle → busy.
- [ ] First load: skeleton. Refresh: stale data dimmed + `aria-busy`.
- [ ] Indicators delayed ~300 ms and shown ≥ ~400 ms.
- [ ] Free-text inputs debounced; superseded requests aborted/ignored.
- [ ] Distinct loading / empty / error renderings; error keeps last data.
- [ ] Action buttons have busy state; admin changes are not optimistic; 503 handled.
- [ ] Works at 375px, light and dark, keyboard only, reduced motion.
- [ ] Colours only via tokens; nothing conveyed by colour alone.
- [ ] Attacker-controlled strings rendered as text.
- [ ] `make test-web` green; tests cover new states.
