# ARIA interface foundation v1

Phase A review candidate. Canonical implementation: `web/static/styles/aria-foundation.css`. Review at `/static/design-system.html`. Architecture and data limits: `docs/aria-phase-a-architecture.md`.

## Design direction

A precise security operations console: midnight blue canvas, layered neutral surfaces, cool blue interactions, cyan observations, amber attention, and coral failures. Use balanced spacing and crisp hairline borders; reserve translucent surfaces for headers/overlays, with opaque fallbacks. Avoid decorative charts, moving graph traffic, ambient activity pulses and health colors unsupported by data.

Use IBM Plex Sans for headings/body/controls and IBM Plex Mono for commands, timestamps, IDs and accounting. These font families already exist in the application; system fallbacks keep the UI usable offline. Headings use weight 500–600, restrained tracking and sentence case. Default body 14px/1.6, support copy 12px/1.6, labels 12–14px. IDs may be truncated visually with an accessible full value and explicit copy action in future inspectors. Source text never enters innerHTML.

## Semantic tokens

| Purpose | Token | Value |
| --- | --- | --- |
| Canvas | `--aria-bg` | `#090d14` |
| Surface | `--aria-surface` | `#101722` |
| Raised surface | `--aria-raised` | `#172130` |
| Hover | `--aria-hover` | `#1e2b3e` |
| Subtle border | `--aria-border` | `#29374b` |
| Control border | `--aria-border-strong` | `#607697` |
| Main text | `--aria-text` | `#edf2fa` |
| Secondary text | `--aria-secondary` | `#b6c3d6` |
| Supporting text | `--aria-muted` | `#8d9fb8` |
| Interaction / focus | `--aria-primary` | `#a2bbff` |
| Text on primary fill | `--aria-on-primary` | `#0a142a` |
| Observed information | `--aria-telemetry` | `#77d5e4` |
| Confirmed success | `--aria-success` | `#83d8af` |
| Attention / approval | `--aria-warning` | `#f2c078` |
| Failure / denial | `--aria-danger` | `#ff9b9f` |
| Unknown / unestablished | `--aria-unknown` | `#b1bdd0` |

Text contrast is verified against the three intended panel surfaces; focus and input-boundary contrast are verified separately. Border-subtle is decorative, never the only indication of a control or status. Color never replaces a label. Exact computed results are in the browser report.

Spacing scale: 4 / 8 / 12 / 16 / 24 / 32 / 48px. Radii: 6px controls, 10px records/panels, 16px review/overlay surfaces. Component table rows use 14px vertical padding or 9px in compact density. Interactive controls remain at least 44px tall. Compact density reduces record padding, not touch targets.

## Component contracts

| Primitive | Contract |
| --- | --- |
| `.aria-panel`, head, body | Consistent surface and hierarchy. Heading, source/freshness, primary record content, then contextual details. |
| `.aria-button` | Native button for actions or anchor for navigation. Label the outcome explicitly. Primary accent for principal action; dangerous execution changes require existing authorization. |
| `.aria-field`, `.aria-input`, `.aria-help` | Visible label, minimum 44px height, associated instructions/error with `aria-describedby`; `aria-invalid` only when invalid. |
| `.aria-badge[data-tone]` | Explicit state text plus color and static marker. Semantic tone is supplied by a source-aware view, never guessed in CSS. |
| `.aria-notice` | Distinguishes absent data, unavailable source, block, failure and uncertainty. Put recorded reason and useful next action alongside the affected record. |
| `.aria-table` / wrap | Caption, scoped headings, stable rows, tabular records and a labeled keyboard-scrollable region if needed. Do not use grid roles on a native table. |
| `.aria-inspector` | Native details/summary disclosure; keyboard accessible without a custom widget. Later side inspectors need focus management and mobile full-screen presentation. |
| `.aria-skip`, `.aria-sr-only` | Focus-revealed skip links and screen-reader context. Main skip target accepts programmatic focus. |

The specimen's inputs, table rows and state notices are visibly labeled examples. Density selection changes row padding; motion checkbox turns off decoration; palette buttons reveal actual computed CSS token values. No specimen button grants authority, sends commands, starts runs or writes account state.

## Data-state vocabulary

- Loading: request is pending; do not announce each heartbeat or clear existing evidence.
- Not started: an authorized campaign read establishes that no campaign exists (expected 404).
- Empty: source successfully returned an empty collection.
- Not recorded: the source never retained that field, such as prompt previews.
- Unavailable: read failed or telemetry capability is absent; show cause category, not secrets.
- Blocked: authoritative source identifies a prerequisite preventing progress; preserve its reason.
- Failed: recorded terminal failure; do not substitute it for transport errors.
- Unknown: source cannot establish the state or a returned value is unrecognized.
- Stale: last good observation with retrieval/recording time; do not present as live.

Preserve source states for campaign/run/task/job; do not force all into a single misleading status. Session ACTIVE is a database lifecycle flag. It cannot prove live execution or an active agent. Missing accounting fields are unknown, never zero.

## Interaction, accessibility and motion

Use native semantics first, visible 2px focus with 3px offset, and logical document order. All interactive icons need names. Every status includes text. Support forced colors and reduced motion; token borders/focus must remain perceptible. Dense tables may scroll inside a named region; the page itself must not overflow at 390px width. Test reflow at 320px and text zoom as later layouts are rebuilt.

Decorative hover transitions last 150ms and do not imply execution. `prefers-reduced-motion` disables animations/transitions globally on adopting pages, including legacy decorative pulses. `html[data-motion="off"]` offers an explicit off switch for consumers; only the review specimen exposes it in Phase A. Do not claim an application-wide stored preference until the shared shell adds one. Later event animations must correspond to an observed event, stop promptly, and have an off switch.

No framework, chart, icon or animation dependency was added. Review header blur is progressive enhancement and keeps a near-opaque background. Shared system fonts remain legible if Google Fonts is blocked.

## Adoption and review boundary

Load the legacy page CSS, then `aria-foundation.css`, then `aria-legacy.css`. New pages use foundation primitives directly; they do not need the legacy adapter. Prefix all new tokens/classes with `aria-` to limit collisions. The adapter maps existing page variables and makes narrow shell/accessibility changes without replacing clients.

This phase unifies the four shells' foundational colors/type/focus/motion. It does not claim to have rebuilt legacy navigation, session lifecycle logic, information architecture, all literal component colors, or telemetry. Those changes require the reviewed phases in the architecture plan. Review the direction, state vocabulary, component density and migration approach before Phase B.
