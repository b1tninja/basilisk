# §58 reviewed — design critique and WCAG 2.1 AA audit

Both passes were run against §58 **before** any component was written, which is
the point: eleven defects in the previous session passed `tsc` and the full
suite while broken in the page, and a row that was drawn before it was argued is
how that happens.

Findings that changed the design are marked **→ §58 revised**. Findings recorded
and not acted on carry their reason.

---

## Design critique

### Overall

The section split is right and the row vocabulary is right — reusing
`.peer-dot[data-peer-state]` means the new rows inherit a state enumeration that
is already exactly `RTCPeerConnection.connectionState`, already CSP-safe, and
already measured. The problem is that the drafted row carries six fields in a
tray column and the identifier loses to its own metadata.

### Usability

| # | Finding | Severity | Recommendation |
|---|---|---|---|
| C1 | **Six fields per row** (dot / id / role / via / channel state / origin badge) in a ~280px tray. `id` is a truncating `<code>` and is the only thing that says *which* connection this is; five siblings squeeze it. | 🔴 Critical | **→ §58 revised.** Drop `role` (offerer/answerer) — negotiation trivia that answers no question the panel exists to answer. It belongs on the `connstate` tile, which opens in a full-width `Sheet`. Drop the origin badge for C2's reason. Four fields, matching the quorum rows. |
| C2 | **The origin badge is redundant with its own section header.** Rows are grouped under "Direct connections"; a `direct` badge on every row inside it is the section title repeated N times. | 🟡 Moderate | **→ §58 revised.** Remove the badge. Grouping *is* the origin signal. |
| C3 | **Restart on a link that has not failed is a control with nothing to do.** ICE has not given up at `new`/`connecting`, so the button is either dead or misleading. | 🟡 Moderate | **→ §58 revised.** Restart renders only for `failed`/`disconnected` — which is precisely what `SessionStrip` already does with `state === "failed"`. Absent, not dimmed: the established rule for a control that does not apply. Close is always available. |
| C4 | **The empty state names only `quorum.offer`/`quorum.join`.** It is now the only place on screen that can teach a user the new capability exists, and it does not mention it. | 🟡 Moderate | **→ §58 revised.** The empty state names `peer.offer` first — it is the lower-ceremony path — then the quorum pair. This is the highest-value copy on the panel. |
| C5 | **§58 says nothing about when a row leaves the list**, so a link that fails could vanish at the moment it becomes worth reading. | 🟡 Moderate | **→ §58 revised.** Mirror the policy `closeQuorumExchange` already uses: a link closed on purpose is deregistered; a link that reached `failed` stays until closed, so it can be read and restarted. |
| C6 | A cell paused inside `peer.wait` has no cell-level strip — `SessionStrip` is wired to the quorum exchange only. The tray answers "what is live", nothing answers "what is *this cell* waiting on". | 🟢 Minor | **Recorded, not built.** A per-cell strip for `peer.*` needs a second state channel through `useNotebook`; it is unit-2 sized and is listed in §59c. |

### Visual hierarchy

- **Eye lands first** on the two section headers, which is correct — "Direct
  connections" is the only name the new capability has on screen.
- **Reading flow** header → caution → rows → actions. The caution before the
  rows is right: it frames them rather than annotating them after the fact.
- **Emphasis**: with C1 applied, the `id` is the widest element in the row and
  the only one at full `--foreground`. Everything else is
  `--muted-foreground` or a chip. That is the correct ranking.

### Consistency

| Element | Issue | Recommendation |
|---|---|---|
| Authentication column | **The two sections would use different grammars in the same column position.** Quorum rows say `verified`/`unverified` per row; the drafted direct rows said nothing per row and put the caution on the header. The section that is *less* safe would look cleaner. | **→ §58 revised.** Direct rows carry `unauthenticated` in the same `.peer-verdict[data-verdict="warn"]` slot. One vocabulary, one column, no new colour. The header keeps the *explanation*; the row keeps the *label* — the same headline/why split `connStateReadout` already uses, which is also what answers the alarm-fatigue objection: the row word is a label, not an alarm. |
| Dot size | `ConnectionsPanel` uses 7px, `SessionStrip` uses 5px. | Direct rows use 7px — they are `ConnectionsPanel` rows. |
| Motion | Considered pulsing the dot while `connecting`, as `SessionStrip` does while the run is paused. | **Rejected.** The two are not the same fact — the strip pulses because a *run* is blocked, and the panel does not know that. The dot's colour already separates `connecting` (`--caret`) from `connected` (`--brand`), so the pulse buys little and costs a `prefers-reduced-motion` rule. |

### What works well

- The state enumeration needed no extension. `RTCPeerConnection.connectionState`
  is the closed set `.peer-dot` already draws, which is why no new colour, no
  new token and no inline style is involved.
- Putting the failure verdict in `connStateReadout` means the panel and the
  `connstate` tile cannot disagree about why a connection failed — the class of
  defect that produced six others in this codebase.

---

## Accessibility audit

**Standard:** WCAG 2.1 AA
**Issues found:** 5 | **Critical:** 0 | **Major:** 3 | **Minor:** 2

### Operable

| # | Issue | Criterion | Severity | Recommendation |
|---|---|---|---|---|
| A1 | **Touch targets under the minimum.** The panel's existing buttons are `px-2 py-1 text-[10px]` — roughly 22px tall against 2.5.8's 24×24 CSS px floor. Per-row buttons would multiply the problem by N. | 2.5.8 Target Size (Minimum) | 🟡 Major | **→ §58 revised.** New controls get a `min-height: 24px` through a stylesheet class (`.link-action`), not a utility soup. **The pre-existing session buttons are a separate, older finding** — recorded in IMPLEMENTATION-STATUS rather than swept into this change, because a blanket find-replace across a widget nobody asked me to touch is how a sibling status doc once ticked three unbuilt items. |
| A2 | Restart absent rather than disabled when it does not apply (C3). | 4.1.2 / §47's disabled-reason finding | 🟢 Minor | Already the resolution of C3. Nothing to add — and it sidesteps the whole `disabled`-hides-its-own-reason problem §47 documents. |

### Robust

| # | Issue | Criterion | Severity | Recommendation |
|---|---|---|---|---|
| A3 | **Per-row buttons have no accessible name beyond their label.** A screen-reader user hears "Close", "Close", "Close" with nothing distinguishing which link each one tears down. This is the single highest-value finding in the audit. | 4.1.2 Name, Role, Value | 🟡 Major | **→ §58 revised.** `aria-label={`Close connection ${id}`}` / `aria-label={`Restart connection ${id}`}`. The visible label stays short; the accessible name carries the object. |

### Perceivable

| # | Issue | Criterion | Severity | Recommendation |
|---|---|---|---|---|
| A4 | **No heading structure inside the panel.** `ConnectionsPanel` has no headings at all today — the tab's `<h3>` lives in `ToolkitShell` — so two sections would be two undifferentiated runs of list. Heading navigation is a primary screen-reader movement. | 1.3.1 Info and Relationships | 🟡 Major | **→ §58 revised.** Each section gets an `<h4>`, and each `<ul>` is associated with it via `aria-labelledby`. |
| A5 | **The caution sentence would be the smallest text on the panel** at 10px while carrying the only safety-relevant prose. | 1.4.3 / editorial | 🟢 Minor | **→ §58 revised.** 10.5px, matching the weight `ToolkitShell` gives a tray tab's own description. |

### Not issues, checked and recorded

- **Colour alone (1.4.1).** `.peer-dot` is colour-only *and* `aria-hidden`, but
  every row also prints its state as text. The information is not conveyed by
  colour alone. This is a second, independent argument for C1's "drop `role`,
  keep the state text".
- **Contrast (1.4.3, 1.4.11).** Every colour in the new rows is an existing
  measured rule — `.peer-dot`, `.peer-verdict`, `--muted-foreground` — from the
  pass that took 208 nodes to zero below 4.5:1 in both themes. New nodes are
  measured on the catalog rather than assumed; figures in
  IMPLEMENTATION-STATUS, sanity-checked at black-on-white = 21.00 first, because
  two probes this week reported false failures by compositing wrongly.
- **Live region.** Rejected. `aria-live="polite"` on a list that churns through
  `new → connecting → connected` during ICE would announce continuously for the
  entire handshake. The panel is a surface you look at, not one that narrates.
- **Keyboard (2.1.1, 2.4.3).** Rows are `<ul>/<li>` with real `<button>`s in DOM
  order after the row text. Nothing custom, nothing to trap.
