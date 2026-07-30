# Handoff: 21b–21e, 22a–22b

Companion to the Quorum handoff. Same repo: `b1tninja/basilisk`, branch
`feat/toolkit-redesign`. Design reference: `21b-22b-reference.html` in this
folder (standalone extract of these six sections). Full context lives in the
design project's turns 19–22.

**Fidelity**: high for layout, spacing, color, copy. Prop shapes are the
intended contract — deviate only where a real repo constraint forces it, and
update this doc to match if so. Run the existing verification bar (`npm run
build`, `npx tsc --noEmit`, `npm test`, then `getComputedStyle` checks on
`/toolkit-widgets`) after each item lands, and add its state to
`toolkit-widgets.tsx` before considering it done.

---

## 21b — Publish plumbing for OutputList

Publish only appears on `openpgp.export` (public key) output rows — not a
generic action on any output. It publishes to the app's own key directory
(the same HKP source `OpsShelf`'s "Key directory" category already fetches
from). Clicking Publish opens a confirm popover ("Publish as `3F2A…C81`?
Anyone with directory access can fetch it.") before it does anything —
one-way action, no silent publish.

`publishedAs`/`directoryUrl` are written into the notebook document itself via
`useNotebook().publishArtifact(cellId, i)` — not local UI state, so reopening
the notebook still shows `@pub`. Once published, the row's Publish button
becomes a link icon next to `@pub` that copies `directoryUrl`.

```ts
interface OutputArtifact {
  // ...existing fields...
  publishable?: boolean;   // true only for key-export rows
  directoryUrl?: string;   // set once publishedAs is
}
// useNotebook().publishArtifact(cellId: string, outputIndex: number): Promise<void>
```

Wire this into `web/src/toolkit/widgets/OutputList` and `useNotebook.ts`.
`ToolkitShell.tsx` needs to actually pass `publishable`/`onPublish` down —
today those props exist on the component but nothing populates them.

---

## 21c — Search suggests the kit

If a browse-mode query matches zero ops but matches `kitOnly` ops, `OpsShelf`
shows a dashed suggestion row above the empty result set: "Not in browse mode.
Try the **AES / RSA** kit ▸". Clicking it calls the existing `onKitFilter`
(from 21a/20a) and keeps the query text, so the kit's own op list is still
filtered by the search term.

No new prop — `suggestedKit` is a derived value:

```ts
const suggestedKit = kits.find(k => k.ops.some(op => matches(op, filterQuery)));
// shown when browseModeResults.length === 0 && suggestedKit
```

Implement inside `OpsShelf`'s empty-state branch.

---

## 21d — Nested-caret shelf filtering

Compound ops declare `nestSlots` in the registry — one entry per internal slot
with its own expected kind. The nested caret (inside a chip, e.g. sign+encrypt)
reads that slot's kind instead of reusing the cell's overall tip fit set.

```ts
// registry.js — new shape on compound ops
nestSlots?: { [slotId: string]: { kind: OpKind } }

// OpsShelf fit computation
const fitKind = path.slotId ? op.nestSlots[path.slotId].kind : cellTip;
```

`Caret`'s `onActivate` needs to pass `slotId` alongside the existing path.
Ops with no `nestSlots` are unaffected — this is one added branch in the fit
computation, not a parallel filtering system.

---

## 21e — Suite status consolidation

`TopBar` already has a single `suiteStatus: { label, tone }` prop (landed with
20d) — the shell still renders four separate suite chips via TopBar's children
slot instead of using it. Collapse to one pill (worst-tone-wins, e.g. "3
suites ready · 1 issue") that opens a popover listing all four suites with
their individual dot/name/note.

```ts
interface TopBarProps {
  // ...existing...
  suiteStatus: { label: string; tone: 'ok' | 'warn' | 'error' };
  suiteDetail: { name: string; tone: 'ok' | 'warn' | 'error'; note: string }[];
}
```

Shell computes `label`/`tone` from `suiteDetail` (worst tone present + count
of non-ok) and passes both down. The four existing per-suite health checks
are unchanged — only their render site moves from inline chips to the
popover.

---

## 22a — Secret params in ParamField

Registry params can be marked `secret: true` (`quorum.offer/join key=`,
`rtc.ice credential=`). A secret `ParamField` renders locked — no free-text
entry, no literal value ever shown or stored — and only accepts a binding to
an Inputs-tray slot (`@slotName`). Recipe serialization (including Publish's
share link, 21b) omits the literal value entirely, keeping only the
`slotRef` string; an unbound secret param stays unbound for the recipient too.

```ts
// registry param shape
interface OpParam {
  // ...existing...
  secret?: boolean;
}
// ParamField value shape for secret params
type SecretParamValue = { kind: 'unbound' } | { kind: 'bound'; slotRef: string };
```

Touches `ParamField` (render branch for `secret`) and whatever serializes a
recipe into a share link — audit both Publish (21b) and plain copy/export for
the same redaction rule.

---

## 22b — TURN-configure action on stun.check

When `stun.check` reports no server-reflexive candidate, its `OutputList` row
grows one inline "Configure TURN" button. It opens the caret at the upstream
`rtc.ice` cell with the `turn=` param field focused — reuses the existing
caret-open mechanism (the same one `OpsShelf` already uses for
`pendingInsert`), targeted at a specific cell/field rather than a new panel.

```ts
interface OutputArtifact {
  // ...existing...
  diagnosticAction?: { label: string; onClick: () => void };
}
```

`onClick` is supplied by the shell (not `stun.check` itself) — present only
when the diagnostic actually failed; a clean check's row has no action.

---

## Not included: items 6 & 7

Live two-peer mesh verification and the resulting SESSION-transition polish
aren't design deliverables — there's nothing to spec until someone runs a
real paired offer/join/send/recv/close session in two browser profiles. See
turn 22's checklist in the design doc. Fold any breakage found there back into
`quorum-ops.js`.
