# Artifact tiles — visual design (§39–§46)

The visual and interaction layer for the capability designed in
[ARTIFACT-ACTIONS-DESIGN.md](../ARTIFACT-ACTIONS-DESIGN.md) §32–§38. That
document is decided; this one visualises it. Where the two could be read as
disagreeing, the structural document wins and this one is wrong.

Numbered §39 onward because §18–§38 are taken. As with the parent document, an
unqualified `§` means this handoff series; the design v2 series is cited in
full (`design v2 §20h`).

Companion file: [`artifact-tiles-mock.html`](./artifact-tiles-mock.html) — every
tile kind, both colour schemes side by side, the three confirmations stacked
for comparison, and the states. This document carries the reasoning; the mock
carries the pixels. Every number below was measured on the mock served over
`http://127.0.0.1:4199` at a 1440×1000 and an 855×1258 viewport, or on the
shipped `OutputList` at `http://localhost:4188/toolkit-widgets.html`.
`window.innerWidth` was non-zero on every measurement reported here; the
0×0-viewport failure the handoff warns about did not occur, and `file:` URLs
were avoided entirely.

**DesignSync was not available in this session.** The MCP tool is not
registered — `ToolSearch` for it returns nothing, and the deferred-tool list
contains no design-project tool of any name. Nothing was read from or written
to the Claude Design project at
`https://claude.ai/design/p/73a4f81e-d784-44bb-89c5-1fe4ff8a979e`, and the
`Basilisk Toolkit v2.dc.html` conventions were therefore matched only
indirectly, through `DESIGN-ITERATION-PROMPT.md`'s description of them and
through the shipped widgets. Per the charter's fallback, the deliverable is
this document plus a self-contained static mock. **Whoever next has DesignSync
should port §39–§46 into the design document as a new numbered section**; the
section structure here was written to be portable to the 19a-style
mockup-panel + dashed-props-panel format.

---

## §39 Foundations, and two corrections the tile needs first

### §39a What this layer is allowed to invent

Nothing. Every colour named here is a token that exists in
`web/src/css/site.css`, in both the `:root` block and the
`@media (prefers-color-scheme: light)` override. The tokens in play:
`--brand`, `--on-brand`, `--surface`, `--surface-raised`, `--border`,
`--border-weak`, `--text` (mirrored as `--foreground`), `--text-muted`
(mirrored as `--muted-foreground`), `--error`, `--success`, `--caret`,
`--decode`, `--warn`, `--accent`.

This is worth stating because the previous static mock
(`../artifact-actions-reference.html`) invented `--ssh: #39c5cf` for a
fifth kind-badge tone, and separately used light-theme values that are not the
product's (`--brand: #1a7f37` where site.css says `#2e7d4f`,
`--muted-foreground: #636c76` where site.css says `#57606a`). Both are easy
mistakes and both are load-bearing: a contrast figure computed against the
wrong light palette is not a weaker claim, it is a false one. The mock in this
directory copies the token block verbatim and scopes it to `[data-theme]`
rather than to a media query, which is what lets both schemes render at once
and be measured in a single pass.

Where a design wants a value the tokens cannot express, §39d says so instead of
inventing one.

### §39b Correction one: `<code>` does not obey the type scale

`site.css:1127` sets

```css
code { font-family: …; font-size: 0.78rem; word-break: break-all; }
```

**unlayered**. Tailwind utilities live in `@layer utilities`, and unlayered
rules beat layered ones regardless of specificity. So every `<code>` element in
the shipped tile renders at 12.48px whatever its class says. Measured on
`/toolkit-widgets.html`:

| element | class asks for | actually renders |
|---|---|---|
| identity label | `text-[11px]` | 12.48px |
| raw body | `text-[10px]` | 12.48px |
| tray label | `text-[11px]` | 12.48px |

A control probe confirms the mechanism rather than guessing at it: a
`<span class="text-[11px]">` injected into the same parent renders at 11px; a
`<code>` with the identical class renders at 12.48px.

Two consequences, and the second is the one that matters. First, the tile has
no working type scale today — three intended sizes collapse to one. Second, the
collapse is an *inversion*: the raw body, specified at 10px as the quietest
text in the tile, renders larger than the identity label that names it. The
densest element is the loudest.

**Decision: mono text in the tile is sized by class in `toolkit.css`, not by a
Tailwind utility, and the identity label is authored as a `<span
class="font-mono">` rather than a `<code>`.** This is the workaround the repo
already documents for exactly this cascade ("add a scoped bump rule in
`toolkit.css` — see `.suggest-chip.border-dashed`, `.tool-card[data-pinned]`),
and it is enumerated CSS in a stylesheet, so it costs nothing under
`style-src 'self'`.

Rejected: deleting or narrowing `code { font-size: .78rem }` in site.css. It is
a global rule serving every non-toolkit page in the product, this design has no
mandate over those pages, and a change there would be felt far outside the
tile. Rejected also: adopting 12.48px as the tile's mono size. It is 25% over
the intended body size on the densest element in the densest widget, and it was
never chosen — it is `0.78rem` inherited from a documentation stylesheet.

### §39c Correction two: the tint that works in dark fails in light

The tile tints backgrounds by mixing a hue into the surface — the kind badge at
12%, the active format-bar tab at 18%. In dark this raises the chip off the
background. In light it lightens the background *toward the text colour*, and
contrast falls. Computed across the four badge hues:

| tint over `--surface` | caret | brand | decode | warn |
|---|---|---|---|---|
| light, 18% (format bar today) | — | **3.97** | — | — |
| light, 12% (badges today) | **4.38** | **4.31** | **4.29** | **4.17** |
| light, 8% | **4.64** | **4.55** | **4.54** | **4.39** |
| light, 6% | 4.77 | 4.67 | 4.66 | **4.51** |
| dark, 12% | 6.30 | 8.74 | 7.89 | 7.94 |

Everything in a tile is small text, so 4.5:1 is the bar throughout; bolded
figures are below it. Every badge tone fails in light today, and so does the
active format tab.

**Decision: one token, `--tile-tint`, carrying `12%` in dark and `6%` in light,
used by the kind badge and the active format tab alike.** 6% is the largest
tint at which the binding case (warn, 4.51:1) still clears. 8% is tempting and
fails on warn; 12% fails on everything.

Rejected: dropping the tint in light and using `--surface-raised` for badge
backgrounds (4.57–4.88 — it passes, but the badge stops reading as tinted at
all and the kind hue survives only in the text, which loses the fastest signal
in the identity line). Rejected: per-hue tint percentages tuned individually —
four numbers to maintain where one will do, and the next hue added would
silently inherit whichever it was nearest.

This is expressible under CSP: it is a custom property set in site.css's
existing light-scheme block, consumed by `color-mix()` in a stylesheet. No
inline style, no `css-vars.js`.

### §39d What the tokens cannot express

One thing, named rather than invented:

- **A fifth kind-badge hue.** The badge tones available are `--caret` (default),
  `--brand` (keys), `--warn` (diagnostics), `--decode` (shares/recipients), and
  an untinted `--surface-raised`/`--muted-foreground` for kinds that have earned
  no hue. That is five slots for fifteen roles, so roles share tones — which is
  correct, because the badge's job is the *label text*, and the hue is a coarse
  family signal. If a future kind genuinely needs its own hue, that is a
  site.css token addition and a palette decision, not something a tile invents.

Everything else this design needs — the three action tiers, the banner shell,
every state — is expressible in the existing tokens.

---

## §40 Tile anatomy, at pixel level

One component, `ArtifactTile`. The §33a pins hold and were re-confirmed by
`getComputedStyle` against the shipped `OutputList`: list border 1px `--border`,
radius 10px, padding 4px, background `--surface`; row padding `8px 10px`; row
gap 4px; action buttons 22px tall at 10px. Nothing below changes a pin.

### §40a The vertical rhythm

```
┌──────────────────────────────────────────────────────────┐  ← 1px --border, r10
│ ░░ 4px list padding ░░                                   │
│ ┌──────────────────────────────────────────────────────┐ │
│ │  8px                                                 │ │
│ │  [KEY] kp · public JWK      sensitive        412 B   │ │  identity, 18px min
│ │  4px                                                 │ │
│ │  <the kind's view, or the masked substitute>         │ │  body
│ │  4px                                                 │ │
│ │  card raw │ Copy  More ▸ │ Add to keyring │ Publish  │ │  actions, 22px
│ │  4px                                                 │ │
│ │  ✓ Added to My Keys · device · SHA256:Ur1h…      ⧉   │ │  receipt
│ │  8px                                                 │ │
│ └──────────────────────────────────────────────────────┘ │
│  ── 1px --border @55% ──                                 │  tile divider
```

The 4px gap is a single `row-gap` on the tile's flex column, not four margins.
Sections that are absent contribute no gap — a tile with no receipt is exactly
as tall as today's row, which is what "the redesign is not a re-skin" has to
mean dimensionally.

### §40b The identity line

`display:flex; align-items:center; gap:10px; min-height:18px`.

| part | spec | token |
|---|---|---|
| kind glyph | 10×10 SVG, `currentColor`, inside the badge | — |
| kind badge | 9px/500, uppercase, `letter-spacing:.05em`, padding `2px 5px`, radius 3px | text = hue, bg = `color-mix(hue var(--tile-tint), --surface)` |
| label | 11px/500 mono, `flex:1`, ellipsis, **authored as `<span class="font-mono">`** (§39b) | `--foreground` |
| sensitive badge | 10px/700 uppercase, padding `1px 6px`, radius 6px, 1px border | `--foreground` on `--accent` 18%, border `--accent` 45% |
| size | 10px/400 mono, `flex:0 0 auto` | `--muted-foreground` |

The badge text is the *kind's* `label` — "Public key", "Keypair", "Token" —
never a ternary computed at the call site. §33a's observation that the same
artifact currently wears one badge in the cell and a different one in the tray
is ended by construction, because both read the same registry entry.

The size stays last and right. It is the one field that is pure metadata, and
putting it at the end lets the label truncate into the space the size does not
use rather than fighting it.

### §40c The body

The body is the kind's `view`, and this document does not specify per-kind
bodies beyond the key card (§42) — that is the registry's business. What the
*tile* owns is the three substitutes, which must look the same on every kind:

- **Masked** (§33e): `sensitive — value not shown`, 10px italic mono,
  `--muted-foreground` (6.15:1 dark / 6.39:1 light), with the Reveal button
  beside it when `revealable` is set. Reveal is a 10px/600 outline button in
  `--warn` at 45% border — the same visual weight as an outward action, because
  it has the same character: deliberate, and it puts something somewhere it was
  not.
- **Empty** (`kind.empty`): 10.5px/400 sans, `--muted-foreground`, max ~62ch.
  Sans rather than mono on purpose — it is a sentence about the value, not the
  value.
- **Failed** (`kind.failed`): 10.5px sans in `--error` on an `--error` 10% tint
  with a 2px `--error` left border, **above** the raw body rather than replacing
  it. The parse failed; the bytes did not.

### §40d Where the raw body sits

`max-height:96px`, `overflow:auto`, `white-space:pre-wrap`,
`overflow-wrap:anywhere`, 10px/1.5 mono, `--muted-foreground` when the value is
public and `--foreground` once revealed. The colour flip is the whole visual
difference between "this is context" and "this is the secret you asked to see",
and it costs nothing.

96px is 4px more than the shipped `max-h-24`; it is the same value, expressed
against the corrected 10px type so it holds ~6 lines rather than ~5.

### §40e The receipt line

Absent until something has happened. `padding-top:4px` above a 1px `--border`
40% rule — the only internal division in the tile, and it earns its place
because the line below it is a statement about the past while everything above
is the present.

10px/400 sans in `--muted-foreground`, with:

- a `--success` tick glyph (11px) for a completed local mutation,
- the vault id in mono `--foreground` with a copy affordance, because that
  string is what a later `agent.sign fpr=…` needs,
- or, for a failure, the thrown message verbatim in `--error`.

Three weights matched to three tiers, per §33f: inert actions produce no
receipt line at all (they route to the notebook toast strip that already
exists); local mutations produce a persistent line; outward actions replace
their own button.

---

## §41 The action row

### §41a The problem, stated as a picture

The hard case is one tile with four inert actions, one local, and one outward —
the public-key card. Six controls in a 22px band. Two failure modes bracket it:
if the tiers are three hues it is a rainbow, and if they are three copies of the
same button it is a toolbar, which is to say the user reads none of them.

**Decision: three weights, one hue.** Weight is carried by fill and label
darkness; colour is spent only on the tier that leaves the machine.

| tier | fill | border | label | measured |
|---|---|---|---|---|
| **inert** | none | none | `--muted-foreground` | 6.15 / 6.39 |
| **local** | `--surface-raised` | 1px `--border` | `--foreground` | 14.64 / 15.20 |
| **outward** | none | 1px `--warn` 45% | `--warn` | 9.72 / 4.87 |

Reading left to right the row goes quiet → solid → outlined-amber, and the
amber appears exactly once. An inert action looks like a link; a local action
looks like a button; an outward action looks like a button someone has drawn a
box around and coloured. That is the correct ranking of consequence, and it
survives being squinted at, which is the actual test.

Rejected: `--caret` for the local tier, which is what
`../artifact-actions-reference.html` proposes. Blue is the caret colour in this
codebase and carries "this is where the insertion point is" in `InsertGap`,
`OpsShelf`'s caret banner, and the pipeline's active-step ring. Spending it on
"this writes to your device" both dilutes a signal that is load-bearing
elsewhere and puts a third hue inside a 22px row.

Rejected: brand fill on the outward action, which is what ships today
(`bg-[var(--brand)] font-bold text-[var(--on-brand)]`). §34a already argues this
on meaning — brand is this codebase's "do this", and the one irreversible action
should not be where the eye lands. The measurements add a second, independent
argument: a `--warn` *fill* with dark text is 9.41:1 in dark and **3.76:1 in
light**, which is the shipped "Configure TURN" button and a live light-theme AA
failure. There is no accessible amber fill available in this palette. Outline is
not merely the more tasteful choice; it is the only one that passes in both
schemes.

### §41b Groups, order, and the gutter

Left to right: **view**, **inert**, **local**, **outward**. Within a group the
gap is 4px; between groups a 6px margin either side of a 1px × 14px `--border`
hairline. The view group (the `FormatBar`, `Expand`) is separated by an 8px
space rather than a hairline, because it is not an action at all and a rule
would imply it were.

The hairline is doing work that colour would otherwise have to do. Three groups
separated by whitespace alone read as one row of six; separated by rules they
read as three things. It costs one pixel of `--border` and no hue.

Outward is always last, so it is last in DOM order, so it is last in tab order
and never the default-focused control — §33b's requirement satisfied by the
ordering rule rather than by remembering an `autoFocus` somewhere.

**No `margin-left:auto` on the outward group.** Pushing it to the far right
edge is precisely the toolbar tell this section is trying to avoid: a left
cluster with one right-aligned control is the universal shape of an application
toolbar with a primary action. Left-packed with a gutter, the row reads as a
sentence that ends in Publish.

### §41c Overflow

More than four visible inert actions collapses everything past the fourth into
the existing `MenuPopover` as **More ▸**, tier order preserved inside the menu.
Local and outward actions are never collapsed. The More button is itself inert
weight, so the collapse does not change the row's colour balance.

### §41d Disabled, and the reason that has to be readable

This is the single most consequential contrast decision in the design, because
§33d makes the reason string *the feature* — "a dead button with no reason is
worse than no button".

The shipped `Button` carries `disabled:opacity-50`. Applied to this row that
yields:

| disabled treatment | dark | light |
|---|---|---|
| `--muted-foreground` at `opacity:.5` | **2.41** | **2.20** |
| `--foreground` at `opacity:.5` | 4.68 | **3.20** |
| **`--muted-foreground`, no opacity (chosen)** | 6.15 | 6.39 |

2.20:1 is not a dimmed label, it is an absent one. A reason nobody can read is
the same as no reason, which is the exact failure §33d exists to prevent — and
it is the same class of bug the last polish pass found in this area at 1.97:1
and 1.59:1.

**Decision: disabled actions do not reduce opacity. The label holds
`--muted-foreground` at full strength; the *affordance* is removed instead** —
no fill, no border, `cursor:not-allowed`, and a dotted underline in
`--muted-foreground` 60% marking that a reason is attached. The reason itself
rides `title` and `aria-describedby` per §33d.

This means a disabled action and an enabled inert action share a label colour,
which sounds like a problem and is not: they differ by the dotted underline and
by the hover response, and an inert action was already the quietest thing in the
row. The alternative — making disabled *darker* than enabled-inert — inverts the
hierarchy to serve a state that should be rare.

Note the interaction with the tier weights: a disabled **local** or **outward**
action loses its fill or its amber border and drops to inert weight. That is
correct and deliberate. A `Publish` button that cannot publish should not still
be wearing the colour that means "this leaves the machine"; the colour is a
promise about what will happen if you click.

### §41e In-flight

The button keeps its tier weight, swaps its label to the progressive form
("Adding…"), and gains a 9px `currentColor` ring spinner. It is not disabled —
it is `aria-busy` — because a disabled control loses its accessible name in some
screen-reader/browser pairs at the exact moment the user most wants to know what
is happening. Under `prefers-reduced-motion: reduce` the spin slows from 0.7s to
2.4s rather than stopping, because a frozen spinner reads as a hang.

---

## §42 The key artifacts

The two tiles the feature will be judged by. Today a keypair renders as two JWK
blobs, one masked, both badged `text`/`secret`, with a single Copy between them.

### §42a The public-key card

Four rows in a `<dl>`, `grid-template-columns: 76px minmax(0,1fr) 16px` —
label, value, copy affordance. Labels 9px/600 uppercase `--muted-foreground`;
values 10px mono `--foreground`; `overflow-wrap:anywhere` so a fingerprint wraps
instead of scrolling.

```
ALGORITHM     ed25519
FINGERPRINT   SHA256:Ur1hPKBrJC3zF0Qw9pLmXaYd8vN2sQ4tR6wE1cB7gH0    ⧉
PUBLIC LINE   ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH8k7vQ2… justin@…  ⧉
```

The 76px label column is the narrowest that fits `FINGERPRINT` at 9px without
wrapping, which is what sets it; `PUBLIC LINE` and `ALGORITHM` fit inside it.

- **Algorithm** is 10px/600 — the one value in the card set in semibold, because
  it is the answer to "what am I looking at" and everything else is an
  identifier. It comes from `traits.alg`, not re-derived from the JWK: the value
  the recipe named is the value to show.
- **Fingerprint in kind shape** (§28a): `SHA256:` + unpadded base64 for SSH,
  grouped hex for OpenPGP, `spki:SHA256:` for raw. The copy affordance copies
  the display format, never a normalised variant — the point of showing it in
  `ssh-keygen -lf` shape is that it can be compared to a server log line
  character for character, and a copy that silently renormalises defeats that.
- **Public line** only for SSH-mappable algorithms. For x25519 / AES / HMAC the
  row *and its action are absent*, per §33d — SSH has no key type for them and a
  disabled row would teach a falsehood about the artifact.
- **Raw** is a format-bar tab (`card` / `raw`), not a separate button. The JWK is
  one click away and nothing is taken away; it stops being the only thing
  offered.

The card is a read-out, and the visual argument for it over the JWK dump is
simply that every line in it is a line a human would say out loud. Nobody reads
`{"kty":"OKP","crv":"Ed25519","x":"…"}` and thinks "ed25519 key".

### §42b The masked private-key tile

The deliverable that carries the most risk, because it is the one place this
design shows *more* than today on a masked value.

```
[KEY] kp · private JWK              sensitive            648 B
ALGORITHM     ed25519
FINGERPRINT   SHA256:Ur1hPKBrJC3zF0Qw9pLmXaYd8vN2sQ4tR6wE1cB7gH0   ⧉
sensitive — value not shown                              [ Reveal ]
Copy(disabled)  Copy fingerprint  Download │ Add to keyring
▌ Download writes the private key unencrypted — …
```

`publicView` renders the algorithm and the fingerprint *while masked*, and the
masked line sits underneath them, unchanged. This is not a softening of the
gate. The rule is stated once and enforced in one place — **a masked tile may
render only what does not derive from the masked material** — and both rows
clear it: the algorithm is `traits.alg`, and the fingerprint is a digest of the
*public* half. The public line is omitted here rather than shown, not because it
would leak but because the private tile's sibling already shows it and repeating
it doubles the tile's height for no new fact.

The actions are the ones §35d specifies, and their visual states are the whole
point:

- **Copy** — declared, disabled, reason `"Reveal this value first — a masked
  value cannot leave the notebook."` It renders at inert weight with the dotted
  underline. Declared rather than omitted because §33d's first question
  ("meaningful for this object?") is yes — the JWK is copyable once revealed.
- **Copy fingerprint** — enabled while masked. What it emits derives from the
  public half. **Download is not**: it takes Copy's branch verbatim and shares
  its sentence, which is why that sentence names neither action. (This bullet
  said Download was enabled; what shipped disables it, because §34b gates on
  whether a value *leaves* and a file is where a secret goes to be kept.)
- **Add to keyring** — enabled while masked, at full local weight. This is the
  clearest case in the design for the mask rule being about *where a value
  lands*: the vault's whole job is to hold the value without showing it, and
  requiring a reveal first would force the secret onto the screen in order to
  put it somewhere safe.

The unencrypted-export warning row (§29f) sits below the action row, not above
it — it is a consequence of one action, and putting it above would make it read
as a property of the artifact.

### §42c The warning row's colour, corrected

The row was drafted as `--warn` body text on a `--warn` 10% tint. Measured:
8.27:1 dark, **4.28:1 light**. Below the bar.

**Decision: the sentence is `--foreground`; the warning is the 2px `--warn` left
border and the 8% tint.** 14.15:1 / 14.60:1. This is also the grammar the
approval banner already uses (§43) — body text in `--foreground`, warn carried
by the border — so a warning row and a confirmation banner now read as one
family rather than two amber things of different saturations.

---

## §43 Confirmations

### §43a One shell, three banners

The outward confirmation (§34c) and the overwrite confirmation (§34d) render in
the same shell as the shipped `ApprovalBanner`, extracted as `GateBanner`.
Measured from `ApprovalBanner.tsx` and reproduced exactly:

| part | spec |
|---|---|
| container | 2px `--warn` left border, 1px `--border` elsewhere, `color-mix(--warn 8%, --surface)` background, padding `10px 14px` |
| header | 11.5px/600 `--foreground` |
| header meta | 10px mono `--muted-foreground`, `margin-left:auto` |
| facts | `<dl>` `grid-template-columns: 68px minmax(0,1fr)`, gap `4px 8px`, 10.5px |
| `<dt>` | 600 weight, `--muted-foreground` (5.44 / 5.77) |
| `<dd>` | `--foreground` (14.15 / 14.60), sub-text `--muted-foreground` |
| actions | `margin-top:10px`, gap 8px, ghost cancel then secondary confirm, both 22px at 10.5px |

The mock stacks all three in one column per theme so the resemblance is
checkable rather than asserted.

Why the same grammar and not a better one: a user who has learned that "a
warn-bordered inline panel with a facts table means something consequential is
about to happen, and I have to choose" should not have to learn a second visual
language for the same sentence. A second confirmation grammar teaches that
confirmations are decorative, which is the failure mode that makes every
confirmation in the product worthless.

### §43b What is visibly absent, and why absence is the design

Compared to §27's banner, the publish confirmation has **no session checkbox,
no "approve the remaining N", and no request counter**. Those absences are the
entire semantic difference, and keeping the shell identical is what makes them
legible: the eye lands where the checkbox was and finds nothing there.

There is no defensible "don't ask again" for publishing. Each publish is its own
irreversible act, and a five-minute window in which a tile publishes without
asking is a bug wearing a checkbox.

### §43c The confirm button is not the loud one

Both new banners use ghost **Cancel** then secondary **Publish** / **Replace** —
the same pairing and the same weights as Deny / Approve once. The confirm button
is *not* rendered in `--warn`: inside the banner it would sit on the warn-8%
tint, where `--warn` text measures 4.39:1 in light and fails. It is also
unnecessary — the banner is already entirely amber-framed, and the user reached
it deliberately.

This is the one place the outward tier's hue does *not* appear on the outward
action, and the rule that reconciles it is: amber marks the *decision point*.
On the tile, the decision point is the button. Inside the banner, the decision
point is the banner, and the buttons are its answer.

### §43d Placement

Inline in the tile, directly under the action row, `role="alertdialog"`, focus
moved to Cancel on open, Escape resolves as cancel. Not the popover
`OutputList` uses today: §27a's reasons transfer verbatim — the context (which
tile, which artifact) must stay visible, and a floating layer that can be
dismissed by clicking away trains dismissal. The tile grows; nothing overlays.

---

## §44 States

Every state below is rendered in the mock, both themes.

| state | body | action row | receipt |
|---|---|---|---|
| **empty** | `kind.empty` sentence, 10.5px sans muted | unchanged | none |
| **failed** | `--error` note on error-10% + 2px left border, **above** the raw body | unchanged | none |
| **masked** | `publicView` if declared, then the masked line + Reveal | Copy disabled w/ reason; fingerprint & Download live | none |
| **disabled-with-reason** | unchanged | affected buttons drop to inert weight + dotted underline | a line naming how many are unavailable |
| **in-flight** | unchanged | button keeps tier weight, `aria-busy`, spinner, progressive label | none |
| **success (local)** | unchanged | unchanged, still enabled | persistent ✓ line with vault id + copy |
| **success (outward)** | unchanged | **button replaced** by `@a1b2c3d4` + link-copy | none |
| **error after action** | unchanged | **stays enabled** — retryable | `--error` line, message verbatim |

Three of these deserve a sentence.

**Failure does not disable.** A failed publish is retryable, a failed keyring
write is retryable, and the thrown message renders verbatim. Swallowing it for a
generic "something went wrong" would be the one thing worse than the failure.

**Outward success removes its own trigger.** The Publish button becomes the
`@slot` plus a link glyph that copies `directoryUrl` — the shipped `publishedAs`
behaviour, kept because it is the only one of the three receipt weights that
makes re-firing an irreversible action structurally impossible. It is not a
disabled button and not a success toast; the affordance is gone.

**Local success keeps its button.** Adding a key to the keyring twice is
harmless in a way publishing twice is not, and §34d's overwrite banner already
guards the case where it would not be.

---

## §45 Responsive

### §45a The constraint is the list, not the viewport

Measured on the shipped app: the output list is **448px wide inside a 1440px
viewport**. A viewport media query therefore asks the wrong question — the tile
is narrow on a wide screen, all the time, because it lives in a cell inside a
column.

**Decision: `container-type: inline-size` on the list, and the one responsive
rule in the design is a `@container` query.** This is the only primitive that
asks "how wide is the tile", and the answer is what the action row's wrapping
actually depends on.

### §45b What breaks, and in what order

Measured on the mock by forcing the list to each width and reading the rendered
line breaks of the six-action worst case:

| list width | line 1 | line 2 | line 3 | row height |
|---|---|---|---|---|
| ≥ 600px | all six | — | — | 22px |
| 560px | 4 inert + local | Publish | — | 50px |
| **448px (shipped)** | 4 inert | Add to keyring | Publish | 84px |
| **375px** | 3 inert | More ▸ + Add to keyring | Publish | 84px |
| 320px | 2 inert | 1 inert + More ▸ + local | Publish | 84px |

No horizontal overflow at any width down to 320px; the body never scrolls
sideways.

The degradation order is: the inert group sheds buttons into **More ▸** first,
then the local group drops to its own line, then the inert group wraps
internally. Nothing is ever hidden without a menu to reach it, and the local and
outward groups are never collapsed — §33b's rule that an action with
consequences does not hide behind a chevron.

### §45c The one rule, and the bug it fixes

Naive `flex-wrap` produced a real defect that only measurement caught: at 448px
and at 375px — the shipped width and the phone width, i.e. the two that matter —
**`Add to keyring` and `Publish` wrapped onto the same line, adjacent**,
separated by nothing but the 1px hairline. The local and outward tiers, which
the entire tier vocabulary exists to distinguish, ended up shoulder to shoulder
at exactly the widths where the row is most crowded.

```css
.brk { display: none; }
@container artifact-list (max-width: 520px) {
  .brk { display: block; flex: 0 0 100%; height: 0; }
  .gsep-outward { display: none; }
}
```

`.brk` is an inert `<span>` emitted immediately before the outward group, dead
at desktop width. Under the query it becomes a zero-height full-width flex item,
which forces the outward action onto its own line *without stretching it* and
without a viewport breakpoint. The hairline that would have ended the previous
line is hidden with it: a separator at end-of-line separates nothing.

520px is the threshold because the row still fits comfortably above it and the
shipped 448px sits below it.

Rejected: `flex-basis:100%` on the outward button itself — it forces its own
line at *every* width, including desktop where the row fits, and it stretches
the button to full width, which makes the most dangerous control in the tile the
biggest. Rejected: a viewport media query — it would not fire at all in the
shipped 448px-in-1440px case, which is the exact case that is broken.

### §45d The rest of the tile at 375px

The identity line and the key card need no special handling: the label
truncates with an ellipsis (it is `flex:1; min-width:0`), the size stays
right-aligned, and the `<dl>`'s `minmax(0,1fr)` value column plus
`overflow-wrap:anywhere` wraps a fingerprint across two lines instead of
scrolling. The 76px label column is kept at 375px rather than collapsing to a
stacked layout — stacking would double the card's height to save 76px, and the
label/value alignment is what makes the card scannable.

---

## §46 Colour and contrast

### §46a Method

Ratios are computed from the site.css token hexes with the WCAG 2.x relative
luminance formula, `color-mix` percentages resolved arithmetically, and
semi-transparent layers composited against the resolved opaque ancestor. The
computed table was cross-checked against `getComputedStyle` on live DOM at four
independent points and matched exactly each time: warn fill 9.41 / 3.76, brand
fill 10.77 / 5.05, sensitive badge 11.40, kind badge 6.30.

Everything in a tile is below WCAG's large-text threshold (18.66px bold /
24px regular), so **4.5:1 is the bar for every figure in this design**, including
the 9px badge text and the 10px button labels.

A caution for whoever measures next: a naive `color(srgb …)` parser that assumes
the channel numbers start at index 1 will silently mis-read every `color-mix`
background Chrome serialises in that form. That bug produced a plausible-looking
4.38:1 for the sensitive badge in this session before being caught against the
computed value of 11.40:1. Cross-check computed against rendered; a single
source of truth here is a single point of failure.

### §46b The table

Full table with every pair, including the rejected alternatives, is rendered at
the foot of `artifact-tiles-mock.html`. The load-bearing rows:

| pair | dark | light |
|---|---|---|
| identity label — `--foreground` on `--surface` | 16.02 | 16.18 |
| size / receipt / masked — `--muted-foreground` on `--surface` | 6.15 | 6.39 |
| kind badge, tint 12% / 6% (worst tone, warn) | 7.94 | 4.51 |
| inert label — `--muted-foreground`, no fill | 6.15 | 6.39 |
| local label — `--foreground` on `--surface-raised` | 14.64 | 15.20 |
| outward label — `--warn` on `--surface` | 9.72 | 4.87 |
| disabled label — `--muted-foreground`, no opacity | 6.15 | 6.39 |
| format bar, active tab — `--brand` on tint | 8.74 | 4.67 |
| banner body — `--foreground` on warn-8% | 14.15 | 14.60 |
| banner `<dt>` — `--muted-foreground` on warn-8% | 5.44 | 5.77 |
| sensitive badge — `--foreground` on accent-18% | 11.40 | 13.98 |
| failure line — `--error` on error-10% | 6.60 | 4.57 |
| receipt tick — `--success` on `--surface` | 7.45 | 5.08 |
| published slot — `--brand` on `--surface` | 10.88 | 5.05 |

A final sweep over 30 element types in both schemes on the finished mock reports
**zero pairs below 4.5:1**.

### §46c The four rejected treatments, with their numbers

Recorded because each is a thing a reasonable implementer would otherwise reach
for, and three of them ship today:

| treatment | dark | light | verdict |
|---|---|---|---|
| disabled via `opacity-50` on muted (shadcn default) | 2.41 | 2.20 | rejected — §41d |
| disabled via `opacity-50` on foreground | 4.68 | 3.20 | rejected — light fails |
| kind badge at 12% tint in light | — | 4.17 | rejected — §39c |
| format bar active tab at 18% tint (**ships today**) | 7.55 | 3.97 | rejected — §39c |
| `--warn` fill with dark text (**"Configure TURN" ships today**) | 9.41 | 3.76 | rejected — §41a |
| `--warn` as warning-row body text | 8.27 | 4.28 | rejected — §42c |

### §46d Light theme is the harder one, and that is structural

Every failure found in this pass was a light-theme failure; the dark theme
cleared 4.5:1 everywhere without adjustment. The reason is not carelessness, it
is that the light palette's hue tokens sit much closer to their surface: on
white, `--brand` is 5.05:1 and `--caret` is 5.19:1, versus 10.88 and 7.49 on the
dark surface. Dark has roughly twice the headroom, so any tint, any opacity
reduction, and any fill that is safe in dark can still fail in light.

**The rule that follows: a colour decision in this area is not done until it has
been checked in light.** Dark-first is the product's stated design posture and
that is fine; it just means light is where the bar actually binds, and it should
be the theme a contrast check starts in rather than the one it gets around to.

---

## Deferred

- **DesignSync export.** Not possible this session (§ preamble). §39–§46 are
  written to port into the design document as a numbered section.
- **Per-kind bodies beyond the key card.** §42 specifies `KeyCard` at pixel
  level because §35 is the motivating case. The ciphertext packet read-out, the
  recipients row list, the sshsig read-out and the QR frame appear in the mock at
  the right anatomy and weight, but their internal layouts are sketched rather
  than pinned — they are registry work, and pinning them here would be inventing
  detail no one has asked a question about yet.
- **The `code { font-size: .78rem }` leak beyond the tile.** §39b fixes it
  inside the artifact tile only. The same rule is very likely flattening the type
  scale of every other toolkit widget that renders a `<code>`; this design did
  not survey them, and a sweep is worth someone's afternoon.
- **Hover and focus-visible states** are specified as behaviour (fill shifts,
  the 2px `--ring` focus ring the `Button` base already carries) but were not
  measured, because the shipped focus ring is unchanged by this design and hover
  is not a state any information depends on (§33g).
