# Open findings — discovered, not fixed

> **Status (2026-08-22):** Written as a handoff. Every item below was found
> while fixing something else, verified at the commit named, and deliberately
> left. None is speculative: each says what is true today, how it was measured,
> and what closing it would cost. Items are removed from this file when they are
> fixed, not ticked.

The house rule this file exists to serve: **a claim the code does not hold is a
defect, even when nothing crashes.** Most of what follows is that shape — a
control that does not control, a check that cannot fire, a label that outruns
its evidence.

---

## 1. Enforcement that is not enforcing

### 1.1 FIPS mode has no effect on the notebook

`assertRecipeAllowedUnderFips` (`web/src/lib/toolkit/engine.js:296`) runs only
for a caller that sets `bindings.fipsMode`. The only such caller is
`executeToolkitRun`, reached by the crypto-worker's `toolkit-run` message —
**which nothing in the app posts**. The notebook runs through `createKernel`
(`web/src/toolkit/useNotebook.ts` → `web/src/lib/toolkit/kernel.js:500,713`),
and neither file mentions FIPS. There is no add-time gate either:
`grep -rn getFipsMode web/src` finds `fips-mode.js` and one read in
`ToolkitShell.tsx`, nothing more.

This was independently recorded elsewhere in the repo before anyone connected
it to FIPS: `web/src/lib/pgp/intended-recipient.js:18` notes that *"Nothing
posts `encrypt` or `toolkit-run` either; `generate` is the only reachable
arm."* A different agent found the same dead worker path from the other
direction and wrote it down beside a different consequence.

**So with the switch on, the banner is the entire effect.** The copy was
corrected in `4f19e1d` to say what is true — it *flags* a recipe before you run
it — but the switch still promises a posture the engine never applies.

Closing it is a real decision, not a wiring chore: it would start **refusing
runs that succeed today**, and the refusal has to name which suite is
unverified and what a person can do about it. Deciding that is the work; the
plumbing is `kernel.js` and `useNotebook.ts`.

### 1.2 A notebook's digest is canonical only by accident of one call site

`handoffContext` digests `migrateRecipe(source).recipe` — the source text
**verbatim**, with no canonicalisation. It is correct today only because its one
caller hands it `serializeRecipe(chains)`, which is already canonical.

**The manifest states identity at two levels and they disagree with each
other.** Reproduced on the `handoff-shell` fixture with a *doubled space* — no
alias, no reordering, nothing a person would call a different notebook:

| | cell 1 | cell 2 | cell 3 | notebook |
|---|---|---|---|---|
| `… \| out $seed \| publish` | `360d760231` | `b6e2d42834` | `bade690b59` | `aa45ec49b500` |
| `… \|  out $seed \| publish` | `360d760231` | `b6e2d42834` | `bade690b59` | `2d34d7fdbcf8` |

Every cell digest matches, because cells go through `serializeRecipe`. The
notebook digest does not, because it is the raw text. So the fine-grained
evidence says these two peers are running the same notebook and the coarse one
refuses the offer.

`sameNotebook` argues for exact text, and its argument is sound for what it
answers: serialising *instead of* the source drops blank cells and shifts every
index after one, so the offer would name cell 4 while the peer's plan calls it
3. That justifies not substituting a re-serialisation. It does not justify the
notebook digest disagreeing with its own cell digests — a canonical form that
preserves cell count and order satisfies both, and nothing has been written
that weighs one against the other.

`c24992a` avoided adding to this by resolving its alias at parse, and proved the
hazard by mutation: resolve after the digest and two peers holding one agreement
get two manifests. The underlying asymmetry is untouched. Lives in
`handoff-shell.js` / `manifest.js`.

---

## 2. Checks that cannot fire, or cannot be tested

### 2.1 Intended-recipient (subpacket 35) has no reachable fixture

The engine half of the RFC 9580 §5.2.3.36 check cannot be exercised here:
**openpgp.js does not write subpacket 35, and neither does GnuPG 2.4.9** —
sign-and-encrypt emits subpacket 33 (issuer fingerprint) and 16 (issuer key id)
and nothing else, and `--dump-options` offers no way to ask for it. Verified
while capturing the subkey fixtures in `312c133`; recorded beside them in
`web/src/test/fixtures/README.md`.

This is not "needs a fixture" — it is untestable with the tooling on hand. The
module-level seam is covered with a constructed packet. Closing the engine half
needs a captured artifact from an implementation that emits it (Sequoia, or a
newer GnuPG).

### 2.2 The shelf's search is the intersection of two disagreeing predicates

Two filters cut the op list for one query: `useNotebook.filteredOps` matches
**name / doc / toolbox**, and `OpsShelf`'s `grouped` matches **name / doc /
label**. Both run, so the effective search is whatever both accept — silently
narrower than either. `3ef6526` fixed the conjugate-row half of this
(`pairRowMatches` lifts a per-step test onto the row it draws) and deliberately
did not unify the predicates, because they genuinely differ and picking one
changes what a query finds.

---

## 3. Parked by design, with the reason still standing

- **`gather`** — deferred since `36d0f26`. The recovery's `quorum.recv` shape did
  not need it, and building a verb with no consumer is the defect this codebase
  keeps finding.
- **Elementwise application** — blocked because `out`, `publish` and `tee`
  declare `input: "any"`, so "accepts text, handed a collection" cannot classify
  them, and the headline example turns on `out`. See `docs/LANGUAGE.md`.
- **The single-cell hybrid decrypt**, lost in `a0c34cf` and partly restored by
  `635fd58`'s `shares tray=merge`. Full restoration needs either *"what the
  recipe names beats what a tray holds"* or *"one `shares` step per pipeline"*
  loosened. Both are separately argued; neither was touched.
- **`pairTileLabel`** has no consumer outside its own test. It is the
  friendly-verb function (`Encrypt`, `Build`), and `3ef6526` recorded why using
  it would have made the direction buttons untypeable. Dead export, kept
  deliberately, listed here so it is not rediscovered as a surprise.

---

## 4. Protocol changes nobody has decided

- **A shared notebook is written to, never acknowledged.** `1dbc950`'s delivery
  acks are a `quorum.send` mechanism — the receiver acks a *chat* frame by
  content digest — and a notebook leaves through `_publishDocument` as a sealed
  document frame that nothing answers. `7ac9f50` established the honest wording
  (a count of writes, permanently unconfirmed) rather than inventing an ack.
  Real delivery confirmation means document frames get their own ack.
- **A newcomer learns nothing at join time when the retention was retired.**
  `e7abf2a` tells a peer that a notebook exists, gated on somebody having pressed
  Share; when the sender edits after the press, the retention is retired and the
  newcomer is told nothing until an offered cell is refused. Closing it means
  announcing "a notebook exists here" unconditionally, which is a new disclosure
  on the wire rather than a wording change.

---

## 4a. One decision nobody has made

**`shares` and `recipients` draw the same mark.** Both resolve to lucide `Users`
in `KIND_GLYPHS`. It is half-deliberate — `GLYPH_PATHS` already holds a distinct
`shares` asset (offset cards), and `kindGlyph` consults `KIND_GLYPHS` first *on
purpose*, so the tray tab keeps its chrome icon. `bca32b8` pinned that exact
pair rather than allowing "some collisions", so a **second** collision fails a
test — but this one stands, and the map's own rule is that drawing two concepts
with one pictogram is the defect it was written against.

`int` and `host` have no mark at all. Both are real registry types with cards on
the Types tab, and neither appears on any step signature, so neither can reach a
`needs …` caption. Recorded in `UNDRAWN_TYPES` with a may-only-shrink rule and a
test that fails the moment a step declares one — rather than guessing two more
marks, which is the reflex that once put one `KeyRound` on six key roles.

---

## 5. User-visible, small, and real

- **Five `scripts/snapshot-*.mjs` capture screenshots of markup that no longer
  exists.** `snapshot-toolkit-ux`, `-ux-overwhelm`, `-ux-resume`, `-conjugates`
  and `-ops-drill` all `waitForSelector` / `locator` on `.chef-workspace` and
  `.chef-ops` — class names the build emits zero times. They were found while
  deleting the dead stylesheet rules for those same classes. Whether they are
  repointed at the current shell or removed is a decision about whether anyone
  still wants that capture set; either way they cannot work as written.
- **The eight pages are audited for landmarks now; headings are still open.**
  `<main>` is fixed and pinned by `site-landmarks.e2e.js`. Headings are not:
  the six `Layout` pages have **no `h2` at all**, so each one's internal
  structure is carried by styling alone and its outline is a single line. That
  is a content question per page, not one shared fix. (`/key` also renders no
  heading until its key loads, so its error and loading states are headingless
  — the smallest concrete piece of this.)

---

## 6. Coverage that is thinner than it looks

- **No face-up cell-state row is proven in a browser.** `2a49f73`'s ceremony
  numbers slots per member (`$share` on the dealer, `$share-2`/`$share-3` on
  holders), so no two machines in that notebook ever write the same label and
  every e2e row is legitimately face down. The face-up case is pinned only at
  the unit layer.
- **`dealer-absent-recovery.e2e.js` alone is blind to a foreign dealer share.**
  `4c27d01` added the all-shares-one-split assertion to `three-party-ceremony`
  because that is the only spec where all three shares exist at once. The
  dealer-absent file is covered transitively — the same generator deals both
  rooms — not directly.
- **Collapsed rail states are not in the layout suite.** `cdf8f8c` drove them by
  hand at both widths; the spec covers the default state only.
- **`.design-sync/previews/` is outside `web/tsconfig.json`**, so `tsc --noEmit`
  never sees the preview files. They are verified to parse and to render in
  capture, and by nothing else.
- **`RoomCells` is not in `web/src/ds-entry.ts`**, so the cell-state table added
  in `2a49f73` is absent from the synced design system. That barrel is a
  reviewed decision rather than a heuristic, so this is a choice to make, not a
  bug to fix.

---

## How to use this file

**Re-verify before acting on an entry.** This file's rule is that items are
deleted when fixed, and it was broken almost immediately: three of §5's six
entries described work that had already landed, and survived two later edits of
this same file because updating it and reading it were separate passes. One of
the three was not merely stale but wrong — it described a keyboard defect on an
element that does not exist. Each was disproved in under a minute by grepping
for the thing it claimed. Do that first; a fix aimed at an already-fixed item
spends the trust this file runs on.

Take the top of §1 first. Everything there is a control that does not control,
which is worse than a missing feature: somebody is relying on it. §2 is next,
because a check that cannot fire is indistinguishable from one that passes.

## A hint that has paid off five times

Before building a mechanism, check whether it already exists and is simply
unused. In one day: `caption` was computed for every conjugate row and read
nowhere; `KIND_GLYPHS` was a carefully measured type vocabulary referenced zero
times from the shelf; `GLYPH_PATHS` shipped `gpg-decrypt` and four other reverse
glyphs that reached no screen; `step-docs.js` already cited 92 of 132 ops; and
the ITU-T X.690 entry was already the precedent for citing a paywalled
non-RFC standard. Each time, the work was wiring rather than inventing, and each
time the first instinct was to build something new.

The corollary is the failure mode: a mechanism with no consumer looks exactly
like a mechanism that is finished. Ask who reads it, not whether it works.

When an item is closed, delete it and say so in the commit — a findings file
that accumulates ticks stops being read.
