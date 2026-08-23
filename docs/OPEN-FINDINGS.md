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

### 1.1 FIPS mode gates running, and still does not gate adding

The run half is closed: the notebook builds `bindings.fipsMode` and
`bindings.suiteStatus` on every kernel run, and `startRun` refuses before the
cell loop rather than after cell 2. `docs/CRYPTOGRAPHY.md:186` still says the
switch "hard-blocks **adding**/running ops", and there is no add-time gate
anywhere — you can write the recipe, you just cannot run it. The tray copy says
so now; the doc still overclaims.

Two things the closure did **not** close:

- **The dead worker path is untouched.** The notebook was wired to the gate,
  not the app to the worker. Nothing still posts `toolkit-run` or `encrypt`;
  `generate` remains the only reachable arm, exactly as
  `web/src/lib/pgp/intended-recipient.js:18` recorded.
- **`conjugate-smoke.js` (lines 85, 174, 196) calls `runAll`/`runRecipe` with
  no `fipsMode`, so it is ungated.** It is a self-check harness rather than a
  person's run, which is why it was left — but it is a second path into the
  engine that the switch does not reach.

### 1.2 The second manifest producer still has the asymmetry

`handoffContext` is fixed — its notebook digest is now the digest of its own
cells joined. `engine.js`'s `currentRunManifest` (around line 4154) is the other
`buildRunManifest` producer and still takes `recipeSource` raw from
`ctx.recipeSource` while digesting cells through
`serializeRecipe({ chains: [chain] })`. It already contains the loop
`canonicalCellSources` now expresses and could adopt both exports directly.

### 1.3 `manifestHonouredBy` verifies a run against its manifest, and nothing calls it

Found while closing §1.2's second producer, by checking who would notice if the
two run documents disagreed. The answer is nobody: `manifestHonouredBy` compares
a manifest's `recipeDigest`, registry and cell rows against the receipt of the
run that was supposed to honour it, and **it appears zero times in the built
bundle** — no `.tsx`, no hook, no op. Its only callers are its own tests.

That is the shape this file exists for. It is not an unused helper but an
unrun *check*: "did the run do what the manifest promised" is a question the
notebook never asks, while `manifest.check` and `run.attest` — which the app
does reach — verify a document's internal consistency and signature rather than
its relationship to what actually happened.

Closing it is a product decision, not wiring: something has to decide when the
comparison runs and what a mismatch does to a person mid-run.

---|---|---|---|---|
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

## 4. Was a protocol change, is now a missing reader

- **A notebook's delivery is confirmed on the wire and shown to nobody.** The
  entry here said document frames had no ack of their own and that inventing one
  was the work. It was invented: `_publishDocument` digests a notebook
  specifically so it can be acked, the receiver calls `_acknowledgeNotebook`,
  `_onNotebookAck` matches the digest and stamps `peer.notebookReachedAt`, and
  `_emitRoster` carries the peers map — the fact included — out to the hook.
  **Every reference to `notebookReachedAt` outside `session.js` is a test.** So
  the room knows a notebook arrived and no surface says so, and the send-time
  wording (a count of writes, deliberately not a promise) is still the last
  thing a person is told. This is a reader, not a protocol change.

## 4a. One decision nobody has made

**A connection state, a diagnostic and a statistic all draw lucide `Activity`.**
This is what is left of the shadowing item, and it is the half that is a design
call rather than a defect: none of the three has a drawing of its own, so
nothing is being thrown away and the only question is whether they should be
told apart at all. It is on the exemption list in `glyph-shadowing.test.js`,
which may only shrink, so a *new* collision fails rather than joining a crowd.

The rest of that item is closed. It was recorded as `shares` and `recipients`
sharing a mark; it was five names, not two, and the previous entry's claim that
`bca32b8` had pinned the pair was false — no test guarded `KIND_GLYPHS`
duplication at all.

`int` and `host` have no mark at all. Both are real registry types with cards on
the Types tab, and neither appears on any step signature, so neither can reach a
`needs …` caption. Recorded in `UNDRAWN_TYPES` with a may-only-shrink rule and a
test that fails the moment a step declares one — rather than guessing two more
marks, which is the reflex that once put one `KeyRound` on six key roles.

---

## 5. User-visible, small, and real

- **One capture was lost on purpose and should be a decision, not an accident.**
  Deleting `snapshot-ux-resume.mjs` dropped the recipient-binder shot — whose
  selectors (`.recipient-binder`, `.binder-search`, `.keyserver-control`,
  `.cell-bind-messaging`) are still live. It was unreachable in that script
  because the only route to it ran through the dead raw-textarea loader. If it
  is wanted, it needs a new purpose-built script.
- **`renderSnippetCard` leaves one titled card headingless on two pages.**
  `web/src/lib/snippets.js:32` emits `<p class="card-title">${title}</p>`, so
  `/`'s "Command-line usage" and `/key`'s "Install with GnuPG / HKP" are the
  only titled sections on those pages outside the outline. The class already
  owns font-size, weight and margin, so it is a tag swap — left because the
  file was outside the heading pass's ownership.
- **`/published` has no `h2` in the state most visitors land in.**
  `published-mount.js` emits "Published under your address" and "Key labels",
  but only in the signed-in-with-at-least-one-key branch — which is why a
  signed-out sweep measures zero and why this looked like a headingless page.
  The signed-out and zero-key states need `keys.js:112` "Submit a public key"
  and published-mount's two prompts promoted to match.

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
