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

### 1.1 The worker's FIPS gate still guards a message nothing sends

The run half is closed and the ways in are pinned:
`fips-engine-entrypoints.test.js` sweeps the source for every caller of
`runRecipe`/`runAll` and requires each to route the flag or be argued onto a
written exemption list. There are three, and `conjugate-smoke.js` is the one
exemption — the suite self-check must be able to test an unverified suite, or it
answers the question by declining to ask it.

What is left is the worker. `executeToolkitRun` applies the gate on the crypto
worker's `toolkit-run` arm and **nothing in the app posts that message**;
`generate` is the only arm anything reaches. So that path enforces nothing, and
`web/src/lib/pgp/intended-recipient.js:18` recorded the same dead arm from the
other direction. Deleting it and deleting the worker's `encrypt` arm with it is
one option; wiring the notebook's runs through the worker is the other. Both are
decisions about where crypto should execute, not tidying.

There is still no add-time gate — you can write the recipe, you cannot run it.
`docs/CRYPTOGRAPHY.md` said the switch "hard-blocks adding/running" and now says
what is true.

### 1.2 The second manifest producer still has the asymmetry

`handoffContext` is fixed — its notebook digest is now the digest of its own
cells joined. `engine.js`'s `currentRunManifest` (around line 4154) is the other
`buildRunManifest` producer and still takes `recipeSource` raw from
`ctx.recipeSource` while digesting cells through
`serializeRecipe({ chains: [chain] })`. It already contains the loop
`canonicalCellSources` now expresses and could adopt both exports directly.

### 1.3 Nothing sweeps for a control with no handler

`onExportProof` was declared, destructured, hung on a `<Button>` and passed by
nobody, so the button rendered enabled and did nothing. It is fixed — but it is
the **second** time: `session-flow.test.js` records the identical defect for
`onStartSession`, and it asserts against that one prop by name rather than
against the shape.

An optional handler prop that no caller supplies is a control that looks
finished. The registry-style sweeps in this repo (`glyph-shadowing`,
`fips-engine-entrypoints`) exist because a list catches the next one and a named
assertion does not. The same is possible here: for every component the shell
renders, every `on*` prop it declares is either passed, or written down as
deliberately optional.

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

### 2.1 The surreptitious-forwarding defence has no message to fire on

The comparison is right and reachable — `engine.js` decrypts with
`verificationKeys` and `decryptSignatureVerdict` runs it — and it reads the
protected half of the signature. What is missing is a message carrying the
subpacket: **openpgp.js does not write subpacket 35, and neither does GnuPG
2.4.9.** Sign-and-encrypt emits subpacket 33 and 16 and nothing else, and
`--dump-options` offers no way to ask for it. Verified while capturing the
subkey fixtures in `312c133`.

So the defence is armed against an attack it will never see evidence of, and
every real message answers `absent`. Closing it needs a captured artifact from
an implementation that emits it — Sequoia, or a newer GnuPG.

**What openpgp.js does with one when it arrives is now known, and is the part
that was wrong here.** There is no `hashedSubpackets` array: `readSubPacket`
pushes every unhashed subpacket into `unhashedSubpackets` and returns early for
any type outside issuer-key-id / issuer-fingerprint / embedded-signature, so
type 35 reaches `unknownSubpackets` **only when it arrived hashed**. That is
what makes `unknownSubpackets` the trustworthy source and `unhashedSubpackets`
not — a distinction this repo had to learn by finding both being read.

Criticality is handled and needs nothing: openpgp.js throws on an unrecognised
**critical** subpacket, which is what RFC 9580 requires.

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

## 4. One decision nobody has made

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

- **`InsertGap` renders a `<button>` when it is `pending`.** The armed-branch
  caret is focusable and answers a press with nothing. No behaviour is missing —
  arming aimed it, and the × on the chip beside it cancels — but a marker that is
  a button reads as a control, and a control that does nothing is the defect this
  file keeps finding. Whether a `pending` gap should be a `<span>` affects all
  five call sites, which is why it was recorded rather than changed.
- **`notebookDelivery` has no consumer.** `useNotebook.ts` exports the structured
  report — `{ wrote, reached, unconfirmed }` — and only the sentence built from
  it, `notebookDeliveryNote`, is read anywhere. Either drop the export or give it
  a reader; it is the recurring shape at small scale.
- **One capture was lost on purpose and should be a decision, not an accident.**
  Deleting `snapshot-ux-resume.mjs` dropped the recipient-binder shot — whose
  selectors (`.recipient-binder`, `.binder-search`, `.keyserver-control`,
  `.cell-bind-messaging`) are still live. It was unreachable in that script
  because the only route to it ran through the dead raw-textarea loader. If it
  is wanted, it needs a new purpose-built script.

---

## 6. Coverage that is thinner than it looks

- **A face-up row means a slot of that name is here, not that the peer's value
  arrived — and the stronger reading is reachable.** `facesFor` asks
  `hasSlot(label)`. On an unplaced cell (`mine` on every machine) both ends
  write the same label locally, so with a `random` source they hold different
  values under one name and both rows read face up beside each other's
  fingerprints. The wording now says what the code does. Making the row mean
  *the peer's own bytes are here* is reachable through the handoff result path —
  the receiver's Run all declines the sharer's cell and offers it back, the
  sharer runs and returns the `result`, and accepting it registers the label on
  the sharer's actual value. `placed-journey.e2e.js` already drives every press
  in that arc with the direction reversed. It is a protocol-shaped decision
  (compare something the announcement carries) rather than a test to write.
- **A peer who only receives a notebook is silent, permanently.** `_sharedEver`
  is set only by `shareNotebook`, so a machine that never offers a notebook
  never announces a cell state. That is a deliberate consent gate and it is
  documented — but it bounds any claim of the form "the room can see what the
  room is running": in every ceremony spec only the dealer can appear in
  anybody's table, and the holders are invisible to each other by construction.
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
- **A `{...spread}` hides a preview's props from the check that now covers
  them.** TypeScript exempts spread properties from excess-property checking, so
  a preview built on a shared `base`/`START` const can pass a prop the component
  does not declare and `tsc` will not say so. That is not hypothetical: it is how
  `SessionStart`'s `suggestions` survived being renamed to `trusted`, and it was
  found by reading the prop list against the fixture rather than by the compiler.
  Annotating those consts with the component's props type would close it —
  `SessionStartProps` and `VaultKeyView` are not exported from `ds-entry.ts`,
  which is what makes that impossible today.

## How to use this file

**Re-verify before acting on an entry.** This file's rule is that items are
deleted when fixed, and it was broken almost immediately. **Eight entries have
now been disproved by reading the code they name** — including one that
described a keyboard defect on an element that does not exist, and one written
during this very sweep, which claimed a delivery confirmation reached no screen
when `useNotebook` had been spelling it into a sentence since `e7abf2a`.

That last one is the instructive failure, because the method was right and the
execution was not: the grep that established it ended in `| head -6`, and twelve
hits in one test file filled all six lines before the real consumer appeared.
**Do not conclude from a truncated list.** Count the matches, or read them all.

**The `dist` grep proves less than it looks, and exactly which less is
measurable.** Several entries here were settled by asking whether a name appears
in `web/dist/assets/*.js`, on the reasoning that a name absent from the build
cannot be reached by any code path. The build is **minified**, so that reasoning
holds for two kinds of name and fails for the third:

| what you are grepping for | survives minification | verdict |
|---|---|---|
| a string literal — a CSS class, message text | yes | **valid**; `ops-panel` 1, `chef-workspace` 0 |
| an object property — `peer.notebookReachedAt` | yes | **valid**; 10, 60 and 35 hits on three live ones |
| a **function identifier** | **no** | **worthless**; `opsMatchingQuery`, `kindGlyph`, `readRunProof` and `planChains` are all live and all score **0** |

So the dead-stylesheet sweep and the `notebookReachedAt` reader stand on it. The
`manifestHonouredBy` finding does not, and it never needed to — every reference
to it outside `src/test/` was a comment, and that source sweep is what actually
established it. For a function, grep the source and check whether each hit is a
comment; the build tells you nothing.

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
