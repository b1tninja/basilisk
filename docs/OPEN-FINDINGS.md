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

*Empty. The FIPS gate reaches the notebook, the ways into the engine are a list
with a written exemption, and the worker arm that guarded a message nothing
sends is deleted.*

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

- **`.cell-recipe-gap-caret` paints `cursor: pointer` on the inert marker.**
  The armed-branch gap is a `<span>` now, but the stylesheet still gives it a
  pointer cursor — one of the signals that made it read as a control. A Tailwind
  utility cannot fix it: `toolkit.css` imports tailwind and then `site.css`
  unlayered, so `site.css` beats `@layer utilities`. It wants
  `button.cell-recipe-gap-caret`.
- **The armed caret is a drop target with no hover accent.** Its call site
  passes no `onDragLeave` and never sets `active`, so only the cursor's copy
  effect signals that it will take a drop. The trap is recorded in
  `InsertGap.tsx`: `active` outranks `pending`, so wiring `active` at that site
  falls through to the `+` branch and produces a dead `+` button. Fixing it is a
  change to the condition, not a prop at the call site.
- **One capture was lost on purpose and should be a decision, not an accident.**
  Deleting `snapshot-ux-resume.mjs` dropped the recipient-binder shot — whose
  selectors (`.recipient-binder`, `.binder-search`, `.keyserver-control`,
  `.cell-bind-messaging`) are still live. It was unreachable in that script
  because the only route to it ran through the dead raw-textarea loader. If it
  is wanted, it needs a new purpose-built script.

---

- **Two engine binding fields have only test producers now.**
  `bindings.recipients` (parsed openpgp `Key` objects) and
  `bindings.gpg.privateKeyArmored` were both set by `executeToolkitRun`, which
  is deleted. Nothing the app ships writes either; the engine reads them in four
  and two places. **Not a deletion candidate** — they are a real contract for
  anyone calling `runRecipe` directly, several specs exercise them, and the
  precedence rule between armor and parsed keys is load-bearing. Recorded
  because "only tests produce it" is the shape that usually precedes a removal,
  and here a removal would be wrong.
- **A family of "worker-safe" comments in `engine.js`** (around lines 3788,
  3958, 3987, 3993, 4010) classifies ops by whether they could run in a Web
  Worker. Each claim is still generically true — `RTCPeerConnection` really is
  absent from workers — and the classification is worth keeping, since routing
  the notebook through a worker is a design that may yet be argued for. But
  there is no worker path now, and a reader can take the family as evidence one
  exists. A decision, not a defect.
- **`CAST-AND-TEST-GAPS.md`'s "block add" half never shipped.** The plan's table
  and diagram promise ops that "cannot be added from drawer / suggest";
  `CRYPTOGRAPHY.md` states plainly there is no add-time gate anywhere. Unrelated
  to the worker deletion and flagged inline beneath the diagram, but the plan
  still reads as though half of it is in force.

---

## 5a. Measured, large, and not safe to act on blindly

**416 of the 949 class selectors in the stylesheets have no producer.** Every
one of them is in `site.css`; `toolkit.css` has none, which is the cleanest
signal in the measurement — the current shell's stylesheet is fully live, and
the legacy toolkit's entire vocabulary is still sitting in the other one. The
`.chef-*`/`.pane-*` deletion took 176 lines of that and stopped at one family.

By prefix: `builder-` 53, `ops-` 49, `cell-` 48, `suggest-` 25, `notebook-` 17,
`encrypt-` 16, `artifact-` 12, `session-` 12, `toolbox-` 12. Note that these are
*subsets* of live families — `ops-panel`, `ops-category` and `ops-rail` are all
in use, while `ops-aes-kit-body` is not — so this cannot be deleted by prefix.

**The sweep has a false-positive mode and at least one confirmed instance.** A
class assembled at runtime never appears as a literal: `packet-map.js:291`
returns `` `pkt-color-${colorIndex % 8}` ``, so the eight `pkt-color-N` rules
*are* reached and the sweep is wrong about them. Any deletion has to check each
family for a constructor first. (`receipt.js`'s `ops-${count}-…` is a registry
version string, not a class — that one is not a producer.)

Method, since it is reusable: the haystack is `git ls-files` plus `web/dist`,
enumerated rather than hand-walked. The first pass walked `web/src` and
`web/*.html` and missed `basilisk/web/templates/claim.html` and
`web/static/*.html` — it happened to change the count by two, but a sweep whose
coverage cannot be checked is not evidence. The `dist` half is valid here
because a CSS class reaches the bundle as a **string literal**, which
minification preserves.

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

**Re-read this file after editing it.** Its worst state was not a stale entry
but a corrupt one: a run of slice-based edits left two closed items standing,
three deleted bullets un-deleted, and a headless fragment of an old entry —
including a bare table header — dangling under a heading it did not belong to.
Every one of those edits reported success. None of them was read back. An entry
that contradicts the code costs a reader an hour; a section that does not parse
costs them their trust in the whole file.

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
