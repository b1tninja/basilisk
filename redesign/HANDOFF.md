# Basilisk Toolkit — handoff

For an agent picking this up cold. Everything here is either non-obvious or
was learned the hard way; the rest you can read from the code faster than I
can describe it.

Repo: `b1tninja/basilisk`, branch `feat/toolkit-redesign`, work in `web/`.

---

## What it is, in one paragraph

A browser-only cryptography notebook. You write a **recipe** — steps joined by
`|` — and each cell runs it against WebCrypto / OpenPGP.js / WebRTC and
produces artifacts. Nothing server-side holds key material.

```
genkey ec/p256 | export spki | pem | out @pub
random 32 | encode base64 | out @cek
```

83 steps across 10 toolboxes, 23 pipeline types, 24 widgets.

---

## The three things most likely to trip you

**1. The dev server's CSP is weaker than production.** Strict CSP breaks HMR,
so `basilisk-dev-server.js` relaxes `script-src`/`style-src` for `serve`. This
means a CSP violation can be *invisible in dev and fatal in the build*. That is
how 23 inline styles accumulated behind a test literally named
"no-inline-styles". The production policy now also rides along **report-only**
(HTTP header — the `<meta>` form of report-only is parsed and then ignored by
every browser), and `lib/boot-diagnostics.js` reports those as "would break in
production" rather than as live failures. If you add a page, add the header.

**2. Verify in the browser, not by reading the diff.** Several things in this
session type-checked, built, passed tests, and were still wrong: a suggestion
that offered `aes-cbc` as the fix for "add export pkcs8"; a `key` prop React
silently consumed; a peer filter matching a field that did not exist. The
catalog at `/toolkit-widgets` is the cheapest way to see a widget's real states
— twice it exposed defects nothing else caught. Add a section for any widget
you create.

**3. `screenshot` compositing is unreliable here.** Assert with
`getComputedStyle`, DOM queries, and geometry instead. "Measured the colour"
beats "looks right", and it is what caught the expiry-escalation and peer-dot
states being correct.

---

## Invariants someone will otherwise break

- **`quorum.*` is the session manager; `rtc.*` is the transport.** `quorum` owns
  `offer`/`join`/`close` only — room, roster, lifecycle. Channel traffic
  (`rtc.send`/`rtc.recv`) lives with the connection primitives. This split is
  what lets the transport work on any data channel rather than only inside a
  quorum room, which the DKG plan depends on.
- **Types are three-way.** DATA is inert and publishable; HANDLE (`session`,
  `channel`) is a live object meaningful only inside the run that made it;
  OBSERVE (`connstate`, `stats`) is a read-out that can be displayed but never
  consumed. `resolveStepType` enforces it. Designs that ignore this produce
  screens the type system refuses to render.
- **`any` is a signature marker, not a value.** The universal passthroughs
  (`out`, `tee`, `peek`, `inspect`, `text`, `select`) declare `input: "any"`,
  stamped from `POLYMORPHIC_STEPS` in types.js. They previously claimed `bytes`
  while the checker special-cased them by name, so the type browser reported
  that *nothing* consumed `stats` or `candidate`.
- **Reveal is gated.** A sensitive artifact may be unmasked only when the author
  explicitly asked to see it — `out`, `text`, or `inspect` set `revealable`.
  Incidental tiles stay masked. Do not "fix" this by revealing everything.
- **Retired names are removed, not aliased.** `to`/`from`, `quorum.send/recv`,
  `hex`/`unhex` all fail live parse and are rewritten by `migrateRecipe` /
  Upgrade recipe. One name per operation.
- **Producers/consumers are derived from STEPS**, never hand-listed, so the
  type docs cannot claim an op that no longer exists.
- **Reference links live in `step-docs.js`**, not the registry — a URL is
  documentation, not part of a step's contract.

---

## Traps that look like bugs but are not, and vice versa

- **`applyCellRecipeText` used to reject any ill-typed recipe** — set a
  page-level error and never committed. So you could not *type* an ill-typed
  pipeline, which made the per-cell error banner unreachable from Source view
  by construction. Now only a *parse* failure is refused. If you find yourself
  unable to reproduce a validation state, check whether the editor is refusing
  the input.
- **`useNotebook`'s `cellOutputs` projection copies named fields.** Anything the
  engine adds is silently dropped until listed there. Cost me two debugging
  rounds (`revealable`, `inspectSnapshot`).
- **`vitest.config.js` now mirrors vite's `@` alias.** Before, importing any
  component failed on `@/lib/cn`, so helpers had to be relocated to `lib/` just
  to be testable. They no longer do.
- **`fetchJson` assumed any 2xx body was JSON.** An SPA fallback answers 200
  with `<!DOCTYPE html>`, surfacing `Unexpected token '<'` for what is a routing
  failure. Fixed, but the pattern may exist elsewhere.
- **The engine withholds `inspectSnapshot` for sensitive values on purpose** —
  a snapshot retains raw private JWK fields the masked text dump does not. Its
  absence is a decision, not a gap.

---

## Verification workflow that works here

```bash
npx tsc --noEmit        # filter out pre-existing memory-safety.js noise
npm run build
npm test
```

**Baseline: green. 957 tests, 957 passing, 77 files.** The three long-standing
failures (`conjugate-stitch`, `toolkit-engine`, `webauthn-mds`) were fixed —
and all three were **stale tests, not broken code**, which is why they
survived so long:

- `conjugate-stitch` string-matched `in @ct` after the serializer deliberately
  switched to the canonical bare `@ct` (RECIPE.md's own multi-chain examples
  use it). Now asserted on the parsed AST via a `loadsSlot` helper, so a
  future printer change cannot break it again.
- `toolkit-engine` used `out name=label`, retired from live parse when slot
  labels started requiring `@`. Recipes updated, plus a new test pinning the
  actual invariant: the legacy form must *fail* parse and be repaired by
  `migrateRecipe`, never silently aliased.
- `webauthn-mds` asserted `status === "true"`; the API returns
  `"verified" | "unverified" | "unavailable"` (a corrupted assertion — its
  sibling test had it right).

**Any failure is now a real one.** Do not re-introduce a tolerated baseline.

Two gates will catch you and are worth knowing about rather than fighting:
`recipe-verbs.test.js` demands every op and every enum value appear in the verb
smoke catalog, and `no-inline-styles.test.js` is a ratchet with a per-file
baseline that may go down but never up.

---

## What is outstanding

**Recipe-language turns 46/47 are implemented** (gap ambiguity + selector
grammar): scope-named nested gaps ("+ step in :public" / "in loop body"),
containers always render their nest region, the continue gap hides while a
tee/foreach is empty, inserting a container auto-focuses its body gap, foreach
bodies anchor on a static "↻ each item" chip, tee stems offer ghost selector
branches from the closed projector table (`selectorGhostsFor` in suggest.js)
plus "+ branch" and "peek instead", an armed branch materializes atomically
with its first step (`addBranchWithStep`), and tee/foreach are absent — not
dimmed — from shelf and fit for any nested caret (enforced in `nestOp` too,
against drag-drops). Tests: `selector-ghosts.test.js`; catalog section
"RecipeChipFlow" shows the new states. Still unbuilt from 47: a chip
affordance for `foreach`'s own `:items`/`:values`/`:keys` gap (source-view
only today, stored as `foreachSelector`), and per-item selector ghosts inside
a body (the caret offers fit-checked ops incl. `select`, just not a dedicated
ghost row).

Design turns **36–39 have no handoff README** — read them from
`Basilisk Toolkit v2.dc.html` directly via the claude_design MCP. Everything
else has one in `redesign/design_handoff_*/`.

Roughly in value order:

1. **P2P mesh** — `redesign/p2p-dkg/DESIGN.md` has the researched plan.
   **Perfect negotiation is done**: `lib/quorum/rtc.js` now runs the MDN
   pattern (lower fingerprint is polite; `offerCollisionAction` is the pure,
   tested rule in `quorum-negotiation.test.js`), and offers ride a single
   `onnegotiationneeded` path — which also made "Restart connection" real,
   since `restartIce()` previously fired an event nobody handled. Note the
   design doc overstates the remaining gaps: `QuorumSession` is already
   N-party, and `derivePairwiseSessionKey` already binds room + both fprs +
   audience + nonces + both DTLS fingerprints (the RFC 8844 shape) at the
   *pairwise* level. **Mesh self-bootstrap is now in**: signaling is
   channel-first (`_sendTo` prefers a live direct link, then a one-hop relay
   over kc-verified links, then the mailbox), sealed envelopes ride data
   channels as `{v, env, hops}` frames with hop cap + bounded dedupe
   (`lib/quorum/relay.js`, tested in `quorum-relay.test.js`), and members
   forward frames addressed to peers they hold links to — so only the first
   join needs the mailbox, and renegotiation survives it dying. `rtc.restart`
   makes ICE recovery chainable, and ConnectionsPanel states mesh degree with
   the DESIGN §1 soft-cap warning past 8 participants. Caveat, stated
   honestly: the relay path is verified at the pure-rule and compile level;
   a live two-browser relay run has not been performed. What remains: DKG
   rounds on the finished bus.
   Also applied: the 48a naming audit — seven camelCase ops renamed
   (`rtc.gather/check/state/stats/offer/answer/quality`; `rtc.statsReport`
   was a seventh the audit missed), old names retired + migrated, and a
   convention test in `rtc-channel-ops.test.js` now locks
   `namespace.singlelowercaseword` for every registered op.
2. ~~**Feed real peers into `ConnectionsPanel`**~~ — done. `quorum-ops`
   projects the live roster through `lib/quorum/roster.js`
   (`projectRosterPeers`) onto the `basilisk:quorum-state` event;
   `authenticated` demands *both* pgpVerified and kcVerified, and `via` is a
   best-effort async `getStats` enrichment that patches in after the row first
   renders. Tests in `quorum-roster.test.js`.
3. ~~**32d clipboard ops**~~ — done. `clipboard.read` (source, gated: the
   shell registers a permission surface via `setClipboardReadGate`, asked
   every run, Allow reads inside the click's transient activation) and
   `clipboard.write` (passthrough sink in `POLYMORPHIC_STEPS`, toast-weight
   confirm via `basilisk:clipboard-wrote`). `lib/toolkit/clipboard-ops.js`,
   tests in `clipboard-ops.test.js`. Note for e2e: a *scripted* Run click has
   no transient activation, so `writeText` is denied — drive Run with a real
   input event. Still open: **33d artifact diff**, **36b/36c**, **37a/37b**,
   **38a/38b** — see the handoff READMEs.
   Also new since: **cross-cell slot gating** (`lib/toolkit/slot-graph.js`) —
   a later cell's unmet inputs no longer block the producing cells; runFrom
   gates per cell (checkpoint semantics) and the `shares` panel op falls back
   to indexed share slots a foreach emitted this session (see
   `split-recover-e2e.test.js` for the real round trip). And **session-only
   keys for e2e**: dev-only `window.__basiliskE2E.mintSessionKey()`
   (`lib/e2e-hooks.js`, tree-shaken from production), resolved by
   `unlockVaultForUse` via the session cache without vault membership.
4. **TOTP (turn 43) deserves its own scope.** A value that mutates on a local
   timer is new for this engine — every current value is fixed at run time.
   That is an engine change, not polish.
5. **Work down the inline-style baseline** — now 11 sites in 7 files. TopBar
   (was 6) and OpsShelf (was 4) are converted: `data-suite-tone` /
   `data-toolbox-dot` plus enumerated rules in toolkit.css.
   `toolbox-dot-css.test.js` guards the registry↔stylesheet colour
   duplication against drift. Remaining: index (3), NetworkArtifact (3),
   ToolkitShell (2), Glyph / RunBar / SessionStrip / toolkit.tsx (1 each).
6. ~~**Wire `boot-diagnostics` into the other nine pages**~~ — done, all ten
   entries (redirect stub included). Bonus find: the dev server never sent
   the report-only CSP header for `/` and `/search` (the early-return skipped
   the header block), so index — which holds 3 of the remaining inline-style
   sites — was blind to exactly the failures the header exists to predict.
   Fixed in `basilisk-dev-server.js`; verified the predicted-violation banner
   fires on `/`.

Unverified: the `CellTypeErrors` banner is confirmed in the catalog and in a
live cell, but the RunBar blocker and the banner still word type errors
independently in one path.

---

## How to work

Read `docs/TOOLKIT-WIDGETS.md` and `docs/RECIPE.md` first; they are current.
Reuse existing primitives — if a design needs a window, it is a `Sheet`. Do not
invent registry ops or types to satisfy a mockup; the registry is the source of
truth and a design that needs a new one should say so explicitly.

Design handoffs are high quality but written against a partly fictional
registry. Prior ones flag which mock details bind and which illustrate — honour
that distinction, and check the claim against the code before implementing it.
One handoff in this project retracted an entire turn as fabricated because it
had been written without reading the source first.
