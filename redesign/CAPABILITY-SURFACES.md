# Surfaces for capability that shipped without one

Four things the engine can do that no screen admitted existed: verifiable
secret sharing, distributed key generation, file/age/QR work, and checking the
code you were served. This document is the design for each, what got built,
and — the part that matters for whoever picks this up — what is asserted here
without being implemented.

Status at a glance:

| | Designed | Built | Wired into `/toolkit` |
|---|---|---|---|
| Custodian share check | yes | yes | yes — More ▸ Check a share…, and inside the ceremony |
| Verifiable cards | yes | yes | yes — the ceremony prints them |
| Verify this deployment | yes | yes | yes — More ▸ Verify this deployment… |
| QR from a card photo | yes | yes | yes — inside the share check |
| DKG session | yes | widget + model only | **no** — there is no op layer |
| Files / age / stream | yes | no | no |

---

## 1. The custodian verification moment

### The situation the design is for

Not "a user wants to verify a share". A specific person: they were handed a
printed card at a ceremony some months ago, they have a mnemonic and a QR on
paper, and a commitments document arrived separately — email, a wiki, a second
envelope. They are opening this tool on a laptop that has never seen the
notebook that made the card. They have no other share and they cannot get one;
the entire point of the scheme is that they cannot.

They have one question, and it is not "is this valid". It is *did I get a real
one*.

### Why this needed a surface at all rather than a recipe

The recipe exists and works:

```
shares | blip39.decode | vss.verify commitments=@commitments | out @checked
```

Three problems with leaving it at that. The custodian does not know the recipe
language and has no reason to. The failure mode is a thrown error, and
`vss.verify: share 2 does not match the commitments — it is corrupt or from a
different split` is accurate and, to the person holding the card, an
accusation. And a success is a green tile with no text on it, which is
indistinguishable from a great many other green tiles.

So: `ShareCheck` (widget) over `lib/toolkit/share-check.js` (model). The panel
prints the recipe in a disclosure, always, so the shortcut is visibly a
shortcut and not a second implementation — the check itself calls
`execVssVerify`, the same op the recipe would run.

### The distinction the whole design turns on

**Well-formed is not genuine.** A BLIP39 mnemonic carries an RS1024 checksum.
It can be decoded, indexed, and shown to be internally consistent while telling
you nothing whatsoever about which split it came from. The obvious design —
type the words, get a tick — would be a lie told fluently.

So `share-only` is its own state with its own wording and its own colour:

> **Share 2 of 3 — well-formed, and unverified.**
> Nothing has been checked. A mnemonic that decodes cleanly proves only that it
> was typed correctly; it does not show which split it came from, or that the
> person who handed it to you dealt it honestly. Paste the published
> commitments to find that out.

It renders amber, and the CSS makes that a rule rather than a choice: the four
tones are enumerated in `toolkit.css` and no rule derives one from another, so
`share-only` cannot reach the verified appearance by a refactor. Measured in
the live catalog: `rgb(227, 179, 65)`, not the brand green.

### The failure wording, and why it is four sentences

The naive message for a failed check is "this share is invalid". It is wrong
twice. The share may be perfectly valid and the *commitments* may be the wrong
document; and the holder's first assumption will be that they mistyped, which
the checksum has already ruled out.

> **Share 1 is not from split CFCC-A045-18B8.**
> The mnemonic is internally valid, so this is almost certainly not a typing
> mistake — the checksum would have caught that. Three things look like this:
> these are another split's commitments, this card is from another ceremony, or
> the card came from `sss.split`, which produces shares that carry no
> commitments and can never match any. The check cannot tell them apart.
> Confirm the split id with whoever published the commitments before treating
> the card as broken.

The third cause is the one nobody would think to state and the one that will
actually happen: an `sss` card and a `vss` card are both BLIP39 mnemonics and
look identical on paper.

### Split ids, and what they are not

`splitIdFor(publicKeyOf(commitments))` → `E872-4E60-D6E3`. Derived from the
public key the commitments commit to, so two people reading it to each other
over a phone are comparing the same cryptographic object rather than a label
someone assigned.

It is stated on the surface and in the code that this is a *label*: matching
split ids is how you notice you have the wrong document, not how you verify a
share. Truncating a public key to twelve hex digits is not a commitment and the
UI never implies it is. The verification is the verification.

There is a second id in play and it is weaker still — BLIP39 stamps a 15-bit
set id into every mnemonic at encode time. It binds cards from one encoding run
to each other and to nothing else. It is shown as a fact about the card, never
as evidence.

### What the card had to start saying

The printed card is the only artifact that outlives the room, so this is where
a wrong instruction does the most damage — and there was one.

`ShareCards` hard-coded its recovery footer to
`shares | blip39.decode | sss.combine`. The ceremony switched to `vss.split`
earlier this month. Every card the ceremony has printed since then instructs
its holder to run an op that will reject their shares, at the exact moment
nobody is available to ask. `recoveryLine(card)` derives it now, and includes
`vss.verify` in the verifiable form, because recovery is precisely when an
unchecked bad share does its damage: combining an unverified set returns a
*different* secret rather than an error.

Cards also gained:

- **`Split E872-4E60-D6E3`**, or, when the set carries no commitments, the
  words **`Unverifiable split`** in amber. The absence has to be legible on
  paper; a card that simply omits the line reads as a card whose printer ran
  out of ink.
- **A check line** — "Check this card against the published commitments for
  split …" — or, honestly, "This share cannot be checked on its own — it
  carries no commitments." An `sss` card genuinely cannot be checked in
  isolation and an instruction that silently fails is worse than none.

`collectShareCards` finds the commitments tile *by shape* (any tile whose
content parses to a `commitments` array), not only by slot name, so relabelling
`out @commitments` does not silently downgrade a verifiable split to an
unverifiable-looking one. A split id is stamped only when the point actually
parses — an id derived from an unreadable document would be a label with
nothing behind it, and comparison is the label's only job.

### The ceremony, extended rather than forked

Two additions, both in `CeremonySheet`, neither a new flow:

**Split stage — publish the public half.** The commitments were being written
to a tile and left there. Commitments that stay in the notebook make a split
verifiable in principle and unverifiable in practice: a custodian cannot check
against a document they were never given, and the split stage is the only
moment when everyone who needs it is still in the room. The panel now states it
as an instruction, including "send them by a different route than the cards".

**Cards stage — check one, the way its holder will.** Stage 3 already proves
the *set* recombines. That is a different proposition from "this card, alone,
against the published commitments", which is what every holder will have to do
and what none of them will know is possible. Doing it once at the table is how
the check gets discovered at all, and it is the last moment the dealer is
available to answer for a card that fails.

### Where it lives, and the one thing not built

`/toolkit` ▸ More ▸ **Check a share…**, as a `Sheet`. No notebook state feeds
it; no input comes from the session.

**Not built, and it should be:** a dedicated route with no notebook at all —
`/check`, or better, a page small enough to read in full. A custodian arriving
cold should not have to load a cryptography notebook to answer one question,
and the smaller the page the more credible "this ran on your device" is. That
is a new page (CSP meta, boot diagnostics, an integrity pin entry, a nav link)
and it was not worth spending the budget of this pass on when the Sheet is
functionally complete.

---

## 2. Files, age, QR

### Built: QR from a photo of a card

`qr.scan` existed with no surface. The share check has one, and it is composed
from the two real ops rather than a new capability:

```js
const file = await execFileRead({ accept: "image/*", as: "bytes" });
const text = await execQrScan(file, {});
```

Exactly `file.read | qr.scan`. The browser's own picker is the consent — the
reasoning `file.read` already records — so there is no second permission gate.

**The degradation is the design.** `BarcodeDetector` is Chromium-only today.
Where it is missing the button is not rendered disabled with a tooltip; it is
replaced by a sentence that names the limitation, names the browsers, and gives
the alternative:

> This browser cannot read QR codes — it has no `BarcodeDetector`, which today
> means anything other than Chrome or Edge. Type the words instead; the
> checksum will catch a slip.

Measured in the catalog against a `scanSupported={false}` fixture, because the
catalog's own browser happens to have no `BarcodeDetector` either — which is
how that state got exercised for free.

### Designed, not built: file-shaped work in a text notebook

`file.read` / `file.save` / `stream.seal` / `stream.open` / `age.*` all work and
all render as ordinary artifact tiles, which is wrong in three specific ways.
The design, for whoever takes it:

**A file tip is not a text tip.** A cell ending in `file.read` on a 400 MB
video currently produces a `bytes` artifact whose preview machinery will try to
make a line of text out of it. The tile for a file-origin value should lead
with filename, size, and mime — the three things the person knows the file by —
and offer the preview second, if at all. `meta.fileRead` already carries all
three; nothing reads them.

**Progress needs a shape the CSP allows.** `stream.seal` is chunked by
construction, so it can report. The two existing precedents are the bucketed
`data-fill` twelfths (`net-buffer-fill`, `jwt-fill`) and a continuous custom
property through `lib/css-vars.js` (`--run-progress`). For a file this should
be the latter — twelfths of a two-minute encryption is a progress bar that lies
by up to ten seconds — plus a byte counter, because the percentage of an
unknown-duration operation is less useful than "38 MB of 400 MB".

This needs an engine change and should be scoped as one: ops are currently
`await`ed to completion with no channel to report through. The honest options
are a progress callback in the op signature or a `basilisk:op-progress` event
in the manner of `basilisk:clipboard-wrote`. The event is smaller and does not
change 83 signatures.

**`file.save` produced nothing to see.** A save is the one op whose entire
effect is outside the page, so its artifact should say where the bytes went and
how many — and must not imply more than the browser told us. With the File
System Access API we know the chosen name; through the download-anchor fallback
we know only that a download was *started*. Those are different claims and the
tile should make different ones. Same discipline as everywhere else here: the
fallback path says "sent to your downloads", not "saved to ~/Downloads/x.age".

**`age` needs a recipient surface, not a text field.** `age.encrypt to=` is
`type: "string"` deliberately (a recipient is public, and `to=age1…` is how
everyone writes it). But `recipient-picker.js` exists for OpenPGP and an
`age1…` key pasted into a bare text field gets no validation until the op runs.
A bech32 check at the field is a small win with a real failure it prevents:
a truncated recipient that still looks plausible.

---

## 3. Distributed key generation

**Design-ahead. Nothing here is wired into the shell, on purpose.**

`lib/quorum/dkg.js` implements the rounds. The op that runs them over a live
exchange does not exist and is explicitly not half-built. What is built here is
`lib/quorum/dkg-session.js` — a pure projection from "what arrived from whom"
to "what should this person be told" — and `DkgPanel`, which renders it. Both
are exercised in the catalog at `#dkg` and neither touches a peer, a channel,
or the registry.

The reason to design it now rather than alongside the transport is that the
interesting part is the failure, and a failure path designed while the happy
path is being demoed comes out looking like an edge case.

### Assumptions this makes about the op layer

Stated plainly, because they are assumptions:

1. **Rounds are ordered and the session waits.** The protocol cannot tolerate a
   participant running round 1 while another is still finalizing, so the op
   wants the wait-for-peers machinery `quorum.offer` already has, not a bare
   `quorum.recv`.
2. **The roster is fixed before round 1.** Adding a participant afterwards is a
   different key, not a bigger room. The `assembling` phase exists to make that
   a moment rather than a race.
3. **Each participant's round state is observable locally.** The panel projects
   what *I* received; it does not claim to know whether B received A's share.
   Any design where one participant reports on another's progress needs
   authenticated attestations and does not exist here.
4. **`connstate`-style types.** A live session is a HANDLE and its readout is
   OBSERVE, matching the existing three-way split, so the panel consumes a
   projection and never a live object.

### Three axes, never merged

Per participant: **connected** (the `peer-dot` vocabulary, shared with
`ConnectionsPanel` so there is one dot language in the app), **authenticated**
(both pgpVerified and kcVerified, the existing rule), and **round** (what they
have contributed). They are genuinely independent — a fully connected, fully
authenticated participant can deal a share that does not check out, and that is
the entire case this panel exists for. The CSS enumerates the three separately
and derives none from another.

### Progress

"Waiting for 2 of 5 commitments" counts *other* participants only. A denominator
that quietly includes yourself is off by one in the direction of looking
healthier than it is. Pinned in `dkg-session.test.js`.

`canFinalize` requires **every** other contribution, not a threshold of them.
Joint-Feldman sums all contributions: a missing one is a different key, not a
smaller quorum. The threshold governs later reconstruction and nothing about
this stage — an easy and expensive thing to get backwards.

The phase itself is derived from what arrived rather than stored, because a
stored phase and a participant list can disagree, and when they do the stored
one wins on screen while the real one governs the protocol.

### The refusal — the reason this document has a DKG section

There is no complaint round. `finalize` refuses and names the dealer. That is
one sentence in `dkg.js` and four paragraphs on screen, because the reader has
four separate things to learn:

**What happened.** They published commitments to a secret and then sent a share
of something else. Deliberate or a bug; the arithmetic cannot tell, and neither
can you.

**What it cost.** Nothing usable came out. The joint key is the sum of *all*
contributions, so one bad contribution is not a share short — it is a different
key nobody can reconstruct. There is no partial result to keep, and the panel
does not offer to keep one.

**The remedy.** Start again without them, and everyone has to restart together;
one participant re-running round 1 against others' stale state lands in a third
key that matches nobody.

**And the part a stack trace could never say.** Commitments are broadcast but
shares are pairwise, so a dealer who sends one bad share corrupts exactly one
participant's view. *Only you saw this.* From every other seat, "X dealt badly"
and "you are claiming X dealt badly" are the same observation. Excluding a
participant on one accuser's word is precisely the attack a complaint round
exists to prevent.

Which is why there is a **Start a new session** button and no **Exclude them**
button. Building the eviction primitive without the adjudication that makes it
safe would be shipping the vulnerability with a nicer interface. The caution
paragraph is set apart in the CSS specifically so it cannot be skimmed as more
of the same; it is the one paragraph arguing against the reader's first
instinct.

### And the standing note

Rendered in every phase including `complete`, because `complete` is the phase
in which someone decides what to protect with the thing they just made:

> Experimental. This produces a key the group jointly controls; it does not
> produce threshold signing — using the key still means reconstructing it
> somewhere, on one machine, at which point one machine holds it. It has not
> been independently reviewed. Do not put anything unrecoverable behind it.

The `complete` panel has **no export button**, and says why: the secret does not
exist, and a button implying otherwise would misstate the protocol.

---

## 4. Verify this deployment

`docs/THREAT-MODEL.md` opens by saying you are trusting served code, and closes
by telling you to check `/integrity/module-roots.json` against the SRI hashes in
the HTML. `lib/module-integrity.js` has been doing exactly that on every page
load. There was nowhere to see the answer.

`IntegrityPanel` over `lib/toolkit/deployment-check.js`, at
`/toolkit` ▸ More ▸ **Verify this deployment…**.

### It does not re-implement the check

The comparison is `verifyModuleRootAgainstPins`, unchanged — the same function
the boot path gates on. Two implementations of a security check drift, and the
one that drifts is always the one people read. Everything in
`deployment-check.js` is presentation: mapping one result onto the state a
person is actually in.

### Four of the six outcomes are "cannot verify"

| Status | Tone | When |
|---|---|---|
| `verified` | ok | root matches the pin(s) |
| `mismatch` | error | root differs — the failure the mechanism exists for |
| `disagree` | error | mirrors disagree with each other |
| `unreachable` | error | pins configured, none could be read |
| `unpinned` | warn | no pin document configured (unsigned build) |
| `no-sri` | warn | the page carries no integrity hashes at all (dev) |

None of the four is drawn as success, and the enumerated CSS is what makes that
structural rather than remembered. The wording refuses the comfortable reading
in each:

- `unreachable`: "A blocked or offline fetch looks exactly like a suppressed
  one. Treat this as unverified rather than as fine: the check that would have
  caught tampering is the check that did not run."
- `unpinned`: the root is real and the browser did enforce every module's SRI —
  "What is missing is anything independent to compare the root against, so this
  number attests to nothing but itself."
- `mismatch`: names the boring explanations (stale cache, half-finished deploy)
  because they are the common ones, and then says they are indistinguishable
  from the interesting one.

### The limitation is not in a disclosure

Under every verdict, including the successful one, uncollapsed:

> This check runs inside the page it is checking. It catches a swapped module, a
> poisoned cache, or one CDN edge out of step — it cannot catch a server that
> served you a tampered checker along with tampered code. For anything
> unrecoverable, verify outside the browser: fetch the pin document yourself, or
> run the recipe through the CLI, where there is no served-code question at all.

A green tick is the moment a reader is most likely to stop reading, which is
exactly why collapsing this would make the panel more reassuring and less true.

The full 64-hex root is shown, selectable, never truncated: the root is the
thing a person compares against another machine or another person, and a
truncated one is decorative.

### What the catalog caught

The live panel on the dev server reported *"Cannot verify — this page carries no
integrity hashes"* while printing a well-formed 64-character **Loaded root**
beside it. `computeLoadedModulesRoot` falls back to hashing its own module bytes
when no SRI is present, producing a perfectly valid root over exactly one file.
Rendered in a row labelled "Loaded root", next to a verdict saying nothing could
be checked, that number looks precisely like the thing a careful reader is meant
to write down and compare — and it is not it. The `no-sri` verdict now blanks
the root, and `deployment-check.test.js` pins that it stays blank.

Nothing else caught this. It type-checked, it built, the unit tests passed, and
the state only occurs on a live dev server.

### And a second thing the catalog could not catch, because of itself

`toolkit-widgets.html` carried **no Content-Security-Policy meta**, and
`toolkit-widgets` was absent from `STATIC_PAGES` in `basilisk-dev-server.js`.
Between them, the one page whose entire purpose is surfacing widget defects was
the one page served without the report-only production policy — so a new
widget's inline style would have looked fine in exactly the place it was
supposed to be caught. Vite resolved the route regardless, so nothing appeared
broken. Both fixed; the report-only header is now measured live on the catalog,
and the new widgets fire no violations.

---

## Registry

**No new ops. No new pipeline types.** Everything above composes registered ops
(`vss.verify`, `vss.commitments`, `blip39.decode`, `file.read`, `qr.scan`) or is
pure presentation over an existing library module. The two places this was
tempting and refused:

- The custodian check could have been a `vss.check` op taking a mnemonic and a
  commitments document directly. It does not need to be: `blip39.decode` on one
  mnemonic yields a one-element share set with the right index, and
  `vss.verify` handles a one-element set unchanged.
- The DKG session would like a `dkg.run` op. That is the op layer, it is a real
  piece of work, and the deliberate decision recorded in `HANDOFF.md` is that it
  is better absent than half-built. This design does not sneak it in.
