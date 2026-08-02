# Peer connections as a managed thing — §54–§59

Design pass for the capability in [BRIEF.md](./BRIEF.md). Sections continue the
handoff series (§32–§38 artifact actions, §47–§53 the representation pass), so
§54 is the first free integer.

Everything below was written against the source, not from memory. Where a claim
about shipped behaviour appears, the file and the line that establishes it are
named, because the last three design docs in this repo each described behaviour
the code did not have.

---

## §54 — The defect, and why it is a design decision rather than a bug fix

### §54a What is actually broken

`execCreateOffer` in `web/src/lib/toolkit/rtc-ops.js` closes its own
`RTCPeerConnection` in a `finally` before returning:

```js
} finally {
  try { pc.close(); } catch (_) { /* ignore */ }
}
```

The SDP it returns is well-formed. It is also meaningless. An offer's
`a=ice-ufrag`, `a=ice-pwd` and `a=fingerprint` name a *live* transport: the
ufrag is the credential the far end must put in its STUN binding requests, and
the fingerprint is the certificate the far end will pin during the DTLS
handshake. Close the connection and all three name an object that no longer
exists. There is nothing to hand the answer back to.

This is not staleness. A stale offer would connect badly; this one cannot
connect at all. The e2e suite asserts it directly today
(`rtc-transport.e2e.js`, "emits an offer whose peer connection is already
gone"): an answer applied to that offer sits at `new`/`connecting`/`failed`
after six seconds, against the ~4 ms a live host-candidate pair takes.

Two shipped templates in `lib/toolkit/recipe.js` describe the flow anyway —
`sdp-hand-carried` ("in a real exchange the offer goes to the other side by any
channel you like") and `sdp-to-clipboard` ("paste it into chat"). Both are
false. A user who follows either gets two SDP blobs and no connection, with
nothing on screen saying why.

### §54b Why the obvious fix is the wrong one

The obvious fix is to delete the `finally` and add an `rtc.accept` op. That
fixes the two templates and nothing else, and it introduces a resource — a live
`RTCPeerConnection` — that nothing owns, nothing enumerates, nothing closes, and
nothing draws. The next question after "the offer is live" is immediately
"which offer", because a notebook has many cells and a user may run `rtc.offer`
three times.

So the moment the connection outlives the op, there has to be something that
holds connections. That thing is the design decision, and it is the same
decision as the connection manager the brief asks for. One registry answers
both.

### §54c What the user asked for, restated as a constraint

> Quorum should be able to communicate with connected peers, but not have to
> worry about how that is done. Just provide a way for users to manage peers. We
> should still offer the underlying raw capabilities / expose WebRTC
> functionality, but users shouldn't be forced to use that to setup a
> connection.

Three requirements, and they are not the same requirement:

1. **A user can get connected without hand-composing SDP.** Today the only path
   to a working data channel is `quorum.offer`/`quorum.join`, which needs an
   OpenPGP private key, a fingerprint audience, a derived room, and a reachable
   signalling relay. That is a lot of ceremony for "connect me to that browser".
2. **The raw layer survives.** `rtc.gather`, `rtc.certificate`, `rtc.check`,
   `rtc.state`, `rtc.stats`, `rtc.quality` are inspection ops and stay exactly
   as they are.
3. **Quorum sits on top rather than beside.** Whatever inventory of live
   connections exists, quorum's peers are in it — otherwise there are two
   parallel notions of "connected" and the diagnostics have to pick one.

Note what requirement 2 does *not* protect. `rtc.offer` and `rtc.answer` are not
raw capabilities in any useful sense: a raw capability is one the browser has,
and the browser has no capability to mint an offer for a connection it then
destroys. They are the defect wearing the raw layer's clothes. See §55c.

---

## §55 — The op surface

### §55a The registry

`web/src/lib/quorum/link-registry.js` — a module-level map of **managed peer
connections**, called *links* throughout, because "connection" is already
overloaded three ways in this codebase (`RTCPeerConnection`, `connectionState`,
`ConnectionsPanel`).

```
LinkRecord {
  id          string     // the name a recipe refers to it by
  origin      "peer" | "quorum"
  role        "offerer" | "answerer"
  pc          RTCPeerConnection
  channel     RTCDataChannel | null
  …           inbox, waiters, flags, timestamps, lastError
}
```

`origin` is the load-bearing field. A `quorum` link is identity-bound: its far
end proved possession of a PGP key and the data channel carries a pairwise
session key. A `peer` link is not: DTLS encrypts the wire, and *whoever received
the offer* is on the other end. Those are different security properties and the
registry is the one place that knows which is which, so every surface that draws
a link — the panel, the `connstate` tile, an op's refusal text — reads it from
there rather than deciding for itself.

### §55b The seven ops

All in toolbox `webrtc`, shelf `peer` (which already exists and is already
called "Peer & signaling"). All comply with the `namespace.singlelowercaseword`
convention that `rtc-channel-ops.test.js` locks.

| Op | kind | input | output | What it does |
|---|---|---|---|---|
| `peer.offer` | source | none | `sdp` | Mints a managed link, opens a data channel, waits for gathering, emits the offer. **The link stays live.** |
| `peer.answer` | transform | `sdp` | `sdp` | Consumes a remote *offer*, mints a managed link, emits the answer. Stays live. |
| `peer.accept` | transform | `sdp` | `connstate` | Applies a remote *answer* to a named link. Signalling only — does not wait. |
| `peer.wait` | source | none | `channel` | Blocks until the named link is connected and its channel open. |
| `peer.send` | transform | `text` | `text` | Writes to the link's channel; passes the value through. |
| `peer.recv` | source | none | `text` \| `bundle` | Reads from the link's inbox. |
| `peer.close` | source | none | `connstate` | Closes one link, or every `peer`-origin link. |

The whole hand-carried exchange, both halves, with no PGP key and no relay:

```
# Alice
peer.offer @a | out @offer            # carry @offer to Bob however you like

# Bob
in @offerFromAlice | peer.answer @b | out @answer

# Alice
in @answerFromBob | peer.accept @a | out @state
peer.wait @a | out @link
"hello" | peer.send @a

# Bob
peer.wait @b | out @link
peer.recv @b | out @msg
```

### §55c What is retired

`rtc.offer` → `peer.offer`, `rtc.answer` → `peer.answer`. **Removed, not
aliased** — the house rule (HANDOFF, "Retired names are removed, not aliased").
Both go into `LEGACY_STEP_MIGRATE` in `step-names.js`, so a saved notebook fails
live parse with a sentence naming the replacement, and Upgrade recipe rewrites
it.

Two existing entries retarget in the same edit, because the migration table is
single-pass and `rtc.createoffer → rtc.offer` would otherwise migrate one
retired name to another:

```
"rtc.createoffer": "peer.offer",     // was → "rtc.offer"
"rtc.createanswer": "peer.answer",   // was → "rtc.answer"
```

**Why rename rather than repair in place.** `rtc.offer` with a `name=` param and
no `finally` would work and would need no migration. It was rejected for one
reason: `rtc-ops.js`'s own header says the module is "the raw layer beneath
`quorum.*`: each op wraps one browser WebRTC capability so ICE / DTLS / SCTP are
inspectable outside a live session". An op that allocates into a registry and
must be closed is not that. Leaving it under `rtc.` would make the module header
a lie on the day it landed, and the two-layer split the brief asks for would
exist in the design document and nowhere a user could see it. The layer boundary
is the feature; the names have to carry it.

`rtc.send`/`rtc.recv` are **not** renamed and **not** widened to managed links.
They write through `QuorumSession.sendChat`, which encrypts under the pairwise
session key before touching the channel. Pointing them at a link that has no
session key would either throw at a confusing place or — worse, if anyone
"fixed" the throw — put plaintext on a channel whose far end is unauthenticated,
under an op name whose whole history is encrypted traffic. `peer.send` /
`peer.recv` are separate names for a different guarantee, and they say so in
their `doc` strings.

### §55d Why `name=` and not a piped handle

`peer.offer` in cell 1 and `peer.accept` in cell 4 are separate engine calls with
a human step in between (carrying the blob to the other browser). A pipeline
value cannot span that, and a slot holding a HANDLE cannot be consumed by
anything — `isObserveOnlyType` refuses HANDLE and OBSERVE as any computing op's
input, which is exactly the rule that makes the type honest.

So the link is referenced by name, and the name is a positional param defaulting
to `default`, which makes the two-party case free of ceremony:

```
peer.offer | out @offer
```

This is the same arrangement `quorum.*` already uses and it is not a new idea:
`quorum.offer` emits a `session` HANDLE artifact, and `rtc.send` downstream does
**not** read that artifact — it reaches the live session through the module-level
`current` in `quorum-ops.js`. The artifact is a receipt that a live thing exists;
the module is how the live thing is reached. `peer.*` copies that, with a keyed
map instead of a single slot.

### §55e Why `peer.accept` does not block

The tempting shape is one op: apply the answer, then wait for ICE, emit the
channel. It was rejected because it folds two unrelated failures into one error
string. "This SDP is not an answer" and "ICE checked every pair and none worked"
have different causes, different fixes, and — per the organizing question the
whole `NetworkArtifact` family is judged by — different next steps. A single op
would have to pick one sentence.

So `peer.accept` is signalling and emits `connstate`; `peer.wait` is the ICE
outcome and emits `channel`. `peer.wait`'s refusal is the ICE-failure sentence
from `connStateReadout`, which already exists and already says what to do next.

---

## §56 — Types

Binding constraint, from HANDOFF: **the output type must be known before the
run**, and the three-way DATA / HANDLE / OBSERVE split is enforced by
`resolveStepType`.

| Value | Class | Why |
|---|---|---|
| `sdp` from `peer.offer` / `peer.answer` | **DATA** | An SDP is inert and is *meant* to be published — carrying it is the entire flow. Unchanged from today. |
| `connstate` from `peer.accept` / `peer.close` | **OBSERVE** | A read-out of link state. Displayable, never an input. |
| `channel` from `peer.wait` | **HANDLE** | A live `RTCDataChannel`, meaningful only inside the run that made it. Already in `NETWORK_HANDLE_TYPES`; this is its first producer. |

**`peer.wait` is where the HANDLE constraint is discharged.** The brief is right
that a managed peer connection is a HANDLE, and the honest place to emit one is
the op whose postcondition is "this connection is live and usable" — not
`peer.offer`, whose postcondition is "an offer exists and nothing is connected
yet". Before `peer.wait` there is no live channel to hand out; after it there
is.

Every one of the seven has a fixed output type independent of state. The one
that varies is `peer.recv`, and it varies on a **parameter**, through
`effectiveIo(params)` — precisely the mechanism `rtc.recv` already uses for
`count=`, which the type checker and the caret both read before the run. That is
the permitted form. The prohibited form — the one seven defects were closed for
yesterday — is a type that depends on what the *run* turns out to produce, and
nothing here does that.

Note what is deliberately absent: there is no op that emits "a link" as DATA.
A link is not publishable and `peer` (already in `NETWORK_DATA_TYPES`) stays
what it is — a description of a remote party, not a live object.

---

## §57 — What quorum stops owning

### §57a The inventory

Today five diagnostic ops — `rtc.state`, `rtc.check`, `rtc.stats`,
`rtc.quality`, `rtc.restart` — begin with:

```js
const session = requireSession("rtc.state");   // getLiveSession() or throw
```

and then iterate `session.peers`. So the *quorum mesh* is the definition of
"what is connected", and any connection made another way is invisible to every
diagnostic in the app. That is the parallel-mesh problem the brief names, seen
from the diagnostics' end.

**The move: those five ops enumerate the link registry, and `QuorumSession`
registers its peer connections into it.** `getLiveSession()` stays — the DKG
transport and the roster projection genuinely want the session object, not a
list of links — but it stops being how the app answers "what is connected".

Quorum registers a link on `_ensurePeerConnection`, deregisters on `stop()`, and
supplies `origin: "quorum"` plus the fingerprint as `id` and its own
`kcVerified` as the authentication fact. Nothing about negotiation, key
derivation, key confirmation or relay moves. The mesh keeps every behaviour the
e2e suite proved; what it gives up is being the sole answer to a question it was
never really the right owner of.

Two things fall out for free, and both are the point:

- `rtc.state | out @s` after a hand-carried `peer.offer` now reports something
  instead of throwing "no live exchange". Every failure surface built in
  `bfec72a` — the verdict, the three-stage track, the terminal outcome, the
  what-to-do-next — starts working for direct links with no new UI.
- `rtc.restart` restarts direct links too, so "Restart connection" means one
  thing.

### §57b What quorum keeps, and why the deeper reuse is not in this unit

The brief's fuller reading of "quorum reuses whatever session management
capabilities" is that `QuorumSession` should *drive* the manager — hold no
`RTCPeerConnection` of its own, and get negotiation, glare handling and ICE
restart from the shared layer. That is right, and it is **not** in this unit.
See §59b for the argument. The registry is the seam it would be built on, which
is why the registry is shaped as an inventory of connections rather than as a
private store for `peer.*`.

---

## §58 — The UI

**Reviewed before it was built.** [UI-REVIEW.md](./UI-REVIEW.md) holds the
design critique and the WCAG 2.1 AA audit in full; six critique findings and
four audit findings changed what is below, and the first draft of this section
is preserved there so the corrections can be read against it. The headline
changes: the row lost two fields, the authentication label moved from the
section header onto the row, and Restart became conditional.

### §58a The Connections tab becomes an inventory

`ConnectionsPanel` today assumes exactly one quorum session and renders a
"No live session" empty state otherwise. It gains a second section — **Direct
connections** — and the empty state moves behind *both* being absent.

Row anatomy, extending the existing vocabulary rather than replacing it, and
deliberately the *same* four fields the quorum rows already carry:

```
● alice-laptop        host/srflx   unauthenticated   connected
│ │                   │            │                 └ connectionState, as text
│ │                   │            └ .peer-verdict, the quorum rows' own slot
│ │                   └ nominated pair (existing `via`)
│ └ existing .peer-dot[data-peer-state]
└ id
```

`.peer-dot[data-peer-state]` already enumerates
`new | connecting | connected | disconnected | failed | closed`, which is
exactly `RTCPeerConnection.connectionState`. No new colours, no new states, no
inline style — the state set is closed so the stylesheet enumerates it, which is
the rule the panel's own comment already states.

**Two fields were cut from the first draft** (critique C1/C2). The negotiation
role (`offerer`/`answerer`) answers no question the panel exists to answer and
belongs on the `connstate` tile, which opens full-width in a `Sheet`. A `direct`
origin badge on every row inside a section titled "Direct connections" is the
section title repeated N times — grouping *is* the origin signal. Both were
squeezing the `id`, which is a truncating `<code>` and the only element that
says which connection a row is.

Keeping `connectionState` as **text** beside the dot is not decoration: the dot
is `aria-hidden` and colour-only, so the text is what satisfies 1.4.1.

### §58b The verdict comes from the read-out, not the widget

When a link is not connected, the row carries the headline and the next step
from **`connStateReadout`** in `artifact-readouts.js` — the same function the
`connstate` tile calls. This is the representation boundary applied literally:
"Could not connect / Add a TURN relay" is one fact, and a second copy in the
panel would be the seventh defect of that class in this codebase.

One new read-out is needed and it belongs in the same file:
`linkOriginNote(origin)` — the sentence that distinguishes an identity-bound
quorum link from a direct one. It has two consumers on day one (the panel's
section caution and `peer.send`'s refusal path), which is check 3 of the
boundary's own test, so it is a read-out rather than view-local text.

### §58c What a direct link says about itself

A direct link is DTLS-encrypted and **unauthenticated**: the peer on the far end
is whoever received the offer.

The first draft put that on the section header only, reasoning that a caution
repeated per row reads as an alarm and stops being read. The critique found the
worse failure underneath: the quorum section reports authentication *per row*
(`verified`/`unverified`), so a direct section that reports it nowhere per-row
uses a different grammar in the same column — and **the less safe section is the
one that looks cleaner**, beside brand-green `connected` dots.

So it splits, along the line `connStateReadout` already uses:

- **The row carries the label** — `unauthenticated`, in the same
  `.peer-verdict[data-verdict="warn"]` slot the quorum rows use for
  `unverified`. One vocabulary, one column position, no new colour.
- **The section header carries the explanation** — one sentence, once, saying
  *why*: DTLS encrypts the wire, and whoever received the offer is on the far
  end.

That also answers the alarm-fatigue objection that motivated the first draft:
the row word is a label, not an alarm. It is the same discipline as `share-only`
never rendering green — the property is structural, so the surface states it
structurally rather than relying on the reader remembering.

### §58d Per-link actions

Each row carries **Close**, and **Restart** only when the link is `failed` or
`disconnected`.

Restart is conditional because ICE has not given up at `new` or `connecting`, so
the control would have nothing to do — and it is *absent* rather than dimmed,
which is both this codebase's established rule for an inapplicable control and
the way past §47's finding that `disabled` removes a button from the tab order
and takes its reason with it. `SessionStrip` already gates its Restart on
`state === "failed"`; this is that rule, not a new one.

Two accessibility requirements are part of the design rather than polish on it:

- **`aria-label` carries the link id** — `Close connection alice-laptop`. Three
  rows of a button labelled only "Close" is three identical announcements with
  nothing to tell them apart (4.1.2, and the highest-value finding in the
  audit).
- **24px minimum height**, via a `.link-action` rule in `toolkit.css` rather
  than utility classes. The panel's existing buttons are ~22px against 2.5.8's
  floor; that is an older finding about a widget this change was not asked to
  touch, and it is recorded in IMPLEMENTATION-STATUS instead of being swept in.

The session-level Restart/Close keep their current meaning and are unchanged.

### §58e Structure, empty state, and when a row leaves

**Headings.** Each section gets an `<h4>` and each `<ul>` is bound to it with
`aria-labelledby`. The panel has no heading structure at all today — the tab's
`<h3>` lives in `ToolkitShell` — so two sections would otherwise be two
undifferentiated runs of list items, and heading navigation is a primary
screen-reader movement (1.3.1).

**The empty state is the most valuable copy on the panel**, because it is the
only place a user learns the new capability exists. It names `peer.offer` first
— the lower-ceremony path — and then the quorum pair, rather than naming only
the quorum pair as it does today.

**When a row leaves the list**, mirroring the policy `closeQuorumExchange`
already implements: a link closed on purpose is deregistered and its row goes; a
link that reached `failed` stays until it is closed, so it can be read and
restarted. A failed link vanishing at the moment it becomes worth reading is the
exact hazard `bfec72a` was fixing at the tile level.

**No live region**, decided rather than overlooked: `aria-live="polite"` on a
list that churns `new → connecting → connected` through an ICE handshake would
announce continuously for its whole duration. The panel is a surface you look
at, not one that narrates.

**No motion.** Pulsing the dot while `connecting` was considered and rejected —
`SessionStrip` pulses because a *run* is blocked, which the panel does not know,
and the dot's colour already separates `connecting` from `connected`. It would
buy little and cost a `prefers-reduced-motion` rule.

---

## §59 — Scope

### §59a Unit 1 — built

1. `lib/quorum/link-registry.js` — the registry, pure enough to test in node.
2. `lib/toolkit/peer-ops.js` — the seven ops.
3. Registry entries, engine dispatch, migration of the two retired names, verb
   smoke cases.
4. The five diagnostic ops read the registry; `QuorumSession` registers into it.
5. `ConnectionsPanel`'s Direct connections section + `linkOriginNote`.
6. Corrected `sdp-hand-carried` / `sdp-to-clipboard` template blurbs, and a
   `SDP_TRANSPORT_CLOSED` that is no longer true of the ops that produce SDP.
7. e2e: two real browsers, an offer carried between them through the ops, ICE
   state transitions, nominated pair, bytes through the channel.

### §59b Unit 2 — designed, not built

**`QuorumSession` drives the manager instead of owning `RTCPeerConnection`s.**

Deferred deliberately, and the reason is not effort. `QuorumSession`'s
negotiation is entangled with its cryptography in a way that is correct and
easy to break: `derivePairwiseSessionKey` binds *both* DTLS fingerprints into the
transcript (the RFC 8844 shape), so `peer.localDtls` is extracted from
`pc.localDescription.sdp` inside the `onnegotiationneeded` handler and
`peer.remoteDtls` arrives on the signalling envelope. A manager that owns
negotiation owns the moment the local fingerprint becomes known, and the key
derivation has to be re-plumbed to it. Get that subtly wrong and the failure mode
is *key confirmation succeeds anyway* on a transcript that no longer binds the
transport — a security regression that every existing test passes.

The right sequencing is: land the registry, let it hold the mesh's links for a
while, and lift negotiation afterwards with the transcript binding as the
explicit acceptance criterion. A reviewed design plus that split is a better
outcome than a half-lifted mesh.

### §59c Deliberately not built, with reasons

- **Trickle ICE for `peer.*`.** `peer.offer` waits for gathering to complete and
  ships a complete offer, because the blob is carried by a human. Trickle needs a
  signalling channel, and if you have one you want `quorum.*`.
- **A `peer.*` glare path.** Perfect negotiation resolves *simultaneous* offers
  on a persistent signalling channel. Hand-carrying is turn-taking by
  construction: there is no window in which both sides offer. The polite/impolite
  machinery stays where it is used, in `QuorumSession`.
- **Persisting links across runs.** A link is a HANDLE. `basilisk_webrtc`
  IndexedDB (§30a/30b) remains unbuilt and this does not need it.
- **`peer.*` in the CLI.** `RTCPeerConnection` does not exist in Node; the ops
  are main-thread browser only, like every other WebRTC op.
