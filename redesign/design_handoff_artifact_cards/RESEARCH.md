# Artifact cards — research (§47–§53)

What every artifact kind's tile is for, whether it answers that today, and
where a *live* or interactive element is legitimate. Design and research only:
nothing under `web/` was touched, and the probes that back the measurements
were run in a throwaway worktree and deleted.

Numbered §47 onward. §32–§38 is `design_handoff_artifact_actions`'s design
series, §39–§46 its visual series; both are cited by shipped code, so this
document starts past them. An unqualified `§` means this series.

## Reading order

1. **§47** — the rule this research tests, and the three tiers of "live". Read
   this first; every per-type verdict is an application of it.
2. **§48** — the per-kind table and the notes behind it.
3. **§49** — **the decision: the output is the object, the card is a
   representation, and pulling a representation into the pipeline is a
   projection.** With the recipe-language cost of building it. This is the
   decision every recommendation below depends on and it reads on its own.
4. **§50** — where the intent gets recorded: metadata, not a step reference.
   With the measurement that settles it.
5. **§51** — what a live card owes the receipt, the tray and a reload.
6. **§52** — defects found while looking. Six are real and reproducible.
7. **§53** — what is worth building, prioritised, with acceptance criteria.

## How this was measured

Every claim below was checked against `a0a81c1`, on 2026-08-01, one of two
ways. **Two agents held `web/src/toolkit/**`, `web/src/css/**` and
`web/glyphs/**` during this work**, so nothing here was measured against the
working tree: a detached worktree was cut at `HEAD`, built with
`npm run build`, and served with `vite preview` on its own port.

- **In the built page**, driven at `/toolkit` (real runs, via `#r=`) and
  `/toolkit-widgets` (the catalog). Geometry and text read out of the DOM, per
  HANDOFF — screenshot compositing is unreliable here and every exact number
  below is a `getBoundingClientRect` / `innerText` / `getComputedStyle` read.
- **In the engine**, by `compileRecipe` + `runRecipe` in a probe test. Note
  both traps: `runRecipe` returns the artifact array **directly**, and
  `compileRecipe`'s errors are at `result.validation.errors`. The probes were
  written against those paths and are quoted with their recipes so they can be
  re-run.

---

## §47 The rule, and what "live" is allowed to mean

### §47a The inherited rule, restated

> **An artifact records what happened. A live card may additionally show what
> is true now, but must never silently replace one with the other.**

This is §37a's corollary — *a button may move an artifact, never compute a new
one* — extended from buttons to time. `OtpCodeCard` already embodies it: the
digits never change, and what ticks is a clock against an absolute expiry
derived from `otpStep × otpPeriod`. Research below did not overturn it. It did
find that the rule is under-applied in one direction (§48 records four cards
that state a *now* fact as a bare date and leave the reader to do the
arithmetic) and mis-applied in exactly one case (§52 D1).

### §47b Three tiers of live, and most things want tier 1

The word "live" has been doing three jobs. Separating them is most of the
design work, because the cheap tier is the one nearly everything needs.

| Tier | What it is | Resolution | Cost | Who needs it |
| --- | --- | --- | --- | --- |
| **0 — static** | Derived once from the body. | — | free | most cards |
| **1 — render-time** | Recomputed against `Date.now()` on each render, no timer. | days / hours | free | expiry verdicts, snapshot age at coarse grain |
| **2 — ticking** | An interval re-renders the card. | seconds | one timer per mounted card | OTP, JOSE `exp` |

**Tier 1 is not a lesser tier 2.** A key that expires in nine days does not
need a timer; it needs a *verdict* — "expires in 9 days", in `--warn` — where
today it prints `expires 2026-08-10` and the reader does the subtraction.
Reaching for tier 2 where tier 1 was wanted is how a page grows timers it does
not need; four of the six things this research found were tier 1.

The line between them is resolution, and resolution follows from the fact
being shown. Ask: *would this text differ if it re-rendered one second later?*
If no, it is tier 1.

### §47c What "interactive" may mean

Interaction on a tile is allowed exactly when it changes **what you see**, not
**what the artifact is**. The test that decides it in one question:

> **Could this interaction change what Copy copies?**

If yes, it is computing a new value and §37a refuses it. If no, it is a view
and the tile may have it. By that test the following are all fine and none of
them needs a new rule: filtering a recipient list, searching it, sorting a
digest table, scaling a QR, toggling raw/armor (four cards already do this),
switching alphabet (the format bar already does this), and expanding into the
Sheet.

The following are refused, and each was already refused for the same reason:
*Refresh* on a code, *Decrypt with…* on a ciphertext, *Verify threshold* on a
share, *Verify* on a signature or a receipt.

---

## §48 Per-kind findings

24 kinds in `web/src/toolkit/artifact-kinds/registry.tsx`. **17 are already
right and are recorded as such.** Grades: ✅ answers its question; ◐ answers it
but leaves work to the reader; ✗ does not answer it.

| Kind | The question someone actually has | Today | Live tier warranted | Verdict |
| --- | --- | --- | --- | --- |
| `openpgp-public` | Whose key is this — and can I still use it? | ◐ | 1 | Date without verdict (§48b) |
| `openpgp-private` | Same, plus: is this the half I can sign with? | ◐ | 1 | Same |
| `keypair` | What did `genkey` make, and where is the other half? | ✅ | 0 | Already right |
| `keypair-public` | Which key, in a form I can paste? | ✅ | 0 | Already right |
| `public-key` | Same, no pair beside it. | ✅ | 0 | Already right; no catalog row (§52 D7) |
| `keypair-private` | Which key is this, *without* revealing it? | ✅ | 0 | Already right — `publicView` is the model |
| `secret-key` | What algorithm, and is it symmetric? | ✅ | 0 | Already right |
| `key` | (deliberately least specific) | ✅ | 0 | Already right — says nothing rather than guessing |
| `ssh-public` | Which key, and does the fingerprint match the server's? | ✅ | 0 | Already right |
| `ssh-private` | Which key, without revealing it? | ✅ | 0 | Already right |
| `network-value` | What is this connection doing **now**? | ✗ | 1 | Present tense over an undated snapshot (§48c) |
| `inspect-snapshot` | What is inside this value? | ✗ | 0 | Unreachable through `out` (§52 D2) |
| `jose-token` | Is this token valid, and when does it expire? | ◐ | 2 | Best card here; behind a 15s reveal (§48d) |
| `ciphertext` | Who could open this, and how is it wrapped? | ✅ | 0 | Already right |
| `envelope` | Is this a share? (no) | ✅ | 0 | Already right |
| `share` | Which share is this, and how many recover the secret? | ✅ | 0 | Already right — the other `publicView` model |
| `recipients` | Who is this going to, and will anyone be skipped? | ◐ | 0 | Right, but unbounded (§52 D6) |
| `sshsig` | Which namespace, and who signed? | ✅ | 0 | Already right |
| `diagnostic` | Can I connect, and what do I do about it? | ✅ | 1 | Right; same tense point as `network-value`, weaker |
| `receipt` | What did this run produce? | ◐ | 0 | Right, but unbounded (§52 D6) |
| `qr` | **Can I scan this?** | ✗ | 0 | Too small to scan (§52 D4) |
| `otp-code` | What do I type, and have I got time? | ◐ | 2 | Right when live, **wrong when pinned** (§52 D1) |
| `text` | (no view, deliberately) | ✅ | 0 | Already right |
| `secret` | (no view, deliberately) | ✅ | 0 | Already right — but see §48e |

### §48a The pattern in the ✅ column

The ten key artifacts are the strongest cards in the codebase and it is worth
naming why, because the fixes below are all applications of the same two moves.

1. **They answer identity, not content.** `KeyCard` leads with the algorithm
   the recipe named and the fingerprint in the shape the matching CLI prints,
   because *which key is this* is the question and the JWK is not an answer to
   it.
2. **`publicView` is the mechanism that makes a masked tile useful.** Three
   kinds use it and all three earn it the same way: the facts drawn come off
   *public* material, so §34b permits them while the secret stays masked. A
   masked private key that names itself is worth more than a masked private key
   that does not, and the rule that makes it safe is already written down.

Everything proposed in §53 is one of those two moves applied somewhere they are
not yet.

### §48b Dates that are asked a *now* question and answer with a date

`OpenPgpKeyCard` renders `created 2026-08-01 · does not expire`, and for a key
with an expiry, `created … · expires 2027-08-01`. Measured on the catalog's
`#keyartifacts` section:

```
Dana Okonkwo <dana@example.org> | public | 5CDE D055 … | created 2026-08-01 · does not expire
```

The reader's question is not "when does it expire", it is "**is it still
good**". Today they subtract two dates mentally. The same is true of
`CertificatePanel` in `NetworkArtifact.tsx:449`, which prints
`expires 2026-08-31` for a DTLS certificate — `RTCCertificate.expires` defaults
to about thirty days out, so the answer changes inside the life of a single
debugging session.

**There is already a shipped, tested answer.** `GpgKeyBinder.tsx` exports
`expiryNote(expires, now)`, which returns `null` outside thirty days, then
`expires in N days` at `warn`, then `error` inside seven, then `expired`. Its
own comment states the discipline that makes it right: *"Only speaks up inside
a month. A key expiring in a year is not news, and a warning shown on every
row would train people to ignore the one that counts."*

Two cards do not use it. That is tier 1, no metadata, no timer, and the
function is already under test.

### §48c Network values speak in the present tense about the past

`ConnStateStrip`, `PairMatrix`, `SessionPanel` and `QualityStats` all render a
snapshot as though it were current — `succeeded`, `connected`, `3/4
connected`. Every one is the state of a `RTCPeerConnection` *at the moment the
op ran*, and nothing on the artifact says when that was.

Verified: `netValue(type, data, filename, meta)` (`rtc-ops.js:77`) stamps
`sensitive` and `filename` and nothing temporal, and no `rtc.*` op adds one —
a repo grep for `capturedAt` / `takenAt` / `observedAt` finds zero hits.

This is the artifact type where "live" is most tempting and where §47a bites
hardest. A card that re-queried the connection would be computing a new value
(and may find the connection closed, so the *artifact* and the *card* would
disagree about a fact the receipt digested). What is honest, and is tier 1, is
to say **how old the reading is**: `captured 4m ago` beside a `connected` badge
turns a false present tense into a true past one, and costs one trait and one
line per panel.

### §48d The best card in the codebase is behind a fifteen-second gate

`JwtArtifact` is the most complete read-out here: verdict, claim table with
registered claims in RFC order, a draining bar, `exp`/`nbf` tones that are
withheld when the signature was not checked (*"Green on a claim nobody checked
is the widget agreeing with the attacker"*). It is tier 2 and correctly so.

Measured: `jose.sign` emits `sensitive: true`.

```
'{"sub":"me"}' | jose.sign key=@k | out @t
→ role "token", tags ["jose","jws"], sensitive: true, kind "jose-token"
```

So on a real run the tile is masked, `jose-token` declares no `publicView`, and
the reader sees `sensitive — value not shown` + **Reveal**. After revealing,
`OutputList`'s list-wide 15s auto-hide re-masks it.

**This is recorded, not proposed.** It is *correct* under §34b: every fact on
that card is decoded from the token, so it derives from the masked material,
and a `publicView` here would be a hole in the mask rather than the disciplined
exception `keypair-private` and `share` earn. The friction is real — a token
you are debugging is read for minutes, not glanced at — but the honest fix is
to the reveal *timer*, which is list-scoped, shared with shares and private
keys, and out of scope for a card design. Naming it here so the next person
does not "fix" it by adding a `publicView`.

One incidental note from the same reading: `ArtifactTile` computes
`kindBody = renderKindView(resolvedKind, a, false)` unconditionally and
discards it when masked. Harmless — a view returns an element rather than
mounting one, so no hooks run and no timer starts — but it means the full view
function executes for every masked tile. Worth knowing before anyone puts work
in a view body.

### §48e The `otpauth://` URI has no card, and it is the generator

`otp.uri` emits `role: "secret"`, `tags: ["otpauth-uri"]`, `sensitive: true`
— measured — so it lands on the `secret` kind, which has no view by design. A
masked tile that says nothing.

Three of these side by side are indistinguishable, and the question a reader
has of one is *which account does this enrol*. That is public: `otp-ops.js`'s
own header says so in as many words — *"the URI **is** the secret, plus a
label"* — and `parseOtpauthUri` already separates `issuer` / `account` /
`period` / `digits` from `secret`. Drawing the label while the secret stays
masked is exactly the §34b move `share` and `keypair-private` already make.

This matters more than a small card, because **this artifact is the thing the
user's "manager" intuition is reaching for.** See §49.

---

## §49 The decision: object, representation, projection

> *"maybe this is just a 'Representation' of the output and the output always
> remains the 'TOTP object'"*

**The framing is right, and it is already this codebase's model.** Three
layers, three rules:

| Layer | What it is | Rule |
| --- | --- | --- |
| **Pipeline value** | the object — for OTP: secret, mode, algorithm, digits, period, counter, label | type fixed at compile time, never varies; sensitive, because it holds the secret |
| **Card** | a *representation* of the object | may move with time; is not a pipeline value; nothing digests it |
| **Projection** | the representation pulled into the pipeline (`:code`) | a fixed artifact with a receipt digest, exactly as today |

This satisfies §49a completely: the pipeline type is known before the run and
never varies. Only the rendering moves, and a rendering is not a value.

It is also not a new idea here. `keypair` is an object, `:public` projects a
half, and nobody thinks a keypair "varies" because it can be projected two
ways. `shares` is an object with `:keys` / `:values` / `:items`.
`projectTypeForMember` (`recipe.js:805`) is exactly a member-name →
required-base table, so a `:code` selector requiring base `otp` invents no
grammar.

**So the model needs no argument. What it needs is a cost, and the cost is the
finding.** §49f–§49j are the recipe-language research; §49k is the verdict, which
is: *record the model, build the split at the tile layer now, and take the base
type when a second type needs it.* §49l–§49n are the earlier
manager-vs-live-step comparison, kept as background because the reasons the
manager loses are the reasons the object model is the thing that replaces it.

### §49a The hard constraint, stated first

> **A live artifact may vary its value. It may never vary its type.**

This is binding, not a consideration. `inferSourceType` / `matchOverload` drive
fit-filtering in the ops drawer, compile-time errors, chip underlining and
`cellErrorsForChains`; all of them compute the output type **before** the run.
The session's own defect log is the argument: `ssh.encode format=private`
declaring `ssh-public` while emitting a private block, and `genkey aes/256`
declaring `keypair` while producing one symmetric key, were bugs *precisely
because a declared type is a promise*. A mechanism that varied its output type
would make that failure a feature.

**Step-as-live satisfies this structurally.** The type comes from the recipe,
the recipe did not change, so nothing has to be maintained.

**Artifact-as-manager would have to pin its type explicitly, and nothing in the
codebase enforces such a pin today.** It is a new unenforced invariant, and
this session is a long argument about what happens to those.

**Verified: the rule has exactly one shipped exception, and it is a latent bug
rather than a carve-out worth reusing.** `file.read` declares `bytes` under the
default `as=auto` — in both `types.js:457` and its `effectiveIo`
(`registry.js:2948`), with matching comments calling the declaration "the
conservative one". At run time `execFileRead` (`file-ops.js:148`) returns
`type: "text"` whenever `fileLooksTextual(mime, name)`, which matches `.pem`,
`.asc`, `.json`, `.txt` and more. The declaration and the runtime disagree.

That would be tolerable if `bytes` were the permissive top type. It is not —
measured:

```
"hello" | stream.seal key=@k   →  error: Type mismatch: "stream.seal" expects bytes, got text.
file.read accept=.pem | base64 →  errors: []          ← compiles clean
```

and `base64` throws `"base64 expects bytes"` at run time (`engine.js:1030`) —
no coercion anywhere. So `file.read accept=.pem | base64` is a **compile-clean
recipe that fails at run time solely because the declared type and the produced
type diverge.** The op's remedy is for the author to write `as=text`, which the
docs' own example does (`RECIPE.md:333`) — but nothing makes them.

Do not reuse this as precedent. §53 files it as its own unit.

### §49f Recipe-language impact — what a new base type touches

Measured by tracing an existing one end to end. `connstate` was chosen because
it is the most recently added and the smallest.

| Edit | Where | Note |
| --- | --- | --- |
| the `IoType` union | `registry.js:26` | one word |
| a `TYPE_META` entry | `type-registry.js` | base, label, summary, doc, `ref` |
| reading order | `type-registry.js` `listTypes()` | else it lands in the tail |
| role projection | `types.js` `artifactMetaFromType` (~L1740) | which artifact role an `otp` value becomes |
| op signatures | `types.js` `sourceTypeFor` / `resolveStepType` | all four `otp.*` ops |
| selector | `recipe-parse.js` `SELECTOR_MEMBERS` + `recipe.js` `projectTypeForMember` | a branch each |
| materialisation | `engine.js` `materializeOutArtifacts` | a per-type `if` chain — a new type needs a branch or `out @tok` writes the wrong thing |
| sensitivity | `engine.js` `pipelineValueIsSensitive` | an `otp` object must always be sensitive |
| the kind | `artifact-kinds/registry.tsx` + a glyph decision | |
| the verb catalog | `recipe-verbs.test.js` | **a gate**: every op and every enum value must appear |

**The good news, and it is real: a base type is not exotic here.** The union
already carries 24 members and eleven of them (`host`, `endpoint`, `candidate`,
`sdp`, `certificate`, `session`, `channel`, `peer`, `connstate`, `stats`, plus
`item`) were added by later capabilities. The type browser and the
producers/consumers lists are **derived** — from `listTypes()` and from STEPS —
so neither needs touching. This is a well-worn path.

**What is free.** Nothing about the base type threatens §49a. `otp` would be
declared by its constructor and consumed by its projection, both statically.

### §49g What happens to the four shipped `otp.*` ops

This is where the cost actually is, and it is larger than the type.

Today all four are text-in/text-out, and that is the whole grammar of the
toolbox: `random 20 | base32` → `text`, `otp.uri` → `text`, `otp.code` → `text`.

| Op | Today | Under the object model | Cost |
| --- | --- | --- | --- |
| `otp.uri` | `text\|bytes → text` (build the URI) | **encode**: `otp → text` | signature change; every template's stem changes |
| `otp.parse` | `text → text`, one field via `field=` | **decode**: `text → otp` | **meaning change** — a migration, not an edit |
| `otp.code` | `text → text`, takes `at=` | see below | the crux |
| `otp.verify` | `text → bool`, secret from a slot | `otp` in the slot rather than text | mostly mechanical |

`otp.uri` / `otp.parse` becoming a genuine encode/decode conjugate pair is a
clear improvement — the registry already has `conjugate` / `conjugateOf` and
`pairLabels` for exactly this shape, and today the pair is asymmetric in a way
that reads as an accident.

**But `otp.parse`'s current job has to go somewhere**, and the shipped
`otp-read-uri` template calls it four times (`otp.parse issuer`,
`account`, `algorithm`, `digits`). Under the object model those become field
access on an object — which is what selectors are. That means
`SELECTOR_MEMBERS`, today a closed set of **seven**, grows by up to eight
(`code`, `issuer`, `account`, `algorithm`, `digits`, `period`, `counter`,
`mode`) — **more than doubling it**, and `:key` / `:value` already mean
something else (an `item`'s halves). A closed vocabulary that doubles for one
type is the signal that the type is being made to carry a general mechanism.

### §49h Is `:code` the right spelling? Yes — but it cannot carry `at=`

`:code` fits the grammar exactly: `canonicalSelectorMember` lowercases and
strips the prefix, `SELECTOR_MEMBERS` gates it, `projectTypeForMember` adds a
branch requiring `current.base === "otp"` and returning
`typeOf("text", { kind: "opaque" })`. Nothing is invented and the spelling
matches `:public` / `:items`.

**The constraint that decides the design: a selector takes no parameters.**
`:public` has none, and the parser builds `{ name: "select", params: { selector } }`
with nowhere to put a kwarg. So `:code` can only ever mean *the code now*, and
`at=` — which must still pin (§49i) — cannot ride on it.

That leaves three options, and none is clean:

1. **`:code` for now, `otp.code at=` for pinned.** Two spellings for one
   projection. This codebase refuses that on principle and is right to.
2. **Pin the object instead** — `otp.at 1700000000` yields a pinned `otp`, and
   `:code` reads it. Elegant, and it puts the pinning intent *on the object*,
   which is where the card can see it by construction. But it is a **new fifth
   op** and a redefinition of `otp.code at=`, so a migration on top of a
   migration.
3. **No selector; `otp.code` stays the projection op.** Which is what ships
   today.

Option 3 is what ships today. That is not an accident — it is the shape the
constraint forces, and it is worth saying plainly: **`otp.code` already *is*
the projection.** What it lacks is not a better spelling; it is an *object* on
its left-hand side, and an object with a card.

### §49i `at=` still pins — and the answer is tidier under this model

Under the object model the answer is clean, and it is better than a policy
field: **`at=` is a property of the projection, never of the object.** An
object has no instant; a projection does. So the pinned instant is recorded on
the *projection artifact*, which is exactly `traits.otpPinnedAt` (§50b), and an
object's card always ticks because there is nothing on an object for it to
honour.

**This means §53 unit 1 is forward-compatible rather than throwaway.** The
trait it adds is the same trait the object model would want, recorded in the
same place, for the same reason. Build it either way.

### §49j Migration, stated honestly

Retired names are removed, not aliased — `migrateRecipe` rewrites them. A
change to `otp.parse`'s *meaning* is worse than a rename, because the old
spelling still parses and would silently mean something new. That needs a real
migration entry in `step-names.js`, and it touches:

- **four shipped presets** (`otp-enrol`, `otp-read-uri`, `otp-hotp-counter`,
  `otp-parameters`), every one of which is a template a new user clicks first;
- **`otp-presets.test.js`**, which asserts those templates *run*, not merely
  parse — deliberately, and the assertions include the security one (the URI
  arrives masked);
- **`otp-code-kind.test.js`**, whose whole subject is that a code's role is
  `text` and its facts ride `traits`;
- **`recipe-verbs.test.js`**, a gate demanding every op and enum value appear
  in the verb smoke catalog.

### §49k Verdict

**Record the model. Do not build the base type now. Build the representation
split at the tile layer, which delivers the same separation for the cost of one
kind, and take the base type when a second type needs it.**

Three things decide it.

**1. The generalisation does not hold up — checked, and it is the strongest
argument.** Which other artifacts are objects with representations?

| Candidate | Object? | Representation that moves? | Already has the split? |
| --- | --- | --- | --- |
| `keypair` | yes | no — a public half is fixed | **yes**, `:public` |
| `shares` | yes | no | **yes**, `:keys` / `:values` / `:items` |
| `certificate` | yes | "valid now" — but tier 1, resolution *days* | n/a — the expiry is already on the artifact |
| `session` / `connstate` | the object is a live handle, not data | yes, but it cannot be an artifact | observe-only by design |
| `otp` | yes | **yes, at 30-second resolution** | **no** |

So the object/projection model is **already built and already applied twice**.
What OTP would add is not the model — it is a *live* representation, and OTP is
the only type in the registry that wants one. The two candidates with
time-varying representations are a certificate (which needs tier 1 and no
object model at all, §53 unit 2) and a connection (whose object is a handle
that cannot be an artifact, §49n).

A base type, four op signature changes, a doubled selector vocabulary and a
four-template migration, to give **one** card a rolling code, is over-built for
one case.

**2. The live card is coherent but is not free of consequence.** The §37a
objection does dissolve — a card computing a *display* is not producing an
artifact, and `g(secret, now)` is the same shape of computation as the
countdown's `f(otpStep, now)`. Two consequences survive and both are real:

- **The secret would move onto the artifact record.** Today `OTP_META_TRAITS`
  provably excludes it — measured, the traits are exactly
  `{otpMode, otpDigits, otpPeriod, otpStep, otpExpiresIn}`. Under this model the
  `otp` artifact must carry the secret so the card can render, which puts a
  credential into `cellOutputs`, both `ToolkitShell` mappings, the tray, the
  Sheet, Copy and Download. Not unprecedented — a private-key artifact already
  carries a private key, and `activity-log.js` stores only a 16-hex digest of
  content, checked — but it is a new credential at the seam this session has
  broken four times.
- **§34b would need rewriting, not applying.** An `otp` object is sensitive, so
  its tile masks, so the live card must be a `publicView` — and §34b says a
  masked tile may render only what does **not** derive from the masked
  material. A rolling code derives from the secret directly. The SSH-private
  analogy does not hold: that card's three facts come off the *public blob the
  container carries*, which is why it is mechanically safe. This would be the
  first deliberate exception, turning a bright line into a line with an
  argument attached. Defensible — codes exist to be read, and `otp-ops.js`
  already marks them not-sensitive — but it is a change to a load-bearing rule
  and should be made deliberately, not as a side effect of a card.

**3. The feature shipped eight hours ago** (`74fdf3d`, `51a8cb1`). Migrating a
four-op toolbox and four templates on that timescale is how a half-migration
happens.

**What to build instead, now:** §53 unit 4 — the enrolment gets a card and the
code names its enrolment. That is the object/representation separation
expressed where it is visible, using the `keypair` precedent verbatim, for one
kind and one `publicView`. It leaves every door in §49f–§49j open and closes
none.

**What would change the verdict:** a second type wanting a live representation,
or `otp.parse`'s field access becoming painful enough on its own to justify the
conjugate-pair rewrite. Either makes the base type pay for itself; neither is
true today.

### §49l Background — why artifact-as-manager loses

**1. The manager must hold the secret. Confirmed, and there is no way around
it.** The code artifact carries exactly seven traits — `OTP_META_TRAITS`
(`engine.js:4244`): `otpMode`, `otpDigits`, `otpPeriod`, `otpStep`,
`otpExpiresIn`, `otpCounter`, `otpLabel`. Measured on a real run, the traits
are exactly `{otpMode, otpDigits, otpPeriod, otpStep, otpExpiresIn}`. No
secret.

That is not an oversight to correct. TOTP is `HMAC(secret, ⌊t/period⌋)`
truncated — computing the *next* code requires the shared secret, by
construction. `otpStep` and `otpPeriod` are enough to know *when* a code stops
being current, which is exactly why the countdown works from public facts and
is the whole reason `OtpCodeCard` is honest. **There is no refresh without the
secret**, so the objection does not dissolve; it is arithmetic.

A manager could instead hold a *reference* to the slot the secret lives in.
That is worse, not better: it is the same stale-reference fork §50 rejects, one
level down, and slots are mutable — a later cell writing `@secret` would
silently change what a card in an earlier cell produces. That is the
cross-cell-mutation defect class (`49cd286`) with a credential in it.

**2. It breaks the receipt.** `digestArtifact` (`receipt.js:164`) digests
`label`, `filename`, `role`, `stepName`, `sensitive`, `length` and the SHA-256
of `content`. An artifact that keeps producing new `content` drifts from what
was digested the moment it refreshes, and `run.verify` compares digests.

**3. §37a.** A manager computing outputs is computing outside the recipe: a
value with no step behind it, nothing in the receipt describing it, and no way
for `basilisk run` to reproduce it.

### §49m Background — why step-as-live is also not the answer

Making *live* a property of the step — a cell that re-runs on a timer — is the
better of the two mechanisms and it is still the wrong thing to build now. It
satisfies §49a for free and keeps the secret in its slot. Its costs, checked:

- **It collides head-on with the approval model.** `ConsequenceBanner`'s
  absences *are* its design (§43b): no session grant, no per-run batch. A cell
  that re-runs every thirty seconds either needs a standing grant — the exact
  thing that was deliberately removed — or raises a banner twice a minute.
  This is the decisive one. Auto-re-running is a standing grant wearing a
  timer.
- **It makes its notebook unverifiable, structurally.** `run.verify` re-runs
  and compares digests. A recipe with a live cell can never match.

  Worth noticing what this reveals: **`at=` is already the verifiability
  switch.** `otp.code` without `at=` is *already* unverifiable — two runs
  thirty seconds apart digest differently. `otp.code at=1700000000` is
  reproducible forever, measured: two runs, both `128534`. Live-vs-pinned is
  not a UI distinction someone invented; it is the reproducibility boundary of
  the recipe, and the tile should say which side of it you are standing on.
  §53 unit 1 is that sentence.
- **Timer ownership and the background tab.** `setInterval` is throttled to
  roughly one call per minute in a backgrounded tab, so a 30s refresh silently
  becomes a 60s one and the card is wrong in the one state where nobody is
  looking to notice. Nothing in `web/src/` reads `visibilityState` today — a
  repo grep finds zero hits outside tests — so this would be new machinery.
- **What happens to prior artifacts.** Measured: outputs are *replaced*, not
  appended — two `Run all` clicks leave one tile. So a live cell would not grow
  the list, and the Activity log is written by `recordActivity` on *actions*,
  not runs, so it would not fill either. Those two costs are smaller than
  feared; the two above are not.
- **Editing under a running timer.** Cells are editable while the notebook
  runs. A timer re-running a cell mid-edit is the ambient-current-cell hazard
  again.

### §49n Where both models were reaching, and the line that survives

Both models reach past something the recipe language already has — which is
§49's answer, arrived at from the other end. `:public` projects a keypair into
a half; **`otp.code` is exactly that step for an enrolment.** The generator and
the projection are already two values, already correctly typed, already
correctly marked (the URI sensitive, the code not). The language is not missing
a word.

What is missing is at the *tile* layer, and it is one-sided. For `genkey`, both
halves have an identity: `keypair-public`, `keypair-private`, and the `keypair`
tile whose entire job is to say *I hold both, here is what I can show you, and
here is the recipe edit that gets you the rest*. For OTP, the projection has a
rich card and **the generator has no card at all** (§48e). That asymmetry is
what makes the code tile feel like it ought to be doing the generator's job.

So both roads end at the same place: **apply the `keypair` precedent to OTP**
(§53 unit 4), which is the object/representation split expressed where it is
visible.

What none of the three gives, stated plainly rather than argued away: **a code
that refreshes itself.** The object model *could*, at the cost in §49k; neither
of the other two can at any cost, because the refresh needs the secret and the
value needs a step. Until the base type pays for itself, the mechanism that
produces the next code with a real derivation, a real receipt and a real type is
*re-running the cell* — one click, which the tile already says in words. Making
that sentence **correct** (§52 D1) is the work.

**The reasoned exception, since one was asked for.** If any type earned
artifact-as-manager it would be `network-value` — the generator is an
`RTCPeerConnection` that genuinely exists in the session, re-querying needs no
credential, and the secret objection does not apply. It still loses, on a
different ground: the artifact would have to hold a live, unserializable handle
it would then keep alive, and a card that re-queried a *closed* connection
would show `closed` where the receipt digested `connected` — the two would
disagree about a fact that was recorded. That is also why it is not a second
customer for the base type (§49k): its object cannot *be* an artifact. The
honest half of the impulse is tier 1 and is §48c: say how old the reading is.

The line that falls out of all of it, and the one worth keeping:

> **A record is a tile. A monitor is a panel.** The notebook already has both
> surfaces; the Connections tray is where a genuinely live view of a
> connection belongs, and nothing there has to pretend to be an artifact.

---

## §50 Where the intent gets recorded

### §50a The fork, and the answer

Record the intent as **metadata on the artifact**. Do not give the artifact a
reference to the step that made it. Four reasons, checked rather than assumed.

**1. The reference is not available, and getting it means crossing the seam.**
There are three hops between an engine artifact and a tile, each an explicit
field list. Verified at `HEAD`: `stepName` is on `ArtifactTile`
(`notebook-types.ts:92`) and **neither** `ToolkitShell` mapping copies it —
grep `<OutputList` finds two, at the cell list and the tray Outputs tab, and
`stepName` appears in neither. `stepIndex` does not exist at hop 2 at all.
Adding a reference means editing all three lists, in the seam HANDOFF records
as having produced four separate defects.

**2. A reference goes stale.** Recipes are editable after a run; move a chip
and an index points elsewhere. `49cd286` is the same class.

**3. Traits are receipt-neutral. Roles are not. Measured, and this is the
decisive one.** `digestArtifact` (`receipt.js:164`) reads exactly `label`,
`filename`, `role`, `stepName`, `sensitive`, `length`, and the digest of
`content`. **`traits` and `tags` are not digested.** A real receipt, printed
from a run:

```
{"digest":"4154fc48…","filename":"c.txt","label":"c","length":6,
 "role":"text","sensitive":false,"stepName":"out"}
```

So adding a trait changes no digest and needs no `RECEIPT_VERSION` bump. Adding
a *role* would — that is precisely why v1→v2 happened (§38c). The mechanism, not
the convention, is why metadata belongs in `traits`.

**The same measurement rules out the other tempting place.** Putting a capture
timestamp inside `netData` would be cheaper — `netData` is copied wholesale by
both hops — but for a network value `content` **is** the serialized payload, so
a timestamp in it would change the digest on every run and make every network
artifact permanently unverifiable by `run.verify`. `traits`, not the payload.

**4. The op already knows at emit time.** `secondsFrom(params)`
(`otp-ops.js:51`) reads `params.at` and collapses it: `at === 0 ? Date.now()/1000
: at`. The distinction exists for one line and is then thrown away.

**No exception was found.** Every case that looked like it wanted a step
reference wanted a fact the step already had.

### §50b The concrete shape: per-type, not a general policy

**Proposed, for OTP:**

```js
// otp-ops.js, in execOtpCode's meta, TOTP branch only:
...(pinnedAt ? { otpPinnedAt: pinnedAt } : {}),
// where  const pinnedAt = Number(params?.at ?? 0) || null;
```

and one line added to `OTP_META_TRAITS` (`engine.js:4244`), which is a frozen
allowlist and is the only other place it must be named. **Two lines, one
commit.** Compare with a step reference: three type/field lists plus two
`ToolkitShell` mappings, five edits in the seam that has broken four times.

Sparse on purpose, matching the bag's existing habit — `otpCounter` is present
only for HOTP. Absent means "the recipe meant now", which is both the common
case and the current meaning of an absent field, so no migration.

**Proposed, for network values:**

```js
// rtc-ops.js netValue(): traits.capturedAt = Date.now()
```

carried on `traits`, for the digest reason in §50a(3).

**Rejected: a general `traits.livePolicy`.** Two producers is not a mechanism,
and the two facts are not the same fact — one says *the recipe pinned this
instant*, the other says *the run observed at this instant*. Collapsing them
into one field would require every reader to know which meaning it carried,
which is the union type that a general mechanism nobody else uses always turns
into. If a third and fourth producer appear and all four want the same
question answered, that is when the shape is knowable; naming it now would be
naming it from two examples.

What *is* general, and is free, is the **rule**:

> **A card may tick only against an instant the recipe did not choose.** If the
> recipe named the instant, the card states it. If the recipe meant *now*, the
> run fixed an instant and the card may count from it.

That covers both producers and any future one, and it is a sentence rather than
a field.

---

## §51 What a live card owes the receipt, the tray and a reload

### §51a Divergence: what the tile shows when now and then disagree

The digest never moves, because `content` never moves — verified in the built
page: a pinned code read `128534` before and after a second `Run all`, and Copy
copies the same string throughout. So there is nothing to reconcile in the
digest. What has to be honest is the *sentence*.

The rule for any live card, stated so it can be applied without re-deriving it:

1. **The value stays put, always, and at full weight.** The digits do not grey
   out, move, or shrink when they expire. They are what the receipt covers.
2. **The live element states which of the two it is describing.** "expired" is
   about the *step*, not the code, and the card must say so — which
   `OtpCodeCard` already does: *"It is still the value this cell produced."*
3. **When they diverge, the card says what to do about it — and the instruction
   must be true.** This is the clause D1 breaks: it tells a pinned code's
   reader to re-run, and re-running is a no-op.

### §51b A reloaded notebook: measured, and the question does not arise

An artifact restored from a share link would have no live run behind it — but
**there is no such artifact.** Measured in the built page: after a run, reload;
the recipe is restored from `#r=` and `document.querySelectorAll('[data-artifact-kind]').length`
is **0**. `localStorage` and `sessionStorage` are both empty. `RECIPE.md:155`
states the policy that produces this: outputs are never persisted, in the
library or the export file.

So a live card's lifetime is bounded by the tab session, every ticking card has
a real run behind it, and there is no zombie state to design for. **Do not add
one.** If artifacts ever are persisted, this section is the thing to re-read
first: a restored OTP tile would be permanently expired and would be telling
the truth.

### §51c The tray mounts a second copy — measured

`ToolkitShell` renders `<OutputList>` twice, and both mappings copy `traits`
wholesale. Measured with the tray's Outputs tab open on a live OTP run:
`document.querySelectorAll('[data-otp-card]').length` is **2**, both showing
the same code and the same countdown.

So the real timer count is `mounted cards × panes`, and the Sheet makes three
for an expanded row. Not a defect — two panes showing one artifact consistently
is correct — but it is the number to reason with.

### §51d Timers: ownership, cost, and why not to build a shared clock

**Ownership.** The card owns it. `OtpCodeCard` and `JwtArtifact` each hold a
`setInterval(…, 1000)` in a `useEffect` whose cleanup is `clearInterval`, so
unmount stops it. That is correct and needs no change.

**Cost, measured.** With a `MutationObserver` on a live OTP tile over 4s:

| Scope | Mutations / 4s | Node changes / 4s |
| --- | --- | --- |
| The tile itself | **13** | 13 |
| Whole document | 469 | 2689 |

≈3 mutations per tick inside the tile — the seconds text, the bar's
`data-otp-fill` bucket, the tone attribute — and nothing outside it. Six OTP
artifacts in one cell, doubled by the tray, is ~36 mutations per second of
attribute and text writes with no layout thrash. **That is not a performance
problem and should not be optimised.**

(The 469 document-wide figure is **not** the card. Attributing it by mutation
target: 171 + 108 + 54 land on `svg > g` inside `.ops-icon-grid` and a toolbar
button — glyph animation in the ops shelf, unrelated to artifacts and owned by
another agent's area. Noted so nobody attributes it to a card.)

**Do not build a shared clock.** A single app-wide 1 Hz tick feeding every card
would centralise a cost that measures at three DOM writes and would couple
every live card to one provider — and the two existing cards already accept an
injected `nowMs` for tests and the catalog, which is the seam that actually
mattered. Revisit only if a measurement, not an intuition, says otherwise.

---

## §52 Defects found while looking

Reproducible at `a0a81c1`. **D1, D2 and D4 are in the shipped app.**

### D1 — A pinned OTP code tells you to do something that cannot work

**Severity: highest, because the card's only instruction is false.**

Driven in the built app at `/toolkit`:

```
"JBSWY3DPEHPK3PXP" | utf8 | otp.code at=1700000000 | out @pinned
```

renders:

> **128 534**  expired
> This was the code for the 30s step ending 2023-11-14T22:13:30Z. It is still
> the value this cell produced — **run the cell again for the current one.**

Clicking *Run all* again produces `128534`. Forever. `at=` pins the instant, so
the instruction is not merely unhelpful, it is the one thing guaranteed not to
work.

**Root cause, verified in the engine.** `execOtpCode`'s meta is byte-identical
in shape for both cases — there is no field that distinguishes them:

```
otp.code            → traits {otpMode:"totp", otpDigits:6, otpPeriod:30, otpStep:"59520188", otpExpiresIn:23}
otp.code at=1700000000 → traits {otpMode:"totp", otpDigits:6, otpPeriod:30, otpStep:"56666666", otpExpiresIn:10}
```

`secondsFrom` collapses `at=0 → now` and the provenance is discarded. The card
is doing the only thing it can with what it was given. Fix is §53 unit 1.

### D2 — `inspect | out @x` silently loses its card

The `inspect-snapshot` kind matches `role: "inspect"`. Naming the output drops
the role, the tag **and** `inspectSnapshot`. Same body, two kinds:

```
"hello" | utf8 | inspect          → role "inspect", tags ["inspect","opaque"], kind inspect-snapshot
"hello" | utf8 | inspect | out @i → role "text",    tags ["opaque"],           kind text
```

The `out` path (`engine.js`'s `materializeOutArtifacts`) does not check
`value.meta.inspect`, which only the bare-text-tip branch at `engine.js:4835`
does. A sensitive value degrades further — to `role: "secret"`. `peek` is
unaffected (it pushes `role: "inspect"` directly).

Not a documented example — `RECIPE.md` shows `inspect` as a tip and `peek` for
side snapshots — but it is the natural thing to write, and it fails by
producing a worse tile rather than an error.

### D3 — The catalog's OTP row can only ever show *expired*

`toolkit-widgets.tsx:2393` hard-codes `otpStep: "59520075"`, which was the
current step when the fixture was written. `(59520075 + 1) × 30` is
2026-08-01T16:38:00Z, so the row on the design surface reads **expired** and
will for the life of the repo — measured at 17:32Z the same day. The one
section that exists to show the live countdown can never show it.

Deriving the fixture from `Date.now()` is the obvious fix and is *wrong*: the
catalog needs to show both states deliberately. Two rows, one pinned to an
injected `nowMs` mid-step and one to an expired step, is the fix — the card
already accepts `nowMs` for exactly this.

### D4 — The QR is too small to scan, and Expand does not help

Measured on `#artifacttiles`:

| | |
| --- | --- |
| Intrinsic SVG | 95 × 95 |
| Rendered `<img>` | **103 × 103** CSS px (95 + 4px padding each side) |
| Class cap | `max-h-40 max-w-40` — 160px, never reached |
| In the Sheet, 560px wide | **103 × 103** — identical |
| `devicePixelRatio` | 1.5 |

A 95-module code across 95 CSS pixels is **one CSS pixel per module**. Practical
phone scanning wants three to four device pixels per module; this is under two.
The one artifact whose entire purpose is to be read by a camera is rendered at
roughly half the size that works, and the affordance that exists to give an
artifact room — Expand, which this row *does* offer, because 12,618 characters
of SVG clears the size threshold — changes nothing, because the intrinsic
size wins and 160px is a maximum rather than a target.

### D5 — Expiry dates carry no verdict

§48b, in two places: `OpenPgpKeyCard` and `NetworkArtifact`'s
`CertificatePanel`. `expiryNote` exists, is exported, and is tested.

### D6 — Two tables render unbounded

Measured: `[data-recipients-card]` has `max-height: none` and
`overflow-y: visible`, at **16px per row**. `hkp.search` on a real keyserver
returns tens of rows; forty is 640px of table inside one output row, with no
cap, no scroll and no filter. `ReceiptCard`'s digest table is the same shape at
the same 16px, one row per output across every cell.

Latent rather than live — this build's directory is local and lists are short
— but it is the case the brief's "filtering or search is interaction that
computes nothing new" was pointing at, and by §47c a filter is permitted.

### D7 — Five kinds have no row on the design surface

Enumerated from the built page by `data-artifact-kind`: `#artifacttiles` and
`#keyartifacts` between them render 19 kinds. Missing: **`key`,
`public-key`, `network-value`, `inspect-snapshot`, `jose-token`.**

`network-value` and `jose-token` have sections of their own (`#networkartifact`,
`#jwtartifact`) but those mount the widget **bare**, not inside a tile — so the
tile-level interactions have never been seen for either. §48d's masking finding
is exactly what that gap hides: it is invisible in the section that renders the
card directly.

`artifact-kinds-table.test.js` gates that every *role* is claimed by a kind. No
gate says every *kind* is rendered on the catalog. That is the gate this
session's traps argue for.

### D8 — `file.read as=auto` breaks the type promise

§49a, in full, with the compile-clean failing recipe. Filed separately because
it is the recipe layer rather than a card, and because it is the one existing
counter-example to the invariant §49a states.

---

## §53 What is worth building

Ordered by (question answered) × (how often it is asked) ÷ cost. Units 1–5 are
the recommendation; 6–8 are real and smaller.

### Unit 1 — A pinned code says it is pinned, and stops giving false advice
**Fixes D1. Cost: two engine lines, one card branch.**

- `otp-ops.js`: `const pinnedAt = Number(params?.at ?? 0) || null;` and
  `...(pinnedAt ? { otpPinnedAt: pinnedAt } : {})` in the TOTP branch of
  `execOtpCode`'s meta.
- `engine.js`: `"otpPinnedAt"` added to `OTP_META_TRAITS`.
- `artifact-readouts.js`: `otpCodeReadout` returns `pinnedAt`.
- `OtpCodeCard`: when `pinnedAt` is set, **do not tick and do not draw the
  bar.** Neither is meaningful — the reader did not ask for a code to type,
  they asked for the code at an instant. Show the instant, and the fact that
  makes a pinned code worth having:

  > **128 534** · pinned
  > The code for the 30s step at `2023-11-14T22:13:20Z`. Pinned by `at=`, so
  > every run of this recipe produces it.

  That last clause is the useful one and it is what `at=` is *for* (§49m): a
  pinned code is the reproducible, `run.verify`-able case, and the live one is
  not.

**Acceptance.** `runRecipe` on `otp.code at=1700000000` carries
`traits.otpPinnedAt === 1700000000`; on `otp.code` the key is absent. In the
built page, the pinned tile contains neither "expired" nor "run the cell
again", holds no interval (patch `setInterval` before mount and assert zero),
and the live tile is unchanged. `traits` are not digested, so no receipt
version moves — assert that too, since it is the property the design rests on.

**Forward-compatible with §49.** Under the object model `at=` is a property of
the *projection*, never of the object (§49i), so this trait is recorded in the
same place for the same reason whichever way §49k later goes. It is not work
that a base type would undo.

### Unit 2 — Expiry dates get a verdict
**Fixes D5. Cost: two call sites, no new code, no metadata.** Tier 1.

- `OpenPgpKeyCard`: keep `created …`; render `expiryNote(expires)` beside it
  when it returns non-null, in its own severity tone. Silent outside 30 days,
  which is the existing discipline and the reason it is safe to add everywhere.
- `NetworkArtifact`'s `CertificatePanel`: the same, on `data.expires`.

**Acceptance.** A key expiring in 9 days shows `expires in 9 days` at `--warn`;
in 3 days, at `--error`; in a year, nothing beyond the date. Walk the
boundaries with an injected `now` rather than a fixture that rots (D3's
lesson). Measure the rendered text in the built page, not only in a unit test.

### Unit 3 — The QR is scannable, and Expand gives it room
**Fixes D4. Cost: one class, one Sheet branch.** No metadata, no new mechanism.

- Render the `<img>` at a target size rather than at its intrinsic one: a
  minimum edge that puts at least 3 device pixels on a module for a typical
  code, capped so it does not dominate a row.
- In the Sheet, let it take the available width. It is an SVG, so upscaling is
  exact; `image-rendering: pixelated` already keeps module edges hard.

**Acceptance.** Measured in the built page, the tile's QR is at least 3× its
module count in device pixels, and the Sheet's is larger than the tile's — the
current state fails both, at 1.5× and equal. State the module count the target
is computed against; a `quorum` share QR is denser than `"hello world"`.

### Unit 4 — The enrolment gets a card, and the code names its enrolment
**Fixes §48e. Delivers §49k — the separation the user asked for.**
**Cost: one kind, one `publicView`, one line on the OTP card.**

- A kind matching `role: "secret", tags: ["otpauth-uri"]` — a tag, at
  specificity 1, exactly as `otp-code` claims `text`; no new role, so
  `ARTIFACT_ROLES` and the receipt are untouched (§50a(3)).
- `sensitivity: "secret"`, no `view` — a revealed URI keeps the tile's own text
  path, its format bar and its auto-hide, which is `share`'s argument verbatim.
- A `publicView` drawing issuer, account, period and digits from
  `parseOtpauthUri`, never `secret`. §34b permits it because `otp-ops.js` itself
  draws that line: *"the URI is the secret, plus a label."*
- A line naming what it is and what projects it: the thing a phone scans, from
  which `otp.code` takes a code — the `keypair` tile's withheld-line move.
- On `OtpCodeCard`, where `otpLabel` is present, say the code is a projection of
  that enrolment rather than only labelling it.

**Acceptance.** Three enrolments in one cell are distinguishable **while
masked**. The `publicView` provably never touches `secret` — assert on a URI
whose `secret=` is a recognisable sentinel that the sentinel appears nowhere in
the rendered output while masked. `runRecipe` on `otp.uri` resolves to the new
kind, checked against the mapped `OutputArtifact` shape and not only the engine
one (HANDOFF's most expensive trap).

**Why this rather than the base type.** It is the *same* object/representation
split, drawn where it is visible, and it is the half of §49 that does not need
a fifth op, a doubled selector vocabulary or a four-template migration. If the
base type is built later, this kind is what `otp`'s tile becomes — the work is
where the model would have put it anyway.

### Unit 5 — Snapshots say how old they are
**Fixes D3's cousin and §48c. Cost: one trait, one shared component, N panels.**
Tier 1.

- `rtc-ops.js`'s `netValue()` stamps `traits.capturedAt = Date.now()`.
  **In `traits`, not in `data`** — `content` for a network value is the
  serialized payload, so a timestamp inside it would change the digest on every
  run and make every network artifact permanently unverifiable (§50a(3)).
- One age read-out on `network-value` and `diagnostic`: `captured 4m ago`,
  coarse. Under a minute it may say `just now`; it does not need seconds and
  therefore does not need a timer.

**Acceptance.** `traits.capturedAt` is present and `run.verify` still matches a
receipt across two runs of the same recipe — that second half is the point of
the unit and is the thing that would silently break if the timestamp went into
the payload. A `connstate` tile ten minutes old does not read as current.

### Unit 6 — `inspect | out @x` keeps its card
**Fixes D2.** `materializeOutArtifacts` should honour `value.meta.inspect` the
way the text-tip branch does — role `inspect`, the `inspect` tag, and
`inspectSnapshot` where the value is not sensitive. Engine-side, not a card.

### Unit 7 — Two tables get a ceiling and a filter
**Fixes D6.** A max height with scroll on both; a filter input on
`recipients` above some row count. §47c permits it — a filter changes what you
see and not what Copy copies. The receipt table wants the ceiling and not the
filter: it is read in `run.verify`'s order and re-ordering it would break the
one property it has.

### Unit 8 — The catalog gates its own coverage
**Fixes D3 and D7.** A test asserting every id in `ARTIFACT_KINDS` appears in
the catalog's tile sections, mirroring the role gate that already exists — and
the OTP fixture rebuilt as two rows with injected `nowMs`, mid-step and
expired, so the design surface shows both states on purpose instead of one by
accident.

### Filed, not scheduled

**D8 — `file.read as=auto`.** Recipe layer, not cards, and the fix is a real
design decision (make the runtime honour the declaration, or make `auto`
declare a union the checker understands, or refuse `auto` into strictly-typed
inputs). It is recorded here because §49a's invariant is stated as binding and
honesty requires naming its one existing counter-example — with the
compile-clean failing recipe, `file.read accept=.pem | base64`, so whoever
picks it up starts from a reproduction rather than a claim.
