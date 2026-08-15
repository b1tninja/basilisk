# Recipe language — design

`RECIPE.md` is the normative grammar as it stands. This is the argument for
what it should become, and why. It is meant to be disagreed with.

## What the language is for

A recipe is a cryptographic procedure that can be **read, shared, and delegated**
— run alone on one machine, or spread across a room where each cell runs on the
machine of whoever it names. Two properties follow from that and constrain
everything below:

- **The text is the agreement.** Both ends digest the recipe into a run manifest
  and compare it, so anything that changes what a recipe *means* has to be
  visible in the text. A default that is applied on parse and dropped on
  serialize is not visible.
- **It is read by people who did not write it.** A recipe arrives in a link or
  over a wire, and the reader has to be able to answer "what does this do, whose
  machine does it run on, and what leaves mine?" without learning an incantation.

## Principles

1. **One way to say each thing.** Multiplicity currently has five spellings —
   `foreach`, `tee` bodies, `at N`, slices, and a runtime binder nobody can see.
2. **Anything that leaves this machine is a verb.** Never a header modifier,
   never a decoration on naming. `out $x` names a value here; sending it
   somewhere must not look like a variant of that.
3. **Multiplicity belongs to values, not to syntax.** The type walk already
   distinguishes `{base:"shares"}` from `{base:"text"}`. The language should
   read that rather than make the author restate it.
4. **A security-relevant parameter is the verb's object, not an option.**
   Options get defaulted; defaults get dropped on serialize; a dropped default
   is absent from the text both ends compare.
5. **Input may be abbreviated; the canonical text is always complete.**
   Short to write, explicit once written down. These pull against each other
   only if the same form has to do both jobs.

Principle 4 is not theoretical. Today:

```text
random 32 | sss.split threshold=2 shares=3 | out $set
```

round-trips through `serializeRecipe` to `random 32 | sss.split | out $set`.
The quorum — the whole security property — is not in the text that travels, and
not in the manifest.

### The quorum as a fraction

The split is written `2/3` — two of three — as the verb's object:

```text
random 32 | split 2/3 | words | scatter
```

The threshold may be omitted, and then it is a **majority** of the shares:
`split 3` and `split 2/3` mean the same thing. Majority is not a rounding
convention: it is what makes any two qualifying sets intersect, so no two
disjoint groups can ever reconstruct the secret independently. Exactly half
would lose that — `2/4` lets two separate pairs each rebuild it without the
other knowing, which is a different security object from the one the word
quorum promises.

**The abbreviation is an input form only.** `split 3` is accepted and
*serializes* as `split 2/3`, by principle 5. A reader of a shared recipe never
has to know the majority rule to know what the recipe does, and the text both
ends digest states the quorum outright. This is the same shape as `@me`, which
is short to author and resolves to a whole fingerprint before it travels: the
language has an authoring form and a canonical form, and serialization is where
they converge.

Refusals the object makes easy to state:

- `1/3` — one share reconstructs, so it is a copy rather than a quorum.
  `ceremonyIssues` already refuses `threshold === 1` in those words.
- `4/3` — more needed than exist; unrecoverable by construction.
- `3/3` — legal, and worth saying out loud: no redundancy at all, and losing any
  share loses the secret. The default for a two-member room is `2/2`, which has
  the same property and is the most likely room there is.
- More than 16 shares — `sss.split` refuses it, and the room picker should say so
  by number rather than leaving it to compile time.

## The changes

### Disclosure is a step, not a header modifier — **done**

```text
# was
@ada publish=$a,$b
random 32 | sha256 | out $a

# is
@ada
random 32 | sha256 | out $a | publish
```

The header goes back to answering one question: *who runs this*. Publishing
happens where the value is. `publish=$a,$b` is gone, and with it the refusal
machinery that had to reconstruct which of a cell's outs a header was talking
about.

Shipped. `publish` binds to the `out` immediately before it and to nothing
else, which is what turns "what does this cell disclose" from a reconstruction
into a lookup — `publishedSlots` walks the steps, and it is the one answer the
planner, the handoff and the assign menu all take. `chain.publish` and
`chain.publishSlots` are gone from the AST; there is no second place the answer
could differ.

Three things fell out of it:

- **"Publishes nothing" stopped being spelled like "publishes everything."** On
  the header, an empty list *meant* all of them, so the assign menu could not
  offer to un-publish the last named slot without silently widening the cell to
  every `out` it writes — it had to refuse the click and explain why. The list
  is exactly what leaves now, and the refusal is gone with the hazard.
- **The handoff's withheld-value guard became reachable from the ordinary form
  of the language.** It could only fire on `publish=$a,$b`, so the commonest
  spelling — a bare `publish` — sat outside it.
- **The refusals name an edit rather than a header.** "Drop `publish` from this
  cell" was true of a modifier and ambiguous about a cell with three `out`s;
  it is "drop `publish` from after `out $share`".

The retired header still parses and is rewritten into steps on the way in, for
the reason `split 3` is accepted: a notebook travels as a `#r=` fragment, and a
link somebody mailed last week has to open into the notebook they meant. One
canonical text comes out either way, so the two spellings converge rather than
persisting as two dialects.

### Selectors are steps — **done**

`:public` → `public`. One fewer sigil; the type rule is unchanged. `:public`
already refuses anything that is not a keypair, and that refusal moves with it.

Shipped, for the two keypair halves and no further. A projection reads a member
out of a pipeline value and hands the result on, which is a verb's shape, so
`public` and `private` are verbs. Both spellings produce the one `select` step
and `serializeRecipe` writes the bare word, so they converge rather than living
side by side. The refusal is the same sentence it always was, because it is the
same predicate: `selector ":public" requires keypair, got text/mnemonic`.

Two things fell out, and one is the more interesting:

- **A branch prefix was a second spelling of a step.** `- :public | export spki`
  and `- public | export spki` mean the same thing, and since `e8473b5` the
  second already worked — a branch runs on a clone and its first step projects.
  So the prefix folds into the branch's body on parse, and there is one AST for
  the two texts rather than two that serialize differently.
- The projection is now an ordinary chip in the builder, which the branch × and
  the step × treat like any other. The step-delete cascade that exists so a
  delete can never hand back an uncompilable recipe therefore fires one removal
  later, because `- public` on its own **is** a recipe.

What stayed on a colon, deliberately: `:key` and `:value` project a member of
the *item* a `foreach :items` loop is holding, so a step named `value` would be
an error everywhere in the language except inside one mode of one loop; and
`:items` / `:keys` / `:values` are not projections at all but the loop's own
mode, written where the loop is declared. `[n]` keeps its brackets because `at`
is already the verb for it.

### A branch is a branch — **done**

```text
genkey ec/p256 | tee
  - private | inspect
  - public | export spki | pem | out $public
```

reads as two branches and *is* two branches — because both lines begin with a
selector. Without one, consecutive `-` lines used to concatenate into a single
body:

```text
$set | tee
  - at 1 | send to=@ada
  - at 2 | send to=@bea
```

became `at 1 | send to=@ada | at 2 | send to=@bea`, which then failed with a
type error about `at`. The documented example only showed the selector form, so
nothing revealed the rule. **Each `-` line is one branch, always.** This was
less a redesign than making the syntax mean what every reader already assumes.

Shipped. `parseBranchLineInto` puts every `-` line under a `tee` into
`branches`, selector or not; a branch without one runs on a clone of the whole
stem, which is what the single-line case always did and what the builder's
"+ branch — no selector" affordance always meant. Three things fell out of it:

- The count of `-` characters is the count of branches, including the mixed
  case. A `tee` holding both kinds used to keep them in two different places and
  `serializeRecipe` wrote all of one before all of the other, so
  `- :public | export spki` followed by `- out $x` came back with its lines
  **swapped** — a notebook that read differently after a round trip through a
  link than it did when it was written. Order is now source order, both ways.
- A branch of several steps is one line, joined with `|`, and the serializer
  writes it that way. There is no continuation marker, and deliberately so: a
  continuation would put back exactly the thing this removed — a line whose
  meaning you cannot settle without reading the next one.
- `foreach` does **not** fan out and never could: the loop threads each item's
  value through the body and hands the result back, so there is no second thing
  a second `-` line could be. Rather than glue two lines together in silence,
  it now refuses and names the join that works. One body, one line.

What is *not* done from the rest of this section's neighbourhood: elementwise
application, `scatter` / `gather`, and the vocabulary aliases. Each is its own
pass.

### Steps apply elementwise

A step that accepts text, handed a collection, applies to each element. A step
that accepts a collection gets it whole. Both facts are already declared in the
registry, so the rule is decidable from what exists.

```text
# now
random 32 | sss.split threshold=2 shares=3 | blip39 | foreach
  - out $share

# proposed
random 32 | split 2/3 | words | out $share
```

`foreach` stays as the explicit form. It stops being necessary.

Output types stay statically known: a collection of `T` is still a type, so the
determinism rule holds.

### `scatter` / `gather` are the room's plural

The room is a list and a split is a list, and the whole ceremony is the
correspondence between them. Stating it once, in a verb, replaces `deal`, `at N`
for distribution, per-item recipients, and indexing:

```text
@me
random 32 | split 2/3 | words | scatter

@*
gather | out $share
```

A dealer deals to the whole table, themselves included, so there is no
`at 1 | out $mine` special case and everyone's share lands in the same slot on
their own machine. "Mine" is the one that never crossed a wire.

`scatter` refuses a count mismatch by naming both numbers, and refuses a room
where any member is unverified — handing a share to a peer whose key
confirmation has not completed is the one mistake this ceremony cannot take back.

#### It is a zip, and the two lists are the shares and the room

Four separate pieces of work have blocked on one operation, and it is narrower
than "a map". `room-ceremony.js` writes the reason at the top of the file:
"`foreach` declares `params: []`, so there is no `to=` for it to change between
rounds; `tee`'s `-` lines concatenate a stem rather than branching to different
addressees." Neither of those is a missing higher-order function. What is
missing is **walking two same-length lists together** — N shares against N
members — and applying a step per pair. Sealing *one* share to *one* named
holder is expressible today; sealing the set is not, because `to=` cannot vary
per item.

So the shape is `foreach`'s, with a second list:

```text
@me
random 32 | split 2/3 | words | scatter
  - gpg.encrypt to=:key mode=combined | out $sealed | publish
```

One `-` line, one body, the rule the branch section already settled. The body
runs once per pair. `scatter`'s own job is to produce the pairs and nothing
else: it draws nothing, sends nothing, and encrypts nothing, so by principle 2
it is not the verb by which anything leaves — `publish` is, in the body, where a
reader can see it.

#### What fixes the order, and why two machines cannot disagree

Share *i* to holder *i* is a correspondence, and it has to be the same
correspondence on both machines. The thing to notice is that **the manifest
cannot check it.** `peersDigest` builds `{ fingerprint: fingerprint }` and hands
it to `canonicalJson`, which sorts the keys; `audienceDigest` sorts its array
outright. Both digests therefore commit to the room as a *set*, and neither
commits to any order at all. A `peersSha` that matches is not evidence that two
ends agree about who is second.

That is safe today for exactly one reason, and it is worth naming because the
reason is about to be removed. `room-ceremony.js` keeps the *panel's* insertion
order — deliberately, so that share 2 goes to whoever is second on the screen
the author is looking at — and it gets away with it because the generator writes
the whole fingerprint into every `to=`. The pairing is in the recipe text, and
the recipe text is what both ends digest. Order is not derived there; it is
*written down*.

A `scatter` that reads the same in a room of three and a room of seven has no
fingerprints in it. So the pairing can no longer be written down, and the only
orders left are the ones both ends can derive from something they already agree
about. There is one such thing: the audience, which the room id is a digest of.
So:

> **The order is `canonicalAudience`'s — ascending whole fingerprint, deduped —
> and it is derived, never chosen.** Two machines cannot disagree about it
> because neither of them is deciding anything: `roomMembers` already returns
> that order, `deriveRoomMaterial` already digests that list, and no panel, no
> arrival order and nobody's typing enters into it.

The cost is that the pairing becomes publicly computable — anybody in the room
can work out that the third fingerprint by hex order holds share 3. That is not
a new disclosure. **The ceremony already discloses it, in the text, to exactly
the same audience**: the whole notebook travels to every member, and
`$set | at 2 | quorum.send to=<fingerprint>` is a cell every one of them reads.
Worth stating plainly because `f96a0d8` drops `shareIndex` from a sealed value
on the grounds that it would "tell the whole room which share went to whom,
which is the one fact a K-of-N split is keeping" — and the room is already told,
one cell higher up. That meta-drop is still right for a published artifact,
which travels further than a notebook does; the sentence justifying it claims
more than the ceremony keeps.

#### The count mismatch is a real refusal, and it cannot be designed away

The hope was that if the share count derived from the room size, a mismatch
would be unreachable by construction rather than refused. It cannot, and the
reason is principle 4. `sss.split`'s `shares` param carries `serialize: "always"`
precisely so N stays in the text both ends compare — a 2-of-3 and a 2-of-16
must not be the same recipe. An N that came from the live roster would be the
security-relevant number moved *out* of the text, which is the defect that
docstring exists to prevent. So the split's N and the room's size are two
independently authored numbers, and `split 3/5 | words | scatter` in a room of
three is a recipe a person can write.

`room-ceremony.js` makes it unreachable *at generation time* — the generator
writes N from the room size — and not afterwards, because a member can leave
between the notebook being written and the cell being run.

The refusal belongs at plan time, since the audience is known before the run and
`planRun` already holds the roster. **It cannot be written there yet.** The
count is not in the static type: `random 32 | sss.split threshold=2 shares=5`
walks to `{base:"shares", kind:"raw"}` with no `length`, and `blip39` retypes to
`{base:"shares", kind:"mnemonic"}`, which would drop a refinement even if
`sss.split` stamped one. `LIST_TYPES` already says `length` counts elements for
`shares`, so the slot is there and empty. Stamping it — and carrying it through
`blip39` and `at` — is a prerequisite for this section, not a detail of it.

#### Output types stay statically known

`scatter`'s tip is a bundle of per-pair tips, which is `foreach`'s answer and is
fixed by the step name alone — no param decides it, so nothing here is as
delicate as `quorum.recv count=` or `gpg.encrypt mode=`. A collection of `T` is a
type, so the determinism rule holds for the same reason the elementwise section
says it does.

#### It does not need the polymorphic steps classified, and that is why it has a body

The elementwise pass stopped because `out`, `publish` and `tee` declare
`input: "any"`, so the "accepts text, handed a collection" rule cannot classify
them — and the headline example of this document turns on `out`. A zip touches
the same steps and does **not** ask the same question: the body is written by
the author, so nothing is inferred about whether a step inside it applies per
element. `foreach` has sidestepped this since the day it was written.

A bare `scatter` meaning "apply the rest of the chain per pair" would ask it, and
would stop exactly where item 4 stopped. The body is therefore not a stylistic
choice; it is what keeps this pass out of that territory.

#### The body does not name the pair's member, because a pair is a value

An earlier draft of this section stopped here, on how the body should *spell*
the recipient — `to=:key`, an omitted `to=`, or a per-iteration slot. All three
accept a premise the language's own principles reject: that the recipient must
be spelled in the body at all. Every step that takes a recipient takes it as a
**parameter**, and that is the wall — so the resolution is verbs that do not.

**A pair is a value, and a pair-consuming verb reads both halves.** That is
principle 3 applied to the pair itself: multiplicity belongs to values, not to
syntax, and so does correspondence. Inside a `scatter` body the pipe carries
the pair; two verbs consume it whole:

- **`seal`** — encrypt the pair's payload to the pair's member. Output:
  ciphertext, fixed. `gpg.encrypt mode=combined` with the `to=` supplied by the
  value rather than the text.
- **`send`** — deliver the pair's payload to the pair's member over the
  session, as `quorum.send` does, addressed by the value.

```text
@me
random 32 | split 2/3 | words | scatter
  - seal | out $sealed | publish
```

No new grammar position. No `to=` whose absence means something. And the
neighbouring warning does not apply: an omitted parameter carrying meaning is
principle 4's failure because an *absence* decides a security property, but
here nothing is absent — the recipient is half the input, exactly as
`sss.combine` never names which shares because the shares *are* the input.
Outside a `scatter` body there is no pair, so `seal` and `send` refuse at
compile time, naming that state: "seal reads the pair a scatter hands it, and
there is no scatter here."

For everything else, the body reuses the vocabulary `foreach :items` already
owns: `:key` and `:value` project a member of the item the loop is holding, and
a scatter body is holding a pair. `- :value | digest sha-256 | out $d` needs no
new rule — it is the same two steps in the same grammatical position they have
always occupied. A payload-taking step fed a whole pair type-refuses, which is
what makes the projection discoverable rather than optional-and-forgotten.

#### The slot-free deal, which this buys and the parked spellings did not

```text
@me
random 32 | split 2/3 | words | scatter
  - seal | out $sealed | publish
```

Walk what this leaves behind on the dealer's machine: the master never enters a
slot (already true, and until now an accident of how the recipe was written),
and now **the shares never enter one either** — split, sealed, published, gone.
The three-browser ceremony's highest-ranked finding was that the dealer keeps
every share in a revealable `$set` with nothing on any screen saying to delete
it, making a 2-of-3 a 1-of-1 until somebody remembers. Under this form the
hazard is not warned about; it is **unconstructable**. The published artifact
set is the deal's record, each holder decrypts only their own envelope, and the
dealer's own share comes back to them the same way everyone else's does —
sealed to their key, because a dealer deals to the whole table.

That is the test the pair-aware form passes and the `to=:key` spelling only
ties: both can seal a set, but only a design in which the shares flow *through*
the body without stopping makes "the dealer retained nothing" a property of the
text rather than of somebody's diligence.

### A ceremony and its reversal are two agreements, so they are two notebooks

The generated ceremony writes the deal and the recovery into one notebook, and
the dealer-absent e2e proved what that costs: `runFrom(i)` walks to the end,
the dealer's return cell sits below the split, so **the one press that deals
the secret also gives the dealer's share back** — and `quorum.recv count=1`
takes whichever message arrived first, so every later recovery silently
preferred the dealer's. The spec had to *delete a cell* to construct a 2-of-3
whose dealer had really given up its share. The picker's phase labels
("Dealing — run once, together" / "Recovering — run when the secret is wanted
back") are doctrine with no mechanism: nothing in the product can run one
phase.

The parked framing was a choice between two mechanisms — stop writing the
return cell, or grow a run-one-phase control. This document's first principle
picks a third reading: **the text is the agreement, and these are two
agreements.** A deal and its reversal are made at different times, by different
sets of people (the recoverer's whole premise is that the dealer may be gone),
under different threat models. One notebook digesting to one manifest makes
them one commitment, which is exactly the confusion the e2e observed from the
outside.

So the deal notebook contains the deal and nothing else. Under the pair-aware
form above it is one cell, and there is nothing below it for a run to walk
into. Recovery is **generated at recovery time**, the way the deal was
generated at deal time — the picker-first pattern that dissolved the original
chicken-and-egg. And it can be: a share's BLIP39 header carries threshold,
share count, index and set id, which is how the "Check a share…" panel already
answers `share 2 of 3 · any 2 recombine · set 465E` from one mnemonic, offline.
A recover generator asks who is contributing, reads everything else off the
shares themselves, and writes the gather. Dealer-absent recovery stops being an
achievement that requires editing the notebook and becomes the default shape —
the recovering quorum writes its own agreement, listing exactly the
contributors it has.

What this retires: the dealer's return cell (finding 1a), the phase labels
whose phases share one press (5a), and the 30-minute gather sitting armed in a
notebook that may not be run for years. What it does not change: the deal
notebook still travels to every member, still digests into the manifest both
ends compare, and still names the quorum in its text.

### Vocabulary

`sss.split` → `split`, `blip39` → `words`, `quorum.send` → `send`. The dotted
namespaces are doing real work; the acronyms are the jargon. Old names stay as
aliases — and `send` is the same verb in both grammatical positions: with
`to=` it is `quorum.send` as it always was; bare inside a `scatter` body it
consumes the pair; bare anywhere else it refuses, naming the missing recipient
rather than borrowing one from a binder.

### Comments survive serialization

`# …` parses today and is discarded by `serializeRecipe`. The one feature aimed
squarely at a reader who did not write the recipe is destroyed at exactly the
moment the recipe leaves for someone else.

## `@*` needs a rule, not a convention — **the rule is there; the sigil is not**

A cell may run on every member **exactly when its value is inherently local to
the machine running it** — `gather`, vault reads, `agent.unlock`. Those are
*supposed* to differ per machine.

The danger is the opposite case, and it is silent: an unheaded `random 32` in a
shared notebook runs on every machine and produces a different secret on each,
while every digest still matches, because the text is identical. That is the one
divergence the manifest comparison cannot see.

**That rule is implemented, and against a better declaration than this section
proposed.** `planRun` asks two questions of any cell in a placed notebook that
names no peer and is not pinned by a private input:

- `keying-unplaced`, from `keyingOp` — the first step whose registry `entropy` is
  `keying`. This is the `random 32` case exactly, and entropy is the right
  declaration for it: `vault-locality` would not have caught `random`, which
  reaches no vault.
- `vault-locality`, from `vaultOp` — a step in the `agent` toolbox, which is what
  "the registry already marks vault-local operations" was pointing at. It is a
  second question beside the first, not the same one.

Both are **asks**, not refusals, and that is right: per-peer is a legitimate
thing to mean, and the ask says so ("leave it if per-peer is what you meant").

What is *not* there is the sigil. `@*` parses and plans as a `rendezvous`, and
then `validateRecipe` refuses it outright — "this build can describe one but not
perform one, so running it would have you enter alone while believing the room
entered with you." So the `gather | out $share` cell above does not compile as
written. It does not need to: a headerless cell already runs on every machine,
and it is headerless cells the rule above is about. `@*` adds a barrier — every
participant entering together — which is a distributed mechanism this build does
not have and which `gather` does not need.

## Migration

This breaks the preset corpus, `recipe-roundtrip.test.js`'s sweep, `publish=` in
`plan.js` and its refusals, and any recipe relying on `-` line concatenation —
which must be searched for, not assumed absent.

Order of work, bug fixes first:

1. **Comments survive serialization.** Small, and it is the readability premise
   everything else rests on.
2. **The quorum becomes an argument** (`split 2/3`). Fixes a real gap in what
   the two ends agree on.
3. **`publish` as a step** — done. **`:public` as a step** — done.
4. Elementwise, prototyped against the preset corpus — the round-trip sweep
   reports immediately how many recipes change meaning.
5. **The share count becomes a `length` refinement** on the `shares` type,
   stamped by `sss.split` and carried through `blip39` and `at`. Small, and
   nothing below can refuse a count mismatch at plan time without it.
6. `scatter` with pair-aware `seal` / `send`. The `@*` rule is already landed,
   and the body-naming question is resolved above — a pair is a value, and the
   verbs that consume one read both halves. `gather` follows once the published
   set exists to gather from.
7. **The recover generator** — recovery written at recovery time from the
   shares' own headers, and the deal notebook reduced to the deal. Retires the
   dealer's return cell and the phase labels one press cannot honour.

## What gated all of it — **met**

This closed by saying nothing had yet proven `quorum.send` / `quorum.recv`
deliver under the placement gate in two real browsers, and that
`placed-journey.e2e.js` was where that belonged. It is there now, and it drives
the five questions in order: the share arrives; both arrival orderings work (sent
before the holder's cell runs, and sent into a waiting receive); the placement
gate declines the holder's cell and hands it over; a holder who is sent nothing
is told so in words about the room they are actually in; and the ceremony
reverses — the holder recombines on a machine that never held the secret, and the
two strings are compared through the screen.

One thing that report also establishes is worth carrying here: `quorum.send` and
`quorum.recv` are named by **zero** of the seventy presets, so the only way
anybody has ever reached these verbs is by typing them. Whatever `scatter`
becomes, it is the first thing that would put this road in front of a person who
did not go looking for it.
