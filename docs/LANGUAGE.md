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

### Vocabulary

`sss.split` → `split`, `blip39` → `words`, `quorum.send` → `send`. The dotted
namespaces are doing real work; the acronyms are the jargon. Old names stay as
aliases.

### Comments survive serialization

`# …` parses today and is discarded by `serializeRecipe`. The one feature aimed
squarely at a reader who did not write the recipe is destroyed at exactly the
moment the recipe leaves for someone else.

## `@*` needs a rule, not a convention

A cell may run on every member **exactly when its value is inherently local to
the machine running it** — `gather`, vault reads, `agent.unlock`. Those are
*supposed* to differ per machine.

The danger is the opposite case, and it is silent: an unheaded `random 32` in a
shared notebook runs on every machine and produces a different secret on each,
while every digest still matches, because the text is identical. That is the one
divergence the manifest comparison cannot see.

The registry already marks vault-local operations, so this is checkable rather
than remembered. It has to land with the design, not after it.

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
5. `scatter` / `gather`, with the `@*` rule.

## What gates all of it

Nothing has yet proven `quorum.send` / `quorum.recv` deliver under the placement
gate in two real browsers. `placed-journey.e2e.js` is where that belongs, and it
should be proven before a language is designed around it.
