# Artifacts that know what they are

## The idea, stated once

Today, if you generate a keypair and want it in your keyring, you must
write it into the recipe:

```
genkey ed25519 | agent.save | out @id
```

That conflates two different things. `genkey ed25519` is a **derivation** —
it says what the value *is*, and it is the same for everyone who runs the
recipe. `agent.save` is a **disposition** — it says what *I* want done with
the result on *this* machine, and it has no business being a property of
the shared artifact.

The consequence is not merely verbosity. A recipe that ends in
`agent.save` mutates the keyring of whoever runs it; a recipe that ends in
`hkp.publish` would push a key to a public server on their behalf. Every
recipe you share is currently also a script of side effects. Moving
dispositions out of the recipe and onto the artifact makes recipes
*portable*: a shared recipe computes, and the person running it decides
what happens to the result.

So: **how you use an artifact should be a UX affordance, not a pipeline
requirement.** A keypair tile offers Export, Add to keyring, Copy public
line, Publish. A ciphertext tile offers Save, Copy, Decrypt with…. A shares
tile offers Print cards, Verify. The recipe stays the cryptography.

## Why now

Three things make this the right next move rather than a nice-to-have.

**It closes the "neat concept → useful tool" gap.** A toolkit that computes
correct values and then hands you a text blob has done the hard half and
skipped the useful half. Almost every real task ends in *put this
somewhere*: authorized_keys, a keyserver, a password manager, a colleague,
a printed backup. Those endings are currently either missing or spelled as
extra pipeline steps that the user has to know exist.

**The abstraction is already overdue.** `OutputList` picks a renderer with
an if/else chain: `hasNetworkRenderer(a.netType)` → `NetworkArtifact`, else
`a.inspectSnapshot` → `InspectorArtifact`, else `hasJoseRenderer(a.jose)` →
`JwtArtifact`, else raw text. Three typed views, three bespoke predicates,
three parallel data fields threaded through the artifact record. A fourth
means a fourth branch and a fourth field. That is the split design and
churn the request names, and it has already started.

**The type system can already drive it.** `artifactMetaFromType` in
`types.js` projects a refined type onto `{ role, tags }` — `keypair` → role
`key`, tag `keypair`; `openpgp-key` public → role `key`, tags `openpgp,
public`; `shares` → role `share`. That projection is the natural key for
both views and actions, and it is derived from the real declared types
rather than a parallel presentational vocabulary that can drift.

## The shape of the thing

Two extension points over one registry, both keyed off the artifact's
projected type — the same source-of-truth discipline `registry.js` already
imposes on ops:

- **Views** — how an artifact renders. Today: text, network read-out,
  inspector snapshot, JOSE reader. Tomorrow: key card, shares sheet,
  recipients list, QR. One declared table replaces the if/else chain, and
  the existing three become its first entries rather than special cases.
- **Actions** — what you can do with it. Declared per role/tag with a
  label, an availability predicate (some actions need a vault, a network,
  a passkey), a tier (below), and a handler.

A view and an action set are then two fields of one artifact-kind
definition, and adding a fifth kind is a table entry, not a widget rewrite.

## Action tiers — the part that must not be got wrong

Not all actions are the same kind of thing, and flattening them into a row
of equal buttons is how a mis-click becomes unrecoverable. Three tiers,
mapping onto distinctions this codebase already draws:

1. **Inert** — Copy, Download, Show QR, Reformat. Local, reversible, no
   state changes. Ordinary button weight, no confirmation.
2. **Local mutation** — Add to keyring, Save to file, Import as recipient.
   Changes durable state on this device. Needs a receipt (see below), and
   a real disabled reason when unavailable rather than a dead button.
3. **Outward-facing / irreversible** — Publish to keyserver, Send to peer.
   A key published to a keyserver **cannot be unpublished**. These need
   explicit confirmation naming the destination and what becomes public,
   in the grammar §27's approval banner established — and they must never
   be the default-focused action in a row.

An artifact that is `sensitive` (a private key, a scalar) is masked until
revealed. **Actions must not become a mask bypass**: a Copy on a masked
private key either reveals first or is disabled with the reason. This is
worth stating because it is exactly the kind of hole a convenience feature
opens.

## Auditability — the open question the design must answer

The recipe is currently a complete record of what happened. Moving
dispositions to buttons breaks that: a key lands in the vault with nothing
in the recipe to say so. Three candidate answers, and the design should
pick one and argue it:

- **Run receipts** — the `receipt` shelf already exists for ceremony audit.
  UI actions append to it.
- **Promote to recipe** — the action does the thing *and* offers "add this
  step to the recipe so it happens every run", turning a one-off
  disposition into a derivation when the user wants it. This is the
  friendliest and keeps the recipe honest for repeat work.
- **Accept the split** — recipes record derivations, a separate activity
  log records dispositions, and neither pretends to be the other.

My instinct is the second as the headline affordance with the first
underneath, but that is the design's call, not mine.

## Candidate actions by artifact kind

Illustrative, not binding — the design should prune aggressively. An action
nobody uses is a button everyone has to read past.

| Artifact | Inert | Local | Outward |
|---|---|---|---|
| keypair / key | Copy public line, Copy JWK, Download PEM, Fingerprint, QR | Add to keyring, Set as signing key | Publish to keyserver |
| openpgp key (public) | Copy armor, Download, Fingerprint | Import as recipient, Trust… | Publish |
| openpgp key (private) | Download (masked) | Add to keyring | — |
| ciphertext / envelope | Copy, Download, Inspect packets | Decrypt with… | Send to peer |
| shares | Copy each, Print cards | Verify threshold | — |
| sshsig | Copy, Download | — | — |
| recipients | Copy list | Save as group | — |
| network values | Copy candidate/SDP | — | Send to peer |

The `key` row is the one that motivated the request and the one most worth
getting right; `keypair` today renders as two JWK blobs and nothing else.

## Constraints

- **Strict CSP**: no inline styles; closed vocabularies as data attributes
  with enumerated CSS; continuous values through `lib/css-vars.js`.
  `connect-src` is an allow-list of two keyservers — a Publish action can
  reach those and nothing else, by policy, not by intention.
- **The registry is the source of truth.** Views and actions key off
  `artifactMetaFromType`'s projection, not off a parallel table of strings.
  If a type stops existing, its view and actions stop existing.
- **The CLI runs the same engine.** Actions are browser affordances by
  nature, but nothing about them may change what a recipe *computes*, or
  headless runs diverge from browser runs.
- **Sensitive artifacts stay masked**, and reveal stays gated.
- Existing typed renderers (`NetworkArtifact`, `InspectorArtifact`,
  `JwtArtifact`) must land inside the new abstraction rather than beside
  it — the point is to remove the branch, not add a fourth path.
