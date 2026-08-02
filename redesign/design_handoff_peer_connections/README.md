# Handoff: peer connections as a managed, first-class thing

A **connection manager** between the two layers that exist today. `rtc.*` stays
raw and inspectable; `quorum.*` stays the identity-bound mesh; the new `peer.*`
layer is how a person gets two browsers connected without hand-composing SDP and
without an OpenPGP audience.

It also closes the defect that made this a design decision rather than a bug
fix: `rtc.offer` destroys the peer connection whose SDP it returns, so two
shipped templates describe a flow that cannot complete.

## Reading order

1. **[BRIEF.md](./BRIEF.md)** — the capability request, what it is right about,
   and the two places it is corrected.
2. **[PEER-CONNECTIONS-DESIGN.md](./PEER-CONNECTIONS-DESIGN.md)** — §54–§59:
   - **§54** the defect, why the narrow fix is not implementable on its own, and
     the three requirements the brief actually contains.
   - **§55** the op surface: the link registry, the seven `peer.*` ops, what is
     retired and how it migrates, why `name=` rather than a piped handle, and
     why `peer.accept` does not block.
   - **§56** types: DATA / HANDLE / OBSERVE per op, where the HANDLE constraint
     is discharged, and why `peer.recv`'s parameter-driven output is the
     permitted form of a varying type.
   - **§57** what quorum stops owning — the five diagnostic ops stop asking the
     mesh what is connected — and what it keeps.
   - **§58** the UI: the Connections tab as an inventory, the verdict coming
     from the read-out rather than the widget, and how a direct link states that
     it is unauthenticated.
   - **§59** scope: unit 1, the unit 2 that is designed and not built, and four
     things deliberately absent.
3. **[IMPLEMENTATION-STATUS.md](./IMPLEMENTATION-STATUS.md)** — what landed,
   what was measured, and the deviations.

## Decided vs. open

**Decided** (each fork argued in the doc, with the rejected option recorded):

- A registry of links, not a bare "keep the offer alive" fix — the narrow fix
  introduces an unowned resource and the next question is immediately "which
  one" (§54b).
- `rtc.offer`/`rtc.answer` are **retired and migrated**, not repaired in place.
  Repairing in place needs no migration and was rejected because it would leave
  a registry-allocating op inside the module whose header promises one browser
  capability per op (§55c).
- `rtc.send`/`rtc.recv` are **not** widened to managed links. They encrypt under
  a pairwise session key; a link has none, and reusing the name would eventually
  put plaintext on an unauthenticated channel under an op whose whole history is
  encrypted traffic (§55c).
- Links are referenced by `name=`, not by a piped handle — the two halves of an
  exchange are separate engine calls with a human in between, and a HANDLE in a
  slot can be consumed by nothing anyway (§55d).
- `peer.accept` (signalling) and `peer.wait` (ICE outcome) are separate ops, so
  "this is not an answer" and "no candidate pair worked" keep separate error
  sentences and separate next steps (§55e).
- `peer.wait` emits the `channel` HANDLE, because its postcondition is the only
  moment at which a live channel exists to hand out (§56).
- The failure verdict in the panel is `connStateReadout`, not a second copy
  (§58b).

**Corrections to the brief**, both load-bearing:

- Lifting negotiation out of `QuorumSession` is deferred, not skipped, and the
  reason is the DTLS-fingerprint transcript binding, whose failure mode is
  silent and green (§59b).
- Perfect negotiation's glare handling is not what a hand-carried exchange
  needs; it stays where it is exercised (§59c).

**Open / deferred**: unit 2 (quorum drives the manager); trickle ICE for
`peer.*`; link persistence across runs; a `peer.*` path in the CLI. Reasons in
§59b–c.

## Conventions

Sections are cited as `§54`–`§59` (this handoff's series, continuing §32–§38 and
§47–§53). The `design v2` numbering line is always cited in full.
