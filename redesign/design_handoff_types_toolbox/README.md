# Handoff: Types Toolbox (instantiable types + docstring links)

## Overview
Two related, toolkit-wide changes (not specific to WebRTC): (1) the flat
"Input / output" shelf category becomes a **Types** category where each type
is its own instantiable source op with a widget shaped like that type's
native form — an Int field takes `42` or `0x2A` directly, a KeyPair can be
generated or imported as a first-class origin — instead of everything
starting as free text and getting cast downstream. (2) every tool card/param
editor gets an optional docs-link footer pointing at the real MDN/spec page
the op wraps (e.g. `genkey` → `SubtleCrypto.generateKey`).

## About the design files
`types-toolbox-reference.html` is a **design reference built in HTML**, not
production code. Recreate it in the real `b1tninja/basilisk` codebase (React
19 + TypeScript + Tailwind v4), reusing existing components (`OpsShelf`,
`ParamField`, the inline param editor, the caret's hover/detail card) — do
not port the HTML/inline-style markup directly.

## Fidelity
High-fidelity for layout, copy, and the registry shape changes below. Treat
the TypeScript shapes as the intended contract.

## Screens / views

### 1. Types category (turn 31a)
Replaces the existing flat "Input / output" category (7 ops, generic gray
dot) in `OpsShelf`'s tree with one entry per real kind: `text` (unchanged —
free text stays free text), `int`, `hex`, `keyPair` (new), `certificate`
(links to turn 29a's `rtc.certificate`), `iceServer`, `bytes`. Same
collapsible category-header pattern already used everywhere else in the
tree; no new tree mechanics. Each entry's dot uses the existing kind-glyph
system (25a) where a kind already has one (e.g. `iceServer` reuses the
rotated-square candidate-family glyph).

**Registry shape**: ops gain `op.kind: 'type' | 'transform' | 'source'` and,
for type ops, `op.instantiates: OpKind`. Downstream fit-checking is
unchanged — a type op's output kind flows through the existing caret
fit-check (19a/20b/25d) exactly like `genkey`'s output already does. This is
a shelf reorganization for authoring clarity, not a new pipeline mechanism.
Existing recipes built on the old `input :text` shape keep working
unmodified.

### 2. Int / Hex widgets (turn 31b)
One field per widget, accepting either decimal (`42`) or `0x`-prefixed hex
(`0x2A`) for Int; a hex-first byte string for Hex. Normalizes on blur and
shows the alternate representation plus byte length inline (e.g. "= 42
decimal · 1 byte · big-endian") so what the user typed and what the pipeline
holds are never ambiguous. Both normalize to the same underlying `bytes`
kind on output — a downstream op consuming bytes doesn't care which type
widget produced them.

```ts
interface IntTypeOp {
  accepts: RegExp; // /^-?\d+$/ | /^0x[0-9a-f]+$/i
  out: { value: bigint; byteLength: number };
}
```

### 3. KeyPair as an instantiable type (turn 31c)
`genkey` (existing WebCrypto-category op) is unchanged and remains the
primary way most keypairs get made. The new Types-category `keyPair` entry
adds a second origin for a keypair a user already has (exported elsewhere, a
long-lived identity) that previously had to masquerade as base64 text and be
parsed downstream. One widget, a segmented **Generate / Import** control:
- **Generate** — renders `genkey`'s exact existing param form inline (not a
  reimplementation) and produces the identical output shape.
- **Import** — accepts a pasted JWK or PEM (PKCS8 private + SPKI public).
  Private half stays non-extractable once imported, same guarantee a
  generated key already has.

Both modes produce the same `CryptoKeyPair` kind, so the rest of the
pipeline is indifferent to which origin was used. This Generate/Import
pattern is the template for any future type with both a "make one" and
"bring your own" origin — `certificate` (29a) is the next candidate:
generate ephemeral vs. import a pinned one.

```ts
interface KeyPairTypeOp {
  mode: 'generate' | 'import';
  // generate: delegates to genkey's existing param set
  // import: accepts { format: 'jwk' } | { format: 'pem', pkcs8, spki }
}
```

### 4. Docstring links (turn 31d)
A quiet one-line footer — "↗ SubtleCrypto.generateKey — MDN" — at the bottom
of both the inline param editor (the expanded per-op form, existing 18b
pattern) and the caret's hover/detail card. Doesn't compete with the op's own
description text; it's a footer, not a callout. Optional per op — composite
ops with no single canonical spec page (e.g. `openpgp.signAndEncrypt`) omit
it rather than linking somewhere approximate.

```ts
interface OpDefinition {
  // ...existing fields...
  docUrl?: string;
}
```

Populate once per op at registry-authoring time. Examples to seed with:
`genkey` → `https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/generateKey`,
`rtc.ice` → `RTCConfiguration.iceServers`,
`rtc.gatherCandidates` → `RTCIceCandidate`,
`aes.encrypt` → `SubtleCrypto.encrypt`,
`quorum.offer` → `RTCPeerConnection`.
This is documentation-authoring work (filling in the field per op), not a
per-op design decision — the same footer renders for every op that has one.

## Interactions & behavior
- Clicking a Types-category entry inserts it exactly like any other source
  op via the caret (19d) — no new insertion mechanism.
- The KeyPair widget's Generate/Import toggle is a plain two-state segmented
  control; switching modes clears whichever mode's fields aren't in use.
- The docs-link footer opens the URL in a new tab; it never appears inline
  with body copy, always as the last row of the card/editor.

## State management
No new state beyond the registry fields (`op.kind`, `op.instantiates`,
`op.docUrl`) and the KeyPair widget's local `mode` toggle. Int/Hex widgets
hold their own normalized value the same way any other `ParamField`/type
widget already manages local input state.

## Design tokens
No new colors. `int`/`hex` reuse the existing HKP/directory orange `#f0883e`
(already established as a "plumbing/utility" accent in the WebRTC toolbox
handoff). `keyPair` uses the existing brand green `#4cde82` (consistent with
`genkey`'s own output treatment in the base v2 shell). Typography and row
chrome unchanged from the rest of the toolkit.

## Assets
None — all glyphs are existing CSS shapes from the kind-glyph system (25a);
no new icons.

## Files
- `types-toolbox-reference.html` — standalone extract of turn 31 (31a-d),
  open directly in a browser.
- Depends on the base v2 shell (`OpsShelf`, `ParamField`, inline param editor,
  caret) from `design_handoff_quorum_toolbox/` and `design_handoff_remaining/`
  — retrofit those first if not already landed.

## Source
Design project: this project, turn 31 in `Basilisk Toolkit v2.dc.html`.
Retrofit target: `b1tninja/basilisk`, branch `feat/toolkit-redesign`.
