# Building with Basilisk's components

Basilisk is a browser-only cryptography notebook. Its look is dense, mono-led
and dark-first: small type, tight rows, colour used to mean something rather
than to decorate. Build with that restraint — a marketing-weight layout made
from these parts will look wrong even if every component is used correctly.

## No provider, no setup

Every component here renders standalone. There is no theme provider, no
context root, and nothing to wrap your tree in. Import and use:

```jsx
import { Button, SuggestChip, ArtifactAction } from "basilisk-portal";
```

Theming comes entirely from `styles.css` and the custom properties it defines,
so a component picks up light or dark automatically from
`prefers-color-scheme`. Do not set colours on these components yourself — pass
the variant the component offers.

## The styling idiom: tokens, not hex

Style your own layout with the CSS custom properties the design system
defines. These are the real names, all defined in the shipped stylesheet:

| Token | Means |
|---|---|
| `--brand` | primary action, trust surface (forest green) |
| `--accent` | shared secrets / SSS surface (gold) |
| `--caret` | position, encode direction (blue) |
| `--decode` | decode direction, selectors (purple) |
| `--warn` | live key material, irreversible actions (amber) |
| `--error` | something failed |
| `--success` | verified, self-test passed |
| `--surface` / `--surface-raised` | page and panel backgrounds |
| `--border` | hairlines |
| `--foreground` / `--muted-foreground` | primary and secondary text |

Use them as `var(--brand)`, and compose tints with `color-mix()`:

```jsx
<div style={{ background: "color-mix(in srgb, var(--warn) 8%, transparent)" }}>
```

Two rules that carry meaning, not taste:

- **`--warn` means "live key material or an irreversible action."** It is not a
  generic highlight. `--error` is reserved for things that actually failed —
  using it for a legitimate-but-dangerous action cries wolf.
- **Tints must stay light in light mode.** Mixing a hue into a light surface
  moves it *toward* the text and contrast collapses. The system carries
  `--tile-tint` (12% dark, 6% light) for exactly this; reuse it rather than
  picking a percentage.

## Closed vocabularies are data attributes

Where a component has a fixed set of states, it reads a `data-*` attribute and
the stylesheet enumerates the cases — there are no inline style objects
anywhere in this system, because the product ships under a CSP that forbids
them. Live examples: `data-action-tier` (`inert` / `local` / `outward`),
`data-cast` (`verified` / `unverified` / `error`), `data-key-kind`
(`pgp` / `ssh` / `raw`). If you extend a component, follow that shape.

## Action weight encodes consequence

`ArtifactAction` is the clearest expression of the system's one strong
opinion: what a control looks like should say what happens if you click it.

- `tier="inert"` — local and reversible (Copy, Download). Quiet text.
- `tier="local"` — changes durable state on this device (Add to keyring).
  Filled and bordered.
- `tier="outward"` — leaves the machine, possibly irreversibly (Publish).
  Amber outline, and never the default-focused control.

Use at most one outward action per row. A disabled action always carries a
`reason` sentence — the prop is what disables it, so the two cannot drift —
and disabled deliberately does **not** dim: the label stays legible and the
affordance is removed instead.

## Where the truth is

Read these before styling anything substantial — they beat any summary:

- `styles.css` and its `@import` closure: every token, in both schemes.
- `components/<group>/<Name>/<Name>.prompt.md`: per-component API and usage.
- `components/<group>/<Name>/<Name>.d.ts`: the prop contract.

## One idiomatic composition

A recipe row as the toolkit actually builds one — library components for the
controls, tokens for your own glue:

```jsx
import { SuggestChip, ArtifactAction } from "basilisk-portal";

export function ArtifactRow({ label, onCopy, onPublish }) {
  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        gap: 8,
        padding: "8px 10px",
        borderRadius: 10,
        border: "1px solid var(--border)",
        background: "var(--surface)",
      }}
    >
      <SuggestChip label={label} variant="placed" />
      <span style={{ marginLeft: "auto", display: "flex", gap: 6 }}>
        <ArtifactAction label="Copy" tier="inert" onClick={onCopy} />
        <ArtifactAction label="Publish" tier="outward" onClick={onPublish} />
      </span>
    </div>
  );
}
```
