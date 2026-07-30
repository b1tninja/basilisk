# Design brief — Basilisk Toolkit: typed inspectors, value display, and the widget backlog

Paste this into the design agent. It assumes access to the repo at
`b1tninja/basilisk`, branch `feat/toolkit-redesign`, and to the existing
`Basilisk Toolkit v2.dc.html` design project.

---

## What Basilisk's Toolkit is

A browser-only cryptography notebook. You write a **recipe** — a pipeline of
steps joined by `|` — and each cell runs it and produces artifacts:

```
genkey ec/p256 | export spki | pem | out @pub

random 32 | encode base64 | out @cek
bytes deadbeef | aes-gcm key=@cek | out @ct
```

Everything runs client-side against WebCrypto, OpenPGP.js, and WebRTC. No
server holds key material.

**The pipeline is typed.** A value flowing between steps has a base type
(`bytes`, `text`, `keypair`, `shares`, `candidate`, `session`, …) plus
refinements (`bytes/master/32B`, `sdp/offer`, `text/opaque/base64url`). Types
are not cosmetic — they gate which ops the caret offers, they select which
widget renders a result, and three of them are deliberately restricted:

- **DATA** types are inert and safe to copy, publish, and pipe onward.
- **HANDLE** types (`session`, `channel`) are live browser objects. They only
  mean anything inside the run that created them.
- **OBSERVE** types (`connstate`, `stats`) are diagnostic read-outs. They can
  be displayed but never consumed as a crypto op's input.

Design work that ignores this three-way split will produce screens the type
system refuses to render.

---

## Stack and constraints (these bind)

- React 19 + TypeScript + Tailwind v4, shadcn-style components over Radix
  primitives (Dialog/Sheet, DropdownMenu, ScrollArea, Tooltip, Popover).
- **Reuse existing primitives.** Do not invent a second dialog system, a second
  chip, a second param editor. If a design needs a window, it is a `Sheet`.
- All colour via CSS custom properties — `--brand`, `--caret`, `--warn`,
  `--surface`, `--surface-raised`, `--border`, `--foreground`,
  `--muted-foreground`. Never hardcode hex in components.
- Light and dark both. Dark is the default reading.
- Deliverable format: a standalone HTML design reference (like the previous
  handoffs) plus a README describing intent, states, and contracts. It is a
  *reference*, not code to port — the retrofit agent rebuilds it in React.

---

## Where to look first

| Path | What it tells you |
|---|---|
| `web/src/pages/toolkit-widgets.tsx` → `/toolkit-widgets` | Live catalog of every widget in its canonical states. **Start here.** |
| `web/src/toolkit/widgets/` | The widgets themselves |
| `docs/TOOLKIT-WIDGETS.md` | Widget responsibilities + uniformity rules |
| `docs/RECIPE.md` | The recipe language |
| `web/src/lib/toolkit/type-registry.js` | Every pipeline type, documented, with producers/consumers |
| `redesign/design_handoff_*/` | Previous handoffs — match their fidelity |

---

## The four problems to design

### 1. The typed inspector (highest value)

`inspect` used to flatten every value into a text dump whose first lines were
metadata:

```
type: text
sensitive: yes
length: 16 chars
<the value>
```

That is wrong twice over: metadata lived *inside the payload* (so it could not
be copied without the header, or styled), and a keypair was described in prose
rather than shown.

A first pass now exists — `InspectorArtifact.tsx` — which renders the
structured snapshot the engine already builds (`{ type, meta, bytes?, text?,
keypair?, shares?, recipients? }`), with metadata as chips above the value and
a real hexdump body for bytes. **It is deliberately plain and wants design.**

Design the inspector properly, per type:

- `bytes` — hexdump. Offset / hex / ASCII columns, selection, byte-range
  highlighting, "show more" for large buffers. What does a 4 KB buffer look
  like versus 16 bytes?
- `text` — charset, line endings, whether it is armored/PEM/JSON, and a
  structure-aware view when it is one of those.
- `keypair` / `key` — algorithm, curve, usages, extractability, which halves
  are present. The private scalar `d` must be *named but never printed*.
- `openpgp-key` — packet structure. Primary key, subkeys, user IDs,
  self-signatures, expiry. This is the richest and least designed.
- `shares` — the SSS set: threshold-of-N, per-share rows, which are present.
- `recipients` — resolved keys, fingerprints, capability (SEIPD v2 or not).
- The network types already have `NetworkArtifact`; make the inspector's
  chrome consistent with it.

**Open question for you to answer with design:** the inspector currently has a
`format` param (`auto | text | hex | hexdump | jwk | meta`) *and* artifacts now
have a post-hoc format switcher. Are these the same control? Should the
inspector's view mode be part of the widget rather than the recipe?

### 2. Value display: formatting, revealing, copying

Artifacts can now be re-rendered after the run as `raw / hex / base64 /
base64url / base32`, and sensitive values can be **revealed** — but only when
the user explicitly asked to see them by writing `out`, `text`, or `inspect`.
A value that merely reached the end of a pipeline stays masked with no reveal
affordance. That gate is a security property; keep it.

This is currently a cramped row of tiny mono buttons. Design:

- The format switcher — is it a segmented control, a dropdown, a per-artifact
  preference? What happens with formats that do not apply?
- Reveal / Hide. Reveal is a deliberate act on a secret. How does it look
  before, during, after? Does it time out? Does it warn on screen-share?
- The relationship between preview (one line), inline body, and the
  expand-to-window `Sheet` — three sizes of the same value.
- Copy. Copy the raw value, or the displayed format? Both?
- **Clipboard is unbuilt and wanted**: a `clipboard` source/sink so a recipe
  can read from and write to the system clipboard. Design its permission
  moment — reading the clipboard is a privacy event and should feel like one.

### 3. Type widgets (the Types tab)

The ops drawer has two peer modes: **Ops** and **Types**. Every one of the 23
pipeline types has a card showing its docs, a reference link, and — derived
from the registry, never hand-written — which ops produce and consume it.

Four types can be written down directly (`bytes`, `text`, `int`, `bool`) and
carry a literal editor; `int` accepts `0x` / `0b` / `0o` and reports
`= 42 decimal · 1 byte · big-endian`. `keypair` instead has two **origins**
(Generate → inserts `genkey`; Import → inserts a run-time paste step). Types
nothing touches yet are honestly labelled *reserved*.

The card is functional and unstyled. Design:

- The type card as a first-class object. What is the hierarchy — name, what it
  is, how you make one, what consumes it?
- Literal editors per type. A byte-string editor is not a number field.
- The origin picker as a reusable pattern (`certificate` is the next candidate:
  generate ephemeral vs. import a pinned one).
- How does browsing types relate to browsing ops? Should a type card offer
  "start a pipeline from here"?

### 4. The session tray

A right-hand tray with tabs: **Keys · Slots · Outputs · Inputs · Params**.
Outputs is new — it gathers every cell's artifacts in one place, grouped by
cell. Inputs holds run-time material never written to the recipe (pasted
messages, share mnemonics, key material).

Design the tray as a coherent surface rather than five unrelated panels. What
belongs here versus inline in the notebook? How does the tray behave at narrow
widths?

---

## Widget inventory and design maturity

Rated by how much design attention each has had. **Early** and **Unbuilt** are
where the work is.

### Well developed — match these, do not redesign without reason

| Widget | Notes |
|---|---|
| `OpsShelf` | Toolbox → shelves → tiles, search, kit footer bar, caret fit-dimming, Ops/Types mode toggle |
| `OpsTile` | Draggable encode/decode tile, tip-fit states |
| `ToolCard` | Op docs — glyph, I/O, params, aliases, reference-link footer |
| `RecipeChipFlow` | The chip pipeline — chips, insert gaps, nest rails |
| `InsertGap` | The single insert affordance |
| `SuggestChip` | Step pill; `candidate` / `placed` / `selector` / `editable` |
| `Glyph` | One glyph renderer; kind shapes derived from real pipeline types |
| `ParamField` / `ParamFieldGroup` | Bool / enum / text / secret / locked params |
| `TopBar`, `RunBar`, `ReadinessBar` | Session chrome, run state, blockers |
| `PresetMenu` | Templates gallery |

### Middling — structure exists, visual design is thin

| Widget | What it needs |
|---|---|
| `OutputList` | Row is crowded: kind badge, label, sensitive badge, size, copy, publish, expand, format bar, reveal. Needs a real information hierarchy. |
| `NetworkArtifact` | Ten typed renderers (ICE candidates, pair matrix, connection state, back-pressure, quality, endpoint, certificate, session, SDP). Functional, sparse. |
| `SessionStrip` | Quorum session state; `failed` + ICE-restart states unbuilt |
| `CryptoProfileControl` | Profile picker; custom sub-fields are dense |
| `ModeToggle`, `MenuPopover` | Fine, but unexamined |

### Early — built to work, explicitly wants design

| Widget | What it needs |
|---|---|
| **`InspectorArtifact`** | **Problem 1.** Per-type bodies, hexdump design, packet trees. |
| **`TypeCard`** | **Problem 3.** Literal editors, origin picker, producer/consumer lists. |
| **Format switcher + Reveal** | **Problem 2.** Currently tiny mono buttons inside an output row. |
| **Outputs tray tab** | **Problem 4.** Grouped list, no design pass. |

### Unbuilt — design from scratch

| Feature | Notes |
|---|---|
| **Clipboard source/sink** | Permission moment, paste preview, write confirmation. |
| **Connections tray tab** | Active peers, server preferences, session log (WebRTC handoff 24a–c, 27). |
| **Peer detail drawer** | Per-peer identity, transport, channels (28b). |
| **Message hexdump** | Data-channel traffic view (28c). |
| **`quorum.mesh`** | Multi-peer mesh cell region (29c). |
| **Session log** | Append-only connection event history (28a). |
| **ICE restart** | `SessionStrip` failed state + recovery (26c). |
| **Artifact history / diff** | Comparing this run's output to the last. |
| **Error surfaces** | Type errors are the most common failure and have no designed presentation. |

---

## How to work

1. Open `/toolkit-widgets` and read the real states before designing.
2. Do not invent registry ops, types, or params. If a design needs one, say so
   explicitly and explain why — the registry is the source of truth and the
   retrofit agent will check.
3. Design the **failure and empty states**, not just the happy path. A masked
   secret, a type mismatch, an unreachable peer, an empty Outputs tab.
4. Say what is *decided* versus what is *illustrative*. Previous handoffs got
   retrofitted faithfully because they were explicit about which mock details
   were binding; where a mock reflected a fictional registry, that was called
   out and the underlying decision was what bound.
5. Prefer removing controls to adding them.
