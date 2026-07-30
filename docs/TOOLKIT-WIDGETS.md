/**
 * Toolkit widget catalog — shared UI building blocks.
 *
 * Source of truth: `web/src/toolkit/widgets/`.
 * Live states: `/toolkit-widgets`.
 * **Cutover complete** — `/toolkit` now loads the React shell (`pages/toolkit.tsx` /
 * `ToolkitShell`) directly. `toolkit-legacy.js` (the vanilla notebook) and its
 * `/toolkit-legacy` / `/toolkit-react` alias routes have been removed. The
 * pre-cutover DOM-mount bridges (`widgets/legacy-bridges.tsx`, `widgets/mount.tsx`,
 * and the deprecated `toolkit/ToolCard.tsx` / `toolkit/OpsIconGrid.tsx` re-export
 * shims) have also been deleted — nothing mounts these widgets as DOM islands
 * anymore, they're used as plain React components everywhere.
 *
 * ## Widgets
 *
 * | Widget | Responsibility |
 * |--------|----------------|
 * | **Glyph** | `GLYPH_PATHS` → sized SVG (op icons only; lucide for chrome) |
 * | **ToolCard** | Op docs / I/O / params (hover, pin, docs) |
 * | **OpsTile** | Draggable encode/decode tile + tip-fit |
 * | **OpsShelf** | Searchable toolbox → shelves → tiles + AES/RSA / Formats / HMAC kits |
 * | **SuggestChip** | Compact step pill (`candidate` / `placed` / `selector` / `editable`) |
 * | **InsertGap** | Insert-at-index `+` (click + DnD) |
 * | **SuggestRail** | Toolbox squares + nest soft-add + pull-out chips / compose |
 * | **RecipeChipFlow** | Preview chip pipeline (chips + gaps + nest rails) |
 * | **ParamField** | Bool / enum / text / locked params |
 * | **ModeToggle** | Segmented modes (Preview/Raw/Cards, PGP) |
 * | **MenuPopover** | Toolbar menus (shadcn DropdownMenu) |
 * | **PresetMenu** | Templates gallery (categories, search, companion pairs) |
 * | **TypeCard** | Pipeline-type docs / producers / consumers / literal constructor |
 *
 * ## Files section (`#fileops`)
 *
 * Not a widget — a states page for the file/`stream`/`age` ops, because they
 * introduced a toolbox, a shelf, seven glyphs, and a toast, and every one of
 * those is a place the catalog is cheaper than the app. It carries the new
 * glyph strip, the `age` toolbox dot beside its neighbours (its colour is
 * duplicated in `toolkit.css` and guarded by `toolbox-dot-css.test.js`), the
 * four ToolCards, and both confirmation toasts.
 *
 * The catalog earned its keep here again: the section is where the picker's
 * off-screen scaffolding was measured, which is how a site-wide
 * `input[type=file] { display: none }` in `site.css` was found sitting on
 * `file.read`'s `<input type=file>` fallback. A `display: none` input is
 * click-inert in some engines, so the fallback would have failed silently on
 * exactly the browsers that lack the File System Access API — invisible to
 * every unit test, since those stub the DOM and never run the cascade.
 *
 * ## Types in the toolbox
 *
 * The ops drawer has two peer modes, `ops` and `types` — a type is not an op, so
 * it is not a fifth entry in the footer kit bar (that bar filters the op tree).
 *
 * `lib/toolkit/type-registry.js` documents every `IoType`. Producers and
 * consumers are **derived** from `STEPS`, not listed by hand, so a card cannot
 * advertise an op that no longer exists — and `host`, `peer`, and `item` are
 * honestly labelled *reserved* because nothing touches them yet.
 *
 * Four types carry a `literal` and can be written down directly rather than
 * reached via `input | cast`: `bytes`, `text`, `int`, `bool`. `int` accepts
 * `0x` / `0b` / `0o` and `_` separators, validating more strictly than the
 * engine's `Number()` so a typo fails at the field instead of becoming a
 * plausible-looking key length, and reports the other notation, byte length,
 * and endianness (§31b). A constructor resolves to a real registry step
 * (`instantiateTypeLiteral`, mirroring `instantiateFormatPick`) and is appended
 * through the ordinary caret path, so literals get the same insert semantics as
 * any op. Everything else can only be *produced*, so those cards list the ops
 * that produce them instead of offering an editor that could not work.
 *
 * A type with more than one legitimate origin carries `origins` instead (§31c)
 * — a segmented picker where each choice inserts a real step. `keypair` is the
 * first: **Generate** inserts `genkey` itself (not a copy of its form), and
 * **Import** inserts the `keypair` source for a pair the user already has.
 * That source takes its JWK/PEM through `unresolvedInputs`, the same runtime
 * channel `input` uses, because a pasted private key must never reach the
 * recipe text and from there a share link or a saved workspace — the recipe
 * records only `keypair jwk`. It accepts a PKCS#8 and an SPKI block *together*:
 * WebCrypto cannot recover a public half from PKCS#8, so a lone private block
 * genuinely cannot satisfy a later `export spki`.
 *
 * The type constructors live in a `types` shelf **inside** the I/O toolbox
 * rather than replacing it. The design's "Input / output" category was seven
 * generic input ops; this registry's is mostly real ops (`random`,
 * `passphrase`, `qr`, `out`) that are not types and must stay.
 *
 * Reference links live in `lib/toolkit/step-docs.js` — kept out of the registry
 * because a URL is documentation, not part of a step's contract. `ToolCard`
 * renders one per step (MDN for the exact call, RFC for the wire format);
 * compact/hover cards omit it, since a link in a pop-over is unreachable.
 *
 * ## Surfaces

| URL | Entry | Role |
|-----|-------|------|
| `/toolkit` | `pages/toolkit.tsx` → `ToolkitShell` | Production — the React shell |
| `/toolkit-widgets` | catalog page | Widget states for review |

## Uniformity rules
 *
 * - One glyph renderer; lucide only for non-op chrome.
 * - One tool-docs surface (`ToolCard`); placement modes are not forks.
 * - One chip (`SuggestChip` variants).
 * - One insert affordance (`InsertGap`).
 * - One param editor (`ParamField`); Cards and inline edit share it.
 * - Preview chip editor is `RecipeChipFlow` (legacy mounts via `mountRecipeChipFlow`).
 * - Cell `#suggest-next` and Cards nest rails use `SuggestRail` (toolbox + pull-out).
 * - Toolbar **More** menu uses `MenuPopover` (`mountMenuPopover`).
 * - Templates gallery uses `PresetMenu` (`mountPresetMenu`) — companion pairs + Append.
 *
 * ## DnD MIME
 *
 * | MIME | Meaning |
 * |------|---------|
 * | `application/x-basilisk-step` | JSON `{ name, decode }` — add op |
 * | `application/x-basilisk-decode` | `"1"` when decode direction |
 * | `application/x-basilisk-reorder` | Stem index (builder cards) |
 * | `application/x-basilisk-chip-reorder` | JSON chip path (Preview chips) |
 * | `text/plain` | Fallback; chip reorder may use `basilisk-chip:{json}` |
 *
 * ## React-native hosting
 *
 * Widgets mount directly as React components now (`RecipientBinderHost`-style
 * bridges only remain where the underlying logic is still a vanilla module,
 * e.g. `recipient-picker.js`, which `RecipientBinderHost.tsx` mounts via its
 * own `useEffect`/ref — no shared DOM-mount helper needed).
 *
 * Wired in `ToolkitShell`:
 * - **OpsShelf** (resizable/collapsible pane; includes AES/RSA / Formats / HMAC kits)
 * - **ToolCard** (hover / chip pop / Docs reference panel; Cards mode is a full
 *   builder — click a card to select, inline `ParamFieldGroup` editor)
 * - **ModeToggle** (cell Preview/Raw/Cards + PGP)
 * - **ParamField** (inline + Cards)
 * - **RecipeChipFlow** (Preview; `activeGap` highlights insert focus)
 * - **SuggestRail** (`#suggest-next` + Cards nest hosts, toolbox pull-out, tip-fit, compose chips)
 * - **MenuPopover** (toolbar More menu)
 * - **PresetMenu** (Templates gallery — companions / Append / Add both)
 *
 * ## Parity notes (post-cutover)
 *
 * Everything in the former cutover checklist is at parity with what legacy had, except
 * the WebCrypto `key` runtime binder (JWK / peer JWK / wrap JWK / signature inputs for
 * sign/verify/aes-gcm/ecdh/wrap) — a known gap, tracked as follow-up work, not a blocker
 * since the legacy fallback no longer exists to fall back to.
 */

export {};
