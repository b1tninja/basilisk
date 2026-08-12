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
 * | **ShareCards** | Print-ready card per share (mnemonic, QR, index, threshold, label, date) |
 * | **CeremonySheet** | Guided key ceremony — quorum → split → verify → cards + playbook → receipt |
 * | **ShareCheck** | Custodian verification — one card, no session, against published commitments |
 * | **IntegrityPanel** | Verify-this-deployment — module root vs published pin, and its limits |
 * | **DkgPanel** | Distributed key generation session (design-ahead; not wired) |
 *
 * ## The key-ceremony kit
 *
 * `ShareCards` is the toolkit's only deliberate secret-to-paper surface, so it
 * is the one place where the reveal gate is a product decision rather than a
 * default: cards render masked, the unmask button says what printing does
 * (cleartext, spooling, print servers) instead of saying "Show", `Print` only
 * appears once revealed, and the gate re-arms on remount. Its `@media print`
 * block in `toolkit.css` *hides* a masked card set rather than printing rows of
 * bullets — a page of dots looks like a successful ceremony artifact once filed.
 *
 * `CeremonySheet` owns sequence and wording, never execution. Every stage's
 * work is ordinary notebook cells run through `useNotebook` on the same kernel
 * as the Run button, so a ceremony is reproducible by hand, visible in Source
 * view, and shareable as recipe text. Two rules live in
 * `lib/toolkit/ceremony.js` rather than in the component: the master secret is
 * never written to an `out` tile (a `tee` branch digests it in place), and
 * verification compares two SHA-256 digests rather than showing the recovered
 * secret. Verification is sequenced *before* printing — proving the shares
 * recombine after the room has dispersed is not a ceremony.
 *
 * The cards stage writes a **playbook** as well as printing cards, and the two
 * go in the same envelope. A card names the split, the threshold and the op
 * that recombines, because that is what fits on paper beside a mnemonic; what
 * it cannot hold is the order of the steps or what to do with the secret once
 * it is back, and that is exactly what a custodian is missing years later when
 * the dealer is gone. The playbook is a signed document (`playbook` /
 * `playbook.verify`) carrying the **recovery** recipe — deliberately not the
 * ceremony that produced it, since a procedure beginning `random 32 |
 * vss.split` would mint a fresh secret rather than recover theirs. It carries
 * no peers, no vault key ids and no pinned inputs, because unlike a run
 * manifest it is meant to be handed to somebody who was never in the room.
 *
 * ## The other end of the ceremony (`#sharecheck`)
 *
 * `ShareCards` makes cards; `ShareCheck` answers the question their holders
 * have months later. It is the surface for `vss.verify`, and the design rule it
 * exists to enforce is that **well-formed is not genuine**: a BLIP39 mnemonic
 * carries a checksum, so it can decode cleanly while proving nothing at all
 * about which split it came from. `share-only` is therefore its own state, in
 * its own (amber) tone, with wording that says explicitly that nothing has been
 * checked. The four tones are enumerated in `toolkit.css` and no rule derives
 * one from another, so that state cannot reach the verified appearance by
 * accident.
 *
 * A failed check does not blame the holder. The checksum has already ruled out
 * transcription, so the verdict names all three remaining causes — wrong
 * commitments, wrong ceremony, or an `sss` card that can never match any — and
 * says the check cannot tell them apart.
 *
 * Every verdict string lives in `lib/toolkit/share-check.js` and is unit-tested
 * as a string, because the wording *is* the feature; the verification itself
 * goes through `execVssVerify`, the same op `… | vss.verify` runs, and the
 * panel prints that recipe in a disclosure so the shortcut is visibly a
 * shortcut.
 *
 * Cards changed with it. `recoveryLine` is derived rather than hard-coded — the
 * footer said `sss.combine` for every card the ceremony has printed since it
 * switched to `vss.split`, which instructs a custodian to run an op that
 * rejects their shares, at the one moment nobody is available to ask. Cards now
 * also print the split id (from `publicKeyOf(commitments)`, a *label* for
 * noticing the wrong document, never a substitute for the check) or the words
 * "Unverifiable split" — the absence has to be legible on paper.
 *
 * ## Verify-this-deployment (`#integrity`)
 *
 * `IntegrityPanel` over `lib/toolkit/deployment-check.js`. It does not
 * re-implement the check: the comparison is `verifyModuleRootAgainstPins`, the
 * same function the boot path gates on. Four of its six outcomes mean *no
 * answer* (`unpinned`, `no-sri`, `unreachable`, `disagree`) and none of them is
 * drawn as success. The limitation — this check runs inside the page it is
 * checking — sits under every verdict including the successful one, uncollapsed,
 * because that is the verdict a reader stops reading at.
 *
 * The catalog earned its keep twice here. The live dev-server panel reported
 * "no integrity hashes" while printing a well-formed 64-hex root beside it —
 * `computeLoadedModulesRoot`'s self-digest fallback, rendered in the row a
 * careful reader is meant to compare against another machine. And
 * `toolkit-widgets.html` turned out to carry no CSP meta while
 * `toolkit-widgets` was missing from `STATIC_PAGES`, so the catalog was the one
 * page served without the report-only production policy. Both fixed.
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
 * | **JwtArtifact** | JWS/JWE reader — verdict banner, header/claims, live expiry bar |
 *
 * `JwtArtifact` renders any artifact carrying a `jose` body (set by the
 * `jose.*` ops via `meta.jose`). The verdict travels *on the artifact* rather
 * than being re-derived from the token text, because only the op that ran
 * knows whether a key checked out — a widget parsing the token itself could
 * report nothing but "unverified". Two rules it enforces: an unverified body
 * never reaches the verified appearance (no green anywhere, including the
 * `exp` row and the validity bar), and the expiry clock ticks live rather
 * than freezing at run time. Tones ride `data-jwt-tone` with the palette
 * enumerated in toolkit.css; the bar width is bucketed into twelfths because
 * a computed percentage would need an inline style the CSP refuses.
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

`DkgPanel` is deliberately absent from the shell: `lib/quorum/dkg.js` has the
rounds, the op that runs them over a live exchange does not exist, and the panel
is design-ahead of it. `lib/quorum/dkg-session.js` states its assumptions about
that op layer; `redesign/CAPABILITY-SURFACES.md` explains why the refusal path
was designed first. There is a **Start a new session** button and no **Exclude
them** button, because commitments are broadcast while shares are pairwise —
only the accuser saw the bad share, and building the eviction primitive without
the complaint round that adjudicates it would ship the vulnerability with a
nicer interface.

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
