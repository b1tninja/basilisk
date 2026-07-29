/**
 * Toolkit widget catalog — shared UI building blocks.
 *
 * Source of truth: `web/src/toolkit/widgets/`.
 * Live states: `/toolkit-widgets`.
 * Production toolkit still loads legacy (`toolkit.html` → `toolkit-legacy.js`);
 * React shell (`toolkit-app.tsx`) and catalog consume these widgets.
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
 *
 * ## Surfaces

| URL | Entry | Role |
|-----|-------|------|
| `/toolkit` | `toolkit-legacy.js` | Production full notebook (widget islands) |
| `/toolkit-react` | `toolkit-app.tsx` → `ToolkitShell` | React shell consuming the catalog |
| `/toolkit-legacy` | same as `/toolkit` | Alias for the notebook surface |
| `/toolkit-widgets` | catalog page | Widget states for review |

**Cutover:** when React parity is ready, point `toolkit.html` at `/src/toolkit/toolkit-app.tsx` (one-line flip). Do **not** flip until the checklist below is green.

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
 * ## Legacy islands
 *
 * Prefer stable host nodes + `renderIsland` / `ensureRoot` from
 * `web/src/toolkit/widgets/mount.tsx` (same pattern as RecipientBinderHost).
 * Pass tip-fit / insert focus as props — do not import legacy module `let`s.
 *
 * Wired today:
 * - **OpsShelf** (drawer; includes AES/RSA / Formats / HMAC kits)
 * - **ToolCard** (hover / chip pop / Docs reference panel)
 * - **ModeToggle** (cell Preview/Raw/Cards + PGP)
 * - **ParamField** (inline + Cards)
 * - **RecipeChipFlow** (Preview; `activeGap` highlights insert focus)
 * - **SuggestRail** (`#suggest-next` + Cards nest hosts via `mountSuggestRail`)
 * - **MenuPopover** (More menu via `mountMenuPopover`)
 * - **PresetMenu** (Templates gallery via `mountPresetMenu` — companions / Append / Add both)
 *
 * Production `/toolkit` stays on legacy until React shell parity is complete.
 *
 * ## React shell vs legacy (cutover checklist)
 *
 * | Area | Legacy | ToolkitShell (`/toolkit-react`) | Ready? |
 * |------|--------|----------------------------------|--------|
 * | Templates gallery | `PresetMenu` island | `PresetMenu` (same widget) | yes |
 * | More menu | `MenuPopover` | `MenuPopover` | yes |
 * | Ops shelf | `OpsShelf` island | `OpsShelf` | yes |
 * | Preview chips | `RecipeChipFlow` + `activeGap` | same | yes |
 * | Preview/Raw/Cards | `ModeToggle` per cell | `ModeToggle` + raw textarea + Cards `ToolCard` list | partial (Cards are docs-only, not full builder cards) |
 * | Cell suggest-next | `SuggestRail` toolbox + tip-fit pull-outs | `SuggestRail` items slice (no tip-fit / toolbox pull-out yet) | no |
 * | Session tray | Agent / Keychain / Trust tray | Keyring + Variables sheets only | no |
 * | Variables drawer | Full slot actions (in / out / inspect) | Sheet list only | no |
 * | Crypto params panel | Full OpenPGP profile sheet | Sheet stub / ModeToggle PGP only | no |
 * | Runtime binders | Shares / GPG / text / recipients per cell | Text + RecipientBinderHost (partial) | partial |
 * | Workspace library / save / import | Full | Missing | no |
 * | Pane resize / collapse / prefs form | Full | Missing | no |
 * | Suite status / FIPS chrome | Full | Status text only | no |
 *
 * Flip production only when session tray, tip-fit suggest rails, workspace library,
 * and full Cards builder parity are covered (or consciously deferred with UX sign-off).
 */

export {};
