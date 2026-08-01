# design-sync notes — Basilisk

## Shape

Basilisk is an **application**, not a published component library:
`web/package.json` is `private: true` with no `main`/`module`/`exports`, and
`web/dist/` holds built HTML pages, not a component dist. So:

- `shape: "package"`, and the converter has no library entry of its own.
- `web/src/ds-entry.ts` is a **hand-authored barrel** written for this sync —
  it re-exports exactly the components that render standalone. Pass it as
  `--entry web/src/ds-entry.ts`. Without it the converter synthesizes an entry
  by scanning all of `src/`, which sweeps in the coupled toolkit widgets
  (`ToolCard` needs the op registry, `OutputList` needs artifact fixtures,
  `ToolkitShell` needs the whole notebook) — none of which render alone.
- Nothing in the app imports `ds-entry.ts`. It exists so the synced surface is
  a reviewed decision rather than a side effect of a heuristic.

## Build command

```sh
cd web && npm run build          # produces dist/assets/toolkit-<hash>.css
cp web/dist/assets/toolkit-*.css web/.ds-styles.css
node .ds-sync/package-build.mjs --config .design-sync/config.json \
  --node-modules web/node_modules --entry web/src/ds-entry.ts --out ./ds-bundle
```

Do **not** run `npm ci` reflexively — `node_modules` is already installed and
green, and a reinstall can disrupt a concurrent session working in this tree.

## Gotchas hit on the first sync

- `cssEntry` is **package-relative and bounded to inside the package**. A path
  like `../.design-sync/.cache/compiled.css` is silently skipped with
  `resolves outside the package`. Hence `web/.ds-styles.css` (gitignored).
- The compiled stylesheet's filename is **content-hashed**, so it cannot be
  referenced directly from config. The `cp` step above stages it at a stable
  path; re-run it after every `npm run build` or the sync ships stale CSS.
- Without `--entry`, the converter looks for `node_modules/basilisk-portal/`
  and dies with ENOENT — npm never self-installs a package into its own repo.

## Known render warns

- `[RENDER_BLANK]` on any component with **no authored preview** is the
  typographic floor card, not a failure. On the first sync that was CastDot,
  KindGlyph, ScrollArea, Separator, ToolboxDot, Badge, Glyph, Input, Textarea.
- Previews render in the **light** colour scheme (headless default) while the
  product is dark-first. Both themes are supported and light was contrast-fixed
  on 2026-07-31, so this is legitimate — but it means the cards do not show the
  dark look the app usually wears.

## Re-sync risks

- **`web/.ds-styles.css` goes stale silently.** It is a copy, gitignored, and
  nothing rebuilds it automatically. If the toolkit's CSS changed and this file
  did not, every card renders against the old tokens with no warning.
- **`ds-entry.ts` drifts from the component set.** A component added to
  `componentSrcMap` but not exported from the barrel will not be in the bundle;
  the reverse ships a component nobody scoped. Keep the two in step.
- **Coupled widgets are excluded by omission, not by a rule.** Someone adding
  an export to `ds-entry.ts` silently widens the sync. That is the intended
  control point — but it is a control point, so review it.
- The `.d.ts` contracts come from source, not a real build, so prop types are
  weaker than a library build would give. Adding a proper library build to
  `web/` would improve them.
