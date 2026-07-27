# Toolkit glyph assets

Source of truth for ops-drawer and toolkit chrome icons.

| Path | Role |
|------|------|
| `manifest.json` | Id, group, label, metaphor, description (and optional refs) |
| `svg/<id>.svg` | Exported stroke SVG (`viewBox="0 0 20 20"`) |
| `../scripts/build-glyphs.mjs` | Emits `src/lib/toolkit/glyphs.js` + `../../docs/GLYPHS.md` |

```bash
npm run glyphs          # rebuild module + docs
# also runs via predev / prebuild / pretest
```

Edit an SVG or the manifest, then rebuild. Do not hand-edit `src/lib/toolkit/glyphs.js`.

Full catalog: [docs/GLYPHS.md](../../docs/GLYPHS.md).
