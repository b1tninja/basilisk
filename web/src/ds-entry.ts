/**
 * Design-system export surface, for `/design-sync`.
 *
 * Basilisk is an application, not a published component library: its
 * `package.json` is `private` with no `main`/`module`/`exports`, so the sync
 * converter has no library entry to bundle. Left to synthesize one, it would
 * scan all of `src/` and sweep in the coupled toolkit widgets — `ToolCard`
 * needs the op registry, `OutputList` needs artifact fixtures, `ToolkitShell`
 * needs the whole notebook — none of which render standalone.
 *
 * So the surface is declared here instead of discovered: exactly the parts
 * that stand on their own and carry Basilisk's look. That makes what ships to
 * the design tool a reviewable decision rather than a side effect of a
 * heuristic, and keeps a coupled widget from silently appearing in the next
 * sync because someone added an export.
 *
 * Nothing in the app imports this file; it exists for the converter. It is not
 * a second implementation of anything — every name below is re-exported from
 * the module the app itself uses.
 */

// Primitives — shadcn-derived, styled by this repo's tokens.
export { Button, buttonVariants } from "./components/ui/button";
export { Badge } from "./components/ui/badge";
export { Input } from "./components/ui/input";
export { Textarea } from "./components/ui/textarea";
export { Separator } from "./components/ui/separator";
export { ScrollArea } from "./components/ui/scroll-area";

// Toolkit parts that render without the notebook around them.
export { SuggestChip } from "./toolkit/widgets/SuggestChip";
export { ArtifactAction } from "./toolkit/widgets/ArtifactAction";
export { Glyph, CastDot, ToolboxDot } from "./toolkit/widgets/Glyph";
export { KindGlyph } from "./toolkit/widgets/kind-glyphs";
