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

/**
 * Artifact cards — the app's actual visual identity.
 *
 * These were absent when this surface was first drawn, and the exclusion has
 * outlived its reason. The rule above is "parts that render without the
 * notebook around them", and every card below meets it: each takes plain props
 * (`content`, `traits`, `jwk`, `alg`, …) and imports nothing from
 * `useNotebook`, `notebook-types` or the op registry. Checked, not assumed.
 *
 * They matter more than the primitives do. A design built from Basilisk's
 * Button and Badge but generic panels is not on-brand; these cards *are* what a
 * Basilisk screen looks like. `OtpCodeCard` even takes an injectable `nowMs`
 * precisely so a catalog can drive its countdown.
 *
 * Deliberately still absent: `KeypairCard` and the other view adapters in
 * `artifact-kinds/registry.tsx`. They take an `ArtifactViewContext` rather than
 * props — they are the glue between a kind and a card, not components. The card
 * underneath each one is what ships, and `KeyCard` is that card.
 */
export { KeyCard } from "./toolkit/widgets/KeyCard";
export { OpenPgpKeyCard } from "./toolkit/widgets/OpenPgpKeyCard";
export { SshKeyCard } from "./toolkit/widgets/SshKeyCard";
export { SshSigCard } from "./toolkit/widgets/SshSigCard";
export { OtpCodeCard } from "./toolkit/widgets/OtpCodeCard";
export { NetworkArtifact } from "./toolkit/widgets/NetworkArtifact";
export { PacketMapCard } from "./toolkit/widgets/PacketMapCard";
export { ReceiptCard } from "./toolkit/widgets/ReceiptCard";
export { RecipientsCard } from "./toolkit/widgets/RecipientsCard";
export { QrArtifact } from "./toolkit/widgets/QrArtifact";
/**
 * `GateFact` rides along with `GateBanner` because the banner cannot be used
 * without it. `facts` takes `<dt>`/`<dd>` pairs that must stay *direct*
 * children of the banner's grid — a wrapper element breaks the 68px column —
 * so the pairing is a real API constraint rather than a convenience. Exported
 * but deliberately not added to `componentSrcMap`: it is a fragment with no
 * standalone rendering, and it belongs on `GateBanner`'s card, not its own.
 */
export { GateBanner, GateFact } from "./toolkit/widgets/GateBanner";
