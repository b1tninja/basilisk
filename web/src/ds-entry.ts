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

/**
 * Overlay and control primitives — added for the shared-notebook surfaces.
 *
 * Without these the design tool has no dialog, no menu and no tooltip, so any
 * screen needing one gets an invented panel that matches nothing in this repo.
 * Every session and peer flow below is a dialog or a menu, which made their
 * absence the actual blocker rather than a gap in the widget list.
 *
 * Each is a compound whose parts must travel together — `SheetContent` outside
 * a `Sheet` has no portal to render into — so the subcomponents are exported
 * for the same reason `GateFact` is, and only the roots get map entries.
 */
export {
  Sheet, SheetTrigger, SheetClose, SheetPortal, SheetOverlay,
  SheetContent, SheetHeader, SheetFooter, SheetTitle, SheetDescription,
} from "./components/ui/sheet";
export {
  DropdownMenu, DropdownMenuTrigger, DropdownMenuGroup, DropdownMenuPortal,
  DropdownMenuSub, DropdownMenuRadioGroup, DropdownMenuContent, DropdownMenuItem,
  DropdownMenuSubTrigger, DropdownMenuSubContent, DropdownMenuSeparator,
  DropdownMenuLabel,
} from "./components/ui/dropdown-menu";
export { TooltipProvider, Tooltip, TooltipTrigger, TooltipContent } from "./components/ui/tooltip";
export { ToggleGroup, ToggleGroupItem } from "./components/ui/toggle-group";

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
 * The encoder behind `QrArtifact`, exported for the same reason
 * `buttonVariants` is: the card takes SVG markup, and without the function
 * that produces it nobody downstream can make one. A QR is also the offline
 * half of sharing, so a design that shows a code needs to be able to generate
 * a real one rather than paste a picture of somebody else's.
 *
 * Not in `componentSrcMap` — it renders nothing on its own.
 */
export { qrSvg } from "./lib/qr.js";
/**
 * `GateFact` rides along with `GateBanner` because the banner cannot be used
 * without it. `facts` takes `<dt>`/`<dd>` pairs that must stay *direct*
 * children of the banner's grid — a wrapper element breaks the 68px column —
 * so the pairing is a real API constraint rather than a convenience. Exported
 * but deliberately not added to `componentSrcMap`: it is a fragment with no
 * standalone rendering, and it belongs on `GateBanner`'s card, not its own.
 */
export { GateBanner, GateFact } from "./toolkit/widgets/GateBanner";

/**
 * Shared-notebook surfaces — the session, its peers, and what gets shared.
 *
 * These were held back on the first sync under the coupling rule at the top of
 * this file, and the rule does not actually exclude them: checked rather than
 * assumed, none of the twelve reads context or a store, and each takes plain
 * props (`state`, `peers`, `cards`, `facts`). The genuinely coupled widgets are
 * still absent — `ToolCard`, `OutputList`, `OpsShelf`, `ToolkitShell` and the
 * rest need the op registry or the notebook itself.
 *
 * They belong here because the multi-party session is what the design tool is
 * being asked to draw next, and without them every dialog for inviting a peer,
 * showing a roster, or approving a handoff would be invented from scratch and
 * map onto none of this code.
 *
 * `quorum` in these files is not stale naming from the abandoned design. It is
 * two live things: the authenticated transport the notebook session sits on
 * top of (`quorum.offer`/`quorum.join` are implemented steps, and `origin:
 * "quorum"` is a live link kind), and — in `ShareCards` and `CeremonySheet` —
 * the Shamir threshold, where "any k of these n" is simply what a quorum is.
 */
export { CellAssign } from "./toolkit/widgets/CellAssign";
export { PlanPanel } from "./toolkit/widgets/PlanPanel";
export { ShareSheet } from "./toolkit/widgets/ShareSheet";
export { SessionStrip } from "./toolkit/widgets/SessionStrip";
export { ConnectionsPanel } from "./toolkit/widgets/ConnectionsPanel";
export { ApprovalBanner } from "./toolkit/widgets/ApprovalBanner";
export { ReadinessBar } from "./toolkit/widgets/ReadinessBar";
export { ModeToggle } from "./toolkit/widgets/ModeToggle";
export { PresetMenu } from "./toolkit/widgets/PresetMenu";
export { CeremonySheet } from "./toolkit/widgets/CeremonySheet";
export { DkgPanel } from "./toolkit/widgets/DkgPanel";
export { ShareCards } from "./toolkit/widgets/ShareCards";
export { ShareCheck } from "./toolkit/widgets/ShareCheck";
export { ShareIdentity } from "./toolkit/widgets/ShareIdentity";
