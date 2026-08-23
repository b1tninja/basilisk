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

/**
 * The fingerprint, which is a primitive here for the same reason `Button` is.
 *
 * It is not a toolkit widget: it is on the keyserver search page, on the key
 * cards, in the roster, in the invite and in the Keyring, and it is the only
 * way a fingerprint is drawn in any of them. A design tool without it will draw
 * one — and what it will draw is `AABBCCDD…EEFF`, because that is what every
 * screenshot of this app used to show and what every other product shows. That
 * form is the thing this component exists to remove.
 *
 * `fingerprintActions` rides along for the reason `startIssues` does: the
 * component renders a menu of rows it does not write, and a catalog with no
 * access to the function can only invent labels and refusals that will drift
 * from the product's. Not in `componentSrcMap` — it renders nothing on its own.
 */
export { Fingerprint, fingerprintActions, ALREADY_IN_ROOM } from "./components/ui/fingerprint";

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
/**
 * The session's own surfaces — naming a room, watching one, and the cells that
 * cross between machines.
 *
 * `ShareSheet` could always *say* a live session existed and had no way to open
 * one; these are the flow itself. They meet the rule at the top of this file for
 * the same reason the twelve above do — each takes plain props and reads no
 * context — and `SessionSheet` is the only one that is a portal, which is why it
 * carries a `primaryStory` in `.design-sync/config.json`.
 */
/**
 * The vault, which is now a panel in the notebook rather than a page.
 *
 * It belongs on this surface for the rule at the top of the file, checked
 * rather than assumed: it takes plain props (`keys`, `now`, callbacks that
 * return promises) and imports no store, no vault and no `useNotebook`. The
 * acts are the shell's; what ships here is the panel and its states.
 *
 * `keyPowerReadout` rides along for the reason `startIssues` does — the rows
 * draw a badge and a sentence they do not write, and a catalog without the
 * function can only invent wording that will drift from the product's. The five
 * states are the whole design; a design tool that had to guess them would guess
 * "unlocked/locked", which is the two-state model this replaced.
 */
export { KeyVault } from "./toolkit/widgets/KeyVault";
export {
  KEY_POWERS,
  keyPower,
  keyPowerReadout,
  loadedCount,
  strongestPower,
} from "./lib/toolkit/key-power.js";
export { InviteCard } from "./toolkit/widgets/InviteCard";
export { SessionStart } from "./toolkit/widgets/SessionStart";
export { SessionLive } from "./toolkit/widgets/SessionLive";
export { SessionSheet } from "./toolkit/widgets/SessionSheet";
export { HandoffQueue } from "./toolkit/widgets/HandoffQueue";
/**
 * The derivations those five render, exported for the same reason `qrSvg` is:
 * the components draw sentences they do not write, so a catalog with no access
 * to the functions can only paste prose that will drift from the product's.
 * `startIssues` in particular is what decides whether Start is available, so a
 * design showing a refusal has to be able to produce the real one.
 *
 * Not in `componentSrcMap` — they render nothing on their own.
 */
export {
  confirmationReadout,
  rosterCounts,
  sessionReadout,
  sessionStage,
  startIssues,
  START_OPENS,
  INVITE_CARRIES,
  INVITE_OMITS,
} from "./lib/toolkit/session-flow.js";
export { SessionStrip } from "./toolkit/widgets/SessionStrip";
export { ConnectionsPanel } from "./toolkit/widgets/ConnectionsPanel";
export { ApprovalBanner } from "./toolkit/widgets/ApprovalBanner";
export { ReadinessBar } from "./toolkit/widgets/ReadinessBar";
export { ModeToggle } from "./toolkit/widgets/ModeToggle";
export { PresetMenu } from "./toolkit/widgets/PresetMenu";
export { CeremonySheet } from "./toolkit/widgets/CeremonySheet";
export { DkgPanel } from "./toolkit/widgets/DkgPanel";
export {
  PoolPanel,
  type PoolPanelProps,
  type PoolParticipant,
} from "./toolkit/widgets/PoolPanel";
/**
 * The room's cell ticker, added because it meets this file's own test.
 *
 * The rule here is "parts that stand on their own", and it is the reason most
 * toolkit widgets are absent: `ToolCard` needs the op registry, `OutputList`
 * needs artifact fixtures. `RoomCells` imports `cn` and `Fingerprint` and
 * nothing else — both already exported above — so it renders from plain props
 * with no notebook behind it.
 *
 * Its types travel with it. The table's whole subject is which outputs are face
 * up and which are only known to exist, and a design tool handed the component
 * without `SlotFace` cannot express that distinction to draw it.
 */
export {
  RoomCells,
  type PeerCellRow,
  type SlotFace,
} from "./toolkit/widgets/RoomCells";
export { ShareCards } from "./toolkit/widgets/ShareCards";
export { ShareCheck } from "./toolkit/widgets/ShareCheck";
export { ShareIdentity } from "./toolkit/widgets/ShareIdentity";

/**
 * `IntegrityPanel`, which was the one widget this file left out.
 *
 * It was excluded because a browser bundle of it did not build: it reaches
 * `lib/module-integrity.js` through `deployment-check.js`, and that module
 * carried an `await import("node:crypto")` fallback written before Node exposed
 * WebCrypto globally. The branch was unreachable — it sits behind
 * `if (!globalThis.crypto?.subtle)` — but a bundler resolves a dynamic import
 * whether or not it runs, so the whole export surface failed on "Could not
 * resolve node:crypto". The line is gone and the module now refuses instead of
 * falling back, which is what `deployment-check.js` already says about having
 * two implementations of one security check.
 *
 * It needed no injectable in the end. The panel already renders from plain
 * props — `verdict` supplies the state and `live={false}` suppresses the
 * automatic run, which is how `pages/toolkit-widgets.tsx` has drawn its six
 * outcomes all along. Nothing about the component changed to get it here.
 */
export { IntegrityPanel, type IntegrityPanelProps } from "./toolkit/widgets/IntegrityPanel";
export { LIMIT_NOTE, type DeploymentVerdict } from "./lib/toolkit/deployment-check.js";
