import {
  Activity,
  AlignLeft,
  Binary,
  Boxes,
  Cable,
  FileDown,
  KeyRound,
  Network,
  Radio,
  Shield,
  Signature,
  Users,
  type LucideIcon,
} from "lucide-react";

/**
 * Pictograms for chrome — one map, every screen (design v2 §35).
 *
 * The codebase's uniformity rule (`docs/TOOLKIT-WIDGETS.md`) is "one glyph
 * renderer [op icons only]; lucide only for non-op chrome". Kind badges and
 * tray tabs are chrome: they label a surface, they do not stand for an op.
 *
 * This map is shared so a kind can never show one pictogram in an output row
 * and a different one on a type card. Anything unmapped renders no glyph
 * rather than a guessed one — a wrong icon reads as a wrong claim.
 *
 * Deliberately NOT covered: the `candidate` / `session` / `channel` /
 * `connstate` dots from §25a. Those stay abstract CSS shapes. A pictogram
 * asserts a real-world reading — a plug for "session" implies *connected*
 * even mid-negotiation — and the abstraction exists precisely to avoid that.
 * Rule: a value's live/handle state → abstract shape; chrome label → lucide.
 */
export const KIND_GLYPHS: Record<string, LucideIcon> = {
  text: AlignLeft,
  bytes: Binary,
  key: KeyRound,
  keypair: KeyRound,
  "openpgp-key": KeyRound,
  share: Users,
  shares: Users,
  recipients: Users,
  diag: Activity,
  stats: Activity,
  connstate: Activity,
  inspect: Binary,
  secret: Shield,
  signature: Signature,
  artifact: FileDown,
  bundle: Boxes,
  endpoint: Network,
  candidate: Radio,
  session: Cable,
  channel: Cable,
};

/**
 * Glyph for a value kind, or null when none applies.
 * @param kind `OutputArtifact.kind`, a pipeline type name, or a role
 */
export function kindGlyph(kind: string | undefined | null): LucideIcon | null {
  if (!kind) return null;
  return KIND_GLYPHS[String(kind).toLowerCase()] || null;
}

/** Renders the kind's glyph at badge size, or nothing. */
export function KindGlyph({
  kind,
  size = 12,
  className,
}: {
  kind: string | undefined | null;
  size?: number;
  className?: string;
}) {
  const Icon = kindGlyph(kind);
  if (!Icon) return null;
  return <Icon size={size} strokeWidth={2} className={className} aria-hidden />;
}
