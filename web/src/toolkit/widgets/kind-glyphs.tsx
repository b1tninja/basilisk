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
  // The badge string is the artifact's *role*, so the two SSH halves need
  // their own entries or they would be the only key artifacts wearing a
  // badge with no pictogram. Same key, so the same glyph: which half it is
  // the badge already says in words, and the `sensitive` badge beside it.
  "ssh-public": KeyRound,
  "ssh-private": KeyRound,
  // Same reason again: `public-key` and `secret-key` are roles, so they are
  // badge strings, and without an entry they would be the only key artifacts
  // wearing a badge with no pictogram. `public-key` was already reachable via
  // OpenPGP and already missing one.
  "public-key": KeyRound,
  "secret-key": KeyRound,
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
 * The roles that wear a key badge (§35, polish pass).
 *
 * Six of them, added over six commits by as many briefs, and until they were
 * rendered in one list nobody had seen what that cost: the *glyph* map above
 * says they are one family — every entry is `KeyRound`, and the two comments
 * in it are each an agent noticing that its role "would be the only key
 * artifact wearing a badge with no pictogram" — while the badge *tint* said
 * they were two. `key` and `keypair` were tinted `--brand`; `public-key`,
 * `secret-key`, `ssh-public` and `ssh-private` fell to the same `--caret` as
 * TEXT, SHARE and RECEIPT, measured at rgb(88,166,255) against the key
 * badge's rgb(76,222,130). The split was not public-versus-private — SSH-PRIVATE
 * and SECRET-KEY are both secret and both fell through — it was simply which
 * two roles existed when the tint was first written.
 *
 * So the family is declared once, here, beside the map that already assumes
 * it. A role added to `KIND_GLYPHS` as `KeyRound` and forgotten here is what
 * `kind-glyphs.test.js` fails on, which is the check that could not exist
 * while the answer lived in a ternary inside a tile.
 */
export const KEY_BADGE_KINDS: ReadonlySet<string> = new Set([
  "key",
  "keypair",
  "public-key",
  "secret-key",
  "ssh-public",
  "ssh-private",
]);

/** How a kind's badge is tinted — a closed three-value vocabulary. */
export type BadgeFamily = "key" | "diag" | "plain";

/**
 * Which tint a badge takes.
 *
 * Three values, so `toolkit.css` covers them with one enumerated rule set and
 * `style-src 'self'` never sees an inline write — the same shape as
 * `.artifact-action[data-action-tier]`, and for the same reason: a closed
 * vocabulary belongs in a stylesheet, not in a conditional at the call site
 * where the next role to be added will not find it.
 */
export function badgeFamily(kind: string | undefined | null): BadgeFamily {
  const k = String(kind || "").toLowerCase();
  if (k === "diag") return "diag";
  return KEY_BADGE_KINDS.has(k) ? "key" : "plain";
}

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
