import {
  Activity,
  AlignLeft,
  Binary,
  Box,
  Boxes,
  Cable,
  FileDown,
  IdCard,
  Network,
  Radio,
  ScrollText,
  Shield,
  Signature,
  ToggleLeft,
  Users,
  type LucideIcon,
} from "lucide-react";
import { GLYPH_PATHS } from "../../lib/toolkit/glyphs.js";
import { Glyph, type GlyphSize } from "./Glyph";

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
 *
 * **The six key roles are the exception, and they earn it.** They draw
 * project glyphs (`GLYPH_PATHS`), so a value here is either a lucide
 * component or a glyph id. The uniformity rule exists to stop two icon
 * systems drifting over the same concept; here the *concept* needs three
 * marks that differ by a measured amount, and lucide has one key. Drawing a
 * public key and a private key with the same pictogram is the drift that rule
 * was written against, not a case of it.
 */
export const KIND_GLYPHS: Record<string, LucideIcon | string> = {
  bytes: Binary,
  /*
   * The six key roles draw project glyphs, not lucide, because lucide has one
   * key and this vocabulary needs three.
   *
   * Every one of them was `KeyRound` until now — including the two comments
   * below this line, each a past agent adding a role so it "would not be the
   * only key artifact wearing a badge with no pictogram", and each correct
   * about that and silent about the half. One glyph for a public key and a
   * private one is the same defect the tint had a commit ago, one channel
   * over: the map asserted a family, and the family was all it could assert.
   *
   * The bow carries it. Filled means the key holds something; hollow means it
   * does not. Measured off the rasterised asset, bow-region ink is 13.1 for
   * `key-secret` against 7.4 for `key-public` — a **1.77×** mass difference,
   * stable at 12, 16 and 24px. It is mass rather than detail on purpose: a
   * gap in the bow and a dot beside it were both tried and both collapse at
   * 12px, which is the size this badge actually draws at.
   *
   * `key` is on the secret side, and that is the honest reading rather than a
   * cautious one: `ARTIFACT_ROLES` documents it as "public or private", and
   * the engine emits `role: secret ? "secret-key" : "key"` for a held half
   * with `sensitive: true`. So `key` means private, or genuinely unknown —
   * never definitely public. Unknown over-warns, for the same asymmetry
   * `badgeTier` below is built on.
   */
  key: "key-secret",
  keypair: "key-pair",
  "ssh-public": "key-public",
  "ssh-private": "key-secret",
  "public-key": "key-public",
  "secret-key": "key-secret",
  /*
   * The seventh key, and the one the split above could not absorb.
   *
   * `openpgp-key` is a *type* rather than a role — no entry in
   * `ARTIFACT_ROLES` wears it — and it is the type `gpg.genkey`, `hkp.get`,
   * `agent.unlock`, `agent.pub` and `agent.save` declare. Left unmapped it
   * drew nothing at all, so the shelf printed `needs openpgp-key` in words
   * beside rows whose types have had a mark since §35.
   *
   * It could not reuse `key-public` or `key-secret`, which is what `ssh-public`
   * and `ssh-private` already draw: an OpenPGP key would then be a *third*
   * concept sharing a pictogram with two others, which is the defect this map
   * was rewritten against one commit above. `key-openpgp` differs by a whole
   * arm rather than by a detail — the shank drops to a second shank with its
   * own bit — because subkeys are what the type's own doc names as the thing
   * an OpenPGP key carries and a CryptoKey has no room for. Not the armour
   * bar `gpg-genkey` wears: that doc says this type is the packet structure
   * "not the armored text around it", so armour would be a mark for the one
   * thing it is not.
   *
   * Measured the way the bow split was, rasterised at 12px: per-pixel L1 of
   * 28.3 against `ssh` and 35.7 against `key-secret`, where `key-public`
   * against `key-secret` — the pair this file already ships as unmistakable
   * at this size — is 6.2.
   *
   * The bow is filled, and that is the same asymmetry `key` is decided on: an
   * OpenPGP key is public or private and this type cannot know which, so the
   * neighbour it is likeliest to be mistaken for should be the secret one.
   * Over-warning costs a reading; under-warning hands out a private key.
   *
   * Deliberately absent from `KEY_GLYPH_TIERS` below, which is the artifact
   * badge's sensitivity axis: this glyph never renders on a badge, because an
   * OpenPGP key whose half is known arrives as the `openpgp-public` or
   * `openpgp-private` *kind* and draws `key-public`/`key-secret` there. There
   * is no tint beside it to agree or disagree with, and a tier here would
   * assert one where none is painted.
   */
  "openpgp-key": "key-openpgp",
  share: Users,
  diag: Activity,
  stats: Activity,
  connstate: Activity,
  secret: Shield,
  signature: Signature,
  artifact: FileDown,
  bundle: Boxes,
  endpoint: Network,
  candidate: Radio,
  session: Cable,
  /*
   * The four remaining pipeline types, all lucide, all chosen at 12px.
   *
   * `bool` is a switch and not a tick. A tick or a cross names *one* of the
   * two values, and the five steps that produce a bool are all verifications
   * — `verify`, `gpg.verify`, `ssh.verify`, `otp.verify`, `run.verify` — whose
   * whole point, in the type's own words, is that "a failed verification is
   * `false`, not an error". A mark that draws the passing case would be a
   * claim about a value that has not been computed yet. A toggle draws the
   * two-valuedness and asserts neither.
   *
   * `sdp` is a written description. The type is "text on the wire, but typed
   * distinctly so an offer cannot be fed where an answer belongs", so the mark
   * says *document*, not *direction* and not *agreement*: a handshake asserts
   * the two ends met, which is exactly what an unanswered offer has not done,
   * and a paired arrow claims the horizontal band `ports` owns.
   *
   * `item` is one of `bundle`. Drawing it as the singular of `Boxes` is the
   * relation itself, and at 12px it is a mass difference rather than a
   * spot-the-cube one: 38.9 of ink against 53.8, L1 48.3 apart.
   *
   * `certificate` is a DTLS certificate, and the type's doc says what it does
   * in four words — it "identifies one end". An identity card says that and
   * nothing more; a rosette or a shield-with-tick would say the certificate
   * was *trusted*, and a self-signed one asserts nothing of the sort.
   *
   * Each was measured against every lucide icon this map already draws,
   * rasterised at 12px: the closest pair is `certificate` against `text` at
   * L1 23.9, and the smallest margin any of the four has is 3.8× the 6.2 that
   * separates `key-public` from `key-secret`.
   */
  bool: ToggleLeft,
  sdp: ScrollText,
  item: Box,
  certificate: IdCard,
  /*
   * `any` is deliberately not here, and it is not an omission.
   *
   * It is the only name in the step vocabulary that is not a type: the type
   * registry does not list it (`listTypes()` returns 23 entries and `any` is
   * none of them), and the nine steps that declare it — `text`, `out`,
   * `inspect`, `tee`, `peek`, `select`, `publish`, `clipboard.write`,
   * `file.save` — are the sinks and the pass-throughs, the ones that place no
   * constraint at all. A pictogram for "anything" is a picture of nothing: it
   * would have to be recognisable, so it would have to look like *something*,
   * and whatever that something was would be a claim these steps do not make.
   *
   * It costs nothing on screen either, because a step whose input is `any`
   * accepts the caret whatever the caret is holding, so it never prints a
   * `needs …` caption for a glyph to sit beside. Unmapped is the honest
   * rendering and the one that never appears.
   */
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
 * Whether a badge's artifact carries secret material — the second axis.
 *
 * `"unstated"` is a value rather than an absence so the vocabulary is visible
 * in the DOM and a test can enumerate it. It is what a kind that declines to
 * guess produces, and it renders exactly as the family's own hue: no claim.
 */
export type BadgeTier = "secret" | "public" | "unstated";

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
 * Whether a badge carries secret material — the second axis (§35).
 *
 * `badgeFamily` above answers *what kind of thing this is*, and one commit ago
 * it was made to answer it the same way for all six key roles, which was
 * right: they wear one glyph, so they are one family. But the family is the
 * only axis it has, and on the axis that matters most `SSH-PRIVATE` and
 * `SSH-PUBLIC` were rendered identically — a private half and a public one,
 * the same rgb(76,222,130), told apart by a 9px word and a chip 330px to the
 * right of it. Two of the six roles do not even have the word: `KEY` and
 * `KEYPAIR` name no half.
 *
 * So this is a *modifier*, not a replacement. A badge keeps its family's hue
 * until this returns `"secret"`. Both attributes ride the element, both are
 * closed vocabularies, and `toolkit.css` enumerates them — the shape
 * `data-action-tier` established and `data-badge-family` adopted.
 *
 * **A claim of secrecy from either source wins**, and the asymmetry is the
 * reason: rendering a secret as public hands someone a private key believing
 * it is a public one, and rendering a public key as secret costs a magenta
 * chip. Only the first is a disclosure, so only the first gets guarded
 * against. A kind that declares nothing — `key`, which by construction does
 * not know which half it holds — falls through to the engine's own flag.
 *
 * @param declared The resolved kind's `sensitivity`, or undefined.
 * @param sensitive The artifact's own `sensitive` flag.
 */
export function badgeTier(
  declared: "secret" | "public" | undefined,
  sensitive: boolean | undefined
): BadgeTier {
  if (sensitive || declared === "secret") return "secret";
  return declared === "public" ? "public" : "unstated";
}

/**
 * The three key glyphs, and which side of the axis each is on.
 *
 * Declared as data rather than left implicit in `KIND_GLYPHS` for the reason
 * `KEY_BADGE_KINDS` is: the pairing of a role to a *sensitivity* is the thing
 * that can silently go wrong, and it goes wrong by omission. A test walks
 * this against `sensitivity` in the kind table, so a key role whose glyph
 * says public while its kind says secret fails CI rather than shipping.
 */
export const KEY_GLYPH_TIERS: Readonly<Record<string, "secret" | "public">> = {
  "key-secret": "secret",
  "key-pair": "secret",
  "key-public": "public",
};

/**
 * Does this name resolve to something drawable?
 *
 * A kind's `glyph` field may name either vocabulary — a `KIND_GLYPHS` key or
 * a `GLYPH_PATHS` id — and after the key split it names the latter. The two
 * namespaces were conflated while every key kind pointed at one lucide icon,
 * which is part of how `openpgp-public` and `openpgp-private` came to declare
 * the *same* glyph.
 */
export function glyphExists(id: string | undefined | null): boolean {
  if (!id) return false;
  return Boolean(GLYPH_PATHS[id] || KIND_GLYPHS[String(id).toLowerCase()]);
}

/**
 * Glyph for a value kind, or null when none applies.
 *
 * Returns either a lucide component or a `GLYPH_PATHS` id — the key roles use
 * the project renderer, everything else stays lucide chrome.
 *
 * @param kind `OutputArtifact.kind`, a pipeline type name, or a role
 */
export function kindGlyph(kind: string | undefined | null): LucideIcon | string | null {
  if (!kind) return null;
  const k = String(kind).toLowerCase();
  // The order stopped mattering, and that is the point. It used to be a
  // precedence rule justified by an example that was not a conflict at all --
  // `share` is `Users` here and `shares` is an asset in `GLYPH_PATHS`, which
  // are two different names that never met. Where names really did meet,
  // precedence silently threw the drawn mark away: `text`, `shares`,
  // `recipients`, `inspect` and `channel` each had a purpose-drawn asset that
  // no consumer of this function could reach, so `inspect` drew the same
  // `Binary` as `bytes` while a magnifying glass sat unused, and a `recipients`
  // toolbox tab drew two people while a `recipients` badge drew `Users`.
  //
  // The invariant now is that no name is in both maps -- pinned by
  // `glyph-shadowing.test.js`, which is what keeps this `||` unable to shadow
  // anything again. If a name needs a drawn mark, it goes in `GLYPH_PATHS` and
  // comes out of here.
  return KIND_GLYPHS[k] || (GLYPH_PATHS[k] ? k : null);
}

/**
 * Renders the kind's glyph at badge size, or nothing.
 *
 * 12px is the default because that is what the artifact badge draws, and it
 * is the size the key glyphs' 1.77× bow-mass difference was measured at.
 */
export function KindGlyph({
  kind,
  size = 12,
  className,
}: {
  kind: string | undefined | null;
  /**
   * On the glyph scale, because this hands `size` straight to `Glyph`, which
   * only draws the scale. It was `number` with a cast at the call below, which
   * made an off-scale badge a compile-time success and a design-system
   * violation. Every caller was already on the scale.
   */
  size?: GlyphSize;
  className?: string;
}) {
  const glyph = kindGlyph(kind);
  if (!glyph) return null;
  if (typeof glyph === "string") {
    // A project glyph. `svgClassName` drops the `ops-glyph` default, which
    // sizes and colours for the ops drawer — a badge sets both itself.
    return (
      <Glyph
        id={glyph}
        size={size}
        className={className}
        svgClassName="shrink-0"
      />
    );
  }
  const Icon = glyph;
  return <Icon size={size} strokeWidth={2} className={className} aria-hidden />;
}
