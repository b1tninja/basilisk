import { GLYPH_PATHS } from "../../lib/toolkit/glyphs.js";
import { TOOLBOX_META, SHELF_META, getShelfMeta } from "../../lib/toolkit/registry.js";
import { toolboxVerification } from "../../lib/toolkit/suite-gate.js";
import type { SuiteStatusMap } from "../../lib/toolkit/suite-gate.js";
import { cn } from "@/lib/cn";

/**
 * 12 and 14 joined the set for the kind badge and the type card.
 *
 * 12 is not a rounding of 16: it is the size the artifact badge actually
 * draws at, inside a 9px-caps chip, and the sensitivity glyphs were measured
 * there — a filled bow carries 1.77× the ink of a hollow one at 12, 16 and
 * 24px, where a gap-in-the-bow and a dot both collapsed at 12. The 16px in
 * the ops drawer is a different surface.
 */
export type GlyphSize = 12 | 14 | 16 | 18 | 22;

type Props = {
  id: string;
  size?: GlyphSize;
  className?: string;
  /** Extra classes on the svg (legacy: ops-glyph ops-glyph-tile). */
  svgClassName?: string;
};

/** Single glyph renderer for op/toolbox icons (not lucide chrome). */
export function Glyph({
  id,
  size = 16,
  className,
  svgClassName = "ops-glyph",
}: Props) {
  const inner = GLYPH_PATHS[id];
  if (!inner) {
    return (
      <span className={cn("inline-flex font-bold leading-none", className)} aria-hidden>
        #
      </span>
    );
  }
  return (
    <svg
      className={cn(svgClassName, className)}
      width={size}
      height={size}
      viewBox="0 0 20 20"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.6"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden
      focusable="false"
    >
      <g dangerouslySetInnerHTML={{ __html: inner }} />
    </svg>
  );
}

/**
 * CAST status for a toolbox — whether its crypto suite passed the power-on
 * self-test this session.
 *
 * Rendered on the toolbox header, because that is the granularity of the
 * claim: the self-test qualifies a *suite*, so twenty rows under "OpenPGP"
 * all carry the same one bit. Stating it once, where the drawer names the
 * suite, is both less noise and a truer picture — a per-op light implies a
 * per-op test that does not exist.
 *
 * It drifted into being a toolbox-identity colour, which is both a weaker
 * signal and a misleading one: a green dot that means "this is the SSS
 * toolbox" reads exactly like a green dot that means "SSS self-tested clean".
 * Identity is the glyph's job — every op already has one.
 *
 * Only `openpgp`, `webcrypto` and `sss` make a CAST claim (`toolboxToSuite`).
 * Everything else renders nothing at all rather than a decorative dot,
 * because an indicator that is always present and never means anything is
 * how the original signal got lost.
 */
export function CastDot({
  op,
  status,
  className,
}: {
  op: { toolbox?: string };
  /** The gate's own map — three named suites, not an open string bag. */
  status?: SuiteStatusMap | null;
  className?: string;
}) {
  if (!status) return null;
  const state = toolboxVerification(op?.toolbox, status);
  if (state === "none") return null;
  const label =
    state === "verified"
      ? "self-test passed"
      : state === "error"
        ? "self-test FAILED — do not rely on this op"
        : "not self-tested yet";
  return (
    <span
      className={cn("cast-dot h-[6px] w-[6px] shrink-0 rounded-full", className)}
      data-cast={state}
      title={`${op?.toolbox || "suite"}: ${label}`}
      role="img"
      aria-label={label}
    />
  );
}

/** Resolve glyph id for a registry-like op. */
export function glyphIdFor(op: {
  glyph?: string;
  shelf?: string;
  toolbox?: string;
}): string {
  if (op.glyph) return op.glyph;
  if (op.shelf) {
    const fromShelf = (SHELF_META as Record<string, { glyph?: string }>)[op.shelf]?.glyph;
    if (fromShelf) return fromShelf;
    const meta = getShelfMeta(op.shelf);
    if (meta?.glyph) return String(meta.glyph);
  }
  return (TOOLBOX_META as Record<string, { glyph?: string }>)[op.toolbox || ""]?.glyph || "gear";
}

/** Toolbox accent color for a registry-like op — a chip's origin without reading the icon. */
export function toolboxColorFor(op: { toolbox?: string }): string {
  return (
    (TOOLBOX_META as Record<string, { color?: string }>)[op.toolbox || ""]?.color || "#8b949e"
  );
}

/**
 * Map a pipeline value type to its dot shape (design v2 §25a). Derived from
 * the op's real declared `output` type — not a parallel presentational field —
 * so the shape can never drift from what the type system actually enforces.
 */
export function shapeForType(output?: string): string | undefined {
  switch (output) {
    case "candidate":
    case "endpoint":
    case "host":
      // Addressing values — diamond.
      return "candidate";
    case "session":
    case "peer":
    case "certificate":
    case "sdp":
      // Session/identity values — square.
      return "session";
    case "channel":
      return "channel";
    case "connstate":
    case "stats":
      // Observe-only — hollow, "display me, don't consume me".
      return "connState";
    default:
      return undefined;
  }
}

/** What a §25a shape is claiming, in words — for the tooltip and the a11y name. */
const KIND_LABEL: Record<string, string> = {
  candidate: "an address",
  session: "a session or identity",
  channel: "a live channel — only valid inside this run",
  connState: "observe-only — can be displayed, not consumed",
};

/**
 * Small toolbox-origin dot, matching the design's chip treatment (color, not
 * icon). Network/WebRTC types (design v2 §25a) additionally get a *shape* —
 * diamond / square / triangle / hollow ring — because a live socket handle
 * shouldn't read as an ordinary data value at a glance. Pure CSS at the same
 * 5-7px footprint every dot already occupies; no icon assets.
 *
 * Where the type is ordinary DATA there is no shape, and callers that only
 * want the meaningful marks should skip the dot entirely rather than render a
 * plain coloured circle — see SuggestChip. The colour alone repeats what the
 * chip's own label already says, and a mark that is always present and never
 * distinguishes anything is how the CAST light got lost in the first place.
 */
export function ToolboxDot({
  op,
  className,
}: {
  op: { toolbox?: string; output?: string };
  className?: string;
}) {
  const kind = shapeForType(op.output);
  const label = kind ? KIND_LABEL[kind] : undefined;
  // Colour and shape both come from CSS now (`.toolbox-shape[data-toolbox]`
  // sets `color`, the shape rules paint with `currentColor`). This one
  // component renders once per op, so its single style prop was responsible
  // for ~76 of the ~79 inline styles on /toolkit — every one of them a write
  // `style-src 'self'` refuses in production. The toolbox palette is a closed
  // set (TOOLBOX_META), so a stylesheet can enumerate it; `toolbox-dot-css`
  // guards the two copies against drift.
  return (
    <span
      className={cn(
        "toolbox-shape inline-block shrink-0",
        kind !== "channel" && "h-[5px] w-[5px]",
        kind === "session"
          ? "rounded-[1px]"
          : kind === "candidate"
            ? "rotate-45 rounded-[1px]"
            : kind !== "channel" && "rounded-full",
        className
      )}
      data-toolbox={op.toolbox || "unknown"}
      data-kind={kind || undefined}
      /* A shape that encodes something gets a name; a bare colour dot stays
         decorative, because its colour repeats the label beside it. */
      title={label}
      role={label ? "img" : undefined}
      aria-label={label}
      aria-hidden={label ? undefined : true}
    />
  );
}
