import { GLYPH_PATHS } from "../../lib/toolkit/glyphs.js";
import { TOOLBOX_META, SHELF_META, getShelfMeta } from "../../lib/toolkit/registry.js";
import { cn } from "@/lib/cn";

export type GlyphSize = 16 | 18 | 22;

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

/**
 * Small toolbox-origin dot, matching the design's chip treatment (color, not
 * icon). Network/WebRTC types (design v2 §25a) additionally get a *shape* —
 * diamond / square / triangle / hollow ring — because a live socket handle
 * shouldn't read as an ordinary data value at a glance. Pure CSS at the same
 * 5-7px footprint every dot already occupies; no icon assets.
 */
export function ToolboxDot({
  op,
  className,
}: {
  op: { toolbox?: string; output?: string };
  className?: string;
}) {
  const kind = shapeForType(op.output);
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
      aria-hidden
    />
  );
}
