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
  const color = toolboxColorFor(op);
  const kind = shapeForType(op.output);

  if (kind === "channel") {
    // CSS border-triangle: the box itself is transparent, the bottom border
    // paints the shape — so no width/height background applies here.
    return (
      <span
        className={cn("inline-block shrink-0", className)}
        style={{
          width: 0,
          height: 0,
          borderLeft: "3.5px solid transparent",
          borderRight: "3.5px solid transparent",
          borderBottom: `6px solid ${color}`,
        }}
        aria-hidden
        data-kind="channel"
      />
    );
  }

  return (
    <span
      className={cn(
        "inline-block h-[5px] w-[5px] shrink-0",
        // connState is observe-only — hollow reads as "don't consume this".
        kind === "connState" ? "rounded-full" : kind === "session" ? "rounded-[1px]" : "rounded-full",
        kind === "candidate" && "rotate-45 rounded-[1px]"
      )}
      style={
        kind === "connState"
          ? { border: `1.5px solid ${color}`, background: "transparent" }
          : { background: color }
      }
      aria-hidden
      data-kind={kind || undefined}
    />
  );
}
