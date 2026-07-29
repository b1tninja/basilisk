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
