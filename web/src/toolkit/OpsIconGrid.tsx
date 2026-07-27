import { useMemo } from "react";
import { TOOLBOX_META, SHELF_META, getShelfMeta } from "../lib/toolkit/registry.js";
import { GLYPH_PATHS } from "../lib/toolkit/glyphs.js";
import { cn } from "@/lib/cn";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Input } from "@/components/ui/input";
import { ToolCard, type ToolCardOp } from "./ToolCard";

type Op = ToolCardOp;

type Props = {
  ops: Op[];
  filter: string;
  onFilter: (q: string) => void;
  onAppend: (name: string) => void;
};

function Glyph({ id, className }: { id: string; className?: string }) {
  const inner = GLYPH_PATHS[id];
  if (!inner) {
    return <span className={cn("text-[0.65rem] font-bold", className)}>#</span>;
  }
  return (
    <svg
      className={className}
      width="18"
      height="18"
      viewBox="0 0 20 20"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.6"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden
    >
      <g dangerouslySetInnerHTML={{ __html: inner }} />
    </svg>
  );
}

function glyphFor(op: Op): string {
  if (op.shelf) {
    const fromShelf = (SHELF_META as Record<string, { glyph?: string }>)[op.shelf]?.glyph;
    if (fromShelf) return fromShelf;
    const meta = getShelfMeta(op.shelf);
    if (meta?.glyph) return String(meta.glyph);
  }
  return (TOOLBOX_META as Record<string, { glyph?: string }>)[op.toolbox || ""]?.glyph || "gear";
}

const STEP_MIME = "application/x-basilisk-step";

export function OpsIconGrid({ ops, filter, onFilter, onAppend }: Props) {
  const grouped = useMemo(() => {
    const map = new Map<string, Op[]>();
    for (const op of ops) {
      const tb = op.toolbox || "io";
      if (!map.has(tb)) map.set(tb, []);
      map.get(tb)!.push(op);
    }
    return [...map.entries()].sort(
      (a, b) =>
        ((TOOLBOX_META as Record<string, { order?: number }>)[a[0]]?.order ?? 9) -
        ((TOOLBOX_META as Record<string, { order?: number }>)[b[0]]?.order ?? 9)
    );
  }, [ops]);

  return (
    <aside className="flex w-[204px] shrink-0 flex-col border-r border-[var(--border)] bg-[color-mix(in_srgb,var(--surface-raised)_88%,var(--surface))]">
      <div className="border-b border-[var(--border)] px-2.5 py-2">
        <p className="text-[0.65rem] font-bold uppercase tracking-wider text-[var(--muted-foreground)]">
          Toolkit
        </p>
        <Input
          className="mt-1.5 h-7 text-xs"
          placeholder="Search…"
          value={filter}
          onChange={(e) => onFilter(e.target.value)}
        />
        <p className="mt-1.5 text-[0.62rem] leading-snug text-[var(--muted-foreground)]">
          Hover for the tool card — drag onto a cell or click.
        </p>
      </div>
      <ScrollArea className="flex-1 px-2 py-2">
        <div className="flex flex-col gap-2 pb-4">
          {grouped.map(([tb, items]) => {
            const meta = (TOOLBOX_META as Record<string, { label?: string }>)[tb] || {
              label: tb,
            };
            return (
              <div key={tb}>
                <div className="mb-1 flex items-center gap-1 px-0.5 text-[0.62rem] font-bold uppercase tracking-wide text-[var(--muted-foreground)]">
                  <Glyph id={glyphFor({ toolbox: tb })} className="opacity-70" />
                  <span className="truncate">{meta.label || tb}</span>
                  <span className="ml-auto opacity-70">{items.length}</span>
                </div>
                <div className="grid grid-cols-3 gap-1">
                  {items.map((op) => {
                    const short =
                      op.name.length > 9 ? `${op.name.slice(0, 8)}…` : op.name;
                    return (
                      <Tooltip key={op.name} delayDuration={280}>
                        <TooltipTrigger asChild>
                          <button
                            type="button"
                            draggable
                            className={cn(
                              "flex aspect-square flex-col items-center justify-center gap-0.5 rounded-lg border border-transparent",
                              "bg-[color-mix(in_srgb,var(--surface)_55%,var(--surface-raised))] px-0.5 py-1",
                              "hover:border-[color-mix(in_srgb,var(--brand)_50%,var(--border))] hover:bg-[color-mix(in_srgb,var(--brand)_12%,transparent)]",
                              "cursor-grab active:cursor-grabbing"
                            )}
                            aria-label={op.name}
                            onClick={() => onAppend(op.name)}
                            onDragStart={(e) => {
                              e.dataTransfer.setData(STEP_MIME, op.name);
                              e.dataTransfer.setData("text/plain", op.name);
                              e.dataTransfer.effectAllowed = "copy";
                            }}
                          >
                            <Glyph id={glyphFor(op)} />
                            <span className="max-w-full truncate font-mono text-[0.5rem] font-semibold leading-none">
                              {short}
                            </span>
                          </button>
                        </TooltipTrigger>
                        <TooltipContent
                          side="right"
                          sideOffset={10}
                          className="max-w-none border-0 bg-transparent p-0 text-left text-[var(--text)] shadow-none"
                        >
                          <ToolCard op={op} className="w-[300px] max-w-[min(300px,calc(100vw-2rem))]" />
                        </TooltipContent>
                      </Tooltip>
                    );
                  })}
                </div>
              </div>
            );
          })}
        </div>
      </ScrollArea>
    </aside>
  );
}

export { STEP_MIME };
