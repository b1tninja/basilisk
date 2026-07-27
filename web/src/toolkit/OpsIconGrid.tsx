import { useMemo } from "react";
import {
  TOOLBOX_META,
  SHELF_META,
  getShelfMeta,
  listDrawerRows,
  pairDirection,
  type StepSpec,
} from "../lib/toolkit/registry.js";
import { GLYPH_PATHS } from "../lib/toolkit/glyphs.js";
import { decodeTwinToken } from "../lib/toolkit/step-names.js";
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
  onAppend: (name: string, opts?: { decode?: boolean }) => void;
};

function asStep(op: Op): StepSpec {
  return op as unknown as StepSpec;
}

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
  if (op.glyph) return op.glyph;
  if (op.shelf) {
    const fromShelf = (SHELF_META as Record<string, { glyph?: string }>)[op.shelf]?.glyph;
    if (fromShelf) return fromShelf;
    const meta = getShelfMeta(op.shelf);
    if (meta?.glyph) return String(meta.glyph);
  }
  return (TOOLBOX_META as Record<string, { glyph?: string }>)[op.toolbox || ""]?.glyph || "gear";
}

function displayName(op: Op, decode?: boolean): string {
  if (decode && op.decodeTwin) {
    return decodeTwinToken(op, true);
  }
  if (op.decodeTwin && !decode) {
    return decodeTwinToken(op, false);
  }
  return op.label || op.name;
}

const STEP_MIME = "application/x-basilisk-step";

type TileProps = {
  op: Op;
  decode?: boolean;
  pairRole?: "forward" | "reverse" | "solo";
  onAppend: Props["onAppend"];
};

function OpTile({ op, decode, pairRole = "solo", onAppend }: TileProps) {
  const nameLabel = displayName(op, decode);
  const short = nameLabel;
  const dir = pairDirection(asStep(op), { decode: !!decode, pairRole });
  const payload = JSON.stringify({ name: op.name, decode: !!decode });

  return (
    <Tooltip delayDuration={280}>
      <TooltipTrigger asChild>
        <button
          type="button"
          draggable
          data-dir={dir}
          data-pair-role={pairRole}
          className={cn(
            "ops-item ops-item-icon flex w-full min-h-[2.35rem] flex-row items-center justify-start gap-2 rounded-lg border px-2 py-1.5",
            "cursor-grab active:cursor-grabbing",
            dir === "encode" &&
              "border-[color-mix(in_srgb,var(--brand)_42%,var(--border))] bg-[color-mix(in_srgb,var(--brand)_10%,var(--surface-raised))]",
            dir === "decode" &&
              "border-[color-mix(in_srgb,var(--accent,#7aa2f7)_42%,var(--border))] bg-[color-mix(in_srgb,var(--accent,#7aa2f7)_10%,var(--surface-raised))]",
            dir === "neutral" &&
              "border-transparent bg-[color-mix(in_srgb,var(--surface)_55%,var(--surface-raised))]",
            "hover:border-[color-mix(in_srgb,var(--brand)_50%,var(--border))]"
          )}
          aria-label={nameLabel}
          onClick={() => onAppend(op.name, { decode: !!decode })}
          onDragStart={(e) => {
            e.dataTransfer.setData(STEP_MIME, payload);
            e.dataTransfer.setData("text/plain", nameLabel);
            e.dataTransfer.effectAllowed = "copy";
          }}
        >
          <Glyph id={glyphFor(op)} />
          <span className="min-w-0 flex-1 truncate text-left font-mono text-[0.72rem] font-semibold leading-tight">
            {short}
          </span>
        </button>
      </TooltipTrigger>
      <TooltipContent
        side="right"
        sideOffset={10}
        className="max-w-none border-0 bg-transparent p-0 text-left text-[var(--text)] shadow-none"
      >
        <ToolCard
          op={op}
          decode={!!decode}
          className="w-[300px] max-w-[min(300px,calc(100vw-2rem))]"
        />
      </TooltipContent>
    </Tooltip>
  );
}

export function OpsIconGrid({ ops, filter, onFilter, onAppend }: Props) {
  const grouped = useMemo(() => {
    const q = filter.trim().toLowerCase();
    const filtered = q
      ? ops.filter(
          (op) =>
            op.name.toLowerCase().includes(q) ||
            (op.doc || "").toLowerCase().includes(q) ||
            (op.label || "").toLowerCase().includes(q)
        )
      : ops;

    const byTb = new Map<string, Op[]>();
    for (const op of filtered) {
      const tb = op.toolbox || "io";
      if (!byTb.has(tb)) byTb.set(tb, []);
      byTb.get(tb)!.push(op);
    }

    return [...byTb.entries()]
      .sort(
        (a, b) =>
          ((TOOLBOX_META as Record<string, { order?: number }>)[a[0]]?.order ?? 9) -
          ((TOOLBOX_META as Record<string, { order?: number }>)[b[0]]?.order ?? 9)
      )
      .map(([tb, items]) => {
        const byShelf = new Map<string, Op[]>();
        for (const op of items) {
          const shelf = op.shelf || "_";
          if (!byShelf.has(shelf)) byShelf.set(shelf, []);
          byShelf.get(shelf)!.push(op);
        }
        const shelves = [...byShelf.entries()].sort(
          (a, b) => getShelfMeta(a[0]).order - getShelfMeta(b[0]).order
        );
        return {
          tb,
          shelves: shelves.map(([shelf, shelfItems]) => ({
            shelf,
            rows: listDrawerRows(shelfItems.map(asStep)),
          })),
        };
      });
  }, [ops, filter]);

  return (
    <aside className="flex w-[220px] shrink-0 flex-col border-r border-[var(--border)] bg-[color-mix(in_srgb,var(--surface-raised)_88%,var(--surface))]">
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
          Hover for the tool card — drag onto a cell or click. Pairs tint encode / decode.
        </p>
      </div>
      <ScrollArea className="flex-1 px-2 py-2">
        <div className="flex flex-col gap-3 pb-4">
          {grouped.map(({ tb, shelves }) => {
            const meta = (TOOLBOX_META as Record<string, { label?: string; glyph?: string }>)[
              tb
            ] || { label: tb };
            return (
              <div key={tb}>
                <div className="mb-1.5 flex items-center gap-1 px-0.5 text-[0.62rem] font-bold uppercase tracking-wide text-[var(--muted-foreground)]">
                  <Glyph id={meta.glyph || glyphFor({ name: tb, toolbox: tb })} className="opacity-70" />
                  <span className="truncate">{meta.label || tb}</span>
                </div>
                <div className="ops-icon-grid flex flex-col gap-0.5">
                  {shelves.map(({ shelf, rows }) => (
                    <div key={`${tb}:${shelf}`} className="flex flex-col gap-0.5">
                      {rows.map((row, i) => {
                        if (row.type === "solo" && row.step) {
                          return (
                            <div key={`${row.step.name}-${i}`} className="ops-pair ops-pair-solo">
                              <OpTile op={row.step} pairRole="solo" onAppend={onAppend} />
                            </div>
                          );
                        }
                        if (row.type !== "pair" || !row.forward) return null;
                        const key = row.forward.name + (row.reverse?.name || "-d");
                        return (
                          <div key={key} className="ops-pair">
                            {row.caption ? (
                              <div className="ops-pair-caption muted fs-xs col-span-2 px-0.5 text-[0.52rem] font-bold uppercase tracking-wide text-[var(--muted-foreground)]">
                                {row.caption}
                              </div>
                            ) : null}
                            <OpTile
                              op={row.forward}
                              pairRole="forward"
                              onAppend={onAppend}
                            />
                            {row.decodeTwin ? (
                              <OpTile
                                op={row.forward}
                                decode
                                pairRole="reverse"
                                onAppend={onAppend}
                              />
                            ) : row.reverse ? (
                              <OpTile
                                op={row.reverse}
                                pairRole="reverse"
                                onAppend={onAppend}
                              />
                            ) : null}
                          </div>
                        );
                      })}
                    </div>
                  ))}
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
