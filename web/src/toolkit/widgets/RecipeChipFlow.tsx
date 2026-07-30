import { useState, type DragEvent, type ReactNode } from "react";
import { cn } from "@/lib/cn";
import { SuggestChip } from "./SuggestChip";
import { InsertGap } from "./InsertGap";
import { ToolCard, type ToolCardOp } from "./ToolCard";
import {
  CHIP_REORDER_MIME,
  REORDER_MIME,
  STEP_MIME,
  parseStepMime,
} from "./mime";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";

export type ChipPath = {
  cell: number;
  stem: number;
  branch?: number | null;
  body?: number | null;
};

export type ChipStepView = {
  name: string;
  label: string;
  hint?: string;
  op?: ToolCardOp;
  error?: boolean;
  ghostIn?: string;
};

export type ChipBranchView = {
  selector: string;
  steps: ChipStepView[];
};

export type ChipStemView = {
  step: ChipStepView;
  hasNest: boolean;
  branches?: ChipBranchView[];
  body?: ChipStepView[];
};

function pathKey(p: ChipPath): string {
  return `${p.cell}:${p.stem}:${p.branch ?? ""}:${p.body ?? ""}`;
}

function samePath(a: ChipPath | null | undefined, b: ChipPath): boolean {
  if (!a) return false;
  return pathKey(a) === pathKey(b);
}

function chipDragTypes(types: readonly string[]): boolean {
  return (
    types.includes(CHIP_REORDER_MIME) ||
    types.includes(REORDER_MIME) ||
    types.includes(STEP_MIME) ||
    types.includes("text/plain")
  );
}

export type RecipeChipFlowProps = {
  cell: number;
  stems: ChipStemView[];
  selected?: ChipPath | null;
  /** Gap path waiting for an op from the shelf (click-to-insert focus). */
  activeGap?: ChipPath | null;
  onSelect: (path: ChipPath) => void;
  onGap: (path: ChipPath) => void;
  onBranchHit: (stem: number, branch: number | null) => void;
  onReorder: (from: ChipPath, to: ChipPath) => void;
  onDropStep?: (
    path: ChipPath,
    name: string,
    opts?: { decode?: boolean }
  ) => void;
  onRemove?: (path: ChipPath) => void;
  className?: string;
};

function PlacedChip({
  step,
  path,
  selected,
  onSelect,
  onRemove,
  onDragStart,
  onDragEnd,
}: {
  step: ChipStepView;
  path: ChipPath;
  selected: boolean;
  onSelect: () => void;
  onRemove?: () => void;
  onDragStart: (e: DragEvent) => void;
  onDragEnd: (e: DragEvent) => void;
}) {
  const chip = (
    <SuggestChip
      label={step.label}
      hint={step.hint}
      variant="placed"
      selected={selected}
      error={step.error}
      op={
        step.op
          ? {
              glyph: step.op.glyph,
              shelf: step.op.shelf,
              toolbox: step.op.toolbox,
              name: step.op.name,
              output: step.op.output,
            }
          : undefined
      }
      draggable
      onClick={onSelect}
      onRemove={onRemove}
      onDragStart={onDragStart}
      onDragEnd={onDragEnd}
      title="Drag to reorder · click to edit · × to remove"
    />
  );
  if (!step.op || selected) return chip;
  return (
    <Tooltip delayDuration={280}>
      <TooltipTrigger asChild>{chip}</TooltipTrigger>
      <TooltipContent
        side="bottom"
        align="start"
        className="max-w-none border-0 bg-transparent p-0 text-left text-[var(--text)] shadow-none"
      >
        <ToolCard op={step.op} compact className="w-[280px]" />
      </TooltipContent>
    </Tooltip>
  );
}

function ChipRow({
  steps,
  base,
  nested = false,
  selected,
  activeGap,
  onSelect,
  onGap,
  onReorder,
  onDropStep,
  onRemove,
}: {
  steps: ChipStepView[];
  base: { cell: number; stem: number; branch?: number | null };
  /** Nested rows use the 14px caret (design v2 §20f). */
  nested?: boolean;
  selected?: ChipPath | null;
  activeGap?: ChipPath | null;
  onSelect: (path: ChipPath) => void;
  onGap: (path: ChipPath) => void;
  onReorder: (from: ChipPath, to: ChipPath) => void;
  onDropStep?: RecipeChipFlowProps["onDropStep"];
  onRemove?: RecipeChipFlowProps["onRemove"];
}) {
  const [dropAt, setDropAt] = useState<number | null>(null);

  const bindGap = (body: number) => {
    const path: ChipPath = { ...base, body };
    return {
      onClick: () => onGap(path),
      onDragOver: (e: DragEvent) => {
        if (!chipDragTypes([...e.dataTransfer.types])) return;
        e.preventDefault();
        e.stopPropagation();
        const types = [...e.dataTransfer.types];
        e.dataTransfer.dropEffect =
          types.includes(CHIP_REORDER_MIME) || types.includes(REORDER_MIME)
            ? "move"
            : "copy";
        setDropAt(body);
      },
      onDragLeave: () => setDropAt((v) => (v === body ? null : v)),
      onDrop: (e: DragEvent) => {
        e.preventDefault();
        e.stopPropagation();
        setDropAt(null);
        const raw =
          e.dataTransfer.getData(CHIP_REORDER_MIME) ||
          (e.dataTransfer.getData("text/plain") || "").replace(
            /^basilisk-chip:/,
            ""
          );
        try {
          if (raw?.startsWith("{")) {
            const from = JSON.parse(raw) as ChipPath;
            if (from?.cell != null) {
              onReorder(from, path);
              return;
            }
          }
        } catch {
          /* ignore */
        }
        const parsed = parseStepMime(
          e.dataTransfer.getData(STEP_MIME) || e.dataTransfer.getData("text/plain")
        );
        if (parsed?.name) {
          const decode =
            parsed.decode ||
            e.dataTransfer.getData("application/x-basilisk-decode") === "1";
          onDropStep?.(path, parsed.name, { decode });
        }
      },
      active: dropAt === body,
      pending: samePath(activeGap, path),
    };
  };

  if (!steps.length) {
    return (
      <div className="suggest-next-chips cell-recipe-indent-chips flex flex-wrap items-center gap-1">
        <InsertGap
          label="Insert first step"
          scale={nested ? "nested" : "default"}
          data-cell={base.cell}
          data-gap-stem={base.stem}
          data-gap-branch={base.branch ?? undefined}
          data-gap-body={0}
          {...bindGap(0)}
        />
      </div>
    );
  }

  return (
    <div
      className="suggest-next-chips cell-recipe-indent-chips flex flex-wrap items-center gap-1"
      role="list"
    >
      {steps.map((step, i) => {
        const path: ChipPath = { ...base, body: i };
        return (
          <span key={pathKey(path)} className="inline-flex flex-wrap items-center gap-1">
            {i > 0 ? (
              <span className="cell-recipe-chip-sep" aria-hidden title={step.ghostIn || undefined}>
                ›
              </span>
            ) : null}
            <PlacedChip
              step={step}
              path={path}
              selected={samePath(selected, path)}
              onSelect={() => onSelect(path)}
              onRemove={onRemove ? () => onRemove(path) : undefined}
              onDragStart={(e) => {
                const payload = JSON.stringify(path);
                e.dataTransfer.effectAllowed = "move";
                e.dataTransfer.setData(CHIP_REORDER_MIME, payload);
                e.dataTransfer.setData("text/plain", `basilisk-chip:${payload}`);
                document.body.classList.add("chip-reorder-dragging");
              }}
              onDragEnd={() =>
                document.body.classList.remove("chip-reorder-dragging")
              }
            />
            <InsertGap
              label="Insert step here"
              scale={nested ? "nested" : "default"}
              data-cell={base.cell}
              data-gap-stem={base.stem}
              data-gap-branch={base.branch ?? undefined}
              data-gap-body={i + 1}
              {...bindGap(i + 1)}
            />
          </span>
        );
      })}
    </div>
  );
}

/** Preview chip pipeline using SuggestChip + InsertGap carets (§20f — SuggestRail retired). */
export function RecipeChipFlow({
  cell,
  stems,
  selected = null,
  activeGap = null,
  onSelect,
  onGap,
  onBranchHit,
  onReorder,
  onDropStep,
  onRemove,
  className,
}: RecipeChipFlowProps) {
  const [stemDrop, setStemDrop] = useState<number | null>(null);

  const stemGap = (stem: number) => {
    const path: ChipPath = { cell, stem };
    return {
      onClick: () => onGap(path),
      onDragOver: (e: DragEvent) => {
        if (!chipDragTypes([...e.dataTransfer.types])) return;
        e.preventDefault();
        e.stopPropagation();
        const types = [...e.dataTransfer.types];
        e.dataTransfer.dropEffect =
          types.includes(CHIP_REORDER_MIME) || types.includes(REORDER_MIME)
            ? "move"
            : "copy";
        setStemDrop(stem);
      },
      onDragLeave: () => setStemDrop((v) => (v === stem ? null : v)),
      onDrop: (e: DragEvent) => {
        e.preventDefault();
        e.stopPropagation();
        setStemDrop(null);
        const raw =
          e.dataTransfer.getData(CHIP_REORDER_MIME) ||
          (e.dataTransfer.getData("text/plain") || "").replace(
            /^basilisk-chip:/,
            ""
          );
        const reorderRaw = e.dataTransfer.getData(REORDER_MIME);
        try {
          if (raw?.startsWith("{")) {
            const from = JSON.parse(raw) as ChipPath;
            if (from?.cell != null) {
              onReorder(from, path);
              return;
            }
          }
        } catch {
          /* ignore */
        }
        if (reorderRaw !== "") {
          onReorder({ cell, stem: Number(reorderRaw) }, path);
          return;
        }
        const parsed = parseStepMime(
          e.dataTransfer.getData(STEP_MIME) || e.dataTransfer.getData("text/plain")
        );
        if (parsed?.name) {
          const decode =
            parsed.decode ||
            e.dataTransfer.getData("application/x-basilisk-decode") === "1";
          onDropStep?.(path, parsed.name, { decode });
        }
      },
      active: stemDrop === stem,
      pending: samePath(activeGap, path),
    };
  };

  const rows: ReactNode[] = [];
  let row: ReactNode[] = [];
  let stemContinue = false;

  const flush = () => {
    if (!row.length) return;
    rows.push(
      <div
        key={`row-${rows.length}`}
        className="cell-recipe-flow-row suggest-next-chips"
        role="list"
      >
        {row}
      </div>
    );
    row = [];
  };

  row.push(
    <InsertGap
      key="gap-0"
      label="Insert at start"
      data-cell={cell}
      data-gap-stem={0}
      {...stemGap(0)}
    />
  );

  stems.forEach((stem, i) => {
    const path: ChipPath = { cell, stem: i };
    const showPipe = stemContinue || row.length > 1;
    if (showPipe) {
      row.push(
        <span
          key={`pipe-${i}`}
          className="cell-recipe-chip-sep"
          aria-hidden
          title={stem.step.ghostIn || undefined}
        >
          ›
        </span>
      );
    }
    row.push(
      <PlacedChip
        key={pathKey(path)}
        step={stem.step}
        path={path}
        selected={samePath(selected, path)}
        onSelect={() => onSelect(path)}
        onRemove={onRemove ? () => onRemove(path) : undefined}
        onDragStart={(e) => {
          const payload = JSON.stringify(path);
          e.dataTransfer.effectAllowed = "move";
          e.dataTransfer.setData(CHIP_REORDER_MIME, payload);
          e.dataTransfer.setData(REORDER_MIME, String(i));
          e.dataTransfer.setData("text/plain", `basilisk-chip:${payload}`);
          document.body.classList.add("chip-reorder-dragging");
        }}
        onDragEnd={() =>
          document.body.classList.remove("chip-reorder-dragging")
        }
      />
    );
    row.push(
      <InsertGap
        key={`gap-${i + 1}`}
        label="Insert step here"
        data-cell={cell}
        data-gap-stem={i + 1}
        {...stemGap(i + 1)}
      />
    );
    stemContinue = false;

    if (!stem.hasNest) return;
    flush();

    (stem.branches || []).forEach((br, bi) => {
      rows.push(
        <div
          key={`br-${i}-${bi}`}
          className="cell-recipe-indent-line"
          role="listitem"
          data-preview-nest={i}
          data-preview-branch={bi}
          data-cell={cell}
        >
          <span className="cell-recipe-indent-dash" aria-hidden>
            -
          </span>
          <SuggestChip
            label={br.selector}
            variant="selector"
            className="cell-recipe-branch-hit"
            title="Add to this side chain"
            onClick={() => onBranchHit(i, bi)}
          />
          {br.steps.length ? (
            <span className="builder-branch-pipe muted" aria-hidden>
              |
            </span>
          ) : null}
          <ChipRow
            steps={br.steps}
            base={{ cell, stem: i, branch: bi }}
            nested
            selected={selected}
            activeGap={activeGap}
            onSelect={onSelect}
            onGap={onGap}
            onReorder={onReorder}
            onDropStep={onDropStep}
            onRemove={onRemove}
          />
        </div>
      );
    });

    if (
      (stem.body && stem.body.length) ||
      (!(stem.branches || []).length && stem.hasNest)
    ) {
      rows.push(
        <div
          key={`body-${i}`}
          className="cell-recipe-indent-line"
          role="listitem"
          data-preview-nest={i}
          data-cell={cell}
        >
          <span className="cell-recipe-indent-dash" aria-hidden>
            -
          </span>
          <ChipRow
            steps={stem.body || []}
            base={{ cell, stem: i, branch: null }}
            nested
            selected={selected}
            activeGap={activeGap}
            onSelect={onSelect}
            onGap={onGap}
            onReorder={onReorder}
            onDropStep={onDropStep}
            onRemove={onRemove}
          />
        </div>
      );
    }

    stemContinue = true;
  });
  flush();

  return (
    <div
      className={cn("cell-recipe-flow", className)}
      role="group"
      aria-label="Recipe chip editor"
    >
      {rows}
    </div>
  );
}
