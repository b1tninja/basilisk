import { useEffect, useState, type DragEvent, type ReactNode } from "react";
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
  /**
   * This step is handling private key material exported into the pipeline
   * (§26c). Computed by `exposureTrace`, not by op name — the mark follows
   * the key, so it lands on the exporting step *and* everything downstream
   * still holding it.
   */
  keyExposed?: boolean;
};

export type ChipBranchView = {
  selector: string;
  steps: ChipStepView[];
};

export type ChipStemView = {
  step: ChipStepView;
  hasNest: boolean;
  /** Which container op this is — drives the nest chrome (anchor chip, ghosts). */
  nestKind?: "tee" | "foreach";
  /**
   * Fitting selector ghosts for a new tee branch, from the closed projector
   * table (suggest.js selectorGhostsFor) — already fit-checked upstream.
   */
  nestAdd?: string[];
  branches?: ChipBranchView[];
  body?: ChipStepView[];
};

/** A tee branch armed client-side — real recipe text once its first step lands. */
export type ArmedBranch = {
  stem: number;
  selector: string;
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
  /** Selector branch armed on a tee — rendered as a ghost row until its first step lands. */
  armedBranch?: ArmedBranch | null;
  onSelect: (path: ChipPath) => void;
  onGap: (path: ChipPath) => void;
  onBranchHit: (stem: number, branch: number | null) => void;
  /** Arm a new selector branch on a tee stem (clicking a ghost chip). */
  onArmBranch?: (stem: number, selector: string) => void;
  /** First step dropped onto an armed branch — materializes branch + step at once. */
  onAddBranchStep?: (
    stem: number,
    selector: string,
    name: string,
    opts?: { decode?: boolean }
  ) => void;
  /** Swap an empty tee for peek — RECIPE.md's documented side-inspect alternative. */
  onPeekInstead?: (stem: number) => void;
  /** Delete a whole selector branch — the × on its selector chip. */
  onRemoveBranch?: (stem: number, branch: number) => void;
  /** Drop the armed branch before it lands — the × on its chip, and Escape. */
  onCancelArmed?: () => void;
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
      keyExposed={step.keyExposed}
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
  scopeLabel,
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
  /**
   * Names the scope this row's gaps insert into (":public", "loop body") so a
   * branch gap can never be mistaken for the continue-main-chain gap — the two
   * previously rendered as the literal same component with the same label
   * (design turn 46a).
   */
  scopeLabel?: string;
  selected?: ChipPath | null;
  activeGap?: ChipPath | null;
  onSelect: (path: ChipPath) => void;
  onGap: (path: ChipPath) => void;
  onReorder: (from: ChipPath, to: ChipPath) => void;
  onDropStep?: RecipeChipFlowProps["onDropStep"];
  onRemove?: RecipeChipFlowProps["onRemove"];
}) {
  const scope = scopeLabel ? ` in ${scopeLabel}` : "";
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
          label={`Insert first step${scope}`}
          showLabel={!!scopeLabel}
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
              label={`Insert step here${scope}`}
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
  armedBranch = null,
  onSelect,
  onGap,
  onBranchHit,
  onArmBranch,
  onAddBranchStep,
  onPeekInstead,
  onRemoveBranch,
  onCancelArmed,
  onReorder,
  onDropStep,
  onRemove,
  className,
}: RecipeChipFlowProps) {
  const [stemDrop, setStemDrop] = useState<number | null>(null);

  /*
   * Escape drops an armed branch. The row is pure client state — nothing has
   * been written to the recipe yet — and it is on screen because the user just
   * clicked a ghost chip, which is `ConsequenceBanner`'s situation (§43d)
   * rather than `ApprovalBanner`'s: the approval banner refuses Escape because
   * it appears unbidden mid-run and a keystroke that used to do nothing must
   * not start denying a signing request. Nothing of that kind is at stake here.
   *
   * The listener is on the window because arming unmounts the ghost chip that
   * was clicked, so focus is back on the body and no ancestor of the armed row
   * would ever see the key. The two guards keep it from eating an Escape that
   * belongs to a layer above — Escape resolves one layer at a time, so an open
   * dialog or a pending gate answers first and this waits its turn.
   */
  useEffect(() => {
    if (!armedBranch || !onCancelArmed) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== "Escape" || e.defaultPrevented) return;
      if (document.querySelector('[role="dialog"], [role="alertdialog"]')) return;
      onCancelArmed();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [armedBranch, onCancelArmed]);

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
    const nestedCount =
      (stem.branches || []).reduce((n, b) => n + b.steps.length, 0) +
      (stem.body?.length || 0);
    // An empty tee/foreach cannot be continued past — it isn't valid syntax
    // yet — so the continue-main-chain gap only appears once the nest has a
    // step (design turn 46b). Everything else keeps its trailing gap.
    if (!stem.hasNest || nestedCount > 0) {
      row.push(
        <InsertGap
          key={`gap-${i + 1}`}
          label="Insert step here"
          data-cell={cell}
          data-gap-stem={i + 1}
          {...stemGap(i + 1)}
        />
      );
    }
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
            title="Click to add to this side chain · × to delete the branch"
            onClick={() => onBranchHit(i, bi)}
            onRemove={
              onRemoveBranch ? () => onRemoveBranch(i, bi) : undefined
            }
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
            scopeLabel={br.selector}
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

    const armedHere = armedBranch && armedBranch.stem === i ? armedBranch : null;
    if (armedHere) {
      // Armed branch — client-side only until its first step lands, because
      // `- :public |` alone is not valid recipe text. Dropping/inserting the
      // first step materializes branch and step as one mutation.
      rows.push(
        <div
          key={`armed-${i}`}
          className="cell-recipe-indent-line"
          role="listitem"
          data-preview-nest={i}
          data-armed-branch={armedHere.selector}
          data-cell={cell}
        >
          <span className="cell-recipe-indent-dash" aria-hidden>
            -
          </span>
          <SuggestChip
            label={armedHere.selector}
            variant="selector"
            className="cell-recipe-branch-hit"
            title="New branch — lands with its first step · × or Escape to cancel"
            onRemove={onCancelArmed}
          />
          <InsertGap
            label={`Insert first step in ${armedHere.selector}`}
            showLabel
            pending
            scale="nested"
            data-cell={cell}
            data-gap-stem={i}
            onDragOver={(e) => {
              if (!chipDragTypes([...e.dataTransfer.types])) return;
              e.preventDefault();
              e.stopPropagation();
              e.dataTransfer.dropEffect = "copy";
            }}
            onDrop={(e) => {
              e.preventDefault();
              e.stopPropagation();
              const parsed = parseStepMime(
                e.dataTransfer.getData(STEP_MIME) ||
                  e.dataTransfer.getData("text/plain")
              );
              if (parsed?.name) {
                onAddBranchStep?.(i, armedHere.selector, parsed.name, {
                  decode: parsed.decode,
                });
              }
            }}
          />
        </div>
      );
    }

    // Body row: foreach always has one (the loop body); a tee shows its
    // no-selector lines when they exist, or when the caret is aimed there.
    const bodyTargeted =
      activeGap &&
      activeGap.stem === i &&
      (activeGap.branch ?? null) === null &&
      activeGap.body != null &&
      activeGap.cell === cell;
    if (
      stem.nestKind === "foreach" ||
      (stem.body && stem.body.length) ||
      bodyTargeted ||
      (!(stem.branches || []).length && !armedHere && stem.nestKind !== "tee")
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
          {stem.nestKind === "foreach" ? (
            // The loop body's anchor — branches get a selector chip to hang
            // on; a body otherwise starts with nothing but the dash (46c).
            <SuggestChip
              label="↻ each item"
              variant="selector"
              className="cell-recipe-branch-hit"
              title="Loop body — runs once per item"
              onClick={() =>
                onGap({
                  cell,
                  stem: i,
                  branch: null,
                  body: stem.body?.length || 0,
                })
              }
            />
          ) : null}
          <ChipRow
            steps={stem.body || []}
            base={{ cell, stem: i, branch: null }}
            nested
            scopeLabel={stem.nestKind === "foreach" ? "loop body" : "branch"}
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

    if (stem.nestKind === "tee" && !armedHere) {
      // Ghost affordances for the next branch: fitting selectors from the
      // closed projector table, an unselected branch (the EBNF makes the
      // selector optional — never force one), and, while the tee is empty,
      // peek — RECIPE.md's documented alternative to an empty tee.
      const ghosts = stem.nestAdd || [];
      rows.push(
        <div
          key={`add-${i}`}
          className="cell-recipe-indent-line"
          role="listitem"
          data-preview-nest={i}
          data-nest-add
          data-cell={cell}
        >
          <span className="cell-recipe-indent-dash" aria-hidden>
            -
          </span>
          {ghosts.map((sel) => {
            // Labelled the way the notebook will write it. A keypair half is a
            // step, so the chip says `public`, not `:public` — a control that
            // offers one spelling and produces another is the drift `CellAssign`
            // exists to avoid, one layer down.
            const token = sel === ":public" || sel === ":private" ? sel.slice(1) : sel;
            return (
              <SuggestChip
                key={sel}
                label={`+ ${token}`}
                variant="ghost"
                title={`Add a ${token} branch`}
                onClick={() => onArmBranch?.(i, sel)}
              />
            );
          })}
          <SuggestChip
            label="+ branch"
            variant="ghost"
            title="Add a branch with no selector — it works on the cloned value directly"
            onClick={() =>
              onGap({
                cell,
                stem: i,
                branch: null,
                body: stem.body?.length || 0,
              })
            }
          />
          {nestedCount === 0 && onPeekInstead ? (
            <SuggestChip
              label="peek instead"
              variant="ghost"
              title="Empty tee is invalid — peek is the side-inspect it usually meant"
              onClick={() => onPeekInstead(i)}
            />
          ) : null}
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
