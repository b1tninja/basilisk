import type { DragEvent } from "react";
import {
  TOOLBOX_META,
  getShelfMeta,
  pairDirection,
} from "../../lib/toolkit/registry.js";
import { decodeTwinToken } from "../../lib/toolkit/step-names.js";
import { cn } from "@/lib/cn";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { Glyph, glyphIdFor } from "./Glyph";
import { ToolCard, type ToolCardOp } from "./ToolCard";
import { STEP_MIME, stepDragPayload } from "./mime";

export type OpsTileOp = ToolCardOp;

type Props = {
  /** The pair's forward (encode/primary) op — also the row's display name and docs. */
  op: OpsTileOp;
  /** Reverse-direction op, when distinct from `op` (e.g. a `conjugate`, not a `decodeTwin`). */
  reverseOp?: OpsTileOp;
  /** Row has a working forward (→) direction. Default true. */
  hasForward?: boolean;
  /** Row has a working reverse (←) direction. Default: true if `op.decodeTwin` or `reverseOp` given. */
  hasReverse?: boolean;
  fit?: { forward: boolean; reverse: boolean };
  /**
   * Per-direction dim reason while a caret is active (§20c) — set for a
   * direction that doesn't fit; renders an 8.5px caption under that arrow
   * and dims just that handle instead of the whole row.
   */
  needs?: { forward?: string; reverse?: string };
  /** Whole-row dim — neither direction fits the caret. */
  dim?: boolean;
  showTooltip?: boolean;
  onAppend: (name: string, opts?: { decode?: boolean }) => void;
  className?: string;
};

// Direction is always color-coded (§19a/19b): encode → blue, decode ← purple.
// `fit` only brightens the handle's background/border toward its own hue.
// Class strings must stay literal so Tailwind's scanner can see them.
function directionButtonClass(active: boolean, fit: boolean, kind: "encode" | "decode") {
  if (!active) {
    return "border-dashed border-[var(--border)] bg-transparent text-transparent cursor-not-allowed";
  }
  if (kind === "decode") {
    return cn(
      "cursor-grab active:cursor-grabbing text-[var(--decode)] hover:border-[var(--decode)]",
      fit
        ? "border-[color-mix(in_srgb,var(--decode)_40%,transparent)] bg-[color-mix(in_srgb,var(--decode)_14%,transparent)]"
        : "border-[var(--border)] bg-[var(--surface-raised)]"
    );
  }
  return cn(
    "cursor-grab active:cursor-grabbing text-[var(--caret)] hover:border-[var(--caret)]",
    fit
      ? "border-[color-mix(in_srgb,var(--caret)_40%,transparent)] bg-[color-mix(in_srgb,var(--caret)_14%,transparent)]"
      : "border-[var(--border)] bg-[var(--surface-raised)]"
  );
}

/** Merged encode/decode row — one dot, one name, up to two direction handles (§19b). */
export function OpsTile({
  op,
  reverseOp,
  hasForward = true,
  hasReverse = !!(op.decodeTwin || reverseOp),
  fit = { forward: false, reverse: false },
  needs,
  dim = false,
  showTooltip = true,
  onAppend,
  className,
}: Props) {
  const forwardName = op.name;
  // A distinct conjugate (e.g. wrap/unwrap) appends its own name with no decode flag;
  // everything else — decodeTwin ops, and same-name cipher-dispatch kits — appends
  // this op's own name with decode:true.
  const reverseIsDistinctConjugate = !!reverseOp && !op.decodeTwin;
  const reverseName = reverseIsDistinctConjugate ? reverseOp!.name : op.name;
  const reverseDecode = !reverseIsDistinctConjugate;
  const reverseDisplayName = op.decodeTwin ? decodeTwinToken(op, true) : reverseName;
  const forwardPayload = stepDragPayload(forwardName, false);
  const reversePayload = stepDragPayload(reverseName, reverseDecode);
  const forwardDir = pairDirection(op, { decode: false, pairRole: "forward" });
  const reverseDir = pairDirection(reverseOp || op, {
    decode: reverseDecode,
    pairRole: "reverse",
  });

  /**
   * One reason, stated once.
   *
   * Both handles used to carry their own 8.5px caption, and for the great
   * majority of pairs those captions read identically ("needs bytes" twice
   * under one row), which doubled the row's height and its noise for no extra
   * information. When the two directions genuinely want different inputs the
   * captions still split per handle; otherwise the row states it inline,
   * right-aligned, in exactly the place a solo row states it — so the same
   * fact sits in the same place whichever kind of row you are looking at.
   */
  /**
   * A handle that doesn't fit is now actually inert.
   *
   * It used to render `cursor-not-allowed opacity-40` and stay fully live:
   * clicking it appended the step anyway, and it stayed in the tab order.
   * Meanwhile the solo rows in the shelf deleted their control outright for
   * the same condition. Three behaviours for one state — looks disabled and
   * works, looks disabled and is gone, looks enabled and works — is worse
   * than any one of them consistently applied.
   */
  const forwardLive = hasForward && !needs?.forward;
  const reverseLive = hasReverse && !needs?.reverse;

  const sharedNeed =
    needs?.forward && needs.forward === needs.reverse ? needs.forward : null;
  const splitNeeds = sharedNeed ? undefined : needs;
  const hasCaptions = !!(splitNeeds?.forward || splitNeeds?.reverse);

  const row = (
    <div
      className={cn(
        "flex gap-2 rounded-md px-1.5 py-[3px] hover:bg-[color-mix(in_srgb,var(--brand)_5%,transparent)]",
        hasCaptions ? "items-start" : "items-center",
        className
      )}
    >
      {/* Identity is the glyph. Verification is not per-op — it lives on the
          toolbox header, one light per suite. */}
      <Glyph
        id={glyphIdFor(op)}
        size={16}
        className={cn("shrink-0", dim ? "opacity-45" : "opacity-80", hasCaptions && "mt-[3px]")}
      />
      <code
        className={cn(
          "min-w-0 flex-1 truncate font-mono text-[11.5px] font-medium",
          // Dimming by opacity took this to 1.97:1 and the caption under it to
          // 1.59:1 in the production build. A colour step is a larger
          // perceptual drop and still legible; see OPS_DIM_TEXT in OpsShelf.
          dim ? "text-[var(--muted-foreground)]" : "text-[var(--foreground)]",
          hasCaptions && "pt-[2px]"
        )}
      >
        {op.name}
      </code>
      {sharedNeed ? (
        <span className="shrink-0 font-mono text-[9.5px] text-[var(--muted-foreground)]">
          {sharedNeed}
        </span>
      ) : null}
      <span className="flex shrink-0 flex-col items-center gap-[2px]">
        <button
          type="button"
          draggable={forwardLive}
          disabled={!forwardLive}
          data-dir={forwardDir}
          aria-hidden={!hasForward}
          className={cn(
            "flex h-5 w-[22px] shrink-0 items-center justify-center rounded-[4px] border text-[10px] font-semibold transition-colors",
            directionButtonClass(hasForward, fit.forward, "encode"),
            needs?.forward && "cursor-not-allowed opacity-60"
          )}
          aria-label={
            hasForward
              ? needs?.forward
                ? `${forwardName} — encode, unavailable: ${needs.forward}`
                : `${forwardName} — encode`
              : undefined
          }
          title={hasForward ? needs?.forward || "Encode" : undefined}
          onClick={forwardLive ? () => onAppend(forwardName, { decode: false }) : undefined}
          onDragStart={
            forwardLive
              ? (e: DragEvent<HTMLButtonElement>) => {
                  e.dataTransfer.setData(STEP_MIME, forwardPayload);
                  e.dataTransfer.setData("text/plain", forwardName);
                  e.dataTransfer.effectAllowed = "copy";
                }
              : undefined
          }
        >
          {hasForward ? <Glyph id="encode" size={16} /> : null}
        </button>
        {splitNeeds?.forward ? (
          <span className="whitespace-nowrap text-[8.5px] text-[var(--muted-foreground)]">
            {splitNeeds.forward}
          </span>
        ) : null}
      </span>
      <span className="flex shrink-0 flex-col items-center gap-[2px]">
        <button
          type="button"
          draggable={reverseLive}
          disabled={!reverseLive}
          data-dir={reverseDir}
          aria-hidden={!hasReverse}
          className={cn(
            "flex h-5 w-[22px] shrink-0 items-center justify-center rounded-[4px] border text-[10px] font-semibold transition-colors",
            directionButtonClass(hasReverse, fit.reverse, "decode"),
            needs?.reverse && "cursor-not-allowed opacity-60"
          )}
          aria-label={
            hasReverse
              ? needs?.reverse
                ? `${reverseDisplayName} — decode, unavailable: ${needs.reverse}`
                : `${reverseDisplayName} — decode`
              : undefined
          }
          title={hasReverse ? needs?.reverse || "Decode" : undefined}
          onClick={
            reverseLive ? () => onAppend(reverseName, { decode: reverseDecode }) : undefined
          }
          onDragStart={
            reverseLive
              ? (e: DragEvent<HTMLButtonElement>) => {
                  e.dataTransfer.setData(STEP_MIME, reversePayload);
                  e.dataTransfer.setData("text/plain", reverseDisplayName);
                  if (reverseDecode) {
                    e.dataTransfer.setData("application/x-basilisk-decode", "1");
                  }
                  e.dataTransfer.effectAllowed = "copy";
                }
              : undefined
          }
        >
          {hasReverse ? <Glyph id="decode" size={16} /> : null}
        </button>
        {splitNeeds?.reverse ? (
          <span className="whitespace-nowrap text-[8.5px] text-[var(--muted-foreground)]">
            {splitNeeds.reverse}
          </span>
        ) : null}
      </span>
    </div>
  );

  if (!showTooltip) return row;

  return (
    <Tooltip delayDuration={280}>
      <TooltipTrigger asChild>{row}</TooltipTrigger>
      <TooltipContent
        side="right"
        sideOffset={10}
        className="max-w-none border-0 bg-transparent p-0 text-left text-[var(--text)] shadow-none"
      >
        <ToolCard op={op} className="w-[300px] max-w-[min(300px,calc(100vw-2rem))]" />
      </TooltipContent>
    </Tooltip>
  );
}

export { TOOLBOX_META, getShelfMeta };
