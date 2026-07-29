import {
  TOOLBOX_META,
  getShelfMeta,
  pairDirection,
  pairTileLabel,
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
  op: OpsTileOp;
  decode?: boolean;
  pairRole?: "forward" | "reverse" | "solo";
  fit?: boolean;
  dim?: boolean;
  showTooltip?: boolean;
  onAppend: (name: string, opts?: { decode?: boolean }) => void;
  className?: string;
};

function displayName(
  op: OpsTileOp,
  decode?: boolean,
  pairRole?: "forward" | "reverse" | "solo"
): string {
  const friendly = pairTileLabel(op as never, { decode: !!decode, pairRole });
  if (friendly) return friendly;
  if (decode && op.decodeTwin) return decodeTwinToken(op, true);
  if (op.decodeTwin && !decode) return decodeTwinToken(op, false);
  return op.label || op.name;
}

/** Draggable encode/decode op tile for shelves and suggest rails. */
export function OpsTile({
  op,
  decode,
  pairRole = "solo",
  fit = false,
  dim = false,
  showTooltip = true,
  onAppend,
  className,
}: Props) {
  const nameLabel = displayName(op, decode, pairRole);
  const recipeName =
    op.decodeTwin && decode
      ? decodeTwinToken(op, true)
      : op.decodeTwin
        ? decodeTwinToken(op, false)
        : op.label || op.name;
  const dir = pairDirection(op, { decode: !!decode, pairRole });
  const payload = stepDragPayload(op.name, !!decode);

  const button = (
    <button
      type="button"
      draggable
      data-dir={dir}
      data-pair-role={pairRole}
      className={cn(
        "ops-item ops-item-icon flex w-full min-h-[2.35rem] flex-row items-center justify-start gap-2 rounded-lg border px-2 py-1.5",
        "cursor-grab active:cursor-grabbing",
        fit && "ops-item-fit",
        dim && "ops-item-dim",
        dir === "encode" &&
          "border-[color-mix(in_srgb,var(--brand)_42%,var(--border))] bg-[color-mix(in_srgb,var(--brand)_10%,var(--surface-raised))]",
        dir === "decode" &&
          "border-[color-mix(in_srgb,var(--accent,#7aa2f7)_42%,var(--border))] bg-[color-mix(in_srgb,var(--accent,#7aa2f7)_10%,var(--surface-raised))]",
        dir === "neutral" &&
          "border-transparent bg-[color-mix(in_srgb,var(--surface)_55%,var(--surface-raised))]",
        "hover:border-[color-mix(in_srgb,var(--brand)_50%,var(--border))]",
        className
      )}
      aria-label={`${nameLabel} (${recipeName})`}
      onClick={() => onAppend(op.name, { decode: !!decode })}
      onDragStart={(e) => {
        e.dataTransfer.setData(STEP_MIME, payload);
        e.dataTransfer.setData("text/plain", recipeName);
        if (decode) e.dataTransfer.setData("application/x-basilisk-decode", "1");
        e.dataTransfer.effectAllowed = "copy";
      }}
    >
      <Glyph id={glyphIdFor(op)} size={18} />
      <span className="min-w-0 flex-1 truncate text-left font-mono text-[0.72rem] font-semibold leading-tight">
        {nameLabel}
      </span>
    </button>
  );

  if (!showTooltip) return button;

  return (
    <Tooltip delayDuration={280}>
      <TooltipTrigger asChild>{button}</TooltipTrigger>
      <TooltipContent
        side="right"
        sideOffset={10}
        className="max-w-none border-0 bg-transparent p-0 text-left text-[var(--text)] shadow-none"
      >
        <ToolCard
          op={op}
          decode={!!decode}
          fit={fit}
          className="w-[300px] max-w-[min(300px,calc(100vw-2rem))]"
        />
      </TooltipContent>
    </Tooltip>
  );
}

export { TOOLBOX_META, getShelfMeta };
