import type { DragEvent, KeyboardEvent, ReactNode } from "react";
import { X } from "lucide-react";
import { cn } from "@/lib/cn";
import { ToolboxDot, shapeForType } from "./Glyph";
import type { ToolCardOp } from "./ToolCard";

export type SuggestChipVariant = "placed" | "selector" | "ghost";

type Props = {
  label: string;
  hint?: string;
  variant?: SuggestChipVariant;
  selected?: boolean;
  error?: boolean;
  op?: Pick<ToolCardOp, "glyph" | "shelf" | "toolbox" | "name" | "output">;
  draggable?: boolean;
  onClick?: () => void;
  onDragStart?: (e: DragEvent) => void;
  onDragEnd?: (e: DragEvent) => void;
  /** Show a trailing × that removes this placed step (does not fire onClick). */
  onRemove?: () => void;
  /**
   * This step is handling a private key that was exported into the pipeline
   * (§26c). Renders as a thin --warn underline: a fact about what is in
   * play, not an alarm — the codebase reserves --error for things that
   * failed, and this op is legitimate.
   */
  keyExposed?: boolean;
  className?: string;
  title?: string;
  children?: ReactNode;
};

/** Compact step pill — suggest candidate, placed recipe step, or selector. */
export function SuggestChip({
  label,
  hint,
  keyExposed,
  variant = "ghost",
  selected = false,
  error = false,
  op,
  draggable = false,
  onClick,
  onDragStart,
  onDragEnd,
  onRemove,
  className,
  title,
  children,
}: Props) {
  const clickable = !!onClick;
  const isPrimary = variant === "selector";

  const chipClass = cn(
    "suggest-chip",
    variant === "placed" && "builder-ingredient-chip",
    variant === "ghost" &&
      "border-dashed border-[var(--border)] bg-transparent text-[var(--muted-foreground)]",
    isPrimary && "suggest-chip-primary builder-branch-selector",
    selected && "is-selected",
    error && "builder-ingredient-chip-error",
    onRemove && "suggest-chip-with-remove",
    className
  );

  /*
   * The dot was carrying two orthogonal encodings at once: its shape said
   * what kind of value the step produces (§25a — address, session, live
   * channel, observe-only) and its colour said which toolbox the step came
   * from. On a chip the colour was the redundant half: the chip's own label
   * is `gpg.encrypt` or `sss.split`, which names the toolbox in words right
   * beside it. So the dot rendered on every chip and, for the ~95% of steps
   * that emit ordinary DATA, said nothing at all — the shape channel was
   * blank and the colour channel was a duplicate.
   *
   * Now its presence is the signal: a chip carries a mark only when the value
   * is not ordinary data, which is exactly when "this is not a byte string
   * you can save" is worth interrupting the reader for. The colour survives
   * only there, where the originating toolbox is genuinely additional
   * information and where a 5px hollow ring needs the contrast to be seen at
   * all. ToolboxDot gives those a real accessible name.
   */
  const marked = !!op && !!shapeForType(op.output);

  const body = (
    <>
      {op && marked ? <ToolboxDot op={op} /> : null}
      <span className="suggest-chip-name">{label}</span>
      {hint ? <span className="suggest-chip-out muted">{hint}</span> : null}
      {children}
    </>
  );

  const removeBtn = onRemove ? (
    <button
      type="button"
      className="suggest-chip-remove"
      aria-label={`Remove ${label}`}
      title={`Remove ${label}`}
      onClick={(e) => {
        e.preventDefault();
        e.stopPropagation();
        onRemove();
      }}
      onMouseDown={(e) => e.stopPropagation()}
      onKeyDown={(e: KeyboardEvent) => {
        if (e.key === "Enter" || e.key === " ") e.stopPropagation();
      }}
    >
      <X size={12} strokeWidth={2.25} aria-hidden />
    </button>
  ) : null;

  // Avoid nested <button>: when removable, outer is a group and the hit target is separate.
  if (onRemove) {
    return (
      <span
        className={chipClass}
        role="group"
        title={title}
        data-key-exposed={keyExposed || undefined}
      >
        {clickable ? (
          <button
            type="button"
            className="suggest-chip-hit"
            draggable={draggable || undefined}
            aria-pressed={variant === "placed" ? selected : undefined}
            onClick={onClick}
            onDragStart={onDragStart}
            onDragEnd={onDragEnd}
          >
            {body}
          </button>
        ) : (
          <span
            className="suggest-chip-hit"
            draggable={draggable || undefined}
            onDragStart={onDragStart}
            onDragEnd={onDragEnd}
          >
            {body}
          </span>
        )}
        {removeBtn}
      </span>
    );
  }

  const Tag = clickable ? "button" : "span";
  return (
    <Tag
      type={Tag === "button" ? "button" : undefined}
      draggable={draggable || undefined}
      className={chipClass}
      title={title}
      data-key-exposed={keyExposed || undefined}
      aria-pressed={variant === "placed" ? selected : undefined}
      onClick={onClick}
      onDragStart={onDragStart}
      onDragEnd={onDragEnd}
    >
      {body}
    </Tag>
  );
}
