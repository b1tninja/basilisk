import type { DragEvent, KeyboardEvent, ReactNode } from "react";
import { X } from "lucide-react";
import { cn } from "@/lib/cn";
import { Glyph, glyphIdFor } from "./Glyph";
import type { ToolCardOp } from "./ToolCard";

export type SuggestChipVariant = "candidate" | "placed" | "selector" | "editable";

type Props = {
  label: string;
  hint?: string;
  variant?: SuggestChipVariant;
  selected?: boolean;
  error?: boolean;
  op?: Pick<ToolCardOp, "glyph" | "shelf" | "toolbox" | "name">;
  glyphId?: string;
  draggable?: boolean;
  onClick?: () => void;
  onDragStart?: (e: DragEvent) => void;
  onDragEnd?: (e: DragEvent) => void;
  /** Show a trailing × that removes this placed step (does not fire onClick). */
  onRemove?: () => void;
  className?: string;
  title?: string;
  children?: ReactNode;
};

/** Compact step pill — suggest candidate, placed recipe step, or selector. */
export function SuggestChip({
  label,
  hint,
  variant = "candidate",
  selected = false,
  error = false,
  op,
  glyphId,
  draggable = false,
  onClick,
  onDragStart,
  onDragEnd,
  onRemove,
  className,
  title,
  children,
}: Props) {
  const clickable = !!(onClick || variant === "editable");
  const gid = glyphId || (op ? glyphIdFor(op) : "");
  const isPrimary = variant === "selector";

  const chipClass = cn(
    "suggest-chip",
    variant === "placed" || variant === "editable"
      ? "builder-ingredient-chip"
      : null,
    variant === "editable" && "builder-ingredient-chip-edit",
    isPrimary && "suggest-chip-primary builder-branch-selector",
    selected && "is-selected",
    error && "builder-ingredient-chip-error",
    onRemove && "suggest-chip-with-remove",
    className
  );

  const body = (
    <>
      {gid ? <Glyph id={gid} size={16} svgClassName="ops-glyph" /> : null}
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
      <span className={chipClass} role="group" title={title}>
        {clickable ? (
          <button
            type="button"
            className="suggest-chip-hit"
            draggable={draggable || undefined}
            aria-pressed={variant === "editable" ? selected : undefined}
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
      aria-pressed={variant === "editable" ? selected : undefined}
      onClick={onClick}
      onDragStart={onDragStart}
      onDragEnd={onDragEnd}
    >
      {body}
    </Tag>
  );
}
