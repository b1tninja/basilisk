import type { DragEvent, KeyboardEvent, ReactNode } from "react";
import { X } from "lucide-react";
import { cn } from "@/lib/cn";
import { ToolboxDot } from "./Glyph";
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
  className?: string;
  title?: string;
  children?: ReactNode;
};

/** Compact step pill — suggest candidate, placed recipe step, or selector. */
export function SuggestChip({
  label,
  hint,
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

  const body = (
    <>
      {op ? <ToolboxDot op={op} /> : null}
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
      aria-pressed={variant === "placed" ? selected : undefined}
      onClick={onClick}
      onDragStart={onDragStart}
      onDragEnd={onDragEnd}
    >
      {body}
    </Tag>
  );
}
