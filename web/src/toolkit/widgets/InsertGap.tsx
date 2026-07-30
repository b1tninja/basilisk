import type { DragEvent } from "react";
import { cn } from "@/lib/cn";

type Props = {
  label?: string;
  /** Dragging an op tile over this gap right now. */
  active?: boolean;
  /** This is the notebook's pendingInsert position — renders the HERE caret. */
  pending?: boolean;
  /** 'nested' = 14px hit target inside a compound-op chip (§20f). */
  scale?: "default" | "nested";
  onClick?: () => void;
  onDragOver?: (e: DragEvent) => void;
  onDragLeave?: (e: DragEvent) => void;
  onDrop?: (e: DragEvent) => void;
  className?: string;
  /** data-* passthrough for legacy hosts */
  "data-gap-stem"?: number;
  "data-gap-branch"?: number;
  "data-gap-body"?: number;
  "data-cell"?: number;
};

/** Insert-at-index caret — click to focus insert, drop target for reorder/ops (§19d). */
export function InsertGap({
  label = "Insert step here",
  active = false,
  pending = false,
  scale = "default",
  onClick,
  onDragOver,
  onDragLeave,
  onDrop,
  className,
  ...data
}: Props) {
  const shared = {
    "data-gap-insert": "1",
    "data-cell": data["data-cell"],
    "data-gap-stem": data["data-gap-stem"],
    "data-gap-branch": data["data-gap-branch"],
    "data-gap-body": data["data-gap-body"],
    onClick,
    onDragOver,
    onDragLeave,
    onDrop,
  } as const;

  if (pending && !active) {
    return (
      <button
        type="button"
        className={cn("cell-recipe-gap-caret", className)}
        aria-label={`${label} — insert position`}
        title={label}
        {...shared}
      >
        <span className="cell-recipe-gap-caret-bar" aria-hidden />
        <span className="cell-recipe-gap-caret-label" aria-hidden>
          HERE
        </span>
      </button>
    );
  }

  return (
    <button
      type="button"
      className={cn(
        "cell-recipe-gap-add",
        scale === "nested" && "cell-recipe-gap-nested",
        active && "cell-recipe-gap-drop-active",
        className
      )}
      aria-label={label}
      title={label}
      {...shared}
    >
      <span aria-hidden>+</span>
    </button>
  );
}
