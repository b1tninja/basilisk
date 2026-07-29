import type { DragEvent } from "react";
import { cn } from "@/lib/cn";

type Props = {
  label?: string;
  active?: boolean;
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

/** Insert-at-index “+” — click to focus insert, drop target for reorder/ops. */
export function InsertGap({
  label = "Insert step here",
  active = false,
  onClick,
  onDragOver,
  onDragLeave,
  onDrop,
  className,
  ...data
}: Props) {
  return (
    <button
      type="button"
      className={cn(
        "cell-recipe-gap-add",
        active && "cell-recipe-gap-drop-active",
        className
      )}
      aria-label={label}
      title={label}
      data-gap-insert="1"
      data-cell={data["data-cell"]}
      data-gap-stem={data["data-gap-stem"]}
      data-gap-branch={data["data-gap-branch"]}
      data-gap-body={data["data-gap-body"]}
      onClick={onClick}
      onDragOver={onDragOver}
      onDragLeave={onDragLeave}
      onDrop={onDrop}
    >
      <span aria-hidden>+</span>
    </button>
  );
}
