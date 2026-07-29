import { cn } from "@/lib/cn";
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group";

export type ModeOption = {
  value: string;
  label: string;
  title?: string;
};

type Props = {
  value: string;
  options: ModeOption[];
  onChange: (value: string) => void;
  ariaLabel?: string;
  /** Use legacy cell-recipe-mode button styles instead of ToggleGroup. */
  legacy?: boolean;
  className?: string;
};

/** Segmented mode toggle (Preview/Raw/Cards, PGP profile, etc.). */
export function ModeToggle({
  value,
  options,
  onChange,
  ariaLabel = "Mode",
  legacy = false,
  className,
}: Props) {
  if (legacy) {
    return (
      <div className={cn("cell-recipe-mode", className)} role="group" aria-label={ariaLabel}>
        {options.map((opt) => (
          <button
            key={opt.value}
            type="button"
            className={cn("cell-recipe-mode-btn", value === opt.value && "is-active")}
            aria-pressed={value === opt.value}
            title={opt.title}
            onClick={() => onChange(opt.value)}
          >
            {opt.label}
          </button>
        ))}
      </div>
    );
  }

  return (
    <ToggleGroup
      type="single"
      value={value}
      onValueChange={(v) => {
        if (v) onChange(v);
      }}
      aria-label={ariaLabel}
      className={className}
    >
      {options.map((opt) => (
        <ToggleGroupItem key={opt.value} value={opt.value} title={opt.title}>
          {opt.label}
        </ToggleGroupItem>
      ))}
    </ToggleGroup>
  );
}
