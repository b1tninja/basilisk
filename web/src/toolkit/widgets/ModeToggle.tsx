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
  className?: string;
};

/** Segmented mode toggle (Pipeline/Source per cell, PGP profile, etc.). */
export function ModeToggle({ value, options, onChange, ariaLabel = "Mode", className }: Props) {
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
