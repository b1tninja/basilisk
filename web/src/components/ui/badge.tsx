import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/cn";

const badgeVariants = cva(
  "inline-flex items-center rounded-md border px-2 py-0.5 text-[0.65rem] font-bold tracking-wide uppercase transition-colors",
  {
    variants: {
      variant: {
        default: "border-transparent bg-[color-mix(in_srgb,var(--brand)_16%,transparent)] text-[var(--brand)]",
        secondary: "border-[var(--border)] bg-[var(--muted)] text-[var(--muted-foreground)]",
        warn: "border-[color-mix(in_srgb,var(--accent)_45%,var(--border))] bg-[color-mix(in_srgb,var(--accent)_18%,transparent)] text-[var(--foreground)]",
        ok: "border-[color-mix(in_srgb,var(--success)_40%,var(--border))] bg-[color-mix(in_srgb,var(--success)_14%,transparent)] text-[var(--success)]",
        destructive:
          "border-[color-mix(in_srgb,var(--error)_40%,var(--border))] bg-[color-mix(in_srgb,var(--error)_14%,transparent)] text-[var(--error)]",
      },
    },
    defaultVariants: { variant: "default" },
  }
);

export function Badge({
  className,
  variant,
  ...props
}: React.ComponentProps<"div"> & VariantProps<typeof badgeVariants>) {
  return <div className={cn(badgeVariants({ variant }), className)} {...props} />;
}
