import * as React from "react";
import { Slot } from "@radix-ui/react-slot";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/cn";

export const buttonVariants = cva(
  "inline-flex items-center justify-center gap-1 whitespace-nowrap rounded-md font-semibold transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--ring)] disabled:pointer-events-none disabled:opacity-50 [&_svg]:pointer-events-none [&_svg]:shrink-0",
  {
    variants: {
      variant: {
        default: "bg-[var(--primary)] text-[var(--primary-foreground)] hover:opacity-90",
        secondary:
          "bg-[var(--secondary)] text-[var(--secondary-foreground)] border border-[var(--border)] hover:bg-[color-mix(in_srgb,var(--brand)_8%,var(--surface-raised))]",
        ghost: "hover:bg-[color-mix(in_srgb,var(--brand)_10%,transparent)] text-[var(--foreground)]",
        outline:
          "border border-[var(--border)] bg-transparent hover:bg-[color-mix(in_srgb,var(--brand)_8%,transparent)]",
        destructive: "bg-[var(--destructive)] text-white hover:opacity-90",
      },
      size: {
        default: "h-auto rounded-[8px] px-[11px] py-[6px] text-[length:12.5px] [&_svg]:size-4",
        sm: "h-auto rounded-[6px] px-[9px] py-[4px] text-[length:10.5px] [&_svg]:size-3.5",
        lg: "h-auto rounded-[9px] px-[16px] py-[9px] text-[length:13.5px] [&_svg]:size-4",
        icon: "h-7 w-7 rounded-[6px] [&_svg]:size-4",
      },
    },
    defaultVariants: {
      variant: "default",
      size: "default",
    },
  }
);

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {
  asChild?: boolean;
}

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, asChild = false, ...props }, ref) => {
    const Comp = asChild ? Slot : "button";
    return (
      <Comp className={cn(buttonVariants({ variant, size, className }))} ref={ref} {...props} />
    );
  }
);
Button.displayName = "Button";
