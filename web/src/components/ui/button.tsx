import * as React from "react";
import { Slot } from "@radix-ui/react-slot";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/cn";
import { RefusalLayout, useRefusal, type RefusalOptions } from "./refusal";

export const buttonVariants = cva(
  // `aria-disabled`, not `:disabled` — see the note on `disabledReason`. The
  // refused button keeps its pointer events, because it has to receive the
  // click in order to refuse it, and hover has to be able to reach it.
  "inline-flex items-center justify-center gap-1 whitespace-nowrap rounded-md font-semibold transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--ring)] aria-disabled:cursor-not-allowed aria-disabled:opacity-50 [&_svg]:pointer-events-none [&_svg]:shrink-0",
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
  extends Omit<React.ButtonHTMLAttributes<HTMLButtonElement>, "disabled">,
    VariantProps<typeof buttonVariants>,
    RefusalOptions {
  asChild?: boolean;
  /**
   * Why this button declines, *here and now* — a sentence naming the state the
   * reader is in, not a restatement of the fact that it is off.
   *
   * Its presence is what makes the button inert, so "off with no explanation"
   * has no spelling: the two cannot drift apart, and the 33 controls that could
   * go dead in front of a person with nothing to read cannot come back one at a
   * time. The button renders it under itself and points `aria-describedby` at
   * it; pass `reasonId` instead where the panel already says it out loud.
   *
   * Undefined when the button works. A button that is *meaningless* here rather
   * than merely impossible should not render at all (§33d) — the reason is for
   * a control the reader could reasonably expect to press.
   */
  disabledReason?: string;
  /**
   * Not a prop. `disabled` is a boolean, and a boolean cannot say why — which
   * is the entire defect. Write `disabledReason` and let its presence do this.
   */
  disabled?: never;
}

/**
 * The button, and the one rule it enforces for every control in the app: it
 * cannot be turned off without saying why. See `refusal.tsx` for the mechanism
 * and the reasoning behind `aria-disabled` over the `disabled` attribute.
 */
export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  (
    {
      className,
      variant,
      size,
      asChild = false,
      disabledReason,
      reasonId,
      busy,
      onClick,
      ...props
    },
    ref
  ) => {
    const refusal = useRefusal(disabledReason, { busy, reasonId });
    const Comp = asChild ? Slot : "button";
    return (
      <RefusalLayout note={refusal.note}>
        <Comp
          className={cn(buttonVariants({ variant, size, className }))}
          ref={ref}
          {...refusal.aria}
          onClick={refusal.guard(onClick)}
          {...props}
        />
      </RefusalLayout>
    );
  }
);
Button.displayName = "Button";
