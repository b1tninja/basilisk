import * as React from "react";
import { cn } from "@/lib/cn";

/**
 * `disabled` is closed off here for the reason it is closed off on `Button`: a
 * boolean cannot say why, and a field that has gone dead with nothing to read
 * is the defect this app kept shipping. Nothing disables an input today, so
 * there is no `disabledReason` to pair with it — giving one a refusal means
 * building the pairing first, in `refusal.tsx`, rather than reaching for the
 * attribute and leaving the reader with a grey box.
 */
export type InputProps = Omit<React.ComponentProps<"input">, "disabled"> & {
  disabled?: never;
};

export const Input = React.forwardRef<HTMLInputElement, InputProps>(
  ({ className, type, ...props }, ref) => (
    <input
      type={type}
      className={cn(
        "flex h-auto w-full rounded-[6px] border border-[var(--input)] bg-[var(--background)] px-[9px] py-[6px] text-[length:12.5px] shadow-sm transition-colors file:border-0 file:bg-transparent file:text-[length:12.5px] file:font-medium placeholder:text-[var(--muted-foreground)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--ring)]",
        className
      )}
      ref={ref}
      {...props}
    />
  )
);
Input.displayName = "Input";
