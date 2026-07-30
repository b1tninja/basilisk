import * as React from "react";
import { cn } from "@/lib/cn";

export const Input = React.forwardRef<HTMLInputElement, React.ComponentProps<"input">>(
  ({ className, type, ...props }, ref) => (
    <input
      type={type}
      className={cn(
        "flex h-auto w-full rounded-[6px] border border-[var(--input)] bg-[var(--background)] px-[9px] py-[6px] text-[length:12.5px] shadow-sm transition-colors file:border-0 file:bg-transparent file:text-[length:12.5px] file:font-medium placeholder:text-[var(--muted-foreground)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--ring)] disabled:cursor-not-allowed disabled:opacity-50",
        className
      )}
      ref={ref}
      {...props}
    />
  )
);
Input.displayName = "Input";
