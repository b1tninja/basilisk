import * as React from "react";
import { cn } from "@/lib/cn";

export const Textarea = React.forwardRef<
  HTMLTextAreaElement,
  React.ComponentProps<"textarea">
>(({ className, ...props }, ref) => (
  <textarea
    className={cn(
      "flex min-h-[60px] w-full rounded-[6px] border border-[var(--input)] bg-[var(--background)] px-[9px] py-[6px] text-[length:12.5px] shadow-sm placeholder:text-[var(--muted-foreground)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--ring)] disabled:cursor-not-allowed disabled:opacity-50 font-mono",
      className
    )}
    ref={ref}
    {...props}
  />
));
Textarea.displayName = "Textarea";
