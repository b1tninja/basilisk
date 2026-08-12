import * as React from "react";
import { cn } from "@/lib/cn";

/** Closed off for the same reason as `Input.disabled` — see the note there. */
export type TextareaProps = Omit<React.ComponentProps<"textarea">, "disabled"> & {
  disabled?: never;
};

export const Textarea = React.forwardRef<HTMLTextAreaElement, TextareaProps>(
  ({ className, ...props }, ref) => (
  <textarea
    className={cn(
      "flex min-h-[60px] w-full rounded-[6px] border border-[var(--input)] bg-[var(--background)] px-[9px] py-[6px] text-[length:12.5px] shadow-sm placeholder:text-[var(--muted-foreground)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--ring)] font-mono",
      className
    )}
    ref={ref}
    {...props}
  />
));
Textarea.displayName = "Textarea";
