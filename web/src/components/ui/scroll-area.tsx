import * as React from "react";
import { cn } from "@/lib/cn";

/**
 * A scrollable region — a div that scrolls, with the scrollbar styled in CSS.
 *
 * This used to wrap `@radix-ui/react-scroll-area`, which renders a `<style>`
 * element at runtime to hide the native scrollbars it replaces with its own
 * JS-driven thumb. Under `style-src 'self'` that injection is refused, so on
 * the built site the rules never applied *and* every mount reported a CSP
 * violation — all for styling that `overflow` and `::-webkit-scrollbar`
 * express directly, with no script and nothing to inject.
 *
 * The props are unchanged, so no call site moved. What is lost is Radix's
 * synthetic thumb; what replaces it is the platform's own, styled to the same
 * tokens in `toolkit.css`.
 */
export const ScrollArea = React.forwardRef<
  HTMLDivElement,
  React.HTMLAttributes<HTMLDivElement>
>(({ className, children, ...props }, ref) => (
  <div ref={ref} className={cn("scroll-area relative", className)} {...props}>
    {children}
  </div>
));
ScrollArea.displayName = "ScrollArea";
