import * as React from "react";
import * as DropdownMenuPrimitive from "@radix-ui/react-dropdown-menu";
import { cn } from "@/lib/cn";
import { useRefusal } from "./refusal";

export const DropdownMenu = DropdownMenuPrimitive.Root;
export const DropdownMenuTrigger = DropdownMenuPrimitive.Trigger;
export const DropdownMenuGroup = DropdownMenuPrimitive.Group;
export const DropdownMenuPortal = DropdownMenuPrimitive.Portal;
export const DropdownMenuSub = DropdownMenuPrimitive.Sub;
export const DropdownMenuRadioGroup = DropdownMenuPrimitive.RadioGroup;

export const DropdownMenuContent = React.forwardRef<
  React.ElementRef<typeof DropdownMenuPrimitive.Content>,
  React.ComponentPropsWithoutRef<typeof DropdownMenuPrimitive.Content>
>(({ className, sideOffset = 4, ...props }, ref) => (
  <DropdownMenuPrimitive.Portal>
    <DropdownMenuPrimitive.Content
      ref={ref}
      sideOffset={sideOffset}
      className={cn(
        "z-50 min-w-[10rem] overflow-hidden rounded-md border border-[var(--border)] bg-[var(--popover)] p-1 text-[var(--popover-foreground)] shadow-md",
        className
      )}
      {...props}
    />
  </DropdownMenuPrimitive.Portal>
));
DropdownMenuContent.displayName = DropdownMenuPrimitive.Content.displayName;

export const DropdownMenuItem = React.forwardRef<
  React.ElementRef<typeof DropdownMenuPrimitive.Item>,
  Omit<React.ComponentPropsWithoutRef<typeof DropdownMenuPrimitive.Item>, "disabled"> & {
    inset?: boolean;
    /**
     * Why this item declines — the same contract as `Button.disabledReason`,
     * and for the same reason: a menu row that does nothing when pressed is the
     * defect at its least visible, because the menu closes and the reader is
     * left where they started with nothing to read.
     *
     * Radix's own `disabled` is deliberately not used. It takes the row out of
     * the arrow-key walk, which puts the explanation out of reach of exactly
     * the people it was written for; the row stays reachable and refuses on
     * select instead. The sentence renders under the label, in the menu.
     */
    disabledReason?: string;
    /** Not a prop — a boolean cannot say why. Write `disabledReason`. */
    disabled?: never;
  }
>(({ className, inset, disabledReason, children, onSelect, asChild, ...props }, ref) => {
  const refusal = useRefusal(disabledReason);
  /**
   * `asChild` hands the row's markup to the caller, and a Slot takes exactly
   * one child — so there is nowhere to put the sentence. Rather than drop it
   * silently, the refused row renders as an ordinary item: the caller's element
   * is almost always an `<a>`, and a link that cannot be followed should not be
   * offering itself as one.
   */
  const slotted = asChild && !refusal.refused;
  return (
    <DropdownMenuPrimitive.Item
      ref={ref}
      className={cn(
        "relative flex cursor-default select-none gap-2 rounded-sm px-2 py-1.5 text-sm outline-none focus:bg-[var(--accent)] aria-disabled:cursor-not-allowed",
        // Two lines when there is a reason under the label, so the row's
        // leading content aligns with the label rather than with their centre.
        refusal.refused ? "items-start" : "items-center",
        inset && "pl-8",
        className
      )}
      asChild={slotted}
      {...refusal.aria}
      onSelect={(event) => {
        // `preventDefault` keeps the menu open, so the sentence is still on
        // screen after the press that asked for it.
        if (refusal.inert) {
          event.preventDefault();
          return;
        }
        onSelect?.(event);
      }}
      {...props}
    >
      {refusal.note ? (
        <span className="flex min-w-0 flex-col gap-[3px]">
          <span className="opacity-60">{children}</span>
          {refusal.note}
        </span>
      ) : (
        children
      )}
    </DropdownMenuPrimitive.Item>
  );
});
DropdownMenuItem.displayName = DropdownMenuPrimitive.Item.displayName;

export const DropdownMenuSubTrigger = React.forwardRef<
  React.ElementRef<typeof DropdownMenuPrimitive.SubTrigger>,
  React.ComponentPropsWithoutRef<typeof DropdownMenuPrimitive.SubTrigger> & {
    inset?: boolean;
  }
>(({ className, inset, children, ...props }, ref) => (
  <DropdownMenuPrimitive.SubTrigger
    ref={ref}
    className={cn(
      "flex cursor-default select-none items-center rounded-sm px-2 py-1.5 text-sm outline-none focus:bg-[var(--accent)] data-[state=open]:bg-[var(--accent)]",
      inset && "pl-8",
      className
    )}
    {...props}
  >
    {children}
    <span className="ml-auto text-[0.65rem] opacity-60" aria-hidden>
      ›
    </span>
  </DropdownMenuPrimitive.SubTrigger>
));
DropdownMenuSubTrigger.displayName = DropdownMenuPrimitive.SubTrigger.displayName;

export const DropdownMenuSubContent = React.forwardRef<
  React.ElementRef<typeof DropdownMenuPrimitive.SubContent>,
  React.ComponentPropsWithoutRef<typeof DropdownMenuPrimitive.SubContent>
>(({ className, ...props }, ref) => (
  <DropdownMenuPrimitive.SubContent
    ref={ref}
    className={cn(
      "z-50 min-w-[14rem] max-h-[min(60vh,24rem)] overflow-auto rounded-md border border-[var(--border)] bg-[var(--popover)] p-1 text-[var(--popover-foreground)] shadow-md",
      className
    )}
    {...props}
  />
));
DropdownMenuSubContent.displayName = DropdownMenuPrimitive.SubContent.displayName;

export const DropdownMenuSeparator = React.forwardRef<
  React.ElementRef<typeof DropdownMenuPrimitive.Separator>,
  React.ComponentPropsWithoutRef<typeof DropdownMenuPrimitive.Separator>
>(({ className, ...props }, ref) => (
  <DropdownMenuPrimitive.Separator
    ref={ref}
    className={cn("-mx-1 my-1 h-px bg-[var(--border)]", className)}
    {...props}
  />
));
DropdownMenuSeparator.displayName = DropdownMenuPrimitive.Separator.displayName;

export const DropdownMenuLabel = React.forwardRef<
  React.ElementRef<typeof DropdownMenuPrimitive.Label>,
  React.ComponentPropsWithoutRef<typeof DropdownMenuPrimitive.Label>
>(({ className, ...props }, ref) => (
  <DropdownMenuPrimitive.Label
    ref={ref}
    className={cn("px-2 py-1.5 text-xs font-semibold text-[var(--muted-foreground)]", className)}
    {...props}
  />
));
DropdownMenuLabel.displayName = DropdownMenuPrimitive.Label.displayName;
