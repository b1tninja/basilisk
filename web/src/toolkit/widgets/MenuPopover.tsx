import type { ReactNode } from "react";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { cn } from "@/lib/cn";

export type MenuPopoverItem = {
  id: string;
  label: string;
  onSelect?: () => void;
  href?: string;
  /**
   * Why this row declines, when it does.
   *
   * It was `disabled?: boolean`, which is the shape of the bug rather than an
   * instance of it: a menu is built by whoever calls this, so the *caller* is
   * the only thing that knows why a row is off, and a boolean is exactly the
   * channel that cannot carry it across. Nothing passed `true` — a dead row
   * with no explanation was simply the only row this type could describe.
   */
  disabledReason?: string;
  separatorBefore?: boolean;
};

type Props = {
  label: ReactNode;
  items: MenuPopoverItem[];
  heading?: string;
  align?: "start" | "center" | "end";
  className?: string;
  triggerClassName?: string;
};

/** Toolbar / chrome menu popover (Presets, Session, Docs). */
export function MenuPopover({
  label,
  items,
  heading,
  align = "end",
  className,
  triggerClassName,
}: Props) {
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button
          type="button"
          variant="ghost"
          size="sm"
          className={cn("toolbar-menu-trigger", triggerClassName)}
        >
          {label}
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align={align} className={cn("min-w-[12rem]", className)}>
        {heading ? <DropdownMenuLabel>{heading}</DropdownMenuLabel> : null}
        {items.map((item) => (
          <span key={item.id}>
            {item.separatorBefore ? <DropdownMenuSeparator /> : null}
            {item.href && !item.disabledReason ? (
              <DropdownMenuItem asChild>
                <a href={item.href}>{item.label}</a>
              </DropdownMenuItem>
            ) : (
              <DropdownMenuItem
                disabledReason={item.disabledReason}
                onSelect={() => item.onSelect?.()}
              >
                {item.label}
              </DropdownMenuItem>
            )}
          </span>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
