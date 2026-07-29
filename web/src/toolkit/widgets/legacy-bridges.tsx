import { createElement } from "react";
import { TooltipProvider } from "@/components/ui/tooltip";
import { ToolCard, type ToolCardOp } from "./ToolCard";
import { OpsShelf, type OpsShelfOp } from "./OpsShelf";
import { ParamFieldGroup, type ParamSpec } from "./ParamField";
import { ModeToggle, type ModeOption } from "./ModeToggle";
import { SuggestChip } from "./SuggestChip";
import { InsertGap } from "./InsertGap";
import {
  SuggestRail,
  type SuggestComposeChip,
  type SuggestRailChip,
  type SuggestRailItem,
  type SuggestRailToolbox,
} from "./SuggestRail";
import {
  RecipeChipFlow,
  type RecipeChipFlowProps,
} from "./RecipeChipFlow";
import { MenuPopover, type MenuPopoverItem } from "./MenuPopover";
import { PresetMenu, type PresetMenuItem } from "./PresetMenu";
import { renderIsland } from "./mount";

export type ToolCardMountProps = {
  op: ToolCardOp;
  decode?: boolean;
  blocked?: boolean;
  fit?: boolean;
  compact?: boolean;
  hideHint?: boolean;
  className?: string;
};

/** Mount ToolCard into a legacy host (ops pop / chip hover). */
export function mountToolCard(host: Element | null, props: ToolCardMountProps | null): void {
  if (!host) return;
  if (!props) {
    renderIsland(host, null);
    return;
  }
  renderIsland(
    host,
    createElement(
      TooltipProvider,
      null,
      createElement(ToolCard, {
        op: props.op,
        decode: props.decode,
        blocked: props.blocked,
        fit: props.fit,
        compact: props.compact,
        hideHint: props.hideHint ?? true,
        className: props.className,
      })
    )
  );
}

export type OpsShelfMountProps = {
  ops: OpsShelfOp[];
  filter: string;
  onFilter: (q: string) => void;
  onAppend: (
    name: string,
    opts?: { decode?: boolean; params?: Record<string, unknown> }
  ) => void;
  tipFit?: Set<string> | null;
  tip?: { base?: string; kind?: string; encoding?: string } | null;
  hideSearch?: boolean;
};

export function mountOpsShelf(host: Element | null, props: OpsShelfMountProps | null): void {
  if (!host) return;
  if (!props) {
    renderIsland(host, null);
    return;
  }
  renderIsland(
    host,
    createElement(
      TooltipProvider,
      null,
      createElement(OpsShelf, {
        ops: props.ops,
        filter: props.filter,
        onFilter: props.onFilter,
        onAppend: props.onAppend,
        tipFit: props.tipFit,
        tip: props.tip,
        hideSearch: props.hideSearch,
        bare: true,
        className: "ops-shelf-island h-full min-h-0",
      })
    )
  );
}

export function mountParamFields(
  host: Element | null,
  props: {
    params: ParamSpec[];
    values: Record<string, unknown>;
    onChange: (name: string, value: string | number | boolean) => void;
    visibilityFor?: (p: ParamSpec) => { show: boolean; forced?: unknown; locked?: boolean };
  } | null
): void {
  if (!host) return;
  if (!props) {
    renderIsland(host, null);
    return;
  }
  renderIsland(host, createElement(ParamFieldGroup, props));
}

export function mountModeToggle(
  host: Element | null,
  props: {
    value: string;
    options: ModeOption[];
    onChange: (value: string) => void;
    legacy?: boolean;
    ariaLabel?: string;
    className?: string;
  } | null
): void {
  if (!host) return;
  if (!props) {
    renderIsland(host, null);
    return;
  }
  renderIsland(
    host,
    createElement(ModeToggle, {
      value: props.value,
      options: props.options,
      onChange: props.onChange,
      legacy: props.legacy !== false,
      ariaLabel: props.ariaLabel || "Mode",
      className: props.className,
    })
  );
}

export function mountSuggestChip(
  host: Element | null,
  props: React.ComponentProps<typeof SuggestChip> | null
): void {
  if (!host) return;
  if (!props) {
    renderIsland(host, null);
    return;
  }
  renderIsland(host, createElement(SuggestChip, props));
}

export function mountInsertGap(
  host: Element | null,
  props: React.ComponentProps<typeof InsertGap> | null
): void {
  if (!host) return;
  if (!props) {
    renderIsland(host, null);
    return;
  }
  renderIsland(host, createElement(InsertGap, props));
}

export type SuggestRailMountProps = {
  items?: SuggestRailItem[];
  onAppend: (name: string, opts?: { decode?: boolean }) => void;
  expandable?: boolean;
  expanded?: boolean;
  onToggleExpand?: () => void;
  expandLabel?: string;
  toolboxes?: SuggestRailToolbox[];
  activeToolbox?: string | null;
  onToolboxClick?: (id: string) => void;
  pulloutChips?: SuggestRailChip[];
  onOpenOps?: (tb: string) => void;
  onClosePullout?: () => void;
  composeChips?: SuggestComposeChip[];
  onCompose?: (id: string) => void;
  scope?: "cell" | "nest";
  className?: string;
};

export function mountSuggestRail(
  host: Element | null,
  props: SuggestRailMountProps | null
): void {
  if (!host) return;
  if (!props) {
    renderIsland(host, null);
    return;
  }
  renderIsland(
    host,
    createElement(
      TooltipProvider,
      null,
      createElement(SuggestRail, props)
    )
  );
}

export function mountMenuPopover(
  host: Element | null,
  props: {
    label: string;
    items: MenuPopoverItem[];
    heading?: string;
    align?: "start" | "center" | "end";
    className?: string;
    triggerClassName?: string;
  } | null
): void {
  if (!host) return;
  if (!props) {
    renderIsland(host, null);
    return;
  }
  renderIsland(
    host,
    createElement(MenuPopover, {
      label: props.label,
      items: props.items,
      heading: props.heading,
      align: props.align,
      className: props.className,
      triggerClassName: props.triggerClassName,
    })
  );
}

export function mountPresetMenu(
  host: Element | null,
  props: {
    presets: PresetMenuItem[];
    groups?: string[];
    onLoad: (id: string) => void;
    onAppend: (id: string) => void;
    onAddBoth: (pairId: string) => void;
    label?: string;
    align?: "start" | "center" | "end";
    triggerClassName?: string;
  } | null
): void {
  if (!host) return;
  if (!props) {
    renderIsland(host, null);
    return;
  }
  renderIsland(
    host,
    createElement(PresetMenu, {
      presets: props.presets,
      groups: props.groups,
      onLoad: props.onLoad,
      onAppend: props.onAppend,
      onAddBoth: props.onAddBoth,
      label: props.label,
      align: props.align ?? "start",
      triggerClassName:
        props.triggerClassName || "btn btn-ghost btn-compact toolkit-presets-summary",
    })
  );
}

/** Mount Preview chip flow (SuggestChip + InsertGap + SuggestRail). */
export function mountRecipeChipFlow(
  host: Element | null,
  props: RecipeChipFlowProps | null
): void {
  if (!host) return;
  if (!props) {
    renderIsland(host, null);
    return;
  }
  renderIsland(
    host,
    createElement(
      TooltipProvider,
      null,
      createElement(RecipeChipFlow, props)
    )
  );
}
