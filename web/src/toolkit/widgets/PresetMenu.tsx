import { useMemo, useState, type ReactNode } from "react";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { cn } from "@/lib/cn";
import {
  bridgeModeMeta,
  stitchPresetPair,
} from "../../lib/toolkit/conjugate-stitch.js";
import { listPresetGroups } from "../../lib/toolkit/recipe.js";

export type PresetMenuItem = {
  id: string;
  group?: string;
  title: string;
  blurb?: string;
  recipe?: string;
  pair?: string;
};

type Props = {
  presets: PresetMenuItem[];
  /** Optional override; defaults to listPresetGroups(presets). */
  groups?: string[];
  label?: ReactNode;
  onLoad: (id: string) => void;
  onAppend: (id: string) => void;
  onAddBoth: (pairId: string) => void;
  align?: "start" | "center" | "end";
  className?: string;
  triggerClassName?: string;
  /** Controlled open (optional). */
  open?: boolean;
  onOpenChange?: (open: boolean) => void;
};

type PairBundle = {
  pairId: string;
  forward: PresetMenuItem;
  reverse: PresetMenuItem;
};

function groupPresets(
  presets: PresetMenuItem[],
  groups: string[],
  q: string
): Map<string, PresetMenuItem[]> {
  const needle = q.trim().toLowerCase();
  const matches = (p: PresetMenuItem) => {
    if (!needle) return true;
    return (
      p.id.toLowerCase().includes(needle) ||
      p.title.toLowerCase().includes(needle) ||
      (p.blurb || "").toLowerCase().includes(needle) ||
      (p.recipe || "").toLowerCase().includes(needle) ||
      (p.group || "").toLowerCase().includes(needle)
    );
  };
  const byGroup = new Map<string, PresetMenuItem[]>();
  for (const g of groups) byGroup.set(g, []);
  for (const p of presets) {
    if (!matches(p)) continue;
    const g = p.group || "Pipelines";
    if (!byGroup.has(g)) byGroup.set(g, []);
    byGroup.get(g)!.push(p);
  }
  return byGroup;
}

function packItems(presets: PresetMenuItem[]): Array<
  | { kind: "single"; preset: PresetMenuItem }
  | { kind: "pair"; bundle: PairBundle }
> {
  const out: Array<
    | { kind: "single"; preset: PresetMenuItem }
    | { kind: "pair"; bundle: PairBundle }
  > = [];
  for (let i = 0; i < presets.length; i++) {
    const p = presets[i];
    const next = presets[i + 1];
    if (p.pair && next?.pair === p.pair) {
      out.push({
        kind: "pair",
        bundle: { pairId: p.pair, forward: p, reverse: next },
      });
      i++;
    } else {
      out.push({ kind: "single", preset: p });
    }
  }
  return out;
}

function PresetCard({
  preset,
  onLoad,
  onAppend,
}: {
  preset: PresetMenuItem;
  onLoad: (id: string) => void;
  onAppend: (id: string) => void;
}) {
  const [showRecipe, setShowRecipe] = useState(false);
  return (
    <div className="preset-card-wrap">
      <button
        type="button"
        className="preset-card"
        title="Replace notebook with this template"
        onClick={() => onLoad(preset.id)}
      >
        <strong>{preset.title}</strong>
        <span className="muted">{preset.blurb}</span>
      </button>
      <div className="preset-card-actions">
        <button
          type="button"
          className="btn btn-ghost btn-compact preset-append-btn"
          title="Append this template’s chains as new cells"
          onClick={(e) => {
            e.stopPropagation();
            onAppend(preset.id);
          }}
        >
          Append
        </button>
        <details
          className="preset-recipe-details"
          open={showRecipe}
          onToggle={(e) => {
            e.stopPropagation();
            setShowRecipe((e.target as HTMLDetailsElement).open);
          }}
        >
          <summary className="muted fs-xs">Show recipe</summary>
          <code className="preset-recipe">{preset.recipe}</code>
        </details>
      </div>
    </div>
  );
}

function CompanionPair({
  bundle,
  onLoad,
  onAppend,
  onAddBoth,
}: {
  bundle: PairBundle;
  onLoad: (id: string) => void;
  onAppend: (id: string) => void;
  onAddBoth: (pairId: string) => void;
}) {
  const { meta, mode } = useMemo(() => {
    const st = stitchPresetPair(bundle.forward, bundle.reverse);
    return {
      mode: st.mode,
      meta: bridgeModeMeta(st.mode, st.bridge),
    };
  }, [bundle.forward, bundle.reverse]);
  const labelId = `preset-pair-${bundle.pairId}`;

  return (
    <div className="preset-pair" role="group" aria-labelledby={labelId}>
      <div className="preset-pair-head">
        <div className="preset-pair-head-text">
          <span className="preset-pair-kicker" id={labelId}>
            Companion
          </span>
          <span className="badge preset-bridge-badge" data-bridge={mode}>
            {meta.badge}
          </span>
        </div>
        <button
          type="button"
          className="btn btn-compact preset-pair-both-btn"
          title={meta.hint}
          onClick={(e) => {
            e.stopPropagation();
            onAddBoth(bundle.pairId);
          }}
        >
          Add both ⇄
        </button>
      </div>
      <div className="preset-pair-body">
        <PresetCard preset={bundle.forward} onLoad={onLoad} onAppend={onAppend} />
        <span className="preset-pair-link" aria-hidden="true" title="Companion pipelines">
          ⇄
        </span>
        <PresetCard preset={bundle.reverse} onLoad={onLoad} onAppend={onAppend} />
      </div>
      <p className="preset-pair-hint muted">{meta.hint}</p>
    </div>
  );
}

/** Templates gallery — category rail, search, companion pairs (legacy CSS). */
export function PresetMenu({
  presets,
  groups: groupsProp,
  label = (
    <>
      Templates <span aria-hidden="true">▾</span>
    </>
  ),
  onLoad,
  onAppend,
  onAddBoth,
  align = "start",
  className,
  triggerClassName,
  open: openProp,
  onOpenChange,
}: Props) {
  const [uncontrolledOpen, setUncontrolledOpen] = useState(false);
  const open = openProp ?? uncontrolledOpen;
  const setOpen = (next: boolean) => {
    onOpenChange?.(next);
    if (openProp === undefined) setUncontrolledOpen(next);
  };

  const groups = useMemo(
    () => groupsProp || listPresetGroups(presets),
    [groupsProp, presets]
  );
  const [filter, setFilter] = useState("");
  const [activeGroup, setActiveGroup] = useState(groups[0] || "");
  const byGroup = useMemo(
    () => groupPresets(presets, groups, filter),
    [presets, groups, filter]
  );
  const searching = !!filter.trim();

  const runAndClose = (fn: () => void) => {
    fn();
    setOpen(false);
    setFilter("");
  };

  const renderPacked = (list: PresetMenuItem[]) => {
    const packed = packItems(list);
    if (!packed.length) {
      return (
        <p className="muted fs-sm preset-menu-empty">No templates in this category.</p>
      );
    }
    return packed.map((entry) =>
      entry.kind === "pair" ? (
        <CompanionPair
          key={entry.bundle.pairId}
          bundle={entry.bundle}
          onLoad={(id) => runAndClose(() => onLoad(id))}
          onAppend={(id) => runAndClose(() => onAppend(id))}
          onAddBoth={(pairId) => runAndClose(() => onAddBoth(pairId))}
        />
      ) : (
        <PresetCard
          key={entry.preset.id}
          preset={entry.preset}
          onLoad={(id) => runAndClose(() => onLoad(id))}
          onAppend={(id) => runAndClose(() => onAppend(id))}
        />
      )
    );
  };

  let panel: ReactNode;
  if (searching) {
    const blocks: ReactNode[] = [];
    for (const g of groups) {
      const list = byGroup.get(g) || [];
      if (!list.length) continue;
      blocks.push(
        <div key={g}>
          <p className="preset-group-title">{g}</p>
          <div className="preset-menu-items">{renderPacked(list)}</div>
        </div>
      );
    }
    panel = blocks.length ? (
      blocks
    ) : (
      <p className="muted fs-sm preset-menu-empty">
        No templates match “{filter.trim()}”.
      </p>
    );
  } else {
    const active = groups.includes(activeGroup) ? activeGroup : groups[0];
    panel = (
      <div className="preset-menu-items">{renderPacked(byGroup.get(active) || [])}</div>
    );
  }

  return (
    <DropdownMenu
      open={open}
      onOpenChange={(next) => {
        setOpen(next);
        if (!next) setFilter("");
      }}
    >
      <DropdownMenuTrigger asChild>
        <Button
          type="button"
          variant="ghost"
          size="sm"
          className={cn("toolbar-menu-trigger toolkit-presets-summary", triggerClassName)}
        >
          {label}
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent
        align={align}
        className={cn(
          "preset-menu-popover p-3",
          "w-[min(640px,calc(100vw-1.5rem))] max-w-[min(640px,calc(100vw-1.5rem))]",
          className
        )}
        onCloseAutoFocus={(e) => e.preventDefault()}
      >
        <p className="muted m-0-b-md fs-sm">
          Pick a category, then a notebook. Companion rows (⇄) can add forward and inverse
          together.
        </p>
        <div className="preset-menu">
          <div className="preset-menu-toolbar">
            <input
              type="search"
              className="preset-menu-search"
              placeholder="Search templates…"
              value={filter}
              autoComplete="off"
              spellCheck={false}
              aria-label="Search templates"
              onChange={(e) => setFilter(e.target.value)}
              onKeyDown={(e) => e.stopPropagation()}
              onClick={(e) => e.stopPropagation()}
            />
          </div>
          <div className="preset-menu-body">
            <nav className="preset-cats" aria-label="Template categories">
              {groups.map((g) => {
                const n = (byGroup.get(g) || []).length;
                const active = !searching && g === (groups.includes(activeGroup) ? activeGroup : groups[0]);
                const dim = searching && n === 0;
                return (
                  <button
                    key={g}
                    type="button"
                    className={cn(
                      "preset-cat-btn",
                      active && "is-active",
                      dim && "is-dim"
                    )}
                    disabled={searching}
                    onClick={() => {
                      setActiveGroup(g);
                      setFilter("");
                    }}
                  >
                    <span>{g}</span>
                    <span className="preset-cat-count">{n}</span>
                  </button>
                );
              })}
            </nav>
            <div className="preset-menu-panel">{panel}</div>
          </div>
        </div>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
