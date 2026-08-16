import { useMemo, useState, type ReactNode } from "react";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { useRefusal } from "@/components/ui/refusal";
import { cn } from "@/lib/cn";
import {
  bridgeModeMeta,
  stitchPresetPair,
} from "../../lib/toolkit/conjugate-stitch.js";
import { listPresetGroups } from "../../lib/toolkit/recipe.js";

/** Where a room entry hands off to — the panel that knows the roster. */
export type RoomHandoff = "ceremony" | "recovery";

export type PresetMenuItem = {
  id: string;
  group?: string;
  title: string;
  blurb?: string;
  recipe?: string;
  pair?: string;
  /**
   * What this template needs before it can run — `recipe.js`'s `Company`,
   * derived from its own steps and checked by `preset-company.test.js`.
   *
   * Read here so the gallery can say it **before** the card is pressed. The
   * failure this removes is the one this menu had for seventy templates: a
   * notebook that loads, looks fine, and then refuses at the run because there
   * is no exchange behind it — a state named after the choice instead of
   * before it.
   */
  company?: "solo" | "room";
  /**
   * Set on the entries that carry no recipe, naming the picker they open.
   *
   * The presence of this field is the whole difference in how a card behaves:
   * with it there is nothing to load, append or preview, because the notebook
   * does not exist until a roster does.
   */
  opens?: RoomHandoff;
};

type Props = {
  // Readonly because nothing here mutates it and the gallery arrives frozen —
  // `GALLERY_ENTRIES` is `Object.freeze`d so a widget cannot reorder the menu
  // for everybody else by sorting in place.
  presets: readonly PresetMenuItem[];
  /** Optional override; defaults to listPresetGroups(presets). */
  groups?: string[];
  label?: ReactNode;
  onLoad: (id: string) => void;
  onAppend: (id: string) => void;
  onAddBoth: (pairId: string) => void;
  /** Open the picker a room entry names. Required once any entry has `opens`. */
  onOpenRoom?: (opens: RoomHandoff, id: string) => void;
  /**
   * Why a handoff cannot be performed right now, per target — one sentence, or
   * absent when it can.
   *
   * The deal picker lives inside the session sheet's *idle* half, so while an
   * exchange is live it is not on screen at all. A card that opened a sheet
   * without the panel it promised would be this menu's own version of the
   * defect it is fixing, so the reason is stated on the card and the press
   * declines.
   */
  roomRefusal?: Partial<Record<RoomHandoff, string>>;
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
  presets: readonly PresetMenuItem[],
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

function packItems(presets: readonly PresetMenuItem[]): Array<
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

/**
 * The one fact about a template that has to be readable before it is chosen.
 *
 * Only drawn when there is something to say: `solo` is the state of almost
 * every card here, and a badge on all seventy would say nothing about any of
 * them.
 */
function CompanyBadge({ preset }: { preset: PresetMenuItem }) {
  if (preset.opens) {
    return (
      <span className="badge preset-company-badge" data-company="written">
        Written for your room
      </span>
    );
  }
  if (preset.company !== "room") return null;
  return (
    <span className="badge preset-company-badge" data-company="room">
      Needs a live room
    </span>
  );
}

/**
 * A room entry — the notebook is generated, so the card offers the picker.
 *
 * No Append and no "Show recipe", because both would be lying about something
 * that does not exist yet: there is no text until an audience has been chosen,
 * which is the reason this card exists in the shape it does rather than as a
 * seventy-first template.
 */
function RoomCard({
  preset,
  onOpenRoom,
  refusal,
}: {
  preset: PresetMenuItem;
  onOpenRoom: (opens: RoomHandoff, id: string) => void;
  refusal?: string;
}) {
  const declined = useRefusal(refusal);
  return (
    <div className="preset-card-wrap">
      <button
        type="button"
        className="preset-card"
        data-room-template={preset.id}
        {...declined.aria}
        onClick={declined.guard(() =>
          onOpenRoom(preset.opens as RoomHandoff, preset.id)
        )}
      >
        <strong>{preset.title}</strong>
        <CompanyBadge preset={preset} />
        <span className="muted">{preset.blurb}</span>
        {/* The press, named on the control rather than left to the arrow: this
            one opens a panel instead of replacing the notebook, and that is a
            different promise from every other card in the menu. */}
        <span className="muted fs-xs preset-company-act">
          Opens the room list — nothing you have open is replaced.
        </span>
      </button>
      {declined.note}
    </div>
  );
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
        <CompanyBadge preset={preset} />
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
  onOpenRoom,
  roomRefusal,
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
  /**
   * One sentence for the whole category rail, because it is one state.
   *
   * Search spans every category, so a category is not a filter you can also
   * apply — picking one would have to throw the search away. The rail dims and
   * declines; what it never did was say that the search box above it is the
   * thing holding it, which is the one fact that turns a dead sidebar into a
   * box you can clear.
   */
  const searchOwnsTheRail = searching
    ? "Search looks through every category at once, so there is no category left to pick. Clear the search box above to browse by category again."
    : undefined;
  const catRefusal = useRefusal(searchOwnsTheRail);

  const runAndClose = (fn: () => void) => {
    fn();
    setOpen(false);
    setFilter("");
  };

  const renderPacked = (list: readonly PresetMenuItem[]) => {
    const packed = packItems(list);
    if (!packed.length) {
      return (
        <p className="muted fs-sm preset-menu-empty">No templates in this category.</p>
      );
    }
    return packed.map((entry) => {
      if (entry.kind === "pair") {
        return (
          <CompanionPair
            key={entry.bundle.pairId}
            bundle={entry.bundle}
            onLoad={(id) => runAndClose(() => onLoad(id))}
            onAppend={(id) => runAndClose(() => onAppend(id))}
            onAddBoth={(pairId) => runAndClose(() => onAddBoth(pairId))}
          />
        );
      }
      // A room entry with nobody wired to receive the handoff would be a card
      // that swallows its own press. Falling through to `PresetCard` would be
      // worse — it would offer Load and Append for a recipe that is
      // `undefined` — so the entry is simply not drawn, which is the honest
      // rendering of "this build has no picker".
      if (entry.preset.opens) {
        if (!onOpenRoom) return null;
        return (
          <RoomCard
            key={entry.preset.id}
            preset={entry.preset}
            refusal={roomRefusal?.[entry.preset.opens]}
            onOpenRoom={(opens, id) => runAndClose(() => onOpenRoom(opens, id))}
          />
        );
      }
      return (
        <PresetCard
          key={entry.preset.id}
          preset={entry.preset}
          onLoad={(id) => runAndClose(() => onLoad(id))}
          onAppend={(id) => runAndClose(() => onAppend(id))}
        />
      );
    });
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
                    {...catRefusal.aria}
                    onClick={catRefusal.guard(() => {
                      setActiveGroup(g);
                      setFilter("");
                    })}
                  >
                    <span>{g}</span>
                    <span className="preset-cat-count">{n}</span>
                  </button>
                );
              })}
              {/* Once, under the rail — not once per category button, which
                  would repeat one sentence eight times down a sidebar. */}
              {catRefusal.note}
            </nav>
            <div className="preset-menu-panel">{panel}</div>
          </div>
        </div>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
