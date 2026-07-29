import { useState, type ReactNode } from "react";
import { cn } from "@/lib/cn";
import { Glyph, glyphIdFor } from "./Glyph";
import { SuggestChip } from "./SuggestChip";
import type { ToolCardOp } from "./ToolCard";
import { STEP_MIME, stepDragPayload } from "./mime";

export type SuggestRailItem = {
  op: ToolCardOp;
  decode?: boolean;
  label?: string;
  /** Tip-type fit (highlight). */
  fit?: boolean;
  /** Soft mute when tip does not accept this op. */
  dim?: boolean;
  /** Hard-disable click/drag when not usable at tip. */
  disabled?: boolean;
  title?: string;
};

/** Toolbox square for cell / nest suggest drawers. */
export type SuggestRailToolbox = {
  id: string;
  label: string;
  badge?: string;
  glyph?: string;
  count?: number;
  fit?: boolean;
  muted?: boolean;
  enabled?: boolean;
  title?: string;
};

/** Quick-pick chip inside a toolbox pull-out. */
export type SuggestRailChip = {
  op: ToolCardOp;
  decode?: boolean;
  label?: string;
  hint?: string;
  primary?: boolean;
  blocked?: boolean;
};

export type SuggestComposeChip = {
  id: string;
  label: string;
  primary?: boolean;
  /** Visual tone — warn/error for unmet runtime needs (e.g. missing key). */
  tone?: "default" | "warn" | "error";
  title?: string;
};

type Props = {
  items?: SuggestRailItem[];
  onAppend: (name: string, opts?: { decode?: boolean }) => void;
  /** Soft + that expands toolbox (nest inline). */
  expandable?: boolean;
  expanded?: boolean;
  onToggleExpand?: () => void;
  expandLabel?: string;
  className?: string;
  /** Extra pull-out content when expanded (nest mode) */
  pullout?: ReactNode;
  /** Toolbox squares mode (cell `#suggest-next` / nest body). */
  toolboxes?: SuggestRailToolbox[];
  activeToolbox?: string | null;
  onToolboxClick?: (id: string) => void;
  pulloutChips?: SuggestRailChip[];
  onOpenOps?: (tb: string) => void;
  onClosePullout?: () => void;
  composeChips?: SuggestComposeChip[];
  onCompose?: (id: string) => void;
  scope?: "cell" | "nest";
};

/** “+ / toolbox squares” rail for cell suggest-next and nest add. */
export function SuggestRail({
  items = [],
  onAppend,
  expandable = false,
  expanded = false,
  onToggleExpand,
  expandLabel = "Add step",
  className,
  pullout,
  toolboxes,
  activeToolbox = null,
  onToolboxClick,
  pulloutChips,
  onOpenOps,
  onClosePullout,
  composeChips,
  onCompose,
  scope = "cell",
}: Props) {
  const [open, setOpen] = useState(expanded);
  const isOpen = onToggleExpand ? expanded : open;
  const toggle = () => {
    if (onToggleExpand) onToggleExpand();
    else setOpen((v) => !v);
  };

  const toolboxMode = Array.isArray(toolboxes) && toolboxes.length > 0;

  const railBody = toolboxMode ? (
    <ToolboxRail
      toolboxes={toolboxes!}
      activeToolbox={activeToolbox}
      onToolboxClick={onToolboxClick}
      pulloutChips={pulloutChips}
      onAppend={onAppend}
      onOpenOps={onOpenOps}
      onClosePullout={onClosePullout}
      scope={scope}
    />
  ) : (
    <div className="suggest-toolbox-rail" role="list">
      <span className="suggest-next-plus" aria-hidden>
        +
      </span>
      <div className="ops-icon-grid ops-drill-grid suggest-toolbox-tiles">
        {items.map(({ op, decode, label, fit, dim, disabled, title }) => (
          <RailTile
            key={`${op.name}:${decode ? 1 : 0}`}
            op={op}
            decode={decode}
            label={label}
            fit={fit}
            dim={dim}
            disabled={disabled}
            title={title}
            onAppend={onAppend}
          />
        ))}
      </div>
    </div>
  );

  if (expandable) {
    return (
      <div
        className={cn(
          "suggest-next suggest-next-nest suggest-next-nest-inline",
          !isOpen && "suggest-next-nest-collapsed",
          className
        )}
      >
        <button
          type="button"
          className={cn("suggest-nest-add", isOpen && "is-open")}
          aria-expanded={isOpen}
          aria-label={expandLabel}
          title={expandLabel}
          onClick={toggle}
        >
          <span className="suggest-next-plus" aria-hidden>
            {isOpen ? "−" : "+"}
          </span>
        </button>
        {isOpen ? (
          <div className="suggest-nest-popout" role="region" aria-label={expandLabel}>
            {pullout || railBody}
          </div>
        ) : null}
      </div>
    );
  }

  return (
    <div
      className={cn("suggest-toolbox-wrap", className)}
      role="group"
      aria-label="Suggested next steps"
      data-suggest-scope={scope}
    >
      {railBody}
      {!toolboxMode && pullout}
      {composeChips?.length ? (
        <>
          {composeChips.some((c) => c.tone === "warn" || c.tone === "error") ? (
            <div
              className="suggest-next-chips suggest-compose-chips suggest-need-chips mb-sm"
              role="list"
              aria-label="Unmet needs"
            >
              <span className="suggest-compose-label muted fs-xs">Need</span>
              {composeChips
                .filter((c) => c.tone === "warn" || c.tone === "error")
                .map((c) => (
                  <SuggestChip
                    key={c.id}
                    label={c.label}
                    variant="candidate"
                    error={c.tone === "error"}
                    className={cn(
                      "suggest-chip-compose",
                      c.tone === "warn" && "suggest-chip-warn",
                      c.tone === "error" && "suggest-chip-need-error"
                    )}
                    title={
                      c.title ||
                      "Open the toolkit to pick a source that satisfies this need"
                    }
                    onClick={() => onCompose?.(c.id)}
                  />
                ))}
            </div>
          ) : null}
          {composeChips.some((c) => !c.tone || c.tone === "default") ? (
            <div className="suggest-next-chips suggest-compose-chips mb-sm" role="list">
              <span className="suggest-compose-label muted fs-xs">Compose</span>
              {composeChips
                .filter((c) => !c.tone || c.tone === "default")
                .map((c) => (
                  <SuggestChip
                    key={c.id}
                    label={c.label}
                    variant="candidate"
                    className={cn(
                      "suggest-chip-compose",
                      c.primary && "suggest-chip-primary"
                    )}
                    title={c.title}
                    onClick={() => onCompose?.(c.id)}
                  />
                ))}
            </div>
          ) : null}
        </>
      ) : null}
    </div>
  );
}

function ToolboxRail({
  toolboxes,
  activeToolbox,
  onToolboxClick,
  pulloutChips,
  onAppend,
  onOpenOps,
  onClosePullout,
  scope,
}: {
  toolboxes: SuggestRailToolbox[];
  activeToolbox: string | null;
  onToolboxClick?: (id: string) => void;
  pulloutChips?: SuggestRailChip[];
  onAppend: Props["onAppend"];
  onOpenOps?: (tb: string) => void;
  onClosePullout?: () => void;
  scope: "cell" | "nest";
}) {
  const openMeta = activeToolbox
    ? toolboxes.find((t) => t.id === activeToolbox)
    : null;

  return (
    <>
      <div className="suggest-toolbox-rail" role="list">
        <span className="suggest-next-plus" aria-hidden title="Add step">
          +
        </span>
        <span className="sr-only">Add step</span>
        <div className="ops-icon-grid ops-drill-grid suggest-toolbox-tiles">
          {toolboxes.map((tb) => {
            const fit = !!tb.fit;
            const muted = tb.muted != null ? !!tb.muted : !fit;
            const enabled = tb.enabled !== false;
            const open = activeToolbox === tb.id;
            return (
              <button
                key={tb.id}
                type="button"
                className={cn(
                  "ops-item ops-item-icon ops-drill-tile",
                  fit && "ops-item-fit",
                  muted && "ops-drill-muted",
                  !enabled && "ops-item-dim"
                )}
                disabled={!enabled}
                data-ops-muted={muted ? "1" : undefined}
                data-suggest-scope={scope}
                data-suggest-pullout={tb.id}
                aria-expanded={open}
                aria-label={`${tb.title || tb.label}${open ? " (open)" : ""}`}
                title={tb.title || tb.label}
                onClick={() => onToolboxClick?.(tb.id)}
              >
                <Glyph
                  id={tb.glyph || "gear"}
                  size={16}
                  svgClassName="ops-glyph ops-glyph-tile"
                />
                <span className="ops-item-name">{tb.badge || tb.label}</span>
                {tb.count != null ? (
                  <span className="ops-drill-count">{tb.count}</span>
                ) : null}
              </button>
            );
          })}
        </div>
      </div>
      {openMeta ? (
        <div
          className="suggest-pullout"
          role="region"
          aria-label={`${openMeta.label} suggestions`}
        >
          <div className="suggest-pullout-head">
            <p className="suggest-pullout-title mb-0">{openMeta.label}</p>
            <button
              type="button"
              className="btn btn-ghost btn-compact"
              title="Open this toolbox in Toolkit"
              onClick={() => onOpenOps?.(openMeta.id)}
            >
              Toolkit ▸
            </button>
            <button
              type="button"
              className="btn btn-ghost btn-compact"
              aria-label="Close menu"
              onClick={() => onClosePullout?.()}
            >
              ✕
            </button>
          </div>
          <div className="suggest-next-chips suggest-pullout-chips" role="list">
            {pulloutChips?.length ? (
              pulloutChips.map(({ op, decode, label, hint, primary, blocked }) => {
                const nameLabel = label || op.label || op.name;
                return (
                  <SuggestChip
                    key={`${op.name}:${decode ? 1 : 0}`}
                    label={nameLabel}
                    hint={hint ? `→ ${hint}` : undefined}
                    op={op}
                    variant="candidate"
                    draggable={!blocked}
                    className={cn(
                      primary && "suggest-chip-primary",
                      blocked && "suggest-chip-fips-blocked"
                    )}
                    title={
                      blocked
                        ? `FIPS mode: blocked — ${op.toolbox || ""} unverified`
                        : op.doc
                    }
                    onClick={
                      blocked
                        ? undefined
                        : () => onAppend(op.name, { decode: !!decode })
                    }
                    onDragStart={
                      blocked
                        ? undefined
                        : (e) => {
                            e.dataTransfer.setData(
                              STEP_MIME,
                              stepDragPayload(op.name, !!decode)
                            );
                            e.dataTransfer.setData("text/plain", op.name);
                            if (decode) {
                              e.dataTransfer.setData(
                                "application/x-basilisk-decode",
                                "1"
                              );
                            }
                            e.dataTransfer.effectAllowed = "copy";
                          }
                    }
                  />
                );
              })
            ) : (
              <p className="muted fs-xs mb-0">
                No quick picks for this tip — try Toolkit ▸
              </p>
            )}
          </div>
        </div>
      ) : null}
    </>
  );
}

function RailTile({
  op,
  decode,
  label,
  fit,
  dim,
  disabled,
  title,
  onAppend,
}: {
  op: ToolCardOp;
  decode?: boolean;
  label?: string;
  fit?: boolean;
  dim?: boolean;
  disabled?: boolean;
  title?: string;
  onAppend: Props["onAppend"];
}) {
  const nameLabel = label || op.label || op.name;
  const muted = dim != null ? dim : fit === false;
  const isDisabled = !!disabled;
  return (
    <button
      type="button"
      className={cn(
        "ops-item ops-item-icon ops-drill-tile",
        fit && "ops-item-fit",
        muted && "ops-drill-muted",
        isDisabled && "ops-item-dim"
      )}
      draggable={!isDisabled}
      disabled={isDisabled}
      data-ops-muted={muted ? "1" : undefined}
      aria-label={nameLabel}
      title={title || nameLabel}
      onClick={() => {
        if (isDisabled) return;
        onAppend(op.name, { decode: !!decode });
      }}
      onDragStart={(e) => {
        if (isDisabled) {
          e.preventDefault();
          return;
        }
        e.dataTransfer.setData(STEP_MIME, stepDragPayload(op.name, !!decode));
        e.dataTransfer.setData("text/plain", nameLabel);
        if (decode) e.dataTransfer.setData("application/x-basilisk-decode", "1");
        e.dataTransfer.effectAllowed = "copy";
      }}
    >
      <Glyph id={glyphIdFor(op)} size={16} svgClassName="ops-glyph ops-glyph-tile" />
      <span className="ops-item-name">{nameLabel}</span>
    </button>
  );
}
