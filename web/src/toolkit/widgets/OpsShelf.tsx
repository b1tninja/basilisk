import { useMemo, useState, type ReactNode } from "react";
import {
  TOOLBOX_META,
  getShelfMeta,
  listDrawerRows,
  listOpCollections,
  KEY_FORMAT_PICKS,
  KEY_FORMAT_META,
  formatDirectionForTip,
  instantiateFormatPick,
  instantiateCipherPick,
  type StepSpec,
} from "../../lib/toolkit/registry.js";
import { CIPHER_DISPATCH_TARGETS } from "../../lib/toolkit/step-names.js";
import { cn } from "@/lib/cn";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Input } from "@/components/ui/input";
import { Glyph, glyphIdFor } from "./Glyph";
import { OpsTile } from "./OpsTile";
import type { ToolCardOp } from "./ToolCard";

export type OpsShelfOp = ToolCardOp;

export type OpsShelfTip = {
  base?: string;
  kind?: string;
  encoding?: string;
} | null;

export type OpsAppendOpts = {
  decode?: boolean;
  params?: Record<string, unknown>;
};

type Props = {
  ops: OpsShelfOp[];
  filter: string;
  onFilter: (q: string) => void;
  onAppend: (name: string, opts?: OpsAppendOpts) => void;
  /** Tip-fit step names (others dim when set). */
  tipFit?: Set<string> | null;
  /** Current pipeline tip (Formats kit direction). */
  tip?: OpsShelfTip;
  className?: string;
  /** Hide outer aside chrome (for embedding in legacy drawer host). */
  bare?: boolean;
  /** Use an external search field (legacy #ops-filter). */
  hideSearch?: boolean;
};

function asStep(op: OpsShelfOp): StepSpec {
  return op as unknown as StepSpec;
}

function kitMatches(q: string, needles: string[]): boolean {
  if (!q) return true;
  return needles.some((n) => n.includes(q) || q.includes(n));
}

/** Searchable toolbox → shelf → tile grid (+ collection / Formats / HMAC kits). */
export function OpsShelf({
  ops,
  filter,
  onFilter,
  onAppend,
  tipFit = null,
  tip = null,
  className,
  bare = false,
  hideSearch = false,
}: Props) {
  const [collectionOpen, setCollectionOpen] = useState<Record<string, boolean>>({
    aes: true,
    rsa: true,
    encoding: true,
  });
  const [formatOpen, setFormatOpen] = useState<"export" | "import" | null>(null);

  const grouped = useMemo(() => {
    const q = filter.trim().toLowerCase();
    const filtered = q
      ? ops.filter(
          (op) =>
            op.name.toLowerCase().includes(q) ||
            (op.doc || "").toLowerCase().includes(q) ||
            (op.label || "").toLowerCase().includes(q)
        )
      : ops;

    const byTb = new Map<string, OpsShelfOp[]>();
    for (const op of filtered) {
      if (op.kitOnly) continue;
      const tb = op.toolbox || "io";
      if (!byTb.has(tb)) byTb.set(tb, []);
      byTb.get(tb)!.push(op);
    }
    // Collection kits are kitOnly — still show their toolbox when the filter matches.
    for (const col of listOpCollections()) {
      if (!kitMatches(q, col.search || [col.id, col.label.toLowerCase()])) continue;
      if (!byTb.has(col.toolbox)) byTb.set(col.toolbox, []);
    }

    return [...byTb.entries()]
      .sort(
        (a, b) =>
          ((TOOLBOX_META as Record<string, { order?: number }>)[a[0]]?.order ?? 9) -
          ((TOOLBOX_META as Record<string, { order?: number }>)[b[0]]?.order ?? 9)
      )
      .map(([tb, items]) => {
        const byShelf = new Map<string, OpsShelfOp[]>();
        for (const op of items) {
          const shelf = op.shelf || "_";
          if (!byShelf.has(shelf)) byShelf.set(shelf, []);
          byShelf.get(shelf)!.push(op);
        }
        const shelves = [...byShelf.entries()].sort(
          (a, b) => getShelfMeta(a[0]).order - getShelfMeta(b[0]).order
        );
        return {
          tb,
          shelves: shelves.map(([shelf, shelfItems]) => ({
            shelf,
            rows: listDrawerRows(shelfItems.map(asStep)),
          })),
        };
      });
  }, [ops, filter]);

  const q = filter.trim().toLowerCase();
  const showMacKit = kitMatches(q, ["hmac", "mac", "sign", "verify"]);
  const showFormatKit = kitMatches(q, [
    "format",
    "export",
    "import",
    "pkcs",
    "spki",
    "jwk",
    "scalar",
  ]);
  const visibleCollections = listOpCollections().filter((col) =>
    kitMatches(q, col.search || [col.id, col.label.toLowerCase()])
  );

  const impliedFormat = formatDirectionForTip(tip || undefined);
  const formatDirection = formatOpen || impliedFormat;

  const body = (
    <>
      {!hideSearch ? (
        <div className={cn("border-b border-[var(--border)] px-2.5 py-2", bare && "px-0")}>
          {!bare ? (
            <p className="text-[0.65rem] font-bold uppercase tracking-wider text-[var(--muted-foreground)]">
              Toolkit
            </p>
          ) : null}
          <Input
            className={cn("h-7 text-xs", !bare && "mt-1.5")}
            placeholder="Search…"
            value={filter}
            onChange={(e) => onFilter(e.target.value)}
            aria-label="Search toolkit"
          />
          {!bare ? (
            <p className="mt-1.5 text-[0.62rem] leading-snug text-[var(--muted-foreground)]">
              Hover for the tool card — drag onto a cell or click. Pairs tint encode / decode.
            </p>
          ) : null}
        </div>
      ) : null}
      <ScrollArea className={cn("flex-1 px-2 py-2", bare && "px-0")}>
        <div className="flex flex-col gap-3 pb-4">
          {grouped.map(({ tb, shelves }) => {
            const meta = (TOOLBOX_META as Record<string, { label?: string; glyph?: string }>)[
              tb
            ] || { label: tb };
            return (
              <div key={tb} className="ops-category" data-toolbox={tb}>
                <div className="mb-1.5 flex items-center gap-1 px-0.5 text-[0.62rem] font-bold uppercase tracking-wide text-[var(--muted-foreground)]">
                  <Glyph
                    id={meta.glyph || glyphIdFor({ name: tb, toolbox: tb })}
                    size={16}
                    className="opacity-70"
                  />
                  <span className="truncate">{meta.label || tb}</span>
                </div>
                <div className="ops-icon-grid flex flex-col gap-0.5">
                  {(() => {
                    const nodes: ReactNode[] = [];
                    const placed = new Set<string>();

                    const appendCollectionMember = (name: string, decode: boolean) => {
                      if (CIPHER_DISPATCH_TARGETS.has(name)) {
                        try {
                          const pick = instantiateCipherPick(name, decode);
                          onAppend(pick.name, {
                            decode: !!pick.params.decode,
                            params: pick.params,
                          });
                        } catch {
                          /* ignore */
                        }
                        return;
                      }
                      onAppend(name, { decode });
                    };

                    const collectionNodes = visibleCollections
                      .filter((col) => col.toolbox === tb)
                      .map((col) => ({
                        col,
                        order: getShelfMeta(col.shelf).order,
                        node: (
                          <ModeShelfKit
                            key={`${col.id}-kit`}
                            dataShelf={col.id}
                            title={col.label}
                            glyph={col.glyph}
                            modes={col.members}
                            actionLabels={col.actionLabels}
                            tipFit={tipFit}
                            expanded={collectionOpen[col.id] !== false}
                            onToggleExpand={() => {
                              setFormatOpen(null);
                              setCollectionOpen((prev) => ({
                                ...prev,
                                [col.id]: !(prev[col.id] !== false),
                              }));
                            }}
                            onPick={appendCollectionMember}
                          />
                        ),
                      }));

                    for (const { shelf, rows } of shelves) {
                      const shelfOrder = getShelfMeta(shelf).order;
                      for (const { col, order, node } of collectionNodes) {
                        if (!placed.has(col.id) && shelfOrder >= order) {
                          nodes.push(node);
                          placed.add(col.id);
                        }
                      }
                      const showFormat =
                        tb === "webcrypto" && shelf === "keys" && showFormatKit;
                      if (!rows.length && !showFormat) continue;
                      nodes.push(
                        <div
                          key={`${tb}:${shelf}`}
                          className="ops-shelf flex flex-col gap-0.5"
                          data-shelf={shelf}
                        >
                          {showFormat ? (
                            <FormatKit
                              tip={tip}
                              direction={formatDirection}
                              open={formatOpen}
                              onToggle={(dir) => {
                                setCollectionOpen((prev) => {
                                  const next = { ...prev };
                                  for (const k of Object.keys(next)) next[k] = false;
                                  return next;
                                });
                                setFormatOpen((prev) => (prev === dir ? null : dir));
                              }}
                              onPick={(fmt) => {
                                const dir = formatOpen || impliedFormat || "export";
                                try {
                                  const pick = instantiateFormatPick(dir, fmt);
                                  setFormatOpen(null);
                                  onAppend(pick.name, { params: pick.params });
                                } catch {
                                  /* ignore */
                                }
                              }}
                            />
                          ) : null}
                          {rows.map((row, i) => {
                            if (row.type === "solo" && row.step) {
                              const fit = !tipFit || tipFit.has(row.step.name);
                              return (
                                <div
                                  key={`${row.step.name}-${i}`}
                                  className="ops-pair ops-pair-solo"
                                >
                                  <OpsTile
                                    op={row.step}
                                    pairRole="solo"
                                    fit={fit}
                                    dim={!!tipFit && !fit}
                                    onAppend={onAppend}
                                  />
                                </div>
                              );
                            }
                            if (row.type !== "pair" || !row.forward) return null;
                            const key = row.forward.name + (row.reverse?.name || "-d");
                            const fitFwd = !tipFit || tipFit.has(row.forward.name);
                            const revName = row.reverse?.name || row.forward.name;
                            const fitRev = !tipFit || tipFit.has(revName);
                            return (
                              <div key={key} className="ops-pair">
                                {row.caption ? (
                                  <div className="ops-pair-caption muted fs-xs col-span-2 px-0.5 text-[0.52rem] font-bold uppercase tracking-wide text-[var(--muted-foreground)]">
                                    {row.caption}
                                  </div>
                                ) : null}
                                <OpsTile
                                  op={row.forward}
                                  pairRole="forward"
                                  fit={fitFwd}
                                  dim={!!tipFit && !fitFwd}
                                  onAppend={onAppend}
                                />
                                {row.decodeTwin ? (
                                  <OpsTile
                                    op={row.forward}
                                    decode
                                    pairRole="reverse"
                                    fit={fitFwd}
                                    dim={!!tipFit && !fitFwd}
                                    onAppend={onAppend}
                                  />
                                ) : row.reverse ? (
                                  <OpsTile
                                    op={row.reverse}
                                    pairRole="reverse"
                                    fit={fitRev}
                                    dim={!!tipFit && !fitRev}
                                    onAppend={onAppend}
                                  />
                                ) : null}
                              </div>
                            );
                          })}
                        </div>
                      );
                    }
                    for (const { col, node } of collectionNodes) {
                      if (!placed.has(col.id)) nodes.push(node);
                    }
                    if (tb === "webcrypto" && showMacKit) {
                      nodes.push(<MacKit key="mac-kit" onAppend={onAppend} />);
                    }
                    return nodes;
                  })()}
                </div>
              </div>
            );
          })}
        </div>
      </ScrollArea>
    </>
  );

  if (bare) {
    return <div className={cn("flex min-h-0 flex-1 flex-col", className)}>{body}</div>;
  }

  return (
    <aside
      className={cn(
        "flex w-[220px] shrink-0 flex-col border-r border-[var(--border)] bg-[color-mix(in_srgb,var(--surface-raised)_88%,var(--surface))]",
        className
      )}
    >
      {body}
    </aside>
  );
}

function KitMetaTile({
  glyph,
  shortName,
  title,
  open,
  onClick,
}: {
  glyph: string;
  shortName: string;
  title: string;
  open?: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      className={cn(
        "ops-item ops-item-icon ops-kit-meta",
        open && "ops-cipher-meta-open ops-item-fit"
      )}
      aria-label={title}
      title={title}
      aria-expanded={open ? "true" : "false"}
      onClick={onClick}
    >
      <Glyph id={glyph} size={16} svgClassName="ops-glyph ops-glyph-tile" />
      <span className="ops-item-name">{shortName}</span>
    </button>
  );
}

function ModeShelfKit({
  dataShelf,
  title,
  glyph,
  modes,
  actionLabels,
  tipFit,
  expanded,
  onToggleExpand,
  onPick,
}: {
  dataShelf: string;
  title: string;
  glyph: string;
  modes: { id: string; name: string; label: string; title?: string }[];
  actionLabels: { forward: string; reverse: string };
  tipFit?: Set<string> | null;
  expanded: boolean;
  onToggleExpand: () => void;
  onPick: (name: string, decode: boolean) => void;
}) {
  const dataAttr =
    dataShelf === "aes"
      ? { "data-aes-kit": "" }
      : dataShelf === "rsa"
        ? { "data-rsa-kit": "" }
        : dataShelf === "encoding"
          ? { "data-encoding-kit": "" }
          : { [`data-${dataShelf}-kit`]: "" };

  return (
    <div className="ops-cipher-kit ops-aes-kit" {...dataAttr} data-shelf={dataShelf}>
      <button
        type="button"
        className={cn("ops-aes-kit-head", expanded && "is-open")}
        aria-expanded={expanded}
        onClick={onToggleExpand}
      >
        <Glyph id={glyph} size={16} svgClassName="ops-glyph ops-glyph-tile" />
        <span className="ops-aes-kit-title">{title}</span>
        <span className="ops-aes-kit-chevron" aria-hidden>
          {expanded ? "▾" : "▸"}
        </span>
      </button>
      {expanded ? (
        <div className="ops-aes-kit-body">
          {modes.map((m) => {
            const fit = !tipFit || tipFit.has(m.name);
            return (
              <div key={m.id} className="ops-aes-mode-shelf" data-mode={m.id}>
                <div className="ops-pair-caption muted fs-xs px-0.5 text-[0.52rem] font-bold uppercase tracking-wide text-[var(--muted-foreground)]">
                  {m.label}
                </div>
                <div
                  className="ops-aes-actions ops-icon-grid"
                  role="group"
                  aria-label={`${title}-${m.label} ${actionLabels.forward.toLowerCase()} or ${actionLabels.reverse.toLowerCase()}`}
                >
                  <button
                    type="button"
                    className={cn(
                      "ops-item ops-item-icon ops-aes-action",
                      fit ? "ops-item-fit" : "ops-item-dim"
                    )}
                    data-dir="encode"
                    title={m.title || m.name}
                    aria-label={`${m.name} ${actionLabels.forward.toLowerCase()}`}
                    onClick={() => onPick(m.name, false)}
                  >
                    <Glyph id={glyph} size={16} svgClassName="ops-glyph ops-glyph-tile" />
                    <span className="ops-item-name">{actionLabels.forward}</span>
                  </button>
                  <button
                    type="button"
                    className={cn(
                      "ops-item ops-item-icon ops-aes-action",
                      fit ? "ops-item-fit" : "ops-item-dim"
                    )}
                    data-dir="decode"
                    title={`${m.name} — ${actionLabels.reverse.toLowerCase()}`}
                    aria-label={`${m.name} ${actionLabels.reverse.toLowerCase()}`}
                    onClick={() => onPick(m.name, true)}
                  >
                    <Glyph id={glyph} size={16} svgClassName="ops-glyph ops-glyph-tile" />
                    <span className="ops-item-name">{actionLabels.reverse}</span>
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      ) : null}
    </div>
  );
}

function FormatKit({
  tip,
  direction,
  open,
  onToggle,
  onPick,
}: {
  tip: OpsShelfTip;
  direction: "export" | "import" | null;
  open: "export" | "import" | null;
  onToggle: (dir: "export" | "import") => void;
  onPick: (fmt: string) => void;
}) {
  const showPicks = !!direction;
  return (
    <div className="ops-cipher-kit" data-format-kit>
      <p className="ops-pair-caption muted fs-xs">Key formats</p>
      <div className="ops-icon-grid">
        <KitMetaTile
          glyph="ports"
          shortName="Export"
          title="Export — choose PKCS#8, SPKI, JWK, raw, or scalar"
          open={open === "export" || (direction === "export" && showPicks && open !== "import")}
          onClick={() => onToggle("export")}
        />
        <KitMetaTile
          glyph="ports"
          shortName="Import"
          title="Import — choose PKCS#8, SPKI, JWK, raw, or scalar"
          open={open === "import" || (direction === "import" && showPicks && open !== "export")}
          onClick={() => onToggle("import")}
        />
      </div>
      {showPicks ? (
        <div className="ops-cipher-picker" role="listbox" aria-label="Choose key format">
          <p className="muted fs-xs mb-xs">
            <code>{direction}</code> — pick a format tool
          </p>
          <div className="ops-icon-grid ops-kit-pick-grid">
            {KEY_FORMAT_PICKS.map((fmt) => {
              const meta = KEY_FORMAT_META[fmt] || { label: fmt, title: fmt };
              const fit =
                direction === "export"
                  ? tip?.base === "keypair" || tip?.base === "key"
                  : tip?.base === "bytes" ||
                    tip?.base === "text" ||
                    tip?.base === "none" ||
                    !tip;
              const short =
                meta.label.length > 9 ? `${meta.label.slice(0, 8)}…` : meta.label;
              return (
                <button
                  key={fmt}
                  type="button"
                  className={cn(
                    "ops-item ops-item-icon ops-cipher-pick",
                    fit ? "ops-item-fit" : "ops-item-dim"
                  )}
                  role="option"
                  aria-label={`${direction} ${meta.label}`}
                  title={`${direction}: ${meta.title}`}
                  onClick={() => onPick(fmt)}
                >
                  <Glyph id="ports" size={16} svgClassName="ops-glyph ops-glyph-tile" />
                  <span className="ops-item-name">{short}</span>
                </button>
              );
            })}
          </div>
        </div>
      ) : (
        <p className="muted fs-xs mb-xs">
          Choose Export or Import, then a format (PKCS#8, SPKI, …).
        </p>
      )}
    </div>
  );
}

function MacKit({ onAppend }: { onAppend: Props["onAppend"] }) {
  return (
    <div className="ops-cipher-kit" data-mac-kit>
      <p className="ops-pair-caption muted fs-xs">HMAC</p>
      <div className="ops-icon-grid">
        <KitMetaTile
          glyph="sign"
          shortName="hmac"
          title="Insert sign (HMAC keys via genkey hmac/sha256)"
          onClick={() => onAppend("sign")}
        />
        <KitMetaTile
          glyph="sign"
          shortName="verify"
          title="Insert verify (recipe sugar: hmac.verify)"
          onClick={() => onAppend("verify")}
        />
      </div>
    </div>
  );
}
