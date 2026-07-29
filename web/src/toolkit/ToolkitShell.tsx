import { useEffect, useMemo, useState } from "react";
import {
  KeyRound,
  Braces,
  Play,
  Link2,
  Eraser,
  Plus,
  MoreHorizontal,
  Settings2,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { cn } from "@/lib/cn";
import { useNotebook } from "./useNotebook";
import { RecipientBinderHost } from "./RecipientBinderHost";
import { OutputCarousel } from "./OutputCarousel";
import {
  OpsShelf,
  STEP_MIME,
  parseStepMime,
  ModeToggle,
  MenuPopover,
  PresetMenu,
  RecipeChipFlow,
  ParamFieldGroup,
  SuggestRail,
  ToolCard,
} from "./widgets/index";
import { getStep } from "../lib/toolkit/registry.js";
import {
  buildSuggestRailModel,
  cellPipelineTip,
  suggestRailItems,
  tipFitFor,
} from "../lib/toolkit/suggest.js";
import type { ChipPath, ChipStemView } from "./widgets/RecipeChipFlow";

type CellView = "preview" | "raw" | "cards";

export function ToolkitShell() {
  const nb = useNotebook();
  const [chipEdit, setChipEdit] = useState<ChipPath | null>(null);
  const [nestExpanded, setNestExpanded] = useState<{
    stem: number;
    branch: number | null;
  } | null>(null);
  /** Gap click sets pending insert; next shelf append / drop uses it. */
  const [pendingInsert, setPendingInsert] = useState<ChipPath | null>(null);
  const [cellViews, setCellViews] = useState<Record<number, CellView>>({});
  const [rawDrafts, setRawDrafts] = useState<Record<number, string>>({});
  const [suggestPullout, setSuggestPullout] = useState<string | null>(null);

  const focusedNeeds = nb.cellInputNeeds(nb.chains[nb.focusedCell] || { steps: [] });
  const recipSlots = nb.cellRecipientSlots(nb.chains[nb.focusedCell] || { steps: [] });
  const unmet = nb.unmetForCell(nb.focusedCell);
  const inputNeedsAttention = unmet.some((u) =>
    ["needs input", "needs ciphertext"].includes(u)
  );

  const tipModel = useMemo(() => {
    const { tip, terminal, hasForeach } = cellPipelineTip(nb.chains, nb.focusedCell);
    const { next, tipFit } = tipFitFor(tip, { terminal, hasForeach });
    const primaryCount = !(nb.chains[nb.focusedCell]?.steps || []).length
      ? 3
      : tip.base === "shares"
        ? 2
        : 3;
    const rail = buildSuggestRailModel({
      next,
      tip,
      tipFit,
      activeToolbox: suggestPullout,
      primaryCount,
    });
    return { tip, next, tipFit, rail };
  }, [nb.chains, nb.focusedCell, suggestPullout]);

  useEffect(() => {
    setSuggestPullout(null);
  }, [nb.focusedCell]);

  const cellView = (i: number): CellView => cellViews[i] || "preview";
  const setCellView = (i: number, view: CellView) => {
    setCellViews((prev) => ({ ...prev, [i]: view }));
    if (view === "raw") {
      setRawDrafts((prev) => ({
        ...prev,
        [i]: prev[i] ?? nb.cellRecipeSource(i),
      }));
    }
  };

  const nestRailFor = (stem: number, branch: number | null) => {
    // Nest tips approximate from cell tip for now; compatible verbs only.
    void stem;
    void branch;
    return suggestRailItems(tipModel.next, tipModel.next, tipModel.tipFit).slice(0, 12);
  };

  const needComposeChips = useMemo(() => {
    const unmet = nb.unmetForCell(nb.focusedCell);
    const chips: import("./widgets/SuggestRail").SuggestComposeChip[] = [];
    if (unmet.includes("needs key")) {
      chips.push({
        id: "missing-key",
        label: "missing key",
        tone: "warn",
        primary: true,
        title: "Open WebCrypto → Keys (genkey / import) in the toolkit",
      });
    }
    if (unmet.includes("needs recipients")) {
      chips.push({
        id: "missing-recipients",
        label: "missing recipients",
        tone: "warn",
        title: "Browse HKP / OpenPGP tools, or use the recipients binder",
      });
    }
    if (unmet.includes("needs input")) {
      chips.push({
        id: "missing-input",
        label: "missing input",
        tone: "warn",
        title: "Add an input source or paste message text",
      });
    }
    if (unmet.includes("needs ciphertext")) {
      chips.push({
        id: "missing-ciphertext",
        label: "missing ciphertext",
        tone: "warn",
        title: "Paste ciphertext or add a decrypt source",
      });
    }
    return chips;
  }, [nb.chains, nb.focusedCell, nb.inputText, nb.ciphertext, nb.unmetForCell]);

  return (
    <TooltipProvider delayDuration={300}>
      <div className="toolkit-shell flex min-h-0 flex-1 flex-col bg-[var(--background)] text-[var(--foreground)]">
        {/* App toolbar */}
        <div className="flex flex-wrap items-center gap-2 border-b border-[var(--border)] px-3 py-2">
          <PresetMenu
            presets={nb.presets}
            onLoad={(id) => {
              const hasContent = nb.chains.some((c) => (c.steps || []).length > 0);
              if (
                hasContent &&
                !window.confirm(
                  "Replace the notebook with this template?\n\nUse Append on the template card to add cells instead."
                )
              ) {
                return;
              }
              nb.loadPreset(id);
            }}
            onAppend={(id) => nb.appendPreset(id)}
            onAddBoth={(pairId) => {
              nb.appendPresetPair(pairId);
            }}
            triggerClassName="h-8"
          />

          <MenuPopover
            label={
              <>
                <MoreHorizontal className="opacity-80" />
                More
              </>
            }
            align="start"
            items={[
              { id: "keyring", label: "Keyring", onSelect: () => nb.setSheet("keyring") },
              { id: "vars", label: "Variables", onSelect: () => nb.setSheet("variables") },
              {
                id: "crypto",
                label: "Cryptographic parameters",
                onSelect: () => nb.setSheet("crypto"),
              },
              {
                id: "copy",
                label: "Copy recipe",
                onSelect: () => void nb.copyRecipe(),
                separatorBefore: true,
              },
              { id: "reset", label: "Reset notebook", onSelect: () => nb.resetNotebook() },
              { id: "prefs", label: "Preferences", href: "/preferences", separatorBefore: true },
              { id: "keys", label: "My Keys", href: "/my-keys" },
            ]}
          />

          <div className="ml-auto flex items-center gap-2 text-xs text-[var(--muted-foreground)]">
            <span>OpenPGP · WebCrypto · SSS</span>
          </div>
        </div>

        <div className="flex min-h-0 flex-1">
          <OpsShelf
            ops={nb.filteredOps}
            filter={nb.opsFilter}
            onFilter={nb.setOpsFilter}
            tipFit={tipModel.tipFit}
            tip={{
              base: tipModel.tip.base,
              kind: tipModel.tip.kind,
              encoding: tipModel.tip.encoding,
            }}
            onAppend={(name, opts) => {
              if (pendingInsert && pendingInsert.cell === nb.focusedCell) {
                const path = pendingInsert;
                setPendingInsert(null);
                if (path.body != null) {
                  nb.nestOp(path.stem, path.branch ?? null, name, {
                    ...opts,
                    at: path.body,
                  });
                  return;
                }
                nb.insertOpAt(path.stem, name, opts);
                return;
              }
              nb.appendOp(name, opts);
            }}
          />

          {/* Notebook */}
          <section
            className="flex min-w-0 flex-1 flex-col"
            onDragOver={(e) => {
              if ([...e.dataTransfer.types].includes(STEP_MIME) || [...e.dataTransfer.types].includes("text/plain")) {
                e.preventDefault();
                e.dataTransfer.dropEffect = "copy";
              }
            }}
            onDrop={(e) => {
              const raw =
                e.dataTransfer.getData(STEP_MIME) || e.dataTransfer.getData("text/plain");
              if (!raw) return;
              e.preventDefault();
              const parsed = parseStepMime(raw);
              if (!parsed?.name) return;
              nb.appendOp(
                parsed.name,
                parsed.decode ? { decode: true } : undefined
              );
            }}
          >
            <header className="sticky top-0 z-10 space-y-2 border-b border-[var(--border)] bg-[color-mix(in_srgb,var(--surface)_94%,transparent)] px-4 py-3 backdrop-blur">
              <div className="flex flex-wrap items-center gap-2">
                <Input
                  className="h-10 min-w-[12rem] flex-1 border-0 bg-transparent px-0 text-xl font-bold tracking-tight shadow-none focus-visible:ring-0"
                  value={nb.title}
                  onChange={(e) => nb.setTitle(e.target.value)}
                  placeholder="Untitled notebook"
                />
                <div className="flex flex-wrap gap-1" role="group" aria-label="Messaging quick starts">
                  <Button
                    size="sm"
                    variant="secondary"
                    title="Insert encrypt cell (shareable #encrypt)"
                    onClick={() => nb.insertMessaging("encrypt")}
                  >
                    Encrypt
                  </Button>
                  <Button
                    size="sm"
                    variant="secondary"
                    title="Insert decrypt cell (shareable #decrypt)"
                    onClick={() => nb.insertMessaging("decrypt")}
                  >
                    Decrypt
                  </Button>
                  <Button
                    size="sm"
                    variant="ghost"
                    title="Password-based encrypt (#symencrypt)"
                    onClick={() => nb.insertMessaging("symencrypt")}
                  >
                    Password
                  </Button>
                </div>
                <div className="flex flex-wrap items-center gap-1">
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <span>
                        <Button
                          size="sm"
                          disabled={!!nb.readinessBlocker || nb.busy || !nb.compiled.validation?.ok}
                          title={nb.readinessBlocker || "Run all cells"}
                          onClick={() => void nb.runFrom(0)}
                        >
                          <Play />
                          Run all
                        </Button>
                      </span>
                    </TooltipTrigger>
                    {nb.readinessBlocker ? (
                      <TooltipContent>{nb.readinessBlocker}</TooltipContent>
                    ) : null}
                  </Tooltip>
                  <Button size="sm" variant="ghost" onClick={() => nb.clearSensitive()}>
                    <Eraser />
                    Clear
                  </Button>
                  <Button size="sm" variant="ghost" onClick={() => void nb.copyShareLink()}>
                    <Link2 />
                    Copy link
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => nb.setSheet("variables")}>
                    <Braces />
                    {nb.slotMetas.length} slots
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => nb.setSheet("keyring")}>
                    <KeyRound />
                    Keyring
                    {nb.unlockedCount ? (
                      <Badge variant="ok" className="ml-1 normal-case tracking-normal">
                        {nb.unlockedCount} unlocked
                      </Badge>
                    ) : null}
                  </Button>
                </div>
              </div>

              {nb.usesPgp ? (
                <div className="flex flex-wrap items-center gap-3">
                  <ModeToggle
                    value={nb.pgpMode}
                    onChange={(v) =>
                      nb.setPgpMode(v as "auto" | "modern" | "compatible")
                    }
                    ariaLabel="OpenPGP mode"
                    options={[
                      { value: "auto", label: "Auto" },
                      { value: "modern", label: "Modern" },
                      { value: "compatible", label: "Compatible" },
                    ]}
                  />
                  <Button size="sm" variant="ghost" onClick={() => nb.setSheet("crypto")}>
                    <Settings2 />
                    Advanced OpenPGP…
                  </Button>
                </div>
              ) : null}

              {nb.runStatus || nb.runError ? (
                <p
                  className={cn(
                    "text-sm",
                    nb.runError ? "text-[var(--error)]" : "text-[var(--muted-foreground)]"
                  )}
                >
                  {nb.runError || nb.runStatus}
                </p>
              ) : null}
            </header>

            <ScrollArea className="flex-1">
              <div className="space-y-3 p-4">
                {nb.chains.map((chain, i) => {
                  const status = nb.cellStatuses[i] || "idle";
                  const needs = nb.unmetForCell(i);
                  const focused = i === nb.focusedCell;
                  return (
                    <article
                      key={i}
                      className={cn(
                        "rounded-xl border bg-[var(--surface)]",
                        focused
                          ? "border-[color-mix(in_srgb,var(--brand)_50%,var(--border))] shadow-[0_0_0_1px_color-mix(in_srgb,var(--brand)_28%,transparent)]"
                          : "border-[var(--border)]"
                      )}
                      onClick={() => nb.setFocusedCell(i)}
                    >
                      <header className="flex flex-wrap items-center gap-2 border-b border-[var(--border)] px-3 py-2">
                        <Button size="sm" variant="ghost" onClick={() => nb.setFocusedCell(i)}>
                          [{i}]
                        </Button>
                        <Badge
                          variant={
                            status === "ok"
                              ? "ok"
                              : status === "error"
                                ? "destructive"
                                : status === "stale"
                                  ? "warn"
                                  : "secondary"
                          }
                        >
                          {status}
                        </Badge>
                        {needs.map((n) => (
                          <Badge key={n} variant="warn">
                            {n}
                          </Badge>
                        ))}
                        <ModeToggle
                          legacy
                          value={cellView(i)}
                          ariaLabel="Recipe view"
                          className="ml-1"
                          options={[
                            { value: "preview", label: "Preview" },
                            { value: "raw", label: "Raw" },
                            {
                              value: "cards",
                              label: "Cards",
                              title: "Show tall step cards under the chip flow",
                            },
                          ]}
                          onChange={(view) => {
                            nb.setFocusedCell(i);
                            setCellView(i, view as CellView);
                            if (view !== "preview") setChipEdit(null);
                          }}
                        />
                        <div className="ml-auto flex gap-1">
                          <Button
                            size="sm"
                            disabled={!!needs.length || !chain.steps?.length || nb.busy}
                            onClick={(e) => {
                              e.stopPropagation();
                              nb.setFocusedCell(i);
                              void nb.runFrom(i);
                            }}
                          >
                            Run
                          </Button>
                          <Button
                            size="sm"
                            variant="ghost"
                            className="text-[var(--error)]"
                            disabled={nb.chains.length <= 1}
                            title="Delete cell"
                            aria-label="Delete cell"
                            onClick={(e) => {
                              e.stopPropagation();
                              nb.deleteCell(i);
                            }}
                          >
                            ✕
                          </Button>
                        </div>
                      </header>

                      <div className="space-y-3 p-3">
                        {focused && focusedNeeds.includes("text") ? (
                          <div
                            className={cn(
                              "cell-runtime-zone rounded-[10px] border-l-[3px] p-3",
                              inputNeedsAttention && unmet.includes("needs input")
                                ? "cell-runtime-needs"
                                : "cell-runtime-ready"
                            )}
                          >
                            <div className="mb-2 text-[0.65rem] font-bold uppercase tracking-wider text-[var(--brand)]">
                              Required at run
                            </div>
                            <p className="mb-2 text-sm font-semibold">Message</p>
                            <Textarea
                              rows={unmet.includes("needs input") ? 2 : 6}
                              value={nb.inputText}
                              onChange={(e) => nb.setInputText(e.target.value)}
                              placeholder="Paste or load the message — not stored in the recipe."
                            />
                          </div>
                        ) : null}

                        {focused && focusedNeeds.includes("gpg") ? (
                          <div
                            className={cn(
                              "cell-runtime-zone rounded-[10px] border-l-[3px] p-3",
                              unmet.includes("needs ciphertext")
                                ? "cell-runtime-needs"
                                : "cell-runtime-ready"
                            )}
                          >
                            <div className="mb-2 text-[0.65rem] font-bold uppercase tracking-wider text-[var(--brand)]">
                              Required at run
                            </div>
                            <p className="mb-2 text-sm font-semibold">Decrypt</p>
                            <Textarea
                              rows={3}
                              value={nb.ciphertext}
                              onChange={(e) => nb.setCiphertext(e.target.value)}
                              placeholder="Paste -----BEGIN PGP MESSAGE----- …"
                            />
                          </div>
                        ) : null}

                        {focused && recipSlots > 0 ? (
                          <RecipientBinderHost
                            slots={recipSlots}
                            onChange={nb.setBoundRecipients}
                          />
                        ) : null}

                        <div className="builder-spine relative space-y-2 pl-1">
                          {cellView(i) === "raw" ? (
                            <div className="space-y-2">
                              <Textarea
                                className="font-mono text-xs"
                                rows={Math.max(3, (chain.steps || []).length + 2)}
                                value={rawDrafts[i] ?? nb.cellRecipeSource(i)}
                                onChange={(e) =>
                                  setRawDrafts((prev) => ({
                                    ...prev,
                                    [i]: e.target.value,
                                  }))
                                }
                                onBlur={() => {
                                  const text = rawDrafts[i] ?? nb.cellRecipeSource(i);
                                  if (nb.applyCellRecipeText(i, text)) {
                                    setRawDrafts((prev) => {
                                      const next = { ...prev };
                                      delete next[i];
                                      return next;
                                    });
                                  }
                                }}
                                spellCheck={false}
                                placeholder="random 32 | base64 | out @secret"
                              />
                              <p className="text-xs text-[var(--muted-foreground)]">
                                Edit the cell recipe as text — applies on blur.
                              </p>
                            </div>
                          ) : null}
                          {cellView(i) !== "raw" && (chain.steps || []).length === 0 ? (
                            <div className="rounded-lg border border-dashed border-[var(--border)] px-4 py-6 text-center text-sm text-[var(--muted-foreground)]">
                              Drop an operation from the shelf, or use Encrypt / Templates.
                            </div>
                          ) : null}
                          {cellView(i) !== "raw" ? (() => {
                            const list = chain.steps || [];
                            const stems: ChipStemView[] = list.map((s) => {
                              const spec = getStep(s.name);
                              const hasNest =
                                (s.name === "tee" || s.name === "foreach") &&
                                ((s.branches || []).length > 0 ||
                                  (s.body || []).length > 0);
                              return {
                                step: {
                                  name: s.name,
                                  label: spec?.label || s.name,
                                  op: spec || undefined,
                                },
                                hasNest,
                                branches: (s.branches || []).map((br) => {
                                  const rawSel = String(
                                    br.selector || br.member || ""
                                  ).trim();
                                  const sel = !rawSel
                                    ? ":?"
                                    : rawSel.startsWith(":") ||
                                        rawSel.startsWith("[")
                                      ? rawSel
                                      : `:${rawSel}`;
                                  return {
                                    selector: sel,
                                    steps: (br.body || []).map((bs) => {
                                      const bspec = getStep(bs.name);
                                      return {
                                        name: bs.name,
                                        label: bspec?.label || bs.name,
                                        op: bspec || undefined,
                                      };
                                    }),
                                  };
                                }),
                                body: (s.body || []).map((bs) => {
                                  const bspec = getStep(bs.name);
                                  return {
                                    name: bs.name,
                                    label: bspec?.label || bs.name,
                                    op: bspec || undefined,
                                  };
                                }),
                              };
                            });
                            const selected =
                              chipEdit?.cell === i ? chipEdit : null;
                            const selectedStep = (() => {
                              if (!selected) return null;
                              const stem = list[selected.stem];
                              if (!stem) return null;
                              if (selected.body != null) {
                                const body =
                                  selected.branch != null
                                    ? stem.branches?.[selected.branch]?.body
                                    : stem.body;
                                return body?.[selected.body] || null;
                              }
                              if (selected.branch != null) return null;
                              return stem;
                            })();
                            const selectedSpec = selectedStep
                              ? getStep(selectedStep.name)
                              : null;
                            return (
                              <>
                                <RecipeChipFlow
                                  cell={i}
                                  stems={stems}
                                  selected={selected}
                                  activeGap={
                                    pendingInsert?.cell === i ? pendingInsert : null
                                  }
                                  showNestRails
                                  nestExpanded={nestExpanded}
                                  nestRailFor={nestRailFor}
                                  onSelect={(path) => {
                                    nb.setFocusedCell(i);
                                    setPendingInsert(null);
                                    setChipEdit((prev) =>
                                      prev &&
                                      prev.cell === path.cell &&
                                      prev.stem === path.stem &&
                                      (prev.branch ?? null) ===
                                        (path.branch ?? null) &&
                                      (prev.body ?? null) === (path.body ?? null)
                                        ? null
                                        : path
                                    );
                                  }}
                                  onGap={(path) => {
                                    nb.setFocusedCell(i);
                                    setChipEdit(null);
                                    setPendingInsert(path);
                                  }}
                                  onBranchHit={(stem, branch) => {
                                    nb.setFocusedCell(i);
                                    setNestExpanded({ stem, branch });
                                    setPendingInsert({
                                      cell: i,
                                      stem,
                                      branch,
                                      body: null,
                                    });
                                  }}
                                  onNestToggle={(stem, branch) => {
                                    setNestExpanded((prev) =>
                                      prev &&
                                      prev.stem === stem &&
                                      (prev.branch ?? null) === branch
                                        ? null
                                        : { stem, branch }
                                    );
                                  }}
                                  onNestAppend={(stem, branch, name, opts) => {
                                    nb.setFocusedCell(i);
                                    nb.nestOp(stem, branch, name, opts);
                                    setNestExpanded(null);
                                  }}
                                  onReorder={(from, to) => {
                                    if (from.cell !== i || to.cell !== i) return;
                                    nb.setFocusedCell(i);
                                    setChipEdit(null);
                                    if (from.body != null || to.body != null) {
                                      if (
                                        from.stem !== to.stem ||
                                        (from.branch ?? null) !== (to.branch ?? null) ||
                                        from.body == null ||
                                        to.body == null
                                      ) {
                                        return;
                                      }
                                      nb.reorderNest(
                                        from.stem,
                                        from.branch ?? null,
                                        from.body,
                                        to.body
                                      );
                                      return;
                                    }
                                    nb.reorderStem(from.stem, to.stem);
                                  }}
                                  onDropStep={(path, name, opts) => {
                                    nb.setFocusedCell(i);
                                    setPendingInsert(null);
                                    if (path.body != null) {
                                      nb.nestOp(
                                        path.stem,
                                        path.branch ?? null,
                                        name,
                                        { ...opts, at: path.body }
                                      );
                                      return;
                                    }
                                    nb.insertOpAt(path.stem, name, opts);
                                    setChipEdit(null);
                                  }}
                                  onRemove={(path) => {
                                    nb.setFocusedCell(i);
                                    if (path.body != null) {
                                      nb.removeNestStep(
                                        path.stem,
                                        path.branch ?? null,
                                        path.body
                                      );
                                    } else {
                                      nb.removeStep(path.stem);
                                    }
                                    setChipEdit((prev) =>
                                      prev &&
                                      prev.cell === path.cell &&
                                      prev.stem === path.stem &&
                                      (prev.branch ?? null) ===
                                        (path.branch ?? null) &&
                                      (prev.body ?? null) === (path.body ?? null)
                                        ? null
                                        : prev
                                    );
                                  }}
                                />
                                {cellView(i) === "cards" && list.length > 0 ? (
                                  <div className="mt-3 space-y-2">
                                    {list.map((s, si) => {
                                      const spec = getStep(s.name);
                                      if (!spec) return null;
                                      return (
                                        <ToolCard
                                          key={`${si}-${s.name}`}
                                          op={spec}
                                          compact
                                          className="max-w-full"
                                        />
                                      );
                                    })}
                                  </div>
                                ) : null}
                                {focused && selectedStep && selectedSpec ? (
                                  <div className="cell-recipe-inline-edit rounded-lg border border-[var(--border)] p-3">
                                    <div className="mb-2 flex flex-wrap items-center gap-2">
                                      <strong>{selectedSpec.label || selectedStep.name}</strong>
                                      <span className="text-xs text-[var(--muted-foreground)]">
                                        {selectedSpec.doc || ""}
                                      </span>
                                      <div className="ml-auto flex gap-1">
                                        <Button
                                          size="sm"
                                          variant="ghost"
                                          className="text-[var(--error)]"
                                          title="Remove step"
                                          aria-label="Remove step"
                                          onClick={() => {
                                            if (!selected) return;
                                            if (selected.body != null) {
                                              nb.removeNestStep(
                                                selected.stem,
                                                selected.branch ?? null,
                                                selected.body
                                              );
                                            } else {
                                              nb.removeStep(selected.stem);
                                            }
                                            setChipEdit(null);
                                          }}
                                        >
                                          ✕
                                        </Button>
                                        <Button
                                          size="sm"
                                          variant="ghost"
                                          onClick={() => setChipEdit(null)}
                                        >
                                          Done
                                        </Button>
                                      </div>
                                    </div>
                                    <ParamFieldGroup
                                      params={selectedSpec.params || []}
                                      values={selectedStep.params || {}}
                                      onChange={(name, value) => {
                                        if (!selected) return;
                                        if (selected.body != null) {
                                          nb.updateNestStepParams(
                                            selected.stem,
                                            selected.branch ?? null,
                                            selected.body,
                                            name,
                                            value
                                          );
                                        } else {
                                          nb.updateStepParams(
                                            selected.stem,
                                            name,
                                            value
                                          );
                                        }
                                      }}
                                    />
                                  </div>
                                ) : null}
                                {focused ? (
                                  <SuggestRail
                                    className="mt-2"
                                    scope="cell"
                                    toolboxes={tipModel.rail.toolboxes}
                                    activeToolbox={tipModel.rail.activeToolbox}
                                    pulloutChips={tipModel.rail.pulloutChips}
                                    composeChips={needComposeChips}
                                    onToolboxClick={(tb) => {
                                      setSuggestPullout((prev) =>
                                        prev === tb ? null : tb
                                      );
                                    }}
                                    onClosePullout={() => setSuggestPullout(null)}
                                    onOpenOps={(tb) => {
                                      setSuggestPullout(null);
                                      if (tb === "webcrypto") nb.setOpsFilter("genkey");
                                      else if (tb === "io") nb.setOpsFilter("input");
                                      else if (tb === "hkp") nb.setOpsFilter("hkp");
                                      else nb.setOpsFilter(tb);
                                    }}
                                    onCompose={(id) => {
                                      if (id === "missing-key") {
                                        setSuggestPullout("webcrypto");
                                        nb.setOpsFilter("genkey");
                                        return;
                                      }
                                      if (id === "missing-recipients") {
                                        setSuggestPullout("hkp");
                                        nb.setOpsFilter("hkp");
                                        return;
                                      }
                                      if (id === "missing-input") {
                                        setSuggestPullout("io");
                                        nb.setOpsFilter("input");
                                        return;
                                      }
                                      if (id === "missing-ciphertext") {
                                        setSuggestPullout("openpgp");
                                        nb.setOpsFilter("decrypt");
                                      }
                                    }}
                                    onAppend={(name, opts) => {
                                      nb.setFocusedCell(i);
                                      setSuggestPullout(null);
                                      if (pendingInsert && pendingInsert.cell === i) {
                                        const path = pendingInsert;
                                        setPendingInsert(null);
                                        if (path.body != null) {
                                          nb.nestOp(path.stem, path.branch ?? null, name, {
                                            ...opts,
                                            at: path.body,
                                          });
                                          return;
                                        }
                                        nb.insertOpAt(path.stem, name, opts);
                                        return;
                                      }
                                      nb.appendOp(name, opts);
                                    }}
                                  />
                                ) : null}
                              </>
                            );
                          })() : null}
                        </div>

                        {(nb.cellOutputs[i] || []).length > 0 ? (
                          <OutputCarousel outputs={nb.cellOutputs[i]} />
                        ) : null}
                      </div>
                    </article>
                  );
                })}

                <div className="flex justify-center py-2">
                  <Button variant="ghost" size="sm" onClick={() => nb.addCell()}>
                    <Plus />
                    Cell
                  </Button>
                </div>

                <details className="rounded-lg border border-[var(--border)] p-3">
                  <summary className="cursor-pointer text-sm text-[var(--muted-foreground)]">
                    Notebook source (text)
                  </summary>
                  <pre className="mt-2 max-h-64 overflow-auto whitespace-pre-wrap font-mono text-xs">
                    {nb.source}
                  </pre>
                </details>
              </div>
            </ScrollArea>
          </section>
        </div>

        {/* Keyring sheet */}
        <Sheet open={nb.sheet === "keyring"} onOpenChange={(o) => nb.setSheet(o ? "keyring" : null)}>
          <SheetContent side="right" className="w-full sm:max-w-md">
            <SheetHeader>
              <SheetTitle>Keyring (My Keys)</SheetTitle>
              <SheetDescription>
                Unlock into the agent session or insert <code>agent.unlock</code> /{" "}
                <code>agent.pub</code> cells. Full vault management is on{" "}
                <a className="text-[var(--brand)] underline" href="/my-keys">
                  My Keys
                </a>
                .
              </SheetDescription>
            </SheetHeader>
            <Separator />
            <ScrollArea className="flex-1 px-4">
              {!nb.vaultKeys.length ? (
                <p className="py-4 text-sm text-[var(--muted-foreground)]">
                  No keys in My Keys yet. Generate one on My Keys or use{" "}
                  <code>agent.save</code>.
                </p>
              ) : (
                <ul className="space-y-3 py-3">
                  {nb.vaultKeys.map((k) => {
                    const unlocked = nb.sessionList().some((e) => e.fingerprint === k.fingerprint);
                    return (
                      <li
                        key={k.fingerprint}
                        className="rounded-lg border border-[var(--border)] bg-[var(--surface-raised)] p-3"
                      >
                        <div className="font-semibold">{k.uid || k.email || "Key"}</div>
                        <a
                          className="font-mono text-xs text-[var(--brand)]"
                          href={`/key?fpr=${k.fingerprint}`}
                          target="_blank"
                          rel="noopener noreferrer"
                        >
                          {nb.formatFingerprint(k.fingerprint)}
                        </a>
                        <div className="mt-1 text-xs text-[var(--muted-foreground)]">
                          {k.protection || "device"}
                          {unlocked ? " · unlocked" : ""}
                        </div>
                        <div className="mt-2 flex flex-wrap gap-1">
                          {unlocked ? (
                            <Button size="sm" variant="ghost" onClick={() => nb.lockKey(k.fingerprint)}>
                              Lock
                            </Button>
                          ) : (
                            <Button
                              size="sm"
                              variant="secondary"
                              onClick={() => void nb.unlockKey(k.fingerprint)}
                            >
                              Unlock
                            </Button>
                          )}
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => nb.insertUnlockCell(k.fingerprint, "agent.unlock")}
                          >
                            Unlock → cell
                          </Button>
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => nb.insertUnlockCell(k.fingerprint, "agent.pub")}
                          >
                            Pub → cell
                          </Button>
                        </div>
                      </li>
                    );
                  })}
                </ul>
              )}
            </ScrollArea>
          </SheetContent>
        </Sheet>

        {/* Variables sheet */}
        <Sheet
          open={nb.sheet === "variables"}
          onOpenChange={(o) => nb.setSheet(o ? "variables" : null)}
        >
          <SheetContent side="right" className="w-full sm:max-w-md">
            <SheetHeader>
              <SheetTitle>Variables</SheetTitle>
              <SheetDescription>
                Live <code>@slots</code> from the notebook kernel. Cleared with Clear sensitive.
              </SheetDescription>
            </SheetHeader>
            <Separator />
            <ScrollArea className="flex-1 px-4">
              {!nb.slotMetas.length ? (
                <p className="py-4 text-sm text-[var(--muted-foreground)]">No slots yet.</p>
              ) : (
                <ul className="space-y-2 py-3">
                  {nb.slotMetas.map((m) => (
                    <li
                      key={m.label}
                      className="rounded-lg border border-[var(--border)] bg-[var(--surface-raised)] px-3 py-2"
                    >
                      <code className="font-semibold">@{m.label}</code>
                      <Badge variant="secondary" className="ml-2 normal-case tracking-normal">
                        {m.type}
                      </Badge>
                      {m.fingerprint ? (
                        <div className="mt-1 font-mono text-[0.7rem] text-[var(--muted-foreground)]">
                          {nb.formatFingerprint(m.fingerprint)}
                        </div>
                      ) : null}
                    </li>
                  ))}
                </ul>
              )}
            </ScrollArea>
          </SheetContent>
        </Sheet>

        {/* Crypto params sheet */}
        <Sheet open={nb.sheet === "crypto"} onOpenChange={(o) => nb.setSheet(o ? "crypto" : null)}>
          <SheetContent side="right" className="w-full sm:max-w-md">
            <SheetHeader>
              <SheetTitle>Cryptographic parameters</SheetTitle>
              <SheetDescription>
                Runtime OpenPGP profile is controlled by the header toggle (Modern / Compatible /
                Auto). Cipher/AEAD/S2K fine-tuning remains available in the classic expert panel in a
                follow-up; profile selection already applies to encrypt runs.
              </SheetDescription>
            </SheetHeader>
            <Separator />
            <div className="space-y-3 p-4 text-sm">
              <p>
                Current mode: <strong>{nb.pgpMode}</strong>
              </p>
              <ModeToggle
                ariaLabel="OpenPGP profile"
                value={nb.pgpMode}
                onChange={(v) => nb.setPgpMode(v as "auto" | "modern" | "compatible")}
                options={[
                  { value: "auto", label: "Auto" },
                  { value: "modern", label: "Modern" },
                  { value: "compatible", label: "Compatible" },
                ]}
              />
            </div>
          </SheetContent>
        </Sheet>
      </div>
    </TooltipProvider>
  );
}
