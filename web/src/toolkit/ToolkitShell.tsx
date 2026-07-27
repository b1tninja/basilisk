import { useMemo } from "react";
import {
  KeyRound,
  Braces,
  Play,
  Link2,
  Eraser,
  Plus,
  Trash2,
  MoreHorizontal,
  BookTemplate,
  Settings2,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { cn } from "@/lib/cn";
import { useNotebook } from "./useNotebook";
import { RecipientBinderHost } from "./RecipientBinderHost";
import { OutputCarousel } from "./OutputCarousel";
import { OpsIconGrid, STEP_MIME } from "./OpsIconGrid";

export function ToolkitShell() {
  const nb = useNotebook();

  const presetsByGroup = useMemo(() => {
    const map = new Map<string, typeof nb.presets>();
    for (const p of nb.presets) {
      const g = p.group || "Other";
      if (!map.has(g)) map.set(g, []);
      map.get(g)!.push(p);
    }
    return [...map.entries()];
  }, [nb.presets]);

  const focusedNeeds = nb.cellInputNeeds(nb.chains[nb.focusedCell] || { steps: [] });
  const recipSlots = nb.cellRecipientSlots(nb.chains[nb.focusedCell] || { steps: [] });
  const unmet = nb.unmetForCell(nb.focusedCell);
  const inputNeedsAttention = unmet.some((u) =>
    ["needs input", "needs ciphertext"].includes(u)
  );

  return (
    <TooltipProvider delayDuration={300}>
      <div className="toolkit-shell flex min-h-0 flex-1 flex-col bg-[var(--background)] text-[var(--foreground)]">
        {/* App toolbar */}
        <div className="flex flex-wrap items-center gap-2 border-b border-[var(--border)] px-3 py-2">
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" size="sm">
                <BookTemplate className="opacity-80" />
                Templates
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent className="max-h-[70vh] w-80 overflow-auto">
              <DropdownMenuLabel>One-click notebooks</DropdownMenuLabel>
              {presetsByGroup.map(([group, items]) => (
                <div key={group}>
                  <DropdownMenuSeparator />
                  <DropdownMenuLabel>{group}</DropdownMenuLabel>
                  {items.map((p) => (
                    <DropdownMenuItem key={p.id} onSelect={() => nb.loadPreset(p.id)}>
                      <div className="flex flex-col gap-0.5">
                        <span>{p.title}</span>
                        <span className="text-[0.7rem] text-[var(--muted-foreground)] line-clamp-2">
                          {p.blurb}
                        </span>
                      </div>
                    </DropdownMenuItem>
                  ))}
                </div>
              ))}
            </DropdownMenuContent>
          </DropdownMenu>

          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" size="sm">
                <MoreHorizontal />
                More
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent>
              <DropdownMenuItem onSelect={() => nb.setSheet("keyring")}>Keyring</DropdownMenuItem>
              <DropdownMenuItem onSelect={() => nb.setSheet("variables")}>Variables</DropdownMenuItem>
              <DropdownMenuItem onSelect={() => nb.setSheet("crypto")}>
                Cryptographic parameters
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem onSelect={() => void nb.copyRecipe()}>Copy recipe</DropdownMenuItem>
              <DropdownMenuItem onSelect={() => nb.resetNotebook()}>Reset notebook</DropdownMenuItem>
              <DropdownMenuItem asChild>
                <a href="/preferences">Preferences</a>
              </DropdownMenuItem>
              <DropdownMenuItem asChild>
                <a href="/my-keys">My Keys</a>
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>

          <div className="ml-auto flex items-center gap-2 text-xs text-[var(--muted-foreground)]">
            <span>OpenPGP · WebCrypto · SSS</span>
          </div>
        </div>

        <div className="flex min-h-0 flex-1">
          <OpsIconGrid
            ops={nb.filteredOps}
            filter={nb.opsFilter}
            onFilter={nb.setOpsFilter}
            onAppend={nb.appendOp}
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
              const name =
                e.dataTransfer.getData(STEP_MIME) || e.dataTransfer.getData("text/plain");
              if (!name) return;
              e.preventDefault();
              nb.appendOp(name);
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
                <div className="flex flex-wrap gap-1">
                  <Button size="sm" variant="secondary" onClick={() => nb.insertMessaging("encrypt")}>
                    Encrypt
                  </Button>
                  <Button size="sm" variant="secondary" onClick={() => nb.insertMessaging("decrypt")}>
                    Decrypt
                  </Button>
                  <Button size="sm" variant="ghost" onClick={() => nb.insertMessaging("symencrypt")}>
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
                  <ToggleGroup
                    type="single"
                    value={nb.pgpMode}
                    onValueChange={(v) => {
                      if (v) nb.setPgpMode(v as "auto" | "modern" | "compatible");
                    }}
                  >
                    <ToggleGroupItem value="auto">Auto</ToggleGroupItem>
                    <ToggleGroupItem value="modern">Modern</ToggleGroupItem>
                    <ToggleGroupItem value="compatible">Compatible</ToggleGroupItem>
                  </ToggleGroup>
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
                            disabled={nb.chains.length <= 1}
                            onClick={(e) => {
                              e.stopPropagation();
                              nb.deleteCell(i);
                            }}
                          >
                            <Trash2 />
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

                        <div className="builder-spine relative space-y-1 pl-1">
                          {(chain.steps || []).length === 0 ? (
                            <div className="rounded-lg border border-dashed border-[var(--border)] px-4 py-6 text-center text-sm text-[var(--muted-foreground)]">
                              Drop an operation from the shelf, or use Encrypt / Templates.
                            </div>
                          ) : (
                            (chain.steps || []).map((step, si) => (
                              <div
                                key={`${step.name}-${si}`}
                                className={cn(
                                  "flex items-start gap-2 rounded-lg bg-[color-mix(in_srgb,var(--surface-raised)_70%,transparent)] px-3 py-2",
                                  step.name.startsWith("gpg.") &&
                                    "border-l-[3px] border-l-[var(--brand)]"
                                )}
                              >
                                <span className="mt-0.5 min-w-6 rounded-full bg-[color-mix(in_srgb,var(--brand)_12%,transparent)] px-1.5 text-center font-mono text-[0.7rem] font-bold text-[var(--brand)]">
                                  {si + 1}
                                </span>
                                <div className="min-w-0 flex-1">
                                  <div className="font-semibold">{step.name}</div>
                                  <code className="text-[0.7rem] text-[var(--muted-foreground)]">
                                    {Object.entries(step.params || {})
                                      .filter(([, v]) => v !== "" && v != null && v !== false)
                                      .map(([k, v]) => `${k}=${String(v)}`)
                                      .join(" · ") || "—"}
                                  </code>
                                </div>
                                {focused ? (
                                  <Button
                                    size="icon"
                                    variant="ghost"
                                    className="text-[var(--error)]"
                                    onClick={() => nb.removeStep(si)}
                                  >
                                    <Trash2 />
                                  </Button>
                                ) : null}
                              </div>
                            ))
                          )}
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
              <ToggleGroup
                type="single"
                value={nb.pgpMode}
                onValueChange={(v) => {
                  if (v) nb.setPgpMode(v as "auto" | "modern" | "compatible");
                }}
              >
                <ToggleGroupItem value="auto">Auto</ToggleGroupItem>
                <ToggleGroupItem value="modern">Modern</ToggleGroupItem>
                <ToggleGroupItem value="compatible">Compatible</ToggleGroupItem>
              </ToggleGroup>
            </div>
          </SheetContent>
        </Sheet>
      </div>
    </TooltipProvider>
  );
}
