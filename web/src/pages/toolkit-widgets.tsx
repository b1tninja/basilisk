import { useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import { listSteps } from "../lib/toolkit/registry.js";
import {
  Glyph,
  ToolCard,
  OpsTile,
  OpsShelf,
  SuggestChip,
  InsertGap,
  SuggestRail,
  RecipeChipFlow,
  ParamField,
  ParamFieldGroup,
  ModeToggle,
  MenuPopover,
  PresetMenu,
} from "../toolkit/widgets/index";
import { TooltipProvider } from "@/components/ui/tooltip";
import "../css/toolkit.css";
import "../css/site.css";

function Section({
  id,
  title,
  children,
}: {
  id: string;
  title: string;
  children: React.ReactNode;
}) {
  return (
    <section id={id} className="mb-10 scroll-mt-6">
      <h2 className="mb-3 text-lg font-bold tracking-tight">{title}</h2>
      <div className="flex flex-col gap-4 rounded-xl border border-[var(--border)] bg-[color-mix(in_srgb,var(--surface-raised)_70%,transparent)] p-4">
        {children}
      </div>
    </section>
  );
}

function StateLabel({ children }: { children: React.ReactNode }) {
  return (
    <p className="mb-2 text-[0.65rem] font-bold uppercase tracking-wider text-[var(--muted-foreground)]">
      {children}
    </p>
  );
}

function CatalogApp() {
  const ops = useMemo(
    () => listSteps(),
    []
  );
  const sample = ops.find((o) => o.name === "genkey") || ops[0];
  const base64 = ops.find((o) => o.name === "base64") || sample;
  const [filter, setFilter] = useState("");
  const [mode, setMode] = useState("preview");
  const [gapActive, setGapActive] = useState(false);
  const [params, setParams] = useState<Record<string, unknown>>({
    alg: "ec/p256",
    usage: "auto",
  });
  const [chipSel, setChipSel] = useState(false);
  const [railOpen, setRailOpen] = useState(false);

  const railItems = useMemo(
    () =>
      ops.slice(0, 6).map((op) => ({
        op,
        label: op.label || op.name,
      })),
    [ops]
  );

  return (
    <TooltipProvider>
      <div className="mx-auto max-w-5xl px-4 py-6">
        <header className="mb-8">
          <p className="text-sm text-[var(--muted-foreground)]">
            Shared toolkit widgets — see{" "}
            <code className="text-[var(--foreground)]">docs/TOOLKIT-WIDGETS.md</code>
          </p>
          <h1 className="mt-1 text-2xl font-bold">Widget catalog</h1>
          <p className="mt-2 max-w-2xl text-sm text-[var(--muted-foreground)]">
            Canonical states for Glyph, ToolCard, OpsTile, OpsShelf, chips, gaps, rails,
            params, toggles, and menus. Production toolkit mounts these as islands over time.
          </p>
          <nav className="mt-4 flex flex-wrap gap-2 text-xs">
            {[
              "glyph",
              "toolcard",
              "opstile",
              "opsshelf",
              "chips",
              "insertgap",
              "suggestrail",
              "recipechipflow",
              "paramfield",
              "modetoggle",
              "menupopover",
              "presetmenu",
            ].map((id) => (
              <a
                key={id}
                href={`#${id}`}
                className="rounded border border-[var(--border)] px-2 py-1 hover:border-[var(--brand)]"
              >
                {id}
              </a>
            ))}
          </nav>
        </header>

        <Section id="glyph" title="Glyph">
          <div className="flex flex-wrap items-end gap-6">
            {["genkey", "openpgp", "tee", "export", "gear"].map((id) => (
              <div key={id} className="flex flex-col items-center gap-1">
                <Glyph id={id} size={22} svgClassName="ops-glyph ops-glyph-tile" />
                <code className="text-[0.65rem]">{id}</code>
              </div>
            ))}
          </div>
        </Section>

        <Section id="toolcard" title="ToolCard">
          <div className="grid gap-4 md:grid-cols-2">
            <div>
              <StateLabel>Default</StateLabel>
              {sample ? <ToolCard op={sample} className="max-w-sm" /> : null}
            </div>
            <div>
              <StateLabel>Compact · fit · blocked</StateLabel>
              {sample ? (
                <ToolCard op={sample} compact fit blocked hideHint className="max-w-sm" />
              ) : null}
            </div>
          </div>
        </Section>

        <Section id="opstile" title="OpsTile">
          <div className="grid max-w-md grid-cols-2 gap-2">
            {base64 ? (
              <>
                <div>
                  <StateLabel>Encode</StateLabel>
                  <OpsTile op={base64} pairRole="forward" onAppend={() => {}} />
                </div>
                <div>
                  <StateLabel>Decode</StateLabel>
                  <OpsTile op={base64} decode pairRole="reverse" onAppend={() => {}} />
                </div>
                <div>
                  <StateLabel>Dim</StateLabel>
                  <OpsTile op={base64} dim onAppend={() => {}} showTooltip={false} />
                </div>
                <div>
                  <StateLabel>Fit</StateLabel>
                  <OpsTile op={base64} fit onAppend={() => {}} showTooltip={false} />
                </div>
              </>
            ) : null}
          </div>
        </Section>

        <Section id="opsshelf" title="OpsShelf">
          <StateLabel>Bare embed (search + tip-fit unset)</StateLabel>
          <div className="h-[320px] max-w-xs overflow-hidden rounded-lg border border-[var(--border)]">
            <OpsShelf
              ops={ops}
              filter={filter}
              onFilter={setFilter}
              onAppend={() => {}}
              bare
            />
          </div>
        </Section>

        <Section id="chips" title="SuggestChip">
          <div className="flex flex-wrap items-center gap-2">
            <SuggestChip label="base64.encode" variant="candidate" op={base64} />
            <SuggestChip
              label="genkey"
              hint="ec/p256"
              variant="placed"
              op={sample}
            />
            <SuggestChip label=":public" variant="selector" />
            <SuggestChip
              label="export"
              hint="spki"
              variant="editable"
              selected={chipSel}
              op={ops.find((o) => o.name === "export")}
              onClick={() => setChipSel((v) => !v)}
            />
            <SuggestChip label="broken" variant="placed" error />
            <SuggestChip
              label="base64"
              variant="editable"
              op={base64}
              onClick={() => {}}
              onRemove={() => {}}
            />
          </div>
        </Section>

        <Section id="insertgap" title="InsertGap">
          <div className="flex items-center gap-3">
            <SuggestChip label="random" variant="placed" />
            <InsertGap
              active={gapActive}
              onClick={() => setGapActive((v) => !v)}
              label="Toggle drop-active"
            />
            <SuggestChip label="out" variant="placed" />
          </div>
        </Section>

        <Section id="suggestrail" title="SuggestRail">
          <StateLabel>Cell-style rail (op tiles)</StateLabel>
          <SuggestRail items={railItems} onAppend={() => {}} />
          <StateLabel>Expandable nest +</StateLabel>
          <SuggestRail
            items={railItems}
            onAppend={() => {}}
            expandable
            expanded={railOpen}
            onToggleExpand={() => setRailOpen((v) => !v)}
          />
          <StateLabel>Toolbox squares + pull-out (cell drawer)</StateLabel>
          <SuggestRail
            toolboxes={[
              {
                id: "encoding",
                label: "Encoding",
                badge: "Encode",
                glyph: "encoding",
                fit: true,
                count: 2,
              },
              {
                id: "webcrypto",
                label: "WebCrypto",
                badge: "WebCrypto",
                glyph: "webcrypto",
                muted: true,
              },
            ]}
            activeToolbox={railOpen ? "encoding" : null}
            onToolboxClick={() => setRailOpen((v) => !v)}
            pulloutChips={railItems.map(({ op, decode, label }, i) => ({
              op,
              decode,
              label,
              primary: i === 0,
            }))}
            onAppend={() => {}}
            onClosePullout={() => setRailOpen(false)}
            composeChips={[
              { id: "encrypt-to", label: "Encrypt message to this set", primary: true },
            ]}
            onCompose={() => {}}
          />
        </Section>

        <Section id="recipechipflow" title="RecipeChipFlow">
          <StateLabel>Stem chips + gaps (fixture)</StateLabel>
          <RecipeChipFlow
            cell={0}
            stems={[
              {
                step: {
                  name: "genkey",
                  label: sample?.label || "genkey",
                  op: sample,
                },
                hasNest: false,
              },
              {
                step: {
                  name: "base64",
                  label: base64?.label || "base64",
                  hint: "encode",
                  op: base64,
                  ghostIn: "bytes",
                },
                hasNest: false,
              },
            ]}
            selected={null}
            showNestRails={false}
            onSelect={() => {}}
            onGap={() => setGapActive((v) => !v)}
            onBranchHit={() => {}}
            onNestToggle={() => {}}
            onNestAppend={() => {}}
            onReorder={() => {}}
          />
          <StateLabel>activeGap highlights insert focus</StateLabel>
          <RecipeChipFlow
            cell={0}
            stems={[
              {
                step: {
                  name: "genkey",
                  label: sample?.label || "genkey",
                  op: sample,
                },
                hasNest: false,
              },
              {
                step: {
                  name: "base64",
                  label: base64?.label || "base64",
                  hint: "encode",
                  op: base64,
                },
                hasNest: false,
              },
            ]}
            selected={null}
            activeGap={gapActive ? { cell: 0, stem: 1, branch: null, body: null } : null}
            showNestRails={false}
            onSelect={() => {}}
            onGap={() => setGapActive(true)}
            onBranchHit={() => {}}
            onNestToggle={() => {}}
            onNestAppend={() => {}}
            onReorder={() => {}}
          />
        </Section>

        <Section id="paramfield" title="ParamField">
          <ParamFieldGroup
            params={[
              {
                name: "alg",
                type: "enum",
                enum: ["ec/p256", "ec/p384", "aes/256"],
                doc: "Algorithm",
              },
              { name: "usage", type: "enum", enum: ["auto", "sign", "encrypt"] },
              { name: "label", type: "string", doc: "Optional label" },
              { name: "decode", type: "bool", flag: "-d" },
            ]}
            values={params}
            visibilityFor={(p) =>
              p.name === "usage"
                ? { show: true, locked: true }
                : { show: true }
            }
            onChange={(name, value) =>
              setParams((prev) => ({ ...prev, [name]: value }))
            }
          />
          <ParamField
            param={{ name: "custom", type: "string" }}
            value=""
            onChange={() => {}}
            control={<span className="muted fs-xs">Custom control slot</span>}
          />
        </Section>

        <Section id="modetoggle" title="ModeToggle">
          <StateLabel>Legacy cell styles</StateLabel>
          <ModeToggle
            legacy
            value={mode}
            onChange={setMode}
            options={[
              { value: "preview", label: "Preview" },
              { value: "raw", label: "Raw" },
              { value: "cards", label: "Cards" },
            ]}
          />
          <StateLabel>ToggleGroup</StateLabel>
          <ModeToggle
            value={mode}
            onChange={setMode}
            options={[
              { value: "preview", label: "Preview" },
              { value: "raw", label: "Raw" },
              { value: "cards", label: "Cards" },
            ]}
          />
        </Section>

        <Section id="menupopover" title="MenuPopover">
          <MenuPopover
            label="More"
            heading="Session"
            items={[
              { id: "a", label: "Keyring", onSelect: () => {} },
              { id: "b", label: "Variables", onSelect: () => {} },
              { id: "c", label: "Docs", href: "/docs/TOOLKIT-WIDGETS.md", separatorBefore: true },
            ]}
          />
        </Section>

        <Section id="presetmenu" title="PresetMenu">
          <StateLabel>Templates gallery (categories + companion pairs)</StateLabel>
          <PresetMenu
            presets={[
              {
                id: "demo-a",
                group: "Keys",
                title: "Demo forward",
                blurb: "Catalog fixture — forward half of a companion pair.",
                recipe: "genkey ec/p256 | out @k",
                pair: "demo-pair",
              },
              {
                id: "demo-b",
                group: "Keys",
                title: "Demo inverse",
                blurb: "Catalog fixture — inverse half.",
                recipe: "in @k | export spki",
                pair: "demo-pair",
              },
              {
                id: "demo-solo",
                group: "Secrets",
                title: "Solo template",
                blurb: "Single card without a companion.",
                recipe: "random 32 | base64url | out @secret",
              },
            ]}
            groups={["Keys", "Secrets"]}
            onLoad={() => {}}
            onAppend={() => {}}
            onAddBoth={() => {}}
          />
        </Section>
      </div>
    </TooltipProvider>
  );
}

const host = document.getElementById("toolkit-widgets-root");
if (!host) throw new Error("#toolkit-widgets-root missing");
createRoot(host).render(<CatalogApp />);
