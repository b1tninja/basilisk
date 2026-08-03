// First import on the page, deliberately: it installs listeners for failures
// that happen *while the rest of this module graph loads*. Anything imported
// above it could fail unobserved.
import { installBootDiagnostics } from "../lib/boot-diagnostics.js";
import { useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import { listSteps } from "../lib/toolkit/registry.js";
import { tipFitFor } from "../lib/toolkit/suggest.js";
import {
  Glyph,
  ToolboxDot,
  ToolCard,
  OpsTile,
  OpsShelf,
  SuggestChip,
  InsertGap,
  RecipeChipFlow,
  ParamField,
  ParamFieldGroup,
  ModeToggle,
  MenuPopover,
  PresetMenu,
  RunBar,
  TopBar,
  ReadinessBar,
  OutputList,
  type OutputArtifact,
  JwtArtifact,
  NetworkArtifact,
  SessionStrip,
  TypeCard,
  CellTypeErrors,
  CryptoProfileControl,
  GpgKeyBinder,
  ConnectionsPanel,
  ShareCards,
  ShareCheck,
  IntegrityPanel,
  DkgPanel,
  CeremonySheet,
  ApprovalBanner,
  ConsequenceBanner,
} from "../toolkit/widgets/index";
import { execVssCommitments, execVssSplit } from "../lib/toolkit/vss-ops.js";
import { qrSvg } from "../lib/qr.js";
import { encodeShareSet } from "../lib/slip39/blip39.js";
import type { DeploymentVerdict } from "../lib/toolkit/deployment-check.js";
import type { DkgParticipant } from "../lib/quorum/dkg-session.js";
import { getTypeMeta } from "../lib/toolkit/type-registry.js";
import { artifactMetaFromType } from "../lib/toolkit/types.js";
import { protectionDowngradeMessage } from "../lib/vault.js";
import type { CeremonyStageId } from "../lib/toolkit/ceremony.js";
import { Button } from "@/components/ui/button";
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
  const [mode, setMode] = useState("pipeline");
  const [gapActive, setGapActive] = useState(false);
  const [params, setParams] = useState<Record<string, unknown>>({
    alg: "ec/p256",
    usage: "auto",
  });
  const [chipSel, setChipSel] = useState(false);
  const [shelfCaretFilter, setShelfCaretFilter] = useState("");
  const [topbarTitle, setTopbarTitle] = useState("Onboard Dana & Sam");
  // A real commitments document, so the card's split id is one that could
  // actually be compared against something rather than a plausible-looking
  // string. The mnemonics beside it stay fake — a card fixture is not the
  // place to exercise verification, and `#sharecheck` is.
  const cardSplit = useDemoSplit();

  // §19a caret-focused fixture: tipFit for a bytes tip, so real ops dim/fit.
  const bytesTipFit = useMemo(
    () => tipFitFor({ base: "bytes" }).tipFit as Set<string>,
    []
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
              "fileops",
              "toolcard",
              "opstile",
              "opsshelf",
              "chips",
              "insertgap",
              "runbar",
              "sessionstrip",
              "topbar",
              "readinessbar",
              "outputlist",
              "artifacttiles",
              "keyartifacts",
              "gatebanners",
              "networkartifact",
              "jwtartifact",
              "typecard",
              "connections",
              "gpgkeybinder",
              "cryptoprofile",
              "celltypeerrors",
              "recipechipflow",
              "paramfield",
              "modetoggle",
              "menupopover",
              "presetmenu",
              "sharecards",
              "ceremonysheet",
              "sharecheck",
              "integrity",
              "dkg",
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
          <StateLabel>
            WebRTC handle kinds (§25a) — shape-coded so a live socket handle never
            reads as an ordinary data value; connState is hollow (observe-only)
          </StateLabel>
          <div className="flex flex-wrap items-end gap-6">
            {[
              { output: "candidate", label: "candidate" },
              { output: "endpoint", label: "endpoint" },
              { output: "session", label: "session" },
              { output: "sdp", label: "sdp" },
              { output: "channel", label: "channel" },
              { output: "connstate", label: "connstate" },
              { output: "stats", label: "stats" },
              { output: "text", label: "text (data)" },
            ].map((k) => (
              <div key={k.label} className="flex flex-col items-center gap-2">
                <span className="flex h-4 items-center">
                  <ToolboxDot op={{ toolbox: "webrtc", output: k.output }} />
                </span>
                <code className="text-[0.65rem]">{k.label}</code>
              </div>
            ))}
          </div>
        </Section>

        <Section
          id="fileops"
          title="Files — file.read / file.save, stream.*, age.*"
        >
          <StateLabel>
            New glyphs. Documents for disk, chunk row for STREAM, key and padlock
            for age — the age toolbox is a padlocked page rather than OpenPGP’s
            envelope, because age encrypts files and PGP encrypts messages
          </StateLabel>
          <div className="flex flex-wrap items-end gap-6">
            {[
              { id: "file-read", label: "file.read" },
              { id: "file-save", label: "file.save" },
              { id: "stream", label: "stream.seal/open" },
              { id: "age", label: "age (toolbox)" },
              { id: "age-key", label: "age.keygen" },
              { id: "age-lock", label: "age.encrypt" },
              { id: "file", label: "files (shelf)" },
            ].map((g) => (
              <div key={g.id} className="flex flex-col items-center gap-1">
                <Glyph id={g.id} size={22} svgClassName="ops-glyph ops-glyph-tile" />
                <code className="text-[0.65rem]">{g.label}</code>
              </div>
            ))}
          </div>

          <StateLabel>
            Toolbox dots — age is its own toolbox (peer of OpenPGP), so it needs
            its own colour in toolkit.css; toolbox-dot-css.test.js guards the
            duplication
          </StateLabel>
          <div className="flex flex-wrap items-end gap-6">
            {["age", "openpgp", "webcrypto", "io"].map((tb) => (
              <div key={tb} className="flex flex-col items-center gap-2">
                <span className="flex h-4 items-center">
                  <ToolboxDot op={{ toolbox: tb, output: "bytes" }} />
                </span>
                <code className="text-[0.65rem]">{tb}</code>
              </div>
            ))}
          </div>

          <StateLabel>
            ToolCards — the docs surface these ops actually ship with, including
            the CLI equivalences and the “this is not age” warning on stream.*
          </StateLabel>
          <div className="grid gap-4 md:grid-cols-2">
            {["file.read", "file.save", "stream.seal", "age.encrypt"].map((n) => {
              const op = ops.find((o) => o.name === n);
              return op ? <ToolCard key={n} op={op} className="max-w-sm" /> : null;
            })}
          </div>

          <StateLabel>
            file.save confirmation — toast weight, matching clipboard.write. The
            user just drove a save dialog; a modal would restate what they did.
            file.read has no counterpart: the picker is both permission and receipt
          </StateLabel>
          <p
            className="border-b border-[var(--border)] px-3.5 py-1 text-[length:11px] text-[var(--muted-foreground)]"
            data-file-saved
          >
            Saved report.pdf.age · 41,984 bytes
          </p>
          <p
            className="border-b border-[var(--border)] px-3.5 py-1 text-[length:11px] text-[var(--muted-foreground)]"
            data-clipboard-wrote
          >
            Copied to clipboard · 128 chars
          </p>
        </Section>

        <Section id="toolcard" title="ToolCard — docs-only (§19f)">
          <div className="grid gap-4 md:grid-cols-3">
            <div>
              <StateLabel>Default</StateLabel>
              {sample ? <ToolCard op={sample} className="max-w-sm" /> : null}
            </div>
            <div>
              <StateLabel>Compact — hover popover over chips / shelf rows</StateLabel>
              {sample ? (
                <ToolCard op={sample} compact className="max-w-sm" />
              ) : null}
            </div>
            <div>
              <StateLabel>Pinned docs panel — brand border, ✕ to close</StateLabel>
              {sample ? (
                <ToolCard op={sample} compact pinned onClose={() => {}} className="max-w-sm" />
              ) : null}
            </div>
          </div>
        </Section>

        <Section id="opstile" title="OpsTile — merged encode/decode row (§19b)">
          <div className="grid max-w-md grid-cols-1 gap-2">
            {base64 ? (
              <>
                <div>
                  <StateLabel>Default — browse, no caret (plain handles)</StateLabel>
                  <OpsTile
                    op={base64}
                    hasReverse
                    fit={{ forward: false, reverse: false }}
                    onAppend={() => {}}
                    showTooltip={false}
                  />
                </div>
                <div>
                  <StateLabel>Caret fit — forward handle brightened</StateLabel>
                  <OpsTile
                    op={base64}
                    hasReverse
                    fit={{ forward: true, reverse: false }}
                    onAppend={() => {}}
                    showTooltip={false}
                  />
                </div>
                <div>
                  <StateLabel>Decode-only op — no forward direction</StateLabel>
                  <OpsTile
                    op={base64}
                    hasForward={false}
                    hasReverse
                    fit={{ forward: false, reverse: true }}
                    onAppend={() => {}}
                    showTooltip={false}
                  />
                </div>
                <div>
                  <StateLabel>Dim — doesn't fit the caret (opacity .32)</StateLabel>
                  <OpsTile
                    op={base64}
                    hasReverse
                    dim
                    fit={{ forward: false, reverse: false }}
                    onAppend={() => {}}
                    showTooltip={false}
                  />
                </div>
              </>
            ) : null}
          </div>
        </Section>

        <Section id="opsshelf" title="OpsShelf — 3 states (§19a) + kit search suggestion (§21c)">
          <div className="grid gap-4 md:grid-cols-2">
            <div>
              <StateLabel>Browse — no caret focus</StateLabel>
              <div className="h-[560px] w-[252px] overflow-hidden rounded-[10px] border border-[var(--border)] bg-[var(--surface)]">
                <OpsShelf
                  ops={ops}
                  filter={filter}
                  onFilter={setFilter}
                  onAppend={() => {}}
                  bare
                />
              </div>
            </div>
            <div>
              <StateLabel>
                Caret focused — tipFit(bytes) dims the rest, zero-fit sections
                collapse to “0 fit”
              </StateLabel>
              <div className="h-[560px] w-[252px] overflow-hidden rounded-[10px] border border-[var(--border)] bg-[var(--surface)]">
                <OpsShelf
                  ops={ops}
                  filter={shelfCaretFilter}
                  onFilter={setShelfCaretFilter}
                  onAppend={() => {}}
                  tipFit={bytesTipFit}
                  tip={{ base: "bytes" }}
                  caretBanner={
                    <div className="border-b border-l-2 border-[var(--border)] border-l-[var(--caret)] bg-[color-mix(in_srgb,var(--caret)_6%,transparent)] px-2.5 py-2">
                      <div className="text-[length:9.5px] font-bold uppercase tracking-wider text-[var(--caret)]">
                        Caret · after `genkey` in cell [0]
                      </div>
                      <div className="mt-0.5 text-[length:10.5px] text-[var(--muted-foreground)]">
                        Showing{" "}
                        <strong className="text-[var(--foreground)]">
                          {bytesTipFit.size} ops
                        </strong>{" "}
                        that accept <code className="font-mono">bytes</code>.
                      </div>
                    </div>
                  }
                  bare
                />
              </div>
            </div>
            <div>
              <StateLabel>
                Search matches nothing in browse mode but matches a kitOnly op —
                suggestion row instead of a bare empty state
              </StateLabel>
              <div className="h-[300px] w-[252px] overflow-hidden rounded-[10px] border border-[var(--border)] bg-[var(--surface)]">
                <OpsShelf
                  ops={ops}
                  filter="rsa-pkcs1"
                  onFilter={() => {}}
                  onAppend={() => {}}
                  bare
                />
              </div>
            </div>
          </div>
        </Section>

        <Section id="chips" title="SuggestChip">
          <div className="flex flex-wrap items-center gap-2">
            <SuggestChip label="base64.encode" variant="ghost" op={base64} />
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
              variant="placed"
              selected={chipSel}
              op={ops.find((o) => o.name === "export")}
              onClick={() => setChipSel((v) => !v)}
            />
            <SuggestChip label="broken" variant="placed" error />
            <SuggestChip
              label="base64"
              variant="placed"
              op={base64}
              onClick={() => {}}
              onRemove={() => {}}
            />
          </div>
          {/* The §25a mark is presence-bearing: a chip carries one only when
              the step emits something other than ordinary DATA. Every chip
              above is a DATA op and shows none; every chip below shows one,
              which is the whole point of the distinction. */}
          <p className="mt-3 text-[11px] text-[var(--muted-foreground)]">
            Non-DATA outputs — the mark appears only here.
          </p>
          <div className="mt-1 flex flex-wrap items-center gap-2">
            {/* Toolbox is per-entry, not a constant on the chip: `quorum.offer`
                is the quorum toolbox and paints purple, while its neighbours
                are WebRTC and paint blue. It was hardcoded `webrtc` for all
                four, which drew the mesh op in the wrong identity colour the
                moment quorum became its own category — and `rtc.open` had not
                existed for several turns. */}
            {[
              { name: "rtc.gather", output: "candidate", toolbox: "webrtc" },
              { name: "quorum.offer", output: "session", toolbox: "quorum" },
              { name: "peer.wait", output: "channel", toolbox: "webrtc" },
              { name: "rtc.state", output: "connstate", toolbox: "webrtc" },
            ].map((o) => (
              <SuggestChip
                key={o.name}
                label={o.name}
                hint={o.output}
                variant="placed"
                op={{ toolbox: o.toolbox, name: o.name, output: o.output }}
              />
            ))}
          </div>
        </Section>

        <Section id="insertgap" title="The caret — InsertGap states (§19d)">
          <div className="flex flex-col gap-3">
            <div>
              <StateLabel>Idle gap — between two placed chips (hover the + to brighten)</StateLabel>
              <div className="flex items-center gap-0.5">
                <SuggestChip label="genkey" variant="placed" op={sample} />
                <InsertGap label="Insert step here" onClick={() => {}} />
                <SuggestChip label="out" variant="placed" />
              </div>
            </div>
            <div>
              <StateLabel>Active — clicked; toolbox targets this position (HERE)</StateLabel>
              <div className="flex items-center gap-0.5">
                <SuggestChip label="genkey" variant="placed" op={sample} />
                <InsertGap label="Insert step here" pending onClick={() => {}} />
                <SuggestChip label="out" variant="placed" />
              </div>
            </div>
            <div>
              <StateLabel>Drop target — dragging an op tile over this gap</StateLabel>
              <div className="flex items-center gap-0.5">
                <SuggestChip label="genkey" variant="placed" op={sample} className="opacity-60" />
                <InsertGap label="Drop here" active onClick={() => setGapActive((v) => !v)} />
                <SuggestChip label="out" variant="placed" className="opacity-60" />
              </div>
            </div>
            <div>
              <StateLabel>End-of-pipeline caret — append is “caret at the end”</StateLabel>
              <div className="flex items-center gap-0.5">
                <SuggestChip label="out" variant="placed" />
                <InsertGap label="Insert at end" onClick={() => {}} />
              </div>
            </div>
          </div>
        </Section>

        <Section id="runbar" title="RunBar — idle / blocked / running (§19g)">
          <div className="flex flex-col gap-3">
            <div>
              <StateLabel>Idle — no blocker on the notebook</StateLabel>
              <div className="overflow-hidden rounded-lg border border-[var(--border)]">
                <RunBar
                  state="idle"
                  focusedCell={2}
                  onRunAll={() => {}}
                  onRunFrom={() => {}}
                >
                  <Button variant="ghost">Copy link</Button>
                  <Button variant="outline">Tray ▸</Button>
                </RunBar>
              </div>
            </div>
            <div>
              <StateLabel>Blocked — inline chip carries the fix, not a tooltip</StateLabel>
              <div className="overflow-hidden rounded-lg border border-[var(--border)]">
                <RunBar
                  state="blocked"
                  blocker="Cell [3] can't run — 2 recipient slots empty"
                  onRunAll={() => {}}
                  onBind={() => {}}
                />
              </div>
            </div>
            <div>
              <StateLabel>Running — Stop replaces Run all, progress 2 of 4</StateLabel>
              <div className="overflow-hidden rounded-lg border border-[var(--border)]">
                <RunBar
                  state="running"
                  progress={{ cell: 2, total: 4 }}
                  onRunAll={() => {}}
                  onStop={() => {}}
                />
              </div>
            </div>
          </div>
        </Section>

        <Section id="sessionstrip" title="SessionStrip + waiting-peer — live p2p exchange (§21a)">
          <div className="flex max-w-md flex-col gap-3">
            <div>
              <StateLabel>Offering — publishing signed invite</StateLabel>
              <SessionStrip state="offering" room="KJ8XW2PQZM4RT9FQ" />
            </div>
            <div>
              <StateLabel>Waiting — run paused at this cell until a peer meshes</StateLabel>
              <SessionStrip
                state="waiting"
                room="KJ8XW2PQZM4RT9FQ"
                invite="quorum KJ8XW2PQZM4RT9FQ · 2 keys · localhost"
                onCopyInvite={() => {}}
                onCancel={() => {}}
              />
            </div>
            <div>
              <StateLabel>Connected — verified peers meshed</StateLabel>
              <SessionStrip state="connected" room="KJ8XW2PQZM4RT9FQ" connected={2} />
            </div>
            <div>
              <StateLabel>Closed — keys zeroized</StateLabel>
              <SessionStrip state="closed" room="KJ8XW2PQZM4RT9FQ" />
            </div>
            <div>
              <StateLabel>
                Mesh — per-peer rows; the summary alone could not say one link is
                down and one peer unverified
              </StateLabel>
              <SessionStrip
                state="connected"
                room="KJ8XW2PQZM4RT9FQ"
                connected={2}
                peers={[
                  { id: "AAAA1111…9999", fingerprint: "A".repeat(40), state: "connected", authenticated: true, via: "srflx" },
                  { id: "BBBB2222…8888", fingerprint: "B".repeat(40), state: "connected", authenticated: false, via: "relay" },
                  { id: "CCCC3333…7777", fingerprint: "C".repeat(40), state: "failed", authenticated: true },
                ]}
                onRestartIce={() => {}}
              />
            </div>
            <div>
              <StateLabel>Mesh, still forming — a peer mid-handshake</StateLabel>
              <SessionStrip
                state="waiting"
                room="KJ8XW2PQZM4RT9FQ"
                invite="quorum KJ8XW2PQZM4RT9FQ · 3 keys · localhost"
                peers={[
                  { id: "AAAA1111…9999", state: "connected", authenticated: true },
                  { id: "BBBB2222…8888", state: "connecting" },
                  { id: "CCCC3333…7777", state: "new" },
                ]}
                onCopyInvite={() => {}}
                onCancel={() => {}}
              />
            </div>
          </div>
          <div>
            <StateLabel>RunBar · waiting-peer — Stop stays, Copy invite / Cancel appear</StateLabel>
            <div className="overflow-hidden rounded-lg border border-[var(--border)]">
              <RunBar
                state="waiting-peer"
                waitingCell={1}
                sessionInvite="quorum KJ8XW2PQZM4RT9FQ · 2 keys · localhost"
                onCopyInvite={() => {}}
                onCancelSession={() => {}}
                onRunAll={() => {}}
                onStop={() => {}}
              />
            </div>
          </div>
        </Section>

        <Section id="topbar" title="TopBar — identity bar + consolidated suite pill (§20d/21e)">
          <StateLabel>Idle — click the title to rename (Enter saves · Esc cancels) · all suites ok</StateLabel>
          <div className="overflow-hidden rounded-lg border border-[var(--border)]">
            <TopBar
              title={topbarTitle}
              onRename={setTopbarTitle}
              subtitle="3 cells"
              suiteStatus={{ label: "4 suites ready", tone: "ok" }}
              suiteDetail={[
                { name: "WebCrypto", tone: "ok", note: "verified" },
                { name: "OpenPGP", tone: "ok", note: "verified" },
                { name: "Secret sharing", tone: "ok", note: "verified" },
                { name: "WebAuthn", tone: "ok", note: "browser" },
              ]}
            >
              <Button variant="outline">Templates</Button>
              <Button variant="outline" className="px-2">
                ⋯
              </Button>
            </TopBar>
          </div>
          <StateLabel>Pill worst-tone-wins — click opens the per-suite popover</StateLabel>
          <div className="overflow-hidden rounded-lg border border-[var(--border)]">
            <TopBar
              title="Onboard Dana & Sam"
              onRename={() => {}}
              subtitle="3 cells"
              suiteStatus={{ label: "3 suites ready · 1 issue", tone: "warn" }}
              suiteDetail={[
                { name: "OpenPGP", tone: "ok", note: "verified" },
                { name: "WebCrypto", tone: "ok", note: "verified" },
                { name: "Secret sharing", tone: "ok", note: "verified" },
                { name: "Quorum", tone: "warn", note: "no STUN" },
              ]}
            >
              <Button variant="outline">Templates</Button>
              <Button variant="outline" className="px-2">
                ⋯
              </Button>
            </TopBar>
          </div>
        </Section>

        <Section id="readinessbar" title="ReadinessBar — “one thing left” triage (§20e)">
          <div className="flex max-w-md flex-col gap-3">
            <div>
              <StateLabel>Single blocker</StateLabel>
              <ReadinessBar
                blockers={[
                  {
                    id: "needs recipients",
                    label: "recipients aren't bound",
                    action: "Bind",
                    onAction: () => {},
                  },
                ]}
              />
            </div>
            <div>
              <StateLabel>Multiple blockers — highest priority named, rest counted</StateLabel>
              <ReadinessBar
                blockers={[
                  {
                    id: "needs recipients",
                    label: "recipients aren't bound",
                    action: "Bind",
                    onAction: () => {},
                  },
                  { id: "b", label: "message text isn't set", action: "Add text", onAction: () => {} },
                  { id: "c", label: "upstream cell hasn't run", action: "Run", onAction: () => {} },
                ]}
              />
            </div>
            <div>
              <StateLabel>Clean run — hidden entirely, not a green checkmark row</StateLabel>
              <ReadinessBar blockers={[]} />
              <div className="h-px bg-[var(--surface-raised)]" />
            </div>
          </div>
        </Section>

        <Section id="networkartifact" title="NetworkArtifact — manager widgets per pipeline type (§23a/23b/26a/26b/29d/30d)">
          <p className="-mt-1 mb-1 text-[11px] text-[var(--muted-foreground)]">
            The value&rsquo;s <em>type</em> picks the renderer — that&rsquo;s the payoff of these
            being real pipeline types rather than JSON text. Each also opens in its own
            window from an artifact row&rsquo;s <strong>Expand</strong> action.
          </p>
          <div className="grid gap-4 md:grid-cols-2">
            <div>
              <StateLabel>candidate — typed ICE rows (26a: all four types, dim when absent)</StateLabel>
              <NetworkArtifact
                netType="candidate"
                data={{
                  candidates: [
                    { type: "host", address: "192.168.1.14", port: 54321, protocol: "udp" },
                    { type: "srflx", address: "203.0.113.9", port: 60122, protocol: "udp", relatedAddress: "0.0.0.0" },
                    { type: "relay", address: "198.51.100.4", port: 3478, protocol: "tcp" },
                  ],
                  byType: { host: 1, prflx: 0, srflx: 1, relay: 1 },
                  ms: 128,
                }}
              />
            </div>
            <div>
              <StateLabel>stats/candidate-pairs — matrix, nominated highlighted, skipped dimmed</StateLabel>
              <NetworkArtifact
                netType="stats"
                netKind="candidate-pairs"
                data={{
                  peers: [
                    {
                      peer: "AABBCCDDEEFF0011",
                      role: "controlling",
                      pairs: [
                        { local: { label: "srflx:60122" }, remote: { label: "srflx:51004" }, state: "succeeded", nominated: true, rttMs: 38 },
                        { local: { label: "host:54321" }, remote: { label: "host:53211" }, state: "failed", nominated: false },
                        { local: { label: "host:54321" }, remote: { label: "srflx:51004" }, state: "waiting", nominated: false },
                      ],
                    },
                  ],
                }}
              />
            </div>
            <div>
              <StateLabel>stats/candidate-pairs — all failed, TURN is the fallback CTA (§23b)</StateLabel>
              <NetworkArtifact
                netType="stats"
                netKind="candidate-pairs"
                onConfigureTurn={() => {}}
                data={{
                  allFailed: true,
                  peers: [
                    {
                      peer: "AABBCCDDEEFF0011",
                      role: "",
                      pairs: [
                        { local: { label: "host:54321" }, remote: { label: "host:53211" }, state: "failed" },
                      ],
                    },
                  ],
                }}
              />
            </div>
            <div>
              <StateLabel>connstate — state-machine strip (§30d)</StateLabel>
              <NetworkArtifact
                netType="connstate"
                data={{
                  peers: [
                    { peer: "AABBCCDDEEFF0011", connectionState: "connected", iceConnectionState: "connected", signalingState: "stable", channelState: "open", verified: true },
                    { peer: "1122334455667788", connectionState: "connecting", iceConnectionState: "checking", signalingState: "have-local-offer", channelState: "connecting" },
                  ],
                }}
              />
            </div>
            {/**
             * The states this panel exists for, and the ones the catalog never
             * showed.
             *
             * `failed` is a real `RTCPeerConnection.connectionState` and was
             * absent from the old five-stage track, so `indexOf` returned -1,
             * nothing was lit and nothing was bolded — a failed connection drew
             * pixel-identical to one that had never started, and no fixture
             * here would have caught it because none of them had failed. That
             * is the whole argument for this row: a catalog that shows the
             * happy path by accident shows nothing on purpose.
             *
             * `connected` with a channel that is not open is the SCTP phase —
             * the one state where "Connected" and "nothing works" are both
             * true, and where telling someone to add TURN is the wrong advice.
             */}
            <div>
              <StateLabel>connstate — failed, disconnected, closed (the reason the panel exists)</StateLabel>
              <NetworkArtifact
                netType="connstate"
                data={{
                  peers: [
                    { peer: "AABBCCDDEEFF0011", connectionState: "failed", iceConnectionState: "failed", signalingState: "stable", channelState: "closed" },
                    { peer: "1122334455667788", connectionState: "disconnected", iceConnectionState: "disconnected", signalingState: "stable", channelState: "open" },
                    { peer: "99AABBCCDDEEFF00", connectionState: "closed", iceConnectionState: "closed", signalingState: "closed", channelState: "closed" },
                  ],
                }}
              />
            </div>
            <div>
              <StateLabel>connstate — connected, channel not open (the SCTP phase)</StateLabel>
              <NetworkArtifact
                netType="connstate"
                data={{
                  peers: [
                    { peer: "AABBCCDDEEFF0011", connectionState: "connected", iceConnectionState: "connected", signalingState: "stable", channelState: "connecting", verified: true },
                  ],
                }}
              />
            </div>
            <div>
              <StateLabel>stats/data-channel — back-pressure bar (§30d)</StateLabel>
              <NetworkArtifact
                netType="stats"
                netKind="data-channel"
                data={{
                  peers: [
                    { peer: "AABBCCDDEEFF0011", readyState: "open", bufferedAmount: 655360, bufferedAmountLowThreshold: 65535, ordered: true, messagesSent: 42, messagesReceived: 17, bytesSent: 719872, bytesReceived: 4148, backPressured: true },
                    { peer: "1122334455667788", readyState: "open", bufferedAmount: 0, bufferedAmountLowThreshold: 65535, ordered: false, messagesSent: 3, messagesReceived: 3, bytesSent: 33, bytesReceived: 33 },
                  ],
                }}
              />
            </div>
            <div>
              <StateLabel>stats/quality — live RTT / throughput, loss unmeasurable (§29d)</StateLabel>
              {/**
               * `packetLossPct: null` is what `rtc.quality` emits, always.
               * Loss statistics come from RTP and this transport is SCTP data
               * channels, so there is nothing to lose packets from — the row
               * says "loss not measured" rather than the `0.2` this fixture
               * used to claim, which was a number the op could never produce.
               */}
              <NetworkArtifact
                netType="stats"
                netKind="quality"
                data={{
                  peers: [{ peer: "AABBCCDDEEFF0011", rttMs: 38, packetLossPct: null, bytesSent: 4300, bytesReceived: 12800, packetsSent: 214, packetsReceived: 190 }],
                  notes: ["packet loss is not measured: this transport is SCTP data channels, so no RTP statistics exist to lose packets from"],
                }}
              />
            </div>
            <div>
              <StateLabel>endpoint — rtc.ice server list (TURN credential stays bound)</StateLabel>
              <NetworkArtifact
                netType="endpoint"
                data={{ iceServers: [
                  { urls: "stun:stun.cloudflare.com:3478" },
                  { urls: "turn:relay.example.org:3478", username: "dana" },
                ] }}
              />
            </div>
            <div>
              <StateLabel>endpoint — stun.check reached a server</StateLabel>
              <NetworkArtifact
                netType="endpoint"
                data={{
                  ok: true,
                  publicAddress: "203.0.113.9:60122",
                  ms: 127,
                  candidates: { host: 1, srflx: 1 },
                }}
              />
            </div>
            {/**
             * The verdict this op exists to deliver, and the one the catalog
             * never showed. `host` candidates but no `srflx` is the whole
             * diagnosis — the browser gathered fine and the STUN round trip
             * never completed, which is a blocked UDP path and *not* the same
             * problem as having no TURN. The relay row says it was not probed
             * because `stun.check` builds its connection with no credential
             * and can never attempt an allocation (b6a33a4, measured against a
             * live coturn that was relaying at the time).
             */}
            <div>
              <StateLabel>endpoint — stun.check blocked (host only, no srflx)</StateLabel>
              <NetworkArtifact
                netType="endpoint"
                data={{ ok: false, publicAddress: "", ms: 5002, candidates: { host: 4, srflx: 0 } }}
              />
            </div>
            {/**
             * `sdp` had no fixture at all, which is how it stayed a bare
             * `<pre>` for as long as it did. The blob below is a real
             * `rtc.offer` output, and the panel's job is the sentence under it:
             * both SDP ops close their `RTCPeerConnection` in a `finally`
             * before returning, so the two shipped SDP templates describe a
             * hand-carried exchange that cannot complete.
             */}
            <div className="md:col-span-2">
              <StateLabel>sdp — the blob, and the transport that is already gone (§30d)</StateLabel>
              <NetworkArtifact
                netType="sdp"
                content={[
                  "v=0",
                  "o=- 2102512630839861970 2 IN IP4 127.0.0.1",
                  "s=-",
                  "t=0 0",
                  "a=group:BUNDLE 0",
                  "m=application 60476 UDP/DTLS/SCTP webrtc-datachannel",
                  "c=IN IP4 99.105.33.21",
                  "a=candidate:1734501310 1 udp 2113937151 4a114678.local 60476 typ host generation 0",
                  "a=candidate:908088438 1 udp 1677729535 99.105.33.21 60476 typ srflx raddr 0.0.0.0 rport 0",
                  "a=ice-ufrag:OsG7",
                  "a=ice-pwd:2Q3Gn94UvGaWF3YjbpPJZSMe",
                  "a=ice-options:trickle",
                  "a=fingerprint:sha-256 32:81:EB:EE:4A:8F:0B:63:40:33:F5:DD:55:DD:36:1D:79:94:A0:F6:86:3C:4F:F1:85:7D:22:65:82:84:37:AA",
                  "a=setup:actpass",
                  "a=mid:0",
                  "a=sctp-port:5000",
                  "a=max-message-size:262144",
                  "",
                ].join("\n")}
                data={null}
              />
            </div>
            {/**
             * Two certificates, both dated **relative to now** (§48b/D5).
             *
             * This row was pinned to `2026-08-29T00:00:00.000Z`, which is D3's
             * mistake in the other artifact: an absolute instant written down
             * on the day the fixture was, so the one section that exists to
             * show the expiry verdict would have shown `expired` for the life
             * of the repo from the day it passed. `RTCCertificate.expires`
             * defaults to about thirty days out, so a relative date is also
             * the *truer* fixture — a real one is never a fixed calendar day.
             *
             * Two of them because the verdict has two tones and a catalog that
             * shows one state by accident shows nothing on purpose.
             */}
            <div>
              <StateLabel>certificate — DTLS identity, verdict at warn (§29a/§48b)</StateLabel>
              <NetworkArtifact
                netType="certificate"
                data={{
                  algorithm: "ECDSA/P-256",
                  expires: new Date(Date.now() + 20 * 86_400_000).toISOString(),
                  fingerprints: [{ algorithm: "sha-256", value: "3F:2A:9C:1B:44:D0:81:E6:B8" }],
                  note: "ephemeral unless pinned",
                }}
              />
            </div>
            <div>
              <StateLabel>certificate — inside a week, so the verdict escalates</StateLabel>
              <NetworkArtifact
                netType="certificate"
                data={{
                  algorithm: "ECDSA/P-256",
                  expires: new Date(Date.now() + 3 * 86_400_000).toISOString(),
                  fingerprints: [{ algorithm: "sha-256", value: "7B:11:E4:0A:52:CC:93:6D:2F" }],
                  note: "ephemeral unless pinned",
                }}
              />
            </div>
            <div>
              <StateLabel>session — live exchange handle (§21a)</StateLabel>
              <NetworkArtifact
                netType="session"
                data={{ room: "KJ8XW2PQZM4RT9FQ", role: "creator", connected: 1, audience: ["AABBCCDDEEFF00112233", "445566778899AABBCCDD"] }}
              />
            </div>
            <div>
              <StateLabel>channel — a direct link, and what it does not prove (§56)</StateLabel>
              <NetworkArtifact
                netType="channel"
                data={{ link: "alice-laptop", origin: "peer", label: "basilisk", ordered: true, state: "open", via: "srflx" }}
              />
            </div>
            <div>
              <StateLabel>channel — the same handle from an identity-bound room</StateLabel>
              {/* Side by side on purpose: these two are the same widget saying
                  opposite things about who is on the far end, and the sentence
                  is the only thing that distinguishes them. Both come from
                  `linkOriginNote`, so neither can drift. */}
              <NetworkArtifact
                netType="channel"
                data={{ link: "AABBCCDDEEFF0011", origin: "quorum", label: "quorum", ordered: true, state: "open", via: "relay" }}
              />
            </div>
          </div>
        </Section>

        <Section id="jwtartifact" title="JwtArtifact — JWS / JWE reader (RFC 7515 / 7516 / 7519)">
          <p className="-mt-1 mb-1 text-[11px] text-[var(--muted-foreground)]">
            The states worth reviewing side by side are the two that must never look
            alike: <strong>verified</strong> and <strong>unverified</strong>. A{" "}
            <code className="font-mono">jose.decode</code> result is claims nobody
            checked, and the whole failure mode of a token inspector is teaching people
            to read those as if someone had. Expiry tones are computed live from{" "}
            <code className="font-mono">exp</code>, so a token lapsing in an open tab
            escalates on its own; the fixed <code className="font-mono">nowMs</code>{" "}
            below pins each example to the state it is meant to show.
          </p>
          <div className="grid gap-4 md:grid-cols-2">
            <div>
              <StateLabel>Verified — signature checked, comfortably in date</StateLabel>
              <JwtArtifact
                nowMs={1_700_000_000_000}
                data={{
                  kind: "jws",
                  verified: true,
                  header: { alg: "ES256", typ: "JWT", kid: "2024-05" },
                  claims: {
                    iss: "https://issuer.example",
                    sub: "alice@example.org",
                    aud: "basilisk",
                    iat: 1_699_999_000,
                    exp: 1_700_086_400,
                    scope: "read:keys",
                  },
                }}
              />
            </div>
            <div>
              <StateLabel>
                Unverified — jose.decode; warning banner, and it says so in words
              </StateLabel>
              <JwtArtifact
                nowMs={1_700_000_000_000}
                data={{
                  kind: "jws",
                  verified: false,
                  header: { alg: "HS256", typ: "JWT" },
                  claims: {
                    iss: "https://issuer.example",
                    sub: "alice@example.org",
                    exp: 1_700_086_400,
                  },
                }}
              />
            </div>
            <div>
              <StateLabel>Expiring soon — under five minutes, warn tone</StateLabel>
              <JwtArtifact
                nowMs={1_700_000_000_000}
                data={{
                  kind: "jws",
                  verified: true,
                  header: { alg: "EdDSA", typ: "JWT" },
                  claims: { sub: "alice", iat: 1_699_996_400, exp: 1_700_000_200 },
                }}
              />
            </div>
            <div>
              <StateLabel>Expired — valid signature, dead token; that distinction is the message</StateLabel>
              <JwtArtifact
                nowMs={1_700_000_000_000}
                data={{
                  kind: "jws",
                  verified: true,
                  expiryChecked: false,
                  header: { alg: "RS256", typ: "JWT" },
                  claims: { sub: "alice", iat: 1_699_900_000, exp: 1_699_990_000 },
                }}
              />
            </div>
            <div>
              <StateLabel>Not yet valid — nbf in the future</StateLabel>
              <JwtArtifact
                nowMs={1_700_000_000_000}
                data={{
                  kind: "jws",
                  verified: true,
                  header: { alg: "ES256" },
                  claims: { sub: "alice", nbf: 1_700_003_600, exp: 1_700_090_000 },
                }}
              />
            </div>
            <div>
              <StateLabel>No exp — a token that never lapses on its own</StateLabel>
              <JwtArtifact
                nowMs={1_700_000_000_000}
                data={{
                  kind: "jws",
                  verified: true,
                  signed: true,
                  header: { alg: "HS512", typ: "JWT" },
                  claims: { sub: "service-account", scope: "internal" },
                }}
              />
            </div>
            <div>
              <StateLabel>JWE, still sealed — payload is not readable yet, and says why</StateLabel>
              <JwtArtifact
                nowMs={1_700_000_000_000}
                data={{
                  kind: "jwe",
                  verified: true,
                  header: { alg: "A256KW", enc: "A256GCM", kid: "kek-1" },
                  claims: null,
                }}
              />
            </div>
            <div>
              <StateLabel>JWE, decrypted — AEAD tag is the authentication</StateLabel>
              <JwtArtifact
                nowMs={1_700_000_000_000}
                data={{
                  kind: "jwe",
                  verified: true,
                  decrypted: true,
                  header: { alg: "dir", enc: "A256GCM" },
                  claims: { sub: "alice", exp: 1_700_050_000 },
                }}
              />
            </div>
            <div>
              <StateLabel>
                Non-JSON payload — a JWS that is not a JWT; no claims invented
              </StateLabel>
              <JwtArtifact
                nowMs={1_700_000_000_000}
                data={{
                  kind: "jws",
                  verified: true,
                  header: { alg: "EdDSA" },
                  claims: null,
                  payloadText: "$argon2id$v=19$m=65536,t=3,p=4$…",
                }}
              />
            </div>
          </div>
        </Section>

        <Section id="outputlist" title="OutputList — stacked artifact rows (§20h/21b/22b)">
          <StateLabel>
            Text outputs — one-line preview under the row (sensitive values stay hidden)
          </StateLabel>
          <div className="max-w-md">
            <OutputList
              outputs={[
                {
                  label: "ciphertext",
                  kind: "text",
                  sizeBytes: 892,
                  onCopy: () => {},
                  preview: "-----BEGIN PGP MESSAGE----- hQEMA1... (892 bytes, armored)",
                },
                {
                  label: "master-key",
                  kind: "text",
                  sizeBytes: 32,
                  sensitive: true,
                  onCopy: () => {},
                },
              ]}
            />
          </div>
          <StateLabel>
            Key export — Publish raises the §34c consequence banner inline; the
            already-published row shows @slot + a link icon that copies the directory
            URL, and offers no Publish at all
          </StateLabel>
          <p className="mb-1 max-w-md text-[11px] text-[var(--muted-foreground)]">
            These two rows carried <code>kind: "key"</code> and no <code>role</code>, so
            they resolved to the <em>fallback</em> kind while purporting to demonstrate
            the publish flow — the "a fixture that merely looks like what the engine
            emits" trap, in the section that exists to catch it. They carry{" "}
            <code>role: "public-key"</code> now, which is what makes Publish appear at
            all: the action is declared by the kind, not passed in as a flag.
          </p>
          <div className="max-w-md">
            <OutputList
              outputs={[
                {
                  label: "dana.pub.asc",
                  kind: "key",
                  role: "public-key",
                  tags: ["openpgp", "public-key"],
                  traits: { fingerprint: "3F2AB19C4D7E0518A2B6C93D4E7F0A1B2C3D4E5F" },
                  sizeBytes: 1843,
                  onCopy: () => {},
                  onPublish: async () => ({ fingerprint: "3F2A…C81" }),
                  directoryHost: "keys.example.com",
                },
                {
                  label: "sam.pub.asc",
                  kind: "key",
                  role: "public-key",
                  tags: ["openpgp", "public-key"],
                  traits: { fingerprint: "C81F5AM19C4D7E0518A2B6C93D4E7F0A1B2C3D4E" },
                  sizeBytes: 1798,
                  onCopy: () => {},
                  publishedAs: "@C81FSAM",
                  directoryUrl: "https://example.org/pks/lookup?op=get&search=0xSAM",
                },
              ]}
            />
          </div>
          <StateLabel>
            The same key with no route to the directory — Publish is declared by the
            kind, so it renders, disabled, carrying the reason
          </StateLabel>
          <div className="max-w-md">
            <OutputList
              outputs={[
                {
                  label: "dana.pub.asc",
                  kind: "key",
                  role: "public-key",
                  tags: ["openpgp", "public-key"],
                  traits: { fingerprint: "3F2AB19C4D7E0518A2B6C93D4E7F0A1B2C3D4E5F" },
                  sizeBytes: 1843,
                  onCopy: () => {},
                },
              ]}
            />
          </div>
          <StateLabel>
            stun.check diagnostic — DIAG badge + "Configure TURN" only when the check failed
          </StateLabel>
          <div className="max-w-md">
            <OutputList
              outputs={[
                {
                  label: "nat",
                  kind: "diag",
                  sizeBytes: 240,
                  onCopy: () => {},
                  diagnosticAction: { label: "Configure TURN", onClick: () => {} },
                },
              ]}
            />
          </div>
        </Section>

        <Section id="artifacttiles" title="Artifact tiles — the §37 inventory, resolved by role">
          <p className="-mt-1 mb-1 text-[11px] text-[var(--muted-foreground)]">
            One row per kind in the registry, fed the same <code>role</code> and{" "}
            <code>tags</code> the engine really emits — the armor, the sshsig block and
            the receipt below were captured from <code>runRecipe</code> rather than
            written by hand. This is the section that answers the question a unit test
            cannot: whether the resolver, the view and the action row agree in the built
            page. Each row carries <code>data-artifact-kind</code>; if one reads{" "}
            <code>fallback</code>, its artifact is not carrying the tags its{" "}
            <code>match</code> requires.
          </p>
          <p className="mb-1 text-[11px] text-[var(--muted-foreground)]">
            §37a decided most of what is <em>absent</em> here: a button may move an
            artifact, never compute a new one. So there is no <em>Decrypt with…</em> on
            the ciphertext, no <em>Verify threshold</em> on the share, and no{" "}
            <em>verify</em> on the signature or the receipt — each would produce a value
            or a verdict with no derivation behind it. What those rows show instead is
            the read-out the action was standing in for.
          </p>
          <div className="max-w-md">
            <OutputList outputs={demoArtifactTiles()} />
          </div>
        </Section>

        <Section id="keyartifacts" title="Key artifacts — the whole badge family, side by side (§35)">
          <p className="-mt-1 mb-1 text-[11px] text-[var(--muted-foreground)]">
            Six roles wear a key badge — <code>KEYPAIR</code>, <code>KEY</code>,{" "}
            <code>PUBLIC-KEY</code>, <code>SECRET-KEY</code>, <code>SSH-PUBLIC</code>,{" "}
            <code>SSH-PRIVATE</code> — and each was added against its own brief, months
            of session apart. They had never been rendered in one list. Every row below
            carries the <code>role</code>, <code>tags</code> and <code>traits</code> a
            real <code>runRecipe</code> stamps, printed off the engine first; the armor,
            the JWKs and the openssh block are that run&rsquo;s actual bytes.
          </p>
          <p className="mb-1 text-[11px] text-[var(--muted-foreground)]">
            This is the section that answers &ldquo;do they read as one family&rdquo;.
            It is also where the three ways of saying <em>there is nothing here</em>{" "}
            meet: the keypair&rsquo;s withheld line, the masked line under a private
            half, and a kind&rsquo;s <code>empty</code> sentence.
          </p>
          <div className="max-w-md">
            <OutputList outputs={demoKeyArtifacts()} />
          </div>
        </Section>

        <Section id="gatebanners" title="Gate banners — the approval moment (§27b/§27c)">
          <p className="-mt-1 mb-1 text-[11px] text-[var(--muted-foreground)]">
            The banner that stands between <code>agent</code> and a rubber stamp. It had
            no catalog section until now, which mattered more than it sounds: the shell
            only renders it while a real <code>agent.sign</code> is suspended mid-run, so
            its states were unreachable without driving a key through the vault, and
            "renders identically after the refactor" was a claim nothing could check.
            Every line is data the engine held at the moment of the request.
          </p>
          <div className="max-w-lg space-y-4" data-catalog-approval>
            <div>
              <StateLabel>
                sshsig — one request, no loop, so no batch offer (§27d)
              </StateLabel>
              <ApprovalBanner
                request={{
                  use: "sign",
                  stepName: "agent.sign",
                  stepText: "agent.sign fpr=SHA256:Ur1hPKBrJC3z namespace=git",
                  cellIndex: 2,
                  keyId: "SHA256:Ur1hPKBrJC3zQ8mB7vXsK2dN4pT6wY9aE1cF3gH5iJ0",
                  keyLabel: "justin@basilisk.dev",
                  keyKind: "ssh",
                  keyProtection: "passkey",
                  payloadBytes: 412,
                  payloadSha256: "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b",
                  payloadPreview: "tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n",
                  namespace: "git",
                  requestIndex: 1,
                  runTotal: null,
                }}
                onDecide={() => {}}
              />
            </div>
            <div>
              <StateLabel>
                Inside a foreach — the batch appears only now, after one real payload and
                the loop's true count have been shown
              </StateLabel>
              <ApprovalBanner
                request={{
                  use: "sign",
                  stepName: "agent.sign",
                  stepText: "agent.sign fpr=3F2A…C81 mode=detached",
                  cellIndex: 4,
                  keyId: "3f2ab19c4d7e0518a2b6c93d4e7f0a1b2c3d4e5f",
                  keyLabel: "Dana Reyes <dana@example.org>",
                  keyKind: "pgp",
                  keyProtection: "passphrase",
                  payloadBytes: 1024,
                  payloadSha256: "9f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c",
                  payloadPreview: null,
                  mode: "detached",
                  requestIndex: 1,
                  runTotal: 12,
                }}
                onDecide={() => {}}
              />
            </div>
            <div>
              <StateLabel>
                agent.decrypt — no preview, because previewing ciphertext is noise
              </StateLabel>
              <ApprovalBanner
                request={{
                  use: "decrypt",
                  stepName: "agent.decrypt",
                  stepText: "agent.decrypt fpr=3F2A…C81",
                  cellIndex: 0,
                  keyId: "3f2ab19c4d7e0518a2b6c93d4e7f0a1b2c3d4e5f",
                  keyLabel: "Dana Reyes <dana@example.org>",
                  keyKind: "pgp",
                  keyProtection: "device",
                  payloadBytes: 892,
                  payloadSha256: "c0ffee1234567890abcdef0987654321c0ffee12",
                  payloadPreview: null,
                  requestIndex: 3,
                  runTotal: null,
                }}
                onDecide={() => {}}
              />
            </div>
          </div>
          <p className="mb-1 mt-4 text-[11px] text-[var(--muted-foreground)]">
            The two consequence banners, stacked under the approval ones on purpose
            (§43a). The resemblance is the feature: a user who has learned that a
            warn-bordered panel with a facts table means a decision should not have to
            learn a second visual language for the same sentence. And §43b's point only
            works if the shell is otherwise identical — the eye lands where the session
            checkbox was, and finds nothing there. There is no defensible "don't ask
            again" for publishing.
          </p>
          <div className="max-w-lg space-y-4" data-catalog-consequence>
            <div>
              <StateLabel>
                Publish — every line is data held at the moment of the click. "Where"
                names this site and can never name a keyserver: there is no upstream
                write path
              </StateLabel>
              <ConsequenceBanner
                spec={{
                  title: "Publish this key to the directory",
                  facts: [
                    {
                      term: "Key",
                      detail: "dana.pub.asc",
                      sub: "3F2A B19C 4D7E 0518 A2B6 C93D 4E7F 0A1B 2C3D 4E5F",
                    },
                    {
                      term: "Where",
                      detail: "keys.example.com",
                      sub: "this site's directory — not an upstream keyserver",
                    },
                    {
                      term: "Becomes public",
                      detail:
                        "The key, its user IDs, and every signature on it — readable by anyone with directory access, including the email addresses in its user IDs.",
                    },
                    {
                      term: "Permanent",
                      detail:
                        "A published key cannot be withdrawn. You can publish a revocation later; you cannot make this copy go away.",
                    },
                  ],
                  confirmLabel: "Publish",
                }}
                onConfirm={() => {}}
                onCancel={() => {}}
              />
            </div>
            <div>
              <StateLabel>
                Failed — the thrown message verbatim, and the button stays live. A failed
                publish is retryable; "something went wrong" is worse than the failure
              </StateLabel>
              <ConsequenceBanner
                spec={{
                  title: "Publish this key to the directory",
                  facts: [
                    { term: "Key", detail: "dana.pub.asc", sub: "3F2A B19C 4D7E 0518" },
                    {
                      term: "Where",
                      detail: "keys.example.com",
                      sub: "this site's directory — not an upstream keyserver",
                    },
                  ],
                  confirmLabel: "Publish",
                }}
                error="Request failed (503): the directory is not accepting keys right now."
                onConfirm={() => {}}
                onCancel={() => {}}
              />
            </div>
            <div>
              <StateLabel>
                Local (§34d) — <code>keyring.add</code>, the one confirming local
                mutation. It ships without a Replace: <code>saveKey</code> defaults to{" "}
                <code>onConflict: &quot;refuse&quot;</code>, and a single click is exactly
                what that default exists for, so a key already held behind a passkey gets
                the vault's refusal here rather than an overwrite to agree to
              </StateLabel>
              <ConsequenceBanner
                spec={{
                  title: "Add this key to My Keys",
                  facts: [
                    { term: "Key", detail: "k", sub: "3F2A B19C 4D7E 0518" },
                    {
                      term: "Where",
                      detail: "My Keys, in this browser",
                      sub: "storage on this device — it is not synced anywhere",
                    },
                    {
                      term: "Protection",
                      detail:
                        "Device protection: no passkey, no passphrase. Anyone who can reach this browser profile can use the key without being asked for anything.",
                      sub: "Enrol a passkey from My Keys afterwards, or write agent.save protection=passkey in the recipe.",
                    },
                    {
                      term: "Reversible",
                      detail:
                        "Deleting the key from My Keys removes it. Nothing leaves this device, so this is not the one-way door publishing is.",
                    },
                  ],
                  confirmLabel: "Add to My Keys",
                }}
                error={protectionDowngradeMessage("passkey", "device")}
                onConfirm={() => {}}
                onCancel={() => {}}
              />
            </div>
          </div>
        </Section>

        <Section
          id="connections"
          title="ConnectionsPanel — live sessions, separate from Outputs (§34)"
        >
          <p className="-mt-1 mb-1 text-[11px] text-[var(--muted-foreground)]">
            Outputs holds what a run <em>produced</em>; this holds what is <em>open</em>,
            with the actions that close or repair it. Connectivity and authentication are
            reported separately on purpose — a peer can be fully connected and completely
            unverified, and conflating the two is how you trust the wrong end of a working
            pipe.
          </p>
          <div className="grid gap-4 md:grid-cols-2">
            <div className="rounded-lg border border-[var(--border)]">
              <StateLabel>Idle — names the op that starts one</StateLabel>
              <ConnectionsPanel session={{ phase: "idle" }} />
            </div>
            <div className="rounded-lg border border-[var(--border)]">
              <StateLabel>Waiting — invite published, no peers yet</StateLabel>
              <ConnectionsPanel
                session={{
                  phase: "waiting",
                  room: "KJ8X2M4P9FQ",
                  role: "creator",
                  invite: "basilisk://join/KJ8X…9FQ",
                  connected: 0,
                  expected: 3,
                }}
                onCopyInvite={() => {}}
                onClose={() => {}}
              />
            </div>
            <div className="rounded-lg border border-[var(--border)]">
              <StateLabel>Mesh — mixed verification, one peer still connecting</StateLabel>
              <ConnectionsPanel
                session={{
                  phase: "connected",
                  room: "KJ8X2M4P9FQ",
                  role: "creator",
                  connected: 2,
                  expected: 3,
                  peers: [
                    { id: "dana@example.com", state: "connected", authenticated: true, via: "srflx" },
                    { id: "peer-7c3f", state: "connected", authenticated: false, via: "relay" },
                    { id: "peer-19ab", state: "connecting" },
                  ],
                }}
                onClose={() => {}}
              />
            </div>
            <div className="rounded-lg border border-[var(--border)]">
              <StateLabel>Failed — recovery in place, room preserved</StateLabel>
              <ConnectionsPanel
                session={{
                  phase: "failed",
                  room: "KJ8X2M4P9FQ",
                  connected: 0,
                  expected: 2,
                  peers: [{ id: "dana@example.com", state: "failed", authenticated: true }],
                }}
                onRestartIce={() => {}}
                onClose={() => {}}
              />
            </div>
            <div className="rounded-lg border border-[var(--border)]">
              <StateLabel>Direct connections, no session at all (§58a)</StateLabel>
              {/* The state the panel could not previously render: `peer.offer`
                  made a real connection and no quorum exchange exists, so the
                  old "No live session" empty state would have hidden it. */}
              <ConnectionsPanel
                session={{ phase: "idle" }}
                links={[
                  {
                    id: "alice-laptop",
                    origin: "peer",
                    role: "offerer",
                    connectionState: "connected",
                    channelState: "open",
                    via: "host",
                  },
                  {
                    id: "b",
                    origin: "peer",
                    role: "answerer",
                    connectionState: "connecting",
                    channelState: "connecting",
                  },
                ]}
                onCloseLink={() => {}}
                onRestartLink={() => {}}
              />
            </div>
            <div className="rounded-lg border border-[var(--border)]">
              <StateLabel>A direct link that failed — verdict, and the one control that helps</StateLabel>
              {/* Restart appears only here. On `new`/`connecting` ICE has not
                  given up, so the button would have nothing to do — absent
                  rather than dimmed, which is also how it keeps its reason out
                  of a disabled attribute nobody can reach. */}
              <ConnectionsPanel
                session={{ phase: "idle" }}
                links={[
                  {
                    id: "alice-laptop",
                    origin: "peer",
                    role: "offerer",
                    connectionState: "failed",
                    channelState: "closed",
                  },
                  {
                    id: "flaky",
                    origin: "peer",
                    role: "answerer",
                    connectionState: "disconnected",
                    channelState: "open",
                    via: "relay",
                  },
                ]}
                onCloseLink={() => {}}
                onRestartLink={() => {}}
              />
            </div>
            <div className="rounded-lg border border-[var(--border)]">
              <StateLabel>Both at once — a mesh above, a hand-carried link below</StateLabel>
              <ConnectionsPanel
                session={{
                  phase: "connected",
                  room: "KJ8X2M4P9FQ",
                  role: "creator",
                  connected: 1,
                  expected: 1,
                  peers: [
                    { id: "dana@example.com", state: "connected", authenticated: true, via: "srflx" },
                  ],
                }}
                links={[
                  // The mesh's own link is in the same inventory and must not be
                  // drawn twice — it is the roster row above.
                  {
                    id: "AABBCCDDEEFF0011",
                    origin: "quorum",
                    role: "offerer",
                    connectionState: "connected",
                    channelState: "open",
                    authenticated: true,
                  },
                  {
                    id: "alice-laptop",
                    origin: "peer",
                    role: "offerer",
                    connectionState: "connected",
                    channelState: "open",
                    via: "host",
                  },
                ]}
                onClose={() => {}}
                onCloseLink={() => {}}
                onRestartLink={() => {}}
              />
            </div>
            <div className="rounded-lg border border-[var(--border)]">
              <StateLabel>Over the mesh soft cap — the honest degradation warning</StateLabel>
              <ConnectionsPanel
                session={{
                  phase: "waiting",
                  room: "KJ8X2M4P9FQ",
                  role: "creator",
                  connected: 3,
                  expected: 11,
                }}
                onClose={() => {}}
              />
            </div>
          </div>
        </Section>

        <Section
          id="gpgkeybinder"
          title="GpgKeyBinder — a key you hold, not one you're encrypting to (§39b)"
        >
          <p className="-mt-1 mb-1 text-[11px] text-[var(--muted-foreground)]">
            Easy to conflate with recipient binding, and the directions are opposite:
            recipients are public keys you encrypt <em>to</em>; this picks a key you can
            act <em>as</em>, for <code className="font-mono">gpg.sign</code> or{" "}
            <code className="font-mono">gpg.decrypt</code>. It reads the same vault the
            Keys tray renders, so there is no second list to fall out of sync.
          </p>
          <div className="grid gap-4 md:grid-cols-2">
            <div>
              <StateLabel>Selection + expiry escalation (quiet &gt; 30d)</StateLabel>
              <GpgKeyBinder
                label="Sign with"
                value="9F2A1C4E8B6D3057AA11BB22CC33DD44EE55FF66"
                onChange={() => {}}
                keys={[
                  {
                    fingerprint: "9F2A1C4E8B6D3057AA11BB22CC33DD44EE55FF66",
                    uid: "Dana Okonkwo <dana@example.com>",
                    expires: null,
                  },
                  {
                    fingerprint: "1122334455667788AABBCCDDEEFF00112233445566",
                    uid: "old-work-key <ops@example.com>",
                    expires: Date.now() + 4 * 86_400_000,
                  },
                  {
                    fingerprint: "AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555",
                    uid: "rotating <rot@example.com>",
                    expires: Date.now() + 20 * 86_400_000,
                  },
                ]}
              />
            </div>
            <div>
              <StateLabel>Empty vault — says what to do, not &ldquo;no keys&rdquo;</StateLabel>
              <GpgKeyBinder label="Decrypt with" keys={[]} onChange={() => {}} />
            </div>
          </div>
        </Section>

        <Section
          id="cryptoprofile"
          title="CryptoProfileControl — Custom mode as a 2×2 grid (§36c)"
        >
          <p className="-mt-1 mb-1 text-[11px] text-[var(--muted-foreground)]">
            Paired by what each choice governs: Cipher/AEAD decide how the message is kept
            secret, S2K/Compression how the passphrase is stretched and the body packed.
            Stacked full-width, the four pickers pushed the divergence warning and the
            flags footer below the fold.
          </p>
          <div className="max-w-md">
            <StateLabel>Custom — all four pickers, flags footer</StateLabel>
            <CryptoProfileControl
              value={{
                profile: "custom",
                cipher: "aes256",
                aead: "gcm",
                s2k: "argon2",
                compression: "off",
              }}
              onChange={() => {}}
              sessionProfile="modern"
            />
          </div>
          <div className="max-w-md">
            <StateLabel>
              Custom that exactly matches Modern — divergence warning spans both columns
            </StateLabel>
            <CryptoProfileControl
              value={{
                profile: "custom",
                cipher: "aes256",
                aead: "ocb",
                s2k: "argon2",
                compression: "off",
              }}
              onChange={() => {}}
              sessionProfile="modern"
            />
          </div>
        </Section>

        <Section
          id="celltypeerrors"
          title="CellTypeErrors — why this cell produced nothing, in this cell (§33c)"
        >
          <p className="-mt-1 mb-1 text-[11px] text-[var(--muted-foreground)]">
            Sits under the chip row, where RunBar&rsquo;s blocked state already lives — a
            banner rather than a tooltip, because a message you must hover to find is not
            one you read before pressing Run. The fix hint only appears when the registry
            knows an op that actually produces the wanted type. Runtime throws land here
            too, at the same weight: a run that died is never less consequential than one
            that was refused. The <code>at run</code> tag carries the difference, because
            a prediction and a report have different next actions.
          </p>
          <div className="max-w-2xl">
            <StateLabel>
              Named step + a real producer for the expected type (offers a fix)
            </StateLabel>
            <CellTypeErrors
              steps={[{ name: "genkey" }, { name: "digest" }]}
              errors={[
                {
                  message:
                    '"digest" expects DER bytes — add export pkcs8, export scalar, or spki first.',
                  stepIndex: 1,
                },
              ]}
              onFocusStep={() => {}}
            />
          </div>
          <div className="max-w-2xl">
            <StateLabel>
              Message names no parseable type — silent rather than a guessed fix
            </StateLabel>
            <CellTypeErrors
              steps={[{ name: "sss.combine" }]}
              errors={[
                { message: "shares/raw needs blip39 -d before sss.combine.", stepIndex: 0 },
              ]}
            />
          </div>
          <div className="max-w-2xl">
            <StateLabel>Validator gave no stepIndex — banner without a chip anchor</StateLabel>
            <CellTypeErrors
              steps={[]}
              errors={[{ message: "Nested foreach is not allowed.", stepIndex: -1 }]}
            />
          </div>
          <div className="max-w-2xl">
            <StateLabel>
              The run died here — same weight, tagged, anchored to the op that threw
            </StateLabel>
            <CellTypeErrors
              steps={[{ name: "rtc.state" }, { name: "out" }]}
              errors={[
                {
                  message:
                    "rtc.state: no live connection — open one with peer.offer / peer.answer, or a mesh with quorum.offer / quorum.join",
                  stepIndex: 0,
                  when: "run",
                },
              ]}
              onFocusStep={() => {}}
            />
          </div>
        </Section>

        <Section
          id="typecard"
          title="TypeCard — types as browsable, sometimes constructible, documentation"
        >
          <p className="-mt-1 mb-1 text-[11px] text-[var(--muted-foreground)]">
            The type-system counterpart to ToolCard. Producers and consumers are{" "}
            <em>derived</em> from the registry, so a card can never advertise an op that
            no longer exists. Four types can be written down directly; the rest can only
            be produced, so they show the ops that produce them instead of an editor that
            could not work.
          </p>
          <div className="grid gap-4 md:grid-cols-2">
            <div>
              <StateLabel>
                int — constructible; the constructor accepts 0x / 0b / 0o and shows the value
              </StateLabel>
              <TypeCard meta={getTypeMeta("int")} onInsertLiteral={() => {}} />
            </div>
            <div>
              <StateLabel>bytes — the most consumed type (26 ops), literal + reference</StateLabel>
              <TypeCard meta={getTypeMeta("bytes")} onInsertLiteral={() => {}} />
            </div>
            <div>
              <StateLabel>
                keypair — two origins (§31c): Generate inserts genkey itself, Import
                inserts the run-time paste step
              </StateLabel>
              <TypeCard meta={getTypeMeta("keypair")} onPickOp={() => {}} />
            </div>
            <div>
              <StateLabel>
                stats — observe-only; nothing consumes it, and the card says so
              </StateLabel>
              <TypeCard meta={getTypeMeta("stats")} />
            </div>
            <div>
              <StateLabel>host — declared in the union but unused: “reserved”</StateLabel>
              <TypeCard meta={getTypeMeta("host")} />
            </div>
            <div>
              <StateLabel>text — compact (summary only, no constructor)</StateLabel>
              <TypeCard meta={getTypeMeta("text")} compact />
            </div>
          </div>
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
            onSelect={() => {}}
            onGap={() => setGapActive(true)}
            onBranchHit={() => {}}
            onNestToggle={() => {}}
            onNestAppend={() => {}}
            onReorder={() => {}}
          />
          <StateLabel>
            Fresh tee — ghost selectors from the projector table, no continue gap yet,
            peek offered while empty (turns 46/47)
          </StateLabel>
          <RecipeChipFlow
            cell={1}
            stems={[
              {
                step: { name: "genkey", label: sample?.label || "genkey", op: sample },
                hasNest: false,
              },
              {
                step: { name: "tee", label: "tee" },
                hasNest: true,
                nestKind: "tee",
                nestAdd: [":public", ":private"],
              },
            ]}
            selected={null}
            onSelect={() => {}}
            onGap={() => {}}
            onBranchHit={() => {}}
            onArmBranch={() => {}}
            onPeekInstead={() => {}}
            onReorder={() => {}}
          />
          <StateLabel>
            A landed :public branch — × on the selector deletes the whole branch
          </StateLabel>
          <RecipeChipFlow
            cell={1}
            stems={[
              {
                step: { name: "genkey", label: sample?.label || "genkey", op: sample },
                hasNest: false,
              },
              {
                step: { name: "tee", label: "tee" },
                hasNest: true,
                nestKind: "tee",
                nestAdd: [":private"],
                branches: [
                  {
                    selector: ":public",
                    steps: [
                      {
                        name: "base64",
                        label: base64?.label || "base64",
                        op: base64,
                      },
                    ],
                  },
                ],
              },
            ]}
            selected={null}
            onSelect={() => {}}
            onGap={() => {}}
            onBranchHit={() => {}}
            onArmBranch={() => {}}
            onRemoveBranch={() => {}}
            onReorder={() => {}}
          />
          <StateLabel>Armed :public branch — lands with its first step (turn 47)</StateLabel>
          <RecipeChipFlow
            cell={2}
            stems={[
              {
                step: { name: "genkey", label: sample?.label || "genkey", op: sample },
                hasNest: false,
              },
              {
                step: { name: "tee", label: "tee" },
                hasNest: true,
                nestKind: "tee",
                nestAdd: [":private"],
              },
            ]}
            selected={null}
            armedBranch={{ stem: 1, selector: ":public" }}
            onSelect={() => {}}
            onGap={() => {}}
            onBranchHit={() => {}}
            onArmBranch={() => {}}
            onAddBranchStep={() => {}}
            onCancelArmed={() => {}}
            onReorder={() => {}}
          />
          <StateLabel>
            foreach — the body anchors on ↻ each item and its gap names the scope (46c)
          </StateLabel>
          <RecipeChipFlow
            cell={3}
            stems={[
              {
                step: { name: "foreach", label: "foreach" },
                hasNest: true,
                nestKind: "foreach",
                body: [],
              },
            ]}
            selected={null}
            onSelect={() => {}}
            onGap={() => {}}
            onBranchHit={() => {}}
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
                ? { show: true, locked: true, lockedReason: "locked by format" }
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
          <StateLabel>Secret param (§22a) — unbound / bound; never free text</StateLabel>
          <div className="grid max-w-md grid-cols-2 gap-3">
            <ParamField
              param={{ name: "key", type: "slot", secret: true, doc: "TURN credential" }}
              value=""
              onChange={() => {}}
              onRequestBind={() => {}}
            />
            <ParamField
              param={{ name: "key", type: "slot", secret: true, doc: "TURN credential" }}
              value="@dana-turn-pass"
              onChange={() => {}}
              onRequestBind={() => {}}
            />
          </div>
        </Section>

        <Section id="modetoggle" title="ModeToggle">
          <StateLabel>Cell view — Pipeline / Source</StateLabel>
          <ModeToggle
            value={mode}
            onChange={setMode}
            options={[
              { value: "pipeline", label: "Pipeline", title: "Chips + inline param panel" },
              { value: "source", label: "Source", title: "Edit the cell recipe as text" },
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

        <Section id="sharecards" title="ShareCards — printable split output (key-ceremony kit)">
          <p className="text-xs text-[var(--muted-foreground)]">
            The toolkit&rsquo;s only deliberate reveal-to-paper surface. Cards render masked;
            the button that unmasks them says what printing actually does, and{" "}
            <strong>Print cards</strong> only appears once revealed. The print stylesheet lives
            in <code>toolkit.css</code> — a masked card set is <em>hidden</em> from the print
            job rather than printed as bullets.
          </p>

          <StateLabel>Masked (default) — 3 shares, 2-of-3, QR present</StateLabel>
          <ShareCards artifacts={demoShareArtifacts} label="Board key ceremony" date="2026-07-30" />

          <StateLabel>Revealed — what goes on the page</StateLabel>
          <ShareCards
            artifacts={demoShareArtifacts}
            label="Board key ceremony"
            date="2026-07-30"
            defaultRevealed
            onPrint={() => {}}
          />

          <StateLabel>
            No QR in the recipe, and no threshold recorded — the card admits both
          </StateLabel>
          <ShareCards
            artifacts={[
              { role: "share", shareIndex: 1, content: "alpha bravo charlie delta echo foxtrot" },
              { role: "share", shareIndex: 2, content: "golf hotel india juliet kilo lima" },
            ]}
            defaultRevealed
            onPrint={() => {}}
          />

          <StateLabel>
            Verifiable split — the card names it, and prints the right recovery op
          </StateLabel>
          <ShareCards
            artifacts={demoShareArtifacts}
            label="Board key ceremony"
            date="2026-07-30"
            commitments={cardSplit.commitments}
            defaultRevealed
            onPrint={() => {}}
          />

          <StateLabel>
            Unverifiable split (<code>sss.split</code>) — the card says so rather than
            offering a check that cannot work
          </StateLabel>
          <ShareCards
            artifacts={demoShareArtifacts}
            label="Board key ceremony"
            date="2026-07-30"
            defaultRevealed
            onPrint={() => {}}
          />

          <StateLabel>Empty — cell has not been run</StateLabel>
          <ShareCards artifacts={[]} />
        </Section>

        <Section id="ceremonysheet" title="CeremonySheet — the guided key ceremony">
          <p className="text-xs text-[var(--muted-foreground)]">
            Sequence and wording only — every stage&rsquo;s work is ordinary notebook cells
            run through <code>useNotebook</code>. Verification sits <em>before</em> printing
            on purpose, and reports a match from two SHA-256 digests without putting the
            secret back on screen.
          </p>
          <CeremonyStates />
        </Section>

        <Section id="sharecheck" title="ShareCheck — the custodian verification moment">
          <p className="text-xs text-[var(--muted-foreground)]">
            One card, months later, on a machine with no session. The states worth staring
            at are the two that are <em>not</em> verdicts:{" "}
            <strong>well-formed but unchecked</strong> must never reach the green
            appearance, and <strong>does not match</strong> must not accuse the holder of
            mistyping — the BLIP39 checksum has already ruled that out.
          </p>
          <ShareCheckStates />
        </Section>

        <Section id="integrity" title="IntegrityPanel — verify this deployment">
          <p className="text-xs text-[var(--muted-foreground)]">
            Four of the six outcomes mean <em>no answer</em>, and none of those is drawn
            as success. The limitation sits under every verdict including the successful
            one, uncollapsed, because that is the verdict a reader stops reading at.
          </p>
          <IntegrityStates />
        </Section>

        <Section id="dkg" title="DkgPanel — distributed key generation (design-ahead)">
          <p className="text-xs text-[var(--muted-foreground)]">
            Not wired into the shell: <code>lib/quorum/dkg.js</code> has the rounds, the
            op that runs them over a live exchange does not exist yet. Here for the
            failure path — there is no complaint round, so a refusal names a dealer whom
            only <em>you</em> saw misbehave.
          </p>
          <DkgStates />
        </Section>
      </div>
    </TooltipProvider>
  );
}

/**
 * A throwaway verifiable split, made at mount from the real ops.
 *
 * Faking this would defeat the section: `verified` and `mismatch` are the
 * states that can be wrong, and they can only be exercised by shares that
 * genuinely do and do not lie on a committed polynomial. The secret is 32
 * random bytes drawn here and never stored, which is why a catalog page is
 * allowed to hold these mnemonics when it is not allowed to hold a real one.
 */
function useDemoSplit(threshold = 2, shares = 3) {
  return useMemo(() => {
    const secret = crypto.getRandomValues(new Uint8Array(32));
    // P-256 scalars must be below the group order; the top byte cleared keeps
    // the fixture from occasionally failing `vss.split`'s own range check.
    secret[0] = 0;
    const set = execVssSplit({ type: "bytes", data: secret }, { threshold, shares });
    const commitments = String(execVssCommitments(set).data);
    // `encodeShareSet` zeroes the raw share bytes as it encodes, so it has to
    // come after the commitments are read off the same object.
    const { mnemonics } = encodeShareSet(set.data as never);
    return { mnemonics, commitments };
  }, [threshold, shares]);
}

/* ── §37 artifact-tile fixtures ───────────────────────────────────────────
 *
 * Captured from `runRecipe`, not written by hand. A fixture that merely looks
 * like what the engine emits is how a tile passes its catalog and falls
 * through to the fallback in production — the roles and tags below are the
 * ones a real run stamps, checked by printing them off the engine first.
 */

/** `"…" | utf8 | gpg.symencrypt mode=passphrase passphrase="hunter2"` */
const DEMO_ARMOR = `-----BEGIN PGP MESSAGE-----

w1gGJgkCFATbgLG36Fi6JP04xyre+pV/AwQQSjtkirG2GKp49PAFfX2yw2w1
z/xCJfxmKLBbNvkC/OAJmObwiE6FKdwW79Bv2s8kcCgNbnJcg/SqmE5cs5cn
0nICCQIMXBGGvd0t7HNI4IHKhzwohOfUXUtkGf/Kbgwey61VoM22vdHvnJyM
2KCRjbk3OJNQ6EfAulYKlchZtISfekj3Xi5YE/D3sEmEd3pHH4LxWf2P6rHe
39m1UXj4UDKsVOixKKmxNvsKlv9BkH2GAXE=
-----END PGP MESSAGE-----
`;

/** `"release-2026.07" | utf8 | ssh.sign key=@id namespace=git` */
const DEMO_SSHSIG = `-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgLvt5SVIUF1g6+jpuSMZQ20lsuX
HEUQU66zrrzhf59eUAAAADZ2l0AAAAAAAAAAZzaGE1MTIAAABTAAAAC3NzaC1lZDI1NTE5
AAAAQPOqks5X4nDEGmajCv07dYYvauDXo7VX+yOTQp+/uXPSWQeEA6QZJ3TBHmNLp9NSZM
ysLuLEsFSvAtr4TEBMjQs=
-----END SSH SIGNATURE-----
`;

/** A v2 receipt in `run.receipt`'s exact shape, with two cells to fill the table. */
const DEMO_RECEIPT = JSON.stringify({
  cells: [
    {
      index: 0,
      inputs: [],
      outputs: [
        {
          digest: "09cfa680dc9c72fe6cbfda867e8a193efce63573e92fc8b758cf516021ef6b99",
          filename: "msg.bin.b64",
          label: "msg",
          length: 8,
          role: "text",
          sensitive: false,
          stepName: "out",
        },
      ],
      recipe: '"plain" | utf8 | out @msg',
      startedAt: "2026-08-01T03:01:48.042Z",
    },
    {
      index: 1,
      inputs: [],
      outputs: [
        {
          digest: "44ffee0186c30b3c2e0c0d9b1e2f5a6d7c8b9a0f1e2d3c4b5a69788796a5b4c3",
          filename: "share-1.bin.b64",
          label: "s · share 1",
          length: 44,
          role: "share",
          sensitive: true,
          shareIndex: 1,
          stepName: "out",
        },
        {
          digest: "1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809",
          filename: "s.asc",
          label: "envelope",
          length: 892,
          role: "envelope",
          sensitive: false,
          stepName: "gpg.symencrypt",
        },
      ],
      recipe: "random 32 | sss.split threshold=2 shares=3 | out @s",
      startedAt: "2026-08-01T03:01:49.101Z",
    },
  ],
  createdAt: "2026-08-01T03:01:48.042Z",
  kind: "basilisk.run-receipt",
  label: "Board key ceremony",
  recipeDigest: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  recipeSource: "",
  registry: "ops-114-12853301",
  v: 2,
});

const DEMO_RECIPIENTS = JSON.stringify(
  [
    {
      fingerprint: "AABBCCDD11223344AABBCCDD11223344AABBCCDD",
      label: "Dana Okonkwo",
      email: "dana@example.org",
      approvalState: "approved",
      encryptCapable: true,
    },
    {
      fingerprint: "99887766554433229988776655443322998877 66",
      label: "Sam Reyes",
      email: "sam@example.org",
      approvalState: "unverified",
      encryptCapable: false,
    },
  ],
  null,
  2
);

/**
 * `hkp.search "example.org"` against a real keyserver — the case the ceiling
 * and the filter exist for.
 *
 * The short list above is the local cache and it is the *unrepresentative*
 * one: a keyserver search returns tens of rows, and at 16px a row that was
 * several hundred pixels of table inside a single artifact row, with no cap,
 * no scroll and no way to find anyone in it. Fourteen rows is past
 * `FILTER_ROWS`, so this is the state where the search box appears, and past
 * the eleven the box can show, so it is also the state where it scrolls.
 *
 * The odd ones are the point: row 7 carries its fingerprint *with* grouping
 * spaces, which is what a real hkp response looks like and what a naive
 * `includes` on a typed query silently fails to match.
 */
const DEMO_RECIPIENTS_MANY = JSON.stringify(
  Array.from({ length: 14 }, (_, i) => ({
    fingerprint:
      i === 6
        ? "99887766554433229988776655443322998877 66"
        : `${(i + 10).toString(16).repeat(2).toUpperCase()}BBCCDD11223344AABBCCDD11223344AABBCC${(i + 10)
            .toString(16)
            .toUpperCase()}`,
    label: ["Dana Okonkwo", "Sam Reyes", "Ingrid Vasquez", "Tomas Bergqvist"][i % 4],
    email: `${["dana", "sam", "ingrid", "tomas"][i % 4]}${i}@example.org`,
    approvalState: i % 3 === 0 ? "approved" : "unverified",
    encryptCapable: i % 5 !== 3,
  })),
  null,
  2
);

/** `"hello world" | utf8 | inspect` — the snapshot and the text dump beside it. */
const DEMO_INSPECT_SNAPSHOT = {
  type: "bytes",
  meta: { type: { base: "bytes", kind: "opaque" }, sensitive: false },
  bytes: [104, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100],
};

const DEMO_INSPECT_TEXT = `type: bytes
sensitive: no
length: 11 bytes

00000000  68 65 6c 6c 6f 20 77 6f 72 6c 64                 |hello world|

--- utf-8 preview ---
hello world
`;

/** `'{"sub":"me"}' | utf8 | jose.sign key=@k alg=ES256 | out @t` */
const DEMO_JWS =
  "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJtZSJ9." +
  "6AeMiatcldxFVP8JEN3i6vlFxrlrlesdexBW-A43exaFIHA03CgB7C7OrpgG4lZerDlE8M5xoDerd76cy083Rw";

/** The verdict the op computed and the token text cannot carry. */
const DEMO_JOSE = {
  kind: "jws",
  verified: true,
  signed: true,
  header: { alg: "ES256", typ: "JWT" },
  claims: { sub: "me" },
  payloadText: null,
  timing: { exp: null, nbf: null, iat: null, expired: false, notYetValid: false },
};

/** Every §37 kind as a tile row, in the order the design lists them. */
function demoArtifactTiles(): React.ComponentProps<typeof OutputList>["outputs"] {
  const row = (o: Partial<OutputArtifact> & { label: string; role: string }) => ({
    kind: o.role === "diagnostic" ? "diag" : o.role,
    sizeBytes: new TextEncoder().encode(o.content || "").length,
    onCopy: () => {},
    ...o,
  }) as OutputArtifact;

  return [
    row({
      label: "message.asc",
      role: "ciphertext",
      tags: ["encrypted", "openpgp"],
      content: DEMO_ARMOR,
    }),
    row({
      label: "OpenPGP envelope — required for recovery (not a share)",
      role: "envelope",
      tags: ["openpgp", "skesk"],
      content: DEMO_ARMOR,
    }),
    row({
      // Masked, which is the state that matters: the identity line is the
      // whole point of the share kind, and it only renders while masked.
      label: "s · share 2",
      role: "share",
      tags: ["sss", "raw"],
      traits: { shareOf: 2, threshold: 2 } as Record<string, unknown>,
      sensitive: true,
      revealable: true,
      content: "D3JWAl1SMNOsjyiSUp5TfOdXE5Jl3Nop3DxOXmWvf1U=",
    }),
    row({
      label: "alices",
      role: "recipients",
      tags: ["openpgp", "recipients"],
      content: DEMO_RECIPIENTS,
    }),
    row({
      // The same kind at keyserver length — capped, scrolling, and filterable.
      // Two rows rather than one because the short list is the one that must
      // *not* grow a search box it does not need.
      label: "found",
      role: "recipients",
      tags: ["openpgp", "recipients"],
      content: DEMO_RECIPIENTS_MANY,
    }),
    row({
      label: "sig",
      role: "sshsig",
      tags: ["ssh", "signature"],
      content: DEMO_SSHSIG,
    }),
    row({
      label: "nat",
      role: "diagnostic",
      tags: ["webrtc", "endpoint"],
      netType: "endpoint",
      netData: {
        v: 1,
        server: "stun:stun.cloudflare.com:3478",
        ok: false,
        publicAddress: null,
        candidates: { host: 4 },
        ms: 1180,
        note: "no srflx candidate — STUN blocked or all-host network; consider a TURN relay (rtc.ice turn=)",
      },
      content: "{…}",
      diagnosticAction: { label: "Configure TURN", onClick: () => {} },
    }),
    row({ label: "r", role: "receipt", tags: ["opaque"], content: DEMO_RECEIPT }),
    row({
      label: "share-2.svg",
      role: "qr",
      tags: ["qr"],
      content: qrSvg("away manual curious become aluminum headset", {
        ecl: "L",
        moduleSize: 3,
        margin: 4,
      }),
    }),
    row({
      /**
       * `"hello world" | utf8 | inspect` — the structured snapshot, in a tile.
       *
       * It had no row, and `inspect-snapshot` is the kind that most needed one:
       * its view is the only one gated on a *parallel field* (`inspectSnapshot`)
       * rather than on the body, so a mapping that dropped the field would leave
       * a tile whose card silently became a text dump. Now visible.
       */
      label: "inspect",
      role: "inspect",
      tags: ["inspect", "opaque"],
      revealable: true,
      filename: "inspect.txt",
      content: DEMO_INSPECT_TEXT,
      inspectSnapshot: DEMO_INSPECT_SNAPSHOT,
    }),
    row({
      /**
       * `jose.sign key=@k alg=ES256 | out @t` — **masked, because that is what
       * the engine emits**, and that is the finding this row exists to make
       * visible (§48d).
       *
       * `JwtArtifact` is the most complete read-out in the codebase — verdict,
       * claims in RFC order, a draining bar, tones withheld when the signature
       * was not checked — and it had a section of its own that mounts it
       * **bare**. Inside a tile it used to look like nothing: `sensitive:
       * true`, no `publicView`, so a reader got "sensitive — value not shown"
       * and a Reveal that the list re-masks fifteen seconds later.
       *
       * **The row now draws the card while masked, and the earlier reading
       * here was wrong.** It said every fact on the card "derives from the
       * masked material", so a `publicView` would be a hole in the mask. That
       * is not the rule as the table practises it: `ssh-private` reads the
       * *masked openssh block* to draw a key type and a fingerprint, because
       * what matters is whether the drawn material is public, not whether the
       * masked bytes were touched. A JWS is signed, not encrypted — its header
       * and payload are base64url and readable by anyone holding it — and the
       * **signature** is the part that makes it a bearer credential. So the
       * kind keeps `sensitive: true` (a compact token on screen is a
       * credential on screen) and declares a `publicView` that draws header,
       * claims and validity and has no path to the third segment: it is handed
       * `meta.jose`, and the compact token is not in it.
       *
       * Keep this row masked. It is the one place the masked state of the
       * best read-out in the codebase is visible at all, and the reason it
       * was missing for so long is that the section above mounts the widget
       * bare, where a mask cannot be seen.
       */
      label: "t",
      role: "token",
      tags: ["jose", "jws"],
      sensitive: true,
      revealable: true,
      filename: "t.txt",
      content: DEMO_JWS,
      jose: DEMO_JOSE,
    }),
    row({
      /**
       * `rtc.state | out @s` — a network value in a tile rather than bare.
       *
       * `#networkartifact` mounts `NetworkArtifact` directly, so the *tile*
       * level of this kind — badge, actions, Expand, the mask gate — had never
       * been seen. The panel is the same one that section draws.
       */
      label: "s",
      role: "netvalue",
      tags: ["webrtc", "connstate"],
      netType: "connstate",
      // The same peer shape `#networkartifact` feeds `ConnStateStrip` — the
      // panel reads `data.peers`, and a fixture built from the *op's* other
      // fields draws "No peers in this exchange", which is the empty state
      // rather than the card. Measured on the built page before this.
      netData: {
        peers: [
          {
            peer: "AABBCCDDEEFF0011",
            connectionState: "connected",
            iceConnectionState: "connected",
            signalingState: "stable",
            channelState: "open",
            verified: true,
          },
          {
            peer: "1122334455667788",
            connectionState: "connecting",
            iceConnectionState: "checking",
            signalingState: "have-local-offer",
            channelState: "connecting",
          },
        ],
      },
      filename: "s.json",
      mime: "application/json",
      content: "{…}",
    }),
    row({ label: "msg", role: "text", tags: ["opaque"], content: "cGxhaW4=" }),
    row({
      label: "cek",
      role: "secret",
      tags: ["master"],
      sensitive: true,
      revealable: true,
      content: "Gds11DxAR4gimt+jS5a4UEPp+iuQbpldaLC+PrBFJxI=",
    }),
    row({
      // Nothing claims this role, so it lands on the fallback — which is a
      // kind with a real view, not a crash (§32f), and still offers Copy.
      label: "from-a-later-build",
      role: "something-later",
      content: "a value this build has no description for",
    }),
  ];
}

/* ── §35 key-artifact fixtures ────────────────────────────────────────────
 *
 * Printed off `runRecipe` and pasted, same rule as the §37 set above: a key
 * fixture that merely looks right is how a badge passes its catalog and
 * resolves to `fallback` in the page. Every `role`/`tags`/`traits` below is
 * what the engine stamped for the recipe named beside it.
 */

/** `genkey ed25519` — the tip, both halves, no body at all. */
const DEMO_KP_PUBLIC_JWK = JSON.stringify(
  {
    key_ops: ["verify"],
    ext: true,
    alg: "Ed25519",
    crv: "Ed25519",
    x: "sQIiq4gvkUFV3jHYS-rsDXSGH8KF0Z20bv7eSgT3IjE",
    kty: "OKP",
  },
  null,
  2
);

/** `genkey ed25519 | out @kp` — the private half. */
const DEMO_KP_PRIVATE = JSON.stringify(
  {
    key_ops: ["sign"],
    ext: true,
    alg: "Ed25519",
    crv: "Ed25519",
    d: "Fbs3cc3d5hXK_o0JGsbb1-4iTlltGS5AlROJfuV02HM",
    x: "WjL4F4L1ZpA3hFYGwAQEzYwDKGx7ZtbeB7a0560UtXc",
    kty: "OKP",
  },
  null,
  2
);

/** …and its public one. */
const DEMO_KP_PUBLIC = JSON.stringify(
  {
    key_ops: ["verify"],
    ext: true,
    alg: "Ed25519",
    crv: "Ed25519",
    x: "WjL4F4L1ZpA3hFYGwAQEzYwDKGx7ZtbeB7a0560UtXc",
    kty: "OKP",
  },
  null,
  2
);

/** `genkey aes/256 | out @k` — a symmetric key, which has no halves. */
const DEMO_SECRET_JWK = JSON.stringify(
  {
    key_ops: ["encrypt", "decrypt"],
    ext: true,
    alg: "A256GCM",
    kty: "oct",
    k: "mFND-klPD2cYlHskuRVvr5OAsIE94MtyWxvZJT--9FI",
  },
  null,
  2
);

/** `genkey ed25519 | ssh.encode comment=dana@laptop | out @pub` */
const DEMO_SSH_PUBLIC =
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOTy7eoXFoeHUYSj7bup7fa6mPizYsdZ8gMg2vlmNxoX dana@laptop";

/** `genkey ed25519 | ssh.encode format=private comment=dana@laptop | out @priv` */
const DEMO_SSH_PRIVATE = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBkGd5qUSLxUpm08/42114C0nW31Ya22yktOxPtCEVrGgAAAJBa8dS1WvHU
tQAAAAtzc2gtZWQyNTUxOQAAACBkGd5qUSLxUpm08/42114C0nW31Ya22yktOxPtCEVrGg
AAAEDheiBMJcccafqYnsaU2VBZ3VpvX0wbV+HCPheFhAfljmQZ3mpRIvFSmbTz/jbXXgLS
dbfVhrbbKS07E+0IRWsaAAAAC2RhbmFAbGFwdG9wAQI=
-----END OPENSSH PRIVATE KEY-----
`;

/** `gpg.genkey name="Dana Okonkwo" email="dana@example.org" | out @k` */
const DEMO_PGP_PUBLIC = `-----BEGIN PGP PUBLIC KEY BLOCK-----

xjMEam4g9hYJKwYBBAHaRw8BAQdAPegJfKCCwBHtEslsjVuJrxBHoXf335px
LzhMtOZNr8DNH0RhbmEgT2tvbmt3byA8ZGFuYUBleGFtcGxlLm9yZz7CwBME
ExYKAIUFgmpuIPYDCwkHCRAG/5WTwL0ce0UUAAAAAAAcACBzYWx0QG5vdGF0
aW9ucy5vcGVucGdwanMub3JnSoPT6dRmk0A0P6NaEYP0CY2Pqpo/ENh+YKDZ
ZNaOtOAFFQoIDgwEFgACAQIZAQKbAwIeARYhBFze0FWLF4oX39CFqwb/lZPA
vRx7AABrtQEA/pUuQgSco65TN7jl/A52itGU7kkiHnG5fXb/lRwqinoBAMjK
p4Mk9C05mY2eHIMmkX/8d6aZa9FRchjDj/Wz04YEzjgEam4g9hIKKwYBBAGX
VQEFAQEHQC+BEv9axBI/a5qrJ9p5BiVh/tJE1LsGDosM6T4UGFBgAwEIB8K+
BBgWCgBwBYJqbiD2CRAG/5WTwL0ce0UUAAAAAAAcACBzYWx0QG5vdGF0aW9u
cy5vcGVucGdwanMub3JnThp71BS2fi+gwN9BFNRH0Kj7E1oUER/TQGcK/xm+
Cq8CmwwWIQRc3tBVixeKF9/QhasG/5WTwL0cewAAbxoBAKHVV6dETeA/jWnu
vOTPmplY7C6wbkyNqlmjmvoD7hWVAP4xJcn2H9Zbab3AjPo/bKKl8jd6Bskc
AtfiE8eeeQsNDg==
=ipoj
-----END PGP PUBLIC KEY BLOCK-----
`;

const DEMO_PGP_PRIVATE = `-----BEGIN PGP PRIVATE KEY BLOCK-----

xVgEam4g9hYJKwYBBAHaRw8BAQdAPegJfKCCwBHtEslsjVuJrxBHoXf335px
LzhMtOZNr8AAAP4nkeu1g+S55FyuDR/kJuvFwnKbwQp+Q/xdQ6/E58nRIBNV
zR9EYW5hIE9rb25rd28gPGRhbmFAZXhhbXBsZS5vcmc+wsATBBMWCgCFBYJq
biD2AwsJBwkQBv+Vk8C9HHtFFAAAAAAAHAAgc2FsdEBub3RhdGlvbnMub3Bl
bnBncGpzLm9yZ0qD0+nUZpNAND+jWhGD9AmNj6qaPxDYfmCg2WTWjrTgBRUK
CA4MBBYAAgECGQECmwMCHgEWIQRc3tBVixeKF9/QhasG/5WTwL0cewAAa7UB
AP6VLkIEnKOuUze45fwOdorRlO5JIh5xuX12/5UcKop6AQDIyqeDJPQtOZmN
nhyDJpF//HemmWvRUXIYw4/1s9OGBMddBGpuIPYSCisGAQQBl1UBBQEBB0Av
gRL/WsQSP2uaqyfaeQYlYf7SRNS7Bg6LDOk+FBhQYAMBCAcAAP9zQmpFoz43
Jmyl0jjCz4Y+emLlx9D57aVKRIelC7tOwBGCwr4EGBYKAHAFgmpuIPYJEAb/
lZPAvRx7RRQAAAAAABwAIHNhbHRAbm90YXRpb25zLm9wZW5wZ3Bqcy5vcmdO
GnvUFLZ+L6DA30EU1EfQqPsTWhQRH9NAZwr/Gb4KrwKbDBYhBFze0FWLF4oX
39CFqwb/lZPAvRx7AABvGgEAodVXp0RN4D+Nae685M+amVjsLrBuTI2qWaOa
+gPuFZUA/jElyfYf1ltpvcCM+j9soqXyN3oGyRwC1+ITx555Cw0O
=xKur
-----END PGP PRIVATE KEY BLOCK-----
`;

const DEMO_PGP_FINGERPRINT = "5CDED0558B178A17DFD085AB06FF9593C0BD1C7B";

/** Every key-badge role as a tile row, in the order a user meets them. */
function demoKeyArtifacts(): React.ComponentProps<typeof OutputList>["outputs"] {
  // The live OTP row's step, taken at render rather than written down. See the
  // row itself for why a fixture that names a step is a fixture that expires.
  const nowSeconds = Math.floor(Date.now() / 1000);
  const liveStep = Math.floor(nowSeconds / 30);
  const row = (o: Partial<OutputArtifact> & { label: string; role: string }) =>
    ({
      kind: o.role,
      sizeBytes: new TextEncoder().encode(o.content || "").length,
      onCopy: () => {},
      ...o,
    }) as OutputArtifact;

  return [
    row({
      // `genkey ed25519` — no `out`. The one key tile with no body by design.
      label: "artifact",
      role: "keypair",
      tags: ["keypair"],
      traits: { alg: "ed25519", publicJwk: DEMO_KP_PUBLIC_JWK },
      sensitive: true,
      content: "",
    }),
    row({
      label: "kp · private JWK",
      role: "key",
      tags: ["keypair", "private"],
      traits: { alg: "ed25519" },
      sensitive: true,
      revealable: true,
      filename: "kp-private.jwk.json",
      mime: "application/json",
      content: DEMO_KP_PRIVATE,
    }),
    row({
      label: "kp · public JWK",
      role: "public-key",
      tags: ["keypair", "public"],
      traits: { alg: "ed25519" },
      revealable: true,
      filename: "kp-public.jwk.json",
      mime: "application/json",
      content: DEMO_KP_PUBLIC,
    }),
    row({
      label: "k · secret JWK",
      role: "secret-key",
      tags: ["secret"],
      traits: { alg: "aes/256" },
      sensitive: true,
      revealable: true,
      filename: "k-secret.jwk.json",
      mime: "application/json",
      content: DEMO_SECRET_JWK,
    }),
    row({
      label: "pub",
      role: "ssh-public",
      tags: ["ssh-public"],
      revealable: true,
      filename: "pub.txt",
      content: DEMO_SSH_PUBLIC,
    }),
    row({
      label: "priv",
      role: "ssh-private",
      tags: ["ssh-private"],
      sensitive: true,
      revealable: true,
      filename: "priv.txt",
      content: DEMO_SSH_PRIVATE,
    }),
    row({
      label: "OpenPGP public key",
      role: "public-key",
      tags: ["openpgp", "public-key"],
      traits: { fingerprint: DEMO_PGP_FINGERPRINT },
      filename: "public.asc",
      mime: "application/pgp-keys",
      content: DEMO_PGP_PUBLIC,
      onPublish: async () => ({ fingerprint: DEMO_PGP_FINGERPRINT }),
      directoryHost: "keys.example.com",
    }),
    row({
      label: "k",
      role: "key",
      tags: ["openpgp", "private"],
      traits: { which: "private", fingerprint: DEMO_PGP_FINGERPRINT },
      sensitive: true,
      revealable: true,
      filename: "k.asc",
      mime: "application/pgp-keys",
      content: DEMO_PGP_PRIVATE,
    }),
    /**
     * The two least-specific key kinds, which had no row on this page at all.
     *
     * Their `role` and `tags` come from `artifactMetaFromType` rather than from
     * a literal, and that is not fussiness — it is the only honest way to draw
     * them. **No shipped step emits either shape through `out` today**: the
     * keypair emit sites tag `keypair`, so `keypair-public` always outscores
     * `public-key`, and PEM/DER exports keep the sensitivity ternary's
     * `text`/`secret` because `key` is not in `TYPE_OWNED_ROLES`. The kinds are
     * not dead — `key` is the declared fallback for any key with no half stated
     * and `public-key` is waiting for an `import spki` tip — but a fixture
     * written by hand for a shape nothing produces is a fixture that can only
     * be wrong. Built from the projection, it is wrong only if the projection is.
     */
    row({
      // `artifactMetaFromType({ base: "openpgp-key", which: "public" })` — the
      // shape `valueToArtifacts` stamps on a dangling openpgp-key tip. It lands
      // on `key` and draws `KeyCard`, which reads JWK and not armor, so the
      // tile shows the algorithm and a raw toggle and no fingerprint. That is
      // §35e's stated gap, on the page rather than in a comment.
      label: "openpgp tip",
      ...artifactMetaFromType({ base: "openpgp-key", which: "public" }),
      traits: { fingerprint: DEMO_PGP_FINGERPRINT },
      revealable: true,
      filename: "artifact.asc",
      mime: "application/pgp-keys",
      content: DEMO_PGP_PUBLIC,
    }),
    row({
      // `artifactMetaFromType({ base: "key", which: "public" })` — a public half
      // with no pair beside it. The `key` kind above says nothing about which
      // half it holds; this one says "public half" and offers the public line.
      label: "spki",
      ...artifactMetaFromType({ base: "key", which: "public" }),
      traits: { alg: "ed25519" },
      revealable: true,
      filename: "spki-public.jwk.json",
      mime: "application/json",
      content: DEMO_KP_PUBLIC,
    }),
    row({
      // `"JBSWY3DPEHPK3PXP" | utf8 | otp.code` — role `text`, claimed by a tag.
      //
      // The step is taken from the clock, and that is the fix rather than the
      // shortcut. It was hard-coded to `59520075` — the step that was current
      // the afternoon the fixture was written — so `(59520075 + 1) × 30` sat in
      // the past from the next minute onward and the one row on this page whose
      // job is to demonstrate a draining countdown could only ever render its
      // end state. A derived step shows the whole life of a live code: it opens
      // mid-step, drains, turns amber under five seconds, and then reads
      // *expired* and stays there — which is the honest thing a live code does,
      // and reloading starts it over. The pinned row below never rots, so
      // between them the two states are both on the surface on purpose.
      label: "code · live",
      role: "text",
      tags: ["otp-code"],
      traits: {
        otpMode: "totp",
        otpDigits: 6,
        otpPeriod: 30,
        otpStep: String(liveStep),
        otpExpiresIn: (liveStep + 1) * 30 - nowSeconds,
      },
      revealable: true,
      filename: "code.txt",
      content: "133042",
    }),
    row({
      // `"JBSWY3DPEHPK3PXP" | utf8 | otp.code at=1700000000` — the traits a real
      // run stamps for that step, printed off the engine: step 56666666, ten
      // seconds left at the named instant, and `otpPinnedAt` saying the recipe
      // named it. The card states the instant and does not tick, because it
      // may tick only against an instant the recipe did not choose.
      label: "code · pinned by at=",
      role: "text",
      tags: ["otp-code"],
      traits: {
        otpMode: "totp",
        otpDigits: 6,
        otpPeriod: 30,
        otpStep: "56666666",
        otpExpiresIn: 10,
        otpPinnedAt: 1700000000,
      },
      revealable: true,
      filename: "pinned.txt",
      content: "324550",
    }),
  ];
}

function ShareCheckStates() {
  const a = useDemoSplit();
  const b = useDemoSplit(3, 5);

  return (
    <>
      <StateLabel>Empty — nothing claimed</StateLabel>
      <ShareCheck key="empty" />

      <StateLabel>
        Share only — well-formed, and the panel says nothing has been checked
      </StateLabel>
      <ShareCheck key="share-only" initialShare={a.mnemonics[1]} />

      <StateLabel>Commitments only — waiting for a card</StateLabel>
      <ShareCheck key="commitments-only" initialCommitments={a.commitments} />

      <StateLabel>Verified — a genuine share against its own split</StateLabel>
      <ShareCheck
        key="verified"
        initialShare={a.mnemonics[1]}
        initialCommitments={a.commitments}
      />

      <StateLabel>
        Mismatch — a genuine share against another split&rsquo;s commitments
      </StateLabel>
      <ShareCheck
        key="mismatch"
        initialShare={a.mnemonics[0]}
        initialCommitments={b.commitments}
      />

      <StateLabel>Unreadable share — the checksum caught it</StateLabel>
      <ShareCheck
        key="bad-share"
        initialShare="acid academic not actually a mnemonic at all"
        initialCommitments={a.commitments}
      />

      <StateLabel>Unreadable commitments</StateLabel>
      <ShareCheck
        key="bad-commitments"
        initialShare={a.mnemonics[0]}
        initialCommitments='{"commitments":["not-a-point"]}'
      />

      <StateLabel>
        QR unsupported — the honest degradation on Firefox / Safari
      </StateLabel>
      <ShareCheck
        key="no-barcode"
        onScanQr={async () => ""}
        scanSupported={false}
      />
    </>
  );
}

const INTEGRITY_FIXTURES: { note: string; verdict: DeploymentVerdict }[] = [
  {
    note: "verified — root matches the published pin",
    verdict: {
      status: "verified",
      tone: "ok",
      headline: "Matches the published pin for toolkit.html.",
      detail:
        "34 modules loaded, folding to root 9f2c1a44b8e07d31…, and 2 pin documents agree. " +
        "The browser separately enforced each module's own SRI hash on load, so nothing " +
        "outside this set executed.",
      root: "9f2c1a44b8e07d3155aa20c9b6de41f8027cc9d54ba1e37f66d0aa9188c3e021",
      expectedRoot: "9f2c1a44b8e07d3155aa20c9b6de41f8027cc9d54ba1e37f66d0aa9188c3e021",
      leafCount: 34,
      pageKey: "toolkit.html",
      pinUrls: ["/integrity/module-roots.json", "https://mirror.example/module-roots.json"],
      fetched: 2,
      raw: "Integrity pin matched (2 sources).",
    },
  },
  {
    note: "mismatch — the failure the mechanism exists for",
    verdict: {
      status: "mismatch",
      tone: "error",
      headline: "The code in this tab is not the code the pin describes.",
      detail:
        "Module Merkle root mismatch (live 9f2c1a44b8e07d31… ≠ pin 41bb90de77c2a8f5…). " +
        "This is the failure the whole mechanism exists to make visible. It can be a stale " +
        "cache or a half-finished deploy — those are the boring explanations and they are the " +
        "common ones — but it is indistinguishable from the interesting one. Close the tab, " +
        "clear the cache, and load it again; if the root still differs, do not enter key " +
        "material into this page.",
      root: "9f2c1a44b8e07d3155aa20c9b6de41f8027cc9d54ba1e37f66d0aa9188c3e021",
      expectedRoot: "41bb90de77c2a8f5b0e1cc7d2299a4531ff08b6ea72d40c3195e6b8aa04d7712",
      leafCount: 34,
      pageKey: "toolkit.html",
      pinUrls: ["/integrity/module-roots.json"],
      fetched: 1,
      raw: "",
    },
  },
  {
    note: "mirrors disagree — CDN split-brain",
    verdict: {
      status: "disagree",
      tone: "error",
      headline: "The pin mirrors do not agree with each other.",
      detail:
        "Integrity pin mirrors disagree (9f2c1a44b8e07d31 vs 41bb90de77c2a8f5). Mirrors exist " +
        "so that subverting one host is not enough; two answers means either a deploy caught " +
        "mid-flight or one of them is lying, and from here those look identical. Do not use " +
        "this tab for anything sensitive until the mirrors converge.",
      root: "9f2c1a44b8e07d3155aa20c9b6de41f8027cc9d54ba1e37f66d0aa9188c3e021",
      expectedRoot: "",
      leafCount: 34,
      pageKey: "toolkit.html",
      pinUrls: ["/integrity/module-roots.json", "https://mirror.example/module-roots.json"],
      fetched: 2,
      raw: "",
    },
  },
  {
    note: "unreachable — the check that did not run",
    verdict: {
      status: "unreachable",
      tone: "error",
      headline: "Cannot verify — the pin document could not be read.",
      detail:
        "Integrity pin fetch failed (HTTP 503). A blocked or offline fetch looks exactly like " +
        "a suppressed one. Treat this as unverified rather than as fine: the check that would " +
        "have caught tampering is the check that did not run.",
      root: "9f2c1a44b8e07d3155aa20c9b6de41f8027cc9d54ba1e37f66d0aa9188c3e021",
      expectedRoot: "",
      leafCount: 34,
      pageKey: "toolkit.html",
      pinUrls: ["/integrity/module-roots.json"],
      fetched: 0,
      raw: "",
    },
  },
  {
    note: "unpinned — a root that attests to nothing but itself",
    verdict: {
      status: "unpinned",
      tone: "warn",
      headline: "Cannot verify — no pin document is configured.",
      detail:
        "The 34 modules this page loaded fold to root 9f2c1a44b8e07d31…, and the browser did " +
        "enforce their individual SRI hashes — a modified module would have failed to execute. " +
        "What is missing is anything independent to compare the root against, so this number " +
        "attests to nothing but itself. Write it down and compare it with another machine, or " +
        "another person, if that matters to you.",
      root: "9f2c1a44b8e07d3155aa20c9b6de41f8027cc9d54ba1e37f66d0aa9188c3e021",
      expectedRoot: "",
      leafCount: 34,
      pageKey: "toolkit.html",
      pinUrls: [],
      fetched: 0,
      raw: "",
    },
  },
  {
    note: "no SRI — the dev server, and the honest thing to say about it",
    verdict: {
      status: "no-sri",
      tone: "warn",
      headline: "Cannot verify — this page carries no integrity hashes.",
      detail:
        "Nothing on it declares an SRI digest, so there is no set of module hashes to check. " +
        "That is normal on the dev server, which serves unhashed modules and a looser " +
        "Content-Security-Policy than production. If you are seeing this on a deployed origin, " +
        "the build that produced it did not run the integrity step, and none of the guarantees " +
        "in the threat model's first section apply to it.",
      root: "",
      expectedRoot: "",
      leafCount: 0,
      pageKey: "index.html",
      pinUrls: [],
      fetched: 0,
      raw: "",
    },
  },
];

const DEMO_CSP =
  "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; " +
  "connect-src 'self' https://keys.openpgp.org https://keys.mailvelope.com; " +
  "img-src 'self' data:; font-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self';";

function IntegrityStates() {
  return (
    <>
      {INTEGRITY_FIXTURES.map((f) => (
        <div key={f.verdict.status}>
          <StateLabel>{f.note}</StateLabel>
          <IntegrityPanel verdict={f.verdict} policy={DEMO_CSP} live={false} />
        </div>
      ))}
      <StateLabel>Live — this page, right now</StateLabel>
      <IntegrityPanel />
    </>
  );
}

const dkgPeer = (
  id: string,
  round: DkgParticipant["round"],
  extra: Partial<DkgParticipant> = {}
): DkgParticipant => ({
  id,
  round,
  state: "connected",
  authenticated: true,
  ...extra,
});

const DKG_FIXTURES: { note: string; props: Parameters<typeof DkgPanel>[0] }[] = [
  {
    note: "assembling — nobody has dealt yet",
    props: {
      participants: [
        dkgPeer("you", "waiting", { self: true }),
        dkgPeer("4f2a…", "waiting"),
        dkgPeer("91cd…", "waiting", { state: "connecting", authenticated: false }),
      ],
      onStart: () => {},
    },
  },
  {
    note: "dealing — waiting on commitments, stated as 1 of 4",
    props: {
      started: true,
      participants: [
        dkgPeer("you", "verified", { self: true }),
        dkgPeer("4f2a…", "commitments"),
        dkgPeer("91cd…", "waiting"),
        dkgPeer("7b03…", "waiting"),
        dkgPeer("e5f1…", "waiting", { state: "connecting", authenticated: false }),
      ],
    },
  },
  {
    note: "collecting — every commitment in, shares arriving",
    props: {
      started: true,
      participants: [
        dkgPeer("you", "verified", { self: true }),
        dkgPeer("4f2a…", "verified"),
        dkgPeer("91cd…", "share"),
        dkgPeer("7b03…", "commitments"),
      ],
    },
  },
  {
    note: "finalizing — all checked, sum not yet taken",
    props: {
      started: true,
      participants: [
        dkgPeer("you", "verified", { self: true }),
        dkgPeer("4f2a…", "verified"),
        dkgPeer("91cd…", "verified"),
      ],
      onFinalize: () => {},
    },
  },
  {
    note: "refused — one bad dealer, and why that is not a verdict",
    props: {
      started: true,
      participants: [
        dkgPeer("you", "verified", { self: true }),
        dkgPeer("4f2a…", "bad"),
        dkgPeer("91cd…", "verified"),
      ],
      onRestart: () => {},
    },
  },
  {
    note: "complete — a key nobody assembled, and no export button",
    props: {
      started: true,
      threshold: 2,
      jointPublicKey: "02a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90",
      participants: [
        dkgPeer("you", "verified", { self: true }),
        dkgPeer("4f2a…", "verified"),
        dkgPeer("91cd…", "verified"),
      ],
    },
  },
  {
    note: "over the mesh soft cap — the ConnectionsPanel warning, restated here",
    props: {
      started: true,
      participants: [
        dkgPeer("you", "waiting", { self: true }),
        ...Array.from({ length: 9 }, (_, i) => dkgPeer(`p${i + 1}…`, "waiting")),
      ],
    },
  },
];

function DkgStates() {
  return (
    <>
      {DKG_FIXTURES.map((f) => (
        <div key={f.note}>
          <StateLabel>{f.note}</StateLabel>
          <DkgPanel {...f.props} />
        </div>
      ))}
    </>
  );
}

/**
 * Each ceremony stage as its own opener, so a reviewer can jump straight to the
 * state they care about instead of clicking through the flow to reach it.
 */
function CeremonyStates() {
  const [stage, setStage] = useState<CeremonyStageId | null>(null);
  // Real commitments, so the split stage's publish panel and the cards stage's
  // split id are the same objects the ceremony actually produces.
  const split = useDemoSplit();
  const [params, setParams] = useState({ threshold: 2, shares: 3, label: "Board key", qr: true });
  const digest = (c: string) => c.repeat(64);

  const stages: { id: CeremonyStageId; note: string }[] = [
    { id: "setup", note: "quorum pickers + validation" },
    { id: "split", note: "digest of the secret + commitments to publish" },
    { id: "verify", note: "digests match" },
    { id: "cards", note: "masked cards, reveal gated, check-a-card" },
    { id: "receipt", note: "signing key picker + receipt" },
  ];

  return (
    <>
      <div className="flex flex-wrap gap-2">
        {stages.map((s) => (
          <Button key={s.id} variant="secondary" onClick={() => setStage(s.id)}>
            {s.id} — {s.note}
          </Button>
        ))}
        <Button
          variant="secondary"
          onClick={() => {
            setParams((p) => ({ ...p, threshold: 5, shares: 3 }));
            setStage("setup");
          }}
        >
          setup — invalid quorum (5 of 3)
        </Button>
      </div>

      <CeremonySheet
        open={stage != null}
        onOpenChange={(o) => setStage(o ? stage : null)}
        stage={stage ?? "setup"}
        onStage={setStage}
        threshold={params.threshold}
        shares={params.shares}
        label={params.label}
        qr={params.qr}
        onParams={(patch) => setParams((p) => ({ ...p, ...patch }))}
        signingKeys={
          stage === "receipt"
            ? [{ fingerprint: "AABBCCDDEEFF00112233445566778899AABBCCDD", uid: "you@example.org" }]
            : []
        }
        signWith=""
        onSignWith={() => {}}
        onRunStage={() => {}}
        runState="idle"
        expectedDigest={stage === "setup" ? "" : digest("a")}
        recoveredDigest={stage === "verify" || stage === "cards" ? digest("a") : ""}
        shareArtifacts={demoShareArtifacts}
        commitmentsText={stage === "setup" ? "" : split.commitments}
        receiptText={
          stage === "receipt"
            ? '{"cells":[{"index":0,"outputs":[{"digest":"aaaa…","label":"share"}]}],"kind":"basilisk.run-receipt","v":1}'
            : ""
        }
      />
    </>
  );
}

/**
 * Catalog fixture: what `sss.split … | blip39 | foreach { - out @share | qr }`
 * leaves behind. Deliberately fake words — a catalog page must never hold a
 * real mnemonic, even a throwaway one.
 */
const demoShareArtifacts = [
  {
    label: "Share 1",
    filename: "share-1.txt",
    role: "share",
    sensitive: true,
    shareIndex: 1,
    traits: { shareOf: 1, threshold: 2 },
    content:
      "sample words only ceremony fixture never real mnemonic catalog page eleven twelve",
  },
  {
    label: "Share 1 QR",
    filename: "share-1.svg",
    role: "qr",
    mime: "image/svg+xml",
    shareIndex: 1,
    content: demoQrSvg(1),
  },
  {
    label: "Share 2",
    filename: "share-2.txt",
    role: "share",
    sensitive: true,
    shareIndex: 2,
    traits: { shareOf: 2, threshold: 2 },
    content:
      "second sample words only ceremony fixture never real mnemonic catalog eleven twelve",
  },
  {
    label: "Share 2 QR",
    filename: "share-2.svg",
    role: "qr",
    mime: "image/svg+xml",
    shareIndex: 2,
    content: demoQrSvg(2),
  },
  {
    label: "Share 3",
    filename: "share-3.txt",
    role: "share",
    sensitive: true,
    shareIndex: 3,
    traits: { shareOf: 3, threshold: 2 },
    content:
      "third sample words only ceremony fixture never real mnemonic catalog eleven twelve",
  },
  {
    label: "Share 3 QR",
    filename: "share-3.svg",
    role: "qr",
    mime: "image/svg+xml",
    shareIndex: 3,
    content: demoQrSvg(3),
  },
];

/** A QR-shaped placeholder — enough to check the card's layout and print size. */
function demoQrSvg(seed: number): string {
  const cells: string[] = [];
  for (let y = 0; y < 12; y++) {
    for (let x = 0; x < 12; x++) {
      if ((x * 7 + y * 5 + seed * 3) % 3 === 0) {
        cells.push(`<rect x="${x}" y="${y}" width="1" height="1"/>`);
      }
    }
  }
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 12 12" fill="currentColor">${cells.join(
    ""
  )}</svg>`;
}

installBootDiagnostics();
const host = document.getElementById("toolkit-widgets-root");
if (!host) throw new Error("#toolkit-widgets-root missing");
createRoot(host).render(<CatalogApp />);
