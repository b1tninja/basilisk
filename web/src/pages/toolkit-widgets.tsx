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
  JwtArtifact,
  NetworkArtifact,
  SessionStrip,
  TypeCard,
  CellTypeErrors,
  CryptoProfileControl,
  GpgKeyBinder,
  ConnectionsPanel,
  ShareCards,
  CeremonySheet,
} from "../toolkit/widgets/index";
import { getTypeMeta } from "../lib/toolkit/type-registry.js";
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
            <div>
              <StateLabel>stats/data-channel — back-pressure bar (§30d)</StateLabel>
              <NetworkArtifact
                netType="stats"
                netKind="data-channel"
                data={{
                  peers: [
                    { peer: "AABBCCDDEEFF0011", readyState: "open", bufferedAmount: 655360, bufferedAmountLowThreshold: 65535, ordered: true, messagesSent: 42, messagesReceived: 17, backPressured: true },
                    { peer: "1122334455667788", readyState: "open", bufferedAmount: 0, bufferedAmountLowThreshold: 65535, ordered: false, messagesSent: 3, messagesReceived: 3 },
                  ],
                }}
              />
            </div>
            <div>
              <StateLabel>stats/quality — live RTT / loss / throughput (§29d)</StateLabel>
              <NetworkArtifact
                netType="stats"
                netKind="quality"
                data={{ peers: [{ peer: "AABBCCDDEEFF0011", rttMs: 38, packetLossPct: 0.2, bytesSent: 4300, bytesReceived: 12800 }] }}
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
              <StateLabel>endpoint — stun.check discovered address</StateLabel>
              <NetworkArtifact
                netType="endpoint"
                data={{ ok: true, publicAddress: "203.0.113.9:60122", ms: 127, note: "STUN reachable — reflexive address discovered" }}
              />
            </div>
            <div>
              <StateLabel>certificate — DTLS identity (§29a)</StateLabel>
              <NetworkArtifact
                netType="certificate"
                data={{
                  algorithm: "ECDSA/P-256",
                  expires: "2026-08-29T00:00:00.000Z",
                  fingerprints: [{ algorithm: "sha-256", value: "3F:2A:9C:1B:44:D0:81:E6:B8" }],
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
            Key export — Publish opens a confirm popover; already-published row shows
            @slot + a link icon that copies the directory URL
          </StateLabel>
          <div className="max-w-md">
            <OutputList
              outputs={[
                {
                  label: "dana.pub.asc",
                  kind: "key",
                  sizeBytes: 1843,
                  onCopy: () => {},
                  publishable: true,
                  publishConfirmLabel: "3F2A…C81",
                  onPublish: () => {},
                },
                {
                  label: "sam.pub.asc",
                  kind: "key",
                  sizeBytes: 1798,
                  onCopy: () => {},
                  publishedAs: "@C81FSAM",
                  directoryUrl: "https://example.org/pks/lookup?op=get&search=0xSAM",
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
          title="CellTypeErrors — type failures as a surface, not a runtime throw (§33c)"
        >
          <p className="-mt-1 mb-1 text-[11px] text-[var(--muted-foreground)]">
            Sits under the chip row, where RunBar&rsquo;s blocked state already lives — a
            banner rather than a tooltip, because a message you must hover to find is not
            one you read before pressing Run. The fix hint only appears when the registry
            knows an op that actually produces the wanted type.
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
      </div>
    </TooltipProvider>
  );
}

/**
 * Each ceremony stage as its own opener, so a reviewer can jump straight to the
 * state they care about instead of clicking through the flow to reach it.
 */
function CeremonyStates() {
  const [stage, setStage] = useState<CeremonyStageId | null>(null);
  const [params, setParams] = useState({ threshold: 2, shares: 3, label: "Board key", qr: true });
  const digest = (c: string) => c.repeat(64);

  const stages: { id: CeremonyStageId; note: string }[] = [
    { id: "setup", note: "quorum pickers + validation" },
    { id: "split", note: "digest of the secret, no secret" },
    { id: "verify", note: "digests match" },
    { id: "cards", note: "masked cards, reveal gated" },
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
