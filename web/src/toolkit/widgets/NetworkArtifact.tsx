import type { ReactNode } from "react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/cn";
import {
  connStateReadout,
  expiryNote,
  linkOriginNote,
  sdpReadout,
  stunReachability,
} from "../../lib/toolkit/artifact-readouts.js";

/**
 * Manager widgets for network/WebRTC artifacts (design v2 §23a/23b/26a/26b/
 * 29d/30d).
 *
 * The pipeline value's *type* is the renderer discriminator — that's the
 * payoff of these being real types rather than JSON text. A `candidate`
 * artifact draws the typed candidate list, `stats/candidate-pairs` draws the
 * pair matrix, `connstate` draws the state-machine strip.
 *
 * Every one of these is a read-out of data the op already produced; none of
 * them invent browser capabilities. Where a design shows an action (23b's
 * "Configure TURN" fallback CTA), it's wired to the same handler the plain
 * OutputList row uses.
 */

/* ────────────────────────────── shared chrome ────────────────────────────── */

/** ICE candidate types, colored by how far the packet has to travel. */
const CANDIDATE_TONE: Record<string, NetTone> = {
  host: "brand",
  prflx: "caret",
  srflx: "caret",
  relay: "warn",
};

/**
 * Badge tones, as *names* rather than colours.
 *
 * This used to be a `tone: string` holding `"var(--brand)"` and friends, which
 * forced a style prop — an element.style write `style-src 'self'` refuses in
 * production. The values were only ever six tokens, so naming them lets the
 * stylesheet enumerate them, and the union means a typo is a type error rather
 * than an invisible transparent badge.
 */
export type NetTone = "brand" | "caret" | "muted" | "error" | "warn" | "decode";

const PAIR_STATE_TONE: Record<string, NetTone> = {
  succeeded: "brand",
  "in-progress": "caret",
  waiting: "muted",
  failed: "error",
  frozen: "muted",
};

/**
 * `faint` is the *absent* mark — a candidate type that was not gathered, or a
 * count of zero. It fades the badge's tint and nothing else.
 *
 * It exists because the whole row used to carry `opacity-45`, which took the
 * sentence beside the badge down with it: "none gathered — no TURN configured"
 * measured 2.16:1 in light and 2.39:1 in dark, making the panel's actual
 * diagnosis the least readable text on it. 26a's rule is that an absent type
 * is informational rather than an error, and a muted badge says that on its
 * own; the explanation has to stay legible to be worth writing.
 */
function TypeBadge({ label, tone, faint }: { label: string; tone: NetTone; faint?: boolean }) {
  return (
    <span
      className="net-badge shrink-0 rounded-[3px] px-[5px] py-[2px] text-[9px] font-medium uppercase tracking-wider"
      data-tone={tone}
      data-faint={faint ? "1" : undefined}
    >
      {label}
    </span>
  );
}

function Row({
  children,
  mark,
  ...rest
}: { children: ReactNode; mark?: boolean } & Record<string, unknown>) {
  return (
    <div
      className={cn(
        "net-row flex items-center gap-2.5 border-b border-[color-mix(in_srgb,var(--border)_45%,transparent)] px-2.5 py-[6px] last:border-b-0",
        mark && "net-row-mark"
      )}
      {...rest}
    >
      {children}
    </div>
  );
}

function Empty({ children }: { children: ReactNode }) {
  return (
    <p className="px-2.5 py-2 text-[10.5px] italic text-[var(--muted-foreground)]">
      {children}
    </p>
  );
}

function fmtBytes(n: number): string {
  if (!n) return "0 B";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

/* ─────────────────────── candidate list (23a / 26a) ─────────────────────── */

type Candidate = {
  type: string;
  address: string;
  port: number;
  protocol: string;
  relatedAddress?: string | null;
  ts?: number;
};

function CandidateList({ data }: { data: any }) {
  const candidates: Candidate[] = Array.isArray(data?.candidates) ? data.candidates : [];
  const byType: Record<string, number> = data?.byType || {};
  // 26a: all four MDN types get a row — a missing one is informational, not a
  // failure, so its badge fades rather than the row being hidden or reddened.
  const order = ["host", "prflx", "srflx", "relay"];
  return (
    <div>
      {order.map((t) => {
        const rows = candidates.filter((c) => c.type === t);
        if (!rows.length) {
          return (
            // Not `dim`. The badge fades; the sentence does not — see
            // `TypeBadge`'s `faint`. This row is where "no TURN is configured"
            // gets said, which is the answer on the screen a user opens when a
            // call did not happen.
            <Row key={t} data-absent>
              <TypeBadge label={t} tone="muted" faint />
              <span className="text-[10.5px] italic leading-snug text-[var(--muted-foreground)]">
                {t === "relay"
                  ? // Not "no TURN configured". A relay was verified end to end
                    // against a live coturn on the day this was written, and the
                    // same run showed that a wrong password and a dead server
                    // both yield exactly this empty result — only
                    // `icecandidateerror` code 401 tells them apart, and nothing
                    // reads it. The gather's output carries no ICE server list,
                    // so the panel cannot know which of the three happened and
                    // says so rather than picking the flattering one.
                    "no relay route — either no TURN is configured, or one is and it refused the credential or never answered. All three arrive here as nothing."
                  : t === "prflx"
                    ? "none — peer-reflexive only appears during negotiation"
                    : "none gathered"}
              </span>
            </Row>
          );
        }
        return rows.map((c, i) => (
          <Row key={`${t}-${i}`}>
            <TypeBadge label={t} tone={CANDIDATE_TONE[t] || "muted"} />
            <code className="min-w-0 flex-1 truncate font-mono text-[11px] text-[var(--foreground)]">
              {c.address ? `${c.address}:${c.port}` : `:${c.port}`}
              {!c.address ? (
                <span className="ml-1 text-[9.5px] italic text-[var(--muted-foreground)]">
                  address redacted (mDNS)
                </span>
              ) : null}
            </code>
            {c.relatedAddress ? (
              <span className="shrink-0 font-mono text-[9.5px] text-[var(--muted-foreground)]">
                via {c.relatedAddress}
              </span>
            ) : null}
            <span className="shrink-0 rounded-[3px] border border-[var(--border)] px-[4px] py-[1px] font-mono text-[9px] text-[var(--muted-foreground)]">
              {c.protocol}
            </span>
          </Row>
        ));
      })}
      <div className="flex items-center gap-2 px-2.5 py-[6px] text-[10px] text-[var(--muted-foreground)]">
        <span>
          {candidates.length} candidate{candidates.length === 1 ? "" : "s"}
        </span>
        {data?.ms != null ? <span>· {data.ms}ms</span> : null}
        <span className="ml-auto font-mono">
          {order
            .filter((t) => byType[t])
            .map((t) => `${t}×${byType[t]}`)
            .join("  ") || "—"}
        </span>
      </div>
    </div>
  );
}

/* ─────────────────── candidate-pair matrix (23b / 26b) ─────────────────── */

function PairMatrix({ data, onConfigureTurn }: { data: any; onConfigureTurn?: () => void }) {
  const peers: any[] = Array.isArray(data?.peers) ? data.peers : [];
  if (!peers.length) return <Empty>No peers — pairs are only checked once a peer joins.</Empty>;
  return (
    <div>
      {peers.map((p, pi) => (
        <div key={pi}>
          <div className="flex items-center gap-2 border-b border-[color-mix(in_srgb,var(--border)_45%,transparent)] px-2.5 py-[6px]">
            <code className="font-mono text-[10px] text-[var(--muted-foreground)]">
              {String(p.peer || "").slice(0, 8)}…
            </code>
            {/* 26b: role is protocol-assigned and informational only. Chromium
                leaves it null, so we say so rather than showing a blank chip. */}
            {p.role ? (
              <TypeBadge label={p.role} tone="caret" />
            ) : (
              <span className="text-[9.5px] italic text-[var(--muted-foreground)]">
                role not reported by this browser
              </span>
            )}
            <span className="ml-auto text-[10px] text-[var(--muted-foreground)]">
              {p.pairs?.length || 0} pair{p.pairs?.length === 1 ? "" : "s"}
            </span>
          </div>
          {!p.pairs?.length ? (
            <Empty>No candidate pairs yet.</Empty>
          ) : (
            p.pairs.map((pair: any, i: number) => (
              // 23b asked for the whole graph, with the losers at 50% opacity
              // so the nominated pair stands out. Measured, 50% put a pair
              // label at 3.16:1 — visible only in the sense that it is still
              // in the DOM, which is the opposite of "never hidden: a user
              // debugging a slow connection needs the whole graph". The
              // hierarchy is the same either way, so the winner is marked *up*
              // with a tint instead of every loser being marked down.
              <Row key={i} mark={pair.nominated}>
                <code className="min-w-0 flex-1 truncate font-mono text-[10.5px] text-[var(--foreground)]">
                  {pair.local?.label || "?"}
                  <span className="mx-1 text-[var(--muted-foreground)]">→</span>
                  {pair.remote?.label || "?"}
                </code>
                {pair.rttMs != null ? (
                  <span className="shrink-0 font-mono text-[9.5px] text-[var(--muted-foreground)]">
                    {pair.rttMs}ms
                  </span>
                ) : null}
                {pair.nominated ? (
                  <TypeBadge label="✓ nominated" tone="brand" />
                ) : (
                  <TypeBadge
                    label={pair.state}
                    tone={PAIR_STATE_TONE[pair.state] || "muted"}
                  />
                )}
              </Row>
            ))
          )}
        </div>
      ))}
      {/* 23b: when every pair fails the fallback is a relay — and the reason
          is the part worth writing down, because "every pair failed" is what
          the reader can already see. The button is kept beside the sentence
          rather than under it so the two are read as one instruction. */}
      {data?.allFailed && onConfigureTurn ? (
        <div className="flex flex-wrap items-center gap-2 px-2.5 py-2">
          <span className="min-w-0 flex-1 text-[10.5px] leading-snug text-[var(--muted-foreground)]">
            <strong className="font-semibold text-[var(--warn)]">
              No route between these two ends.
            </strong>{" "}
            Every candidate pair was checked and none succeeded, so neither peer
            can reach the other directly — a relay has to carry the traffic.
          </span>
          <Button
            size="sm"
            className="ml-auto h-[22px] rounded-[5px] bg-[var(--warn)] px-2 text-[10px] font-bold text-[#1a1405] hover:opacity-90"
            onClick={onConfigureTurn}
          >
            Configure TURN
          </Button>
        </div>
      ) : null}
    </div>
  );
}

/* ─────────────────── connection-state strip (30d) ─────────────────── */

/**
 * The panel a user opens when a call did not happen — so it leads with the
 * verdict, not with the enum.
 *
 * The old strip laid `new · connecting · connected · disconnected · closed`
 * out as one five-step track and bolded whichever one `connectionState`
 * matched. Two things were wrong with that and both showed up the moment a
 * connection actually failed:
 *
 *  - `"failed"` is a real `RTCPeerConnection.connectionState` and was not on
 *    the track, so `indexOf` returned `-1`, nothing was marked reached and
 *    nothing was bolded — **a failed connection drew identically to one that
 *    had never started.**
 *  - `disconnected` and `closed` are outcomes, not milestones. Drawing them in
 *    line after `connected` said a healthy connection is progressing toward
 *    being closed.
 *
 * So the track is the three stages that really are a sequence, an outcome is a
 * terminal chip beside it, and `connStateReadout` — which is where the verdict
 * and the next step are written and tested — supplies both. The bar is
 * `aria-hidden`: it is a picture of the headline above it, and a screen reader
 * that read five stage words with only a font weight to say which one is
 * current learned nothing (WCAG 1.3.1).
 */
function ConnStateStrip({ data }: { data: any }) {
  const peers: any[] = Array.isArray(data?.peers) ? data.peers : [];
  if (!peers.length) return <Empty>No peers in this exchange.</Empty>;
  return (
    <div>
      {peers.map((p, i) => {
        const read = connStateReadout(p);
        return (
          <div
            key={i}
            className="border-b border-[color-mix(in_srgb,var(--border)_45%,transparent)] px-2.5 py-2 last:border-b-0"
            data-conn-state={p.connectionState || "new"}
          >
            <div className="mb-1.5 flex flex-wrap items-center gap-x-2 gap-y-1">
              <code className="font-mono text-[10px] text-[var(--muted-foreground)]">
                {String(p.peer || "").slice(0, 8)}…
              </code>
              <span className="net-headline text-[11px] font-semibold" data-tone={read.tone}>
                {read.headline}
              </span>
              {read.terminal ? (
                <TypeBadge label={read.terminal.name} tone={read.terminal.tone} />
              ) : null}
              {p.verified ? <TypeBadge label="verified" tone="brand" /> : null}
              <span className="ml-auto font-mono text-[9.5px] text-[var(--muted-foreground)]">
                ice {p.iceConnectionState} · sig {p.signalingState} · ch {p.channelState}
              </span>
            </div>
            <div className="flex items-center gap-1" aria-hidden>
              {read.stages.map((s) => (
                <span
                  key={s.name}
                  className="net-stage h-[3px] flex-1 rounded-full"
                  data-stage={s.state}
                  data-tone={read.tone}
                />
              ))}
              {read.terminal ? (
                <span
                  className="net-stage h-[3px] w-[22%] rounded-full"
                  data-stage="terminal"
                  data-tone={read.terminal.tone}
                />
              ) : null}
            </div>
            <div className="mt-1 flex text-[9px] text-[var(--muted-foreground)]" aria-hidden>
              {read.stages.map((s) => (
                <span
                  key={s.name}
                  className={cn(
                    "flex-1 text-center",
                    s.state === "current" && "font-bold text-[var(--foreground)]"
                  )}
                >
                  {s.name}
                </span>
              ))}
              {read.terminal ? (
                <span className="w-[22%] text-center font-bold text-[var(--foreground)]">
                  {read.terminal.name}
                </span>
              ) : null}
            </div>
            <Diagnosis why={read.why} next={read.next} />
          </div>
        );
      })}
    </div>
  );
}

/**
 * Why it did not connect, and what to do — the two sentences every panel in
 * this file exists to deliver and none of them used to.
 *
 * Both are optional and both are omitted when the answer is "nothing is
 * wrong": a healthy connection that explains itself anyway is a panel nobody
 * reads when it finally has something to say.
 */
function Diagnosis({ why, next }: { why?: string | null; next?: string | null }) {
  if (!why && !next) return null;
  return (
    <div className="mt-1.5 flex flex-col gap-1">
      {why ? (
        <p className="text-[10.5px] leading-snug text-[var(--muted-foreground)]">{why}</p>
      ) : null}
      {next ? (
        <p className="net-next text-[10.5px] leading-snug">
          <strong className="font-semibold">Next</strong> {next}
        </p>
      ) : null}
    </div>
  );
}

/* ───────────────────────── stats panels (29d / 30d) ───────────────────────── */

function QualityStats({ data }: { data: any }) {
  const peers: any[] = Array.isArray(data?.peers) ? data.peers : [];
  if (!peers.length) return <Empty>No connected peers to measure.</Empty>;
  const notes: string[] = Array.isArray(data?.notes) ? data.notes : [];
  return (
    <div>
      {peers.map((p, i) => (
        <Row key={i}>
          <code className="min-w-0 flex-1 truncate font-mono text-[10.5px]">
            {String(p.peer || "").slice(0, 8)}…
          </code>
          <span className="shrink-0 font-mono text-[10px] text-[var(--caret)]">
            {p.rttMs != null ? `${p.rttMs}ms rtt` : "— rtt"}
          </span>
          {/* Words, not a dash. The dash next door is the right shape for RTT,
              which is a real measurement that is merely not in yet — it fills
              in a beat later. Loss is never measurable on an SCTP-only
              transport, so a placeholder that looks like a pending number would
              have the reader waiting for one. `?? 0` was worse still: it
              rendered the absence as a confident "0% loss" on the one panel
              you open when a call is going badly. */}
          {p.packetLossPct != null ? (
            <span className="shrink-0 font-mono text-[10px] text-[var(--muted-foreground)]">
              {p.packetLossPct}% loss
            </span>
          ) : (
            <span className="shrink-0 text-[10px] italic text-[var(--muted-foreground)]">
              loss not measured
            </span>
          )}
          <span className="shrink-0 font-mono text-[10px] text-[var(--muted-foreground)]">
            ↑{fmtBytes(p.bytesSent || 0)} ↓{fmtBytes(p.bytesReceived || 0)}
          </span>
        </Row>
      ))}
      {notes.map((n, i) => (
        <p key={i} className="px-2.5 py-[6px] text-[10px] text-[var(--muted-foreground)]">
          {n}
        </p>
      ))}
    </div>
  );
}

function ChannelStats({ data }: { data: any }) {
  const peers: any[] = Array.isArray(data?.peers) ? data.peers : [];
  if (!peers.length) return <Empty>No data channels open.</Empty>;
  return (
    <div>
      {peers.map((p, i) => {
        // 30d: back-pressure against the low-water mark, using 20b's bar.
        const threshold = Number(p.bufferedAmountLowThreshold) || 65535;
        const pct = Math.min(100, Math.round((Number(p.bufferedAmount) / threshold) * 100));
        return (
          <div
            key={i}
            className="border-b border-[color-mix(in_srgb,var(--border)_45%,transparent)] px-2.5 py-2 last:border-b-0"
          >
            <div className="flex items-center gap-2">
              <code className="min-w-0 flex-1 truncate font-mono text-[10.5px]">
                {String(p.peer || "").slice(0, 8)}…
              </code>
              <TypeBadge
                label={p.readyState}
                tone={p.readyState === "open" ? "brand" : "muted"}
              />
              {p.backPressured ? <TypeBadge label="back-pressure" tone="warn" /> : null}
            </div>
            {/* Per-peer value, so no single custom property can serve a list
                of these, and a width style prop is what the CSP refuses. The
                fill is quantized to 5% and enumerated in CSS instead.
                Deliberately not a native <progress>: its fill can only be
                styled through vendor pseudo-elements, and `getComputedStyle`
                cannot read those back (verified — a probe set to rgb(1,2,3)
                reads as the host's background), so the one construct we could
                not measure is the one guarding a diagnostic that matters most
                when things are already going wrong. ARIA carries the real
                value; the bar is just its picture. */}
            <div
              className="mt-1.5 h-[3px] overflow-hidden rounded-full bg-[var(--surface-raised)]"
              role="progressbar"
              aria-valuenow={Math.round(pct)}
              aria-valuemin={0}
              aria-valuemax={100}
              aria-label={`buffered ${fmtBytes(p.bufferedAmount || 0)}`}
            >
              <div
                className="net-buffer-fill h-full transition-[width]"
                data-tone={p.backPressured ? "warn" : "caret"}
                data-fill={Math.round(Math.max(0, Math.min(100, pct)) / 5) * 5}
              />
            </div>
            <div className="mt-1 flex gap-3 font-mono text-[9.5px] text-[var(--muted-foreground)]">
              <span>buffered {fmtBytes(p.bufferedAmount || 0)}</span>
              <span>
                msgs ↑{p.messagesSent || 0} ↓{p.messagesReceived || 0}
              </span>
              <span className="ml-auto">{p.ordered === false ? "unordered" : "ordered"}</span>
            </div>
          </div>
        );
      })}
    </div>
  );
}

/* ──────────────────── endpoint / certificate / sdp ──────────────────── */

function EndpointPanel({ data }: { data: any }) {
  // Two shapes share the `endpoint` type: rtc.ice's server list and
  // stun.check's discovered reflexive address.
  if (Array.isArray(data?.iceServers)) {
    return (
      <div>
        {data.iceServers.map((s: any, i: number) => {
          const url = String(Array.isArray(s.urls) ? s.urls[0] : s.urls);
          const isTurn = /^turns?:/i.test(url);
          return (
            <Row key={i}>
              <TypeBadge
                label={isTurn ? "turn" : "stun"}
                tone={isTurn ? "warn" : "caret"}
              />
              <code className="min-w-0 flex-1 truncate font-mono text-[10.5px]">{url}</code>
              {s.username ? (
                <span className="shrink-0 font-mono text-[9.5px] text-[var(--muted-foreground)]">
                  as {s.username}
                </span>
              ) : null}
              {isTurn ? <TypeBadge label="credential bound" tone="brand" /> : null}
            </Row>
          );
        })}
      </div>
    );
  }
  // `stun.check` has always counted the candidate mix it gathered and this
  // panel used to throw it away, so the one screen a "blocked" verdict sends
  // you to could not say *what* it did get. Which types arrived is the whole
  // diagnosis, and `stunReachability` is where that reading is written and
  // tested — host-only means the STUN round trip never completed, host+srflx
  // means STUN is not the problem, and those are two different afternoons.
  const read = stunReachability(data);
  const byType: Record<string, number> = data?.candidates || {};
  // Only the two types this op can actually observe. `relay` used to be drawn
  // here as a third count, and it was a constant rather than a measurement:
  // `stun.check` refuses any `server=` that is not `stun:`/`stuns:` and builds
  // its peer connection with no username and no credential, so no allocation
  // is ever attempted and the count is always zero. Measured against a live
  // coturn that was relaying for two peers at the time — still zero, because
  // the op never asked. Drawn beside two real counts as `RELAY ×0` that reads
  // as "TURN was checked and is missing", on the one screen a user lands on
  // when a connection fails. The row stays, because its absence is a fair
  // question to have, but it says it was not probed and names the op that does.
  const types = ["host", "srflx"];
  return (
    <div>
      <Row>
        <TypeBadge label={read.verdict} tone={read.tone} />
        <code className="min-w-0 flex-1 truncate font-mono text-[11px]">
          {data?.publicAddress || "no public address discovered"}
        </code>
        {data?.ms != null ? (
          <span className="shrink-0 font-mono text-[9.5px] text-[var(--muted-foreground)]">
            {data.ms}ms
          </span>
        ) : null}
      </Row>
      {data?.candidates ? (
        <Row>
          <span className="shrink-0 text-[10px] text-[var(--muted-foreground)]">
            gathered
          </span>
          <span className="flex min-w-0 flex-1 flex-wrap items-center gap-1.5">
            {/* A zero count is dimmed on the *badge* only. Dropping the whole
                pair to 45% measured 1.99:1 against the panel, and the zeroes
                are the diagnosis — the least legible thing here was the thing
                the row exists to report (WCAG 1.4.3). Same fix in the
                candidate list's absent-type rows. */}
            {types.map((t) => (
              <span key={t} className="flex items-center gap-1">
                <TypeBadge
                  label={t}
                  tone={byType[t] ? CANDIDATE_TONE[t] : "muted"}
                  faint={!byType[t]}
                />
                <span className="font-mono text-[9.5px] text-[var(--muted-foreground)]">
                  ×{byType[t] || 0}
                </span>
              </span>
            ))}
            <span className="flex items-center gap-1">
              <TypeBadge label="relay" tone="muted" faint />
              <span className="text-[9.5px] italic text-[var(--muted-foreground)]">
                not probed — see rtc.gather
              </span>
            </span>
          </span>
        </Row>
      ) : null}
      <div className="px-2.5 py-[6px]">
        <Diagnosis why={read.why} next={read.next} />
      </div>
    </div>
  );
}

/**
 * An SDP blob, and the thing about it nobody could see (§30d).
 *
 * This was a bare `<pre>`: 700 bytes of `a=` lines with the DTLS fingerprint
 * buried at line 14, and — far worse — no hint that the transport it describes
 * is already gone. `rtc.offer` and `rtc.answer` each close their
 * `RTCPeerConnection` in a `finally` before returning, which the first run
 * against two real browsers made plain, so the hand-carried exchange the two
 * shipped SDP templates describe **cannot complete**. A panel that renders
 * that blob beautifully and lets the reader try anyway has failed the only
 * question it is ever asked.
 *
 * The header is the three things a human opens an SDP for — the DTLS
 * fingerprint, the candidates, the transport line. The limit is stated once,
 * from `sdpReadout`, above the raw text rather than below it: a caveat under
 * 700 bytes of `a=` lines is a caveat nobody reaches.
 */
function SdpPanel({ content }: { content?: string }) {
  const read = sdpReadout(content || "");
  return (
    <div>
      <Row>
        <TypeBadge label="sdp" tone="caret" />
        {read.setup ? (
          <span className="shrink-0 font-mono text-[9.5px] text-[var(--muted-foreground)]">
            setup:{read.setup}
          </span>
        ) : null}
        {read.transport ? (
          <code className="min-w-0 flex-1 truncate font-mono text-[10px] text-[var(--muted-foreground)]">
            {read.transport}
          </code>
        ) : null}
        <span className="ml-auto shrink-0 font-mono text-[9.5px] text-[var(--muted-foreground)]">
          {read.candidates.length
            ? read.candidates.map((c) => `${c.type}×${c.count}`).join("  ")
            : "no candidates"}
        </span>
      </Row>
      {read.fingerprint ? (
        <Row>
          <span className="shrink-0 font-mono text-[9.5px] text-[var(--muted-foreground)]">
            {read.fingerprint.algorithm}
          </span>
          <code className="min-w-0 flex-1 break-all font-mono text-[10px] text-[var(--foreground)]">
            {read.fingerprint.value}
          </code>
        </Row>
      ) : null}
      <p className="net-limit px-2.5 py-[7px] text-[10.5px] leading-snug" data-sdp-limit>
        {read.note}
      </p>
      <pre className="max-h-[320px] overflow-auto whitespace-pre-wrap break-all px-2.5 py-2 font-mono text-[10px] leading-relaxed text-[var(--muted-foreground)]">
        {content || ""}
      </pre>
    </div>
  );
}

function CertificatePanel({ data }: { data: any }) {
  const prints: any[] = Array.isArray(data?.fingerprints) ? data.fingerprints : [];
  /**
   * The same verdict the key card gets, for the same reason (§48b) — and this
   * is the panel where a bare date is *least* defensible: `RTCCertificate`
   * expires about thirty days out by default, so the answer can change inside
   * the life of one debugging session, and it sits permanently inside the
   * window `expiryNote` speaks in.
   *
   * The stored value is an ISO string (`rtc-ops.js` serializes it), which is
   * why `expiryInstant` normalizes rather than each caller parsing — this panel
   * doing its own `Date.parse` is precisely the second derivation the boundary
   * calls a bug.
   */
  const expiry = expiryNote(data?.expires);
  return (
    <div>
      <Row>
        <TypeBadge label="dtls" tone="decode" />
        <code className="min-w-0 flex-1 truncate font-mono text-[10.5px]">{data?.algorithm}</code>
        {data?.expires ? (
          <span className="shrink-0 font-mono text-[9.5px] text-[var(--muted-foreground)]">
            expires {String(data.expires).slice(0, 10)}
            {expiry ? (
              <>
                {" · "}
                <span className="artifact-expiry" data-expiry-tone={expiry.severity}>
                  {expiry.text}
                </span>
              </>
            ) : null}
          </span>
        ) : null}
      </Row>
      {prints.map((f, i) => (
        <Row key={i}>
          <span className="shrink-0 font-mono text-[9.5px] text-[var(--muted-foreground)]">
            {f.algorithm}
          </span>
          <code className="min-w-0 flex-1 break-all font-mono text-[10px] text-[var(--foreground)]">
            {f.value}
          </code>
        </Row>
      ))}
      {data?.note ? (
        <p className="px-2.5 py-[6px] text-[10px] italic text-[var(--muted-foreground)]">
          {data.note}
        </p>
      ) : null}
    </div>
  );
}

function SessionPanel({ data }: { data: any }) {
  const audience: string[] = Array.isArray(data?.audience) ? data.audience : [];
  return (
    <div>
      <Row>
        <TypeBadge label={data?.role || "session"} tone="caret" />
        <code className="min-w-0 flex-1 truncate font-mono text-[10.5px]">room {data?.room}</code>
        <span className="shrink-0 font-mono text-[10px] text-[var(--brand)]">
          {data?.connected ?? 0}/{Math.max(0, audience.length - 1)} connected
        </span>
      </Row>
      {audience.map((f, i) => (
        <Row key={i}>
          <code className="min-w-0 flex-1 truncate font-mono text-[10px] text-[var(--muted-foreground)]">
            {f.slice(0, 16)}…
          </code>
        </Row>
      ))}
    </div>
  );
}

/**
 * `peer.wait`'s live data channel (§56).
 *
 * The one question a reader has here that the quorum session panel never has
 * to answer: *is the far end anybody in particular?* It is not, on a direct
 * link — DTLS encrypts the wire and nothing proves who received the offer. The
 * sentence comes from `linkOriginNote`, so this panel and the Connections tab
 * cannot word that difference two ways.
 */
function ChannelPanel({ data }: { data: any }) {
  const origin = String(data?.origin || "peer");
  const note = linkOriginNote(origin);
  return (
    <div>
      <Row>
        <TypeBadge label="channel" tone="caret" />
        <code className="min-w-0 flex-1 truncate font-mono text-[10.5px]">
          {String(data?.link || "")}
        </code>
        <span className="peer-verdict shrink-0" data-verdict={note.tone}>
          {note.label}
        </span>
        <span className="shrink-0 font-mono text-[10px] text-[var(--muted-foreground)]">
          {String(data?.state || "")}
        </span>
      </Row>
      <Row>
        <span className="min-w-0 flex-1 text-[10.5px] text-[var(--muted-foreground)]">
          {note.why}
        </span>
      </Row>
      <Row>
        <span className="shrink-0 font-mono text-[10px] text-[var(--muted-foreground)]">
          label {String(data?.label || "—")}
        </span>
        <span className="shrink-0 font-mono text-[10px] text-[var(--muted-foreground)]">
          {data?.ordered === false ? "unordered" : "ordered"}
        </span>
        {data?.via ? (
          <span className="shrink-0 font-mono text-[10px] text-[var(--muted-foreground)]">
            via {String(data.via)}
          </span>
        ) : null}
      </Row>
    </div>
  );
}

/* ────────────────────────────── dispatcher ────────────────────────────── */

export type NetworkArtifactProps = {
  /** Pipeline type — the renderer discriminator. */
  netType: string;
  /** Refinement within the type (e.g. "candidate-pairs", "quality"). */
  netKind?: string;
  /** Structured value from the op. */
  data: unknown;
  /** Raw serialized form, for types that are text on the wire (SDP). */
  content?: string;
  onConfigureTurn?: () => void;
  className?: string;
};

/** True when this artifact has a richer rendering than a JSON preview. */
export function hasNetworkRenderer(netType?: string): boolean {
  return (
    !!netType &&
    [
      "candidate",
      "stats",
      "connstate",
      "endpoint",
      "certificate",
      "session",
      "channel",
      "sdp",
    ].includes(netType)
  );
}

/**
 * Render a network artifact as its manager widget. Falls back to nothing when
 * the type has no richer view — callers keep their plain preview for that.
 */
export function NetworkArtifact({
  netType,
  netKind,
  data,
  content,
  onConfigureTurn,
  className,
}: NetworkArtifactProps) {
  let body: ReactNode = null;
  switch (netType) {
    case "candidate":
      body = <CandidateList data={data} />;
      break;
    case "stats":
      body =
        netKind === "candidate-pairs" ? (
          <PairMatrix data={data} onConfigureTurn={onConfigureTurn} />
        ) : netKind === "data-channel" ? (
          <ChannelStats data={data} />
        ) : (
          <QualityStats data={data} />
        );
      break;
    case "connstate":
      body = <ConnStateStrip data={data} />;
      break;
    case "endpoint":
      body = <EndpointPanel data={data} />;
      break;
    case "certificate":
      body = <CertificatePanel data={data} />;
      break;
    case "session":
      body = <SessionPanel data={data} />;
      break;
    case "channel":
      body = <ChannelPanel data={data} />;
      break;
    case "sdp":
      body = <SdpPanel content={content} />;
      break;
    default:
      return null;
  }
  return (
    <div
      className={cn(
        // 30%, not 55%. The fill is a grouping cue and the border already
        // carries it; in dark the raised surface is *lighter* than the page,
        // so every wash of it spends contrast on the muted text inside — the
        // pair matrix's `→` and its RTT figure both measured 4.47:1 at 55%,
        // and this is the panel that has to stay readable when a call is going
        // badly. Light theme is unaffected either way.
        "net-panel overflow-hidden rounded-[7px] border border-[color-mix(in_srgb,var(--border)_60%,transparent)] bg-[color-mix(in_srgb,var(--surface-raised)_30%,transparent)]",
        className
      )}
      data-network-artifact={netType}
      data-network-kind={netKind || undefined}
    >
      {body}
    </div>
  );
}
