import type { ReactNode } from "react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/cn";

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
const CANDIDATE_TONE: Record<string, string> = {
  host: "var(--brand)",
  prflx: "var(--caret)",
  srflx: "var(--caret)",
  relay: "var(--warn)",
};

const PAIR_STATE_TONE: Record<string, string> = {
  succeeded: "var(--brand)",
  "in-progress": "var(--caret)",
  waiting: "var(--muted-foreground)",
  failed: "var(--error)",
  frozen: "var(--muted-foreground)",
};

function TypeBadge({ label, tone }: { label: string; tone: string }) {
  return (
    <span
      className="shrink-0 rounded-[3px] px-[5px] py-[2px] text-[9px] font-medium uppercase tracking-wider"
      style={{
        color: tone,
        background: `color-mix(in srgb, ${tone} 12%, transparent)`,
      }}
    >
      {label}
    </span>
  );
}

function Row({ children, dim }: { children: ReactNode; dim?: boolean }) {
  return (
    <div
      className={cn(
        "flex items-center gap-2.5 border-b border-[color-mix(in_srgb,var(--border)_45%,transparent)] px-2.5 py-[6px] last:border-b-0",
        dim && "opacity-50"
      )}
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
  // failure, so it renders dim rather than being hidden or shown as an error.
  const order = ["host", "prflx", "srflx", "relay"];
  return (
    <div>
      {order.map((t) => {
        const rows = candidates.filter((c) => c.type === t);
        if (!rows.length) {
          return (
            <Row key={t} dim>
              <TypeBadge label={t} tone={CANDIDATE_TONE[t] || "var(--muted-foreground)"} />
              <span className="text-[10.5px] italic text-[var(--muted-foreground)]">
                {t === "relay"
                  ? "none gathered — no TURN configured"
                  : t === "prflx"
                    ? "none — peer-reflexive only appears during negotiation"
                    : "none gathered"}
              </span>
            </Row>
          );
        }
        return rows.map((c, i) => (
          <Row key={`${t}-${i}`}>
            <TypeBadge label={t} tone={CANDIDATE_TONE[t] || "var(--muted-foreground)"} />
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
              <TypeBadge label={p.role} tone="var(--caret)" />
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
              // 23b: non-nominated pairs stay visible at reduced opacity —
              // debugging "why is this slow" needs the whole graph, not the winner.
              <Row key={i} dim={!pair.nominated && pair.state !== "failed"}>
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
                  <TypeBadge label="✓ nominated" tone="var(--brand)" />
                ) : (
                  <TypeBadge
                    label={pair.state}
                    tone={PAIR_STATE_TONE[pair.state] || "var(--muted-foreground)"}
                  />
                )}
              </Row>
            ))
          )}
        </div>
      ))}
      {/* 23b: when every pair fails, the fallback CTA is a TURN relay. */}
      {data?.allFailed && onConfigureTurn ? (
        <div className="flex items-center gap-2 px-2.5 py-2">
          <span className="text-[10.5px] text-[var(--warn)]">
            Every candidate pair failed.
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

const CONN_STAGES = ["new", "connecting", "connected", "disconnected", "closed"];

function ConnStateStrip({ data }: { data: any }) {
  const peers: any[] = Array.isArray(data?.peers) ? data.peers : [];
  if (!peers.length) return <Empty>No peers in this exchange.</Empty>;
  return (
    <div>
      {peers.map((p, i) => {
        const at = CONN_STAGES.indexOf(String(p.connectionState));
        return (
          <div
            key={i}
            className="border-b border-[color-mix(in_srgb,var(--border)_45%,transparent)] px-2.5 py-2 last:border-b-0"
          >
            <div className="mb-1.5 flex items-center gap-2">
              <code className="font-mono text-[10px] text-[var(--muted-foreground)]">
                {String(p.peer || "").slice(0, 8)}…
              </code>
              {p.verified ? <TypeBadge label="verified" tone="var(--brand)" /> : null}
              <span className="ml-auto font-mono text-[9.5px] text-[var(--muted-foreground)]">
                ice {p.iceConnectionState} · sig {p.signalingState} · ch {p.channelState}
              </span>
            </div>
            {/* Same strip shape 26a's type row uses. */}
            <div className="flex items-center gap-1">
              {CONN_STAGES.map((s, si) => {
                const active = si === at;
                const past = at >= 0 && si < at;
                const failed = s === "disconnected" || s === "closed";
                return (
                  <span key={s} className="flex flex-1 items-center gap-1">
                    <span
                      className="h-[3px] flex-1 rounded-full"
                      style={{
                        background: active
                          ? failed
                            ? "var(--error)"
                            : "var(--brand)"
                          : past
                            ? "color-mix(in srgb, var(--brand) 40%, transparent)"
                            : "var(--surface-raised)",
                      }}
                    />
                  </span>
                );
              })}
            </div>
            <div className="mt-1 flex justify-between text-[9px] text-[var(--muted-foreground)]">
              {CONN_STAGES.map((s) => (
                <span
                  key={s}
                  className={cn(
                    "flex-1 text-center",
                    s === p.connectionState && "font-bold text-[var(--foreground)]"
                  )}
                >
                  {s}
                </span>
              ))}
            </div>
          </div>
        );
      })}
    </div>
  );
}

/* ───────────────────────── stats panels (29d / 30d) ───────────────────────── */

function QualityStats({ data }: { data: any }) {
  const peers: any[] = Array.isArray(data?.peers) ? data.peers : [];
  if (!peers.length) return <Empty>No connected peers to measure.</Empty>;
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
          <span className="shrink-0 font-mono text-[10px] text-[var(--muted-foreground)]">
            {p.packetLossPct ?? 0}% loss
          </span>
          <span className="shrink-0 font-mono text-[10px] text-[var(--muted-foreground)]">
            ↑{fmtBytes(p.bytesSent || 0)} ↓{fmtBytes(p.bytesReceived || 0)}
          </span>
        </Row>
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
                tone={p.readyState === "open" ? "var(--brand)" : "var(--muted-foreground)"}
              />
              {p.backPressured ? <TypeBadge label="back-pressure" tone="var(--warn)" /> : null}
            </div>
            <div className="mt-1.5 h-[3px] overflow-hidden rounded-full bg-[var(--surface-raised)]">
              <div
                className="h-full transition-[width]"
                style={{
                  width: `${pct}%`,
                  background: p.backPressured ? "var(--warn)" : "var(--caret)",
                }}
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
                tone={isTurn ? "var(--warn)" : "var(--caret)"}
              />
              <code className="min-w-0 flex-1 truncate font-mono text-[10.5px]">{url}</code>
              {s.username ? (
                <span className="shrink-0 font-mono text-[9.5px] text-[var(--muted-foreground)]">
                  as {s.username}
                </span>
              ) : null}
              {isTurn ? <TypeBadge label="credential bound" tone="var(--brand)" /> : null}
            </Row>
          );
        })}
      </div>
    );
  }
  const ok = data?.ok !== false;
  return (
    <div>
      <Row>
        <TypeBadge label={ok ? "reachable" : "blocked"} tone={ok ? "var(--brand)" : "var(--warn)"} />
        <code className="min-w-0 flex-1 truncate font-mono text-[11px]">
          {data?.publicAddress || "no public address discovered"}
        </code>
        {data?.ms != null ? (
          <span className="shrink-0 font-mono text-[9.5px] text-[var(--muted-foreground)]">
            {data.ms}ms
          </span>
        ) : null}
      </Row>
      {data?.note ? (
        <p className="px-2.5 py-[6px] text-[10px] text-[var(--muted-foreground)]">{data.note}</p>
      ) : null}
    </div>
  );
}

function CertificatePanel({ data }: { data: any }) {
  const prints: any[] = Array.isArray(data?.fingerprints) ? data.fingerprints : [];
  return (
    <div>
      <Row>
        <TypeBadge label="dtls" tone="var(--decode)" />
        <code className="min-w-0 flex-1 truncate font-mono text-[10.5px]">{data?.algorithm}</code>
        {data?.expires ? (
          <span className="shrink-0 font-mono text-[9.5px] text-[var(--muted-foreground)]">
            expires {String(data.expires).slice(0, 10)}
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
        <TypeBadge label={data?.role || "session"} tone="var(--caret)" />
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
    ["candidate", "stats", "connstate", "endpoint", "certificate", "session", "sdp"].includes(
      netType
    )
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
    case "sdp":
      body = (
        <pre className="max-h-[320px] overflow-auto whitespace-pre-wrap break-all px-2.5 py-2 font-mono text-[10px] leading-relaxed text-[var(--muted-foreground)]">
          {content || ""}
        </pre>
      );
      break;
    default:
      return null;
  }
  return (
    <div
      className={cn(
        "overflow-hidden rounded-[7px] border border-[color-mix(in_srgb,var(--border)_60%,transparent)] bg-[color-mix(in_srgb,var(--surface-raised)_55%,transparent)]",
        className
      )}
      data-network-artifact={netType}
      data-network-kind={netKind || undefined}
    >
      {body}
    </div>
  );
}
