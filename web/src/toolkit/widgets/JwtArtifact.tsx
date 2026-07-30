import { useEffect, useState } from "react";
import { cn } from "@/lib/cn";
import { claimTiming } from "../../lib/toolkit/jose-ops.js";

/**
 * JWT / JOSE artifact reader.
 *
 * A token's own rows are the wrong unit of attention. What a reader actually
 * needs to answer, in order, is: *was this checked*, *what does it claim*, and
 * *is it still good*. So the widget leads with a verdict banner, then the
 * claims, then a validity timeline — rather than a JSON dump the eye has to
 * search.
 *
 * Two behaviours are deliberate:
 *
 *  - **Unverified never looks verified.** A `jose.decode` result renders with
 *    a warning banner and a muted body. There is no styling path by which an
 *    unchecked token reaches the same appearance as a checked one, because
 *    the whole failure mode of a JWT inspector is teaching people to read
 *    claims they have not authenticated.
 *  - **The clock is live.** Expiry is recomputed on a one-second tick from
 *    the claims, not read from a value frozen at run time. A token that lapses
 *    while the tab is open turns red without the cell being re-run — which is
 *    the state a developer most needs to notice and is exactly the one a
 *    render-time snapshot would hide.
 *
 * Tones ride `data-jwt-tone` with the palette enumerated in toolkit.css: the
 * CSP forbids inline styles, and the tone set here is closed (ok / warn /
 * error / muted), so enumeration costs nothing.
 */

export type JoseTiming = {
  exp: number | null;
  nbf: number | null;
  iat: number | null;
  expired: boolean;
  notYetValid: boolean;
};

export type JoseArtifactData = {
  kind: "jws" | "jwe";
  /** True only when a signature was checked or a JWE was actually decrypted. */
  verified: boolean;
  /** Set by `jose.sign` — this token was produced here, not merely accepted. */
  signed?: boolean;
  decrypted?: boolean;
  /** Whether `jose.verify` enforced exp/nbf, or was told to ignore them. */
  expiryChecked?: boolean;
  header: Record<string, unknown>;
  claims: Record<string, unknown> | null;
  payloadText?: string | null;
  timing?: JoseTiming;
};

type Tone = "ok" | "warn" | "error" | "muted";

/** Claims RFC 7519 §4.1 gives a meaning, in the order a reader wants them. */
const REGISTERED: Record<string, string> = {
  iss: "Issuer",
  sub: "Subject",
  aud: "Audience",
  exp: "Expires",
  nbf: "Not before",
  iat: "Issued at",
  jti: "JWT ID",
};

/** Header parameters worth naming; anything else still renders, unlabelled. */
const HEADER_LABELS: Record<string, string> = {
  alg: "Algorithm",
  enc: "Encryption",
  typ: "Type",
  cty: "Content type",
  kid: "Key ID",
  zip: "Compression",
};

const MINUTE = 60;
const HOUR = 3600;
const DAY = 86400;

/**
 * "in 4 minutes" / "3 days ago" — coarse on purpose. A token's remaining life
 * is an order-of-magnitude question until it is nearly over, at which point
 * seconds start to matter and this starts reporting them.
 */
export function relativeSeconds(delta: number): string {
  const abs = Math.abs(delta);
  const suffix = delta < 0 ? " ago" : "";
  const prefix = delta < 0 ? "" : "in ";
  let body: string;
  if (abs < 60) body = `${abs}s`;
  else if (abs < HOUR) body = `${Math.floor(abs / MINUTE)}m ${abs % MINUTE}s`;
  else if (abs < DAY) body = `${Math.floor(abs / HOUR)}h ${Math.floor((abs % HOUR) / MINUTE)}m`;
  else body = `${Math.floor(abs / DAY)}d`;
  return `${prefix}${body}${suffix}`;
}

/** Seconds of remaining life below which the row escalates. */
export const EXPIRY_WARN_SECONDS = 300;
export const EXPIRY_URGENT_SECONDS = 60;

/**
 * The tone an `exp` deserves right now.
 *
 * Split out and exported because it is the one piece of this widget with a
 * decision in it — the catalog exercises the boundaries directly rather than
 * waiting for a real token to age past them.
 */
export function expiryTone(secondsLeft: number | null): Tone {
  if (secondsLeft == null) return "muted";
  if (secondsLeft <= 0) return "error";
  if (secondsLeft <= EXPIRY_URGENT_SECONDS) return "error";
  if (secondsLeft <= EXPIRY_WARN_SECONDS) return "warn";
  return "ok";
}

function fmtEpoch(seconds: number): string {
  try {
    return new Date(seconds * 1000).toISOString().replace(".000Z", "Z");
  } catch {
    return String(seconds);
  }
}

function Chip({ tone, children }: { tone: Tone; children: React.ReactNode }) {
  return (
    <span
      data-jwt-tone={tone}
      className="jwt-chip shrink-0 rounded-[3px] px-[5px] py-[2px] text-[9px] font-medium uppercase tracking-wider"
    >
      {children}
    </span>
  );
}

function Rows({
  entries,
  labels,
  tones,
}: {
  entries: [string, unknown][];
  labels: Record<string, string>;
  tones?: Record<string, Tone>;
}) {
  if (!entries.length) {
    return (
      <p className="px-2.5 py-2 text-[10.5px] italic text-[var(--muted-foreground)]">
        none
      </p>
    );
  }
  return (
    <dl className="m-0">
      {entries.map(([k, v]) => (
        <div
          key={k}
          className="flex items-baseline gap-2.5 border-b border-[color-mix(in_srgb,var(--border)_45%,transparent)] px-2.5 py-[5px] last:border-b-0"
        >
          {/* The registered-claim name is a tooltip, not a second column: it
              was one, and at the widths this widget actually renders at the
              label was clipped by the term column rather than read. */}
          <dt
            className="w-[64px] shrink-0 font-mono text-[10px] text-[var(--muted-foreground)]"
            title={labels[k] || undefined}
          >
            {k}
          </dt>
          <dd
            data-jwt-tone={tones?.[k] || "muted"}
            className="jwt-value m-0 min-w-0 flex-1 break-all font-mono text-[11px]"
          >
            {typeof v === "string" ? v : JSON.stringify(v)}
          </dd>
        </div>
      ))}
    </dl>
  );
}

/**
 * iat / nbf → exp, as a draining bar.
 *
 * The fill is **remaining** life, not elapsed. Filling with elapsed time was
 * the first cut and it read wrong in the catalog: a freshly issued token —
 * the healthiest state there is — drew an empty bar, which looks like a
 * broken widget rather than a good token. Draining also matches the mental
 * model of the thing being measured, and the bar ends up empty exactly when
 * the token is dead.
 *
 * Rendered from twelve width buckets rather than a computed percentage: a
 * per-token percentage needs an inline `style`, which the CSP refuses.
 * Twelfths are finer than the eye reads off a bar this size.
 */
function Timeline({
  iat,
  nbf,
  exp,
  now,
  notYetValid,
  claimed,
}: {
  iat: number | null;
  nbf: number | null;
  exp: number | null;
  now: number;
  notYetValid: boolean;
  /** Unverified: these dates are asserted, not established. */
  claimed: boolean;
}) {
  if (exp == null) {
    return (
      <p className="px-2.5 py-1.5 text-[10.5px] italic text-[var(--muted-foreground)]">
        No `exp` — this token does not expire on its own.
      </p>
    );
  }
  const start = nbf ?? iat ?? Math.min(now, exp);
  const span = Math.max(1, exp - start);
  const left = exp - now;
  const remaining = Math.min(Math.max(left, 0), span);
  // A bar with some life left never rounds down to nothing — 0 is reserved
  // for "expired", which is the one state that should read as empty.
  const raw = (remaining / span) * 12;
  const bucket = remaining > 0 ? Math.max(1, Math.round(raw)) : 0;
  // A token that is not valid yet is not a healthy token, whatever its `exp`
  // says — without this the bar drew green under a red banner. And an
  // unverified token gets no green at all: its dates are an assertion by
  // whoever wrote the token, so a healthy-looking bar would be the widget
  // vouching for something nothing has checked.
  const tone: Tone = notYetValid ? "error" : claimed ? "muted" : expiryTone(left);
  return (
    <div className="flex flex-col gap-1 px-2.5 py-2">
      <div
        className="jwt-track relative h-[6px] overflow-hidden rounded-full"
        role="img"
        aria-label={`Token validity: ${
          notYetValid
            ? `not valid until ${fmtEpoch(nbf as number)}`
            : left <= 0
              ? `expired ${relativeSeconds(left)}`
              : `expires ${relativeSeconds(left)}`
        }`}
      >
        <span data-jwt-tone={tone} data-jwt-fill={bucket} className="jwt-fill absolute inset-y-0 left-0" />
      </div>
      <div className="flex items-baseline justify-between gap-2 text-[9.5px] text-[var(--muted-foreground)]">
        <span className="font-mono">{fmtEpoch(start)}</span>
        <span data-jwt-tone={tone} className="jwt-value font-mono font-semibold">
          {notYetValid
            ? `valid ${relativeSeconds((nbf as number) - now)}`
            : left <= 0
              ? `expired ${relativeSeconds(left)}`
              : `expires ${relativeSeconds(left)}`}
        </span>
        <span className="font-mono">{fmtEpoch(exp)}</span>
      </div>
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="border-t border-[color-mix(in_srgb,var(--border)_45%,transparent)] first:border-t-0">
      <h4 className="px-2.5 pt-2 pb-1 text-[9px] font-semibold uppercase tracking-wider text-[var(--muted-foreground)]">
        {title}
      </h4>
      {children}
    </section>
  );
}

export function JwtArtifact({
  data,
  className,
  /** Injectable for the catalog and tests; production ticks the real clock. */
  nowMs,
}: {
  data: JoseArtifactData;
  className?: string;
  nowMs?: number;
}) {
  const [tick, setTick] = useState(() => nowMs ?? Date.now());
  useEffect(() => {
    if (nowMs != null) {
      setTick(nowMs);
      return undefined;
    }
    const id = setInterval(() => setTick(Date.now()), 1000);
    return () => clearInterval(id);
  }, [nowMs]);

  const timing: JoseTiming = claimTiming(data.claims, tick);
  const now = Math.floor(tick / 1000);
  const verified = !!data.verified;
  const isJwe = data.kind === "jwe";

  const verdictTone: Tone = !verified
    ? "warn"
    : timing.expired || timing.notYetValid
      ? "error"
      : "ok";
  const verdict = !verified
    ? "Unverified — signature not checked"
    : isJwe
      ? data.decrypted
        ? "Decrypted — content authenticated by the AEAD tag"
        : "Encrypted"
      : data.signed
        ? "Signed here"
        : timing.expired
          ? "Signature valid — but expired"
          : timing.notYetValid
            ? "Signature valid — but not valid yet"
            : "Signature verified";

  const claimEntries = Object.entries(data.claims || {});
  // Registered claims first, in RFC order, then whatever else the issuer put
  // in — private claims are usually the interesting ones, but they are not
  // the ones a reader checks first.
  const order = Object.keys(REGISTERED);
  claimEntries.sort(([a], [b]) => {
    const ia = order.indexOf(a);
    const ib = order.indexOf(b);
    if (ia === -1 && ib === -1) return a.localeCompare(b);
    if (ia === -1) return 1;
    if (ib === -1) return -1;
    return ia - ib;
  });

  /** Time claims render as an absolute instant plus how far off it is. */
  const shownClaims: [string, unknown][] = claimEntries.map(([k, v]) => {
    if ((k === "exp" || k === "nbf" || k === "iat") && typeof v === "number") {
      return [k, `${fmtEpoch(v)}  (${relativeSeconds(v - now)})`];
    }
    return [k, v];
  });

  // Same rule as the bar: an unverified token's `exp` is an assertion, so it
  // gets no colour. Green on a claim nobody checked is the widget agreeing
  // with the attacker.
  const claimTones: Record<string, Tone> = {};
  if (verified) {
    if (timing.exp != null) claimTones.exp = expiryTone(timing.exp - now);
    if (timing.notYetValid) claimTones.nbf = "error";
  }

  return (
    <div
      className={cn(
        "overflow-hidden rounded-[6px] border border-[var(--border)] bg-[var(--surface)]",
        className
      )}
      data-jwt-artifact
      data-jwt-verified={verified ? "true" : "false"}
    >
      <div
        data-jwt-tone={verdictTone}
        className="jwt-banner flex items-center gap-2 px-2.5 py-[6px]"
      >
        <Chip tone={verdictTone}>{isJwe ? "JWE" : "JWS"}</Chip>
        <span className="jwt-value min-w-0 flex-1 truncate text-[10.5px] font-semibold" data-jwt-tone={verdictTone}>
          {verdict}
        </span>
        {verified && data.expiryChecked === false ? (
          <Chip tone="warn">exp not enforced</Chip>
        ) : null}
      </div>

      {!verified ? (
        <p className="border-b border-[color-mix(in_srgb,var(--border)_45%,transparent)] px-2.5 py-1.5 text-[10px] text-[var(--muted-foreground)]">
          These claims are whatever the token says. Anyone can write a token —
          run <code className="font-mono">jose.verify key=@…</code> before
          trusting any of it.
        </p>
      ) : null}

      <Section title="Header">
        <Rows entries={Object.entries(data.header || {})} labels={HEADER_LABELS} />
      </Section>

      {isJwe && !data.decrypted ? (
        <Section title="Payload">
          <p className="px-2.5 py-2 text-[10.5px] italic text-[var(--muted-foreground)]">
            Encrypted — run <code className="font-mono">jose.decrypt</code> with
            the recipient key to read it.
          </p>
        </Section>
      ) : data.claims ? (
        <>
          <Section title="Claims">
            <Rows entries={shownClaims} labels={REGISTERED} tones={claimTones} />
          </Section>
          <Section title="Validity">
            <Timeline
              iat={timing.iat}
              nbf={timing.nbf}
              exp={timing.exp}
              now={now}
              notYetValid={timing.notYetValid}
              claimed={!verified}
            />
          </Section>
        </>
      ) : (
        <Section title="Payload">
          <code className="block max-h-24 overflow-auto whitespace-pre-wrap break-all px-2.5 py-2 font-mono text-[10.5px] text-[var(--muted-foreground)]">
            {data.payloadText || "(empty)"}
          </code>
        </Section>
      )}
    </div>
  );
}

/** True when an artifact carries a JOSE body worth rendering as one. */
export function hasJoseRenderer(data: unknown): data is JoseArtifactData {
  return (
    !!data &&
    typeof data === "object" &&
    (( data as JoseArtifactData).kind === "jws" || (data as JoseArtifactData).kind === "jwe")
  );
}
