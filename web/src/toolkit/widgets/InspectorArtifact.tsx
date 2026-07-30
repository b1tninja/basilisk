import { useState } from "react";
import { cn } from "@/lib/cn";
import { formatHexdump } from "../../lib/toolkit/inspect.js";

/**
 * Structured inspector for a pipeline value.
 *
 * `inspect` builds a *snapshot* — `{ type, meta, bytes?, text?, keypair?, … }` —
 * and the old reader flattened it into a text dump whose first lines were
 * `type: …` / `sensitive: …` / `length: …`. That put metadata *inside the
 * payload*: it could not be copied without the header, could not be styled,
 * and a keypair ended up described in prose rather than shown.
 *
 * This renders the snapshot as it actually is. The type picks the body, and
 * the metadata becomes chrome — badges above the value, not lines within it.
 * The text dump remains available for Copy raw, where a flat form is what you
 * actually want.
 */

export type InspectSnapshot = {
  type: string;
  meta?: Record<string, unknown>;
  bytes?: Uint8Array | number[];
  text?: string;
  value?: unknown;
  shares?: { mnemonics?: string[]; threshold?: number; enveloped?: boolean };
  keypair?: {
    privateJwk?: JsonWebKey;
    publicJwk?: JsonWebKey;
    hasPrivate?: boolean;
    hasPublic?: boolean;
  };
  recipients?: { label?: string; fingerprint?: string; hasArmor?: boolean }[];
  openpgpKey?: {
    which?: string;
    fingerprint?: string;
    primary?: { alg?: string; fingerprint?: string; created?: string; expires?: string };
    userIds?: { id: string; selfSigned?: boolean }[];
    subkeys?: { alg?: string; fingerprint?: string; bound?: boolean }[];
  };
};

type Props = {
  snapshot: InspectSnapshot;
  /** Masked until the user reveals — same gate as the artifact row. */
  masked?: boolean;
  className?: string;
};

function asBytes(b: InspectSnapshot["bytes"]): Uint8Array | null {
  if (!b) return null;
  return b instanceof Uint8Array ? b : new Uint8Array(b);
}

/** One metadata chip. Chrome — deliberately not part of the value. */
function Chip({ label, value }: { label: string; value: string }) {
  return (
    <span className="inline-flex items-baseline gap-1 rounded-[4px] bg-[var(--surface-raised)] px-1.5 py-px">
      <span className="text-[9px] uppercase tracking-wider text-[var(--muted-foreground)]">
        {label}
      </span>
      <span className="font-mono text-[10px] text-[var(--foreground)]">{value}</span>
    </span>
  );
}

/** Key/value grid used by the structured bodies. */
function Rows({ rows }: { rows: [string, string][] }) {
  if (!rows.length) return null;
  return (
    <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5">
      {rows.map(([k, v]) => (
        <div key={k} className="contents">
          <dt className="font-mono text-[10px] text-[var(--muted-foreground)]">{k}</dt>
          <dd className="break-all font-mono text-[10px] text-[var(--foreground)]">{v}</dd>
        </div>
      ))}
    </dl>
  );
}

/** Bytes — a real hexdump, offset / hex / ASCII, not a paragraph about bytes. */
function BytesBody({ bytes }: { bytes: Uint8Array }) {
  const [limit, setLimit] = useState(256);
  const truncated = bytes.length > limit;
  return (
    <div className="flex flex-col gap-1">
      <pre className="max-h-56 overflow-auto whitespace-pre font-mono text-[10px] leading-[1.5] text-[var(--foreground)]">
        {formatHexdump(bytes, { limit })}
      </pre>
      {truncated ? (
        <button
          type="button"
          className="w-fit text-[10px] font-semibold text-[var(--brand)] hover:underline"
          onClick={() => setLimit((n) => n * 4)}
        >
          Show more — {bytes.length - limit} of {bytes.length} bytes hidden
        </button>
      ) : null}
    </div>
  );
}

/** A CryptoKey pair, shown as key material rather than described. */
function KeypairBody({ keypair }: { keypair: NonNullable<InspectSnapshot["keypair"]> }) {
  const jwk = keypair.privateJwk || keypair.publicJwk;
  const rows: [string, string][] = [];
  if (jwk?.kty) rows.push(["kty", String(jwk.kty)]);
  if (jwk?.crv) rows.push(["crv", String(jwk.crv)]);
  if (jwk?.alg) rows.push(["alg", String(jwk.alg)]);
  if (Array.isArray(jwk?.key_ops) && jwk.key_ops.length) {
    rows.push(["key_ops", jwk.key_ops.join(", ")]);
  }
  // The public coordinates are safe to show; `d` is the private scalar and is
  // named but never printed, even when the tile has been revealed.
  if (jwk?.x) rows.push(["x", String(jwk.x)]);
  if (jwk?.y) rows.push(["y", String(jwk.y)]);
  if (jwk?.n) rows.push(["n", `${String(jwk.n).slice(0, 32)}…`]);
  return (
    <div className="flex flex-col gap-2">
      <div className="flex gap-1.5">
        <span
          className={cn(
            "rounded-[4px] px-1.5 py-px text-[10px] font-semibold",
            keypair.hasPrivate
              ? "bg-[color-mix(in_srgb,var(--warn)_16%,transparent)] text-[var(--warn)]"
              : "bg-[var(--surface-raised)] text-[var(--muted-foreground)]"
          )}
        >
          {keypair.hasPrivate ? "private half present" : "no private half"}
        </span>
        <span
          className={cn(
            "rounded-[4px] px-1.5 py-px text-[10px] font-semibold",
            keypair.hasPublic
              ? "bg-[color-mix(in_srgb,var(--brand)_16%,transparent)] text-[var(--brand)]"
              : "bg-[var(--surface-raised)] text-[var(--muted-foreground)]"
          )}
        >
          {keypair.hasPublic ? "public half present" : "no public half"}
        </span>
      </div>
      <Rows rows={rows} />
      {keypair.privateJwk?.d ? (
        <p className="font-mono text-[10px] italic text-[var(--muted-foreground)]">
          d — private scalar, withheld
        </p>
      ) : null}
    </div>
  );
}

/** Secret-sharing set — one row per share, not a blob of mnemonics. */
function SharesBody({ shares }: { shares: NonNullable<InspectSnapshot["shares"]> }) {
  const list = shares.mnemonics || [];
  return (
    <div className="flex flex-col gap-1">
      {shares.threshold ? (
        <p className="text-[10px] text-[var(--muted-foreground)]">
          any <strong className="text-[var(--foreground)]">{shares.threshold}</strong> of{" "}
          <strong className="text-[var(--foreground)]">{list.length}</strong> reconstruct
          the secret
        </p>
      ) : null}
      <ol className="flex flex-col gap-0.5">
        {list.map((m, i) => (
          <li key={i} className="flex gap-2">
            <span className="shrink-0 font-mono text-[10px] text-[var(--muted-foreground)]">
              {i + 1}
            </span>
            <code className="break-all font-mono text-[10px] text-[var(--foreground)]">
              {m}
            </code>
          </li>
        ))}
      </ol>
    </div>
  );
}

/**
 * An OpenPGP key is a tree, not a blob (§32b): a primary key with user IDs and
 * subkeys bound under it. This is the only nested body — every other type is
 * flat — so the indent and rule are local rather than a shared layout.
 */
function OpenpgpKeyBody({
  pgpKey: k,
}: {
  pgpKey: NonNullable<InspectSnapshot["openpgpKey"]>;
}) {
  const primary = k.primary;
  if (!primary) {
    // Unparseable, or an older snapshot without structure — fall back to the
    // flat identity fields rather than showing nothing.
    return (
      <Rows
        rows={[
          ["which", String(k.which || "—")],
          ["fingerprint", String(k.fingerprint || "—")],
        ]}
      />
    );
  }
  return (
    <div className="flex flex-col gap-2">
      <div>
        <p className="text-[10px] font-bold uppercase tracking-wider text-[var(--muted-foreground)]">
          primary
        </p>
        <Rows
          rows={[
            ["alg", primary.alg || "—"],
            ["fingerprint", primary.fingerprint || "—"],
            ...(primary.created ? ([["created", primary.created]] as [string, string][]) : []),
            ...(primary.expires
              ? ([["expires", primary.expires]] as [string, string][])
              : ([["expires", "never"]] as [string, string][])),
          ]}
        />
      </div>
      <div className="border-l border-[var(--border)] pl-2.5">
        {k.userIds?.length ? (
          <div className="mb-1.5">
            <p className="text-[10px] font-bold uppercase tracking-wider text-[var(--muted-foreground)]">
              user ids
            </p>
            <ul className="flex flex-col gap-0.5">
              {k.userIds.map((u, i) => (
                <li key={i} className="flex items-baseline gap-1.5">
                  <code className="break-all font-mono text-[10px] text-[var(--foreground)]">
                    {u.id}
                  </code>
                  {u.selfSigned ? (
                    <span className="shrink-0 text-[9px] text-[var(--brand)]">self-signed</span>
                  ) : null}
                </li>
              ))}
            </ul>
          </div>
        ) : null}
        {k.subkeys?.length ? (
          <div>
            <p className="text-[10px] font-bold uppercase tracking-wider text-[var(--muted-foreground)]">
              subkeys <span className="font-mono font-normal">{k.subkeys.length}</span>
            </p>
            <ul className="flex flex-col gap-0.5">
              {k.subkeys.map((s, i) => (
                <li key={i} className="flex items-baseline gap-1.5">
                  <span className="shrink-0 font-mono text-[10px] text-[var(--muted-foreground)]">
                    {s.alg || "?"}
                  </span>
                  <code className="break-all font-mono text-[10px] text-[var(--foreground)]">
                    {s.fingerprint}
                  </code>
                </li>
              ))}
            </ul>
          </div>
        ) : null}
      </div>
      {k.which === "private" ? (
        <p className="font-mono text-[10px] italic text-[var(--muted-foreground)]">
          secret key material — withheld
        </p>
      ) : null}
    </div>
  );
}

export function InspectorArtifact({ snapshot, masked = false, className }: Props) {
  const meta = snapshot.meta || {};
  const bytes = asBytes(snapshot.bytes);
  const chips: [string, string][] = [["type", snapshot.type]];
  if (bytes) chips.push(["size", `${bytes.length} B`]);
  else if (typeof snapshot.text === "string") {
    chips.push(["length", `${snapshot.text.length} chars`]);
  }
  if (meta.alg) chips.push(["alg", String(meta.alg)]);
  if (meta.encoding) chips.push(["encoding", String(meta.encoding)]);

  return (
    <div
      className={cn(
        "inspector-artifact flex flex-col gap-2 rounded-[8px] border border-[var(--border)] bg-[var(--surface-raised)] p-2",
        className
      )}
      data-inspect-type={snapshot.type}
    >
      {/* Metadata as chrome. It describes the value; it is not part of it. */}
      <div className="flex flex-wrap items-center gap-1">
        {chips.map(([k, v]) => (
          <Chip key={k} label={k} value={v} />
        ))}
        {meta.sensitive ? (
          <span className="rounded-[4px] bg-[color-mix(in_srgb,var(--warn)_14%,transparent)] px-1.5 py-px text-[10px] font-semibold text-[var(--warn)]">
            sensitive
          </span>
        ) : null}
      </div>

      {masked ? (
        <p className="font-mono text-[10px] italic text-[var(--muted-foreground)]">
          sensitive — value not shown
        </p>
      ) : snapshot.openpgpKey ? (
        <OpenpgpKeyBody pgpKey={snapshot.openpgpKey} />
      ) : snapshot.keypair ? (
        <KeypairBody keypair={snapshot.keypair} />
      ) : snapshot.shares ? (
        <SharesBody shares={snapshot.shares} />
      ) : snapshot.recipients ? (
        <Rows
          rows={snapshot.recipients.map((r, i) => [
            r.label || `recipient ${i + 1}`,
            r.fingerprint || (r.hasArmor ? "armored key" : "—"),
          ])}
        />
      ) : bytes ? (
        <BytesBody bytes={bytes} />
      ) : typeof snapshot.text === "string" ? (
        <pre className="max-h-56 overflow-auto whitespace-pre-wrap break-all font-mono text-[10px] text-[var(--foreground)]">
          {snapshot.text}
        </pre>
      ) : snapshot.value !== undefined ? (
        <code className="font-mono text-[11px] text-[var(--foreground)]">
          {String(snapshot.value)}
        </code>
      ) : (
        <p className="font-mono text-[10px] italic text-[var(--muted-foreground)]">
          no value body for {snapshot.type}
        </p>
      )}
    </div>
  );
}

/** Whether a snapshot has a structured body worth rendering. */
export function hasInspectorRenderer(snapshot: InspectSnapshot | null | undefined): boolean {
  return !!snapshot?.type;
}
