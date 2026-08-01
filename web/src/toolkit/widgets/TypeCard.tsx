import { useState } from "react";
import {
  consumersOf,
  producersOf,
  type TypeMeta,
} from "../../lib/toolkit/type-registry.js";
import { cn } from "@/lib/cn";
import { Input } from "@/components/ui/input";
import { KindGlyph } from "./kind-glyphs";

type Props = {
  meta: TypeMeta;
  /** Append a constructed literal step to the pipeline. */
  onInsertLiteral?: (step: { name: string; params: Record<string, unknown> }) => void;
  /** Append one of the producing/consuming ops. */
  onPickOp?: (name: string) => void;
  /** Compact hover layout — drops the constructor and the op lists. */
  compact?: boolean;
  className?: string;
};

/** Op names, as clickable chips. Silent when the list is empty. */
function OpChips({
  title,
  names,
  emptyNote,
  onPickOp,
}: {
  title: string;
  names: string[];
  emptyNote: string;
  onPickOp?: (name: string) => void;
}) {
  return (
    <div className="border-b border-[var(--border)] px-3.5 py-2.5">
      <p className="pb-1.5 text-xs font-bold uppercase tracking-wider text-[var(--muted-foreground)]">
        {title}
        {names.length ? (
          <span className="ml-1.5 font-mono font-normal normal-case tracking-normal opacity-70">
            {names.length}
          </span>
        ) : null}
      </p>
      {names.length ? (
        <div className="flex flex-wrap gap-1">
          {names.map((n) => (
            <button
              key={n}
              type="button"
              className="rounded-[5px] border border-[color-mix(in_srgb,var(--border)_70%,transparent)] bg-[var(--surface-raised)] px-1.5 py-0.5 font-mono text-[11px] text-[var(--muted-foreground)] transition-colors hover:border-[var(--brand)] hover:text-[var(--foreground)]"
              onClick={() => onPickOp?.(n)}
              title={`Append ${n}`}
            >
              {n}
            </button>
          ))}
        </div>
      ) : (
        <p className="text-xs italic text-[var(--muted-foreground)]">{emptyNote}</p>
      )}
    </div>
  );
}

/**
 * Constructor for a type you can write down. Renders only when the type
 * carries a `literal`; the parse result is shown live so `0x20 → 32` is
 * visible before the step is inserted rather than after it runs.
 */
function LiteralConstructor({
  meta,
  onInsertLiteral,
}: {
  meta: TypeMeta;
  onInsertLiteral?: (step: { name: string; params: Record<string, unknown> }) => void;
}) {
  const literal = meta.literal;
  const [raw, setRaw] = useState("");
  if (!literal) return null;

  const touched = raw.trim().length > 0;
  const parsed = literal.parse(raw);
  const canInsert = parsed.ok && !!onInsertLiteral;

  return (
    <div className="border-b border-[var(--border)] px-3.5 py-3">
      <p className="pb-1.5 text-xs font-bold uppercase tracking-wider text-[var(--muted-foreground)]">
        Make one
      </p>
      <div className="flex gap-1.5">
        <Input
          value={raw}
          placeholder={literal.placeholder}
          aria-label={`New ${meta.label} value`}
          aria-invalid={touched && !parsed.ok ? true : undefined}
          className="h-7 flex-1 font-mono text-xs"
          onChange={(e) => setRaw(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && canInsert) {
              onInsertLiteral?.(literal.build(raw));
              setRaw("");
            }
          }}
        />
        <button
          type="button"
          disabled={!canInsert}
          className={cn(
            "shrink-0 rounded-[6px] border px-2 py-1 text-[11px] font-semibold transition-colors",
            canInsert
              ? "border-[var(--brand)] bg-[color-mix(in_srgb,var(--brand)_14%,transparent)] text-[var(--brand)] hover:bg-[color-mix(in_srgb,var(--brand)_22%,transparent)]"
              : "cursor-not-allowed border-[color-mix(in_srgb,var(--border)_60%,transparent)] text-[var(--muted-foreground)] opacity-60"
          )}
          onClick={() => {
            if (!canInsert) return;
            onInsertLiteral?.(literal.build(raw));
            setRaw("");
          }}
        >
          Insert
        </button>
      </div>
      {/* Only complain once the user has typed — an empty field is not an error. */}
      <p
        className={cn(
          "mt-1 font-mono text-[11px]",
          touched && !parsed.ok ? "text-[var(--warn)]" : "text-[var(--muted-foreground)]"
        )}
      >
        {touched && !parsed.ok
          ? parsed.error
          : touched && parsed.note
            ? parsed.note
            : literal.hint}
      </p>
    </div>
  );
}

/**
 * Segmented origin picker (§31c) — for types with more than one legitimate
 * way to come into existence. Each origin inserts a real registry step, so
 * "Generate" is `genkey` itself with its own param form rather than a second
 * implementation of it.
 */
function OriginPicker({
  meta,
  onPickOp,
}: {
  meta: TypeMeta;
  onPickOp?: (name: string) => void;
}) {
  const origins = meta.origins;
  const [mode, setMode] = useState(origins?.[0]?.id ?? "");
  if (!origins?.length) return null;
  const active = origins.find((o) => o.id === mode) || origins[0];

  return (
    <div className="border-b border-[var(--border)] px-3.5 py-3">
      <p className="pb-1.5 text-xs font-bold uppercase tracking-wider text-[var(--muted-foreground)]">
        Make one
      </p>
      <div
        role="tablist"
        aria-label={`How to make a ${meta.label}`}
        className="flex overflow-hidden rounded-[6px] border border-[var(--border)]"
      >
        {origins.map((o) => (
          <button
            key={o.id}
            type="button"
            role="tab"
            aria-selected={o.id === active.id}
            className={cn(
              "flex-1 px-2 py-1 text-[11px] font-semibold transition-colors",
              o.id === active.id
                ? "bg-[var(--brand)] text-[var(--surface)]"
                : "bg-[var(--surface-raised)] text-[var(--muted-foreground)] hover:text-[var(--foreground)]"
            )}
            onClick={() => setMode(o.id)}
          >
            {o.label}
          </button>
        ))}
      </div>
      <p className="mt-1.5 text-[11px] leading-snug text-[var(--muted-foreground)]">
        {active.hint}
      </p>
      <button
        type="button"
        className="mt-1.5 w-full rounded-[6px] border border-[var(--brand)] bg-[color-mix(in_srgb,var(--brand)_14%,transparent)] px-2 py-1 text-[11px] font-semibold text-[var(--brand)] hover:bg-[color-mix(in_srgb,var(--brand)_22%,transparent)]"
        onClick={() => onPickOp?.(active.step)}
      >
        Insert <code className="font-mono">{active.step}</code>
      </button>
    </div>
  );
}

/**
 * Documentation card for a pipeline type — the type-system counterpart to
 * ToolCard. Producers and consumers come from `type-registry.js`, which
 * derives them from STEPS, so the card cannot claim an op that no longer
 * exists.
 */
export function TypeCard({ meta, onInsertLiteral, onPickOp, compact = false, className }: Props) {
  const producers = producersOf(meta.base);
  const consumers = consumersOf(meta.base);
  /**
   * "Reserved" means you cannot make one — not that nothing touches it.
   *
   * This used to require no producers AND no consumers, which made the badge
   * unreachable for every type it was written for: the generic sinks (`out`,
   * `peek`, `inspect`, `tee`, `select`, `text`, `file.save`,
   * `clipboard.write`) accept anything, so every declared type has eight
   * consumers and the conjunction was only ever true for `none`. Producers
   * are the honest signal — a type no step yields is one a recipe cannot
   * obtain, however many sinks would swallow it.
   *
   * `int` never reaches here: it is `literal`, caught earlier in the chain.
   */
  const orphan = !producers.length;

  return (
    <div
      className={cn(
        "type-card rounded-lg border border-[var(--border)] bg-[var(--surface)]",
        className
      )}
      data-type={meta.base}
    >
      <header className="flex items-center gap-2 border-b border-[var(--border)] p-3.5">
        {/* Same kind→glyph map the output rows use, so a type never shows one
            icon here and a different one there (§35). */}
        <KindGlyph kind={meta.base} size={14} className="text-[var(--muted-foreground)]" />
        <code className="font-mono text-sm font-bold text-[var(--foreground)]">{meta.label}</code>
        <span className="text-xs text-[var(--muted-foreground)]">type</span>
        {meta.literal ? (
          <span
            className="ml-auto rounded-[5px] bg-[color-mix(in_srgb,var(--brand)_14%,transparent)] px-1.5 py-0.5 text-[10px] font-semibold text-[var(--brand)]"
            title="Can be written directly as a literal"
          >
            literal
          </span>
        ) : meta.origins?.length ? (
          <span
            className="ml-auto rounded-[5px] bg-[color-mix(in_srgb,var(--brand)_14%,transparent)] px-1.5 py-0.5 text-[10px] font-semibold text-[var(--brand)]"
            title="More than one way to make one"
          >
            {meta.origins.length} origins
          </span>
        ) : orphan ? (
          <span
            className="ml-auto rounded-[5px] bg-[var(--surface-raised)] px-1.5 py-0.5 text-[10px] font-semibold text-[var(--muted-foreground)]"
            title="Declared in the type union, but no step produces one yet"
          >
            reserved
          </span>
        ) : null}
      </header>

      <p className="border-b border-[var(--border)] px-3.5 py-3 text-xs leading-relaxed text-[var(--muted-foreground)]">
        {compact ? meta.summary : meta.doc}
      </p>

      {!compact && meta.ref ? (
        <p className="border-b border-[var(--border)] px-3.5 py-2 text-xs">
          <a
            href={meta.ref.url}
            target="_blank"
            rel="noreferrer noopener"
            className="inline-flex items-center gap-1 text-[var(--brand)] hover:underline"
            title={meta.ref.url}
          >
            {meta.ref.label}
            <span aria-hidden="true">↗</span>
          </a>
        </p>
      ) : null}

      {!compact ? (
        <>
          <LiteralConstructor meta={meta} onInsertLiteral={onInsertLiteral} />
          <OriginPicker meta={meta} onPickOp={onPickOp} />
          <OpChips
            title="Produced by"
            names={producers}
            emptyNote={
              meta.literal
                ? "Only written directly, above."
                : "Nothing produces this type yet."
            }
            onPickOp={onPickOp}
          />
          <OpChips
            title="Accepted by"
            names={consumers}
            emptyNote="Nothing consumes this type — display it with out or inspect."
            onPickOp={onPickOp}
          />
        </>
      ) : null}
    </div>
  );
}
