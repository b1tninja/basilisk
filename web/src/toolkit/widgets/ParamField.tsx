import { useId, type ReactNode } from "react";
import type { ParamSpec } from "../../lib/toolkit/registry.js";
import { cn } from "@/lib/cn";
import { useRefusal } from "@/components/ui/refusal";

export type { ParamSpec };

/** `locked` must ship with `lockedReason` — an unexplained lock reads as a bug. */
type Visibility = { show: boolean; forced?: unknown; locked?: boolean; lockedReason?: string };

type Props = {
  param: ParamSpec;
  value: unknown;
  visibility?: Visibility;
  onChange: (name: string, value: string | number | boolean) => void;
  /** Extra control slot (e.g. recipient binder for to=). */
  control?: ReactNode;
  /** Secret params (design v2 §22a): open the Inputs/Slots tray to pick a binding. */
  onRequestBind?: () => void;
  /** One-shot focus jump (design v2 §22b's "Configure TURN" → rtc.ice's turn=). */
  autoFocus?: boolean;
  className?: string;
};

/** `$label` slot reference, or empty/unbound. Secret params only ever hold this shape. */
function slotRefOf(val: unknown): string | null {
  const s = typeof val === "string" ? val.trim() : "";
  return s.startsWith("$") && s.length > 1 ? s : null;
}

/**
 * The effective default, shown exactly while it is in effect (§ParamSpec.emptyMeans).
 *
 * An empty field looks like nothing happening. For `rtc.ice stun=` it meant
 * *contact Cloudflare and Google*, said only in a `title` tooltip — a
 * behaviour-changing default that a user could neither see nor knowingly
 * accept. The registry writes the phrase; this renders it, and stops rendering
 * it the moment the field has a value, because then the default no longer
 * applies and the line would be describing something that is not happening.
 */
function EmptyMeans({ param, value }: { param: ParamSpec; value: unknown }) {
  const phrase = param.emptyMeans;
  if (!phrase) return null;
  if (String(value ?? "").trim() !== "") return null;
  return (
    <p className="param-empty-means mt-1 text-[10px] leading-snug text-[var(--text-muted)]">
      <span className="param-empty-means-key">empty →</span> {phrase}
    </p>
  );
}

/** Single builder param — bool / enum / text / locked. Redesigned with uniform widget system. */
export function ParamField({
  param,
  value,
  visibility = { show: true },
  onChange,
  control,
  onRequestBind,
  autoFocus = false,
  className,
}: Props) {
  // An unexplained lock is a bug, not a state — no reason, no lock.
  const locked = !!visibility.locked && !!visibility.lockedReason;
  const lockedReason = visibility.lockedReason;
  /**
   * The label already prints `lockedReason` beside the param name, so the
   * control points at it rather than printing a second copy under itself.
   * Above the `show` guard because hooks cannot sit behind a condition.
   */
  const lockedId = useId();
  const bindRefusal = useRefusal(
    // The tray is the only way to bind a secret, and a builder rendered
    // without `onRequestBind` has no tray behind it — a catalog or a preview.
    // "Not available" would be true and useless; what the reader needs to know
    // is that this copy of the field is a picture of one.
    onRequestBind
      ? undefined
      : "This field is a preview — there is no Inputs tray open for it to bind from. Open the same step in a notebook to bind a value."
  );
  if (!visibility.show) return null;
  const val = visibility.forced != null ? visibility.forced : value ?? param.default ?? "";
  const title = param.doc || undefined;

  // Secret params (design v2 §22a): no free text, ever — bind-only. The literal
  // value never renders even when bound; only the $slotRef name is shown.
  if (param.secret) {
    const ref = slotRefOf(val);
    return (
      <div className={cn("param-field", className)} title={title}>
        <div className="mb-1.5 flex items-center gap-1.5">
          <code className="text-xs font-bold uppercase tracking-widest text-[var(--text-muted)]">
            {param.name}
          </code>
          <span className={cn("text-[9px]", ref ? "text-[var(--brand)]" : "text-[var(--warn)]")}>
            🔒
          </span>
          <span
            className={cn(
              "ml-auto text-[9px] font-medium",
              ref ? "text-[var(--brand)]" : "text-[var(--warn)]"
            )}
          >
            {ref ? "bound" : "secret"}
          </span>
        </div>
        {ref ? (
          <div className="flex h-[26px] items-center gap-1.5 rounded-[5px] border border-[color-mix(in_srgb,var(--brand)_30%,transparent)] bg-[color-mix(in_srgb,var(--brand)_7%,transparent)] px-2">
            <code className="font-mono text-[10.5px] font-medium text-[var(--brand)]">{ref}</code>
            <button
              type="button"
              className="ml-auto text-[9px] text-[var(--text-muted)] hover:text-[var(--text)]"
              aria-label={`Unbind ${param.name}`}
              title="Unbind"
              onClick={() => onChange(param.name, "")}
            >
              ✕
            </button>
          </div>
        ) : (
          <>
            <button
              type="button"
              className="flex h-[26px] w-full items-center rounded-[5px] border border-dashed border-[var(--border)] bg-[var(--surface)] px-2 text-left text-[10.5px] text-[var(--text-muted)] hover:border-[var(--brand)] hover:text-[var(--text)]"
              onClick={bindRefusal.guard(onRequestBind)}
              {...bindRefusal.aria}
            >
              Bind a value from Inputs…
            </button>
            {bindRefusal.note}
          </>
        )}
        {/* Unbound is the empty case for a secret: `ssh.encode passphrase=`
            left alone writes the private block in the clear, which is the
            same class of invisible default as `stun=`. */}
        <EmptyMeans param={param} value={ref ? val : ""} />
      </div>
    );
  }

  if (control) {
    return (
      <div className={cn("param-field", className)} title={title}>
        <label className="text-xs font-bold uppercase tracking-widest text-[var(--text-muted)] block mb-1.5">
          {param.name}
        </label>
        {control}
      </div>
    );
  }

  if (param.type === "bool" || param.type === "flag") {
    const checked = val === true || val === "true";

    // "decode" reads as a direction, not a toggle — segmented Encode/Decode.
    if (param.name === "decode") {
      return (
        <div className={cn("param-field", className)} title={title}>
          <label className="text-xs font-bold uppercase tracking-widest text-[var(--text-muted)] block mb-2">
            {param.name}
          </label>
          <div className="inline-flex rounded-md border border-[var(--border)] overflow-hidden bg-[var(--surface-raised)]">
            {(
              [
                { v: false, label: "Encode" },
                { v: true, label: "Decode" },
              ] as const
            ).map((opt) => (
              <button
                key={String(opt.v)}
                type="button"
                onClick={() => onChange(param.name, opt.v)}
                className={cn(
                  "px-3 py-1.5 text-sm font-bold border-l border-[var(--border)] first:border-l-0 transition-colors",
                  checked === opt.v
                    ? "bg-[var(--brand)] text-[var(--on-brand)]"
                    : "bg-[var(--surface)] text-[var(--text)] hover:bg-[var(--surface-raised)]"
                )}
              >
                {opt.label}
              </button>
            ))}
          </div>
        </div>
      );
    }

    return (
      <div className={cn("param-field param-field-bool", className)} title={title}>
        <label className="flex items-center gap-2 cursor-pointer">
          <input
            type="checkbox"
            checked={checked}
            onChange={(e) => onChange(param.name, e.target.checked)}
            className="w-4 h-4 rounded border-[var(--border)] bg-[var(--surface)] accent-[var(--brand)]"
          />
          <span className="text-sm font-semibold text-[var(--text)]">{param.name}</span>
          {param.flag ? (
            <code className="text-xs text-[var(--text-muted)] font-mono">{param.flag}</code>
          ) : null}
        </label>
      </div>
    );
  }

  if (param.type === "enum") {
    const enumValues = param.enum || [];
    // If <= 3 options, show as segmented buttons; otherwise use select
    if (enumValues.length <= 3) {
      return (
        <div className={cn("param-field", className)} title={title}>
          <label className="text-xs font-bold uppercase tracking-widest text-[var(--text-muted)] block mb-2">
            {param.name}
            {locked && (
              <span
                id={lockedId}
                data-disabled-reason
                className="ml-2 text-xs font-normal normal-case text-[var(--text-muted)]"
              >
                ({lockedReason})
              </span>
            )}
          </label>
          <div className="inline-flex rounded-md border border-[var(--border)] overflow-hidden bg-[var(--surface-raised)]">
            {enumValues.map((e) => (
              <button
                key={e}
                aria-disabled={locked || undefined}
                aria-describedby={locked ? lockedId : undefined}
                onClick={(event) => {
                  if (locked) {
                    event.preventDefault();
                    return;
                  }
                  onChange(param.name, e);
                }}
                className={cn(
                  "px-3 py-1.5 text-sm font-bold border-l border-[var(--border)] first:border-l-0 transition-colors",
                  String(val) === e
                    ? "bg-[var(--brand)] text-[var(--on-brand)]"
                    : "bg-[var(--surface)] text-[var(--text)] hover:bg-[var(--surface-raised)]"
                )}
              >
                {e}
              </button>
            ))}
          </div>
        </div>
      );
    }

    return (
      <div className={cn("param-field", className)} title={title}>
        <label className="text-xs font-bold uppercase tracking-widest text-[var(--text-muted)] block mb-1.5">
          {param.name}
          {/* `lockedReason`, not "locked by format": the second was a guess
              about which of the lock's several causes this one was, printed
              beside a control that had been handed the real answer. */}
          {locked && (
            <span
              id={lockedId}
              data-disabled-reason
              className="ml-2 text-xs font-normal normal-case text-[var(--text-muted)]"
            >
              ({lockedReason})
            </span>
          )}
        </label>
        {/* The one place the native attribute stays. `aria-disabled` on a
            <select> is advisory — the popup still opens and the value still
            changes — so the control has to be genuinely off, and the reason
            reaches it by description instead. */}
        <select
          className="w-full px-2.5 py-1.5 text-sm border border-[var(--border)] rounded-md bg-[var(--surface)] text-[var(--text)] focus:outline-none focus:ring-2 focus:ring-[var(--brand)] focus:ring-offset-1"
          disabled={locked}
          aria-describedby={locked ? lockedId : undefined}
          value={String(val)}
          onChange={(e) => onChange(param.name, e.target.value)}
        >
          {enumValues.map((e) => (
            <option key={e} value={e}>
              {e}
            </option>
          ))}
        </select>
      </div>
    );
  }

  return (
    <div className={cn("param-field", className)} title={title}>
      <label className="text-xs font-bold uppercase tracking-widest text-[var(--text-muted)] block mb-1.5">
        {param.name}
      </label>
      <input
        className="w-full px-2.5 py-1.5 text-sm border border-[var(--border)] rounded-md bg-[var(--surface)] text-[var(--text)] font-mono focus:outline-none focus:ring-2 focus:ring-[var(--brand)] focus:ring-offset-1"
        type={param.type === "int" ? "number" : "text"}
        value={String(val ?? "")}
        // The ghost text in the box says what the box is already doing. It is
        // the same phrase as the hint below, from the same registry field —
        // one is legible at a glance, the other survives a narrow column.
        placeholder={param.emptyMeans || undefined}
        autoFocus={autoFocus}
        onChange={(e) =>
          onChange(
            param.name,
            param.type === "int" ? Number(e.target.value) : e.target.value
          )
        }
      />
      <EmptyMeans param={param} value={val} />
    </div>
  );
}

type GroupProps = {
  params: ParamSpec[];
  values: Record<string, unknown>;
  visibilityFor?: (p: ParamSpec) => Visibility;
  onChange: (name: string, value: string | number | boolean) => void;
  /** Called with the param name when a secret field's "Bind…" is clicked. */
  onRequestBind?: (paramName: string) => void;
  /** One-shot: autofocus this param's field on mount (design v2 §22b). */
  focusParam?: string | null;
  className?: string;
};

export function ParamFieldGroup({
  params,
  values,
  visibilityFor,
  onChange,
  onRequestBind,
  focusParam,
  className,
}: GroupProps) {
  const visibleParams = params.filter((p) => visibilityFor?.(p)?.show !== false);

  return (
    <div className={cn("flex flex-col gap-4", className)}>
      {visibleParams.map((p) => (
        <ParamField
          key={p.name}
          param={p}
          value={values[p.name]}
          visibility={visibilityFor?.(p)}
          onChange={onChange}
          onRequestBind={onRequestBind ? () => onRequestBind(p.name) : undefined}
          autoFocus={!!focusParam && p.name === focusParam}
        />
      ))}
    </div>
  );
}
