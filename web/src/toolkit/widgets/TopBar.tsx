import { useEffect, useRef, useState, type ReactNode } from "react";
import { cn } from "@/lib/cn";

export type SuiteTone = "ok" | "warn" | "error";
export type SuiteDetail = { name: string; tone: SuiteTone; note: string };

// Tone colour comes from `[data-suite-tone]` rules in toolkit.css, never an
// inline style prop: the page runs under `style-src 'self'`, which blocks
// every `element.style` write. The tone set is closed, so a stylesheet can
// enumerate it (same conversion as ConnectionsPanel's peer dots).

type Props = {
  title: string;
  /** Commit a rename (Enter or blur). Esc cancels without committing. */
  onRename: (next: string) => void;
  placeholder?: string;
  /**
   * Id for the `<h1>` the title becomes — and, through it, the name of
   * whatever landmark the page hands this bar's subject.
   *
   * Optional because a heading is a claim about the page, not about this
   * widget: on `/toolkit` the notebook named here *is* the subject, and the
   * shell points its `<main>` at this id. On the widget gallery a TopBar is a
   * specimen in a catalogue of specimens, and an `h1` per specimen would be a
   * lie about the page it is pinned to. No id, no heading, no claim.
   */
  headingId?: string;
  /** Small muted text after the title (e.g. "3 cells"). */
  subtitle?: ReactNode;
  /** One pill, worst-status tone — click opens the per-suite popover (design v2 §21e). */
  suiteStatus?: { label: string; tone: SuiteTone };
  suiteDetail?: SuiteDetail[];
  /** Right-aligned chrome — Templates, More (design v2 §20d). */
  children?: ReactNode;
  className?: string;
};

/**
 * The title, wrapped in the page's `<h1>` when the page says it is one.
 *
 * Both branches go through here, the input included: the shell's `<main>` is
 * named by this id, and a name that vanishes for as long as someone is typing
 * a new one is worse than no name at all. A textbox inside a heading
 * contributes its *value* to the name computation, so the landmark tracks the
 * rename keystroke by keystroke rather than going quiet.
 *
 * The box is undone in toolkit.css. site.css sizes `h1` for a document — 24px,
 * a bottom margin, tightened tracking — and this is a 46px bar of chrome; the
 * heading is here for the outline, not for weight. It cannot be undone with
 * utility classes: site.css's element rules are unlayered and Tailwind's
 * utilities are in `@layer utilities`, so the element rule wins whatever the
 * specificity says. (Measured, before any of this: the shelf's `<p>` rendered
 * site.css's 8px paragraph margin, not its own `mb-1.5`.)
 */
function Heading({ id, children }: { id?: string; children: ReactNode }) {
  if (!id) return <>{children}</>;
  return (
    <h1 id={id} className="topbar-heading">
      {children}
    </h1>
  );
}

/**
 * Notebook identity bar — title is a plain span until clicked, then a
 * controlled input owned by TopBar's local state (design v2 §20d).
 */
export function TopBar({
  title,
  onRename,
  placeholder = "Untitled notebook",
  headingId,
  subtitle,
  suiteStatus,
  suiteDetail,
  children,
  className,
}: Props) {
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(title);
  const [suitePopoverOpen, setSuitePopoverOpen] = useState(false);
  const inputRef = useRef<HTMLInputElement | null>(null);
  const suiteRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (!suitePopoverOpen) return;
    const onDocClick = (e: MouseEvent) => {
      if (!suiteRef.current?.contains(e.target as Node)) setSuitePopoverOpen(false);
    };
    document.addEventListener("mousedown", onDocClick);
    return () => document.removeEventListener("mousedown", onDocClick);
  }, [suitePopoverOpen]);

  useEffect(() => {
    if (editing) inputRef.current?.select();
  }, [editing]);

  const commit = () => {
    setEditing(false);
    const next = draft.trim();
    if (next !== title) onRename(next);
  };

  return (
    <div
      className={cn(
        "flex min-h-[46px] flex-wrap items-center gap-2.5 border-b border-[var(--border)] px-3.5 py-1.5",
        className
      )}
      data-topbar
    >
      {editing ? (
        <>
          <Heading id={headingId}>
            <input
              ref={inputRef}
              className="w-[190px] rounded-[5px] border border-[var(--caret)] bg-[var(--surface)] px-[7px] py-[3px] text-[13px] font-medium text-[var(--foreground)] outline-none"
              value={draft}
              placeholder={placeholder}
              onChange={(e) => setDraft(e.target.value)}
              onBlur={commit}
              onKeyDown={(e) => {
                if (e.key === "Enter") commit();
                else if (e.key === "Escape") {
                  setDraft(title);
                  setEditing(false);
                }
              }}
            />
          </Heading>
          <span className="text-[10px] text-[var(--muted-foreground)]">
            Enter to save · Esc to cancel
          </span>
        </>
      ) : (
        <Heading id={headingId}>
          <button
            type="button"
            className="max-w-[20rem] cursor-text truncate rounded-[4px] px-[6px] py-[2px] text-left text-[13px] font-medium text-[var(--foreground)] hover:bg-[var(--surface-raised)]"
            title="Rename notebook"
            onClick={() => {
              setDraft(title);
              setEditing(true);
            }}
          >
            {title || <span className="text-[var(--muted-foreground)]">{placeholder}</span>}
          </button>
        </Heading>
      )}
      {!editing && subtitle ? (
        <span className="text-[length:10.5px] text-[var(--muted-foreground)]">{subtitle}</span>
      ) : null}

      {suiteStatus || children ? (
      <div className="ml-auto flex flex-wrap items-center gap-1.5">
        {suiteStatus ? (
          <div className="relative" ref={suiteRef}>
            <button
              type="button"
              aria-expanded={suitePopoverOpen}
              className="suite-pill flex items-center gap-1.5 rounded-full border px-[9px] py-[4px]"
              data-suite-tone={suiteStatus.tone}
              onClick={() => setSuitePopoverOpen((v) => !v)}
            >
              <span
                className="suite-tone-dot h-[5px] w-[5px] shrink-0 rounded-full"
                data-suite-tone={suiteStatus.tone}
                aria-hidden
              />
              <span
                className="suite-tone-text font-mono text-[10.5px] font-medium"
                data-suite-tone={suiteStatus.tone}
              >
                {suiteStatus.label}
              </span>
              <span
                className="suite-tone-text text-[8px]"
                data-suite-tone={suiteStatus.tone}
                aria-hidden
              >
                ▾
              </span>
            </button>
            {suitePopoverOpen && suiteDetail?.length ? (
              <div className="absolute right-0 top-full z-10 mt-1 w-[220px] rounded-[8px] border border-[var(--border)] bg-[var(--surface-raised)] p-[5px] shadow-[0_10px_30px_rgba(0,0,0,.5)]">
                {suiteDetail.map((s) => (
                  <div key={s.name} className="flex items-center gap-2 px-[9px] py-[7px]">
                    <span
                      className="suite-tone-dot h-[5px] w-[5px] shrink-0 rounded-full"
                      data-suite-tone={s.tone}
                      aria-hidden
                    />
                    <span className="flex-1 font-mono text-[11px] font-medium text-[var(--foreground)]">
                      {s.name}
                    </span>
                    <span
                      className="suite-tone-note text-[10px]"
                      data-suite-tone={s.tone}
                    >
                      {s.note}
                    </span>
                  </div>
                ))}
              </div>
            ) : null}
          </div>
        ) : null}
        {children}
      </div>
      ) : null}
    </div>
  );
}
