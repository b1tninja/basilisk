import { useEffect, useRef } from "react";
import { mountRecipientBinder } from "../lib/recipient-picker.js";
import type { ResolvedRecipient } from "./notebook-types";

type Props = {
  slots: number;
  foreach?: boolean;
  /**
   * Recipients already chosen. The binder can be mounted twice — on the
   * encrypt step's own panel and in the Inputs tray — and without this the
   * second one opens empty, contradicting the first.
   */
  initial?: ResolvedRecipient[];
  onChange: (recs: ResolvedRecipient[]) => void;
  className?: string;
};

/** Host the existing vanilla recipient binder inside React (phase-1 bridge). */
export function RecipientBinderHost({
  slots,
  foreach = false,
  initial,
  onChange,
  className,
}: Props) {
  const ref = useRef<HTMLDivElement>(null);
  // Deliberately not a dependency below: this seeds the *initial* render, and
  // re-mounting on every selection would tear the binder down mid-interaction.
  const seed = useRef(initial);
  seed.current = initial;

  useEffect(() => {
    const el = ref.current;
    if (!el || slots <= 0) return;
    const binder = mountRecipientBinder(el, {
      slots,
      foreach,
      initial: seed.current,
      onChange: (
        recs: {
          fingerprint?: string;
          armoredKey?: string;
          label?: string;
          email?: string;
          modernCapable?: boolean;
        }[]
      ) => {
        onChange(
          (recs || [])
            .filter((r) => r?.fingerprint)
            .map((r) => ({
              fingerprint: String(r.fingerprint),
              armoredKey: String(r.armoredKey || ""),
              label: r.label || undefined,
              email: r.email || undefined,
              modernCapable: !!r.modernCapable,
            }))
        );
      },
    });
    return () => {
      try {
        binder.destroy?.();
      } catch {
        /* ignore */
      }
      el.innerHTML = "";
    };
  }, [slots, foreach, onChange]);

  return (
    <div
      ref={ref}
      className={className || "cell-bind-messaging cell-runtime-zone"}
    />
  );
}
