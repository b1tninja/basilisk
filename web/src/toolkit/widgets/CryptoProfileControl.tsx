import { useMemo } from "react";
import { cn } from "@/lib/cn";
import { Badge } from "@/components/ui/badge";
import { formatFingerprint } from "../../lib/utils.js";
import { PROFILE_COMPATIBLE, PROFILE_MODERN } from "../../lib/pgp/encrypt.js";
import { customProfileFromParams } from "../../lib/pgp/profile-from-step.js";
import {
  describeProfileDivergence,
  formatProfileSpec,
} from "../../lib/pgp/encrypt-intent.js";
import type { ResolvedRecipient, StepCryptoProfile } from "../notebook-types";

/** @typedef {import("../../lib/pgp/types.js").EncryptProfile} EncryptProfile */
type EncryptProfile = {
  cipher: string;
  aead: string | null;
  compression: string;
  s2k: string;
};

export type CryptoProfileValue = {
  profile: StepCryptoProfile;
  cipher: string;
  aead: string;
  s2k: string;
  compression: string;
};

type Props = {
  value: CryptoProfileValue;
  onChange: (name: string, value: string) => void;
  /** Session default profile (Preferences → Cryptographic parameters), used when profile="auto". */
  sessionProfile: EncryptProfile;
  /** Recipients bound to this step — only meaningful for gpg.encrypt. */
  recipients?: ResolvedRecipient[];
  className?: string;
};

const PROFILE_OPTIONS: { value: StepCryptoProfile; label: string }[] = [
  { value: "auto", label: "Auto" },
  { value: "modern", label: "Modern" },
  { value: "compatible", label: "Compatible" },
  { value: "custom", label: "Custom" },
];

function resolveDisplayProfile(value: CryptoProfileValue, sessionProfile: EncryptProfile): EncryptProfile {
  if (value.profile === "modern") return { ...PROFILE_MODERN };
  if (value.profile === "compatible") return { ...PROFILE_COMPATIBLE };
  if (value.profile === "custom") return customProfileFromParams(value);
  return sessionProfile;
}

function compressionFlag(compression: string): string {
  if (compression === "zlib") return "1";
  if (compression === "zip") return "2";
  return "0";
}

function profileFlags(p: EncryptProfile): string {
  return `--cipher ${p.cipher} --aead ${p.aead || "off"} --s2k ${p.s2k} -z ${compressionFlag(p.compression)}`;
}

function SegmentedRow({
  options,
  value,
  onChange,
}: {
  options: [string, string][];
  value: string;
  onChange: (v: string) => void;
}) {
  return (
    <div className="inline-flex w-full overflow-hidden rounded-md border border-[var(--border)] bg-[var(--surface)]">
      {options.map(([v, label]) => (
        <button
          key={v}
          type="button"
          onClick={() => onChange(v)}
          className={cn(
            "flex-1 border-l border-[var(--border)] px-2 py-[6px] text-[length:11px] font-bold transition-colors first:border-l-0",
            value === v
              ? "bg-[var(--brand)] text-[var(--on-brand)]"
              : "bg-transparent text-[var(--foreground)] hover:bg-[var(--surface-raised)]"
          )}
        >
          {label}
        </button>
      ))}
    </div>
  );
}

/** Inline crypto-profile control for gpg.encrypt/gpg.symencrypt steps — design section 11. */
export function CryptoProfileControl({
  value,
  onChange,
  sessionProfile,
  recipients = [],
  className,
}: Props) {
  const profile = value.profile || "auto";
  const resolved = useMemo(
    () => resolveDisplayProfile(value, sessionProfile),
    [value, sessionProfile]
  );
  const divergence = useMemo(() => describeProfileDivergence(resolved), [resolved]);
  const flags = useMemo(() => profileFlags(resolved), [resolved]);
  const legacyRecipients = recipients.filter((r) => !r.modernCapable);

  return (
    <div
      className={cn(
        "crypto-profile-control rounded-lg border border-[var(--border)] bg-[var(--surface-raised)] p-3",
        className
      )}
    >
      <p className="mb-2 text-[length:10px] font-bold uppercase tracking-wider text-[var(--muted-foreground)]">
        Crypto profile
      </p>
      <div className="inline-flex w-full overflow-hidden rounded-md border border-[var(--border)] bg-[var(--surface)]">
        {PROFILE_OPTIONS.map((opt) => (
          <button
            key={opt.value}
            type="button"
            onClick={() => onChange("profile", opt.value)}
            className={cn(
              "flex-1 border-l border-[var(--border)] px-2 py-[7px] text-[length:11px] font-bold transition-colors first:border-l-0",
              profile === opt.value
                ? opt.value === "custom"
                  ? "bg-[color-mix(in_srgb,var(--warn)_70%,var(--surface))] text-[var(--foreground)]"
                  : "bg-[var(--brand)] text-[var(--on-brand)]"
                : "bg-transparent text-[var(--foreground)] hover:bg-[var(--surface-raised)]"
            )}
          >
            {opt.label}
          </button>
        ))}
      </div>

      {profile !== "custom" ? (
        <p className="mt-2 text-[length:11px] text-[var(--muted-foreground)]">
          {formatProfileSpec(resolved)}
          {profile === "auto" ? " · follows the session default" : ""}
        </p>
      ) : null}

      {profile === "auto" && recipients.length ? (
        <div className="mt-3 rounded-md border border-[var(--border)] bg-[var(--surface)] p-2.5">
          <p className="mb-1.5 text-[length:9.5px] font-bold uppercase tracking-wider text-[var(--muted-foreground)]">
            Resolved for these recipients
          </p>
          <ul className="space-y-1">
            {recipients.map((r) => (
              <li
                key={r.fingerprint}
                className="flex items-center justify-between gap-2 text-[length:11px]"
              >
                <span className="truncate">
                  {r.label || r.email || formatFingerprint(r.fingerprint)}
                </span>
                <Badge
                  variant={r.modernCapable ? "ok" : "warn"}
                  className="shrink-0 normal-case tracking-normal"
                >
                  {r.modernCapable ? "Modern" : "Compatible"}
                </Badge>
              </li>
            ))}
          </ul>
          {legacyRecipients.length ? (
            <p className="mt-1.5 text-[length:10px] text-[var(--muted-foreground)]">
              {legacyRecipients.length === recipients.length
                ? "None of these keys advertise SEIPD v2 — this step falls back to Compatible."
                : `${legacyRecipients.length} of ${recipients.length} recipient${
                    recipients.length === 1 ? "" : "s"
                  } predate AEAD — those get SEIPD v1, others are unaffected.`}
            </p>
          ) : null}
        </div>
      ) : null}

      {profile === "custom" ? (
        <div className="mt-3 space-y-3">
          <div>
            <p className="mb-1 text-[length:10px] font-bold uppercase tracking-wider text-[var(--muted-foreground)]">
              Cipher
            </p>
            <SegmentedRow
              options={[
                ["aes128", "AES128"],
                ["aes192", "AES192"],
                ["aes256", "AES256"],
              ]}
              value={value.cipher}
              onChange={(v) => onChange("cipher", v)}
            />
          </div>
          <div>
            <p className="mb-1 text-[length:10px] font-bold uppercase tracking-wider text-[var(--muted-foreground)]">
              AEAD
            </p>
            <select
              className="w-full rounded-md border border-[var(--border)] bg-[var(--surface)] px-2.5 py-[7px] text-[length:11.5px] focus:outline-none focus:ring-2 focus:ring-[var(--brand)] focus:ring-offset-1"
              value={value.aead}
              onChange={(e) => onChange("aead", e.target.value)}
            >
              <option value="off">Off · SEIPD v1, MDC only (legacy)</option>
              <option value="ocb">OCB · SEIPD v2</option>
              <option value="gcm">GCM · SEIPD v2</option>
              <option value="eax">EAX · SEIPD v2</option>
            </select>
          </div>
          <div>
            <p className="mb-1 text-[length:10px] font-bold uppercase tracking-wider text-[var(--muted-foreground)]">
              S2K
            </p>
            <SegmentedRow
              options={[
                ["argon2", "Argon2"],
                ["iterated", "Iterated"],
              ]}
              value={value.s2k}
              onChange={(v) => onChange("s2k", v)}
            />
          </div>
          <div>
            <p className="mb-1 text-[length:10px] font-bold uppercase tracking-wider text-[var(--muted-foreground)]">
              Compression
            </p>
            <SegmentedRow
              options={[
                ["off", "Off"],
                ["zlib", "ZLIB"],
                ["zip", "ZIP"],
              ]}
              value={value.compression}
              onChange={(v) => onChange("compression", v)}
            />
          </div>

          {divergence.preset !== "custom" ? (
            <div className="rounded-md border border-l-[3px] border-[color-mix(in_srgb,var(--warn)_45%,var(--border))] border-l-[var(--warn)] bg-[color-mix(in_srgb,var(--warn)_10%,transparent)] px-2.5 py-2">
              <p className="text-[length:11px] font-bold text-[var(--foreground)]">
                Same as {divergence.preset === "modern" ? "Modern" : "Compatible"} — no need for
                Custom
              </p>
              <p className="mt-0.5 text-[length:10.5px] text-[var(--muted-foreground)]">
                These four values match the{" "}
                {divergence.preset === "modern" ? "Modern" : "Compatible"} profile exactly. Switch
                back so the recipe stays readable, or keep Custom if you're about to change
                something.
              </p>
            </div>
          ) : null}

          <div className="flex items-center justify-between gap-2 rounded-md bg-[var(--surface)] px-2.5 py-[6px]">
            <code className="truncate text-[length:10.5px] text-[var(--muted-foreground)]">
              {flags}
            </code>
            <button
              type="button"
              className="shrink-0 text-[length:10.5px] font-bold text-[var(--brand)] hover:underline"
              onClick={() => void navigator.clipboard.writeText(flags)}
            >
              Copy flags
            </button>
          </div>
        </div>
      ) : null}
    </div>
  );
}
