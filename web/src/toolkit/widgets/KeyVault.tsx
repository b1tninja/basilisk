import { useId, useState } from "react";
import { cn } from "@/lib/cn";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Fingerprint } from "@/components/ui/fingerprint";
import { RefusalLayout, useRefusal } from "@/components/ui/refusal";
import { loadedCount } from "@/lib/toolkit/key-power.js";
import type { TrustLevel } from "@/lib/trust.js";

/**
 * The browser vault, where the notebook can reach it.
 *
 * ## Why this is a panel and not a link to `/my-keys`
 *
 * The Keys tray used to be a read-only picker with a sentence pointing at
 * another page: "Full vault management is on My Keys." Everything a person
 * needed while holding a notebook — make a key, take one in, get one out, throw
 * one away — was one navigation away from the thing they were doing, on a page
 * behind a sign-in, under a heading that calls two different stores "keys". The
 * split that produced the original report is exactly that: `/my-keys` draws
 * "Your keys" (public keys on your account) above "Your browser vault" (private
 * keys in this browser) and a session told somebody with three of the first
 * that they had none of the second. Both statements were true.
 *
 * So the vault's home is here, beside the run that needs it. The verbs are
 * `lib/toolkit/vault-manage.js`'s, shared with `/my-keys` rather than
 * reimplemented, and **every refusal on this panel is one of that module's
 * sentences** — which is what stops a tray and a page from disagreeing about
 * why the same key cannot be exported.
 *
 * ## What the rows say
 *
 * Each row leads with `data-key-power`: what this key can do for you, here,
 * now (`lib/toolkit/key-power.js`). It is a closed set of five, so the colour
 * is the stylesheet's — `style-src 'self'` refuses the alternative, and the
 * value is the same one `SessionStart` and the run bar's chip read. A key that
 * says `ready` in the tray cannot be refused by the session for a reason the
 * tray did not show.
 *
 * ## Plain props, and why the callbacks return sentences
 *
 * Nothing here fetches, opens IndexedDB or reads a store — `ds-entry.ts`'s rule
 * for everything on the design surface. The vault acts are `Promise`-returning
 * props, and each resolves with the line to print or throws with the reason it
 * did not happen, which is the shape `SessionStart.onSearch` already uses. That
 * keeps the status text beside the control that produced it without this
 * component knowing what a vault is.
 */

/** The five states, as the attribute spells them. */
export type KeyPower = "absent" | "unusable" | "held" | "loaded" | "ready";

/** One live approval grant against a key (§27c). */
export type KeyGrant = { use: string; uses: number; expiresAt: number };

export type VaultKeyView = {
  fingerprint: string;
  uid?: string;
  email?: string;
  kind?: "pgp" | "ssh" | "raw";
  /** passphrase | passkey | device | session — the vault's own word. */
  protection?: string;
  /** `keyPower`'s answer, computed in the shell against the same clock. */
  power: KeyPower;
  /** `keyPowerReadout`'s label — two or three words for the row. */
  powerLabel: string;
  /** `keyPowerReadout`'s sentence, shown where the row has room for it. */
  why: string;
  /** When the agent session drops this key's armor, or null while it holds none. */
  loadedUntil?: number | null;
  /** OpenSSH public line, on ssh records only — public material, so it sits on the row. */
  publicLine?: string;
  trust?: TrustLevel | null;
  /** This browser's private note about which physical device holds the key. */
  deviceLabel?: string;
  grants?: KeyGrant[];
  /**
   * `expiryNote`'s verdict — "is this still good", not a date.
   *
   * Only inside a month, which is the discipline that makes it safe to put on
   * every row: a key expiring in a year is not news, and a warning on
   * everything trains people to ignore the one that counts. Null the rest of
   * the time, and `power` has already said `unusable` once it is past.
   */
  expiryNote?: { text: string; severity: "warn" | "error" } | null;
};

export type GenerateSpec = {
  name: string;
  email: string;
  expiryPreset: string;
  protection: "passphrase" | "passkey" | "device";
  passphrase: string;
};

export type ImportSpec = {
  armored: string;
  passphrase: string;
  target: "vault" | "session";
};

export type ExportSpec = {
  fingerprint: string;
  format: string;
  exportPassphrase: string;
};

export type KeyVaultProps = {
  keys: VaultKeyView[];
  /** Ticked once a second by the shell; every countdown here reads it. */
  now: number;
  /** Whether this browser can do WebAuthn PRF at all — decides one radio's fate. */
  passkeyAvailable: boolean;
  /** Why passkey protection is not on offer, when it is not. */
  passkeyRefusal?: string;
  onLockAll: () => void;
  onUnlock: (fingerprint: string) => void;
  onLock: (fingerprint: string) => void;
  onDelete: (fingerprint: string) => Promise<void>;
  onGenerate: (spec: GenerateSpec) => Promise<string>;
  onImport: (spec: ImportSpec) => Promise<string>;
  onExport: (spec: ExportSpec) => Promise<string>;
  onTrust: (fingerprint: string, level: TrustLevel) => void;
  onDeviceLabel: (fingerprint: string, label: string) => void;
  onCopyPublicLine: (fingerprint: string) => void;
  onInsertCell: (fingerprint: string, step: "agent.unlock" | "agent.pub") => void;
  /** A generated EFF-wordlist passphrase, fetched lazily by the shell. */
  onSuggestPassphrase: () => Promise<{ passphrase: string; bits: number }>;
  className?: string;
};

/** Every download `vault-manage.js` can write, in the order it lists them. */
const EXPORT_BUTTONS: { id: string; label: string }[] = [
  { id: "asc", label: "Armored (.asc)" },
  { id: "gpg", label: "Binary (.gpg)" },
  { id: "qr", label: "QR code (.svg)" },
  { id: "paper", label: "Paper backup (.html)" },
];

/** The presets `EXPIRY_PRESETS` knows, worded as a person would choose them. */
const EXPIRY_CHOICES: { id: string; label: string }[] = [
  { id: "1d", label: "1 day" },
  { id: "1w", label: "1 week" },
  { id: "1m", label: "1 month" },
  { id: "1y", label: "1 year" },
  { id: "none", label: "No expiration" },
];

const FIELD =
  "rounded-[6px] border border-[var(--border)] bg-[var(--surface)] px-2 py-1 text-[11px] text-[var(--foreground)]";

function countdown(ms: number): string {
  const total = Math.max(0, Math.round(ms / 1000));
  return `${Math.floor(total / 60)}:${String(total % 60).padStart(2, "0")}`;
}

/** A status line that is either what happened or why it did not. */
type Note = { tone: "ok" | "err"; text: string } | null;

function NoteLine({ note }: { note: Note }) {
  if (!note) return null;
  return (
    <p
      aria-live="polite"
      className={cn(
        "text-[10.5px] leading-snug",
        note.tone === "err" ? "text-[var(--warn)]" : "text-[var(--muted-foreground)]"
      )}
    >
      {note.text}
    </p>
  );
}

/** Run a vault act, and turn either outcome into one line of text. */
async function report(
  act: () => Promise<string | void>,
  ok: string,
  set: (note: Note) => void
) {
  try {
    const said = await act();
    set({ tone: "ok", text: typeof said === "string" && said ? said : ok });
    return true;
  } catch (err) {
    set({ tone: "err", text: err instanceof Error ? err.message : "That did not work." });
    return false;
  }
}

/**
 * Deleting a key, which is the one act on this panel nothing can undo.
 *
 * Two presses rather than a `confirm()`. A native dialog steals focus, cannot
 * carry the fingerprint in a form anybody can check, and reads out as a
 * sentence with a key id in it that the reader has no way to compare against
 * the row they clicked — and this app's own rule is that a decision about a key
 * is made where the key is drawn. The second press is the confirmation, and the
 * row is still on screen underneath it.
 */
function DeleteControl({
  view,
  onDelete,
  onNote,
}: {
  view: VaultKeyView;
  onDelete: (fingerprint: string) => Promise<void>;
  onNote: (note: Note) => void;
}) {
  const [armed, setArmed] = useState(false);
  const [busy, setBusy] = useState(false);
  if (!armed) {
    return (
      <Button size="sm" variant="ghost" onClick={() => setArmed(true)}>
        Delete
      </Button>
    );
  }
  return (
    <span className="inline-flex items-center gap-1">
      <Button
        size="sm"
        variant="ghost"
        busy={busy}
        className="text-[var(--error)]"
        onClick={() => {
          setBusy(true);
          void report(
            () => onDelete(view.fingerprint),
            "Deleted from this browser's vault.",
            onNote
          ).finally(() => {
            setBusy(false);
            setArmed(false);
          });
        }}
      >
        {busy ? "Deleting…" : "Delete for good"}
      </Button>
      <Button size="sm" variant="ghost" onClick={() => setArmed(false)}>
        Keep
      </Button>
      {/* Said at the moment of the decision, not in a dialog that covers the
          row. The vault is the only copy — there is no server-side backup of a
          private key and there never has been. */}
      <span className="text-[10px] leading-snug text-[var(--muted-foreground)]">
        This browser holds the only copy. Export it first if you want one.
      </span>
    </span>
  );
}

/** The four downloads, and the passphrase an unprotected key owes before them. */
function ExportPanel({
  view,
  onExport,
  onSuggestPassphrase,
}: {
  view: VaultKeyView;
  onExport: (spec: ExportSpec) => Promise<string>;
  onSuggestPassphrase: () => Promise<{ passphrase: string; bits: number }>;
}) {
  const [passphrase, setPassphrase] = useState("");
  const [suggested, setSuggested] = useState("");
  const [note, setNote] = useState<Note>(null);
  const [busyFormat, setBusyFormat] = useState("");
  const fieldId = useId();
  /**
   * Whether a passphrase is owed cannot be known before the envelope is open —
   * a device-protected record's armor is bare and a passphrase-protected one's
   * is not, and only the unlock tells them apart. So the field is offered
   * whenever the *stored* mode is not passphrase, and `exportRefusal` is what
   * actually decides, after the unlock, in the module both surfaces share.
   */
  const mayOweOne = view.protection !== "passphrase";

  return (
    <div className="mt-2 flex flex-col gap-1.5 rounded-[7px] border border-[var(--border)] p-2">
      {mayOweOne ? (
        <>
          <label className="text-[10px] font-bold text-[var(--muted-foreground)]" htmlFor={fieldId}>
            Export passphrase
          </label>
          <p className="text-[10px] leading-snug text-[var(--muted-foreground)]">
            This key is not passphrase-protected in the vault, and a file leaves
            this browser. Every export is written GnuPG-compatible and encrypted.
          </p>
          <div className="flex flex-wrap items-center gap-1.5">
            <input
              id={fieldId}
              type="password"
              autoComplete="new-password"
              className={cn(FIELD, "min-w-[150px] flex-1")}
              value={passphrase}
              onChange={(e) => setPassphrase(e.currentTarget.value)}
            />
            <Button
              size="sm"
              variant="ghost"
              onClick={() => {
                void onSuggestPassphrase().then(({ passphrase: made, bits }) => {
                  setPassphrase(made);
                  setSuggested(`${made} (~${bits} bits — write it down; you need it to import the key)`);
                });
              }}
            >
              Suggest
            </Button>
          </div>
          {suggested ? (
            <p className="break-all font-mono text-[10.5px] text-[var(--foreground)]">
              {suggested}
            </p>
          ) : null}
        </>
      ) : (
        <p className="text-[10px] leading-snug text-[var(--muted-foreground)]">
          Exports keep this key's existing passphrase — GnuPG will ask for it
          when you import the file.
        </p>
      )}
      <div className="flex flex-wrap gap-1">
        {EXPORT_BUTTONS.map((f) => (
          <Button
            key={f.id}
            size="sm"
            variant="secondary"
            busy={busyFormat === f.id}
            onClick={() => {
              setBusyFormat(f.id);
              void report(
                () =>
                  onExport({
                    fingerprint: view.fingerprint,
                    format: f.id,
                    exportPassphrase: passphrase,
                  }),
                "Exported.",
                setNote
              ).finally(() => setBusyFormat(""));
            }}
          >
            {f.label}
          </Button>
        ))}
      </div>
      <p className="text-[10px] leading-snug text-[var(--muted-foreground)]">
        Restore anywhere with <code className="font-mono">gpg --import</code>. The
        paper backup carries a QR code and printed instructions — store it like cash.
      </p>
      <NoteLine note={note} />
    </div>
  );
}

/** The private note about which physical device holds this key. */
function DeviceLabelControl({
  view,
  onDeviceLabel,
}: {
  view: VaultKeyView;
  onDeviceLabel: (fingerprint: string, label: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const [value, setValue] = useState(view.deviceLabel || "");
  const fieldId = useId();
  if (!open) {
    return (
      <Button size="sm" variant="ghost" onClick={() => setOpen(true)}>
        {view.deviceLabel ? `Device: ${view.deviceLabel}` : "Name the device"}
      </Button>
    );
  }
  return (
    <span className="inline-flex flex-wrap items-center gap-1">
      <label className="sr-only" htmlFor={fieldId}>
        Device label for this key
      </label>
      <input
        id={fieldId}
        type="text"
        maxLength={200}
        placeholder="e.g. Blue YubiKey 5C"
        className={cn(FIELD, "min-w-[140px]")}
        value={value}
        onChange={(e) => setValue(e.currentTarget.value)}
      />
      <Button
        size="sm"
        variant="secondary"
        onClick={() => {
          onDeviceLabel(view.fingerprint, value.trim());
          setOpen(false);
        }}
      >
        Save
      </Button>
      <Button size="sm" variant="ghost" onClick={() => setOpen(false)}>
        Cancel
      </Button>
      {/* Stored here and nowhere else, which is the whole reason it exists: a
          hardware serial number identifies the person carrying it. */}
      <span className="text-[10px] leading-snug text-[var(--muted-foreground)]">
        Kept in this browser only — never published, never sent.
      </span>
    </span>
  );
}

/** One key: what it can do, what it is, and everything you can do to it. */
function KeyRow({
  view,
  now,
  onUnlock,
  onLock,
  onDelete,
  onExport,
  onTrust,
  onDeviceLabel,
  onCopyPublicLine,
  onInsertCell,
  onSuggestPassphrase,
}: {
  view: VaultKeyView;
  now: number;
} & Pick<
  KeyVaultProps,
  | "onUnlock"
  | "onLock"
  | "onDelete"
  | "onExport"
  | "onTrust"
  | "onDeviceLabel"
  | "onCopyPublicLine"
  | "onInsertCell"
  | "onSuggestPassphrase"
>) {
  const [showExport, setShowExport] = useState(false);
  const [note, setNote] = useState<Note>(null);
  const loaded = view.power === "loaded" || view.power === "ready";
  /**
   * An `unusable` key has nothing to unlock *toward*. `vault.unlockKey` would
   * succeed — it knows nothing about validity or armor kind — and hand back
   * material the next step cannot use, which is the failure this state was
   * named to stop one screen earlier. So the button refuses in the readout's
   * own words rather than disappearing: the reader clicked something, and the
   * row they clicked has to answer.
   */
  const unlockRefusal = view.power === "unusable" ? view.why : undefined;
  /** Exporting is not signing: an expired or ssh key is still yours to back up. */
  const sessionOnly = view.protection === "session";

  return (
    <li
      className="rounded-[9px] border border-[var(--border)] bg-[var(--surface-raised)] p-3"
      data-key-power={view.power}
    >
      <div className="flex flex-wrap items-baseline gap-1.5 font-semibold">
        {view.kind && view.kind !== "pgp" ? (
          <span className="key-kind-badge" data-key-kind={view.kind}>
            {view.kind.toUpperCase()}
          </span>
        ) : null}
        <span className="min-w-0 break-words">{view.uid || view.email || "Key"}</span>
        <span className="key-power" data-key-power={view.power}>
          {view.powerLabel}
        </span>
      </div>
      <Fingerprint
        className="text-xs text-[var(--muted-foreground)]"
        fpr={view.fingerprint}
      />
      <div className="mt-1 text-xs text-[var(--muted-foreground)]">
        {view.protection || "device"}
        {view.expiryNote ? (
          <>
            {" · "}
            <span
              className={cn(
                "font-semibold",
                view.expiryNote.severity === "error"
                  ? "text-[var(--error)]"
                  : "text-[var(--warn)]"
              )}
            >
              {view.expiryNote.text}
            </span>
          </>
        ) : null}
        {loaded && view.loadedUntil ? (
          <>
            {" · "}
            <span className="font-mono text-[length:10.5px] text-[var(--warn)]">
              {countdown(view.loadedUntil - now)} left
            </span>
          </>
        ) : null}
      </div>
      {/* The sentence behind the badge. Drawn for every state except the two
          that are self-evident from the row above — a locked key in a vault
          list needs no paragraph explaining that it is in the vault. */}
      {view.power === "unusable" || view.power === "loaded" ? (
        <p className="mt-1 text-[10.5px] leading-snug text-[var(--muted-foreground)]">
          {view.why}
        </p>
      ) : null}
      {/* §27c: a grant nobody can see is a rubber stamp with extra steps. This
          one counts its uses live and shows its own clock. */}
      {(view.grants || []).map((g) => (
        <div
          key={g.use}
          className="mt-0.5 font-mono text-[length:10.5px] text-[var(--warn)]"
          data-approval-grant={g.use}
        >
          approved: {g.use} · {g.uses} {g.uses === 1 ? "use" : "uses"} ·{" "}
          {countdown(g.expiresAt - now)} left
        </div>
      ))}

      <div className="mt-2 flex flex-wrap items-center gap-1">
        {loaded ? (
          <Button size="sm" variant="ghost" onClick={() => onLock(view.fingerprint)}>
            Lock
          </Button>
        ) : (
          <Button
            size="sm"
            variant="secondary"
            disabledReason={unlockRefusal}
            onClick={() => onUnlock(view.fingerprint)}
          >
            Unlock
          </Button>
        )}
        <Button
          size="sm"
          variant="ghost"
          onClick={() => onInsertCell(view.fingerprint, "agent.unlock")}
        >
          Unlock → cell
        </Button>
        <Button
          size="sm"
          variant="ghost"
          onClick={() => onInsertCell(view.fingerprint, "agent.pub")}
        >
          Pub → cell
        </Button>
        {view.publicLine ? (
          // §28b: public material, so it sits on the row rather than behind
          // Export — it is the single most common thing anybody does with an
          // SSH key.
          <Button size="sm" variant="ghost" onClick={() => onCopyPublicLine(view.fingerprint)}>
            Copy public line
          </Button>
        ) : null}
      </div>

      <div className="mt-2 flex flex-wrap items-center gap-1">
        <Button
          size="sm"
          variant="ghost"
          aria-expanded={showExport}
          disabledReason={
            sessionOnly
              ? "This key was imported for this session only, so the vault has no record to export. It exists in memory until the session drops it."
              : undefined
          }
          onClick={() => setShowExport((v) => !v)}
        >
          Export
        </Button>
        <DeviceLabelControl view={view} onDeviceLabel={onDeviceLabel} />
        {sessionOnly ? null : (
          <DeleteControl view={view} onDelete={onDelete} onNote={setNote} />
        )}
      </div>

      <div className="mt-2 flex flex-wrap items-center gap-1">
        <span className="text-[length:10.5px] text-[var(--muted-foreground)]">Trust:</span>
        {(["trusted", "marginal", "never"] as TrustLevel[]).map((level) => (
          <Button
            key={level}
            variant={view.trust === level ? "secondary" : "ghost"}
            className={cn(
              "h-auto rounded-md px-[8px] py-[2px] text-[length:10px] font-semibold capitalize",
              view.trust === level && level === "trusted" && "text-[var(--success)]",
              view.trust === level && level === "never" && "text-[var(--error)]"
            )}
            onClick={() => onTrust(view.fingerprint, level)}
          >
            {level}
          </Button>
        ))}
      </div>

      {showExport ? (
        <ExportPanel
          view={view}
          onExport={onExport}
          onSuggestPassphrase={onSuggestPassphrase}
        />
      ) : null}
      <NoteLine note={note} />
    </li>
  );
}

/** Make a key here, in this browser, with no account and no server. */
function GenerateCard({
  passkeyAvailable,
  passkeyRefusal,
  onGenerate,
  onSuggestPassphrase,
}: Pick<
  KeyVaultProps,
  "passkeyAvailable" | "passkeyRefusal" | "onGenerate" | "onSuggestPassphrase"
>) {
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [expiryPreset, setExpiryPreset] = useState("1m");
  const [protection, setProtection] = useState<"passphrase" | "passkey" | "device">(
    "passphrase"
  );
  const [passphrase, setPassphrase] = useState("");
  const [suggested, setSuggested] = useState("");
  const [note, setNote] = useState<Note>(null);
  const [busy, setBusy] = useState(false);
  const ids = useId();
  const passkeyWhy =
    passkeyRefusal ||
    "This browser cannot do WebAuthn PRF, which is what turns a security key into a vault passphrase. Passphrase protection is the strong option here.";
  const passkey = useRefusal(passkeyAvailable ? undefined : passkeyWhy);

  return (
    <details className="rounded-[9px] border border-[var(--border)] p-2.5" data-vault-generate>
      <summary className="cursor-pointer text-[11px] font-bold">Generate a key here</summary>
      <div className="mt-2 flex flex-col gap-1.5">
        <p className="text-[10px] leading-snug text-[var(--muted-foreground)]">
          A Curve25519 OpenPGP keypair, made in a worker in this browser. The
          private half goes into this browser's vault and nowhere else — nothing
          is uploaded and no account is involved.
        </p>
        <label className="text-[10px] font-bold text-[var(--muted-foreground)]" htmlFor={`${ids}-name`}>
          Display name (optional)
        </label>
        <input
          id={`${ids}-name`}
          type="text"
          maxLength={100}
          className={FIELD}
          value={name}
          onChange={(e) => setName(e.currentTarget.value)}
        />
        <label className="text-[10px] font-bold text-[var(--muted-foreground)]" htmlFor={`${ids}-email`}>
          Address
        </label>
        <input
          id={`${ids}-email`}
          type="email"
          autoComplete="email"
          className={FIELD}
          value={email}
          onChange={(e) => setEmail(e.currentTarget.value)}
        />
        <label className="text-[10px] font-bold text-[var(--muted-foreground)]" htmlFor={`${ids}-expiry`}>
          Expires
        </label>
        <select
          id={`${ids}-expiry`}
          className={FIELD}
          value={expiryPreset}
          onChange={(e) => setExpiryPreset(e.currentTarget.value)}
        >
          {EXPIRY_CHOICES.map((c) => (
            <option key={c.id} value={c.id}>
              {c.label}
            </option>
          ))}
        </select>

        <fieldset className="m-0 flex flex-col gap-1 border-0 p-0">
          <legend className="p-0 text-[10px] font-bold text-[var(--muted-foreground)]">
            How the private half is protected
          </legend>
          <label className="flex items-baseline gap-1.5 text-[10.5px]">
            <input
              type="radio"
              name={`${ids}-protection`}
              checked={protection === "passphrase"}
              onChange={() => setProtection("passphrase")}
            />
            Passphrase (Argon2) — recommended
          </label>
          <RefusalLayout note={passkey.note}>
            <label className="flex items-baseline gap-1.5 text-[10.5px]">
              <input
                type="radio"
                name={`${ids}-protection`}
                checked={protection === "passkey"}
                {...passkey.aria}
                onChange={passkey.guard(() => setProtection("passkey"))}
              />
              Passkey or security key (WebAuthn PRF)
            </label>
          </RefusalLayout>
          <label className="flex items-baseline gap-1.5 text-[10.5px]">
            <input
              type="radio"
              name={`${ids}-protection`}
              checked={protection === "device"}
              onChange={() => setProtection("device")}
            />
            Device-only — weakest
          </label>
          {protection === "device" ? (
            <p className="text-[10px] leading-snug text-[var(--warn)]">
              Device-only asks for nothing at unlock, which means any script that
              gets onto this origin can use the key while the page is open.
            </p>
          ) : null}
        </fieldset>

        {protection === "passphrase" ? (
          <>
            <label
              className="text-[10px] font-bold text-[var(--muted-foreground)]"
              htmlFor={`${ids}-pw`}
            >
              Passphrase
            </label>
            <div className="flex flex-wrap items-center gap-1.5">
              <input
                id={`${ids}-pw`}
                type="password"
                autoComplete="new-password"
                className={cn(FIELD, "min-w-[150px] flex-1")}
                value={passphrase}
                onChange={(e) => setPassphrase(e.currentTarget.value)}
              />
              <Button
                size="sm"
                variant="ghost"
                onClick={() => {
                  void onSuggestPassphrase().then(({ passphrase: made, bits }) => {
                    setPassphrase(made);
                    setSuggested(`${made} (~${bits} bits — write it down before continuing)`);
                  });
                }}
              >
                Suggest
              </Button>
            </div>
            {suggested ? (
              <p className="break-all font-mono text-[10.5px] text-[var(--foreground)]">
                {suggested}
              </p>
            ) : null}
          </>
        ) : null}

        <Button
          busy={busy}
          onClick={() => {
            setBusy(true);
            void report(
              () => onGenerate({ name, email, expiryPreset, protection, passphrase }),
              "Key generated and stored in this browser's vault.",
              setNote
            )
              .then((ok) => {
                if (ok) setPassphrase("");
              })
              .finally(() => setBusy(false));
          }}
        >
          {busy ? "Generating…" : "Generate"}
        </Button>
        <NoteLine note={note} />
      </div>
    </details>
  );
}

/**
 * Taking a key in, to the vault or for this session only.
 *
 * One box and one choice, because the reader's decision is *where it goes*, not
 * which of two forms to fill in. Session-only was `quorum-mount.js`'s — paste
 * an armored key, use it once, never store it — and it had no home in the
 * notebook at all, while `refreshVault` has folded session entries into the key
 * list the whole time. The consumer was in place and there was no way to put
 * anything there.
 */
function ImportCard({
  onImport,
  onSuggestPassphrase,
}: Pick<KeyVaultProps, "onImport" | "onSuggestPassphrase">) {
  const [armored, setArmored] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [suggested, setSuggested] = useState("");
  const [target, setTarget] = useState<"vault" | "session">("vault");
  const [note, setNote] = useState<Note>(null);
  const [busy, setBusy] = useState(false);
  const ids = useId();

  return (
    <details className="rounded-[9px] border border-[var(--border)] p-2.5" data-vault-import>
      <summary className="cursor-pointer text-[11px] font-bold">Import a private key</summary>
      <div className="mt-2 flex flex-col gap-1.5">
        <Textarea
          className="min-h-[64px] font-mono text-[10.5px]"
          aria-label="Armored private key"
          placeholder="-----BEGIN PGP PRIVATE KEY BLOCK-----"
          spellCheck={false}
          value={armored}
          onChange={(e) => setArmored(e.currentTarget.value)}
        />
        <fieldset className="m-0 flex flex-col gap-1 border-0 p-0" data-import-target>
          <legend className="p-0 text-[10px] font-bold text-[var(--muted-foreground)]">
            Where it goes
          </legend>
          <label className="flex items-baseline gap-1.5 text-[10.5px]">
            <input
              type="radio"
              name={`${ids}-target`}
              checked={target === "vault"}
              onChange={() => setTarget("vault")}
            />
            Into this browser's vault — kept until you delete it
          </label>
          <label className="flex items-baseline gap-1.5 text-[10.5px]">
            <input
              type="radio"
              name={`${ids}-target`}
              checked={target === "session"}
              onChange={() => setTarget("session")}
            />
            For this session only — held in memory, never written down
          </label>
          <p className="text-[10px] leading-snug text-[var(--muted-foreground)]">
            {target === "vault"
              ? "A key with no passphrase of its own gets one here, because an openable private key in browser storage is what the vault exists to prevent."
              : "Nothing reaches storage, so nothing needs protecting: the armor lives in the agent session and goes when its five minutes run out, when you lock it, or when you close the tab."}
          </p>
        </fieldset>

        {target === "vault" ? (
          <>
            <label
              className="text-[10px] font-bold text-[var(--muted-foreground)]"
              htmlFor={`${ids}-import-pw`}
            >
              Passphrase to protect it, if it has none
            </label>
            <div className="flex flex-wrap items-center gap-1.5">
              <input
                id={`${ids}-import-pw`}
                type="password"
                autoComplete="new-password"
                className={cn(FIELD, "min-w-[150px] flex-1")}
                value={passphrase}
                onChange={(e) => setPassphrase(e.currentTarget.value)}
              />
              <Button
                size="sm"
                variant="ghost"
                onClick={() => {
                  void onSuggestPassphrase().then(({ passphrase: made, bits }) => {
                    setPassphrase(made);
                    setSuggested(`${made} (~${bits} bits — write it down)`);
                  });
                }}
              >
                Suggest
              </Button>
            </div>
            {suggested ? (
              <p className="break-all font-mono text-[10.5px] text-[var(--foreground)]">
                {suggested}
              </p>
            ) : null}
          </>
        ) : null}

        <Button
          busy={busy}
          disabledReason={
            armored.trim()
              ? undefined
              : "Paste an armored private key block first — there is nothing here to import."
          }
          onClick={() => {
            setBusy(true);
            void report(
              () => onImport({ armored, passphrase, target }),
              target === "vault"
                ? "Imported into this browser's vault."
                : "Loaded for this session only — it is in the key list until it expires.",
              setNote
            )
              .then((ok) => {
                if (!ok) return;
                setArmored("");
                setPassphrase("");
              })
              .finally(() => setBusy(false));
          }}
        >
          {busy ? "Importing…" : "Import"}
        </Button>
        <NoteLine note={note} />
      </div>
    </details>
  );
}

export function KeyVault({
  keys,
  now,
  passkeyAvailable,
  passkeyRefusal,
  onLockAll,
  onUnlock,
  onLock,
  onDelete,
  onGenerate,
  onImport,
  onExport,
  onTrust,
  onDeviceLabel,
  onCopyPublicLine,
  onInsertCell,
  onSuggestPassphrase,
  className,
}: KeyVaultProps) {
  // The same count the Keys tab button carries, from the same function, so the
  // badge and this header cannot disagree about how many keys are open.
  const loaded = loadedCount(keys.map((k) => k.power));
  return (
    <div className={cn("flex min-h-0 flex-col", className)} data-key-vault>
      <div className="flex items-center justify-between gap-2 border-b border-[var(--border)] p-3">
        <div>
          <h3 className="text-sm font-bold">Your browser vault</h3>
          <p className="mt-0.5 text-[length:10.5px] text-[var(--muted-foreground)]">
            Private keys held in this browser, envelope-encrypted with a
            device-bound key. Unlocking one loads its armor into the agent
            session for five minutes.
          </p>
        </div>
        {loaded > 0 ? (
          <Button
            variant="outline"
            className="h-auto shrink-0 rounded-[7px] border-[var(--error)] px-[9px] py-[4px] text-[length:11px] font-semibold text-[var(--error)]"
            onClick={onLockAll}
          >
            Lock all
          </Button>
        ) : null}
      </div>
      <div className="flex flex-col gap-3 px-3 py-3">
        {keys.length ? (
          <ul className="flex list-none flex-col gap-3 p-0">
            {keys.map((view) => (
              <KeyRow
                key={view.fingerprint}
                view={view}
                now={now}
                onUnlock={onUnlock}
                onLock={onLock}
                onDelete={onDelete}
                onExport={onExport}
                onTrust={onTrust}
                onDeviceLabel={onDeviceLabel}
                onCopyPublicLine={onCopyPublicLine}
                onInsertCell={onInsertCell}
                onSuggestPassphrase={onSuggestPassphrase}
              />
            ))}
          </ul>
        ) : (
          // Not an error. An empty vault is the ordinary first-run state, and
          // both ways out of it are on this panel rather than on another page.
          <p className="text-sm text-[var(--muted-foreground)]">
            Nothing held here yet. Generate a key below, or import one you
            already have — both stay in this browser.
          </p>
        )}
        <GenerateCard
          passkeyAvailable={passkeyAvailable}
          passkeyRefusal={passkeyRefusal}
          onGenerate={onGenerate}
          onSuggestPassphrase={onSuggestPassphrase}
        />
        <ImportCard onImport={onImport} onSuggestPassphrase={onSuggestPassphrase} />
      </div>
    </div>
  );
}
