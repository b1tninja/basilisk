import { KeyVault, keyPowerReadout } from "basilisk-portal";

/*
 * The browser vault, where the notebook can reach it.
 *
 * Every row leads with `data-key-power`: **what this key can do for you, here,
 * now**. That is a closed set of five, and it is the whole point of the panel.
 * The split it replaced was on *where the bytes live* — a page with "Your keys"
 * (public keys on an account) above "Your browser vault" (private keys in this
 * browser), both called keys — which is how a person holding three of the first
 * was told by a shared session that they had none of the second. Both statements
 * were true, about different things.
 *
 * Three things worth carrying into any design that touches a key:
 *
 * - **An open envelope is not a usable key.** The vault's device-bound wrapper
 *   and OpenPGP's own S2K passphrase are two different locks, and unlocking here
 *   removes only the first. `loaded` and `ready` are two states for that reason,
 *   and "unlocked · 4:58 left" was a true sentence about the envelope and a
 *   false one about the key.
 * - **`unusable` is two states and the row says which.** An ssh key and an
 *   expired OpenPGP key both cannot sign an invite, and telling the holder of an
 *   expired key that they are looking at an SSH key would be a confident lie.
 * - **Delete is two presses, never a `confirm()`.** A native dialog steals
 *   focus, cannot carry the fingerprint anybody can check, and covers the row
 *   the decision is about.
 *
 * The badge wording is `keyPowerReadout`'s own, so these cards cannot drift from
 * the words the product prints.
 */

const ADA = "D772078C5C7C2A0EDCA09ED32C5EBBB46AD01388";
const GRACE = "9F2A11B4C8D30E5761AA0C4E88B2F6D5091C7E43";
const LIN = "44C1D9E07B8A2F631E5D0A9C2B7E4F81D3A65029";
const SSH = "SHA256:Ur1hQxK8mN3vZpLyD7aQwE5rT2yU8iO0pAsDfGhJkLm";

const NOW = Date.parse("2026-08-12T12:00:00Z");
const inDays = (n: number) => new Date(NOW + n * 86_400_000).toISOString();

const noop = () => {};
const never = async () => "";

const base = {
  now: NOW,
  passkeyAvailable: true,
  onLockAll: noop,
  onUnlock: noop,
  onLock: noop,
  onDelete: async () => {},
  onGenerate: never,
  onImport: never,
  onExport: never,
  onTrust: noop,
  onDeviceLabel: noop,
  onCopyPublicLine: noop,
  onInsertCell: noop,
  onSuggestPassphrase: async () => ({ passphrase: "acorn ridge candle mint", bits: 62 }),
};

/**
 * What `keyPowerReadout` reads, and nothing else.
 *
 * `kind` is a closed set here. `PowerKey` spells it `"pgp"|"ssh"|"raw"|string`
 * so a legacy vault record can arrive with anything in it; the row the panel
 * draws does not, and a preview is the one place both shapes meet.
 */
type PowerFacts = {
  kind?: "pgp" | "ssh" | "raw";
  /** passphrase | passkey | device | session — the vault's own word. */
  protection?: string;
  expires?: string | number | null;
  /** `sessionList`'s answer: is OpenPGP's own S2K lock still on the armor. */
  locked?: boolean;
  /** Whether the agent session is holding this key's armor at all. */
  loaded?: boolean;
};

/** What the panel draws that the readout has no opinion about. */
type RowExtras = {
  uid?: string;
  email?: string;
  publicLine?: string;
  loadedUntil?: number | null;
  deviceLabel?: string;
};

/**
 * A row, with its badge and sentence taken from the product's own readout.
 *
 * **`PowerKey` and `VaultKeyView` are two different shapes**, and the split
 * here is the point rather than tidiness. `keyPowerReadout` is asked only about
 * what it reads — kind, protection, expiry, and the two locks — and everything
 * the panel draws around that answer (`uid`, `publicLine`, `loadedUntil`) stays
 * on the row and is never handed to it. Spreading one into the other is how a
 * `uid` came to be passed to a function that has never had one, and how
 * `expires` and `locked` came to be set on a row that has no such fields.
 */
function row(fingerprint: string, facts: PowerFacts, extras: RowExtras = {}) {
  const readout = keyPowerReadout({ fingerprint, ...facts }, NOW);
  return {
    fingerprint,
    kind: facts.kind,
    protection: facts.protection,
    power: readout.power,
    powerLabel: readout.label,
    why: readout.why,
    ...extras,
  };
}

/**
 * **The ordinary state: keys held, nothing open.** No countdown, no colour, no
 * warning — an at-rest vault key is not a hazard and drawing it as one would
 * spend the reader's attention on the wrong row.
 */
export const AtRest = () => (
  <KeyVault
    {...base}
    keys={[
      row(ADA, { protection: "passphrase" }, { uid: "Ada Lovelace <ada@example.org>" }),
      row(GRACE, { protection: "passkey" }, { uid: "Grace Hopper <grace@example.org>" }),
    ]}
  />
);

/**
 * **One key open, one still owing its passphrase.** The countdown is the agent
 * session's five minutes; the second row is the distinction the whole vocabulary
 * exists for — the vault let go and OpenPGP has not, so the run would fail at
 * the signature with the reader several steps away from the choice.
 */
export const Open = () => (
  <KeyVault
    {...base}
    keys={[
      row(
        ADA,
        { protection: "device", loaded: true, locked: false },
        { uid: "Ada Lovelace <ada@example.org>", loadedUntil: NOW + 238_000 }
      ),
      row(
        GRACE,
        { protection: "passphrase", loaded: true, locked: true },
        { uid: "Grace Hopper <grace@example.org>", loadedUntil: NOW + 61_000 }
      ),
    ]}
  />
);

/**
 * **Both kinds of `unusable`, side by side.** An OpenPGP key past its expiry and
 * an SSH key: neither can sign a session invite, and each says why in its own
 * terms. Unlock refuses rather than disappearing — the reader pressed something,
 * and the row they pressed has to answer.
 */
export const CannotSign = () => (
  <KeyVault
    {...base}
    keys={[
      row(
        LIN,
        { protection: "passphrase", expires: inDays(-4) },
        { uid: "Lin Zhou <lin@example.org>" }
      ),
      row(
        SSH,
        { kind: "ssh", protection: "device" },
        {
          uid: "lin@workstation",
          publicLine: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIF9k lin@workstation",
        }
      ),
    ]}
  />
);

/**
 * **An empty vault, which is the ordinary first run and not an error.** Both
 * ways out of it are on this panel — generate, or import — rather than on
 * another page behind a sign-in, which is the change this component is.
 */
export const Empty = () => <KeyVault {...base} keys={[]} />;

/**
 * **A browser with no WebAuthn PRF.** The passkey option refuses with a sentence
 * instead of vanishing: an option that is simply absent teaches nobody why the
 * security key in their hand is not on offer.
 */
export const NoPasskeySupport = () => (
  <KeyVault
    {...base}
    passkeyAvailable={false}
    keys={[
      row(ADA, { protection: "passphrase" }, { uid: "Ada Lovelace <ada@example.org>" }),
    ]}
  />
);
