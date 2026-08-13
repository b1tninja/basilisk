/**
 * What a key can do for you, here, now.
 *
 * The split that produced the original report was on **where the bytes live**:
 * `/my-keys` drew "Your keys" (the public keys `/api/v1/me/keys` holds for your
 * account) above "Your browser vault" (the private keys `vault.js` keeps in
 * IndexedDB) and called both of them keys. So a person with three
 * account keys was told by the session that they had none, and both statements
 * were true about different things. Storage is not a property anybody is asking
 * about. What they are asking is whether *this* key can sign the thing in front
 * of them right now.
 *
 * Five answers, and they are the whole vocabulary:
 *
 * - **`absent`** — not held in this browser at all. There is nothing to unlock.
 * - **`unusable`** — held here, and cannot sign a PGP invite whatever you do to
 *   it today: an `ssh`/`raw` record, or an OpenPGP key past its expiry.
 * - **`held`** — the private key is in this vault, and nothing is open.
 * - **`loaded`** — armor is in `vault-session`, the clock is running, and
 *   something is still owed before it can sign.
 * - **`ready`** — loaded, and nothing this browser can see is still owed.
 *
 * It is a **closed set**, which is why it travels as a `data-key-power`
 * attribute the stylesheet enumerates rather than as a colour chosen at the call
 * site — the same shape as `data-key-kind`, `data-cast` and `data-action-tier`,
 * and the same reason: `style-src 'self'` refuses the alternative.
 *
 * `keyOwesPassphrase` lives here rather than in `session-flow.js`, where it was
 * written. It is the fact that separates `loaded` from `ready`, so this is the
 * module it belongs to — and the layering has to run this way round: the
 * session's refusals are built on the vocabulary, not the vocabulary on the
 * session's refusals. `startIssues` imports it from here now, which is one
 * spelling of one fact rather than a re-export creating a second import path.
 *
 * @module lib/toolkit/key-power
 */

import { expiryInstant } from "./artifact-readouts.js";

/**
 * Every value `data-key-power` may take, in order of increasing capability.
 *
 * Exported so the stylesheet's rules and the tests that sweep them have one
 * list to answer to; a sixth state added here without a rule beside it is the
 * kind of drift a closed vocabulary exists to prevent.
 */
export const KEY_POWERS = Object.freeze([
  "absent",
  "unusable",
  "held",
  "loaded",
  "ready",
]);

/**
 * @typedef {object} PowerKey
 * @property {string} [fingerprint]
 * @property {"pgp"|"ssh"|"raw"|string} [kind]  absent means a legacy vault
 *   record, which is definitionally pgp
 * @property {string} [protection]  passphrase | passkey | device | session
 * @property {number|string|Date|null} [expires]
 * @property {boolean|undefined} [locked]  `sessionList`'s answer for this key
 * @property {boolean} [loaded]  whether `vault-session` is holding its armor
 */

/**
 * Whether this key still owes an OpenPGP passphrase before it can sign.
 *
 * Two locks, and only one of them is the vault's. `vault.unlockKey` opens the
 * device-bound envelope and returns armor that may still be S2K-protected, so
 * "unlocked" and "usable" are different claims about the same key — the
 * distinction `sessionPut` records and this reads.
 *
 * Observation beats intent: `locked` came from parsing the armor that
 * `decryptKey` will be handed, so where it disagrees with `protection` it wins.
 * `protection` answers for a key that is not loaded, because that is all there
 * is to go on before an unlock — and it is what the mode *means*
 * ("passphrase: OpenPGP S2K/Argon2 locks the armored key before wrapping").
 *
 * `undefined` where neither settles it, and callers must stay silent on it. A
 * sentence about a passphrase that may not be owed is a refusal naming a state
 * the reader is not in, which is the failure this whole repair is about.
 *
 * @param {PowerKey|null|undefined} key
 * @returns {boolean|undefined}
 */
export function keyOwesPassphrase(key) {
  if (!key) return undefined;
  if (typeof key.locked === "boolean") return key.locked;
  const protection = String(key.protection || "");
  if (protection === "passphrase") return true;
  if (protection === "device" || protection === "passkey") return false;
  return undefined;
}

/**
 * Whether this row's `expires` is a statement about the *key's* validity.
 *
 * A session-only row carries the agent session's TTL in the same field — it is
 * five minutes from the unlock, not a certificate lifetime — so reading it as
 * validity would print "this key expired" about a key that expired at nothing.
 * That is a refusal naming a state the reader is not in, said about the one
 * kind of key the reader most recently created by hand.
 *
 * @param {PowerKey} key
 */
function expiryIsTheKeys(key) {
  return String(key?.protection || "") !== "session";
}

/**
 * Whether an OpenPGP key is past its expiry, by this browser's clock.
 *
 * **The instant, not the day.** `expiryNote` deliberately answers in days and
 * never runs a timer, because it is advice on a card and a warning that changes
 * under the reader is worse than one that is a few hours coarse. This is not
 * advice — it decides whether a key is offered to sign with — and at day
 * resolution a key that expired this morning answers "expires today" and is
 * still offered, which is the very failure the state exists to prevent. Both
 * read `expiryInstant`, so there is still one normalizer and one place the
 * three spellings of an expiry are reconciled.
 *
 * @param {PowerKey} key
 * @param {number} [now]  Unix milliseconds
 * @returns {boolean}
 */
export function keyIsExpired(key, now = Date.now()) {
  if (!key || !expiryIsTheKeys(key)) return false;
  const at = expiryInstant(key.expires);
  return at != null && at <= now;
}

/**
 * What this key can do, here, now.
 *
 * Total, and `absent` is what nothing answers to — a fingerprint with no row is
 * a key this browser does not hold, which is a real state and the one the
 * session's empty picker was in.
 *
 * `ready` absorbs `keyOwesPassphrase`'s `undefined`, deliberately. Undefined
 * means *nobody established it*, and this app's standing rule is that an
 * unestablished lock may not produce a refusal — a "needs a passphrase" on a
 * device key is the same defect pointing the other way. `keyPowerReadout` is
 * written to match: `ready` claims only that nothing this browser can see is
 * still owed, which is exactly what is known.
 *
 * @param {PowerKey|null|undefined} key
 * @param {number} [now]  Unix milliseconds
 * @returns {"absent"|"unusable"|"held"|"loaded"|"ready"}
 */
export function keyPower(key, now = Date.now()) {
  if (!key) return "absent";
  if (String(key.kind || "pgp") !== "pgp") return "unusable";
  if (keyIsExpired(key, now)) return "unusable";
  if (!key.loaded) return "held";
  return keyOwesPassphrase(key) === true ? "loaded" : "ready";
}

/** How a date is printed in these sentences — the ISO day, no locale guessing. */
function isoDay(expires) {
  const at = expiryInstant(expires);
  return at == null ? "" : new Date(at).toISOString().slice(0, 10);
}

/**
 * @typedef {object} KeyPowerReadout
 * @property {"absent"|"unusable"|"held"|"loaded"|"ready"} power
 * @property {string} label   two or three words, for a chip or a row
 * @property {string} why     a sentence naming the state and the way out of it
 */

/**
 * The state, as a word and as a sentence.
 *
 * It takes the key rather than the power because **`unusable` is two states**,
 * and a refusal has to name the one the reader is in: an SSH key and an expired
 * OpenPGP key are both unable to sign an invite, and telling the holder of an
 * expired key that they are looking at an SSH key would be a confident lie. The
 * power alone cannot tell them apart, so the power alone is not the input.
 *
 * @param {PowerKey|null|undefined} key
 * @param {number} [now]  Unix milliseconds
 * @returns {KeyPowerReadout}
 */
export function keyPowerReadout(key, now = Date.now()) {
  const power = keyPower(key, now);
  if (power === "absent") {
    return {
      power,
      label: "not here",
      why: "No private key with this fingerprint is held in this browser, so there is nothing to unlock. Import it under Keys, or generate one there.",
    };
  }
  if (power === "unusable") {
    const kind = String(key?.kind || "pgp");
    if (kind !== "pgp") {
      return {
        power,
        label: `${kind} key`,
        why: `This is ${kind === "ssh" ? "an OpenSSH" : "a raw"} key. A shared session signs an OpenPGP invite and every envelope after it, so only an OpenPGP key can open one — this key is held here and cannot.`,
      };
    }
    const day = isoDay(key?.expires);
    return {
      power,
      label: "expired",
      why: `This key expired${day ? ` on ${day}` : ""}. OpenPGP refuses to sign with an expired key, so unlocking it here would succeed and the signature would still fail — extend it or use another key.`,
    };
  }
  if (power === "held") {
    return {
      power,
      // The act, not the adjective. "Locked" beside a list of vault keys says
      // nothing a reader could not already see; the session's chooser needs to
      // tell somebody what this key will ask of them if they pick it, and it is
      // the same answer in both places.
      label: "needs an unlock",
      why: "The private key is in this browser's vault and nothing is open. Unlock it to load its armor into the agent session for five minutes.",
    };
  }
  if (power === "loaded") {
    return {
      power,
      label: "open, needs its passphrase",
      why: "The vault's own envelope is open and OpenPGP's S2K lock is still on the armor, so this key cannot sign yet. Type its passphrase under Inputs → Key passphrase; unlocking the vault does not remove that second lock.",
    };
  }
  return {
    power,
    label: "ready",
    why: "Loaded into the agent session, and nothing this browser can see is still owed. It can sign now, until its five minutes run out.",
  };
}

/**
 * How many of these are open — the number the Keys tab button carries.
 *
 * It takes **powers**, not rows, so the tab's badge, the tray's header and the
 * run bar's chip all count the same already-decided list rather than each
 * re-deriving a power from a differently-shaped row. A count that disagrees
 * with the list beside it is the original report in miniature.
 *
 * `loaded` and `ready` both count: the badge says how many keys have armor in
 * memory with a clock running, which is what Lock all acts on. Whether one of
 * them still owes a passphrase is the row's business.
 *
 * @param {string[]} powers
 * @returns {number}
 */
export function loadedCount(powers) {
  return (Array.isArray(powers) ? powers : []).filter(
    (p) => p === "loaded" || p === "ready"
  ).length;
}

/**
 * The best any of these keys can do — what a chip for the whole browser says.
 *
 * `KEY_POWERS` is ordered by capability precisely so this is a maximum rather
 * than a table of special cases, and the summary is the *strongest* rather than
 * the weakest because the chip answers "can I do the thing", not "is everything
 * perfect". A person holding one ready key and one expired one can sign.
 *
 * An empty list is `absent`, which is the honest reading: nothing held.
 *
 * @param {string[]} powers
 * @returns {"absent"|"unusable"|"held"|"loaded"|"ready"}
 */
export function strongestPower(powers) {
  let best = 0;
  for (const p of Array.isArray(powers) ? powers : []) {
    const rank = KEY_POWERS.indexOf(p);
    if (rank > best) best = rank;
  }
  return /** @type {"absent"|"unusable"|"held"|"loaded"|"ready"} */ (KEY_POWERS[best]);
}
