/**
 * Making, taking in, and getting out a private key — the vault's own verbs.
 *
 * These were `my-keys-mount.js`'s, written as HTML strings with the decisions
 * interleaved into the DOM wiring: `wireGenerateForm` reads four inputs,
 * validates three of them, and generates; `runVaultExport` unlocks, re-protects
 * and downloads inside one click handler. None of it could be called from
 * anywhere else and none of it could be tested without a browser.
 *
 * The Keys tray needs the same verbs, and the way to have two surfaces for one
 * vault is not two implementations of the verbs — it is one module of verbs and
 * two surfaces. So the refusals below are **functions that return sentences**,
 * separate from the acts that follow them: a refusal is the part that has to be
 * identical between a tray and a page, and it is also the only part that can be
 * tested in node.
 *
 * Nothing here writes to the DOM or reads a form. `downloadFile` is the one
 * exception and it is a browser act by definition — the same one `key-export.js`
 * has always owned.
 *
 * @module lib/toolkit/vault-manage
 */

import {
  armoredToBinary,
  armoredToQrSvg,
  downloadFile,
  ensurePassphraseProtected,
  inspectPrivateKey,
  isArmoredKeyLocked,
  paperBackupHtml,
} from "../key-export.js";
import { estimatePassphraseStrength } from "../pgp/passphrase.js";
import { sessionPut } from "../vault-session.js";
import {
  EXPIRY_PRESETS,
  createPasskeyPrf,
  expiryIsoFromPreset,
  getPasskeyPrf,
  saveKey,
  unlockKey,
} from "../vault.js";

/** The armor header every one of these paths is looking for. */
const PRIVATE_BLOCK = "PRIVATE KEY BLOCK";

/** Every download this module can produce, and what each one is called. */
export const EXPORT_FORMATS = Object.freeze([
  { id: "asc", label: "Armored (.asc)", ext: "private.asc", mime: "application/pgp-keys" },
  { id: "gpg", label: "Binary (.gpg)", ext: "private.gpg", mime: "application/octet-stream" },
  { id: "qr", label: "QR code (.svg)", ext: "private-qr.svg", mime: "image/svg+xml" },
  { id: "paper", label: "Paper backup (.html)", ext: "paper-backup.html", mime: "text/html" },
]);

/**
 * Why a passphrase is not good enough yet, or "" when it is.
 *
 * One function because three surfaces ask it — generate, import, export — and
 * the estimator's own hint is what makes the refusal actionable. "Too weak" on
 * its own is the word that ends the question.
 *
 * @param {string} passphrase
 * @returns {string}
 */
export function passphraseRefusal(passphrase) {
  const est = estimatePassphraseStrength(String(passphrase || ""));
  if (est.label !== "weak") return "";
  return `That passphrase is about ${est.bits} bits, which is weak enough to be worth guessing. ${est.hint}`;
}

/**
 * Why this key cannot be generated yet, or "" when it can.
 *
 * @param {{ email?: string, protection?: string, passphrase?: string, confirm?: string }} spec
 * @returns {string}
 */
export function generateRefusal(spec) {
  const email = String(spec?.email || "").trim();
  if (!email.includes("@")) {
    // An OpenPGP user id is a name and an address, and the address is what the
    // keyserver, the recipient picker and every `gpg --recv-keys` search key
    // off. A key with none is a key nobody can look up, including you.
    return "An OpenPGP key is identified by an address, so this needs one — it becomes the key's user id and it is what a keyserver search finds.";
  }
  if (String(spec?.protection || "passphrase") !== "passphrase") return "";
  const passphrase = String(spec?.passphrase || "");
  if (!passphrase) {
    return "Passphrase protection was chosen and no passphrase is typed. It is what makes a stolen copy of this browser's vault useless, so it cannot be blank.";
  }
  if (passphrase !== String(spec?.confirm ?? passphrase)) {
    return "The two passphrases are different. A key protected with one you did not mean to type is a key you cannot open.";
  }
  return passphraseRefusal(passphrase);
}

/**
 * Why this armor cannot be taken in yet, or "" when it can.
 *
 * `locked` is what `inspectPrivateKey` observed, or undefined before anything
 * has looked. Undefined asks for nothing: a paste box that demanded a
 * passphrase before it had read the armor would be asking about a key it has
 * not seen.
 *
 * **Session-only never asks for one.** The point of that target is that the
 * armor is used once and never written down, so there is no vault record to
 * protect and no reason to make somebody invent a passphrase for a key that
 * expires in five minutes. The vault target is the opposite: an unprotected
 * key on disk is the state the vault exists to prevent.
 *
 * @param {{ armored?: string, locked?: boolean, passphrase?: string,
 *   target?: "vault"|"session" }} spec
 * @returns {string}
 */
export function importRefusal(spec) {
  const armored = String(spec?.armored || "");
  if (!armored.includes(PRIVATE_BLOCK)) {
    return "That is not an armored private key. Paste the block that begins -----BEGIN PGP PRIVATE KEY BLOCK----- — a public key cannot sign or decrypt anything.";
  }
  if (String(spec?.target || "vault") === "session") return "";
  if (spec?.locked !== false) return "";
  const passphrase = String(spec?.passphrase || "");
  if (!passphrase) {
    return "This key carries no passphrase of its own, and storing it that way would put an openable private key in this browser's storage. Set one, or import it for this session only.";
  }
  return passphraseRefusal(passphrase);
}

/**
 * Why an export cannot go yet, or "" when it can.
 *
 * `armorLocked` is what the *unlocked* armor turned out to be, so this is asked
 * after the vault envelope is open and not before — a device-protected key has
 * nothing to type until that moment.
 *
 * @param {{ armorLocked?: boolean, exportPassphrase?: string }} spec
 * @returns {string}
 */
export function exportRefusal(spec) {
  if (spec?.armorLocked !== false) return "";
  const passphrase = String(spec?.exportPassphrase || "");
  if (!passphrase) {
    return "This key is not passphrase-protected in the vault, and an export leaves this browser. Set an export passphrase — every file this writes is GnuPG-compatible and encrypted.";
  }
  return passphraseRefusal(passphrase);
}

/**
 * Generate a keypair in the worker and store it in the vault.
 *
 * It does **not** publish. `my-keys-mount.js` follows this with a POST to
 * `/api/v1/me/keys`, because that page is behind a sign-in and publishing is an
 * account act; the tray has no account and a key that exists only here is a
 * complete, usable key. Publishing stays where the session that authorizes it
 * is.
 *
 * @param {{ name?: string, email: string, expiryPreset?: string,
 *   protection?: "passphrase"|"passkey"|"device", passphrase?: string }} spec
 * @returns {Promise<{ fingerprint: string, publicArmored: string,
 *   mds?: import("../webauthn/mds.js").MdsLookupResult }>}
 */
export async function generateVaultKey(spec) {
  const refusal = generateRefusal({ ...spec, confirm: spec?.passphrase });
  if (refusal) throw new Error(refusal);

  const email = String(spec.email).trim();
  const name = String(spec?.name || "").trim();
  const preset = String(spec?.expiryPreset || "1m");
  const protection = /** @type {"passphrase"|"passkey"|"device"} */ (
    spec?.protection || "passphrase"
  );
  const passphrase = protection === "passphrase" ? String(spec?.passphrase || "") : "";

  let armoredPrivate = "";
  /** @type {Uint8Array|undefined} */
  let prfIkm;
  /** @type {import("../webauthn/mds.js").MdsLookupResult|undefined} */
  let mds;
  /** @type {import("../vault.js").PrfEnrolment|undefined} */
  let prfEnrolment;
  try {
    // Lazy, matching `engine.js` and `keyring-service.js`: the worker pulls
    // OpenPGP in, and most notebooks never generate a key.
    const { generateKeyViaWorker } = await import("../generate-key.js");
    const gen = await generateKeyViaWorker({
      email,
      name,
      keyExpirationTime: EXPIRY_PRESETS[preset] ?? null,
      passphrase,
    });
    armoredPrivate = gen.armoredPrivate;

    if (protection === "passkey") {
      const prf = await createPasskeyPrf(email);
      prfIkm = prf.prfIkm;
      mds = prf.mds;
      prfEnrolment = prf.enrolment;
    }

    await saveKey({
      fingerprint: gen.fingerprint,
      armoredPrivate,
      publicArmored: gen.armoredPublic,
      uid: name ? `${name} <${email}>` : email,
      email,
      name,
      expires: expiryIsoFromPreset(preset),
      protection,
      prfIkm,
      prfEnrolment,
      mds,
    });
    return { fingerprint: gen.fingerprint, publicArmored: gen.armoredPublic, mds };
  } finally {
    // Strings are immutable, so this drops the reference rather than the bytes
    // — the same best effort `my-keys-mount.js` makes, and the same one
    // `sessionEvict` documents.
    armoredPrivate = "";
    try {
      prfIkm?.fill?.(0);
    } catch (_) {
      /* wipe */
    }
  }
}

/**
 * Take an armored private key in — to the vault, or for this session only.
 *
 * The two targets are the same paste box and genuinely different acts, which is
 * why the target is a parameter rather than two functions: what a reader
 * decides is *where it goes*, and a UI with two boxes would be asking them to
 * decide it twice. `quorum-mount.js`'s session-only identity was this, and it
 * had no home in the notebook at all.
 *
 * The session target writes no vault record and records what it observed about
 * the armor, so `sessionList` can say whether a passphrase is still owed rather
 * than leaving the chrome to guess — see `sessionPut`.
 *
 * @param {string} armored
 * @param {{ passphrase?: string, target?: "vault"|"session" }} [opts]
 * @returns {Promise<{ fingerprint: string, uid: string, target: "vault"|"session" }>}
 */
export async function importPrivateKey(armored, opts = {}) {
  const target = opts.target === "session" ? "session" : "vault";
  let text = String(armored || "").trim();
  const shapeRefusal = importRefusal({ armored: text, target });
  if (shapeRefusal) throw new Error(shapeRefusal);

  const info = await inspectPrivateKey(text);
  const refusal = importRefusal({
    armored: text,
    locked: info.locked,
    passphrase: opts.passphrase,
    target,
  });
  if (refusal) throw new Error(refusal);

  if (target === "session") {
    sessionPut(info.fingerprint, text, { locked: info.locked });
    text = "";
    return { fingerprint: info.fingerprint, uid: info.uid, target };
  }

  if (!info.locked) text = await ensurePassphraseProtected(text, String(opts.passphrase || ""));
  await saveKey({
    fingerprint: info.fingerprint,
    armoredPrivate: text,
    uid: info.uid,
    email: info.email,
    expires: info.expires,
    protection: "passphrase",
  });
  text = "";
  return { fingerprint: info.fingerprint, uid: info.uid, target };
}

/**
 * Unlock a vault key, make sure it is protected, and download it.
 *
 * The protection step is not optional and not a preference: a device- or
 * passkey-protected vault entry holds armor with no passphrase on it, and the
 * vault's own wrapper does not travel with the file. Writing that to disk would
 * turn the strongest storage mode into the weakest file, so the export is
 * re-locked with a passphrase the reader supplies. `exportRefusal` is where
 * that is said before anything is unlocked.
 *
 * @param {{ fingerprint: string, format: string, exportPassphrase?: string,
 *   meta?: import("../vault.js").VaultKeyMeta|null }} spec
 * @returns {Promise<{ filename: string }>}
 */
export async function exportVaultKey(spec) {
  const fpr = String(spec?.fingerprint || "");
  const format = EXPORT_FORMATS.find((f) => f.id === spec?.format);
  if (!format) {
    throw new Error(
      `There is no "${spec?.format}" export. This vault writes armored, binary, QR and paper backups.`
    );
  }

  /** @type {{ passphrase?: string, prfIkm?: Uint8Array }} */
  const unlockOpts = {};
  let armored = "";
  try {
    if (spec?.meta?.protection === "passkey") unlockOpts.prfIkm = await getPasskeyPrf(fpr);
    armored = await unlockKey(fpr, unlockOpts);

    const armorLocked = await isArmoredKeyLocked(armored);
    const refusal = exportRefusal({ armorLocked, exportPassphrase: spec?.exportPassphrase });
    if (refusal) throw new Error(refusal);
    if (!armorLocked) {
      armored = await ensurePassphraseProtected(armored, String(spec?.exportPassphrase || ""));
    }

    const shortId = fpr.slice(-8).toLowerCase();
    const filename = `${shortId}-${format.ext}`;
    if (format.id === "asc") {
      downloadFile(filename, armored, format.mime);
    } else if (format.id === "gpg") {
      downloadFile(filename, await armoredToBinary(armored), format.mime);
    } else if (format.id === "qr") {
      downloadFile(filename, armoredToQrSvg(armored), format.mime);
    } else {
      downloadFile(
        filename,
        paperBackupHtml({
          armored,
          fingerprint: fpr,
          uid: spec?.meta?.uid || spec?.meta?.email || "",
          expires: spec?.meta?.expires || null,
        }),
        format.mime
      );
    }
    return { filename };
  } finally {
    armored = "";
    try {
      unlockOpts.prfIkm?.fill?.(0);
    } catch (_) {
      /* wipe */
    }
  }
}
