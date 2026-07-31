/**
 * Toolkit Agent ops — local My Keys vault (gpg-agent metaphor).
 * Unlock / save need the window thread (passkey PRF + IndexedDB UX).
 */

import { ensurePassphraseProtected, inspectPrivateKey } from "../key-export.js";
import { bytesToBase64 } from "./encode.js";
import { sshFingerprint } from "../ssh/fingerprint.js";
import { buildPublicBlob, formatPublicLine } from "../ssh/wire.js";
import { encodeOpensshPrivateKey } from "../ssh/openssh-key-v1.js";
import { execSshDecode } from "./ssh-ops.js";
import { pipelineKeyHandles } from "./webcrypto-ops.js";
import {
  createPasskeyPrf,
  expiryIsoFromPreset,
  listKeys,
  saveKey,
} from "../vault.js";
import { unlockVaultForUse } from "../vault-unlock.js";
import { normalizeVaultFingerprint } from "../vault-session.js";
import { getToolkitPrefs } from "./prefs.js";
import { openPgpKeyPipelineValue } from "./recipients-ops.js";

/**
 * @param {Record<string, *>} params
 * @param {import("./engine.js").RuntimeBindings} [bindings]
 */
export async function execAgentUnlock(params = {}, bindings = {}) {
  const fpr = normalizeVaultFingerprint(params.fpr);
  const kindShaped = fpr.startsWith("SHA256:") || fpr.startsWith("spki:");
  if (!kindShaped && fpr.length < 40) {
    throw new Error(
      "agent.unlock requires fpr= (40+ hex fingerprint, or a SHA256:… ssh key id)"
    );
  }
  const openPgpPassphrase = String(
    bindings?.inputs?.gpg?.passphrase || bindings?.inputs?.agent?.passphrase || ""
  );
  const result = await unlockVaultForUse(fpr, {
    openPgpPassphrase,
    skipSession: getToolkitPrefs().sessionOff,
  });
  if (result.kind && result.kind !== "pgp") {
    // §28d: a non-PGP key materializes as live CryptoKeys — the honest type
    // for what it is; it flows into sign/ecdh/export with no casts.
    return materializeUnlockedKey(result);
  }
  return openPgpKeyPipelineValue(result.armored, {
    which: "private",
    fingerprint: result.fingerprint,
    protection: result.protection,
    sensitive: true,
  });
}

/**
 * @param {Record<string, *>} params
 */
export async function execAgentPub(params = {}) {
  const fpr = normalizeVaultFingerprint(params.fpr);
  const kindShaped = fpr.startsWith("SHA256:") || fpr.startsWith("spki:");
  if (!kindShaped && fpr.length < 40) {
    throw new Error(
      "agent.pub requires fpr= (40+ hex fingerprint, or a SHA256:… ssh key id)"
    );
  }
  const keys = await listKeys();
  const meta = keys.find((k) => k.fingerprint === fpr);
  if (!meta) throw new Error("Key not found in vault");
  if (meta.kind === "ssh") {
    // The ssh counterpart of publicArmored — the one-line public form, the
    // thing authorized_keys and GitHub actually want.
    const line = String(meta.publicLine || "").trim();
    if (!line) throw new Error("No publicLine stored for this ssh key — re-save it");
    return { type: "text", data: line, meta: { kind: "ssh-public", fingerprint: fpr } };
  }
  if (meta.kind === "raw") {
    throw new Error("agent.pub: raw keys store no public serialization — agent.unlock and export spki");
  }
  const pub = String(meta.publicArmored || "").trim();
  if (!pub.includes("BEGIN PGP")) {
    throw new Error(
      "No publicArmored stored for this key — unlock it once (Encrypt / Decrypt / agent.unlock) to backfill"
    );
  }
  return openPgpKeyPipelineValue(pub, {
    which: "public",
    fingerprint: fpr,
    label: meta.uid || meta.email || fpr,
    email: meta.email || "",
  });
}

/**
 * @returns {Promise<{ type: "text", data: string, meta: object }>}
 */
export async function execAgentList() {
  const keys = await listKeys();
  const rows = keys.map((k) => ({
    fingerprint: k.fingerprint,
    // Absent kind means a legacy record, which is definitionally pgp (§28a).
    kind: k.kind || "pgp",
    uid: k.uid || "",
    email: k.email || "",
    name: k.name || "",
    protection: k.protection,
    lastUsedAt: k.lastUsedAt || null,
    expires: k.expires ?? null,
    ...(k.kind === "ssh" && k.publicLine ? { publicLine: k.publicLine } : {}),
  }));
  return {
    type: "text",
    data: JSON.stringify(rows, null, 2),
    meta: { sensitive: false, kind: "opaque", vaultList: true },
  };
}

/**
 * @param {{ type?: string, data?: * }|null} value
 * @param {Record<string, *>} params
 * @param {import("./engine.js").RuntimeBindings} [bindings]
 * @returns {Promise<{ type: "text", data: string, meta: object }>}
 */
export async function execAgentSave(value, params = {}, bindings = {}) {
  if (value?.type === "keypair" || value?.type === "key") {
    return saveKeypairKind(value, params);
  }
  if (
    !value ||
    (value.type !== "text" &&
      !(value.type === "openpgp-key" && value.meta?.which !== "public"))
  ) {
    throw new Error("agent.save expects openpgp-key/private on the pipeline");
  }
  let armored = String(value.data || "").trim();
  if (!armored.includes("PRIVATE KEY BLOCK")) {
    throw new Error("agent.save expects an armored PRIVATE key block");
  }

  const protection = String(params.protection || "device").toLowerCase();
  if (!["device", "passphrase", "passkey"].includes(protection)) {
    throw new Error("agent.save protection= must be device|passphrase|passkey");
  }

  const panelPass = String(
    bindings?.inputs?.gpg?.passphrase || bindings?.inputs?.agent?.passphrase || ""
  );
  const emailParam = String(params.email || "").trim();
  const nameParam = String(params.name || "").trim();
  const expiryPreset = String(params.expiry || "none");

  const info = await inspectPrivateKey(armored);
  const fingerprint = info.fingerprint;
  const email = emailParam || info.email || "";
  const name = nameParam || "";
  const uid =
    name && email ? `${name} <${email}>` : email || info.uid || fingerprint;

  /** @type {Uint8Array|undefined} */
  let prfIkm;
  /** @type {import("../webauthn/mds.js").MdsLookupResult|undefined} */
  let mds;

  try {
    if (protection === "passphrase") {
      if (!panelPass && !info.locked) {
        throw new Error(
          "agent.save protection=passphrase needs a key passphrase (Inputs panel)"
        );
      }
      if (!info.locked && panelPass) {
        armored = await ensurePassphraseProtected(armored, panelPass);
      }
    }
    if (protection === "passkey") {
      const prf = await createPasskeyPrf(email || "basilisk-vault");
      prfIkm = prf.prfIkm;
      mds = prf.mds;
    }

    await saveKey({
      fingerprint,
      armoredPrivate: armored,
      uid,
      email,
      name,
      expires: expiryIsoFromPreset(expiryPreset),
      protection: /** @type {"device"|"passphrase"|"passkey"} */ (protection),
      prfIkm,
      mds,
    });
  } finally {
    try {
      prfIkm?.fill?.(0);
    } catch (_) {
      /* wipe */
    }
  }

  return openPgpKeyPipelineValue(armored, {
    which: "private",
    fingerprint,
    vaultSaved: true,
    protection,
    sensitive: true,
  });
}

/** §28b, verbatim — the honest constraint, not a silent downgrade. */
export const NON_PGP_PASSPHRASE_MESSAGE =
  "Passphrase protection for SSH keys needs an encryption this browser build does not ship yet — use passkey or device protection.";

const b64u = (bytes) => bytesToBase64(bytes).replace(/=+$/, "");

/**
 * SSH-mappable wire material from a private JWK, or null when SSH has no
 * key type for it (x25519 and friends → kind "raw").
 * @param {JsonWebKey} jwk
 */
function sshMaterialOrNull(jwk) {
  const fieldBytes = (b64url) => {
    const b64 = String(b64url).replace(/-/g, "+").replace(/_/g, "/");
    const bin = atob(b64 + "=".repeat((4 - (b64.length % 4)) % 4));
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  };
  if (jwk.kty === "OKP" && jwk.crv === "Ed25519" && jwk.d) {
    return { type: "ssh-ed25519", pub: fieldBytes(jwk.x), priv: fieldBytes(jwk.d) };
  }
  if (jwk.kty === "EC" && jwk.d) {
    const curveName = { "P-256": "nistp256", "P-384": "nistp384", "P-521": "nistp521" }[
      jwk.crv || ""
    ];
    if (!curveName) return null;
    const x = fieldBytes(jwk.x);
    const y = fieldBytes(jwk.y);
    const point = new Uint8Array(1 + x.length + y.length);
    point[0] = 4;
    point.set(x, 1);
    point.set(y, 1 + x.length);
    return {
      type: `ecdsa-sha2-${curveName}`,
      curveName,
      point,
      scalar: fieldBytes(jwk.d),
    };
  }
  if (jwk.kty === "RSA" && jwk.d) {
    return {
      type: "ssh-rsa",
      n: fieldBytes(jwk.n),
      e: fieldBytes(jwk.e),
      d: fieldBytes(jwk.d),
      p: fieldBytes(jwk.p),
      q: fieldBytes(jwk.q),
      iqmp: fieldBytes(jwk.qi),
    };
  }
  return null;
}

/**
 * `agent.save` on a WebCrypto keypair (§28a): SSH-mappable algorithms save
 * as kind "ssh" (payload openssh-key-v1, id the SSH SHA256 fingerprint);
 * everything else asymmetric saves as kind "raw" (payload the private JWK,
 * id SHA-256 over the SPKI DER, `spki:`-prefixed).
 *
 * Symmetric keys are refused rather than half-stored: they have no SPKI to
 * fingerprint and no public half to list, so a vault row for one would be
 * a label over nothing the listing can honestly display. Slots hold them
 * fine within a run.
 *
 * @param {{ type?: string, data?: *, meta?: * }} value
 * @param {Record<string, *>} params
 */
async function saveKeypairKind(value, params) {
  const protection = String(params.protection || "device").toLowerCase();
  if (!["device", "passphrase", "passkey"].includes(protection)) {
    throw new Error("agent.save protection= must be device|passphrase|passkey");
  }
  if (protection === "passphrase") {
    // §28b: today's passphrase mode is OpenPGP S2K on the armor, which a
    // non-PGP payload does not have; encrypted openssh-key-v1 needs
    // bcrypt_pbkdf (deferred). Refuse, never silently downgrade.
    throw new Error(NON_PGP_PASSPHRASE_MESSAGE);
  }

  const handles = pipelineKeyHandles(value);
  if (handles.secretKey || (handles.privateKey?.algorithm?.name || "").startsWith("AES") || handles.privateKey?.algorithm?.name === "HMAC") {
    throw new Error(
      "agent.save stores asymmetric keys — a symmetric key has no public half to list. Keep it in a slot, or wrap it with a stored key."
    );
  }
  const privateKey = handles.privateKey;
  if (!privateKey) throw new Error("agent.save needs a private key (public halves need no vault)");
  if (!privateKey.extractable) {
    throw new Error("agent.save: key is not extractable — regenerate it with genkey to store it");
  }

  const jwk = await crypto.subtle.exportKey("jwk", privateKey);
  const alg = String(value.meta?.alg || "").toLowerCase() || (jwk.crv || jwk.kty || "").toLowerCase();
  const emailParam = String(params.email || "").trim();
  const nameParam = String(params.name || "").trim();
  const comment = emailParam || nameParam || "";

  /** @type {"ssh"|"raw"} */
  let kind;
  /** @type {string} */
  let id;
  /** @type {string} */
  let payload;
  let publicLine = "";

  const material = sshMaterialOrNull(jwk);
  if (material) {
    kind = "ssh";
    const blob = buildPublicBlob(material);
    id = await sshFingerprint(blob);
    publicLine = formatPublicLine(blob, comment);
    payload = encodeOpensshPrivateKey(material, { comment });
  } else {
    kind = "raw";
    if (!handles.publicKey) {
      throw new Error("agent.save: raw keypairs need their public half to fingerprint (spki)");
    }
    const spki = new Uint8Array(await crypto.subtle.exportKey("spki", handles.publicKey));
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", spki));
    id = `spki:SHA256:${b64u(digest)}`;
    payload = JSON.stringify(jwk);
  }

  /** @type {Uint8Array|undefined} */
  let prfIkm;
  /** @type {import("../webauthn/mds.js").MdsLookupResult|undefined} */
  let mds;
  try {
    if (protection === "passkey") {
      const prf = await createPasskeyPrf(comment || "basilisk-vault");
      prfIkm = prf.prfIkm;
      mds = prf.mds;
    }
    await saveKey({
      fingerprint: id,
      armoredPrivate: payload,
      uid: nameParam ? `${nameParam} (${alg})` : comment ? `${comment} (${alg})` : `${alg} keypair`,
      email: emailParam,
      name: nameParam,
      expires: expiryIsoFromPreset(String(params.expiry || "none")),
      protection: /** @type {"device"|"passkey"} */ (protection),
      prfIkm,
      mds,
      kind,
      publicLine,
      alg,
    });
  } finally {
    try {
      prfIkm?.fill?.(0);
    } catch (_) {
      /* wipe */
    }
  }

  // Pass the keypair through, stamped with where it now lives — the same
  // contract the pgp path keeps (the pipeline value is unchanged in kind).
  return {
    ...value,
    meta: {
      ...(value.meta || {}),
      sensitive: true,
      vaultSaved: true,
      fingerprint: id,
      vaultKind: kind,
      ...(publicLine ? { publicLine } : {}),
    },
  };
}

/**
 * Non-PGP unlock (§28d): materialize the stored payload back into live
 * CryptoKeys — the honest type for what it is; it flows into sign/ecdh/
 * export with no casts. The §26c exposure treatment applies identically.
 * @param {import("../vault-unlock.js").VaultUnlockResult} result
 */
export async function materializeUnlockedKey(result) {
  if (result.kind === "ssh") {
    const v = await execSshDecode({ type: "text", data: result.armored });
    return {
      ...v,
      meta: {
        ...(v.meta || {}),
        sensitive: true,
        fingerprint: result.fingerprint,
        protection: result.protection,
        vaultKind: "ssh",
      },
    };
  }
  // raw: the payload is the private JWK.
  const jwk = JSON.parse(result.armored);
  if (jwk.kty === "OKP" && jwk.crv === "X25519") {
    const priv = await crypto.subtle.importKey("jwk", jwk, "X25519", true, [
      "deriveBits",
      "deriveKey",
    ]);
    const pubJwk = { kty: jwk.kty, crv: jwk.crv, x: jwk.x };
    const pub = await crypto.subtle.importKey("jwk", pubJwk, "X25519", true, []);
    return {
      type: "keypair",
      data: { privateKey: priv, publicKey: pub },
      meta: {
        alg: "x25519",
        sensitive: true,
        fingerprint: result.fingerprint,
        protection: result.protection,
        vaultKind: "raw",
      },
    };
  }
  throw new Error(
    `agent.unlock: stored raw key has kty=${jwk.kty}/${jwk.crv || "?"} — no import path for it yet`
  );
}
