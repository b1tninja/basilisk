/**
 * Toolkit Agent ops — local My Keys vault (gpg-agent metaphor).
 * Unlock / save need the window thread (passkey PRF + IndexedDB UX).
 */

import { ensurePassphraseProtected, inspectPrivateKey } from "../key-export.js";
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
  if (fpr.length < 40) {
    throw new Error("agent.unlock requires fpr= (40+ hex fingerprint)");
  }
  const openPgpPassphrase = String(
    bindings?.inputs?.gpg?.passphrase || bindings?.inputs?.agent?.passphrase || ""
  );
  const result = await unlockVaultForUse(fpr, {
    openPgpPassphrase,
    skipSession: getToolkitPrefs().sessionOff,
  });
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
  if (fpr.length < 40) {
    throw new Error("agent.pub requires fpr= (40+ hex fingerprint)");
  }
  const keys = await listKeys();
  const meta = keys.find((k) => k.fingerprint === fpr);
  if (!meta) throw new Error("Key not found in vault");
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
    uid: k.uid || "",
    email: k.email || "",
    name: k.name || "",
    protection: k.protection,
    lastUsedAt: k.lastUsedAt || null,
    expires: k.expires ?? null,
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
