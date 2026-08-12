/**
 * Toolkit Agent ops — local My Keys vault (gpg-agent metaphor).
 * Unlock / save need the window thread (passkey PRF + IndexedDB UX).
 */

import { decryptKey, decrypt as openpgpDecrypt, readMessage, readPrivateKey } from "openpgp";
import { signOpenPgp } from "../pgp/sign.js";
import {
  digestForApproval,
  requireApproval,
  keyIdText,
} from "./approval-gate.js";
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
    return saveKeypairKind(value, params, bindings);
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
  /** @type {import("../vault.js").PrfEnrolment|undefined} */
  let prfEnrolment;

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
      prfEnrolment = prf.enrolment;
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
      prfEnrolment,
      mds,
      // A recipe that says `agent.save protection=device` said it out loud,
      // with the fingerprint in front of it; the vault's default refusal is
      // for the paths where a single click could weaken a key by accident.
      onConflict: "replace",
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

/**
 * §28b, verbatim — the honest constraint, narrowed to what is still true.
 *
 * SSH-mappable keys now take a passphrase: they store as openssh-key-v1, and
 * that container has a passphrase form (`bcrypt_pbkdf` + `aes256-ctr`). Keys
 * of kind `raw` — x25519 today — store as a bare private JWK, which has no
 * standard passphrase form to write, so the refusal survives for exactly
 * those. Naming the kind matters: "SSH keys are not supported" was the
 * sentence, and it is now the wrong one.
 */
export const NON_PGP_PASSPHRASE_MESSAGE =
  "Passphrase protection needs a container that can hold one — this key stores as a bare JWK (kind raw), which has none. Use passkey or device protection.";

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
 * How the vault files a private JWK (§28a): the kind it stores as, the id it
 * is filed under, the payload it holds, and the public line when there is one.
 *
 * Split out of `saveKeypairKind` so the *button* (`keyring.add`) and the *op*
 * (`agent.save`) share one encoder. Two encoders that can disagree about a
 * key's identity is the failure mode worth engineering against here: the same
 * key added by a click and saved by a recipe has to land under the same id, or
 * one key grows two rows in My Keys and neither is wrong.
 *
 * @param {JsonWebKey} jwk  The private half.
 * @param {{ comment?: string, publicKey?: CryptoKey, passphrase?: string }} [opts]
 *   `publicKey` short-circuits the spki id when the caller already holds the
 *   handle; without one it is re-imported from the JWK's public fields.
 *   `passphrase` encrypts the openssh-key-v1 payload (§28b) — it reaches only
 *   the `ssh` branch, and a `raw` key handed one is refused rather than
 *   stored bare under a label that claims protection.
 * @returns {Promise<{ kind: "ssh"|"raw", id: string, payload: string, publicLine: string }>}
 */
export async function vaultMaterialFromPrivateJwk(jwk, opts = {}) {
  const comment = String(opts.comment || "");
  const passphrase = String(opts.passphrase || "");
  const material = sshMaterialOrNull(jwk);
  if (material) {
    const blob = buildPublicBlob(material);
    return {
      kind: "ssh",
      id: await sshFingerprint(blob),
      payload: await encodeOpensshPrivateKey(material, { comment, passphrase }),
      publicLine: formatPublicLine(blob, comment),
    };
  }
  if (passphrase) throw new Error(NON_PGP_PASSPHRASE_MESSAGE);
  const publicKey = opts.publicKey || (await publicKeyFromPrivateJwk(jwk));
  const spki = new Uint8Array(await crypto.subtle.exportKey("spki", publicKey));
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", spki));
  return {
    kind: "raw",
    id: `spki:SHA256:${b64u(digest)}`,
    payload: JSON.stringify(jwk),
    publicLine: "",
  };
}

/**
 * The public half of a private JWK as a CryptoKey — needed only for the spki
 * id of a `raw` key, and only when the caller has no handle to hand over.
 *
 * X25519 is the one raw algorithm the vault round-trips (`materializeUnlockedKey`
 * imports nothing else), so refusing anything else here keeps both ends honest
 * rather than storing a key no unlock can read back.
 *
 * @param {JsonWebKey} jwk
 * @returns {Promise<CryptoKey>}
 */
async function publicKeyFromPrivateJwk(jwk) {
  if (jwk?.kty === "OKP" && jwk.crv === "X25519") {
    return crypto.subtle.importKey(
      "jwk",
      { kty: jwk.kty, crv: jwk.crv, x: jwk.x },
      "X25519",
      true,
      []
    );
  }
  throw new Error(
    `My Keys has no storage form for a ${jwk?.kty || "?"}/${jwk?.crv || "?"} key — SSH-mappable keys (ed25519, ec/p256, rsa) and x25519 can be stored.`
  );
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
async function saveKeypairKind(value, params, bindings = {}) {
  const protection = String(params.protection || "device").toLowerCase();
  if (!["device", "passphrase", "passkey"].includes(protection)) {
    throw new Error("agent.save protection= must be device|passphrase|passkey");
  }
  // §28b: the pgp path wraps the armor in OpenPGP S2K; the ssh path wraps the
  // openssh-key-v1 container in bcrypt_pbkdf + aes256-ctr. Both are "the
  // payload protects itself", which is what makes the vault row honest.
  // `raw` payloads have no such form and are refused in
  // `vaultMaterialFromPrivateJwk` — never silently downgraded.
  const panelPass = String(
    bindings?.inputs?.gpg?.passphrase || bindings?.inputs?.agent?.passphrase || ""
  );
  if (protection === "passphrase" && !panelPass) {
    throw new Error("agent.save protection=passphrase needs a key passphrase (Inputs panel)");
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

  if (!sshMaterialOrNull(jwk) && !handles.publicKey) {
    throw new Error("agent.save: raw keypairs need their public half to fingerprint (spki)");
  }
  // One encoder, shared with the `keyring.add` button — see the function's own
  // note on why a second one is the thing to avoid.
  const { kind, id, payload, publicLine } = await vaultMaterialFromPrivateJwk(jwk, {
    comment,
    publicKey: handles.publicKey,
    ...(protection === "passphrase" ? { passphrase: panelPass } : {}),
  });

  /** @type {Uint8Array|undefined} */
  let prfIkm;
  /** @type {import("../webauthn/mds.js").MdsLookupResult|undefined} */
  let mds;
  /** @type {import("../vault.js").PrfEnrolment|undefined} */
  let prfEnrolment;
  try {
    if (protection === "passkey") {
      const prf = await createPasskeyPrf(comment || "basilisk-vault");
      prfIkm = prf.prfIkm;
      mds = prf.mds;
      prfEnrolment = prf.enrolment;
    }
    await saveKey({
      fingerprint: id,
      armoredPrivate: payload,
      uid: nameParam ? `${nameParam} (${alg})` : comment ? `${comment} (${alg})` : `${alg} keypair`,
      email: emailParam,
      name: nameParam,
      expires: expiryIsoFromPreset(String(params.expiry || "none")),
      protection: /** @type {"device"|"passphrase"|"passkey"} */ (protection),
      prfIkm,
      prfEnrolment,
      mds,
      kind,
      publicLine,
      alg,
      // Same reasoning as the pgp branch: an explicit op replaces.
      onConflict: "replace",
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
    // `openPgpPassphrase` is the Inputs-panel passphrase, whatever the key's
    // kind — the field is named for the first op that read it, not for the
    // only one. A protection=passphrase ssh key needs it to open its
    // container; a device/passkey one ignores an empty string.
    // `format: "private"` explicitly: the vault only ever stores openssh-key-v1
    // blocks here, and `ssh.decode`'s default is `public` like its conjugate's.
    const v = await execSshDecode({ type: "text", data: result.armored }, { format: "private" }, {
      passphrase: result.openPgpPassphrase,
    });
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

/**
 * Shared preamble for the boundary ops (§26): resolve the key's metadata,
 * digest the payload, ask for approval, and only then unlock. The order
 * matters — approval precedes the unlock ceremony, so the banner is the
 * informed consent and the authenticator (which cannot display what is
 * being signed) is only the proof of presence (§27e).
 *
 * @param {"sign"|"decrypt"} use
 * @param {string} stepName
 * @param {Uint8Array} payload
 * @param {Record<string, *>} params
 * @param {import("./engine.js").RuntimeBindings} bindings
 */
async function approveAndUnlock(use, stepName, payload, params, bindings) {
  const fpr = normalizeVaultFingerprint(params.fpr);
  if (!fpr) throw new Error(`${stepName} requires fpr= (a My Keys id)`);
  const keys = await listKeys();
  const meta = keys.find((k) => k.fingerprint === fpr);
  if (!meta) throw new Error(`${stepName}: key not found in My Keys — check the id`);
  const kind = meta.kind || "pgp";

  const isText = (() => {
    try {
      const s = new TextDecoder("utf-8", { fatal: true }).decode(payload);
      return /^[\s\S]*$/.test(s) ? s : null;
    } catch (_) {
      return null;
    }
  })();

  await requireApproval({
    use,
    stepName,
    stepText: serializeApprovalStep(stepName, params),
    cellIndex: bindings?.cellIndex,
    keyId: fpr,
    keyLabel: meta.uid || meta.email || meta.name || fpr,
    keyKind: /** @type {"pgp"|"ssh"|"raw"} */ (kind),
    keyProtection: meta.protection || "device",
    payloadBytes: payload.length,
    payloadSha256: await digestForApproval(payload),
    // Ciphertext previews are noise (§27b); text payloads preview so a human
    // can notice "that is not my commit message".
    payloadPreview: use === "decrypt" || isText == null ? null : isText.slice(0, 256),
    ...(params.namespace ? { namespace: String(params.namespace) } : {}),
    ...(params.mode ? { mode: String(params.mode) } : {}),
    runTotal: bindings?.approvalRunTotal ?? null,
  });

  const result = await unlockVaultForUse(fpr, {
    openPgpPassphrase: String(
      bindings?.inputs?.gpg?.passphrase || bindings?.inputs?.agent?.passphrase || ""
    ),
    skipSession: getToolkitPrefs().sessionOff,
  });
  return { meta, kind, result };
}

/** The step as the recipe wrote it — shown verbatim in the banner (§27b). */
function serializeApprovalStep(stepName, params) {
  const parts = [stepName];
  if (params.fpr) parts.push(String(params.fpr));
  for (const k of ["format", "mode", "namespace"]) {
    if (params[k]) parts.push(`${k}=${params[k]}`);
  }
  return parts.join(" ");
}

/**
 * `agent.sign` (§26f) — the payload goes in, a signature comes out, and the
 * private key never enters the pipeline. This is the op `agent.unlock |
 * gpg.sign` should have been.
 *
 * @param {import("./engine.js").PipelineValue} value
 * @param {Record<string, *>} params
 * @param {import("./engine.js").RuntimeBindings} [bindings]
 */
export async function execAgentSign(value, params = {}, bindings = {}) {
  const payload = approvalPayloadBytes(value, "agent.sign");
  const { kind, result } = await approveAndUnlock(
    "sign",
    "agent.sign",
    payload,
    params,
    bindings
  );

  let format = String(params.format || "auto");
  if (format === "auto") format = kind === "pgp" ? "gpg" : "ssh";
  if (format === "gpg" && kind !== "pgp") {
    throw new Error(
      `agent.sign: key ${keyIdText(result.fingerprint)} is an ${kind.toUpperCase()} key — format=gpg needs a pgp-kind key.`
    );
  }
  if (format === "ssh" && kind === "pgp") {
    throw new Error(
      `agent.sign: key ${keyIdText(result.fingerprint)} is an OpenPGP key — format=ssh needs an ssh-kind key.`
    );
  }

  if (format === "gpg") {
    const privateKey = await readOpenPgpPrivate(result, bindings);
    const mode = String(params.mode || "cleartext") === "detached" ? "detached" : "cleartext";
    const data = mode === "cleartext" ? new TextDecoder().decode(payload) : payload;
    const { armored } = await signOpenPgp(data, [privateKey], mode);
    return {
      type: "text",
      data: armored,
      meta: {
        sensitive: false,
        openPgpSigned: true,
        detached: mode === "detached",
        agentSigned: true,
        fingerprint: result.fingerprint,
      },
    };
  }

  // ssh / raw: sshsig over the payload, key materialized in this frame only.
  const keyPair = await execSshDecode({ type: "text", data: result.armored }, { format: "private" }, {
    passphrase: result.openPgpPassphrase,
  });
  const { execSshSign } = await import("./ssh-ops.js");
  const signed = await execSshSign(
    { type: "bytes", data: payload },
    {
      key: "@__agent_key",
      namespace: String(params.namespace || "file"),
      hash: String(params.hash || "sha512"),
    },
    { resolveSlot: () => keyPair }
  );
  return {
    ...signed,
    meta: { ...(signed.meta || {}), agentSigned: true, fingerprint: result.fingerprint },
  };
}

/**
 * `agent.decrypt` (§26f) — ciphertext in, plaintext out, key stays in the
 * vault. PGP-kind keys only: an SSH signing key cannot decrypt, and saying
 * so plainly beats a confusing crypto error three layers down.
 *
 * @param {import("./engine.js").PipelineValue} value
 * @param {Record<string, *>} params
 * @param {import("./engine.js").RuntimeBindings} [bindings]
 */
export async function execAgentDecrypt(value, params = {}, bindings = {}) {
  const payload = approvalPayloadBytes(value, "agent.decrypt");
  const { kind, result } = await approveAndUnlock(
    "decrypt",
    "agent.decrypt",
    payload,
    params,
    bindings
  );
  if (kind !== "pgp") {
    throw new Error(
      `agent.decrypt: key ${keyIdText(result.fingerprint)} is an ${kind === "ssh" ? "SSH signing key — it cannot decrypt" : "raw key — it has no OpenPGP decryption path"}. Only pgp-kind keys decrypt.`
    );
  }
  const privateKey = await readOpenPgpPrivate(result, bindings);
  const message = await readMessage({ armoredMessage: new TextDecoder().decode(payload) });
  const out = await openpgpDecrypt({
    message,
    decryptionKeys: privateKey,
    config: { allowInsecureDecryptionWithSigningKeys: true },
  });
  const plaintext =
    typeof out.data === "string" ? out.data : new TextDecoder().decode(out.data);
  return {
    type: "text",
    data: plaintext,
    // The plaintext is the answer the user asked for, not key material —
    // masking it would be theater (§26c: mark the leak, not the safe path).
    meta: { sensitive: false, agentDecrypted: true, fingerprint: result.fingerprint },
  };
}

/**
 * Read the unlocked armor into a decrypted OpenPGP private key. Lives in
 * this call frame only — it is never bound to a slot, which is the whole
 * boundary (§26a).
 * @param {import("../vault-unlock.js").VaultUnlockResult} result
 * @param {import("./engine.js").RuntimeBindings} bindings
 */
async function readOpenPgpPrivate(result, bindings) {
  let privateKey = await readPrivateKey({ armoredKey: result.armored });
  if (!privateKey.isDecrypted()) {
    privateKey = await decryptKey({
      privateKey,
      passphrase:
        result.openPgpPassphrase ||
        bindings?.inputs?.gpg?.passphrase ||
        bindings?.inputs?.agent?.passphrase ||
        "",
    });
  }
  return privateKey;
}

/** Payload bytes for a boundary op — the exact bytes the digest covers. */
function approvalPayloadBytes(value, stepName) {
  if (value?.type === "bytes" && value.data instanceof Uint8Array) return value.data;
  if (value?.type === "text") return new TextEncoder().encode(String(value.data));
  throw new Error(`${stepName}: needs text or bytes on the pipeline`);
}
