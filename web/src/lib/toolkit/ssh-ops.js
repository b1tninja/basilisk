/**
 * Toolkit `ssh.*` ops (§29, design_handoff_agent_ssh) — the registry surface
 * over lib/ssh/'s codecs.
 *
 * This file owns exactly one job the codecs refuse: adapting between the
 * pipeline's live-CryptoKey values (what `genkey` emits, what downstream
 * WebCrypto ops consume) and the codecs' typed wire material. The bridge is
 * JWK, because it is the one serialization both sides already speak.
 *
 * Everything here is pure JS + SubtleCrypto — no DOM, no vault — so all five
 * ops run headlessly in the CLI.
 */

import { jwkFieldToBytes } from "./encode.js";
import { pipelineKeyHandles } from "./webcrypto-ops.js";
import {
  ECDSA_CURVES,
  NIST_CURVE_WEB,
  buildPublicBlob,
  concatBytes,
  formatPublicLine,
  parsePublicLine,
} from "../ssh/wire.js";
import {
  encodeOpensshPrivateKey,
  parseOpensshPrivateKey,
} from "../ssh/openssh-key-v1.js";
import { sshFingerprint } from "../ssh/fingerprint.js";
import { sshsigSign, sshsigVerify } from "../ssh/sshsig.js";

/** SSH key-type name for a JWK, or the reason there isn't one. */
function sshTypeForJwk(jwk) {
  if (jwk.kty === "OKP" && jwk.crv === "Ed25519") return "ssh-ed25519";
  if (jwk.kty === "EC") {
    const t = { "P-256": "ecdsa-sha2-nistp256", "P-384": "ecdsa-sha2-nistp384", "P-521": "ecdsa-sha2-nistp521" }[jwk.crv];
    if (t) return t;
    throw new Error(`SSH has no key type for EC curve ${jwk.crv}`);
  }
  if (jwk.kty === "RSA") return "ssh-rsa";
  if (jwk.kty === "OKP" && jwk.crv === "X25519") {
    // x25519 does ECDH; SSH user keys sign. The kex use of curve25519 is not
    // a key file format, so there is nothing honest to emit here.
    throw new Error("SSH has no x25519 user-key type — generate ed25519 for SSH");
  }
  throw new Error(`SSH has no key type for ${jwk.kty}${jwk.crv ? "/" + jwk.crv : ""} keys`);
}

/** Typed wire material (lib/ssh shape) from a JWK; private fields when present. */
function sshMaterialFromJwk(jwk) {
  const type = sshTypeForJwk(jwk);
  if (type === "ssh-ed25519") {
    const pub = jwkFieldToBytes(jwk.x);
    return jwk.d ? { type, pub, priv: jwkFieldToBytes(jwk.d) } : { type, pub };
  }
  if (type in ECDSA_CURVES) {
    const x = jwkFieldToBytes(jwk.x);
    const y = jwkFieldToBytes(jwk.y);
    const point = concatBytes([new Uint8Array([4]), x, y]);
    const curveName = ECDSA_CURVES[/** @type {keyof typeof ECDSA_CURVES} */ (type)];
    return jwk.d
      ? { type, curveName, point, scalar: jwkFieldToBytes(jwk.d) }
      : { type, curveName, point };
  }
  // ssh-rsa. JWK's qi is the same CRT coefficient openssh calls iqmp.
  const base = { type, n: jwkFieldToBytes(jwk.n), e: jwkFieldToBytes(jwk.e) };
  if (jwk.d) {
    return {
      ...base,
      d: jwkFieldToBytes(jwk.d),
      p: jwkFieldToBytes(jwk.p),
      q: jwkFieldToBytes(jwk.q),
      iqmp: jwkFieldToBytes(jwk.qi),
    };
  }
  return base;
}

const b64u = (bytes) => {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};

/** JWKs (private and public) from typed wire material. */
function jwksFromSshMaterial(m) {
  if (m.type === "ssh-ed25519") {
    const pub = { kty: "OKP", crv: "Ed25519", x: b64u(m.pub) };
    return { pub, priv: m.priv ? { ...pub, d: b64u(m.priv) } : null };
  }
  if (m.type in ECDSA_CURVES) {
    const coordLen = (m.point.length - 1) / 2;
    const crv = NIST_CURVE_WEB[m.curveName];
    const pub = {
      kty: "EC",
      crv,
      x: b64u(m.point.subarray(1, 1 + coordLen)),
      y: b64u(m.point.subarray(1 + coordLen)),
    };
    return { pub, priv: m.scalar ? { ...pub, d: b64u(m.scalar) } : null };
  }
  if (m.type === "ssh-rsa") {
    const pub = { kty: "RSA", n: b64u(m.n), e: b64u(m.e) };
    if (!m.d) return { pub, priv: null };
    const toBig = (b) => {
      let v = 0n;
      for (const x of b) v = (v << 8n) | BigInt(x);
      return v;
    };
    const fromBig = (v) => {
      let hex = v.toString(16);
      if (hex.length % 2) hex = "0" + hex;
      const out = new Uint8Array(hex.length / 2);
      for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
      return out;
    };
    const d = toBig(m.d);
    const p = toBig(m.p);
    const q = toBig(m.q);
    return {
      pub,
      priv: {
        ...pub,
        d: b64u(m.d),
        p: b64u(m.p),
        q: b64u(m.q),
        dp: b64u(fromBig(d % (p - 1n))),
        dq: b64u(fromBig(d % (q - 1n))),
        qi: b64u(m.iqmp),
      },
    };
  }
  throw new Error(`SSH: unsupported key type "${m.type}"`);
}

/**
 * WebCrypto import parameters per SSH type, matching what genkey produces.
 *
 * The `hash` only reaches the RSA case, and it is not cosmetic: WebCrypto binds
 * the digest into an RSA key handle at import, so whatever is chosen here is
 * what a later `sign`/`verify` on this key is stuck with. The SSH wire type
 * `ssh-rsa` names no digest — the signature algorithms built on it do
 * (rsa-sha2-256, rsa-sha2-512) — so there is a choice to make, and `ssh.decode
 * hash=` is where the user makes it. sshsig does not depend on it either way:
 * `sshsigSign` re-imports the raw material under SHA-512 itself, deliberately
 * matching `ssh-keygen -Y sign`.
 *
 * @param {string} type
 * @param {string} [hash]  recipe token — `sha512` (default) or `sha256`
 */
function importParamsFor(type, hash = "sha512") {
  if (type === "ssh-ed25519") return { alg: "ed25519", params: "Ed25519" };
  if (type in ECDSA_CURVES) {
    const curve = NIST_CURVE_WEB[ECDSA_CURVES[/** @type {keyof typeof ECDSA_CURVES} */ (type)]];
    return {
      alg: `ec/${curve.toLowerCase().replace("-", "")}`,
      params: { name: "ECDSA", namedCurve: curve },
    };
  }
  const digest = /256/.test(String(hash)) ? "SHA-256" : "SHA-512";
  return { alg: "rsa", params: { name: "RSASSA-PKCS1-v1_5", hash: digest } };
}

/**
 * The passphrase for a protected openssh-key-v1 block, from the Inputs panel.
 *
 * Same channel the gpg ops read (`execAgentSave`, `readOpenPgpPrivate`) — a
 * second one would mean a user who typed their passphrase into the panel
 * still got refused by whichever op happened to look somewhere else.
 *
 * @param {import("./engine.js").RuntimeBindings} [bindings]
 */
function panelPassphrase(bindings) {
  return String(bindings?.inputs?.gpg?.passphrase || bindings?.inputs?.agent?.passphrase || "");
}

/** Typed wire material for one pipeline value (keypair/key handles, or SSH text). */
async function materialFromValue(value, need, bindings) {
  if (!value) throw new Error("SSH: empty value where a key was expected");
  if (value.type === "keypair" || value.type === "key") {
    const handles = pipelineKeyHandles(value);
    const key =
      need === "private"
        ? handles.privateKey
        : handles.publicKey || handles.privateKey;
    if (!key) {
      throw new Error(
        need === "private"
          ? "SSH: this slot has no private key (a public key cannot sign)"
          : "SSH: this slot has no usable key"
      );
    }
    if (!key.extractable) {
      throw new Error("SSH: key is not extractable — regenerate it with genkey to encode it");
    }
    const jwk = await crypto.subtle.exportKey("jwk", key);
    const m = sshMaterialFromJwk(jwk);
    if (need === "private" && !("priv" in m || "scalar" in m || "d" in m)) {
      throw new Error("SSH: this slot has no private key (a public key cannot sign)");
    }
    return m;
  }
  if (value.type === "text") {
    const text = String(value.data || "");
    if (text.includes("BEGIN OPENSSH PRIVATE KEY")) {
      return parseOpensshPrivateKey(text, { passphrase: panelPassphrase(bindings) });
    }
    return parsePublicLine(text);
  }
  throw new Error(`SSH: cannot read a key from a ${value.type} value`);
}

/** @param {import("./engine.js").PipelineValue} value */
function payloadBytes(value) {
  if (value?.type === "bytes" && value.data instanceof Uint8Array) return value.data;
  if (value?.type === "text") return new TextEncoder().encode(String(value.data));
  throw new Error("SSH: payload must be text or bytes (pipe through `utf8` first)");
}

/** Resolve a slot ref to its raw pipeline value. */
function slotValue(bindings, ref, what) {
  const r = String(ref || "").trim();
  if (!r) throw new Error(`SSH: ${what} is required`);
  const resolve = bindings?.resolveSlot;
  if (typeof resolve !== "function") throw new Error(`Slot ${r}: runtime slot resolver missing`);
  return resolve(r);
}

/** `ssh.encode` — keypair/key → public line, or (explicit) unencrypted private PEM. */
export async function execSshEncode(value, params = {}, bindings = {}) {
  const format = String(params.format || "public");
  const comment = String(params.comment || "");
  const m = await materialFromValue(value, format === "private" ? "private" : "public", bindings);
  if (format === "private") {
    // Deliberately unencrypted: `ssh.encode` has no `passphrase=` param, and
    // silently encrypting because the Inputs panel happens to hold a gpg
    // passphrase would be a different artifact than the recipe asked for.
    // `agent.save protection=passphrase` is the op that writes a protected
    // container; the codec below takes a passphrase whenever one is wired.
    const pem = await encodeOpensshPrivateKey(m, { comment });
    return {
      type: "text",
      data: pem,
      // §29f: an unencrypted private block is masked like every private
      // artifact; the tile-level warning rides the compile warning.
      meta: { kind: "ssh-private", sensitive: true },
    };
  }
  const blob = m.publicBlob || buildPublicBlob(m);
  return {
    type: "text",
    data: formatPublicLine(blob, comment),
    meta: { kind: "ssh-public" },
  };
}

/**
 * `ssh.decode` — public line or openssh-key-v1 → live key/keypair value.
 *
 * A passphrase-protected block opens when the Inputs panel holds its
 * passphrase (or `opts.passphrase` is passed directly, which is how the
 * vault hands one over); without it the codec names what is missing.
 *
 * @param {import("./engine.js").PipelineValue} value
 * @param {Record<string, *>} [params_]
 * @param {import("./engine.js").RuntimeBindings & { passphrase?: string }} [bindings]
 */
export async function execSshDecode(value, params_ = {}, bindings = {}) {
  if (value?.type !== "text") {
    throw new Error("ssh.decode expects text (a public line or an OPENSSH PRIVATE KEY block)");
  }
  const text = String(value.data || "");
  const isPrivate = text.includes("BEGIN OPENSSH PRIVATE KEY");
  const passphrase = String(bindings?.passphrase || "") || panelPassphrase(bindings);
  const m = isPrivate ? await parseOpensshPrivateKey(text, { passphrase }) : parsePublicLine(text);
  const { pub, priv } = jwksFromSshMaterial(m);
  const { alg, params } = importParamsFor(m.type, String(params_.hash || "sha512"));
  // Extractable on purpose: these keys exist to be re-encoded, exported and
  // moved — the vault, not extractability, is the at-rest protection story.
  const publicKey = await crypto.subtle.importKey("jwk", pub, params, true, ["verify"]);
  if (!priv) {
    return {
      type: "key",
      data: publicKey,
      meta: { alg, which: "public", comment: m.comment || "" },
    };
  }
  const privateKey = await crypto.subtle.importKey("jwk", priv, params, true, ["sign"]);
  return {
    type: "keypair",
    data: { privateKey, publicKey },
    meta: { alg, sensitive: true, comment: m.comment || "" },
  };
}

/** `ssh.fingerprint` — SHA256:… of the public key, matching `ssh-keygen -lf`. */
export async function execSshFingerprint(value, params = {}, bindings = {}) {
  const m = await materialFromValue(value, "public", bindings);
  const blob = m.publicBlob || buildPublicBlob(m);
  return { type: "text", data: await sshFingerprint(blob) };
}

/** `ssh.sign` — sshsig over the payload; key from a slot. */
export async function execSshSign(value, params = {}, bindings = {}) {
  const payload = payloadBytes(value);
  const keyVal = slotValue(bindings, params.key, "key= (private key slot)");
  const m = await materialFromValue(keyVal, "private", bindings);
  const armor = await sshsigSign(payload, m, {
    namespace: String(params.namespace || "file"),
    hash: /** @type {"sha512"|"sha256"} */ (String(params.hash || "sha512")),
  });
  return { type: "text", data: armor, meta: { kind: "sshsig" } };
}

/** `ssh.verify` — check an sshsig over the payload; fail-loud, `-q` soft. */
export async function execSshVerify(value, params = {}, bindings = {}) {
  const payload = payloadBytes(value);
  const sigVal = slotValue(bindings, params.signature, "signature= (sshsig slot)");
  if (sigVal?.type !== "text") throw new Error("ssh.verify: signature slot must hold sshsig text");
  const keyVal = slotValue(bindings, params.key, "key= (signer's public key)");
  const m = await materialFromValue(keyVal, "public", bindings);
  const publicBlob = m.publicBlob || buildPublicBlob(m);
  const namespace = String(params.namespace || "file");
  try {
    await sshsigVerify(payload, String(sigVal.data), { namespace, publicBlob });
  } catch (err) {
    if (params.soft) return { type: "bool", data: false };
    throw err;
  }
  return { type: "bool", data: true };
}

/**
 * SSH identity for a JWK, or null when SSH has no key type for it (§35c).
 *
 * The key tiles need a fingerprint and a public line without running an op.
 * This is the same codec path `ssh.encode` and `ssh.fingerprint` take — no new
 * crypto, and the bytes match what a recipe would emit — but it returns null
 * instead of throwing for x25519/AES/HMAC, because "SSH has no key type for
 * this" is an ordinary answer for a tile to render (the row is simply absent)
 * rather than an error to handle.
 *
 * @param {JsonWebKey} jwk
 * @param {string} [comment]
 * @returns {Promise<{ publicLine: string, fingerprint: string, type: string } | null>}
 */
export async function sshIdentityFromJwk(jwk, comment = "") {
  let material;
  try {
    material = sshMaterialFromJwk(jwk);
  } catch (_) {
    return null;
  }
  const blob = buildPublicBlob(material);
  return {
    publicLine: formatPublicLine(blob, comment),
    fingerprint: await sshFingerprint(blob),
    type: material.type,
  };
}
