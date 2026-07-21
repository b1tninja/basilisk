/**
 * Execute a compiled toolkit recipe AST.
 * Returns encoded artifacts only (never CryptoKey handles).
 */

import {
  decrypt as openpgpDecrypt,
  decryptKey,
  readMessage,
  readPrivateKey,
} from "openpgp";
import { generateWordPassphrase } from "../passphrase-gen.js";
import { qrSvg } from "../qr.js";
import { PROFILE_AUTO, encryptArtifacts } from "../pgp/encrypt.js";
import { zeroKeyMaterial } from "../pgp/memory.js";
import {
  combineShares,
  splitShares,
  validateShareMnemonic,
} from "../slip39/slip39.js";
import {
  base64ToBytes,
  bytesToBase64,
  bytesToBase64Url,
  bytesToHex,
  bytesToText,
  fromPem,
  hexToBytes,
  pemLabelFor,
  textToBytes,
  toPem,
  zeroBuffer,
} from "./encode.js";
import { inspectValue } from "./inspect.js";
import { getStep } from "./registry.js";

/**
 * @typedef {object} ToolkitArtifact
 * @property {string} label
 * @property {string} filename
 * @property {string} content  text (PEM, mnemonic, armored, SVG, …)
 * @property {boolean} [sensitive]
 * @property {number} [shareIndex]
 * @property {string} [mime]
 * @property {string} [encoding]
 * @property {string} [recipientFingerprint]
 */

/**
 * @typedef {object} RuntimeBindings
 * @property {import("openpgp").Key[]} [recipients]  ordered; for foreach encrypt, one per share
 * @property {string[]} [recipientFingerprints]
 * @property {{
 *   shares?: { mnemonics: string[], envelopeB64?: string, passphrase?: string },
 *   text?: { value: string },
 *   gpg?: {
 *     armoredMessages: string[],
 *     privateKeyArmored: string,
 *     passphrase?: string,
 *     envelopeB64?: string,
 *   },
 * }} [inputs]
 */

/**
 * @typedef {object} PipelineValue
 * @property {string} type
 * @property {*} data
 * @property {Record<string, *>} [meta]
 */

/**
 * Run a recipe AST.
 * @param {import("./recipe.js").RecipeAst} ast
 * @param {RuntimeBindings} [bindings]
 * @returns {Promise<ToolkitArtifact[]>}
 */
export async function runRecipe(ast, bindings = {}) {
  const steps = ast?.steps || [];
  if (!steps.length) throw new Error("Empty recipe");

  /** @type {ToolkitArtifact[]} */
  const artifacts = [];
  /** @type {PipelineValue|null} */
  let value = null;
  /** Track whether envelope was already emitted for this run. */
  let envelopeEmitted = false;
  /** True when the last top-level step was `out` (already materialized; skip trailing emit). */
  let lastStepWasOut = false;

  const plan = expandPlan(steps);

  for (const node of plan) {
    if (node.kind === "foreach") {
      lastStepWasOut = false;
      if (!value || value.type !== "shares") {
        throw new Error("foreach requires shares");
      }
      const items = /** @type {string[]} */ (value.data.mnemonics);
      const envelope = value.data.envelope;
      const body = node.body;
      for (let i = 0; i < items.length; i++) {
        /** @type {PipelineValue} */
        let itemVal = {
          type: "text",
          data: items[i],
          meta: {
            shareIndex: i + 1,
            shareCount: items.length,
            envelope,
            sensitive: true,
          },
        };
        for (const step of body) {
          itemVal = await execStep(step, itemVal, bindings, artifacts, i);
        }
        if (itemVal && itemVal.type === "text") {
          const last = body[body.length - 1];
          if (last && getStep(last.name)?.kind !== "sink") {
            artifacts.push({
              label: `Share ${i + 1}`,
              filename: `share-${i + 1}.txt`,
              content: String(itemVal.data),
              sensitive: true,
              shareIndex: i + 1,
            });
          }
        }
      }
      // Envelope must be emitted once so share sets are recoverable.
      if (envelope && !envelopeEmitted) {
        emitEnvelope(artifacts, envelope);
        envelopeEmitted = true;
      }
      value = { type: "bundle", data: artifacts };
      continue;
    }

    value = await execStep(node.step, value, bindings, artifacts, 0);
    lastStepWasOut = node.step.name === "out";
    if (
      value?.meta?.envelope &&
      !envelopeEmitted &&
      getStep(node.step.name)?.kind === "sink"
    ) {
      emitEnvelope(artifacts, value.meta.envelope);
      envelopeEmitted = true;
    }
  }

  if (value && value.type !== "bundle" && value.type !== "artifact") {
    // Bare slip39 (no foreach/sink) leaves a shares value here — emit the
    // envelope before converting mnemonics, or PEM/large payloads become unrecoverable.
    const bareEnvelope = value.data?.envelope || value.meta?.envelope || null;
    if (value.type === "shares" && bareEnvelope && !envelopeEmitted) {
      emitEnvelope(artifacts, bareEnvelope);
      envelopeEmitted = true;
    }
    // Terminal `out` already pushed tiles; later transforms clear lastStepWasOut.
    if (!lastStepWasOut) {
      artifacts.push(...valueToArtifacts(value));
    }
  }

  return artifacts;
}

/**
 * @param {ToolkitArtifact[]} artifacts
 * @param {Uint8Array} envelope
 */
function emitEnvelope(artifacts, envelope) {
  artifacts.push({
    label: "Envelope ciphertext — required for recovery, not secret",
    filename: "envelope.bin.b64",
    content: bytesToBase64(envelope),
    sensitive: false,
    mime: "application/octet-stream",
  });
}

/**
 * @param {import("./recipe.js").RecipeStep[]} steps
 */
function expandPlan(steps) {
  /** @type {Array<{ kind: "step", step: import("./recipe.js").RecipeStep } | { kind: "foreach", body: import("./recipe.js").RecipeStep[] }>} */
  const plan = [];
  for (let i = 0; i < steps.length; i++) {
    const s = steps[i];
    if (s.name === "foreach") {
      const body = [];
      i++;
      while (i < steps.length && steps[i].name !== "merge") {
        if (steps[i].name === "foreach") {
          throw new Error("Nested foreach is not supported");
        }
        body.push(steps[i]);
        i++;
      }
      plan.push({ kind: "foreach", body });
      continue;
    }
    if (s.name === "merge") continue;
    plan.push({ kind: "step", step: s });
  }
  return plan;
}

/**
 * @param {import("./recipe.js").RecipeStep} step
 * @param {PipelineValue|null} value
 * @param {RuntimeBindings} bindings
 * @param {ToolkitArtifact[]} artifacts
 * @param {number} _shareIndex0
 * @returns {Promise<PipelineValue>}
 */
async function execStep(step, value, bindings, artifacts, _shareIndex0) {
  void _shareIndex0;
  switch (step.name) {
    case "genkey":
      return generateKeyValue(String(step.params.alg || "ec/p256"), String(step.params.usage || "auto"));
    case "random": {
      const n = Number(step.params.length) || 32;
      const buf = crypto.getRandomValues(new Uint8Array(n));
      return { type: "bytes", data: buf, meta: { sensitive: true } };
    }
    case "passphrase": {
      const words = Number(step.params.words) || 6;
      const { passphrase } = generateWordPassphrase(words);
      return { type: "text", data: passphrase, meta: { sensitive: true } };
    }
    case "input": {
      const text = String(bindings.inputs?.text?.value ?? "");
      if (!text.trim()) {
        throw new Error("No input text provided — paste or load a file before running.");
      }
      return { type: "text", data: text, meta: { sensitive: true } };
    }
    case "recombine": {
      const kind = String(step.params.kind || "shares");
      const inp = bindings.inputs?.shares;
      if (kind === "text") {
        const text = (inp?.mnemonics || []).join("\n");
        if (!text.trim()) throw new Error("No input text provided");
        return { type: "text", data: text, meta: { sensitive: true } };
      }
      const mnemonics = (inp?.mnemonics || []).map((m) => String(m).trim()).filter(Boolean);
      if (!mnemonics.length) {
        throw new Error("No SLIP-39 share mnemonics provided — paste shares before running.");
      }
      /** @type {Uint8Array|null} */
      let envelope = null;
      if (inp?.envelopeB64) {
        envelope = base64ToBytes(String(inp.envelopeB64).replace(/\s+/g, ""));
      }
      return {
        type: "shares",
        data: {
          mnemonics,
          envelope,
          threshold: 0,
          shares: mnemonics.length,
          enveloped: !!envelope,
        },
        meta: {
          sensitive: true,
          envelope,
          passphrase: inp?.passphrase || "",
        },
      };
    }
    case "decrypt":
      return decryptGpgSource(bindings, artifacts);
    case "export":
      return exportKey(value, String(step.params.format || "pkcs8"), String(step.params.which || "private"));
    case "import":
      return importKey(
        value,
        String(step.params.format || "pkcs8"),
        String(step.params.alg || "ec/p256"),
        String(step.params.usage || "auto")
      );
    case "pem": {
      if (step.params.decode) {
        if (!value || value.type !== "text") throw new Error("pem -d expects PEM text");
        const der = fromPem(String(value.data));
        return {
          type: "bytes",
          data: der,
          meta: { ...value.meta, format: "pkcs8", sensitive: true },
        };
      }
      if (!value || value.type !== "bytes") throw new Error("pem expects bytes");
      let label = String(step.params.label || "auto");
      if (label === "auto") {
        label = pemLabelFor(value.meta?.format || "pkcs8", value.meta?.which || "private");
      }
      const text = toPem(value.data, label);
      return { type: "text", data: text, meta: { ...value.meta, sensitive: true } };
    }
    case "der":
      if (!value || value.type !== "bytes") throw new Error("der expects bytes");
      return value;
    case "base64":
      if (step.params.decode) {
        if (!value || value.type !== "text") throw new Error("base64 -d expects text");
        return {
          type: "bytes",
          data: base64ToBytes(String(value.data).replace(/\s+/g, "")),
          meta: { ...value.meta, sensitive: !!value.meta?.sensitive },
        };
      }
      if (!value || value.type !== "bytes") throw new Error("base64 expects bytes");
      return {
        type: "text",
        data: bytesToBase64(value.data),
        meta: { ...value.meta, sensitive: !!value.meta?.sensitive },
      };
    case "base64url":
      if (!value || value.type !== "bytes") throw new Error("base64url expects bytes");
      return {
        type: "text",
        data: bytesToBase64Url(value.data),
        meta: { ...value.meta, sensitive: !!value.meta?.sensitive },
      };
    case "hex":
      if (step.params.decode) {
        if (!value || value.type !== "text") throw new Error("hex -d expects text");
        return {
          type: "bytes",
          data: hexToBytes(String(value.data)),
          meta: { ...value.meta, sensitive: !!value.meta?.sensitive },
        };
      }
      if (!value || value.type !== "bytes") throw new Error("hex expects bytes");
      return {
        type: "text",
        data: bytesToHex(value.data),
        meta: { ...value.meta, sensitive: !!value.meta?.sensitive },
      };
    case "utf8": {
      if (!value) throw new Error("utf8 expects a value");
      if (value.type === "bytes") {
        return {
          type: "text",
          data: bytesToText(value.data),
          meta: { ...value.meta, sensitive: !!value.meta?.sensitive },
        };
      }
      if (value.type === "text") {
        return {
          type: "bytes",
          data: textToBytes(value.data),
          meta: { ...value.meta, sensitive: !!value.meta?.sensitive },
        };
      }
      throw new Error("utf8 expects bytes or text");
    }
    case "slip39": {
      let bytes;
      if (value?.type === "bytes") bytes = value.data;
      else if (value?.type === "text") bytes = textToBytes(value.data);
      else throw new Error("slip39 expects bytes or text");
      const result = await splitShares(bytes, {
        threshold: Number(step.params.threshold) || 2,
        shares: Number(step.params.shares) || 3,
        passphrase: String(step.params.passphrase || ""),
      });
      return {
        type: "shares",
        data: result,
        meta: { sensitive: true, envelope: result.envelope },
      };
    }
    case "combine": {
      if (!value || value.type !== "shares") throw new Error("combine expects shares");
      const mnemonics = value.data.mnemonics || [];
      const passphrase =
        String(step.params.passphrase || "") ||
        String(value.meta?.passphrase || "") ||
        "";
      const envelope = value.data.envelope || value.meta?.envelope || null;
      let secret;
      try {
        secret = await combineShares(mnemonics, {
          passphrase: passphrase || undefined,
          envelope,
        });
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        if (/Need at least \d+ shares/i.test(msg)) {
          throw new Error(
            `${msg}. If some shares were decrypted outside the browser (Kleopatra/gpg/YubiKey), paste those mnemonics in the share rows and keep remaining OpenPGP ciphertext in the GPG panel.`
          );
        }
        throw err;
      }
      return {
        type: "bytes",
        data: secret,
        meta: { sensitive: true },
      };
    }
    case "encrypt":
    case "gpg": {
      // "gpg" alias resolves to encrypt at parse time; keep case for safety.
      if (!value || (value.type !== "text" && value.type !== "bytes")) {
        throw new Error("encrypt expects text");
      }
      const text =
        value.type === "text" ? String(value.data) : bytesToBase64(value.data);
      const recipients = bindings.recipients || [];
      if (!recipients.length) {
        throw new Error("GPG recipients not bound — choose recipients before running.");
      }
      let key = recipients[0];
      let fpr = bindings.recipientFingerprints?.[0] || "";
      if (value.meta?.shareIndex) {
        const idx = value.meta.shareIndex - 1;
        key = recipients[Math.min(idx, recipients.length - 1)];
        fpr = bindings.recipientFingerprints?.[idx] || fpr;
      }
      const arts = await encryptArtifacts({
        recipients: [key],
        passwords: [],
        payloads: [{ kind: "text", text }],
        profile: PROFILE_AUTO,
      });
      for (const a of arts) {
        artifacts.push({
          label: value.meta?.shareIndex
            ? `Share ${value.meta.shareIndex} (GPG)`
            : a.label || "GPG ciphertext",
          filename: value.meta?.shareIndex
            ? `share-${value.meta.shareIndex}.asc`
            : a.filename || "encrypted.asc",
          content: a.armored,
          sensitive: false,
          shareIndex: value.meta?.shareIndex,
          recipientFingerprint: fpr,
          mime: "application/pgp-encrypted",
        });
      }
      return { type: "artifact", data: null, meta: value.meta };
    }
    case "qr": {
      if (!value || value.type !== "text") throw new Error("qr expects text");
      const svg = qrSvg(String(value.data), { ecl: "L", moduleSize: 3, margin: 4 });
      artifacts.push({
        label: value.meta?.shareIndex ? `Share ${value.meta.shareIndex} QR` : "QR code",
        filename: value.meta?.shareIndex
          ? `share-${value.meta.shareIndex}.svg`
          : "artifact.svg",
        content: svg,
        sensitive: !!value.meta?.sensitive,
        shareIndex: value.meta?.shareIndex,
        mime: "image/svg+xml",
      });
      return { type: "artifact", data: null, meta: value.meta };
    }
    case "out": {
      if (!value) throw new Error("out expects a value");
      const emitted = await materializeOutArtifacts(value, step.params || {});
      for (const a of emitted) {
        if (value.meta?.shareIndex && !a.shareIndex) {
          a.shareIndex = value.meta.shareIndex;
        }
        artifacts.push(a);
      }
      // Pass through so the recipe can continue (e.g. out | encrypt gpg).
      return value;
    }
    case "inspect": {
      if (!value) throw new Error("inspect expects a value");
      const format = String(step.params.format || "auto");
      const dump = await inspectValue(value, format);
      return {
        type: "text",
        data: dump,
        meta: {
          ...value.meta,
          sensitive:
            !!value.meta?.sensitive ||
            value.type === "keypair" ||
            value.type === "shares",
          inspect: true,
        },
      };
    }
    case "tee": {
      if (!value) throw new Error("tee expects a value");
      const name = String(step.params.name || "tee")
        .replace(/[^\w.-]+/g, "_")
        .slice(0, 64) || "tee";
      const format = String(step.params.format || "auto");
      const dump = await inspectValue(value, format);
      artifacts.push({
        label: `tee:${name}`,
        filename: `${name}.inspect.txt`,
        content: dump,
        sensitive:
          !!value.meta?.sensitive ||
          value.type === "keypair" ||
          value.type === "shares",
      });
      return value;
    }
    default:
      throw new Error(`Unsupported step: ${step.name}`);
  }
}

/**
 * True when text looks like an OpenPGP armored message (not a bare mnemonic).
 * @param {string} text
 */
function looksLikePgpMessage(text) {
  return /-----BEGIN PGP MESSAGE-----/i.test(String(text || ""));
}

/**
 * Normalize and accept a SLIP-39 mnemonic if the checksum validates.
 * @param {string} text
 * @returns {string|null}
 */
function asShareMnemonic(text) {
  const normalized = String(text || "")
    .replace(/\s+/g, " ")
    .trim();
  if (!normalized) return null;
  return validateShareMnemonic(normalized).ok ? normalized : null;
}

/**
 * Decrypt OpenPGP-wrapped shares and/or accept already-plaintext mnemonics.
 * Merges share-panel mnemonics (e.g. decrypted externally via Kleopatra/gpg)
 * with in-browser decrypt results — browsers cannot use OpenPGP smartcards /
 * YubiKey GPG applets, so hybrid recovery is the supported path.
 * @param {RuntimeBindings} bindings
 * @param {ToolkitArtifact[]} _artifacts
 * @returns {Promise<PipelineValue>}
 */
async function decryptGpgSource(bindings, _artifacts) {
  void _artifacts;
  const gpg = bindings.inputs?.gpg;
  const external = (bindings.inputs?.shares?.mnemonics || [])
    .map((m) => asShareMnemonic(String(m)))
    .filter(Boolean);
  const chunks = gpg?.armoredMessages || [];

  /** @type {string[]} */
  const ciphertexts = [];
  /** @type {string[]} */
  const mnemonics = [...external];
  /** @type {string[]} */
  const problems = [];

  for (const raw of chunks) {
    const text = String(raw || "").trim();
    if (!text) continue;
    if (looksLikePgpMessage(text)) {
      ciphertexts.push(text);
      continue;
    }
    const mnemonic = asShareMnemonic(text);
    if (mnemonic) {
      mnemonics.push(mnemonic);
      continue;
    }
    problems.push(
      "A pasted block was neither an OpenPGP message nor a valid SLIP-39 mnemonic"
    );
  }

  if (!ciphertexts.length && !mnemonics.length) {
    throw new Error(
      "Paste OpenPGP-encrypted shares and/or already-decrypted SLIP-39 mnemonics (share rows)."
    );
  }

  /** @type {import("openpgp").PrivateKey|null} */
  let privateKey = null;
  try {
    if (ciphertexts.length) {
      if (!gpg?.privateKeyArmored) {
        throw new Error(
          `${ciphertexts.length} OpenPGP message(s) still need a browser-unlockable private key. ` +
            `YubiKey/OpenPGP smartcards are not available to the browser — decrypt those shares in Kleopatra/gpg, then paste the mnemonics into the share rows.`
        );
      }
      privateKey = await readPrivateKey({ armoredKey: gpg.privateKeyArmored });
      if (!privateKey.isDecrypted()) {
        privateKey = await decryptKey({
          privateKey,
          passphrase: gpg.passphrase || "",
        });
      }
      for (const armored of ciphertexts) {
        try {
          const result = await openpgpDecrypt({
            message: await readMessage({ armoredMessage: armored }),
            decryptionKeys: privateKey,
            config: { allowInsecureDecryptionWithSigningKeys: true },
          });
          const plaintext =
            typeof result.data === "string"
              ? result.data
              : new TextDecoder().decode(result.data);
          const mnemonic = asShareMnemonic(plaintext) || String(plaintext).trim();
          if (mnemonic) mnemonics.push(mnemonic);
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err);
          problems.push(`Decrypt failed: ${msg}`);
        }
      }
    }

    /** @type {string[]} */
    const unique = [];
    /** @type {Set<string>} */
    const seen = new Set();
    for (const m of mnemonics) {
      const key = String(m).replace(/\s+/g, " ").trim();
      if (!key || seen.has(key)) continue;
      seen.add(key);
      unique.push(key);
    }

    if (!unique.length) {
      const detail = problems.length ? ` (${problems.join("; ")})` : "";
      throw new Error(`No share mnemonics recovered${detail}`);
    }

    /** @type {Uint8Array|null} */
    let envelope = null;
    if (gpg?.envelopeB64) {
      envelope = base64ToBytes(String(gpg.envelopeB64).replace(/\s+/g, ""));
    } else if (bindings.inputs?.shares?.envelopeB64) {
      envelope = base64ToBytes(
        String(bindings.inputs.shares.envelopeB64).replace(/\s+/g, "")
      );
    }
    return {
      type: "shares",
      data: {
        mnemonics: unique,
        envelope,
        threshold: 0,
        shares: unique.length,
        enveloped: !!envelope,
      },
      meta: {
        sensitive: true,
        envelope,
        passphrase: bindings.inputs?.shares?.passphrase || "",
        decryptNotes: problems,
      },
    };
  } finally {
    if (privateKey) zeroKeyMaterial(privateKey);
  }
}

/**
 * @param {string} alg
 * @param {string} usage
 * @returns {Promise<PipelineValue>}
 */
async function generateKeyValue(alg, usage) {
  if (alg.startsWith("ec/")) {
    const curve =
      alg === "ec/p384" ? "P-384" : alg === "ec/p521" ? "P-521" : "P-256";
    const useDerive = usage === "derive";
    const keyPair = await crypto.subtle.generateKey(
      { name: useDerive ? "ECDH" : "ECDSA", namedCurve: curve },
      true,
      useDerive ? ["deriveBits", "deriveKey"] : ["sign", "verify"]
    );
    return {
      type: "keypair",
      data: keyPair,
      meta: { alg, curve, algorithm: useDerive ? "ECDH" : "ECDSA", sensitive: true },
    };
  }
  if (alg === "ed25519") {
    const keyPair = await crypto.subtle.generateKey("Ed25519", true, [
      "sign",
      "verify",
    ]);
    return {
      type: "keypair",
      data: keyPair,
      meta: { alg, algorithm: "Ed25519", sensitive: true },
    };
  }
  if (alg === "x25519") {
    const keyPair = await crypto.subtle.generateKey("X25519", true, [
      "deriveBits",
      "deriveKey",
    ]);
    return {
      type: "keypair",
      data: keyPair,
      meta: { alg, algorithm: "X25519", sensitive: true },
    };
  }
  if (alg.startsWith("rsa/")) {
    const modulus = Number(alg.split("/")[1]) || 3072;
    const useEncrypt = usage === "encrypt";
    const keyPair = await crypto.subtle.generateKey(
      {
        name: useEncrypt ? "RSA-OAEP" : "RSA-PSS",
        modulusLength: modulus,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      true,
      useEncrypt ? ["encrypt", "decrypt"] : ["sign", "verify"]
    );
    return {
      type: "keypair",
      data: keyPair,
      meta: {
        alg,
        algorithm: useEncrypt ? "RSA-OAEP" : "RSA-PSS",
        sensitive: true,
      },
    };
  }
  if (alg.startsWith("aes/")) {
    const length = alg === "aes/128" ? 128 : 256;
    const key = await crypto.subtle.generateKey(
      { name: "AES-GCM", length },
      true,
      ["encrypt", "decrypt"]
    );
    return {
      type: "keypair",
      data: { privateKey: key, publicKey: null },
      meta: { alg, algorithm: "AES-GCM", symmetric: true, sensitive: true },
    };
  }
  if (alg.startsWith("hmac/")) {
    const hash = alg === "hmac/sha512" ? "SHA-512" : "SHA-256";
    const key = await crypto.subtle.generateKey(
      { name: "HMAC", hash, length: hash === "SHA-512" ? 512 : 256 },
      true,
      ["sign", "verify"]
    );
    return {
      type: "keypair",
      data: { privateKey: key, publicKey: null },
      meta: { alg, algorithm: "HMAC", symmetric: true, sensitive: true },
    };
  }
  throw new Error(`Unsupported algorithm: ${alg}`);
}

/**
 * @param {PipelineValue|null} value
 * @param {string} format
 * @param {string} which
 */
async function exportKey(value, format, which) {
  if (!value || value.type !== "keypair") throw new Error("export expects a keypair");
  const { data, meta } = value;
  const priv = data.privateKey;
  const pub = data.publicKey;

  if (format === "jwk") {
    const jwk =
      which === "public" && pub
        ? await crypto.subtle.exportKey("jwk", pub)
        : await crypto.subtle.exportKey("jwk", priv);
    const text = JSON.stringify(jwk, null, 2);
    return {
      type: "text",
      data: text,
      meta: { ...meta, format: "jwk", which, sensitive: which !== "public" },
    };
  }

  if (format === "raw") {
    const key = which === "public" && pub ? pub : priv;
    try {
      const raw = new Uint8Array(await crypto.subtle.exportKey("raw", key));
      return {
        type: "bytes",
        data: raw,
        meta: { ...meta, format: "raw", which, sensitive: which !== "public" },
      };
    } catch (err) {
      throw new Error(
        `raw export not supported for this key (${meta?.algorithm}): ${err?.message || err}`
      );
    }
  }

  if (format === "spki" || which === "public") {
    if (!pub) throw new Error("No public key to export as SPKI");
    const der = new Uint8Array(await crypto.subtle.exportKey("spki", pub));
    return {
      type: "bytes",
      data: der,
      meta: { ...meta, format: "spki", which: "public", sensitive: false },
    };
  }

  try {
    const der = new Uint8Array(await crypto.subtle.exportKey("pkcs8", priv));
    return {
      type: "bytes",
      data: der,
      meta: { ...meta, format: "pkcs8", which: "private", sensitive: true },
    };
  } catch (err) {
    if (meta?.symmetric) {
      const raw = new Uint8Array(await crypto.subtle.exportKey("raw", priv));
      return {
        type: "bytes",
        data: raw,
        meta: { ...meta, format: "raw", which: "private", sensitive: true },
      };
    }
    throw new Error(`pkcs8 export failed: ${err?.message || err}`);
  }
}

/**
 * @param {PipelineValue|null} value
 * @param {string} format
 * @param {string} alg
 * @param {string} usage
 */
async function importKey(value, format, alg, usage) {
  if (!value || value.type !== "bytes") throw new Error("import expects bytes");
  const der = value.data;
  const useDerive = usage === "derive";
  const useEncrypt = usage === "encrypt";

  if (alg.startsWith("ec/")) {
    const curve =
      alg === "ec/p384" ? "P-384" : alg === "ec/p521" ? "P-521" : "P-256";
    const name = useDerive ? "ECDH" : "ECDSA";
    const usages = useDerive
      ? /** @type {KeyUsage[]} */ (["deriveBits", "deriveKey"])
      : /** @type {KeyUsage[]} */ (["sign", "verify"]);
    if (format === "spki") {
      const publicKey = await crypto.subtle.importKey(
        "spki",
        der,
        { name, namedCurve: curve },
        true,
        useDerive ? [] : ["verify"]
      );
      return {
        type: "keypair",
        data: { privateKey: null, publicKey },
        meta: { alg, curve, algorithm: name, sensitive: false },
      };
    }
    const privateKey = await crypto.subtle.importKey(
      format === "raw" ? "raw" : "pkcs8",
      der,
      { name, namedCurve: curve },
      true,
      usages.filter((u) => u !== "verify")
    );
    return {
      type: "keypair",
      data: { privateKey, publicKey: null },
      meta: { alg, curve, algorithm: name, sensitive: true },
    };
  }

  if (alg === "ed25519") {
    if (format === "spki") {
      const publicKey = await crypto.subtle.importKey(
        "spki",
        der,
        "Ed25519",
        true,
        ["verify"]
      );
      return {
        type: "keypair",
        data: { privateKey: null, publicKey },
        meta: { alg, algorithm: "Ed25519", sensitive: false },
      };
    }
    const privateKey = await crypto.subtle.importKey(
      format === "raw" ? "raw" : "pkcs8",
      der,
      "Ed25519",
      true,
      ["sign"]
    );
    return {
      type: "keypair",
      data: { privateKey, publicKey: null },
      meta: { alg, algorithm: "Ed25519", sensitive: true },
    };
  }

  if (alg === "x25519") {
    const privateKey = await crypto.subtle.importKey(
      format === "raw" ? "raw" : "pkcs8",
      der,
      "X25519",
      true,
      ["deriveBits", "deriveKey"]
    );
    return {
      type: "keypair",
      data: { privateKey, publicKey: null },
      meta: { alg, algorithm: "X25519", sensitive: true },
    };
  }

  if (alg.startsWith("rsa/")) {
    const name = useEncrypt ? "RSA-OAEP" : "RSA-PSS";
    const privateKey = await crypto.subtle.importKey(
      "pkcs8",
      der,
      { name, hash: "SHA-256" },
      true,
      useEncrypt ? ["decrypt"] : ["sign"]
    );
    return {
      type: "keypair",
      data: { privateKey, publicKey: null },
      meta: { alg, algorithm: name, sensitive: true },
    };
  }

  if (alg.startsWith("aes/")) {
    const key = await crypto.subtle.importKey("raw", der, "AES-GCM", true, [
      "encrypt",
      "decrypt",
    ]);
    return {
      type: "keypair",
      data: { privateKey: key, publicKey: null },
      meta: { alg, algorithm: "AES-GCM", symmetric: true, sensitive: true },
    };
  }

  if (alg.startsWith("hmac/")) {
    const hash = alg === "hmac/sha512" ? "SHA-512" : "SHA-256";
    const key = await crypto.subtle.importKey(
      "raw",
      der,
      { name: "HMAC", hash },
      true,
      ["sign", "verify"]
    );
    return {
      type: "keypair",
      data: { privateKey: key, publicKey: null },
      meta: { alg, algorithm: "HMAC", symmetric: true, sensitive: true },
    };
  }

  throw new Error(`Unsupported import algorithm: ${alg}`);
}

/**
 * @param {string} raw
 * @returns {string}
 */
function safeOutputStem(raw) {
  const s = String(raw || "output")
    .trim()
    .replace(/[^\w.-]+/g, "_")
    .replace(/^\.+/, "")
    .slice(0, 64);
  return s || "output";
}

/**
 * Build downloadable tiles from a pipeline value for `out`.
 * @param {PipelineValue} value
 * @param {Record<string, *>} params
 * @returns {Promise<ToolkitArtifact[]>}
 */
async function materializeOutArtifacts(value, params) {
  const stem = safeOutputStem(params.name || "output");
  const label = String(params.label || stem);
  const encoding = String(params.encoding || "auto").toLowerCase();
  const extOverride = String(params.ext || "")
    .replace(/^\./, "")
    .replace(/[^\w.-]+/g, "");
  const mimeOverride = String(params.mime || "").trim();
  const shareSuffix = value.meta?.shareIndex
    ? `-${value.meta.shareIndex}`
    : "";

  if (value.type === "text") {
    let content = String(value.data);
    let encodingUsed = "text";
    let ext = extOverride || "txt";
    let mime = mimeOverride || "text/plain; charset=utf-8";
    if (encoding === "hex") {
      content = bytesToHex(textToBytes(content));
      encodingUsed = "hex";
      ext = extOverride || "hex";
      mime = mimeOverride || "text/plain";
    } else if (encoding === "base64") {
      content = bytesToBase64(textToBytes(String(value.data)));
      encodingUsed = "base64";
      ext = extOverride || "b64";
      mime = mimeOverride || "text/plain";
    }
    return [
      {
        label: value.meta?.shareIndex
          ? `${label} (share ${value.meta.shareIndex})`
          : label,
        filename: `${stem}${shareSuffix}.${ext}`,
        content,
        sensitive: !!value.meta?.sensitive,
        mime,
        encoding: encodingUsed,
        shareIndex: value.meta?.shareIndex,
      },
    ];
  }

  if (value.type === "bytes") {
    let content;
    let encodingUsed;
    let ext;
    let mime;
    if (encoding === "hex") {
      content = bytesToHex(value.data);
      encodingUsed = "hex";
      ext = extOverride || "hex";
      mime = mimeOverride || "text/plain";
    } else if (encoding === "text") {
      content = bytesToText(value.data);
      encodingUsed = "text";
      ext = extOverride || "txt";
      mime = mimeOverride || "text/plain; charset=utf-8";
    } else {
      // auto / base64
      content = bytesToBase64(value.data);
      encodingUsed = "base64";
      ext = extOverride || "bin.b64";
      mime = mimeOverride || "application/octet-stream";
    }
    return [
      {
        label,
        filename: `${stem}${shareSuffix}.${ext}`,
        content,
        sensitive: !!value.meta?.sensitive,
        mime,
        encoding: encodingUsed,
        shareIndex: value.meta?.shareIndex,
      },
    ];
  }

  if (value.type === "shares") {
    return (value.data.mnemonics || []).map((m, i) => ({
      label: `${label} · share ${i + 1}`,
      filename: `${stem}-${i + 1}.${extOverride || "txt"}`,
      content: String(m),
      sensitive: true,
      mime: mimeOverride || "text/plain; charset=utf-8",
      encoding: "text",
      shareIndex: i + 1,
    }));
  }

  if (value.type === "keypair") {
    const parts = [];
    const priv = value.data?.privateKey;
    const pub = value.data?.publicKey;
    if (priv) {
      try {
        const jwk = await crypto.subtle.exportKey("jwk", priv);
        parts.push({
          label: `${label} · private JWK`,
          filename: `${stem}-private.${extOverride || "jwk.json"}`,
          content: JSON.stringify(jwk, null, 2),
          sensitive: true,
          mime: mimeOverride || "application/json",
          encoding: "jwk",
        });
      } catch (err) {
        parts.push({
          label: `${label} · private`,
          filename: `${stem}-private.txt`,
          content: `Private key present but not exportable: ${err?.message || err}`,
          sensitive: true,
          mime: "text/plain",
          encoding: "text",
        });
      }
    }
    if (pub) {
      try {
        const jwk = await crypto.subtle.exportKey("jwk", pub);
        parts.push({
          label: `${label} · public JWK`,
          filename: `${stem}-public.${extOverride || "jwk.json"}`,
          content: JSON.stringify(jwk, null, 2),
          sensitive: false,
          mime: mimeOverride || "application/json",
          encoding: "jwk",
        });
      } catch (_) {
        /* ignore */
      }
    }
    if (!parts.length) {
      parts.push({
        label,
        filename: `${stem}.txt`,
        content: "[keypair — no extractable material]",
        sensitive: true,
        mime: "text/plain",
        encoding: "text",
      });
    }
    return parts;
  }

  return valueToArtifacts(value, stem);
}

/**
 * @param {PipelineValue} value
 * @param {string} [name]
 * @returns {ToolkitArtifact[]}
 */
function valueToArtifacts(value, name = "artifact") {
  if (value.type === "text") {
    return [
      {
        label: name,
        filename: `${name}.txt`,
        content: String(value.data),
        sensitive: !!value.meta?.sensitive,
        mime: "text/plain; charset=utf-8",
        encoding: "text",
      },
    ];
  }
  if (value.type === "bytes") {
    return [
      {
        label: name,
        filename: `${name}.bin.b64`,
        content: bytesToBase64(value.data),
        sensitive: !!value.meta?.sensitive,
        mime: "application/octet-stream",
        encoding: "base64",
      },
    ];
  }
  if (value.type === "shares") {
    return value.data.mnemonics.map((m, i) => ({
      label: `Share ${i + 1}`,
      filename: `share-${i + 1}.txt`,
      content: m,
      sensitive: true,
      shareIndex: i + 1,
      mime: "text/plain; charset=utf-8",
      encoding: "text",
    }));
  }
  if (value.type === "keypair") {
    return [
      {
        label: name,
        filename: `${name}.txt`,
        content: "[keypair — use out or export before emitting]",
        sensitive: true,
        mime: "text/plain",
        encoding: "text",
      },
    ];
  }
  return [];
}

export { splitArmoredMessages } from "../pgp/armor.js";
export { zeroBuffer, bytesToText };
