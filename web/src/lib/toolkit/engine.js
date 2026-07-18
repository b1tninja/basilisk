/**
 * Execute a compiled toolkit recipe AST.
 * Returns encoded artifacts only (never CryptoKey handles).
 */

import { generateWordPassphrase } from "../passphrase-gen.js";
import { qrSvg } from "../qr.js";
import { PROFILE_AUTO, encryptArtifacts } from "../pgp/encrypt.js";
import { splitShares } from "../slip39/slip39.js";
import {
  bytesToBase64,
  bytesToBase64Url,
  bytesToHex,
  bytesToText,
  pemLabelFor,
  textToBytes,
  toPem,
  zeroBuffer,
} from "./encode.js";
import { getStep } from "./registry.js";

/**
 * @typedef {object} ToolkitArtifact
 * @property {string} label
 * @property {string} filename
 * @property {string} content  text (PEM, mnemonic, armored, SVG, …)
 * @property {boolean} sensitive
 * @property {string} [mime]
 * @property {number} [shareIndex]
 * @property {string} [recipientFingerprint]
 */

/**
 * @typedef {object} RuntimeBindings
 * @property {import("openpgp").Key[]} [recipients]  ordered; for foreach gpg, one per share
 * @property {string[]} [recipientFingerprints]
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

  // Expand foreach scopes into an execution plan
  const plan = expandPlan(steps);

  for (const node of plan) {
    if (node.kind === "foreach") {
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
        // If last step wasn't a sink that already emitted, emit out
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
      value = { type: "bundle", data: artifacts };
      continue;
    }

    value = await execStep(node.step, value, bindings, artifacts, 0);
  }

  // If pipeline ended with a non-sink value, emit it
  if (value && value.type !== "bundle" && value.type !== "artifact") {
    artifacts.push(...valueToArtifacts(value));
  }

  return artifacts;
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
      // i points at merge or past end
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
 * @param {number} shareIndex0
 * @returns {Promise<PipelineValue>}
 */
async function execStep(step, value, bindings, artifacts, shareIndex0) {
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
    case "export":
      return exportKey(value, String(step.params.format || "pkcs8"), String(step.params.which || "private"));
    case "pem": {
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
      if (!value || value.type !== "bytes") throw new Error("hex expects bytes");
      return {
        type: "text",
        data: bytesToHex(value.data),
        meta: { ...value.meta, sensitive: !!value.meta?.sensitive },
      };
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
        meta: { sensitive: true },
      };
    }
    case "gpg": {
      if (!value || (value.type !== "text" && value.type !== "bytes")) {
        throw new Error("gpg expects text");
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
      const name = String(step.params.name || "artifact");
      const emitted = valueToArtifacts(value, name);
      for (const a of emitted) {
        if (value.meta?.shareIndex) {
          a.shareIndex = value.meta.shareIndex;
          a.label = `Share ${value.meta.shareIndex}`;
          a.filename = `${name}-${value.meta.shareIndex}.txt`;
        }
        artifacts.push(a);
      }
      // Also emit envelope alongside first share if present
      if (value.meta?.envelope && shareIndex0 === 0 && value.meta.shareIndex === 1) {
        artifacts.push({
          label: "Envelope ciphertext",
          filename: "envelope.bin.b64",
          content: bytesToBase64(value.meta.envelope),
          sensitive: false,
          mime: "application/octet-stream",
        });
      }
      return { type: "artifact", data: null, meta: value.meta };
    }
    default:
      throw new Error(`Unsupported step: ${step.name}`);
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
      useEncrypt
        ? ["encrypt", "decrypt"]
        : ["sign", "verify"]
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

  // pkcs8 private
  try {
    const der = new Uint8Array(await crypto.subtle.exportKey("pkcs8", priv));
    return {
      type: "bytes",
      data: der,
      meta: { ...meta, format: "pkcs8", which: "private", sensitive: true },
    };
  } catch (err) {
    // Symmetric keys: fall back to raw
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
    }));
  }
  if (value.type === "keypair") {
    return [
      {
        label: name,
        filename: `${name}.txt`,
        content: "[keypair — export before emitting]",
        sensitive: true,
      },
    ];
  }
  return [];
}

export { zeroBuffer, bytesToText };
