/**
 * Execute a compiled toolkit recipe AST (multi-chain + @slot registry).
 * Normative language: docs/RECIPE.md
 * Returns encoded artifacts only (never CryptoKey handles).
 */

import {
  decrypt as openpgpDecrypt,
  decryptKey,
  generateKey as openpgpGenerateKey,
  readKey,
  readMessage,
  readPrivateKey,
} from "openpgp";
import {
  generateCharPassphrase,
  generateWordPassphrase,
} from "../passphrase-gen.js";
import {
  dearmorToBytes,
  enrichSpansWithPackets,
  mapPacketSpans,
} from "../packet-map.js";
import { qrSvg } from "../qr.js";
import {
  PROFILE_AUTO,
  encryptArtifacts,
  summarizeEncryption,
} from "../pgp/encrypt.js";
import {
  analyzeArmored,
  formatAnalysisSummary,
} from "../pgp/inspect.js";
import { signOpenPgp, verifyOpenPgp } from "../pgp/sign.js";
import { zeroKeyMaterial } from "../pgp/memory.js";
import {
  decodeShareSet,
  encodeShareSet,
  validateShareMnemonic,
} from "../slip39/blip39.js";
import { combineRawShares, splitRawShares } from "../slip39/slip39.js";
import {
  base32ToBytes,
  base64ToBytes,
  bytesToBase32,
  bytesToBase64,
  bytesToBase64Url,
  bytesToHex,
  bytesToText,
  fromPem,
  hexToBytes,
  jwkFieldToBytes,
  pemLabelFor,
  pkcs8FromEcScalar,
  textToBytes,
  toPem,
} from "./encode.js";
import {
  aesCbcDecrypt,
  aesCbcEncrypt,
  aesContentUnwrap,
  aesContentWrap,
  aesCtrDecrypt,
  aesCtrEncrypt,
  aesGcmDecrypt,
  aesGcmEncrypt,
  aesKwUnwrap,
  aesKwWrap,
  aesLengthFromAlg,
  ecdhDerive,
  ensureAesWrapKey,
  extractableWrapTarget,
  hkdfDerive,
  hmacHashFromAlg,
  hmacLengthBits,
  importBoundJwk,
  normalizeHashName,
  pbkdf2Derive,
  resolveBoundKey,
  resolveSlotKey,
  rsaOaepParams,
  rsaOaepUnwrap,
  rsaOaepWrap,
  subtleSign,
  subtleVerify,
  unwrapImportParams,
  valueToBytes,
} from "./webcrypto-ops.js";
import { buildInspectSnapshot, inspectFromSnapshot } from "./inspect.js";
import { getStep } from "./registry.js";
import { recipeChains } from "./recipe.js";
import {
  LEGACY_CRYPTO_TAGS,
  rsaesPkcs1Decrypt,
  rsaesPkcs1Encrypt,
} from "./rsaes-pkcs1.js";
import {
  resolveStepType,
  typeOf,
} from "./types.js";
import {
  clonePipelineValue,
  createSlotRegistry,
} from "./slot-registry.js";

/**
 * @typedef {"share"|"envelope"|"ciphertext"|"key"|"secret"|"inspect"|"qr"|"text"} ArtifactRole
 *
 * @typedef {object} ToolkitArtifact
 * @property {string} label
 * @property {string} filename
 * @property {string} content  text (PEM, mnemonic, armored, SVG, …)
 * @property {boolean} [sensitive]
 * @property {number} [shareIndex]
 * @property {string} [mime]
 * @property {string} [encoding]
 * @property {string} [recipientFingerprint]
 * @property {string} [cryptoSummary]
 * @property {number} [stepIndex]  1-based index of the pipeline step that produced this artifact
 * @property {string} [stepName]
 * @property {"message"|"file"} [disposition]
 *   message = printable text (Encrypt opens as a compose message);
 *   file = named/binary/QR/share output (Encrypt attaches as a file)
 * @property {ArtifactRole} [role]
 * @property {string[]} [tags]
 * @property {{
 *   shareOf?: number,
 *   threshold?: number,
 *   which?: "public"|"private",
 *   alg?: string,
 * }} [traits]
 * @property {import("./types.js").RefinedType} [pipeType]  refined pipeline type at emit time
 * @property {Uint8Array} [bytes]  raw octets when content is a textual encoding of binary
 * @property {import("./inspect.js").InspectSnapshot} [inspectSnapshot]  for live format switching
 * @property {string} [inspectFormat]  current inspect dump format
 */

/**
 * @typedef {object} RuntimeBindings
 * @property {import("openpgp").Key[]} [recipients]  ordered; for foreach encrypt, one per share
 * @property {string[]} [recipientFingerprints]
 * @property {Record<string, string[]>} [recipientResolutions]  email/query → chosen fingerprints
 * @property {(ref: string) => PipelineValue|null|undefined} [resolveSlot]
 * @property {{
 *   shares?: {
 *     mnemonics: string[],
 *     envelopeB64?: string,
 *     envelopeArmored?: string,
 *     passphrase?: string,
 *   },
 *   envelope?: { armored: string },
 *   text?: { value: string },
 *   gpg?: {
 *     armoredMessages: string[],
 *     privateKeyArmored: string,
 *     passphrase?: string,
 *     envelopeB64?: string,
 *     envelopeArmored?: string,
 *   },
 *   key?: {
 *     jwkText?: string,
 *     jwk?: JsonWebKey,
 *     privateKey?: CryptoKey,
 *     publicKey?: CryptoKey,
 *     secretKey?: CryptoKey,
 *     alg?: string,
 *     peerJwkText?: string,
 *     wrapJwkText?: string,
 *     signatureB64url?: string,
 *   },
 * }} [inputs]
 * @property {{
 *   profile?: import("../pgp/types.js").EncryptProfile,
 *   hideRecipients?: boolean,
 * }} [encryption]
 * @property {boolean} [fipsMode]  when true, refuse unverified CAST suites
 * @property {import("./suite-gate.js").SuiteStatusMap} [suiteStatus]
 */

/**
 * @typedef {object} PipelineValue
 * @property {string} type
 * @property {*} data
 * @property {Record<string, *>} [meta]
 */

/**
 * Run a recipe AST.
 * @param {import("./recipe.js").RecipeAst|import("./recipe.js").RecipeChain[]|import("./recipe.js").RecipeStep[]} ast
 * @param {RuntimeBindings} [bindings]
 * @param {{
 *   slotRegistry?: ReturnType<typeof createSlotRegistry>,
 *   allowReplaceSlots?: boolean,
 *   chainStart?: number,
 *   chainEnd?: number,
 * }} [opts]
 * @returns {Promise<ToolkitArtifact[]>}
 */
export async function runRecipe(ast, bindings = {}, opts = {}) {
  const chains = recipeChains(ast);
  const chainStart = Math.max(0, opts.chainStart ?? 0);
  const chainEnd = Math.min(chains.length, opts.chainEnd ?? chains.length);
  const slice = chains.slice(chainStart, chainEnd);
  if (!slice.length || !slice.some((c) => c.steps?.length)) {
    throw new Error("Empty recipe");
  }

  if (bindings.fipsMode) {
    const { assertRecipeAllowedUnderFips } = await import("./suite-gate.js");
    const status = bindings.suiteStatus || {
      openpgp: "unverified",
      webcrypto: "unverified",
      sss: "unverified",
    };
    // Validate the full AST when provided; otherwise the slice alone.
    const forFips =
      ast && typeof ast === "object" && !Array.isArray(ast) && ast.chains
        ? ast
        : { chains: slice, steps: slice[0]?.steps || [], source: "" };
    assertRecipeAllowedUnderFips(forFips, status, true);
  }

  /** @type {ToolkitArtifact[]} */
  const artifacts = [];
  const registry = opts.slotRegistry || createSlotRegistry();
  const allowReplaceSlots = !!opts.allowReplaceSlots;

  /**
   * @param {string} nameRef
   * @param {PipelineValue} value
   * @param {Set<string>} preexisting
   */
  const registerSlot = (nameRef, value, preexisting) => {
    registry.register(nameRef, value, {
      allowReplace: allowReplaceSlots,
      preexisting,
    });
  };

  const resolveSlot = (ref) => registry.resolve(ref);

  // Named slot args (`key=@cek`) resolve through the same registry as `in`.
  bindings = { ...bindings, resolveSlot };

  let stepOrdinal = 0;

  for (const chain of slice) {
    const steps = chain.steps || [];
    if (!steps.length) continue;
    const preexisting = registry.snapshotKeys();

    /** @type {PipelineValue|null} */
    let value = null;
    /** True when the last top-level step already materialized tiles (`out` / `text`). */
    let lastStepEmitted = false;

    const plan = expandPlan(steps);

    // Stamp artifacts pushed since `before` with the pipeline step that produced
    // them, so the UI can point each output tile back at its builder card.
    /** @param {number} before @param {import("./recipe.js").RecipeStep|undefined} step */
    const stampNew = (before, step) => {
      if (!step) return;
      const idx = steps.indexOf(step);
      for (let i = before; i < artifacts.length; i++) {
        if (artifacts[i].stepIndex == null) {
          if (idx >= 0) artifacts[i].stepIndex = stepOrdinal + idx + 1;
          artifacts[i].stepName = step.name;
        }
      }
    };

  for (const node of plan) {
    if (node.kind === "tee") {
      lastStepEmitted = false;
      if (!value) throw new Error("tee requires a pipeline value");

      /**
       * Run a side chain; auto-emit dangling values (e.g. bare `inspect`).
       * @param {PipelineValue} start
       * @param {import("./recipe.js").RecipeStep[]} body
       */
      const runTeeSide = async (start, body) => {
        let sideVal = start;
        let emitted = false;
        for (const step of body) {
          const before = artifacts.length;
          sideVal = await execStep(step, sideVal, bindings, artifacts, 0);
          stampNew(before, node.step);
          for (let ai = before; ai < artifacts.length; ai++) {
            artifacts[ai].stepName = step.name;
          }
          if (step.name === "out" && sideVal) {
            registerSlot(String(step.params?.name || "@output"), sideVal, preexisting);
          }
          if (step.name === "out" || step.name === "text") emitted = true;
          if (artifacts.length > before) emitted = true;
        }
        if (
          sideVal &&
          !emitted &&
          sideVal.type !== "bundle" &&
          sideVal.type !== "artifact"
        ) {
          const before = artifacts.length;
          artifacts.push(...valueToArtifacts(sideVal));
          stampNew(before, node.step);
        }
      };

      if (node.body?.length) {
        await runTeeSide(clonePipelineValue(value), node.body);
      }
      for (const br of node.branches || []) {
        await runTeeSide(
          projectSelector(value, br.selector || `.${br.member}`),
          br.body
        );
      }
      // Stem value unchanged.
      continue;
    }

    if (node.kind === "foreach") {
      lastStepEmitted = false;
      if (!value || value.type !== "shares") {
        throw new Error("foreach requires shares");
      }
      const threshold = Number(value.data.threshold) || 0;
      const body = node.body;
      const mode = String(node.step.foreachSelector || ".values")
        .replace(/^\./, "")
        .toLowerCase();
      const rawItems = value.data.raw;
      const mnemonicItems = value.data.mnemonics;
      const useRaw = Array.isArray(rawItems) && rawItems.length > 0;
      const items = useRaw ? rawItems : mnemonicItems || [];
      if (!items.length) throw new Error("foreach requires a non-empty share set");

      for (let i = 0; i < items.length; i++) {
        /** @type {PipelineValue} */
        let itemVal;
        const shareIndex = useRaw
          ? /** @type {{ index: number, data: Uint8Array }} */ (items[i]).index ||
            i + 1
          : i + 1;
        const valuePayload = useRaw
          ? {
              type: "bytes",
              data: /** @type {{ index: number, data: Uint8Array }} */ (items[i])
                .data,
              meta: {
                shareIndex,
                shareCount: items.length,
                threshold,
                sensitive: true,
              },
            }
          : {
              type: "text",
              data: /** @type {string} */ (items[i]),
              meta: {
                shareIndex,
                shareCount: items.length,
                threshold,
                sensitive: true,
              },
            };

        if (mode === "keys") {
          itemVal = {
            type: "text",
            data: String(shareIndex),
            meta: {
              shareIndex,
              shareCount: items.length,
              threshold,
              sensitive: false,
            },
          };
        } else if (mode === "items") {
          itemVal = {
            type: "item",
            data: { key: shareIndex, value: valuePayload },
            meta: {
              shareIndex,
              shareCount: items.length,
              threshold,
              sensitive: true,
            },
          };
        } else {
          itemVal = valuePayload;
        }
        for (const step of body) {
          const before = artifacts.length;
          itemVal = await execStep(step, itemVal, bindings, artifacts, i);
          stampNew(before, node.step);
          for (let ai = before; ai < artifacts.length; ai++) {
            artifacts[ai].stepName = step.name;
          }
          if (step.name === "out" && itemVal) {
            registerSlot(String(step.params?.name || "@output"), itemVal, preexisting);
          }
        }
        if (itemVal && (itemVal.type === "text" || itemVal.type === "bytes")) {
          const last = body[body.length - 1];
          if (last && getStep(last.name)?.kind !== "sink") {
            const before = artifacts.length;
            const idx = itemVal.meta?.shareIndex || i + 1;
            if (itemVal.type === "text") {
              artifacts.push({
                label: `Share ${idx}`,
                filename: `share-${idx}.txt`,
                content: String(itemVal.data),
                sensitive: true,
                shareIndex: idx,
                disposition: "file",
                role: "share",
                tags: ["mnemonic", "blip39"],
                traits: {
                  shareOf: idx,
                  threshold: threshold || undefined,
                },
              });
            } else {
              artifacts.push({
                label: `Share ${idx}`,
                filename: `share-${idx}.bin.b64`,
                content: bytesToBase64(itemVal.data),
                bytes: new Uint8Array(itemVal.data),
                sensitive: true,
                shareIndex: idx,
                disposition: "file",
                role: "share",
                tags: ["sss", "raw"],
                traits: {
                  shareOf: idx,
                  threshold: threshold || undefined,
                },
              });
            }
            stampNew(before, node.step);
            for (let ai = before; ai < artifacts.length; ai++) {
              artifacts[ai].stepName = last.name;
            }
          }
        }
      }
      value = { type: "bundle", data: artifacts };
      continue;
    }

    if (node.step.name === "in") {
      lastStepEmitted = false;
      value = resolveSlot(String(node.step.params?.ref || ""));
      continue;
    }

    const before = artifacts.length;
    value = await execStep(node.step, value, bindings, artifacts, 0);
    stampNew(before, node.step);
    lastStepEmitted = node.step.name === "out" || node.step.name === "text";
    if (node.step.name === "out" && value) {
      registerSlot(String(node.step.params?.name || "@output"), value, preexisting);
    }
  }

  if (value && value.type !== "bundle" && value.type !== "artifact") {
    // Terminal `out` / `text` already pushed tiles; later transforms clear this flag.
    if (!lastStepEmitted) {
      const before = artifacts.length;
      artifacts.push(...valueToArtifacts(value));
      stampNew(before, steps[steps.length - 1]);
    }
  }

  stepOrdinal += steps.length;
  } // end chains

  return artifacts;
}

/**
 * @param {import("./recipe.js").RecipeStep[]} steps
 */
function expandPlan(steps) {
  /** @type {Array<
   *   | { kind: "step", step: import("./recipe.js").RecipeStep }
   *   | { kind: "foreach", body: import("./recipe.js").RecipeStep[], step: import("./recipe.js").RecipeStep }
   *   | { kind: "tee", body: import("./recipe.js").RecipeStep[], branches?: *, step: import("./recipe.js").RecipeStep }
   * >} */
  const plan = [];
  for (let i = 0; i < steps.length; i++) {
    const s = steps[i];
    if (s.name === "foreach") {
      if (!s.body?.length) {
        throw new Error(
          "foreach requires a body — use indented `-` lines or `{ … }`"
        );
      }
      plan.push({ kind: "foreach", body: s.body, step: s });
      continue;
    }
    if (
      s.name === "tee" &&
      (s.body?.length || s.branches?.length)
    ) {
      plan.push({
        kind: "tee",
        body: s.body || [],
        branches: s.branches || [],
        step: s,
      });
      continue;
    }
    plan.push({ kind: "step", step: s });
  }
  return plan;
}

/**
 * Project a selector (`.private`, `.items`, `.key`, …) from a pipeline value.
 * @param {PipelineValue} value
 * @param {string} selector
 * @returns {PipelineValue}
 */
export function projectSelector(value, selector) {
  const raw = String(selector || "").trim();
  if (/^\[\d/.test(raw)) {
    throw new Error(
      `selector ${raw}: use as a stem stage ([n] / at), not projectSelector`
    );
  }
  const m = raw.replace(/^\./, "").toLowerCase();
  if (m === "private" || m === "priv" || m === "secret") {
    if (value.type !== "keypair") {
      throw new Error(`selector .private requires a keypair`);
    }
    const priv = value.data?.privateKey;
    const pub = value.data?.publicKey;
    if (!priv) throw new Error("selector .private: no private key on keypair");
    return {
      type: "keypair",
      data: { privateKey: priv, publicKey: pub },
      meta: { ...value.meta, which: "private", sensitive: true },
    };
  }
  if (m === "public" || m === "pub") {
    if (value.type !== "keypair") {
      throw new Error(`selector .public requires a keypair`);
    }
    const pub = value.data?.publicKey;
    if (!pub) throw new Error("selector .public: no public key on keypair");
    return {
      type: "keypair",
      data: { publicKey: pub },
      meta: { ...value.meta, which: "public", sensitive: false },
    };
  }
  if (m === "key") {
    if (value.type !== "item") {
      throw new Error(`selector .key requires an item ({key, value})`);
    }
    return {
      type: "text",
      data: String(value.data?.key ?? ""),
      meta: { ...value.meta, sensitive: false },
    };
  }
  if (m === "value") {
    if (value.type !== "item") {
      throw new Error(`selector .value requires an item ({key, value})`);
    }
    const inner = value.data?.value;
    if (!inner || typeof inner !== "object") {
      throw new Error("selector .value: missing item value");
    }
    return /** @type {PipelineValue} */ (inner);
  }
  if (m === "keys" || m === "values" || m === "items") {
    throw new Error(
      `selector .${m}: use as foreach .${m} (stem projection of whole collections is not supported)`
    );
  }
  throw new Error(`Unknown selector ".${m}"`);
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
  const prevType =
    value?.meta?.type ||
    (value ? typeOf(/** @type {import("./registry.js").IoType} */ (value.type)) : typeOf("none"));
  const result = await execStepBody(step, value, bindings, artifacts);
  const spec = getStep(step.name);
  if (result && spec && result.type !== "bundle") {
    const resolved = resolveStepType(spec, prevType, step.params || {});
    if (resolved.ok) {
      result.meta = { ...result.meta, type: resolved.output };
    }
  }
  return result;
}

/**
 * @param {import("./recipe.js").RecipeStep} step
 * @param {PipelineValue|null} value
 * @param {RuntimeBindings} bindings
 * @param {ToolkitArtifact[]} artifacts
 * @returns {Promise<PipelineValue>}
 */
async function execStepBody(step, value, bindings, artifacts) {
  switch (step.name) {
    case "genkey":
      return generateKeyValue(
        String(step.params.alg || "ec/p256"),
        String(step.params.usage || "auto"),
        String(step.params.padding || "pss"),
        String(step.params.hash || "sha-256")
      );
    case "random": {
      const n = Number(step.params.length) || 32;
      const buf = crypto.getRandomValues(new Uint8Array(n));
      return { type: "bytes", data: buf, meta: { sensitive: true } };
    }
    case "passphrase": {
      const mode = String(step.params.mode || "diceware").toLowerCase();
      if (mode === "char") {
        const length = Number(step.params.length) || 20;
        const { passphrase } = generateCharPassphrase(length);
        return { type: "text", data: passphrase, meta: { sensitive: true } };
      }
      const words = Number(step.params.words) || 6;
      const { passphrase } = generateWordPassphrase(words);
      return { type: "text", data: passphrase, meta: { sensitive: true } };
    }
    case "gpg.genkey": {
      const email = String(step.params.email || "").trim();
      if (!email) {
        throw new Error("gpg.genkey requires email=… (OpenPGP user ID)");
      }
      const name = String(step.params.name || "").trim();
      const passphrase = String(step.params.passphrase || "");
      const expiry = Number(step.params.expiry) || 0;
      /** @type {Parameters<typeof openpgpGenerateKey>[0]} */
      const genOpts = {
        type: "ecc",
        curve: "curve25519",
        userIDs: [{ name: name || email, email }],
        format: "armored",
      };
      if (passphrase) genOpts.passphrase = passphrase;
      if (expiry > 0) genOpts.keyExpirationTime = expiry;
      const { privateKey: armoredPrivate, publicKey: armoredPublic } =
        await openpgpGenerateKey(genOpts);
      const pub = await readKey({ armoredKey: String(armoredPublic) });
      const fingerprint = pub.getFingerprint().toUpperCase();
      artifacts.push({
        label: "OpenPGP public key",
        filename: "public.asc",
        content: String(armoredPublic),
        sensitive: false,
        mime: "application/pgp-keys",
        disposition: "file",
        role: "public-key",
        tags: ["openpgp", "public-key"],
        traits: { fingerprint },
      });
      return {
        type: "openpgp-key",
        data: String(armoredPrivate),
        meta: {
          which: "private",
          sensitive: true,
          fingerprint,
          armoredPublic: String(armoredPublic),
        },
      };
    }
    case "input": {
      const text = String(bindings.inputs?.text?.value ?? "");
      if (!text.trim()) {
        throw new Error("No input text provided — paste or load a file before running.");
      }
      return { type: "text", data: text, meta: { sensitive: true } };
    }
    case "shares": {
      const inp = bindings.inputs?.shares;
      const mnemonics = (inp?.mnemonics || []).map((m) => String(m).trim()).filter(Boolean);
      if (!mnemonics.length) {
        throw new Error("No BLIP39 share mnemonics provided — paste shares before running.");
      }
      /** @type {Uint8Array|null} */
      let envelope = null;
      if (inp?.envelopeB64) {
        envelope = base64ToBytes(String(inp.envelopeB64).replace(/\s+/g, ""));
      }
      return {
        type: "shares",
        data: {
          encoding: "mnemonic",
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
    case "gpg.decrypt":
      return decryptGpgSource(bindings, artifacts);
    case "export": {
      const whichDefault =
        value?.meta?.which === "public" || value?.meta?.which === "private"
          ? value.meta.which
          : "private";
      return exportKey(
        value,
        String(step.params.format || "pkcs8"),
        String(step.params.which || whichDefault)
      );
    }
    case "import":
      return importKey(
        value,
        String(step.params.format || "pkcs8"),
        String(step.params.alg || "ec/p256"),
        String(step.params.usage || "auto"),
        String(step.params.padding || "pss"),
        String(step.params.hash || "sha-256")
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
      // Preserve export/selector sensitivity (public SPKI stays non-sensitive).
      return {
        type: "text",
        data: text,
        meta: { ...value.meta, sensitive: !!value.meta?.sensitive },
      };
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
      if (step.params.decode) {
        if (!value || value.type !== "text") {
          throw new Error("base64url -d expects text");
        }
        return {
          type: "bytes",
          data: base64ToBytes(String(value.data).replace(/\s+/g, "")),
          meta: { ...value.meta, sensitive: !!value.meta?.sensitive },
        };
      }
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
    case "base32":
      if (step.params.decode) {
        if (!value || value.type !== "text") throw new Error("base32 -d expects text");
        return {
          type: "bytes",
          data: base32ToBytes(String(value.data)),
          meta: { ...value.meta, sensitive: !!value.meta?.sensitive },
        };
      }
      if (!value || value.type !== "bytes") throw new Error("base32 expects bytes");
      return {
        type: "text",
        data: bytesToBase32(value.data),
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
    case "digest": {
      const bytes = valueToBytes(value);
      const algRaw = String(step.params.alg || "sha-256").toLowerCase();
      const name =
        algRaw === "sha-1" || algRaw === "sha1"
          ? "SHA-1"
          : algRaw === "sha-384" || algRaw === "sha384"
            ? "SHA-384"
            : algRaw === "sha-512" || algRaw === "sha512"
              ? "SHA-512"
              : "SHA-256";
      const digest = new Uint8Array(await crypto.subtle.digest(name, bytes));
      const legacy = name === "SHA-1";
      return {
        type: "bytes",
        data: digest,
        meta: {
          sensitive: false,
          alg: name.toLowerCase(),
          tags: legacy ? [...LEGACY_CRYPTO_TAGS, "sha-1"] : undefined,
        },
      };
    }
    case "sign": {
      const bytes = valueToBytes(value);
      let signingKey = await resolveSlotKey(
        bindings,
        step.params?.key,
        "either"
      );
      if (!signingKey) {
        const keyInp = bindings.inputs?.key;
        if (keyInp?.privateKey) signingKey = keyInp.privateKey;
        else if (keyInp?.secretKey) signingKey = keyInp.secretKey;
        else {
          const bound =
            keyInp?.jwk || keyInp?.jwkText
              ? await importBoundJwk(keyInp)
              : null;
          signingKey = bound?.privateKey || bound?.secretKey;
        }
        if (!signingKey) {
          signingKey = await resolveBoundKey(bindings, "either");
        }
      }
      if (!signingKey.usages.includes("sign")) {
        throw new Error("Bound key cannot sign — need private or HMAC key with sign usage");
      }
      const hashParam = String(step.params.hash || "auto");
      const sig = await subtleSign(signingKey, bytes, {
        saltLength: Number(step.params.saltLength) || 32,
        hash: hashParam === "auto" || !hashParam ? undefined : hashParam,
      });
      const pkcs1 = signingKey.algorithm?.name === "RSASSA-PKCS1-v1_5";
      return {
        type: "bytes",
        data: sig,
        meta: {
          sensitive: false,
          kind: "signature",
          tags: pkcs1
            ? [...LEGACY_CRYPTO_TAGS, "rsassa-pkcs1-v1_5"]
            : undefined,
        },
      };
    }
    case "verify": {
      const bytes = valueToBytes(value);
      // Prefer public (asymmetric) then secret (HMAC); avoid private-only handles.
      let verifyKey =
        (await resolveSlotKey(bindings, step.params?.key, "public")) ||
        (await resolveSlotKey(bindings, step.params?.key, "secret"));
      if (!verifyKey) {
        const keyInp = bindings.inputs?.key;
        if (keyInp?.publicKey) verifyKey = keyInp.publicKey;
        else if (keyInp?.secretKey) verifyKey = keyInp.secretKey;
        else {
          const bound =
            keyInp?.jwk || keyInp?.jwkText
              ? await importBoundJwk(keyInp)
              : null;
          verifyKey = bound?.publicKey || bound?.secretKey;
        }
        if (!verifyKey) {
          try {
            verifyKey = await resolveBoundKey(bindings, "public");
          } catch (_) {
            verifyKey = await resolveBoundKey(bindings, "secret");
          }
        }
      }
      if (!verifyKey.usages.includes("verify")) {
        throw new Error("Bound key cannot verify — need public or HMAC key with verify usage");
      }
      const signature = await resolveVerifySignature(bindings, step.params?.signature);
      const hashParam = String(step.params.hash || "auto");
      const ok = await subtleVerify(verifyKey, signature, bytes, {
        saltLength: Number(step.params.saltLength) || 32,
        hash: hashParam === "auto" || !hashParam ? undefined : hashParam,
      });
      const soft = !!step.params.soft;
      const pkcs1 = verifyKey.algorithm?.name === "RSASSA-PKCS1-v1_5";
      const tags = pkcs1
        ? [...LEGACY_CRYPTO_TAGS, "rsassa-pkcs1-v1_5"]
        : undefined;
      if (!ok) {
        if (soft) {
          return {
            type: "text",
            data: "invalid",
            meta: { sensitive: false, tags },
          };
        }
        throw new Error("Signature verification failed");
      }
      return {
        type: "text",
        data: "verified",
        meta: { sensitive: false, tags },
      };
    }
    case "aes-gcm": {
      const bytes = valueToBytes(value);
      const key =
        (await resolveSlotKey(bindings, step.params?.key, "secret")) ||
        (await resolveBoundKey(bindings, "secret"));
      assertExpectedAesKeyBits(key, step.params?.expectedKeyBits, "aes-gcm");
      const aadStr = String(step.params.aad || "");
      const aad = aadStr ? textToBytes(aadStr) : undefined;
      const tagLength = Number(step.params.tagLength) || 128;
      if (step.params.decode) {
        const plain = await aesGcmDecrypt(key, bytes, aad, tagLength);
        try {
          bytes.fill(0);
        } catch (_) {
          /* wipe */
        }
        return {
          type: "bytes",
          data: plain,
          meta: { sensitive: true },
        };
      }
      const packed = await aesGcmEncrypt(key, bytes, aad, tagLength);
      try {
        bytes.fill(0);
      } catch (_) {
        /* wipe */
      }
      return {
        type: "bytes",
        data: packed,
        meta: { sensitive: true },
      };
    }
    case "aes-cbc": {
      const bytes = valueToBytes(value);
      const key =
        (await resolveSlotKey(bindings, step.params?.key, "secret")) ||
        (await resolveBoundKey(bindings, "secret"));
      assertExpectedAesKeyBits(key, step.params?.expectedKeyBits, "aes-cbc");
      if (step.params.decode) {
        const plain = await aesCbcDecrypt(key, bytes);
        try {
          bytes.fill(0);
        } catch (_) {
          /* wipe */
        }
        return { type: "bytes", data: plain, meta: { sensitive: true } };
      }
      const packed = await aesCbcEncrypt(key, bytes);
      try {
        bytes.fill(0);
      } catch (_) {
        /* wipe */
      }
      return { type: "bytes", data: packed, meta: { sensitive: true } };
    }
    case "aes-ctr": {
      const bytes = valueToBytes(value);
      const key =
        (await resolveSlotKey(bindings, step.params?.key, "secret")) ||
        (await resolveBoundKey(bindings, "secret"));
      assertExpectedAesKeyBits(key, step.params?.expectedKeyBits, "aes-ctr");
      const ctrLength = Number(step.params.length) || 64;
      if (step.params.decode) {
        const plain = await aesCtrDecrypt(key, bytes, ctrLength);
        try {
          bytes.fill(0);
        } catch (_) {
          /* wipe */
        }
        return { type: "bytes", data: plain, meta: { sensitive: true } };
      }
      const packed = await aesCtrEncrypt(key, bytes, ctrLength);
      try {
        bytes.fill(0);
      } catch (_) {
        /* wipe */
      }
      return { type: "bytes", data: packed, meta: { sensitive: true } };
    }
    case "rsa-oaep": {
      const bytes = valueToBytes(value);
      const decrypt = !!step.params.decode;
      const need = decrypt ? "private" : "public";
      const key =
        (await resolveSlotKey(bindings, step.params?.key, need, "rsa-oaep")) ||
        (await resolveBoundKey(bindings, need));
      if (key.algorithm?.name !== "RSA-OAEP") {
        throw new Error(
          `rsa-oaep requires an RSA-OAEP key, got ${key.algorithm?.name || "unknown"}`
        );
      }
      const oaep = rsaOaepParams(step.params.label);
      if (decrypt) {
        const plain = new Uint8Array(
          await crypto.subtle.decrypt(oaep, key, bytes)
        );
        try {
          bytes.fill(0);
        } catch (_) {
          /* wipe */
        }
        return { type: "bytes", data: plain, meta: { sensitive: true } };
      }
      const ct = new Uint8Array(
        await crypto.subtle.encrypt(oaep, key, bytes)
      );
      try {
        bytes.fill(0);
      } catch (_) {
        /* wipe */
      }
      return { type: "bytes", data: ct, meta: { sensitive: true } };
    }
    case "rsa-pkcs1": {
      const bytes = valueToBytes(value);
      const decrypt = !!step.params.decode;
      const need = decrypt ? "private" : "public";
      const key =
        (await resolveSlotKey(bindings, step.params?.key, need)) ||
        (await resolveBoundKey(bindings, need));
      const algoName = key.algorithm?.name || "";
      if (!String(algoName).startsWith("RSA")) {
        throw new Error(
          `rsa-pkcs1 requires an RSA key, got ${algoName || "unknown"}`
        );
      }
      const jwk = await crypto.subtle.exportKey("jwk", key);
      let out;
      if (decrypt) {
        out = rsaesPkcs1Decrypt(jwk, bytes);
      } else {
        out = rsaesPkcs1Encrypt(jwk, bytes);
      }
      try {
        bytes.fill(0);
      } catch (_) {
        /* wipe */
      }
      return {
        type: "bytes",
        data: out,
        meta: {
          sensitive: true,
          alg: "rsaes-pkcs1-v1_5",
          tags: [...LEGACY_CRYPTO_TAGS, "rsaes-pkcs1-v1_5"],
        },
      };
    }
    case "hkdf": {
      const ikm = valueToBytes(value);
      const length = Number(step.params.length) || 32;
      const as = String(step.params.as || "bytes");
      const hash = String(step.params.hash || "sha-256")
        .toUpperCase()
        .replace("SHA-", "SHA-");
      const hashName =
        hash === "SHA-384" ? "SHA-384" : hash === "SHA-512" ? "SHA-512" : "SHA-256";
      const saltStr = String(step.params.salt || "");
      const infoStr = String(step.params.info || "");
      const out = await hkdfDerive(ikm, {
        length,
        as,
        hash: hashName,
        salt: saltStr ? textToBytes(saltStr) : new Uint8Array(),
        info: infoStr ? textToBytes(infoStr) : new Uint8Array(),
      });
      if (out && typeof out === "object" && out.type === "keypair") return out;
      return {
        type: "bytes",
        data: out,
        meta: { sensitive: true, kind: "master", length },
      };
    }
    case "pbkdf2": {
      const password = valueToBytes(value);
      const length = Number(step.params.length) || 32;
      const as = String(step.params.as || "bytes");
      const iterations = Number(step.params.iterations) || 100000;
      const hash = String(step.params.hash || "sha-256")
        .toUpperCase()
        .replace("SHA-", "SHA-");
      const hashName =
        hash === "SHA-384" ? "SHA-384" : hash === "SHA-512" ? "SHA-512" : "SHA-256";
      const salt = textToBytes(String(step.params.salt || "basilisk"));
      const out = await pbkdf2Derive(password, {
        salt,
        iterations,
        length,
        as,
        hash: hashName,
      });
      if (out && typeof out === "object" && out.type === "keypair") return out;
      return {
        type: "bytes",
        data: out,
        meta: { sensitive: true, kind: "master", length },
      };
    }
    case "ecdh": {
      const privateKey =
        (await resolveSlotKey(bindings, step.params?.private, "private")) ||
        (await resolveBoundKey(bindings, "private"));
      let peerPublic = null;
      if (step.params?.peer) {
        peerPublic = await resolveSlotKey(bindings, step.params.peer, "public");
      }
      if (!peerPublic) {
        const peerText = String(bindings.inputs?.key?.peerJwkText || "").trim();
        if (!peerText) {
          throw new Error(
            "ecdh needs peer=@slot or peer public JWK in the peer key field"
          );
        }
        const peer = await importBoundJwk({ jwkText: peerText, alg: "ecdh" });
        if (!peer.publicKey) {
          throw new Error("Peer JWK must include public key material");
        }
        peerPublic = peer.publicKey;
      }
      const out = await ecdhDerive(privateKey, peerPublic, {
        bits: Number(step.params.bits) || 0,
        as: String(step.params.as || "bytes"),
      });
      if (out && typeof out === "object" && out.type === "keypair") return out;
      return {
        type: "bytes",
        data: out,
        meta: { sensitive: true, kind: "opaque", length: out.length },
      };
    }
    case "wrap": {
      const mode = String(step.params?.mode || "aes-kw").toLowerCase();
      let keyObj = null;
      if (step.params?.target) {
        keyObj = await resolveSlotKey(bindings, step.params.target, "secret");
      }
      if (!keyObj) {
        const wrapText = String(bindings.inputs?.key?.wrapJwkText || "").trim();
        if (!wrapText) {
          throw new Error(
            "wrap needs target=@slot or key-to-wrap JWK in the wrap panel"
          );
        }
        const toWrap = await importBoundJwk({ jwkText: wrapText });
        keyObj = toWrap.secretKey || toWrap.privateKey;
        if (!keyObj) throw new Error("wrap key-to-wrap must be an oct JWK");
      }
      const extractable = await extractableWrapTarget(keyObj);
      if (mode === "rsa-oaep") {
        const wrappingKey =
          (await resolveSlotKey(bindings, step.params?.key, "public", "rsa-oaep")) ||
          (await resolveBoundKey(bindings, "public"));
        const wrapped = await rsaOaepWrap(
          wrappingKey,
          extractable,
          step.params.label
        );
        return { type: "bytes", data: wrapped, meta: { sensitive: true, mode } };
      }
      const wrappingKey =
        (await resolveSlotKey(bindings, step.params?.key, "secret")) ||
        (await resolveBoundKey(bindings, "secret"));
      if (mode === "aes-gcm" || mode === "aes-cbc" || mode === "aes-ctr") {
        const packed = await aesContentWrap(mode, wrappingKey, extractable, {
          tagLength: Number(step.params.tagLength) || 128,
          length: Number(step.params.length) || 64,
        });
        return { type: "bytes", data: packed, meta: { sensitive: true, mode } };
      }
      const kw = await ensureAesWrapKey(wrappingKey, "AES-KW");
      const wrapped = await aesKwWrap(kw, extractable);
      return {
        type: "bytes",
        data: wrapped,
        meta: { sensitive: true, mode: "aes-kw" },
      };
    }
    case "unwrap": {
      const wrapped = valueToBytes(value);
      const mode = String(step.params?.mode || "aes-kw").toLowerCase();
      const alg = String(step.params.alg || "aes/256");
      const { importAlg, usages, metaAlg } = unwrapImportParams(alg);
      let unwrapped;
      if (mode === "rsa-oaep") {
        const wrappingKey =
          (await resolveSlotKey(bindings, step.params?.key, "private", "rsa-oaep")) ||
          (await resolveBoundKey(bindings, "private"));
        unwrapped = await rsaOaepUnwrap(
          wrappingKey,
          wrapped,
          importAlg,
          usages,
          step.params.label
        );
      } else if (mode === "aes-gcm" || mode === "aes-cbc" || mode === "aes-ctr") {
        const wrappingKey =
          (await resolveSlotKey(bindings, step.params?.key, "secret")) ||
          (await resolveBoundKey(bindings, "secret"));
        unwrapped = await aesContentUnwrap(
          mode,
          wrappingKey,
          wrapped,
          importAlg,
          usages,
          {
            tagLength: Number(step.params.tagLength) || 128,
            length: Number(step.params.length) || 64,
          }
        );
      } else {
        const wrappingKey =
          (await resolveSlotKey(bindings, step.params?.key, "secret")) ||
          (await resolveBoundKey(bindings, "secret"));
        const kw = await ensureAesWrapKey(wrappingKey, "AES-KW");
        unwrapped = await aesKwUnwrap(kw, wrapped, importAlg, usages);
      }
      const raw = new Uint8Array(await crypto.subtle.exportKey("raw", unwrapped));
      return {
        type: "bytes",
        data: raw,
        meta: {
          sensitive: true,
          kind: "opaque",
          alg: metaAlg,
          mode,
          length: raw.length,
        },
      };
    }
    case "sss.split": {
      let bytes;
      if (value?.type === "bytes") bytes = value.data;
      else if (value?.type === "text") bytes = textToBytes(value.data);
      else throw new Error("sss expects bytes or text");
      const pipeKind = value?.meta?.type?.kind;
      if (
        pipeKind &&
        pipeKind !== "master" &&
        pipeKind !== "scalar"
      ) {
        throw new Error(
          `sss expects bytes/master or bytes/scalar (got ${pipeKind}). ` +
            `For EC keys use "export scalar"; for PEM/arbitrary data use "gpg.symencrypt" first.`
        );
      }
      const result = await splitRawShares(bytes, {
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
    case "blip39": {
      if (!value || value.type !== "shares") throw new Error("blip39 expects shares");
      const decode = !!step.params.decode;
      if (decode) {
        const mnemonics = value.data.mnemonics || [];
        if (!mnemonics.length) {
          throw new Error("blip39 -d expects mnemonic shares");
        }
        const rawSet = decodeShareSet(mnemonics);
        return {
          type: "shares",
          data: {
            ...rawSet,
            envelope: value.data.envelope || null,
          },
          meta: {
            sensitive: true,
            envelope: value.meta?.envelope || value.data.envelope || null,
            passphrase: value.meta?.passphrase || "",
          },
        };
      }
      const raw = value.data.raw || [];
      if (!raw.length) {
        throw new Error("blip39 encode expects raw SSS shares (from sss)");
      }
      const encoded = encodeShareSet({
        raw,
        threshold: Number(value.data.threshold) || 0,
        shares: Number(value.data.shares) || raw.length,
        flags: Number(value.data.flags) || 0,
      });
      return {
        type: "shares",
        data: encoded,
        meta: { sensitive: true },
      };
    }
    case "sss.combine": {
      if (!value || value.type !== "shares") {
        throw new Error("sss.combine expects shares");
      }
      if (value.data.mnemonics?.length && !value.data.raw?.length) {
        throw new Error(
          'sss.combine expects raw SSS shares — add "blip39 -d" before sss.combine'
        );
      }
      const passphrase =
        String(step.params.passphrase || "") ||
        String(value.meta?.passphrase || "") ||
        "";
      const envelope = value.data.envelope || value.meta?.envelope || null;
      let secret;
      try {
        secret = await combineRawShares(value.data, {
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
    case "gpg.symencrypt": {
      if (!value || (value.type !== "text" && value.type !== "bytes")) {
        throw new Error("gpg.symencrypt expects text or bytes");
      }
      /** @type {{ kind: "text", text: string } | { kind: "file", bytes: Uint8Array, filename: string }} */
      let payload;
      if (value.type === "text") {
        payload = { kind: "text", text: String(value.data) };
      } else {
        // Copy — encryptArtifacts zeros file payload buffers after encrypt.
        payload = {
          kind: "file",
          bytes: new Uint8Array(value.data),
          filename: "payload.bin",
        };
      }
      const master = crypto.getRandomValues(new Uint8Array(32));
      const hexPass = bytesToHex(master);
      const arts = await encryptArtifacts({
        recipients: [],
        passwords: [hexPass],
        payloads: [payload],
        profile: bindings.encryption?.profile || PROFILE_AUTO,
        hideRecipients: false,
      });
      if (!arts.length) throw new Error("gpg.symencrypt produced no ciphertext");
      const armored = arts[0].armored;
      const cryptoSummary = await summarizeEncryption(armored);
      const stem = safeOutputStem(step.params.name || "envelope");
      artifacts.push({
        label: "OpenPGP envelope — required for recovery (not a share)",
        filename: `${stem}.asc`,
        content: armored,
        sensitive: false,
        mime: "application/pgp-encrypted",
        cryptoSummary,
        disposition: "file",
        role: "envelope",
        tags: ["openpgp", "skesk"],
      });
      return {
        type: "bytes",
        data: master,
        meta: { ...value.meta, sensitive: true, openPgpEnvelope: true },
      };
    }
    case "gpg.symdecrypt": {
      if (!value || value.type !== "bytes") {
        throw new Error("gpg.symdecrypt expects master bytes from recover");
      }
      const master = value.data;
      if (!(master instanceof Uint8Array) || (master.length !== 16 && master.length !== 32)) {
        throw new Error(
          `gpg.symdecrypt expects a 16- or 32-byte master (got ${master?.length ?? 0})`
        );
      }
      const armored = resolveEnvelopeArmored(bindings);
      if (!armored) {
        throw new Error(
          "No OpenPGP envelope.asc bound — paste the armored envelope before running."
        );
      }
      const hexPass = bytesToHex(master);
      const message = await readMessage({ armoredMessage: armored });
      const { data } = await openpgpDecrypt({
        message,
        passwords: [hexPass],
        format: "binary",
      });
      const plain =
        data instanceof Uint8Array
          ? data
          : data instanceof ArrayBuffer
            ? new Uint8Array(data)
            : textToBytes(String(data));
      return {
        type: "bytes",
        data: plain,
        meta: { sensitive: true },
      };
    }
    case "gpg.sign": {
      if (!value || (value.type !== "text" && value.type !== "bytes")) {
        throw new Error("gpg.sign expects text or bytes");
      }
      const format =
        String(step.params?.format || "cleartext").toLowerCase() === "detached"
          ? "detached"
          : "cleartext";
      const privateKey = await resolveGpgPrivateKey(bindings, step.params?.key);
      const data =
        value.type === "text"
          ? String(value.data)
          : value.data instanceof Uint8Array
            ? value.data
            : textToBytes(String(value.data));
      if (format === "cleartext" && typeof data !== "string") {
        throw new Error("gpg.sign format=cleartext expects text (use utf8 first, or format=detached)");
      }
      const { armored } = await signOpenPgp(data, [privateKey], format);
      return {
        type: "text",
        data: armored,
        meta: {
          ...value.meta,
          sensitive: false,
          openPgpSigned: true,
          detached: format === "detached",
        },
      };
    }
    case "gpg.verify": {
      if (!value || value.type !== "text") {
        throw new Error(
          "gpg.verify expects text (cleartext signed message or original for detached)"
        );
      }
      const soft = !!step.params?.soft;
      const detached = await resolveGpgDetachedSignature(
        bindings,
        step.params?.signature
      );
      const keys = await resolveGpgVerificationKeys(bindings, step.params?.key);
      try {
        const ok = await verifyOpenPgp(String(value.data), keys, detached);
        if (!ok) {
          if (soft) {
            return { type: "text", data: "invalid", meta: { sensitive: false } };
          }
          throw new Error("gpg.verify: signature invalid");
        }
        return { type: "text", data: "verified", meta: { sensitive: false } };
      } catch (err) {
        if (soft) {
          const msg = err instanceof Error ? err.message : String(err);
          if (/invalid|verification|signature/i.test(msg)) {
            return { type: "text", data: "invalid", meta: { sensitive: false } };
          }
        }
        throw err;
      }
    }
    case "gpg.inspect": {
      if (!value || value.type !== "text") {
        throw new Error("gpg.inspect expects armored OpenPGP text");
      }
      const armored = String(value.data);
      const analysis = await analyzeArmored(armored);
      const format = String(step.params.format || "summary").toLowerCase();
      if (format === "json") {
        return {
          type: "text",
          data: JSON.stringify(
            {
              type: analysis.type,
              recipientKeyIDs: analysis.recipientKeyIDs,
              sigDetails: (analysis.sigDetails || []).map((s) => ({
                keyId: s.keyId,
                fingerprint: s.fingerprint,
                created:
                  s.created instanceof Date && !Number.isNaN(s.created.getTime())
                    ? s.created.toISOString()
                    : null,
              })),
              hasSkesk: analysis.hasSkesk,
              hasPkesk: analysis.hasPkesk,
            },
            null,
            2
          ),
          meta: { ...value.meta, sensitive: false, openPgpInspect: true },
        };
      }
      /** @type {string[]} */
      const parts = [formatAnalysisSummary(analysis)];
      if (format === "packets") {
        try {
          const binary = dearmorToBytes(analysis.armored || armored);
          const spans = mapPacketSpans(binary);
          const packets =
            analysis.message &&
            analysis.type !== "cleartext" &&
            analysis.type !== "detached"
              ? analysis.message.packets
              : analysis.message?.packets ||
                analysis.message?.signature?.packets ||
                null;
          const enriched = enrichSpansWithPackets(spans, packets);
          parts.push("", "packets:");
          for (const s of enriched) {
            parts.push(`- ${s.name} @ ${s.headerStart}–${s.end}`);
            for (const line of s.detail?.lines || []) {
              parts.push(`    ${line}`);
            }
            for (const w of s.detail?.warnings || []) {
              parts.push(`    ! ${w}`);
            }
          }
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err);
          parts.push("", `packets: (unavailable — ${msg})`);
        }
      }
      return {
        type: "text",
        data: parts.join("\n"),
        meta: { ...value.meta, sensitive: false, openPgpInspect: true },
      };
    }
    case "gpg.encrypt": {
      if (!value || (value.type !== "text" && value.type !== "bytes")) {
        throw new Error("gpg.encrypt expects text");
      }
      const text =
        value.type === "text" ? String(value.data) : bytesToBase64(value.data);
      const mode = String(step.params?.mode || "separate").toLowerCase();
      const policy = String(step.params?.policy || "ask").toLowerCase();
      const resolved = await resolveEncryptRecipients(
        bindings,
        step.params?.to,
        policy
      );
      let keys = resolved.keys;
      let fps = resolved.fingerprints;
      if (!keys.length) {
        throw new Error(
          "GPG recipients not bound — set to=@slot / look up to=email, or choose binder recipients."
        );
      }
      // Foreach + binder: one recipient per share index (legacy SSS fan-out).
      if (
        value.meta?.shareIndex &&
        !String(step.params?.to || "").trim() &&
        keys.length > 1
      ) {
        const idx = value.meta.shareIndex - 1;
        const i = Math.min(idx, keys.length - 1);
        keys = [keys[i]];
        fps = [fps[i] || ""];
      }
      const wantSign = !!step.params.sign;
      /** @type {import("openpgp").PrivateKey|null} */
      let signingKey = null;
      try {
        if (wantSign) {
          signingKey = await resolveGpgPrivateKey(bindings, step.params?.key);
        }
        /** @type {{ keys: import("openpgp").Key[], fpr: string }[]} */
        const batches =
          mode === "combined"
            ? [{ keys, fpr: fps[0] || "" }]
            : keys.map((k, i) => ({ keys: [k], fpr: fps[i] || "" }));
        for (let bi = 0; bi < batches.length; bi++) {
          const batch = batches[bi];
          const arts = await encryptArtifacts({
            recipients: batch.keys,
            passwords: [],
            payloads: [{ kind: "text", text }],
            profile: bindings.encryption?.profile || PROFILE_AUTO,
            hideRecipients: !!bindings.encryption?.hideRecipients,
            signingKeys: signingKey ? [signingKey] : undefined,
          });
          for (const a of arts) {
            const cryptoSummary = await summarizeEncryption(a.armored);
            const isShare = !!value.meta?.shareIndex;
            const short =
              batch.fpr && batch.fpr.length >= 8
                ? batch.fpr.slice(-8).toLowerCase()
                : String(bi + 1);
            const multi = mode !== "combined" && batches.length > 1;
            artifacts.push({
              label: isShare
                ? `Share ${value.meta.shareIndex} (GPG)`
                : multi
                  ? `GPG ciphertext (${short})`
                  : a.label || "GPG ciphertext",
              filename: isShare
                ? `share-${value.meta.shareIndex}.asc`
                : multi
                  ? `encrypted-${short}.asc`
                  : a.filename || "encrypted.asc",
              content: a.armored,
              sensitive: false,
              shareIndex: value.meta?.shareIndex,
              recipientFingerprint: batch.fpr,
              mime: "application/pgp-encrypted",
              cryptoSummary,
              disposition: "file",
              role: isShare ? "share" : "ciphertext",
              tags: isShare
                ? ["encrypted", "openpgp", "blip39"]
                : wantSign
                  ? ["encrypted", "openpgp", "signed"]
                  : ["encrypted", "openpgp"],
              traits: isShare
                ? {
                    shareOf: value.meta.shareIndex,
                    threshold: value.meta.threshold,
                  }
                : undefined,
            });
          }
        }
        return { type: "artifact", data: null, meta: value.meta };
      } finally {
        zeroKeyMaterial(signingKey);
      }
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
        disposition: "file",
        role: "qr",
        tags: value.meta?.shareIndex ? ["share", "qr"] : ["qr"],
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
        a.disposition = "file";
        if (!a.role) {
          if (a.shareIndex) {
            a.role = "share";
            a.tags = a.tags || ["mnemonic", "blip39"];
            a.traits = a.traits || {
              shareOf: a.shareIndex,
              threshold: value.meta?.threshold,
            };
          } else if (value.meta?.sensitive) {
            a.role = "secret";
          } else {
            a.role = "text";
          }
        }
        artifacts.push(a);
      }
      // Pass through so the recipe can continue (e.g. out | gpg.encrypt).
      return value;
    }
    case "text": {
      // Print as a message tile (not a named downloadable file — use `out` for that).
      if (!value) throw new Error("text expects a value");
      const label = String(step.params.label || step.params.name || "text").trim() || "text";
      const stem = safeOutputStem(label);
      let content;
      if (value.type === "text") {
        content = String(value.data);
      } else if (value.type === "bytes") {
        content = bytesToText(value.data);
      } else {
        throw new Error("text expects text or bytes (use inspect for other types)");
      }
      artifacts.push({
        label: value.meta?.shareIndex
          ? `${label} (share ${value.meta.shareIndex})`
          : label,
        filename: `${stem}.txt`,
        content,
        sensitive: !!value.meta?.sensitive,
        shareIndex: value.meta?.shareIndex,
        mime: "text/plain; charset=utf-8",
        encoding: "text",
        disposition: "message",
        role: "text",
        tags: value.meta?.sensitive ? ["sensitive"] : [],
      });
      return value;
    }
    case "inspect": {
      if (!value) throw new Error("inspect expects a value");
      const format = String(step.params.format || "auto");
      const snapshot = await buildInspectSnapshot(value);
      const dump = inspectFromSnapshot(snapshot, format);
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
          inspectSnapshot: snapshot,
          inspectFormat: format,
        },
      };
    }
    case "tee": {
      throw new Error(
        "tee requires a body — use `{ - .public | … }` or indented `-` lines (use `peek` for a side inspect)"
      );
    }
    case "peek": {
      if (!value) throw new Error("peek expects a value");
      const name =
        String(step.params.name || "peek")
          .replace(/[^\w.-]+/g, "_")
          .slice(0, 64) || "peek";
      const format = String(step.params.format || "auto");
      const snapshot = await buildInspectSnapshot(value);
      const dump = inspectFromSnapshot(snapshot, format);
      artifacts.push({
        label: `peek:${name}`,
        filename: `${name}.inspect.txt`,
        content: dump,
        sensitive:
          !!value.meta?.sensitive ||
          value.type === "keypair" ||
          value.type === "shares",
        disposition: "file",
        role: "inspect",
        tags: ["inspect"],
        inspectSnapshot: snapshot || undefined,
        inspectFormat: format,
      });
      return value;
    }
    case "as": {
      if (!value || value.type !== "bytes") {
        throw new Error("as expects bytes");
      }
      const kind = String(step.params.type || "opaque").toLowerCase();
      const data = value.data;
      const len = data instanceof Uint8Array ? data.length : undefined;
      if (kind === "master") {
        if (len !== 16 && len !== 32) {
          throw new Error(`as master requires 16 or 32 bytes, got ${len ?? "?"}B`);
        }
        return {
          type: "bytes",
          data,
          meta: {
            ...value.meta,
            kind: "master",
            length: len,
            sensitive: true,
          },
        };
      }
      if (kind === "scalar") {
        return {
          type: "bytes",
          data,
          meta: {
            ...value.meta,
            kind: "scalar",
            length: len,
            sensitive: true,
          },
        };
      }
      if (kind === "opaque") {
        return {
          type: "bytes",
          data,
          meta: {
            ...value.meta,
            kind: "opaque",
            length: len,
            sensitive: !!value.meta?.sensitive,
          },
        };
      }
      throw new Error(`as type must be master, scalar, or opaque — got "${kind}"`);
    }
    case "select": {
      if (!value) throw new Error("select expects a value");
      return projectSelector(value, String(step.params.selector || ""));
    }
    case "at": {
      if (!value || value.type !== "shares") {
        throw new Error("at expects shares");
      }
      const sel = String(step.params.selector || "1").trim();
      const range = sel.match(/^(\d+):(\d+)$/);
      const single = sel.match(/^(\d+)$/);
      const d = value.data || {};
      const rawItems = Array.isArray(d.raw) ? d.raw : [];
      const mnemonics = Array.isArray(d.mnemonics) ? d.mnemonics : [];
      const useRaw = rawItems.length > 0;
      const count = useRaw ? rawItems.length : mnemonics.length;
      if (!count) throw new Error("at: empty share set");

      if (range) {
        const a = Number(range[1]);
        const b = Number(range[2]);
        if (a < 1 || b < a || b > count) {
          throw new Error(`at ${sel}: out of range (1–${count})`);
        }
        if (useRaw) {
          const sliced = rawItems.slice(a - 1, b).map((s, i) => ({
            index: s.index || a + i,
            data: new Uint8Array(s.data),
          }));
          return {
            type: "shares",
            data: {
              ...d,
              raw: sliced,
              mnemonics: undefined,
              shares: sliced.length,
            },
            meta: { ...value.meta, sensitive: true },
          };
        }
        const sliced = mnemonics.slice(a - 1, b).map(String);
        return {
          type: "shares",
          data: {
            ...d,
            mnemonics: sliced,
            raw: undefined,
            shares: sliced.length,
          },
          meta: { ...value.meta, sensitive: true },
        };
      }

      if (!single) throw new Error(`at: invalid selector "${sel}"`);
      const n = Number(single[1]);
      if (n < 1 || n > count) {
        throw new Error(`at ${n}: out of range (1–${count})`);
      }
      if (useRaw) {
        const share = rawItems[n - 1];
        return {
          type: "bytes",
          data: new Uint8Array(share.data),
          meta: {
            sensitive: true,
            shareIndex: share.index || n,
            shareCount: count,
            threshold: d.threshold,
          },
        };
      }
      return {
        type: "text",
        data: String(mnemonics[n - 1]),
        meta: {
          sensitive: true,
          shareIndex: n,
          shareCount: count,
          threshold: d.threshold,
          kind: "mnemonic",
        },
      };
    }
    case "webauthn.caps":
    case "webauthn.create":
    case "webauthn.get":
    case "webauthn.prf":
    case "webauthn.attest":
    case "webauthn.mds": {
      // Lazy: keep vault/MDS out of the worker bundle unless these steps run.
      const wa = await import("./webauthn-ops.js");
      if (step.name === "webauthn.caps") return wa.execWaCaps();
      if (step.name === "webauthn.create") return wa.execWaCreate(step.params || {});
      if (step.name === "webauthn.get") return wa.execWaGet();
      if (step.name === "webauthn.prf") return wa.execWaPrf();
      if (step.name === "webauthn.attest") return wa.execWaAttest(value);
      return wa.execWaMds(value, step.params || {});
    }
    case "agent.unlock":
    case "agent.pub":
    case "agent.list":
    case "agent.save": {
      const agent = await import("./agent-ops.js");
      if (step.name === "agent.unlock") {
        return agent.execAgentUnlock(step.params || {}, bindings);
      }
      if (step.name === "agent.pub") return agent.execAgentPub(step.params || {});
      if (step.name === "agent.list") return agent.execAgentList();
      return agent.execAgentSave(value, step.params || {}, bindings);
    }
    case "hkp.get":
    case "hkp.search":
    case "hkp.filter":
    case "hkp.cache": {
      const hkp = await import("./hkp-ops.js");
      if (step.name === "hkp.get") return hkp.execHkpGet(step.params || {});
      if (step.name === "hkp.search") return hkp.execHkpSearch(step.params || {});
      if (step.name === "hkp.cache") return hkp.execHkpCache(step.params || {});
      return hkp.execHkpFilter(value, step.params || {});
    }
    case "recipients.merge": {
      const {
        mergeRecipients,
        pipelineValueToRecipients,
        recipientsPipelineValue,
      } = await import("./recipients-ops.js");
      const primary = pipelineValueToRecipients(value);
      let secondary = [];
      const withRef = String(step.params?.with || "").trim();
      if (withRef) {
        const resolve = bindings?.resolveSlot;
        if (typeof resolve !== "function") {
          throw new Error("recipients.merge with=: runtime slot resolver missing");
        }
        const other = resolve(withRef);
        if (!other) throw new Error(`recipients.merge with=${withRef}: unknown slot`);
        secondary = pipelineValueToRecipients(other);
      }
      return recipientsPipelineValue(mergeRecipients(primary, secondary), {
        ...(value?.meta || {}),
        merged: true,
      });
    }
    default:
      throw new Error(`Unsupported step: ${step.name}`);
  }
}

/**
 * Resolve OpenPGP envelope.asc from runtime bindings.
 * @param {RuntimeBindings} bindings
 * @returns {string}
 */
function resolveEnvelopeArmored(bindings) {
  const candidates = [
    bindings.inputs?.envelope?.armored,
    bindings.inputs?.shares?.envelopeArmored,
    bindings.inputs?.gpg?.envelopeArmored,
  ];
  for (const c of candidates) {
    const t = String(c || "").trim();
    if (t) return t;
  }
  return "";
}

/**
 * True when text looks like an OpenPGP armored message (not a bare mnemonic).
 * @param {string} text
 */
function looksLikePgpMessage(text) {
  return /-----BEGIN PGP MESSAGE-----/i.test(String(text || ""));
}

/**
 * Normalize and accept a BLIP39 mnemonic if the checksum validates.
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
 * @param {CryptoKey} key
 * @param {unknown} expectedBits
 * @param {string} op
 */
function assertExpectedAesKeyBits(key, expectedBits, op) {
  const want = Number(expectedBits);
  if (!want) return;
  const len = key?.algorithm?.length;
  if (len != null && len !== want) {
    throw new Error(
      `${op}: key is ${len}-bit but recipe requested ${want}-bit (e.g. aes-${want}-gcm)`
    );
  }
}

/**
 * @param {RuntimeBindings} bindings
 * @param {string|undefined|null} [keyRef]  `key=@slot` armored private
 * @returns {Promise<import("openpgp").PrivateKey>}
 */
async function resolveGpgPrivateKey(bindings, keyRef) {
  const ref = String(keyRef || "").trim();
  if (ref) {
    const armored = resolveGpgArmoredFromSlot(bindings, ref, "gpg private key");
    let privateKey = await readPrivateKey({ armoredKey: armored });
    if (!privateKey.isDecrypted()) {
      privateKey = await decryptKey({
        privateKey,
        passphrase: bindings.inputs?.gpg?.passphrase || "",
      });
    }
    return privateKey;
  }
  const gpg = bindings.inputs?.gpg;
  if (!gpg?.privateKeyArmored) {
    throw new Error(
      "OpenPGP private key required (vault / key panel / key=@slot) — used by gpg.sign and gpg.encrypt -s"
    );
  }
  let privateKey = await readPrivateKey({ armoredKey: gpg.privateKeyArmored });
  if (!privateKey.isDecrypted()) {
    privateKey = await decryptKey({
      privateKey,
      passphrase: gpg.passphrase || "",
    });
  }
  return privateKey;
}

/**
 * @param {RuntimeBindings} bindings
 * @param {string} ref
 * @param {string} label
 * @returns {string}
 */
function resolveGpgArmoredFromSlot(bindings, ref, label) {
  const resolve = bindings?.resolveSlot;
  if (typeof resolve !== "function") {
    throw new Error(`${label} ${ref}: runtime slot resolver missing`);
  }
  const value = resolve(ref);
  if (!value) throw new Error(`${label} ${ref}: unknown slot`);
  if (value.type === "openpgp-key") return String(value.data);
  if (value.type === "text") return String(value.data);
  if (value.type === "bytes") return bytesToText(value.data);
  if (value.type === "recipients") {
    const first = Array.isArray(value.data) ? value.data[0] : null;
    const armored = String(first?.armoredPublic || "");
    if (armored.includes("BEGIN PGP")) return armored;
  }
  throw new Error(
    `${label} ${ref}: slot must be openpgp-key, recipients, text, or bytes`
  );
}

/**
 * Resolve OpenPGP public keys for gpg.encrypt from to= / binder.
 * @param {RuntimeBindings} bindings
 * @param {string|undefined|null} toParam
 * @param {string} [policy]
 * @returns {Promise<{ keys: import("openpgp").Key[], fingerprints: string[] }>}
 */
async function resolveEncryptRecipients(bindings, toParam, policy = "ask") {
  const {
    parseEncryptToToken,
    pipelineValueToRecipients,
    recipientResolutionKey,
  } = await import("./recipients-ops.js");
  const token = parseEncryptToToken(toParam);

  /** @type {import("./recipients-ops.js").ToolkitRecipient[]} */
  let list = [];

  if (token.kind === "empty") {
    const binderKeys = bindings.recipients || [];
    const fps = bindings.recipientFingerprints || [];
    if (!binderKeys.length) {
      return { keys: [], fingerprints: [] };
    }
    return {
      keys: binderKeys,
      fingerprints: fps.length
        ? fps
        : binderKeys.map((k) => {
            try {
              return k.getFingerprint().toUpperCase();
            } catch {
              return "";
            }
          }),
    };
  }

  if (token.kind === "slot") {
    const resolve = bindings?.resolveSlot;
    if (typeof resolve !== "function") {
      throw new Error(`gpg.encrypt to=${token.ref}: runtime slot resolver missing`);
    }
    const value = resolve(token.ref);
    if (!value) throw new Error(`gpg.encrypt to=${token.ref}: unknown slot`);
    list = pipelineValueToRecipients(value);
  } else if (token.kind === "fpr") {
    list = [{ fingerprint: token.fingerprint, armoredPublic: "", valid: true, encryptCapable: true }];
  } else if (token.kind === "email") {
    const key = recipientResolutionKey(token.query);
    const chosen = bindings.recipientResolutions?.[key] ||
      bindings.recipientResolutions?.[token.query] ||
      [];
    if (!chosen.length) {
      throw new Error(
        `gpg.encrypt to=${token.query}: look up recipients first (search glyph beside to=)`
      );
    }
    if (policy === "one" && chosen.length !== 1) {
      throw new Error(
        `gpg.encrypt policy=one expects exactly one key, got ${chosen.length}`
      );
    }
    list = chosen.map((fpr) => ({
      fingerprint: String(fpr).toUpperCase().replace(/[^0-9A-F]/g, ""),
      armoredPublic: "",
      valid: true,
      encryptCapable: true,
    }));
  }

  if (!list.length) {
    throw new Error("gpg.encrypt: empty recipients after resolve");
  }

  const { loadRecipientKey } = await import("../recipient-picker.js");
  /** @type {import("openpgp").Key[]} */
  const keys = [];
  /** @type {string[]} */
  const fingerprints = [];
  for (const r of list) {
    let armored = String(r.armoredPublic || "").trim();
    const fpr = String(r.fingerprint || "")
      .toUpperCase()
      .replace(/[^0-9A-F]/g, "");
    if (!armored.includes("BEGIN PGP")) {
      if (fpr.length < 40) {
        throw new Error("gpg.encrypt: recipient missing armor and fingerprint");
      }
      const loaded = await loadRecipientKey(fpr);
      armored = String(loaded?.armoredKey || "").trim();
      if (!armored.includes("BEGIN PGP")) {
        throw new Error(
          loaded?.error || `Could not load public key for ${fpr.slice(-8)}`
        );
      }
    }
    const key = await readKey({ armoredKey: armored });
    keys.push(key);
    fingerprints.push(fpr || key.getFingerprint().toUpperCase());
  }
  return { keys, fingerprints };
}

/**
 * @param {RuntimeBindings} bindings
 * @param {string|undefined|null} [keyRef]  `key=@slot` armored public or private
 * @returns {Promise<import("openpgp").Key[]>}
 */
async function resolveGpgVerificationKeys(bindings, keyRef) {
  const ref = String(keyRef || "").trim();
  if (ref) {
    const armored = resolveGpgArmoredFromSlot(bindings, ref, "gpg.verify key");
    try {
      const pub = await readKey({ armoredKey: armored });
      return [pub];
    } catch (_) {
      const priv = await resolveGpgPrivateKey(bindings, ref);
      return [priv.toPublic()];
    }
  }
  const gpg = bindings.inputs?.gpg;
  if (gpg?.privateKeyArmored) {
    const priv = await resolveGpgPrivateKey(bindings);
    return [priv.toPublic()];
  }
  if (gpg?.publicKeyArmored) {
    const pub = await readKey({ armoredKey: gpg.publicKeyArmored });
    return [pub];
  }
  const recipients = bindings.recipients || [];
  if (recipients.length) return recipients;
  throw new Error(
    "gpg.verify needs an OpenPGP public key (key=@slot, vault key panel, or recipients)"
  );
}

/**
 * @param {RuntimeBindings} bindings
 * @param {string|undefined|null} refOrText
 * @returns {Promise<string>}
 */
async function resolveGpgDetachedSignature(bindings, refOrText) {
  const raw = String(refOrText || "").trim();
  if (!raw) {
    return String(
      bindings.inputs?.key?.signatureB64url || bindings.inputs?.signature || ""
    ).trim();
  }
  if (raw.startsWith("@")) {
    const resolve = bindings?.resolveSlot;
    if (typeof resolve !== "function") {
      throw new Error(`gpg.verify signature=${raw}: runtime slot resolver missing`);
    }
    const value = resolve(raw);
    if (!value) throw new Error(`gpg.verify signature=${raw}: unknown slot`);
    if (value.type === "text") return String(value.data);
    if (value.type === "bytes") return bytesToText(value.data);
    throw new Error(`gpg.verify signature=${raw}: slot must be text or bytes`);
  }
  return raw;
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
      "A pasted block was neither an OpenPGP message nor a valid BLIP39 mnemonic"
    );
  }

  if (!ciphertexts.length && !mnemonics.length) {
    throw new Error(
      "Paste OpenPGP-encrypted shares and/or already-decrypted BLIP39 mnemonics (share rows)."
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
        encoding: "mnemonic",
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
 * Resolve verify signature= from @slot, base64url string, or panel binding.
 * @param {object} bindings
 * @param {string|undefined|null} refOrB64
 * @returns {Promise<Uint8Array>}
 */
async function resolveVerifySignature(bindings, refOrB64) {
  const raw = String(refOrB64 || "").trim();
  if (raw.startsWith("@")) {
    const resolve = bindings?.resolveSlot;
    if (typeof resolve !== "function") {
      throw new Error(`verify signature=${raw}: runtime slot resolver missing`);
    }
    const value = resolve(raw);
    if (!value) throw new Error(`verify signature=${raw}: unknown slot`);
    if (value.type === "bytes") return value.data;
    if (value.type === "text") {
      return base64ToBytes(String(value.data).replace(/\s+/g, ""));
    }
    throw new Error(
      `verify signature=${raw}: slot must be bytes or base64url text`
    );
  }
  const sigB64 =
    raw || String(bindings.inputs?.key?.signatureB64url || "").trim();
  if (!sigB64) {
    throw new Error("verify needs signature=… (base64url or @slot) or sig binding");
  }
  return base64ToBytes(sigB64);
}

/**
 * @param {string} alg
 * @param {string} usage
 * @param {string} [padding]
 * @param {string} [hash]
 * @returns {Promise<PipelineValue>}
 */
async function generateKeyValue(alg, usage, padding = "pss", hash = "sha-256") {
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
      meta: {
        alg,
        curve,
        algorithm: useDerive ? "ECDH" : "ECDSA",
        sensitive: true,
        type: typeOf("keypair", { alg, which: "private" }),
      },
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
      meta: {
        alg,
        algorithm: "Ed25519",
        sensitive: true,
        type: typeOf("keypair", { alg, which: "private" }),
      },
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
      meta: {
        alg,
        algorithm: "X25519",
        sensitive: true,
        type: typeOf("keypair", { alg, which: "private" }),
      },
    };
  }
  if (alg.startsWith("rsa/")) {
    const modulus = Number(alg.split("/")[1]) || 3072;
    const useEncrypt = usage === "encrypt";
    const usePkcs1 =
      !useEncrypt && String(padding || "pss").toLowerCase() === "pkcs1";
    const name = useEncrypt
      ? "RSA-OAEP"
      : usePkcs1
        ? "RSASSA-PKCS1-v1_5"
        : "RSA-PSS";
    const hashName = normalizeHashName(hash);
    const keyPair = await crypto.subtle.generateKey(
      {
        name,
        modulusLength: modulus,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: hashName,
      },
      true,
      useEncrypt
        ? ["encrypt", "decrypt", "wrapKey", "unwrapKey"]
        : ["sign", "verify"]
    );
    return {
      type: "keypair",
      data: keyPair,
      meta: {
        alg,
        algorithm: name,
        hash: hashName,
        sensitive: true,
        padding: useEncrypt ? undefined : usePkcs1 ? "pkcs1" : "pss",
        tags: usePkcs1
          ? [...LEGACY_CRYPTO_TAGS, "rsassa-pkcs1-v1_5"]
          : undefined,
      },
    };
  }
  if (alg.startsWith("aes/")) {
    const length = aesLengthFromAlg(alg);
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
    const hmacHash = hmacHashFromAlg(alg);
    const key = await crypto.subtle.generateKey(
      { name: "HMAC", hash: hmacHash, length: hmacLengthBits(hmacHash) },
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
  const fmt = String(format || "pkcs8").toLowerCase();

  if (fmt === "scalar" || fmt === "d") {
    if (!priv) throw new Error("scalar export requires a private key");
    const jwk = await crypto.subtle.exportKey("jwk", priv);
    if (!jwk.d) {
      throw new Error(
        `scalar export unavailable for ${meta?.algorithm || "this key"} (no JWK.d)`
      );
    }
    const bytes = jwkFieldToBytes(jwk.d);
    return {
      type: "bytes",
      data: bytes,
      meta: {
        ...meta,
        format: "scalar",
        which: "private",
        sensitive: true,
      },
    };
  }

  if (fmt === "jwk") {
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

  if (fmt === "raw") {
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

  if (fmt === "spki" || which === "public") {
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
 * @param {string} [padding]
 * @param {string} [hash]
 */
async function importKey(value, format, alg, usage, padding = "pss", hash = "sha-256") {
  const useDerive = usage === "derive";
  const useEncrypt = usage === "encrypt";
  const fmt = String(format || "pkcs8").toLowerCase();
  const usePkcs1Sign =
    !useEncrypt && String(padding || "pss").toLowerCase() === "pkcs1";
  const hashName = normalizeHashName(hash);

  if (fmt === "jwk") {
    if (!value || value.type !== "text") throw new Error("import jwk expects text");
    const hint =
      useEncrypt && String(alg).startsWith("rsa/")
        ? "rsa-oaep"
        : usePkcs1Sign && String(alg).startsWith("rsa/")
          ? "rsassa-pkcs1"
          : useDerive
            ? "ecdh"
            : alg;
    const bound = await importBoundJwk({
      jwkText: String(value.data),
      alg: hint,
      padding: usePkcs1Sign ? "pkcs1" : undefined,
    });
    const sensitive = !!(bound.privateKey || bound.secretKey);
    return {
      type: "keypair",
      data: {
        privateKey: bound.privateKey || bound.secretKey || null,
        publicKey: bound.publicKey || null,
        secretKey: bound.secretKey || null,
      },
      meta: {
        alg: bound.alg || alg,
        algorithm: bound.alg || alg,
        symmetric: !!bound.secretKey,
        sensitive,
      },
    };
  }

  if (!value || value.type !== "bytes") throw new Error("import expects bytes");
  const der = value.data;

  if (fmt === "scalar" || fmt === "d") {
    return importScalarKey(der, alg, usage);
  }

  if (alg.startsWith("ec/")) {
    const curve =
      alg === "ec/p384" ? "P-384" : alg === "ec/p521" ? "P-521" : "P-256";
    const name = useDerive ? "ECDH" : "ECDSA";
    const usages = useDerive
      ? /** @type {KeyUsage[]} */ (["deriveBits", "deriveKey"])
      : /** @type {KeyUsage[]} */ (["sign", "verify"]);
    if (fmt === "spki") {
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
      fmt === "raw" ? "raw" : "pkcs8",
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
    if (fmt === "spki") {
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
      fmt === "raw" ? "raw" : "pkcs8",
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
    if (fmt === "spki") {
      const publicKey = await crypto.subtle.importKey(
        "spki",
        der,
        "X25519",
        true,
        []
      );
      return {
        type: "keypair",
        data: { privateKey: null, publicKey },
        meta: { alg, algorithm: "X25519", sensitive: false },
      };
    }
    const privateKey = await crypto.subtle.importKey(
      fmt === "raw" ? "raw" : "pkcs8",
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
    const usePkcs1 =
      !useEncrypt && String(padding || "pss").toLowerCase() === "pkcs1";
    const name = useEncrypt
      ? "RSA-OAEP"
      : usePkcs1
        ? "RSASSA-PKCS1-v1_5"
        : "RSA-PSS";
    const legacyTags = usePkcs1
      ? [...LEGACY_CRYPTO_TAGS, "rsassa-pkcs1-v1_5"]
      : undefined;
    if (fmt === "spki") {
      const publicKey = await crypto.subtle.importKey(
        "spki",
        der,
        { name, hash: hashName },
        true,
        useEncrypt ? ["encrypt", "wrapKey"] : ["verify"]
      );
      return {
        type: "keypair",
        data: { privateKey: null, publicKey },
        meta: {
          alg,
          algorithm: name,
          hash: hashName,
          sensitive: false,
          padding: useEncrypt ? undefined : usePkcs1 ? "pkcs1" : "pss",
          tags: legacyTags,
        },
      };
    }
    const privateKey = await crypto.subtle.importKey(
      "pkcs8",
      der,
      { name, hash: hashName },
      true,
      useEncrypt ? ["decrypt", "unwrapKey"] : ["sign"]
    );
    return {
      type: "keypair",
      data: { privateKey, publicKey: null },
      meta: {
        alg,
        algorithm: name,
        hash: hashName,
        sensitive: true,
        padding: useEncrypt ? undefined : usePkcs1 ? "pkcs1" : "pss",
        tags: legacyTags,
      },
    };
  }

  if (alg.startsWith("aes/")) {
    const length = aesLengthFromAlg(alg);
    const key = await crypto.subtle.importKey(
      "raw",
      der,
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
    const hmacHash = hmacHashFromAlg(alg);
    const key = await crypto.subtle.importKey(
      "raw",
      der,
      { name: "HMAC", hash: hmacHash },
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
 * Reconstruct a keypair from a private scalar / seed (JWK.d bytes).
 * @param {Uint8Array} scalar
 * @param {string} alg
 * @param {string} usage
 * @returns {Promise<PipelineValue>}
 */
async function importScalarKey(scalar, alg, usage) {
  if (!(scalar instanceof Uint8Array) || !scalar.length) {
    throw new Error("import scalar expects non-empty bytes");
  }
  const useDerive = usage === "derive";

  if (alg.startsWith("ec/")) {
    const curve =
      alg === "ec/p384" ? "P-384" : alg === "ec/p521" ? "P-521" : "P-256";
    const expected = curve === "P-384" ? 48 : curve === "P-521" ? 66 : 32;
    if (scalar.length !== expected) {
      throw new Error(
        `EC ${curve} scalar must be ${expected} bytes (got ${scalar.length})`
      );
    }
    const name = useDerive ? "ECDH" : "ECDSA";
    const pkcs8 = pkcs8FromEcScalar(scalar, curve);
    const privateKey = await crypto.subtle.importKey(
      "pkcs8",
      pkcs8,
      { name, namedCurve: curve },
      true,
      useDerive ? ["deriveBits", "deriveKey"] : ["sign"]
    );
    // JWK export includes public coordinates — rebuild the public half.
    const jwk = await crypto.subtle.exportKey("jwk", privateKey);
    /** @type {JsonWebKey} */
    const pubJwk = {
      kty: jwk.kty,
      crv: jwk.crv,
      x: jwk.x,
      y: jwk.y,
      ext: true,
      key_ops: useDerive ? [] : ["verify"],
    };
    const publicKey = await crypto.subtle.importKey(
      "jwk",
      pubJwk,
      { name, namedCurve: curve },
      true,
      useDerive ? [] : ["verify"]
    );
    return {
      type: "keypair",
      data: { privateKey, publicKey },
      meta: { alg, curve, algorithm: name, sensitive: true, format: "scalar" },
    };
  }

  if (alg === "ed25519") {
    if (scalar.length !== 32) {
      throw new Error(`Ed25519 seed must be 32 bytes (got ${scalar.length})`);
    }
    const privateKey = await crypto.subtle.importKey(
      "raw",
      scalar,
      "Ed25519",
      true,
      ["sign"]
    );
    const jwk = await crypto.subtle.exportKey("jwk", privateKey);
    const publicKey = await crypto.subtle.importKey(
      "jwk",
      { kty: jwk.kty, crv: jwk.crv, x: jwk.x, ext: true, key_ops: ["verify"] },
      "Ed25519",
      true,
      ["verify"]
    );
    return {
      type: "keypair",
      data: { privateKey, publicKey },
      meta: { alg, algorithm: "Ed25519", sensitive: true, format: "scalar" },
    };
  }

  if (alg === "x25519") {
    if (scalar.length !== 32) {
      throw new Error(`X25519 seed must be 32 bytes (got ${scalar.length})`);
    }
    const privateKey = await crypto.subtle.importKey(
      "raw",
      scalar,
      "X25519",
      true,
      ["deriveBits", "deriveKey"]
    );
    const jwk = await crypto.subtle.exportKey("jwk", privateKey);
    const publicKey = await crypto.subtle.importKey(
      "jwk",
      { kty: jwk.kty, crv: jwk.crv, x: jwk.x, ext: true, key_ops: [] },
      "X25519",
      true,
      []
    );
    return {
      type: "keypair",
      data: { privateKey, publicKey },
      meta: { alg, algorithm: "X25519", sensitive: true, format: "scalar" },
    };
  }

  throw new Error(
    `import scalar supports ec/p256|p384|p521, ed25519, x25519 (got ${alg})`
  );
}

/**
 * @param {string} raw
 * @returns {string}
 */
function safeOutputStem(raw) {
  const s = String(raw || "output")
    .trim()
    .replace(/^@+/, "")
    .replace(/[^\w.-]+/g, "_")
    .replace(/^\.+/, "")
    .slice(0, 64);
  return s || "output";
}

/**
 * Stamp refined pipeline type (and raw bytes when available) onto an artifact.
 *
 * Keeping `artifact.bytes` is a memory-safety requirement for file sinks:
 * Encrypt transfers Uint8Array (transferable / wipeable). Do not remove this
 * and force Encrypt to decode `content` strings — immutable strings cannot be
 * zeroed (see `src/lib/memory-safety.js`).
 *
 * @param {ToolkitArtifact} artifact
 * @param {PipelineValue} [value]
 * @returns {ToolkitArtifact}
 */
function attachPipeMeta(artifact, value) {
  if (value?.meta?.type) {
    artifact.pipeType = value.meta.type;
  }
  const metaTags = Array.isArray(value?.meta?.tags) ? value.meta.tags : [];
  if (metaTags.length) {
    const prev = Array.isArray(artifact.tags) ? artifact.tags : [];
    const seen = new Set(prev.map(String));
    const merged = [...prev];
    for (const t of metaTags) {
      const s = String(t);
      if (!seen.has(s)) {
        seen.add(s);
        merged.push(s);
      }
    }
    artifact.tags = merged;
  }
  if (
    value?.type === "bytes" &&
    value.data instanceof Uint8Array &&
    (artifact.encoding === "base64" ||
      artifact.encoding === "base64url" ||
      artifact.encoding === "hex" ||
      artifact.mime === "application/octet-stream")
  ) {
    // Dedicated copy: Encrypt may transfer a further copy; pipeline value.data
    // can still be wiped by the engine without detaching this tile.
    artifact.bytes = new Uint8Array(value.data);
  }
  return artifact;
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
      attachPipeMeta(
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
          role: value.meta?.shareIndex ? "share" : value.meta?.sensitive ? "secret" : "text",
          tags: value.meta?.shareIndex ? ["mnemonic", "blip39"] : [],
          traits: value.meta?.shareIndex
            ? { shareOf: value.meta.shareIndex, threshold: value.meta.threshold }
            : undefined,
        },
        value
      ),
    ];
  }

  if (value.type === "openpgp-key") {
    const which = value.meta?.which === "public" ? "public" : "private";
    const content = String(value.data || "");
    return [
      attachPipeMeta(
        {
          label,
          filename: `${stem}${shareSuffix}.asc`,
          content,
          sensitive: which === "private" || !!value.meta?.sensitive,
          mime: "application/pgp-keys",
          encoding: "text",
          role: "key",
          tags: ["openpgp", which],
          traits: {
            which,
            fingerprint: value.meta?.fingerprint,
          },
        },
        value
      ),
    ];
  }

  if (value.type === "recipients") {
    const rows = Array.isArray(value.data) ? value.data : [];
    const content = JSON.stringify(
      rows.map((r) => ({
        fingerprint: r.fingerprint,
        label: r.label || "",
        email: r.email || "",
        approvalState: r.approvalState || "",
        encryptCapable: r.encryptCapable !== false,
      })),
      null,
      2
    );
    return [
      attachPipeMeta(
        {
          label,
          filename: `${stem}${shareSuffix}.json`,
          content,
          sensitive: false,
          mime: "application/json",
          encoding: "text",
          role: "text",
          tags: ["openpgp", "recipients"],
        },
        value
      ),
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
    const isScalar = value.meta?.format === "scalar";
    return [
      attachPipeMeta(
        {
          label,
          filename: `${stem}${shareSuffix}.${ext}`,
          content,
          sensitive: !!value.meta?.sensitive,
          mime,
          encoding: encodingUsed,
          shareIndex: value.meta?.shareIndex,
          role: value.meta?.sensitive ? "secret" : "text",
          tags: isScalar ? ["scalar"] : [],
        },
        value
      ),
    ];
  }

  if (value.type === "shares") {
    if (value.data.raw?.length) {
      return value.data.raw.map((s, i) => {
        const idx = s.index || i + 1;
        return attachPipeMeta(
          {
            label: `${label} · share ${idx}`,
            filename: `${stem}-${idx}.${extOverride || "bin.b64"}`,
            content: bytesToBase64(s.data),
            bytes: new Uint8Array(s.data),
            sensitive: true,
            mime: mimeOverride || "application/octet-stream",
            encoding: "base64",
            shareIndex: idx,
            role: "share",
            tags: ["sss", "raw"],
            traits: {
              shareOf: idx,
              threshold: value.data.threshold,
            },
          },
          value
        );
      });
    }
    return (value.data.mnemonics || []).map((m, i) =>
      attachPipeMeta(
        {
          label: `${label} · share ${i + 1}`,
          filename: `${stem}-${i + 1}.${extOverride || "txt"}`,
          content: String(m),
          sensitive: true,
          mime: mimeOverride || "text/plain; charset=utf-8",
          encoding: "text",
          shareIndex: i + 1,
          role: "share",
          tags: ["mnemonic", "blip39"],
          traits: {
            shareOf: i + 1,
            threshold: value.data.threshold,
          },
        },
        value
      )
    );
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
    const isInspect = !!value.meta?.inspect && value.meta?.inspectSnapshot;
    return [
      attachPipeMeta(
        {
          label: isInspect ? "inspect" : name,
          filename: isInspect ? "inspect.txt" : `${name}.txt`,
          content: String(value.data),
          sensitive: !!value.meta?.sensitive,
          mime: "text/plain; charset=utf-8",
          encoding: "text",
          // Bare pipeline text prints as a message (use `out` for a named file).
          disposition: isInspect ? "file" : "message",
          role: isInspect ? "inspect" : "text",
          tags: isInspect
            ? ["inspect"]
            : value.meta?.sensitive
              ? ["sensitive"]
              : [],
          inspectSnapshot: isInspect ? value.meta.inspectSnapshot : undefined,
          inspectFormat: isInspect
            ? String(value.meta.inspectFormat || "auto")
            : undefined,
        },
        value
      ),
    ];
  }
  if (value.type === "bytes") {
    return [
      attachPipeMeta(
        {
          label: name,
          filename: `${name}.bin.b64`,
          content: bytesToBase64(value.data),
          sensitive: !!value.meta?.sensitive,
          mime: "application/octet-stream",
          encoding: "base64",
          disposition: "file",
          role: value.meta?.sensitive ? "secret" : "text",
          tags: value.meta?.format === "scalar" ? ["scalar"] : [],
        },
        value
      ),
    ];
  }
  if (value.type === "shares") {
    if (value.data.raw?.length) {
      return value.data.raw.map((s, i) => {
        const idx = s.index || i + 1;
        return attachPipeMeta(
          {
            label: `Share ${idx}`,
            filename: `share-${idx}.bin.b64`,
            content: bytesToBase64(s.data),
            bytes: new Uint8Array(s.data),
            sensitive: true,
            shareIndex: idx,
            mime: "application/octet-stream",
            encoding: "base64",
            disposition: "file",
            role: "share",
            tags: ["sss", "raw"],
            traits: {
              shareOf: idx,
              threshold: value.data.threshold,
            },
          },
          value
        );
      });
    }
    return (value.data.mnemonics || []).map((m, i) =>
      attachPipeMeta(
        {
          label: `Share ${i + 1}`,
          filename: `share-${i + 1}.txt`,
          content: m,
          sensitive: true,
          shareIndex: i + 1,
          mime: "text/plain; charset=utf-8",
          encoding: "text",
          disposition: "file",
          role: "share",
          tags: ["mnemonic", "blip39"],
          traits: {
            shareOf: i + 1,
            threshold: value.data.threshold,
          },
        },
        value
      )
    );
  }
  if (value.type === "keypair") {
    return [
      attachPipeMeta(
        {
          label: name,
          filename: `${name}.txt`,
          content: "[keypair — use out or export before emitting]",
          sensitive: true,
          mime: "text/plain",
          encoding: "text",
          disposition: "file",
          role: "key",
          tags: ["keypair"],
        },
        value
      ),
    ];
  }
  if (value.type === "openpgp-key") {
    const which = value.meta?.which === "public" ? "public" : "private";
    return [
      attachPipeMeta(
        {
          label: name,
          filename: `${name}.asc`,
          content: String(value.data || ""),
          sensitive: which === "private" || !!value.meta?.sensitive,
          mime: "application/pgp-keys",
          encoding: "text",
          disposition: "file",
          role: "key",
          tags: ["openpgp", which],
        },
        value
      ),
    ];
  }
  if (value.type === "recipients") {
    const rows = Array.isArray(value.data) ? value.data : [];
    return [
      attachPipeMeta(
        {
          label: name,
          filename: `${name}.json`,
          content: JSON.stringify(rows, null, 2),
          sensitive: false,
          mime: "application/json",
          encoding: "text",
          disposition: "file",
          role: "text",
          tags: ["openpgp", "recipients"],
        },
        value
      ),
    ];
  }
  return [];
}

export { splitArmoredMessages } from "../pgp/armor.js";
export { bytesToText };
