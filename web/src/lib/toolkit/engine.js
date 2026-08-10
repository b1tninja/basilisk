/**
 * Execute a compiled toolkit recipe AST (multi-chain + $slot registry).
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
  dearmorToBytes,
  enrichSpansWithPackets,
  mapPacketSpans,
} from "../packet-map.js";
import { qrSvg } from "../qr.js";
import { DEFAULT_OUT_SLOT, SLOT_SIGIL } from "./recipe-parse.js";
import {
  PROFILE_AUTO,
  encryptArtifacts,
  summarizeEncryption,
} from "../pgp/encrypt.js";
import { resolveStepProfile } from "../pgp/profile-from-step.js";
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
  hexToBytes,
  jwkFieldToBytes,
  parsePem,
  parsePemBlocks,
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
  isCryptoKey,
  normalizeHashName,
  pbkdf2Derive,
  pipelineKeyHandles,
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
import { placementGate } from "./placement.js";
import { recipeChains } from "./recipe.js";
import {
  LEGACY_CRYPTO_TAGS,
  rsaesPkcs1Decrypt,
  rsaesPkcs1Encrypt,
} from "./rsaes-pkcs1.js";
import {
  NETWORK_TYPES as NETWORK_VALUE_TYPES,
  algTokenForKey,
  artifactMetaFromType,
  genkeyOutputBase,
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
 *   fingerprint?: string,
 * }} [traits]
 * @property {import("./types.js").RefinedType} [pipeType]  refined pipeline type at emit time
 * @property {Uint8Array} [bytes]  raw octets when content is a textual encoding of binary
 * @property {import("./inspect.js").InspectSnapshot} [inspectSnapshot]  for live format switching
 * @property {string} [inspectFormat]  current inspect dump format
 * @property {string} [publishedAs]  directory slot once published (design v2 §21b)
 * @property {string} [directoryUrl]  set alongside `publishedAs`
 * @property {string} [netType]  network/WebRTC pipeline type — the UI's renderer
 *   discriminator for manager widgets (design v2 §23a/23b/29d/30d)
 * @property {string} [netKind]  refinement within that type (e.g. "candidate-pairs")
 * @property {*} [netData]  the structured value, unserialized, for the widget to read
 * @property {{
 *   kind: "jws"|"jwe",
 *   verified: boolean,
 *   signed?: boolean,
 *   decrypted?: boolean,
 *   expiryChecked?: boolean,
 *   header: Record<string, *>,
 *   claims: Record<string, *>|null,
 *   payloadText?: string|null,
 *   timing?: { exp: number|null, nbf: number|null, iat: number|null, expired: boolean, notYetValid: boolean },
 * }} [jose]  JOSE body for the JWT reader — `verified` is the op's verdict,
 *   not something re-derivable from the token text
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
 *   placement?: import("./placement.js").Placement,
 * }} [opts]
 *   `placement` is the only way a cell fails to run here, and its absence is
 *   not a weaker form of it: with no `placement` this function does exactly
 *   what it did before the gate existed, and with one it refuses anything the
 *   plan does not fully cover. See `placement.js` for why there is no third
 *   state.
 * @returns {Promise<ToolkitArtifact[]>}
 */
/**
 * Whether a live pipeline value must be treated as secret in UI / inspect tiles.
 * @param {PipelineValue|null|undefined} value
 */
function pipelineValueIsSensitive(value) {
  if (!value) return false;
  if (value.meta?.sensitive) return true;
  if (value.type === "keypair" || value.type === "shares") return true;
  if (value.type === "key" || value.type === "openpgp-key") {
    return String(value.meta?.which || "") !== "public";
  }
  return false;
}

export async function runRecipe(ast, bindings = {}, opts = {}) {
  const chains = recipeChains(ast);
  const chainStart = Math.max(0, opts.chainStart ?? 0);
  const chainEnd = Math.min(chains.length, opts.chainEnd ?? chains.length);
  const slice = chains.slice(chainStart, chainEnd);
  if (!slice.length || !slice.some((c) => c.steps?.length)) {
    throw new Error("Empty recipe");
  }

  // Who runs what, decided before this call and read here rather than worked
  // out again. `null` when no placement was supplied, which is every caller
  // that predates the gate — see `placement.js` on why that is a separate
  // object from a gate that admits everything.
  //
  // Plan indices count *non-empty* chains, the same filter `planRun` applies,
  // so a notebook with a blank cell in it lines the two up. That is index
  // bookkeeping, not a second placement decision.
  const filled = (/** @type {*[]} */ list) => list.filter((c) => c?.steps?.length).length;
  const gate =
    opts.placement == null
      ? null
      : placementGate(opts.placement, {
          cells: filled(chains),
          first: filled(chains.slice(0, chainStart)),
          count: filled(slice),
        });

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

  // Named slot args (`key=$cek`) resolve through the same registry as `in`.
  // `listIndexedSlots` lets the `shares` panel op fall back to share slots an
  // earlier cell's foreach emitted this session (wired inputs, §slot-graph).
  bindings = {
    ...bindings,
    resolveSlot,
    listIndexedSlots: () => registry.indexed?.() || [],
  };

  let stepOrdinal = 0;
  let cellIndex = gate ? gate.firstCell : 0;

  for (const chain of slice) {
    const steps = chain.steps || [];
    if (!steps.length) continue;
    if (gate) {
      const here = gate.admit(cellIndex, (label) => registry.has(label));
      cellIndex++;
      if (!here) {
        // Not performed, and the numbering moves on regardless: a step's
        // ordinal is its place in the notebook, and a cell that ran elsewhere
        // still occupies its place in it.
        stepOrdinal += steps.length;
        continue;
      }
    }
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

    /**
     * The top-level step the plan is currently on — the anchor a failure
     * carries out to the banner.
     *
     * Numbered exactly the way `validateRecipe` numbers its `stepIndex`:
     * continuous across cells, and a step inside a `foreach` body or a `tee`
     * branch reports the stem it hangs off rather than a number no chip has.
     * Matching that convention is the point — a runtime error and a compile
     * error about the same pipeline must not light different chips.
     */
    let stemIndex = -1;
    // The loop body below is deliberately left at its original indentation:
    // re-indenting 230 lines to add an anchor would bury the change.
    try {

  for (const node of plan) {
    stemIndex = steps.indexOf(node.step);
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
            registerSlot(String(step.params?.name || DEFAULT_OUT_SLOT), sideVal, preexisting);
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
          artifacts.push(...(await valueToArtifacts(sideVal)));
          stampNew(before, node.step);
        }
      };

      if (node.body?.length) {
        await runTeeSide(clonePipelineValue(value), node.body);
      }
      for (const br of node.branches || []) {
        await runTeeSide(
          projectSelector(value, br.selector || `:${br.member}`),
          br.body
        );
      }
      // Stem value unchanged.
      continue;
    }

    if (node.kind === "foreach") {
      lastStepEmitted = false;
      // A bundle is already a list of pipeline values, so iterating it needs
      // none of the share-specific unpacking below — run the body per part and
      // re-bundle. This is what makes `quorum.recv count=all | foreach` work, and
      // it closes the older gap where `foreach` produced a type it could not
      // then consume.
      if (value?.type === "bundle") {
        const inParts = Array.isArray(value.data?.parts) ? value.data.parts : [];
        if (!inParts.length) throw new Error("foreach requires a non-empty bundle");
        /** @type {PipelineValue[]} */
        const outParts = [];
        for (let i = 0; i < inParts.length; i++) {
          let itemVal = inParts[i];
          for (const step of node.body) {
            itemVal = await execStep(step, itemVal, bindings, artifacts, i);
          }
          outParts.push(itemVal);
        }
        value = {
          type: "bundle",
          data: { parts: outParts, count: outParts.length },
          meta: { ...value.meta, count: outParts.length },
        };
        continue;
      }
      if (!value || value.type !== "shares") {
        throw new Error("foreach requires shares or a bundle");
      }
      const threshold = Number(value.data.threshold) || 0;
      const body = node.body;
      const mode = String(node.step.foreachSelector || ":values")
        .replace(/^[.:]/, "")
        .toLowerCase();
      const rawItems = value.data.raw;
      const mnemonicItems = value.data.mnemonics;
      const useRaw = Array.isArray(rawItems) && rawItems.length > 0;
      const items = useRaw ? rawItems : mnemonicItems || [];
      if (!items.length) throw new Error("foreach requires a non-empty share set");

      /** @type {PipelineValue[]} */
      const parts = [];
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
            registerSlot(String(step.params?.name || DEFAULT_OUT_SLOT), itemVal, preexisting);
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
        if (itemVal) parts.push(itemVal);
      }
      // Tip is a foreach bundle of per-item tips — not the global artifact list.
      // Side effects (out tiles / auto-emitted shares) already live in `artifacts`.
      value = {
        type: "bundle",
        data: { parts, count: parts.length },
        meta: { kind: "foreach", count: parts.length },
      };
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
      registerSlot(String(node.step.params?.name || DEFAULT_OUT_SLOT), value, preexisting);
    }
  }

  if (value && value.type !== "bundle" && value.type !== "artifact") {
    // Terminal `out` / `text` already pushed tiles; later transforms clear this flag.
    if (!lastStepEmitted) {
      const before = artifacts.length;
      artifacts.push(...(await valueToArtifacts(value)));
      stampNew(before, steps[steps.length - 1]);
    }
  }

    } catch (err) {
      attribute(err, "basiliskStepIndex", stemIndex < 0 ? -1 : stepOrdinal + stemIndex);
      throw err;
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
 * Project a selector (`:private`, `:items`, `:key`, …) from a pipeline value.
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
  const m = raw.replace(/^[.:]/, "").toLowerCase();
  if (m === "private" || m === "priv" || m === "secret") {
    if (value.type !== "keypair") {
      throw new Error(`selector :private requires a keypair`);
    }
    const handles = pipelineKeyHandles(value);
    const priv = handles.privateKey;
    if (!priv) throw new Error("selector :private: no private key on keypair");
    return {
      type: "key",
      data: priv,
      meta: { ...value.meta, which: "private", sensitive: true },
    };
  }
  if (m === "public" || m === "pub") {
    if (value.type !== "keypair") {
      throw new Error(`selector :public requires a keypair`);
    }
    const handles = pipelineKeyHandles(value);
    const pub = handles.publicKey;
    if (!pub) throw new Error("selector :public: no public key on keypair");
    return {
      type: "key",
      data: pub,
      meta: { ...value.meta, which: "public", sensitive: false },
    };
  }
  if (m === "key") {
    if (value.type !== "item") {
      throw new Error(`selector :key requires an item ({key, value})`);
    }
    return {
      type: "text",
      data: String(value.data?.key ?? ""),
      meta: { ...value.meta, sensitive: false },
    };
  }
  if (m === "value") {
    if (value.type !== "item") {
      throw new Error(`selector :value requires an item ({key, value})`);
    }
    const inner = value.data?.value;
    if (!inner || typeof inner !== "object") {
      throw new Error("selector :value: missing item value");
    }
    return /** @type {PipelineValue} */ (inner);
  }
  if (m === "keys" || m === "values" || m === "items") {
    throw new Error(
      `selector :${m}: use as foreach :${m} (stem projection of whole collections is not supported)`
    );
  }
  throw new Error(`Unknown selector ":${m}"`);
}

/**
 * Stamp a thrown error with where it came from, leaving its message untouched.
 *
 * Non-enumerable and `configurable`, so attribution never shows up in a
 * serialized error, never overwrites an inner attribution (the innermost
 * thrower is the specific one), and never turns a failure into a second,
 * different failure: a frozen error simply carries no anchor.
 *
 * @param {unknown} err
 * @param {"basiliskStep"|"basiliskStepIndex"} key
 * @param {string|number} value
 */
function attribute(err, key, value) {
  if (!err || typeof err !== "object" || key in err) return;
  try {
    Object.defineProperty(err, key, { value, enumerable: false, configurable: true });
  } catch (_) {
    /* frozen error: attribution is best-effort */
  }
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
  /** @type {PipelineValue} */
  let result;
  try {
    result = await execStepBody(step, value, bindings, artifacts);
  } catch (err) {
    // Attribute the failure to its step without touching the message — callers
    // (the headless CLI, and the per-cell banner) can say *which* op died even
    // when the throw came from a lazily imported module that never saw the
    // step. Messages are left byte-identical on purpose; tests assert them.
    attribute(err, "basiliskStep", step.name);
    throw err;
  }
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
/**
 * Base encodings reachable through `to <enc>` / `from <enc>`.
 *
 * The set matches the `base64`/`base64url`/`base32` twin steps exactly — the
 * two spellings are the same operation, so they share one table rather than
 * drifting into "hex only works one way, base64 only the other". `base64ToBytes`
 * already accepts the URL alphabet, which is why both map onto it.
 * @type {Record<string, (b: Uint8Array) => string>}
 */
const BASE_ENCODERS = {
  hex: bytesToHex,
  base64: bytesToBase64,
  base64url: bytesToBase64Url,
  base32: bytesToBase32,
};

/** @type {Record<string, (s: string) => Uint8Array>} */
const BASE_DECODERS = {
  hex: hexToBytes,
  base64: base64ToBytes,
  base64url: base64ToBytes,
  base32: base32ToBytes,
};

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
    case "bytes": {
      const raw = String(step.params?.value ?? "").trim();
      const encoding = String(step.params?.encoding || "hex").toLowerCase();
      let data;
      if (encoding === "utf8") data = textToBytes(raw);
      else if (encoding === "base64") data = base64ToBytes(raw);
      else data = hexToBytes(raw.replace(/^0[xX]/, ""));
      // Not marked sensitive: the value is written in the recipe in plain
      // sight, so masking the output would hide it in one pane while showing
      // it in the other. `random` is the sensitive source; this one is a
      // literal the author chose to publish.
      return { type: "bytes", data, meta: {} };
    }
    case "lit": {
      const kind = String(step.params?.kind || "text");
      if (kind === "int") {
        const n = Number(step.params?.value);
        return {
          type: "int",
          data: Number.isFinite(n) ? Math.trunc(n) : 0,
          meta: {},
        };
      }
      if (kind === "bool") {
        const v = step.params?.value;
        const b =
          v === true ||
          v === 1 ||
          String(v).toLowerCase() === "true" ||
          String(v) === "1";
        return { type: "bool", data: b, meta: {} };
      }
      return {
        type: "text",
        data: String(step.params?.value ?? ""),
        meta: {},
      };
    }
    case "passphrase": {
      // Lazy: the EFF wordlist is a 7776-line asset pulled in through Vite's
      // `?raw`, so a static import made every consumer of the engine — the
      // crypto worker, and now the headless CLI — depend on the bundler even
      // when no recipe generates a passphrase. Same lazy-import remedy the
      // clipboard/rtc cases already use.
      const { generateCharPassphrase, generateWordPassphrase } = await import(
        "../passphrase-gen.js"
      );
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
      let mnemonics = (inp?.mnemonics || []).map((m) => String(m).trim()).filter(Boolean);
      if (!mnemonics.length) {
        // Wired fallback: a split cell that ran earlier this session left its
        // shares as indexed slots (foreach `out` values carry shareIndex).
        // Pasting always wins — the fallback only fires on an empty panel.
        const indexed = bindings.listIndexedSlots?.() || [];
        mnemonics = indexed
          .filter((v) => v?.type === "text" && v.meta?.shareIndex)
          .map((v) => String(v.data).trim())
          .filter(Boolean);
      }
      if (!mnemonics.length) {
        throw new Error(
          "No BLIP39 share mnemonics provided — paste shares (or run a split cell first) before running."
        );
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
      // Projected `key` tip selects the half; which= only applies to full keypairs.
      const tipWhich =
        value?.type === "key" &&
        (value?.meta?.which === "public" ||
          value?.meta?.which === "private" ||
          value?.meta?.which === "secret")
          ? value.meta.which
          : null;
      return exportKey(
        value,
        String(step.params.format || "pkcs8"),
        tipWhich || String(step.params.which || "private")
      );
    }
    case "keypair": {
      // Source form of `import` (§31c). Delegates to the very same importKey
      // the `import` transform calls, so a keypair authored here and one
      // piped through `… | import` are indistinguishable downstream.
      const material = String(bindings.inputs?.keypair?.value ?? "").trim();
      if (!material) {
        throw new Error("No key material provided — paste a JWK or PEM before running.");
      }
      const alg = String(step.params?.alg || "ec/p256");
      const usage = String(step.params?.usage || "auto");
      // Same declaration `inferSourceType` types this step from. Without it the
      // paste decided the type: `keypair alg=ec/p256` fed an `oct` JWK, or
      // `keypair format=pem` fed an SPKI block alone, both compiled clean and
      // then `export pkcs8` shipped raw key bytes / SPKI DER under a recipe
      // that said pkcs8. The material may now only agree with the recipe.
      const wantPublic = String(step.params?.which || "private").toLowerCase() === "public";
      if (String(step.params?.format || "jwk").toLowerCase() === "jwk") {
        return importKey(
          { type: "text", data: material, meta: { kind: "jwk", encoding: "jwk" } },
          "jwk",
          alg,
          usage,
          "pss",
          "sha-256",
          { step: "keypair jwk", which: wantPublic ? "public" : "private" }
        );
      }
      // The PEM label already says which half each block is, so the caller
      // does not have to declare pkcs8 vs spki a second time and get it wrong.
      // `which=` is not that second declaration: it says which *tip* the
      // recipe wants, which the label cannot, because a paste of both blocks
      // could serve either.
      //
      // Both halves are accepted together (the design's "PKCS8 private + SPKI
      // public") because importing PKCS#8 alone leaves `publicKey` null —
      // WebCrypto will not recover the public half for you, so a lone private
      // block cannot satisfy a later `export spki`. Pasting both blocks is the
      // only way to get a genuinely complete pair.
      const blocks = parsePemBlocks(material);
      if (!blocks.length) throw new Error("No PEM block found — expected -----BEGIN …-----");
      /** @type {*} */
      let pair = null;
      /** @type {CryptoKey|null} */
      let publicKey = null;
      for (const block of blocks) {
        const imported = await importKey(
          { type: "bytes", data: block.der, meta: {} },
          block.format,
          alg,
          usage
        );
        if (imported.type === "key" && imported.meta?.which === "public") {
          publicKey = /** @type {*} */ (imported.data);
        } else {
          pair = imported;
        }
      }
      if (wantPublic) {
        // The public half, from an SPKI block or off a pasted pair — the tip
        // `keypair which=public` declared, and never the pair itself.
        const pub = publicKey || pair?.data?.publicKey || null;
        if (!pub) throw new Error(noPublicHalfMessage("keypair pem"));
        return {
          type: "key",
          data: pub,
          meta: { alg, which: "public", sensitive: false },
        };
      }
      // Only a public block was pasted. This used to return a `key/public`
      // tip while `inferSourceType` had already declared `keypair/private`,
      // which is how `keypair alg=ed25519 format=pem | export pkcs8` emitted
      // SPKI DER under a recipe that said pkcs8.
      if (!pair) {
        if (!publicKey) throw new Error("Could not import any PEM block");
        throw new Error(noPrivateHalfMessage("keypair pem"));
      }
      if (publicKey && !pair.data.publicKey) pair.data.publicKey = publicKey;
      return pair;
    }
    case "import":
      return importKey(
        value,
        String(step.params.format || "pkcs8"),
        String(step.params.alg || "ec/p256"),
        String(step.params.usage || "auto"),
        String(step.params.padding || "pss"),
        String(step.params.hash || "sha-256"),
        // The declaration `inferParamDrivenType` typed this step from. Passing
        // it is what turns "whatever the JWK held" into "the tip the recipe
        // named, or a refusal".
        {
          step: "import jwk",
          which:
            String(step.params.which || "private").toLowerCase() === "public"
              ? "public"
              : "private",
        }
      );
    case "pem": {
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
        meta: {
          ...value.meta,
          kind: "pem",
          encoding: "pem",
          which: value.meta?.which,
          sensitive: !!value.meta?.sensitive,
        },
      };
    }
    case "der": {
      if (!value || value.type !== "text") throw new Error("der expects PEM text");
      const block = parsePem(String(value.data));
      return {
        type: "bytes",
        data: block.der,
        meta: {
          ...value.meta,
          format: block.format === "opaque" ? value.meta?.format : block.format,
          which: block.which ?? value.meta?.which,
          pemLabel: block.label,
          kind: "der",
          sensitive: (block.which ?? value.meta?.which) !== "public",
        },
      };
    }
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
    // `to`/`from` are the uniform spelling of a base encoding — one verb, the
    // encoding as an argument. The `base64`/`base32`/… twins remain as the
    // shorthand, and both routes share these tables so they cannot diverge.
    case "encode": {
      const enc = String(step.params?.encoding || "hex").toLowerCase();
      const encode = BASE_ENCODERS[enc];
      if (!encode) throw new Error(`encode: unsupported alphabet "${enc}"`);
      if (!value || value.type !== "bytes") throw new Error(`encode ${enc} expects bytes`);
      return {
        type: "text",
        data: encode(value.data),
        meta: {
          ...value.meta,
          kind: "opaque",
          encoding: enc,
          sensitive: !!value.meta?.sensitive,
        },
      };
    }
    case "decode": {
      const enc = String(step.params?.encoding || "hex").toLowerCase();
      const decode = BASE_DECODERS[enc];
      if (!decode) throw new Error(`decode: unsupported alphabet "${enc}"`);
      if (!value || value.type !== "text") throw new Error(`decode ${enc} expects text`);
      return {
        type: "bytes",
        data: decode(String(value.data)),
        meta: { ...value.meta, sensitive: !!value.meta?.sensitive },
      };
    }
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
            type: "bool",
            data: false,
            meta: { sensitive: false, tags },
          };
        }
        throw new Error("Signature verification failed");
      }
      return {
        type: "bool",
        data: true,
        meta: { sensitive: false, tags },
      };
    }
    case "aes-gcm": {
      const bytes = valueToBytes(value);
      const key =
        (await resolveSlotKey(bindings, step.params?.key, "secret")) ||
        (await resolveBoundKey(bindings, "secret"));
      assertExpectedAesKeyBits(key, step.params?.keyBits ?? step.params?.expectedKeyBits, "aes-gcm");
      const aad = await resolveBytesOrUtf8Param(
        bindings,
        step.params?.aad,
        "aes-gcm aad"
      );
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
      assertExpectedAesKeyBits(key, step.params?.keyBits ?? step.params?.expectedKeyBits, "aes-cbc");
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
      assertExpectedAesKeyBits(key, step.params?.keyBits ?? step.params?.expectedKeyBits, "aes-ctr");
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
      assertExpectedOaepHash(key, step.params?.hash ?? step.params?.oaepHash);
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
      const salt =
        (await resolveBytesOrUtf8Param(
          bindings,
          step.params?.salt,
          "hkdf salt"
        )) || new Uint8Array();
      const info =
        (await resolveBytesOrUtf8Param(
          bindings,
          step.params?.info,
          "hkdf info"
        )) || new Uint8Array();
      const out = await hkdfDerive(ikm, {
        length,
        as,
        hash: hashName,
        salt,
        info,
      });
      if (out && typeof out === "object" && out.type === "key") return out;
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
      const salt =
        (await resolveBytesOrUtf8Param(
          bindings,
          step.params?.salt,
          "pbkdf2 salt",
          { defaultUtf8: "basilisk" }
        )) || textToBytes("basilisk");
      const out = await pbkdf2Derive(password, {
        salt,
        iterations,
        length,
        as,
        hash: hashName,
      });
      if (out && typeof out === "object" && out.type === "key") return out;
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
            "ecdh needs peer=$slot or peer public JWK in the peer key field"
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
      if (out && typeof out === "object" && out.type === "key") return out;
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
            "wrap needs target=$slot or key-to-wrap JWK in the wrap panel"
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
      let key;
      if (mode === "rsa-oaep") {
        const wrappingKey =
          (await resolveSlotKey(bindings, step.params?.key, "private", "rsa-oaep")) ||
          (await resolveBoundKey(bindings, "private"));
        key = await rsaOaepUnwrap(
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
        key = await aesContentUnwrap(
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
        key = await aesKwUnwrap(kw, wrapped, importAlg, usages);
      }
      return {
        type: "key",
        data: key,
        meta: {
          sensitive: true,
          which: "secret",
          alg: metaAlg,
          mode,
          symmetric: true,
        },
      };
    }
    case "vss.split":
    case "vss.verify":
    case "vss.commitments":
    case "vss.combine": {
      // Lazy: the curve arithmetic is only pulled in by a recipe that shares
      // verifiably, which most do not.
      const vss = await import("./vss-ops.js");
      if (step.name === "vss.split") return vss.execVssSplit(value, step.params || {});
      if (step.name === "vss.verify") {
        return vss.execVssVerify(value, step.params || {}, bindings);
      }
      if (step.name === "vss.commitments") return vss.execVssCommitments(value);
      return vss.execVssCombine(value);
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
      const mode = resolveGpgSymMode(step.params, "gpg.symencrypt");
      const userPass =
        mode === "passphrase"
          ? await resolvePassphraseParam(
              bindings,
              step.params?.passphrase,
              "gpg.symencrypt passphrase"
            )
          : null;
      if (mode === "passphrase" && !userPass) {
        throw new Error(
          "gpg.symencrypt mode=passphrase requires passphrase= or passphrase=$slot"
        );
      }
      const master = mode === "master" ? crypto.getRandomValues(new Uint8Array(32)) : null;
      const password = userPass || bytesToHex(/** @type {Uint8Array} */ (master));
      const arts = await encryptArtifacts({
        recipients: [],
        passwords: [password],
        payloads: [payload],
        profile: resolveStepProfile(step, bindings.encryption?.profile || PROFILE_AUTO),
        hideRecipients: false,
      });
      if (!arts.length) throw new Error("gpg.symencrypt produced no ciphertext");
      const armored = arts[0].armored;
      const cryptoSummary = await summarizeEncryption(armored);
      const stem = safeOutputStem(step.params.name || "envelope");
      // Hoisted out of the `role:` line below rather than written inline,
      // because `artifact-roles.test.js` reads the role literals off that line
      // to check them against the vocabulary — and `mode === "passphrase"`
      // would have put a string on it that is not a role.
      const ceremonyEnvelope = mode !== "passphrase";
      artifacts.push({
        label:
          mode === "passphrase"
            ? "OpenPGP symmetric ciphertext"
            : "OpenPGP envelope — required for recovery (not a share)",
        filename: `${stem}.asc`,
        content: armored,
        sensitive: false,
        mime: "application/pgp-encrypted",
        cryptoSummary,
        disposition: "file",
        /**
         * **The mode decides the role, because the two modes make two
         * different objects.**
         *
         * Both branches said `envelope`, so a `mode=passphrase` message —
         * whose own label calls it "OpenPGP symmetric ciphertext" — wore the
         * **ENVELOPE** badge. That word is not decoration here. `envelope` is
         * a role the ceremony vocabulary owns: the master-key wrap that a
         * witness must keep and must *not* count toward the threshold, which
         * is the whole reason the kind exists separately from `ciphertext`
         * when both draw the same packet read-out. A badge that says
         * "envelope" over an ordinary passphrase-encrypted message spends
         * that word on something that is not one, and the label and the badge
         * disagreed on the same tile.
         *
         * `mode=master` is the ceremony's own branch — it is the one that
         * mints the random master key the shares reconstruct — so it keeps
         * the role. Nothing else about the artifact moves: same body, same
         * filename, same `.asc`, same tags, and both roles resolve to a kind
         * whose view is `PacketMapCard`.
         */
        role: ceremonyEnvelope ? "envelope" : "ciphertext",
        tags:
          mode === "passphrase"
            ? ["openpgp", "skesk", "passphrase"]
            : ["openpgp", "skesk"],
      });
      if (mode === "passphrase") {
        return {
          type: "text",
          data: armored,
          meta: {
            ...value.meta,
            kind: "armored",
            encoding: "openpgp",
            sensitive: false,
          },
        };
      }
      return {
        type: "bytes",
        data: /** @type {Uint8Array} */ (master),
        meta: { ...value.meta, sensitive: true, openPgpEnvelope: true },
      };
    }
    case "gpg.symdecrypt": {
      const mode = resolveGpgSymMode(step.params, "gpg.symdecrypt");
      if (mode === "passphrase") {
        const userPass = await resolvePassphraseParam(
          bindings,
          step.params?.passphrase,
          "gpg.symdecrypt passphrase"
        );
        if (!userPass) {
          throw new Error(
            "gpg.symdecrypt mode=passphrase requires passphrase= or passphrase=$slot"
          );
        }
        let armored;
        if (value?.type === "text") {
          armored = String(value.data);
        } else if (value?.type === "bytes" && value.data instanceof Uint8Array) {
          armored = bytesToText(value.data);
        } else {
          throw new Error(
            "gpg.symdecrypt mode=passphrase expects armored ciphertext on the tip"
          );
        }
        if (!/BEGIN PGP MESSAGE/i.test(armored)) {
          throw new Error(
            "gpg.symdecrypt mode=passphrase: tip does not look like an OpenPGP message"
          );
        }
        const message = await readMessage({ armoredMessage: armored });
        const { data } = await openpgpDecrypt({
          message,
          passwords: [userPass],
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
            return { type: "bool", data: false, meta: { sensitive: false } };
          }
          throw new Error("gpg.verify: signature invalid");
        }
        return { type: "bool", data: true, meta: { sensitive: false } };
      } catch (err) {
        if (soft) {
          const msg = err instanceof Error ? err.message : String(err);
          if (/invalid|verification|signature/i.test(msg)) {
            return { type: "bool", data: false, meta: { sensitive: false } };
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
        // Only reachable with no `to=` at all: every other token kind throws
        // its own, more specific error inside resolveEncryptRecipients. So
        // this message should describe *that* case rather than reciting all
        // three ways to name a recipient — two of which would be advice to do
        // what the author already did.
        throw new Error(
          "gpg.encrypt: no recipients chosen. Pick them in the Keys tray, or name them on the step — `to=$slot` for an earlier lookup, or `to=someone@example.com` to resolve one now."
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
            profile: resolveStepProfile(step, bindings.encryption?.profile || PROFILE_AUTO),
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
        // Writing `qr` is the request to *see* this value as a code, exactly
        // as `out` / `text` / `inspect` are — and a masked tile runs no view
        // at all, so without this a QR of anything sensitive (an otpauth
        // enrolment URI, a share card) is a permanently blank square. The
        // mask still applies; what this grants is the Reveal that makes it
        // openable.
        revealable: true,
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
        // Writing `out` *is* the request to see this value, so its tile may
        // offer Reveal even when the value is sensitive. Tiles the engine
        // materializes on its own carry no such request and stay masked —
        // that is the whole point of the gate.
        a.revealable = true;
        if (value.meta?.runReceipt) {
          // Its own role so the kernel can keep it out of the run log and the
          // UI can offer "verify this" rather than treating it as loose text.
          a.role = "receipt";
        } else if (value.meta?.stunCheck) {
          // Quorum diagnostic (§22b) — overrides materializeOutArtifacts'
          // generic text/secret default; UI reads the JSON body for ok/
          // candidates and offers "Configure TURN" when srflx is missing.
          a.role = "diagnostic";
        } else if (!a.role) {
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
        revealable: true,
        tags: value.meta?.sensitive ? ["sensitive"] : [],
      });
      return value;
    }
    case "inspect": {
      if (!value) throw new Error("inspect expects a value");
      const format = String(step.params.format || "auto");
      const snapshot = await buildInspectSnapshot(value);
      const dump = inspectFromSnapshot(snapshot, format);
      const sensitive = pipelineValueIsSensitive(value);
      return {
        type: "text",
        data: dump,
        meta: {
          ...value.meta,
          sensitive,
          inspect: true,
          // Keep live snapshot only for non-sensitive tips (format switch).
          // Private openpgp-key / keypair dumps stay masked without retaining armor.
          inspectSnapshot: sensitive ? undefined : snapshot,
          inspectFormat: format,
        },
      };
    }
    case "tee": {
      throw new Error(
        "tee requires a body — use `{ - :public | … }` or indented `-` lines (use `peek` for a side inspect)"
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
      const sensitive = pipelineValueIsSensitive(value);
      artifacts.push({
        label: `peek:${name}`,
        filename: `${name}.inspect.txt`,
        content: dump,
        sensitive,
        disposition: "file",
        role: "inspect",
        tags: ["inspect"],
        inspectSnapshot: sensitive ? undefined : snapshot || undefined,
        inspectFormat: format,
      });
      return value;
    }
    case "as": {
      const kind = String(step.params.type || "opaque").toLowerCase();
      const alg = String(step.params.alg || value?.meta?.alg || "ec/p256");
      const usage = String(step.params.usage || "auto");
      const padding = String(step.params.padding || "pss");
      const hash = String(step.params.hash || "sha-256");

      // Materialize: DER/PEM/JWK → CryptoKey tip(s)
      if (kind === "key" || kind === "keypair") {
        // JWK text
        if (
          value?.type === "text" &&
          (value.meta?.encoding === "jwk" ||
            value.meta?.kind === "jwk" ||
            /^\s*\{/.test(String(value.data || "")))
        ) {
          const imported = await importKey(value, "jwk", alg, usage, padding, hash);
          if (kind === "keypair") {
            if (imported.type === "key") {
              throw new Error("as keypair: JWK is public-only — need a private JWK");
            }
            return imported;
          }
          const handles = pipelineKeyHandles(imported);
          if (handles.privateKey) {
            return {
              type: "key",
              data: handles.privateKey,
              meta: { ...imported.meta, which: "private", sensitive: true },
            };
          }
          if (handles.publicKey) {
            return {
              type: "key",
              data: handles.publicKey,
              meta: { ...imported.meta, which: "public", sensitive: false },
            };
          }
          if (handles.secretKey) {
            return {
              type: "key",
              data: handles.secretKey,
              meta: { ...imported.meta, which: "secret", sensitive: true },
            };
          }
          throw new Error("as key: empty JWK import");
        }
        let material = value;
        if (value?.type === "text") {
          const block = parsePem(String(value.data));
          material = {
            type: "bytes",
            data: block.der,
            meta: {
              ...value.meta,
              format: block.format === "opaque" ? value.meta?.format : block.format,
              which: block.which ?? value.meta?.which,
              kind: "der",
              pemLabel: block.label,
            },
          };
        }
        if (!material || material.type !== "bytes") {
          throw new Error(`as ${kind} expects bytes/der or text/pem`);
        }
        const which = material.meta?.which;
        if (kind === "keypair") {
          if (which === "public") {
            throw new Error("as keypair needs private material — tip is public; use as key");
          }
          const format =
            material.meta?.format === "scalar" || material.meta?.kind === "scalar"
              ? "scalar"
              : "pkcs8";
          const imported = await importKey(material, format, alg, usage, padding, hash);
          if (imported.type === "key") {
            throw new Error("as keypair: import produced a public-only key");
          }
          return imported;
        }
        // as key
        if (which !== "public" && which !== "private") {
          throw new Error(
            "as key needs which — use as public / as private first, or PEM with a known BEGIN label"
          );
        }
        const format = which === "public" ? "spki" : "pkcs8";
        const imported = await importKey(material, format, alg, usage, padding, hash);
        if (imported.type === "key") {
          if (isCryptoKey(imported.data)) return imported;
          const handles = pipelineKeyHandles(imported);
          const ck = which === "public" ? handles.publicKey : handles.privateKey;
          if (!ck) throw new Error("as key: import produced empty key");
          return {
            type: "key",
            data: ck,
            meta: { ...imported.meta, which, sensitive: which !== "public" },
          };
        }
        // Private pkcs8 import yields keypair — project to private CryptoKey tip
        const handles = pipelineKeyHandles(imported);
        if (!handles.privateKey) throw new Error("as key: no private key after import");
        return {
          type: "key",
          data: handles.privateKey,
          meta: {
            ...imported.meta,
            which: "private",
            sensitive: true,
          },
        };
      }

      // Retag which on der/pem
      if (kind === "public" || kind === "private") {
        if (!value || (value.type !== "bytes" && value.type !== "text")) {
          throw new Error(`as ${kind} expects bytes/der or text/pem`);
        }
        const prev = value.meta?.which;
        if (prev && prev !== kind) {
          throw new Error(`as ${kind} conflicts with tip which=${prev}`);
        }
        return {
          type: value.type,
          data: value.data,
          meta: {
            ...value.meta,
            which: kind,
            kind:
              value.type === "text"
                ? value.meta?.kind || "pem"
                : value.meta?.kind || "der",
            encoding:
              value.type === "text"
                ? value.meta?.encoding || "pem"
                : value.meta?.encoding,
            sensitive: kind !== "public",
          },
        };
      }

      if (kind === "int" || kind === "bool") {
        return coercePipelineScalar(value, kind);
      }

      if (!value || value.type !== "bytes") {
        throw new Error("as expects bytes");
      }
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
      throw new Error(
        `as type must be master, scalar, opaque, public, private, key, keypair, int, or bool — got "${kind}"`
      );
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
    case "agent.sign":
    case "agent.decrypt":
    case "agent.pub":
    case "agent.list":
    case "agent.save": {
      const agent = await import("./agent-ops.js");
      if (step.name === "agent.unlock") {
        return agent.execAgentUnlock(step.params || {}, bindings);
      }
      if (step.name === "agent.sign") {
        return agent.execAgentSign(value, step.params || {}, bindings);
      }
      if (step.name === "agent.decrypt") {
        return agent.execAgentDecrypt(value, step.params || {}, bindings);
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
    case "rtc.ice":
    case "stun.check":
    case "quorum.offer":
    case "quorum.join":
    case "quorum.send":
    case "quorum.recv":
    case "quorum.close": {
      // Lazy: keeps WebRTC + the quorum mesh out of the base bundle.
      // Main-thread only — RTCPeerConnection does not exist in workers.
      const q = await import("./quorum-ops.js");
      if (step.name === "rtc.ice") {
        const params = { ...(step.params || {}) };
        const credRef = String(params.credential || "").trim();
        if (credRef.startsWith(SLOT_SIGIL)) {
          const resolve = bindings?.resolveSlot;
          if (typeof resolve !== "function") {
            throw new Error("rtc.ice: runtime slot resolver missing for credential=");
          }
          const slot = resolve(credRef);
          if (!slot) throw new Error(`rtc.ice: unknown slot ${credRef}`);
          params.credential =
            slot.type === "text"
              ? String(slot.data)
              : new TextDecoder().decode(/** @type {Uint8Array} */ (slot.data));
        }
        return q.execRtcIce(params);
      }
      if (step.name === "stun.check") return q.execStunCheck(step.params || {});
      if (step.name === "quorum.send") return q.execQuorumSend(value, step.params || {});
      if (step.name === "quorum.recv") return q.execQuorumRecv(step.params || {});
      if (step.name === "quorum.close") return q.execQuorumClose(value);
      const privateKey = await resolveGpgPrivateKey(bindings, step.params?.key);
      let ice = null;
      const iceRef = String(step.params?.ice || "").trim();
      if (iceRef) {
        const resolve = bindings?.resolveSlot;
        if (typeof resolve !== "function") {
          throw new Error("quorum: runtime slot resolver missing for ice=");
        }
        const slot = resolve(iceRef);
        if (!slot) throw new Error(`quorum: unknown slot ${iceRef}`);
        // Pass the slot value through unchanged — `rtc.ice` now emits structured
        // `endpoint` data; only a legacy text slot needs string parsing.
        ice = q.parseIceConfig(slot.data);
      }
      return q.execQuorumOpen(
        step.params || {},
        privateKey,
        ice,
        step.name === "quorum.offer" ? "creator" : "joiner"
      );
    }
    case "run.receipt": {
      const receipt = await currentRunReceipt(bindings, artifacts, step.params || {});
      const { receiptToJson } = await import("./receipt.js");
      return {
        type: "text",
        data: receiptToJson(receipt),
        // A receipt is digests and recipe text by construction — publishing it
        // is the point, so masking it would be theatre. `run.receipt` is also
        // not on the reveal-gate list precisely because there is nothing here
        // to reveal.
        meta: { sensitive: false, kind: "opaque", runReceipt: true },
      };
    }
    case "run.manifest": {
      const manifest = await currentRunManifest(bindings, step.params || {});
      const { manifestToJson } = await import("./manifest.js");
      return {
        type: "text",
        data: manifestToJson(manifest),
        // A manifest is recipe text and digests — the document exists to be
        // handed round, so masking it would be theatre, exactly as for a
        // receipt. It carries no `role` of its own: a role is a UI vocabulary
        // with a kind, a badge and a read-out behind it, and this unit is the
        // documents. `out $manifest` gives it the ordinary text tile.
        meta: { sensitive: false, kind: "opaque" },
      };
    }
    case "run.attest": {
      if (!value || value.type !== "text") {
        throw new Error(
          "run.attest expects manifest text (use `input` to paste one)"
        );
      }
      const { manifestDigest, parseManifest } = await import("./manifest.js");
      const { attestationToJson, buildAttestation } = await import("./attest.js");
      // Parsed rather than digested as-is, so a signed manifest attests to the
      // same digest as the plain one it wraps, and so text that is not a
      // manifest is refused here rather than attested to.
      const manifest = parseManifest(String(value.data));
      const attestation = await buildAttestation({
        manifestSha: await manifestDigest(manifest),
      });
      return {
        type: "text",
        data: attestationToJson(attestation),
        meta: { sensitive: false, kind: "opaque" },
      };
    }
    case "run.verify": {
      if (!value || value.type !== "text") {
        throw new Error("run.verify expects receipt text (use `input` to paste one)");
      }
      const { parseReceipt, compareReceipts, summarizeComparison } = await import(
        "./receipt.js"
      );
      const claimed = parseReceipt(String(value.data));
      // The re-run's own receipt is built from the same artifacts this run has
      // produced so far, so `… | run.verify` compares like with like.
      const actual = await currentRunReceipt(bindings, artifacts, {
        label: claimed.label,
      });
      const result = compareReceipts(claimed, actual);
      if (!result.ok && !step.params?.soft) {
        throw new Error(summarizeComparison(result));
      }
      return {
        type: "bool",
        data: result.ok,
        meta: {
          sensitive: false,
          receiptComparison: result,
          receiptSummary: summarizeComparison(result),
        },
      };
    }
    case "jose.decode":
    case "jose.sign":
    case "jose.verify":
    case "jose.encrypt":
    case "jose.decrypt": {
      // Lazy like the other product modules — a recipe that never touches a
      // token never pays for the JOSE tables. Unlike clipboard/WebRTC this is
      // pure WebCrypto, so it is worker-safe.
      const jose = await import("./jose-ops.js");
      const p = step.params || {};
      switch (step.name) {
        case "jose.decode":
          return jose.execJoseDecode(value, p);
        case "jose.sign":
          return jose.execJoseSign(value, p, bindings);
        case "jose.verify":
          return jose.execJoseVerify(value, p, bindings);
        case "jose.encrypt":
          return jose.execJoseEncrypt(value, p, bindings);
        default:
          return jose.execJoseDecrypt(value, p, bindings);
      }
    }
    case "dkg.run": {
      // Lazy + main-thread: it drives the live RTCPeerConnection mesh.
      const { execDkgRun } = await import("./dkg-ops.js");
      return execDkgRun(step.params || {});
    }
    case "qr.scan": {
      // Lazy + main-thread: BarcodeDetector and canvas rasterization are not
      // available in the worker.
      const { execQrScan } = await import("./qr-scan.js");
      return execQrScan(value, step.params || {});
    }
    case "clipboard.read":
    case "clipboard.write": {
      // Lazy + main-thread only — navigator.clipboard does not exist in workers.
      const cb = await import("./clipboard-ops.js");
      return step.name === "clipboard.read"
        ? cb.execClipboardRead()
        : cb.execClipboardWrite(value);
    }
    case "file.read":
    case "file.save": {
      // Lazy + main-thread only — both pickers need a document and the Run
      // click's transient activation.
      const io = await import("./file-ops.js");
      return step.name === "file.read"
        ? io.execFileRead(step.params || {})
        : io.execFileSave(value, step.params || {});
    }
    case "stream.seal":
    case "stream.open": {
      // Worker-safe: pure WebCrypto. Lazy only to keep the format's tables out
      // of the hot path for recipes that never touch a file.
      const s = await import("./stream-aead.js");
      const bytes = valueToBytes(value);
      const key =
        (await resolveSlotKey(bindings, step.params?.key, "secret")) ||
        (await resolveBoundKey(bindings, "secret"));
      if (step.name === "stream.open") {
        const plain = await s.streamOpen(key, bytes);
        return {
          type: "bytes",
          data: plain,
          meta: {
            sensitive: true,
            kind: "opaque",
            filename: String(value?.meta?.filename || "").replace(/\.bskstrm$/i, "") || undefined,
          },
        };
      }
      const sealed = await s.streamSeal(key, bytes, {
        chunk: step.params?.chunk,
      });
      const sourceName = String(value?.meta?.filename || "").trim();
      return {
        type: "bytes",
        data: sealed,
        meta: {
          // The ciphertext itself is not secret — that is the point of
          // encrypting it — so it is not masked, matching `age.encrypt`.
          sensitive: false,
          kind: "opaque",
          streamSealed: true,
          filename: sourceName ? `${sourceName}.bskstrm` : "sealed.bskstrm",
          mime: "application/octet-stream",
        },
      };
    }
    case "age.keygen":
    case "age.recipient":
    case "age.encrypt":
    case "age.decrypt": {
      // Lazy: typage plus its noble primitives is a real chunk of bundle, and
      // most recipes never reach for age.
      const age = await import("./age-ops.js");
      const p = step.params || {};
      switch (step.name) {
        case "age.keygen":
          return age.execAgeKeygen();
        case "age.recipient":
          return age.execAgeRecipient(value);
        case "age.encrypt":
          return age.execAgeEncrypt(value, p, bindings);
        default:
          return age.execAgeDecrypt(value, p, bindings);
      }
    }
    case "ssh.encode":
    case "ssh.decode":
    case "ssh.fingerprint":
    case "ssh.sign":
    case "ssh.verify": {
      // Lazy for the same reason as age: a whole wire-format family most
      // recipes never touch.
      const ssh = await import("./ssh-ops.js");
      const p = step.params || {};
      switch (step.name) {
        case "ssh.encode":
          return ssh.execSshEncode(value, p, bindings);
        case "ssh.decode":
          // bindings, so a passphrase-protected openssh-key-v1 block can be
          // opened with the Inputs-panel passphrase the gpg ops already read.
          return ssh.execSshDecode(value, p, bindings);
        case "ssh.fingerprint":
          return ssh.execSshFingerprint(value, p, bindings);
        case "ssh.sign":
          return ssh.execSshSign(value, p, bindings);
        default:
          return ssh.execSshVerify(value, p, bindings);
      }
    }
    case "otp.uri":
    case "otp.parse":
    case "otp.code":
    case "otp.verify": {
      // Lazy for the same reason as age and ssh: a whole format family most
      // recipes never touch.
      const otp = await import("./otp-ops.js");
      const p = step.params || {};
      switch (step.name) {
        case "otp.uri":
          return otp.execOtpUri(value, p);
        case "otp.parse":
          return otp.execOtpParse(value, p);
        case "otp.code":
          return otp.execOtpCode(value, p);
        default:
          return otp.execOtpVerify(value, p, bindings);
      }
    }
    case "rtc.gather":
    case "rtc.check":
    case "rtc.certificate":
    case "rtc.state":
    case "rtc.restart":
    case "rtc.stats":
    case "rtc.quality": {
      // Lazy + main-thread only, same as the quorum ops these sit under.
      const rtc = await import("./rtc-ops.js");
      const p = step.params || {};
      switch (step.name) {
        case "rtc.gather":
          return rtc.execGatherCandidates(p, bindings);
        case "rtc.check":
          return rtc.execCheckConnectivity();
        case "rtc.certificate":
          return rtc.execCertificate(p);
        case "rtc.state":
          return rtc.execConnectionState();
        case "rtc.restart":
          return rtc.execRtcRestart();
        case "rtc.stats":
          return rtc.execDataChannelStats();
        default:
          return rtc.execStatsReport();
      }
    }
    case "peer.offer":
    case "peer.answer":
    case "peer.accept":
    case "peer.wait":
    case "peer.send":
    case "peer.recv":
    case "peer.close": {
      // Lazy + main-thread only: the manager holds real RTCPeerConnections.
      const peer = await import("./peer-ops.js");
      const p = step.params || {};
      switch (step.name) {
        case "peer.offer":
          return peer.execPeerOffer(p, bindings);
        case "peer.answer":
          return peer.execPeerAnswer(value, p, bindings);
        case "peer.accept":
          return peer.execPeerAccept(value, p);
        case "peer.wait":
          return peer.execPeerWait(p);
        case "peer.send":
          return peer.execPeerSend(value, p);
        case "peer.recv":
          return peer.execPeerRecv(p);
        default:
          return peer.execPeerClose(p);
      }
    }
    default:
      throw new Error(`Unsupported step: ${step.name}`);
  }
}

/**
 * Build a receipt for the run in progress.
 *
 * Two halves, because a run receipt spans more than one engine call. The
 * kernel accumulates a digested log of the cells it has already executed this
 * session and hands it over as `bindings.receipt.runLog`; the artifacts of the
 * *current* call become one more cell appended to that log. So `run.receipt`
 * placed in the last cell of a notebook receipts the whole notebook, and the
 * same op run standalone (no kernel, as in tests) receipts just itself.
 *
 * Modelled as an op rather than a kernel-only export deliberately: a receipt
 * that can only be produced by a button is not composable, and the entire
 * value here comes from piping it into `gpg.sign` and `out` — the existing
 * signing path, with no new key handling. The kernel-level facts it cannot see
 * for itself (notebook source, prior cells) arrive through `bindings`, the
 * same runtime channel `input` and `shares` already use and the same one that
 * keeps them out of recipe text.
 *
 * @param {RuntimeBindings} bindings
 * @param {ToolkitArtifact[]} artifacts  artifacts of the current engine call
 * @param {Record<string, *>} params
 */
async function currentRunReceipt(bindings, artifacts, params) {
  const { buildRunReceipt, digestArtifact, digestInputs, opsRegistryVersion } =
    await import("./receipt.js");
  const ctx = /** @type {*} */ (bindings).receipt || {};
  /** @type {import("./receipt.js").ReceiptCell[]} */
  const cells = Array.isArray(ctx.runLog) ? [...ctx.runLog] : [];
  const outputs = [];
  for (const a of artifacts) outputs.push(await digestArtifact(a));
  cells.push({
    index: Number(ctx.cellIndex) || cells.length,
    recipe: String(ctx.cellRecipe || ctx.recipeSource || ""),
    startedAt: String(ctx.startedAt || new Date().toISOString()),
    inputs: await digestInputs(bindings.inputs),
    outputs,
  });
  const label =
    String(params?.label || "").trim() || String(ctx.label || "").trim() || undefined;
  return buildRunReceipt({
    label,
    registry: opsRegistryVersion(),
    recipeSource: String(ctx.recipeSource || ctx.cellRecipe || ""),
    cells,
  });
}

/**
 * Build the manifest for the notebook this call belongs to.
 *
 * The sibling of `currentRunReceipt`, and it reads the same `bindings.receipt`
 * context — `recipeSource` when the shell supplies the notebook's text,
 * this cell's text otherwise. The two ops are honest about the same notebook or
 * neither is, so they share the fallback rather than each inventing one.
 *
 * The cells are *read from the recipe*, not accumulated from a run log: a
 * manifest describes a run that has not happened, so there is no log to read.
 * The reading is `recipeChains` + `serializeRecipe`, which is the spelling
 * `appendRunLog` records — a manifest built any other way would compare
 * unequal to an honest receipt on whitespace alone. `buildRunManifest` declines
 * to do this itself for the reason its doc comment gives; doing it here, in the
 * caller, is what that comment asks for.
 *
 * `peers` is deliberately empty. A manifest's `peersSha` commits to a
 * label→fingerprint binding, and this build has no roster to bind: the session
 * layer that would carry one does not exist yet. Passing the labels with blank
 * fingerprints would commit to a binding that says nothing while looking like
 * it says something. The cells still carry their `@peer` headers, which is what
 * the recipe actually knows.
 *
 * `entropy` and `clock` are left at `buildRunManifest`'s fail-closed defaults
 * (`local`, `free`), because they are true of every run this build performs: no
 * op reads a pool and no op reads a pinned `t0`. `manifestReproducibility` will
 * say so, which is the honest answer rather than a flattering one.
 *
 * @param {RuntimeBindings} bindings
 * @param {Record<string, *>} params
 */
async function currentRunManifest(bindings, params) {
  const { buildRunManifest } = await import("./manifest.js");
  const { opsRegistryVersion } = await import("./receipt.js");
  const { serializeRecipe } = await import("./recipe.js");
  const { parseRecipeSource } = await import("./recipe-parse.js");
  const ctx = /** @type {*} */ (bindings).receipt || {};
  const recipeSource = String(ctx.recipeSource || ctx.cellRecipe || "");

  const { ast } = parseRecipeSource(recipeSource);
  /** @type {{ index: number, peer: string, publish: boolean, recipe: string }[]} */
  const cells = [];
  const chains = ast ? recipeChains(ast) : [];
  for (let i = 0; i < chains.length; i++) {
    const chain = chains[i];
    if (!chain?.steps?.length) continue;
    let recipe = "";
    try {
      recipe = serializeRecipe({ chains: [chain] });
    } catch (_) {
      // A cell that will not serialize is recorded as empty rather than
      // dropped: a manifest that silently omitted a cell would be a commitment
      // to a shorter notebook than the one about to run.
      recipe = "";
    }
    cells.push({
      index: i,
      peer: String(chain.peer || ""),
      publish: !!chain.publish,
      recipe,
    });
  }

  const title =
    String(params?.title || "").trim() || String(ctx.label || "").trim() || undefined;
  return buildRunManifest({
    title,
    registry: opsRegistryVersion(),
    recipeSource,
    cells,
  });
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
 * @param {CryptoKey} key
 * @param {unknown} expectedHash
 */
function assertExpectedOaepHash(key, expectedHash) {
  const want = String(expectedHash || "")
    .trim()
    .toLowerCase()
    .replace(/_/g, "-");
  if (!want) return;
  const got = String(key?.algorithm?.hash?.name || "")
    .toLowerCase()
    .replace(/_/g, "-");
  const norm = (h) =>
    h === "sha-1" || h === "sha1"
      ? "sha-1"
      : h === "sha-256" || h === "sha256"
        ? "sha-256"
        : h === "sha-384" || h === "sha384"
          ? "sha-384"
          : h === "sha-512" || h === "sha512"
            ? "sha-512"
            : h;
  if (got && norm(got) !== norm(want)) {
    throw new Error(
      `rsa-oaep: key hash is ${got || "unknown"} but recipe requested ${want}`
    );
  }
}

/**
 * Coerce pipeline tip to int or bool.
 * @param {PipelineValue|null|undefined} value
 * @param {"int"|"bool"} kind
 * @returns {PipelineValue}
 */
function coercePipelineScalar(value, kind) {
  if (!value) throw new Error(`as ${kind} expects a pipeline value`);
  if (kind === "int") {
    if (value.type === "int") {
      const n = Number(value.data);
      return {
        type: "int",
        data: Number.isFinite(n) ? Math.trunc(n) : 0,
        meta: { ...value.meta },
      };
    }
    if (value.type === "bool") {
      return { type: "int", data: value.data ? 1 : 0, meta: { ...value.meta } };
    }
    if (value.type === "text") {
      const s = String(value.data).trim();
      const n = /^-?\d+$/.test(s)
        ? Number(s)
        : /^0x[0-9a-f]+$/i.test(s)
          ? Number.parseInt(s.slice(2), 16)
          : Number(s);
      if (!Number.isFinite(n)) {
        throw new Error(`as int: cannot parse "${s}"`);
      }
      return { type: "int", data: Math.trunc(n), meta: { ...value.meta } };
    }
    if (value.type === "bytes" && value.data instanceof Uint8Array) {
      if (value.data.length === 0) {
        throw new Error("as int: empty bytes");
      }
      // Big-endian unsigned from up to 6 bytes (safe integer).
      const slice = value.data.subarray(0, Math.min(6, value.data.length));
      let n = 0;
      for (const b of slice) n = n * 256 + b;
      return { type: "int", data: n, meta: { ...value.meta } };
    }
    throw new Error(`as int expects int, text, bytes, or bool (got ${value.type})`);
  }
  // bool
  if (value.type === "bool") {
    return { type: "bool", data: !!value.data, meta: { ...value.meta } };
  }
  if (value.type === "int") {
    return { type: "bool", data: Number(value.data) !== 0, meta: { ...value.meta } };
  }
  if (value.type === "text") {
    const s = String(value.data).trim().toLowerCase();
    if (["true", "yes", "1", "on"].includes(s)) {
      return { type: "bool", data: true, meta: { ...value.meta } };
    }
    if (["false", "no", "0", "off", ""].includes(s)) {
      return { type: "bool", data: false, meta: { ...value.meta } };
    }
    throw new Error(`as bool: cannot parse "${value.data}"`);
  }
  if (value.type === "bytes" && value.data instanceof Uint8Array) {
    return {
      type: "bool",
      data: value.data.some((b) => b !== 0),
      meta: { ...value.meta },
    };
  }
  throw new Error(`as bool expects bool, int, text, or bytes (got ${value.type})`);
}

/**
 * @param {RuntimeBindings} bindings
 * @param {string|undefined|null} [keyRef]  `key=$slot` armored private
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
      "OpenPGP private key required (vault / key panel / key=$slot) — used by gpg.sign and gpg.encrypt -s"
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
    // Reached when a `to=$slot` resolved to a value carrying no usable public
    // key — an empty recipients set, or text that is not armor. Naming the
    // slot and what it should hold beats reporting the internal outcome.
    const ref = token.kind === "slot" ? token.ref : "";
    throw new Error(
      ref
        ? `gpg.encrypt to=${ref}: that slot holds no usable public key. Point it at a lookup result — e.g. \`hkp.search someone@example.com | out ${ref}\`.`
        : "gpg.encrypt: no usable public key among the resolved recipients."
    );
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
 * @param {string|undefined|null} [keyRef]  `key=$slot` armored public or private
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
    "gpg.verify needs an OpenPGP public key (key=$slot, vault key panel, or recipients)"
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
  if (raw.startsWith(SLOT_SIGIL)) {
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
 * Resolve optional bytes from a UTF-8 literal or `$slot` of text/bytes.
 * Empty / missing → null (caller supplies default).
 * @param {object} bindings
 * @param {string|undefined|null} raw
 * @param {string} label
 * @param {{ defaultUtf8?: string }} [opts]
 * @returns {Promise<Uint8Array|null>}
 */
async function resolveBytesOrUtf8Param(bindings, raw, label, opts = {}) {
  const s = String(raw ?? "").trim();
  if (!s) {
    if (opts.defaultUtf8 != null) return textToBytes(String(opts.defaultUtf8));
    return null;
  }
  if (s.startsWith(SLOT_SIGIL)) {
    const resolve = bindings?.resolveSlot;
    if (typeof resolve !== "function") {
      throw new Error(`${label}=${s}: runtime slot resolver missing`);
    }
    const value = resolve(s);
    if (!value) throw new Error(`${label}=${s}: unknown slot`);
    if (value.type === "bytes" && value.data instanceof Uint8Array) {
      return new Uint8Array(value.data);
    }
    if (value.type === "text") return textToBytes(String(value.data));
    throw new Error(`${label}=${s}: slot must be text or bytes`);
  }
  return textToBytes(s);
}

/**
 * Explicit dual-mode for gpg.symencrypt / gpg.symdecrypt.
 * Default `mode=master` (SSS). Passphrase path requires `mode=passphrase`
 * — passphrase alone does not flip the tip shape.
 * @param {Record<string, *>|undefined|null} params
 * @param {string} op
 * @returns {"master"|"passphrase"}
 */
function resolveGpgSymMode(params, op) {
  const rawMode = String(params?.mode ?? "").trim().toLowerCase();
  const pw = String(params?.passphrase ?? "").trim();
  const mode = rawMode || "master";
  if (mode !== "master" && mode !== "passphrase") {
    throw new Error(
      `${op} mode= must be master or passphrase (got ${rawMode || "(empty)"})`
    );
  }
  if (mode === "master" && pw) {
    throw new Error(
      `${op}: passphrase= requires mode=passphrase (default mode=master is the SSS envelope path)`
    );
  }
  if (mode === "passphrase" && !pw) {
    throw new Error(
      `${op} mode=passphrase requires passphrase= or passphrase=$slot`
    );
  }
  return /** @type {"master"|"passphrase"} */ (mode);
}

/**
 * Resolve passphrase= literal or `$slot` text. Empty → null.
 * @param {object} bindings
 * @param {string|undefined|null} raw
 * @param {string} label
 * @returns {Promise<string|null>}
 */
async function resolvePassphraseParam(bindings, raw, label) {
  const s = String(raw ?? "").trim();
  if (!s) return null;
  if (s.startsWith(SLOT_SIGIL)) {
    const resolve = bindings?.resolveSlot;
    if (typeof resolve !== "function") {
      throw new Error(`${label}=${s}: runtime slot resolver missing`);
    }
    const value = resolve(s);
    if (!value) throw new Error(`${label}=${s}: unknown slot`);
    if (value.type === "text") return String(value.data);
    if (value.type === "bytes" && value.data instanceof Uint8Array) {
      return bytesToText(value.data);
    }
    throw new Error(`${label}=${s}: slot must be text (or UTF-8 bytes)`);
  }
  return s;
}

/**
 * Resolve verify signature= from $slot, base64url string, or panel binding.
 * @param {object} bindings
 * @param {string|undefined|null} refOrB64
 * @returns {Promise<Uint8Array>}
 */
async function resolveVerifySignature(bindings, refOrB64) {
  const raw = String(refOrB64 || "").trim();
  if (raw.startsWith(SLOT_SIGIL)) {
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
    throw new Error("verify needs signature=… (base64url or $slot) or sig binding");
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
  // Symmetric: `generateKey` fulfils with one `CryptoKey`, whose `type` is
  // `"secret"`. It was packed as `{ privateKey: key, publicKey: null }` under
  // a `keypair` value — a keypair missing its public half — which is what put
  // `tags: ["keypair"]` and a meaningless `which: "private"` on an AES tile.
  // One key, typed `key`, marked the half it is: none.
  if (alg.startsWith("aes/")) {
    const length = aesLengthFromAlg(alg);
    const key = await crypto.subtle.generateKey(
      { name: "AES-GCM", length },
      true,
      ["encrypt", "decrypt"]
    );
    return {
      type: "key",
      data: key,
      meta: {
        alg,
        algorithm: "AES-GCM",
        symmetric: true,
        sensitive: true,
        which: "secret",
        type: typeOf("key", { alg, which: "secret" }),
      },
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
      type: "key",
      data: key,
      meta: {
        alg,
        algorithm: "HMAC",
        symmetric: true,
        sensitive: true,
        which: "secret",
        type: typeOf("key", { alg, which: "secret" }),
      },
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
  if (!value || (value.type !== "keypair" && value.type !== "key")) {
    throw new Error("export expects a keypair or key");
  }
  const { meta } = value;
  const handles = pipelineKeyHandles(value);
  // Symmetric / unwrap tips store the handle as secretKey (which=secret).
  const priv = handles.privateKey || handles.secretKey;
  const pub = handles.publicKey;
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
 * What a key-import step says when the material is not the key it declared.
 *
 * `alg=` and `which=` are written in the recipe and fix the tip's type before
 * the picker opens; the pasted body arrives afterwards and may only agree. It
 * used to decide instead — `kty` chose `key` or `keypair`, `crv` chose the
 * curve, `d`'s absence chose the half — so `import jwk alg=ec/p256` fed an
 * `oct` JWK compiled clean and then `export pkcs8` shipped 32 raw AES bytes
 * under a recipe that said pkcs8, and `keypair alg=ec/p256` did the same from
 * the Inputs panel.
 *
 * Verbatim, in the `ENCRYPTED_KEY_MESSAGE` register: what was declared, what
 * turned up, and the word that reconciles them. `step` is the clause naming
 * the op, because both `import jwk` and `keypair` reach here.
 * @param {string} step
 * @param {string} declared
 * @param {string} found
 * @param {string} fix
 */
export function keyDeclarationMessage(step, declared, found, fix) {
  return `${step} declares alg=${declared}, but this key material holds ${found}. The tip's type is fixed by the recipe before the material is read, so it cannot be taken from the paste — ${fix}`;
}

/** A step that declared a keypair, handed material with no private half. */
export function noPrivateHalfMessage(step) {
  return `${step} declares a keypair, but this material carries no private half (a JWK with no \`d\`, or an SPKI block alone). Write \`${step.split(" ")[0]} … which=public\` to read the public half as a key tip.`;
}

/** …and the mirror: `which=public` against material with no public half. */
export function noPublicHalfMessage(step) {
  return `${step} which=public, but no public half could be read from this material.`;
}

/**
 * Hold imported JWK material to the `alg=` / `which=` the recipe wrote.
 *
 * Passed a `step` only by the two ops whose declared type is computed from
 * those params — the `import` transform and the `keypair` source. `as` does
 * its own shape handling around `importKey` (`as key` legitimately accepts a
 * public-only JWK and projects it), so it is left alone.
 *
 * @param {import("./webcrypto-ops.js").BoundWebCryptoKey} bound
 * @param {string} step
 * @param {string} alg
 * @param {"private"|"public"} which
 */
function assertJwkMatchesDeclaration(bound, step, alg, which) {
  const declared = String(alg || "").toLowerCase();
  const key = bound.secretKey || bound.privateKey || bound.publicKey;
  const found = algTokenForKey(key);
  if (found && found !== declared) {
    throw new Error(
      keyDeclarationMessage(
        step,
        declared,
        found,
        `write alg=${found}, or paste a ${declared} key.`
      )
    );
  }
  if (genkeyOutputBase(declared) === "key") {
    // Symmetric: one key, and `which=` was already refused at compile time.
    if (!bound.secretKey) {
      throw new Error(
        keyDeclarationMessage(step, declared, "an asymmetric key", "write the alg= it really is.")
      );
    }
    return;
  }
  if (bound.secretKey) {
    throw new Error(
      keyDeclarationMessage(
        step,
        declared,
        'a symmetric key (kty "oct")',
        "a symmetric key is one key and not a pair — use `import jwk alg=aes/256` (or the hmac/… it really is)."
      )
    );
  }
  if (which === "public") {
    if (!bound.publicKey) throw new Error(noPublicHalfMessage(step));
    return;
  }
  if (!bound.privateKey) throw new Error(noPrivateHalfMessage(step));
}

/**
 * @param {PipelineValue|null} value
 * @param {string} format
 * @param {string} alg
 * @param {string} usage
 * @param {string} [padding]
 * @param {string} [hash]
 * @param {{ step: string, which: "private"|"public" }|null} [declared]
 *   set by the ops whose output type is computed from `alg=` / `which=`
 */
async function importKey(
  value,
  format,
  alg,
  usage,
  padding = "pss",
  hash = "sha-256",
  declared = null
) {
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
      hash,
    });
    if (declared) assertJwkMatchesDeclaration(bound, declared.step, alg, declared.which);
    if (declared?.which === "public") {
      return {
        type: "key",
        data: /** @type {CryptoKey} */ (bound.publicKey),
        meta: {
          alg: bound.alg || alg,
          algorithm: bound.alg || alg,
          symmetric: false,
          sensitive: false,
          which: "public",
        },
      };
    }
    const sensitive = !!(bound.privateKey || bound.secretKey);
    // An `oct` JWK is one key. It used to be filed on `privateKey` *and*
    // `secretKey` of a `keypair` bag, which is how a symmetric key came to be
    // read as the private half of a pair.
    if (bound.secretKey) {
      return {
        type: "key",
        data: bound.secretKey,
        meta: {
          alg: bound.alg || alg,
          algorithm: bound.alg || alg,
          symmetric: true,
          sensitive,
          which: "secret",
        },
      };
    }
    return {
      type: "keypair",
      data: {
        privateKey: bound.privateKey || null,
        publicKey: bound.publicKey || null,
      },
      meta: {
        alg: bound.alg || alg,
        algorithm: bound.alg || alg,
        symmetric: false,
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
        type: "key",
        data: publicKey,
        meta: { alg, curve, algorithm: name, which: "public", sensitive: false },
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
        type: "key",
        data: publicKey,
        meta: { alg, algorithm: "Ed25519", which: "public", sensitive: false },
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
        type: "key",
        data: publicKey,
        meta: { alg, algorithm: "X25519", which: "public", sensitive: false },
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
        type: "key",
        data: publicKey,
        meta: {
          alg,
          algorithm: name,
          hash: hashName,
          which: "public",
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

  // Symmetric imports are one key, for the same reason `genkey` is.
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
      type: "key",
      data: key,
      meta: {
        alg,
        algorithm: "AES-GCM",
        symmetric: true,
        sensitive: true,
        which: "secret",
      },
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
      type: "key",
      data: key,
      meta: {
        alg,
        algorithm: "HMAC",
        symmetric: true,
        sensitive: true,
        which: "secret",
      },
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
    .replace(/^[$@]+/, "")
    .replace(/[^\w.-]+/g, "_")
    .replace(/^\.+/, "")
    .slice(0, 64);
  return s || "output";
}

/**
 * Roles that outrank an emit site's `text`/`secret` (§32c, §37).
 *
 * Those two words are not a claim about identity — they are the sensitivity
 * ternary the text and bytes branches have always written (`sensitive ?
 * "secret" : "text"`), and `text` is defined in ARTIFACT_ROLES as "anything
 * with no better description". When the type system *has* a better
 * description, the ternary must not outrank it. Without this, an `out` of an
 * sshsig block wore role `text` while carrying tags `["ssh","signature"]`, so
 * `role: "sshsig"` sat in the vocabulary with nothing able to claim it — and a
 * JWS/JWE landed as `text`/`secret`, which left the shipped `jose-token` kind
 * (§32e) matching nothing at all and the JWT reader unreachable from a
 * notebook.
 *
 * Deliberately a closed set rather than "any projected role wins". `pem`/`der`
 * project to `key`, and the key card reads JWK — promoting a PEM export today
 * would swap a readable armor body for an emptier card. That widening belongs
 * with a KeyCard that can read PEM (§35e), not here.
 *
 * The SSH halves join for the sshsig reason and one more. `ssh.encode`'s two
 * formats are both `text`, so the ternary gave the same private block `secret`
 * through `out $priv` and `text` through a dangling tip — one artifact with
 * two identities, and `ArtifactMatch.role` is exact, so a kind could only ever
 * claim one of them. The half is a fact about the *type*
 * (`text/ssh-private`), which is what makes it this set's business rather than
 * a second tag the emit sites would have to remember.
 *
 * Role rides inside `digestArtifact`, so this moves the digests of sshsig,
 * JOSE and SSH-key artifacts. It is the same change RECEIPT_VERSION 2 was
 * bumped for (§38c) and lands before v2 has shipped, so it needs no second
 * boundary.
 *
 * `public-key` and `secret-key` join for the same reason as the SSH halves:
 * which half a key handle is (or that it is no half at all) is a fact about
 * the *type* — `key/…/public`, `key/…/secret` — and the badge on a tile is the
 * role, so leaving the sensitivity ternary in charge means a public JWK and
 * the private one beside it wear the same word.
 */
const TYPE_OWNED_ROLES = new Set([
  "sshsig",
  "token",
  "ssh-public",
  "ssh-private",
  "public-key",
  "secret-key",
]);

/**
 * What `otp.code` knew and its body cannot say, carried onto the artifact.
 *
 * A code is six digits. *Whose* account it is, *which* time step it belongs to
 * and *how long* that step had left are all facts the op computed and the
 * string does not contain — and unlike a fingerprint or a packet map, none of
 * them can be re-derived from the body, because re-deriving them would mean
 * knowing the secret. `execOtpCode` emits them for exactly this reason; before
 * this they reached nothing.
 *
 * They ride `traits` rather than a field of their own because `traits` is the
 * one bag that already survives every projection between here and a tile — the
 * shell's two `OutputList` mappings list it, and a field a mapping does not
 * list is dropped silently on the way in, which has made a shipped tile inert
 * twice. `jose` above is the same decision made once already: a run-time fact
 * travels with the artifact instead of being recomputed by a widget.
 */
const OTP_META_TRAITS = Object.freeze([
  "otpMode",
  "otpDigits",
  "otpPeriod",
  "otpStep",
  "otpExpiresIn",
  "otpCounter",
  "otpLabel",
  // Not a computed value but an *intent*: whether the recipe named the instant
  // with `at=` or meant "now". It belongs in this bag rather than in a role or
  // a reference back to the step because `digestArtifact` reads `label`,
  // `filename`, `role`, `stepName`, `sensitive`, `length` and a digest of
  // `content` — and neither `traits` nor `tags`. So a trait moves no receipt
  // digest and needs no `RECEIPT_VERSION` bump, where a role would have needed
  // both; that is exactly why v1 → v2 happened. The mechanism, not the
  // convention, is why intent lands here.
  "otpPinnedAt",
]);

/**
 * Stamp refined pipeline type (and raw bytes when available) onto an artifact.
 *
 * Keeping `artifact.bytes` is a memory-safety requirement for file sinks:
 * Encrypt transfers Uint8Array (transferable / wipeable). Do not remove this
 * and force Encrypt to decode `content` strings — immutable strings cannot be
 * zeroed (see `src/lib/memory-safety.js`).
 *
 * `refine` narrows the *artifact's* copy of the refined type where one value
 * produces several artifacts that are not all the same type. The keypair
 * branch of `materializeOutArtifacts` is the case that forced it: one
 * `keypair` value becomes a private JWK and a public JWK, and both used to
 * inherit the value's `which: "private"` verbatim — so the public tile's tags
 * said `public` while its type said `private`. Nothing matched on `which`, so
 * nothing was visibly wrong, which is exactly what was true of `ssh-public`
 * before it bit (7d563cd). The value's type is untouched; only the artifact's
 * copy is narrowed.
 *
 * @param {ToolkitArtifact} artifact
 * @param {PipelineValue} [value]
 * @param {Partial<import("./types.js").RefinedType>} [refine]
 * @returns {ToolkitArtifact}
 */
function attachPipeMeta(artifact, value, refine) {
  if (value?.meta?.type) {
    let pipeType = value.meta.type;
    if (refine) {
      pipeType = { ...pipeType, ...refine };
      // An explicit `undefined` *removes* a refinement rather than setting one
      // to nothing — `{ which: undefined }` is how the whole-keypair tip stops
      // claiming a half, and a key left present with an undefined value would
      // still print in `formatType` and still be enumerable to a test.
      for (const k of Object.keys(refine)) {
        if (refine[k] === undefined) delete pipeType[k];
      }
    }
    artifact.pipeType = pipeType;
    // §32c: the projection is the *floor*, the emit site is the override.
    //
    // Role is a property of the artifact, not of the value: the same `text`
    // emitted by `inspect` and by `out $msg` are one type and two different
    // artifacts, and `receipt`/`diagnostic` come from why the artifact
    // exists, which no projection of a type can know. So a site that
    // declares a role keeps it; a site that declares none stops being
    // role-less. That is what turns a keypair emitted by `out` from
    // "text"/"secret" into role `key`, which is the whole of §35.
    const projected = artifactMetaFromType(pipeType);
    if (!artifact.role && projected.role) artifact.role = projected.role;
    else if (
      (artifact.role === "text" || artifact.role === "secret") &&
      TYPE_OWNED_ROLES.has(projected.role)
    ) {
      artifact.role = projected.role;
    }
    if (projected.tags?.length) {
      const prev = Array.isArray(artifact.tags) ? artifact.tags : [];
      const seen = new Set(prev.map(String));
      artifact.tags = [...prev, ...projected.tags.filter((t) => !seen.has(String(t)))];
    }
  }
  // JOSE body — header/claims/verification verdict, for the JWT reader. Rides
  // here rather than being re-parsed in the UI so that the *verdict* travels
  // with the value: whether a signature was checked is something only the op
  // that ran knows, and a widget that re-derived it from the token text could
  // only ever report "unverified".
  if (value?.meta?.jose) {
    artifact.jose = value.meta.jose;
  }
  // The OTP facts, for the same reason and by the same route (see
  // OTP_META_TRAITS). Copied field by field rather than spreading `meta`, so
  // an op cannot widen what reaches a tile by adding a key.
  if (value?.meta) {
    /** @type {Record<string, *>} */
    const otp = {};
    for (const key of OTP_META_TRAITS) {
      if (value.meta[key] !== undefined) otp[key] = value.meta[key];
    }
    if (Object.keys(otp).length) {
      artifact.traits = { ...(artifact.traits || {}), ...otp };
    }
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
 * The one artifact a network / WebRTC value becomes, wherever it is emitted.
 *
 * Shared by `materializeOutArtifacts` and `valueToArtifacts` because one value
 * described two ways is the failure this exists to prevent: an SDP offer
 * written by `out $offer` and the same offer left dangling at the end of a
 * pipeline are the same value, and `ArtifactMatch.role` is exact — so a kind
 * can only ever claim one of two spellings, and the other silently renders as
 * untyped text (7d563cd, and §35d before it).
 *
 * **No role is declared here, and that is the point.** The seven network bases
 * *are* the definition of `role: "netvalue"` in `artifactMetaFromType`, so the
 * projection supplies it; a second list in this file would be exactly the
 * parallel vocabulary the kind table's header records as deliberately deleted
 * (`hasNetworkRenderer`). `stun.check` is the one exception, and it is an
 * exception about *why* the artifact exists rather than what it is — a
 * reachability verdict carrying the "Configure TURN" affordance, which no
 * projection of `endpoint` could know.
 *
 * The `NETWORK_TYPES` predicate its two callers gate on is wider than those
 * seven: `host`, `channel` and `peer` are IoType vocabulary that **no step
 * outputs**, so this is unreachable for them. If one ever gains a producer it
 * lands as `text` rather than `netvalue`, which is the honest answer — a live
 * `channel` handle has no read-out, and inventing one is the decision to take
 * then, with the base added to `NETWORK_BASES`, not pre-empted here.
 *
 * @param {PipelineValue} value
 * @param {string} label
 * @param {string} fallbackName  filename to use when the op named none
 * @returns {ToolkitArtifact}
 */
function networkArtifact(value, label, fallbackName) {
  // SDP is already text on the wire; the rest carry structured data that
  // renders as JSON, exactly the way `recipients` already does.
  const isSdp = value.type === "sdp";
  return attachPipeMeta(
    {
      label,
      filename: String(value.meta?.filename || "") || fallbackName,
      content: isSdp ? String(value.data) : JSON.stringify(value.data, null, 2),
      sensitive: !!value.meta?.sensitive,
      mime: isSdp ? "application/sdp" : "application/json",
      encoding: "text",
      // stun.check keeps its 22b "Configure TURN" affordance.
      role: value.meta?.stunCheck ? "diagnostic" : undefined,
      tags: ["webrtc", value.type],
      // The pipeline type doubles as the UI's renderer discriminator — a
      // `candidate` artifact draws the typed candidate list, a
      // `stats/candidate-pairs` one draws the pair matrix, and so on. All
      // three ride to the tile through `traits`' neighbours in both of
      // `ToolkitShell`'s `OutputList` mappings and `useNotebook`'s, which is
      // the projection a new field has silently failed to survive four times.
      netType: value.type,
      netKind: value.meta?.kind || value.meta?.statsKind || undefined,
      netData: value.data,
    },
    value
  );
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
    /**
     * An `inspect` snapshot keeps its identity through `out`.
     *
     * `valueToArtifacts`' text branch has honoured `value.meta.inspect` since
     * `inspect` shipped; this one did not, so naming the output changed what
     * the artifact *was*:
     *
     *     "hello" | utf8 | inspect          → role "inspect", tags ["inspect"]
     *     "hello" | utf8 | inspect | out $i → role "text",    tags []
     *
     * Identical bytes, two identities — the `inspect-snapshot` kind claims
     * `role: "inspect"`, so the second one resolved as `text` and lost its
     * structured inspector, and a sensitive value degraded further still to
     * `secret`. It failed by producing a worse tile rather than an error,
     * which is why it survived: nothing was missing, only downgraded.
     *
     * The role is a property of the *artifact*, not of the value, and this is
     * exactly the case that rule exists for — the same text from `inspect` and
     * from `out $msg` is one type and two different artifacts. What `out` adds
     * is a name and a file; what it must not do is forget why the value was
     * asked for. `peek` was never affected, because it pushes `role: "inspect"`
     * itself.
     *
     * The re-encodings above are left alone deliberately. `out encoding=hex`
     * on a snapshot is still a snapshot — the identity is what the step was for
     * — and `inspectSnapshot` is structured data the inspector draws rather
     * than a second copy of the body, so it cannot disagree with the hex.
     */
    const isInspect = !!value.meta?.inspect;
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
          // A share still wins: `sss.split | inspect | out` is not a thing, and
          // if it ever were, which share this is would be the more useful of
          // the two identities by a wide margin.
          role: value.meta?.shareIndex
            ? "share"
            : isInspect
              ? "inspect"
              : value.meta?.sensitive
                ? "secret"
                : "text",
          tags: value.meta?.shareIndex
            ? ["mnemonic", "blip39"]
            : isInspect
              ? ["inspect"]
              : [],
          traits: value.meta?.shareIndex
            ? { shareOf: value.meta.shareIndex, threshold: value.meta.threshold }
            : undefined,
          // Omitted by the op for a sensitive value, on purpose — a snapshot
          // retains raw private JWK fields the masked text dump does not — so
          // this carries whatever `inspect` decided rather than deciding again.
          inspectSnapshot: value.meta?.inspectSnapshot,
          inspectFormat: isInspect
            ? String(value.meta.inspectFormat || "auto")
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

  // Network / WebRTC values (design v2 §25a). One shape, built in one place —
  // see `networkArtifact`, which the dangling-tip path shares.
  if (NETWORK_VALUE_TYPES.has(value.type)) {
    return [
      networkArtifact(
        value,
        label,
        `${stem}${shareSuffix}.${value.type === "sdp" ? "sdp" : "json"}`
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
          role: "recipients",
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

  if (value.type === "keypair" || value.type === "key") {
    const parts = [];
    const handles = pipelineKeyHandles(value);
    /**
     * A symmetric key is not a half, so it is not labelled as one.
     *
     * `handles.privateKey || handles.secretKey` used to collapse the two, and
     * everything downstream inherited the collapse: `genkey aes/256 | out $k`
     * wrote a tile called "k · private JWK", tagged `["keypair", "private"]`,
     * which resolved to the `keypair-private` kind and captioned itself
     * "private half" — of a pair that does not exist. The handles know the
     * difference (`key.type`), so the word does too.
     */
    const secret = handles.secretKey;
    const priv = handles.privateKey;
    const pub = handles.publicKey;
    const held = secret || priv;
    const heldWhich = secret ? "secret" : "private";
    if (held) {
      try {
        const jwk = await crypto.subtle.exportKey("jwk", held);
        // §32c/1.5: declare the role and which half this is. Before this the
        // branch returned bare parts with no `attachPipeMeta` at all, so the
        // `out` fallback stamped both halves `secret` from the *value's*
        // sensitivity — which mislabelled the public JWK as a secret and left
        // the tile with no way to tell the halves apart.
        parts.push(
          attachPipeMeta(
            {
              label: `${label} · ${heldWhich} JWK`,
              filename: `${stem}-${heldWhich}.${extOverride || "jwk.json"}`,
              content: JSON.stringify(jwk, null, 2),
              sensitive: true,
              mime: mimeOverride || "application/json",
              encoding: "jwk",
              role: secret ? "secret-key" : "key",
              // No `keypair` tag on a lone symmetric key: the tag is what the
              // `keypair-private` / `keypair-public` kinds match on, and a
              // key with no counterpart belongs to neither.
              tags: secret ? ["secret"] : ["keypair", "private"],
              traits: value.meta?.alg ? { alg: value.meta.alg } : undefined,
            },
            value,
            // The half this artifact *is*, not the half the value's type
            // happened to name. See `attachPipeMeta`.
            { which: heldWhich }
          )
        );
      } catch (err) {
        parts.push({
          label: `${label} · ${heldWhich}`,
          filename: `${stem}-${heldWhich}.txt`,
          content: `${heldWhich === "secret" ? "Secret" : "Private"} key present but not exportable: ${err?.message || err}`,
          sensitive: true,
          mime: "text/plain",
          encoding: "text",
        });
      }
    }
    if (pub) {
      try {
        const jwk = await crypto.subtle.exportKey("jwk", pub);
        parts.push(
          attachPipeMeta(
            {
              label: `${label} · public JWK`,
              filename: `${stem}-public.${extOverride || "jwk.json"}`,
              content: JSON.stringify(jwk, null, 2),
              sensitive: false,
              mime: mimeOverride || "application/json",
              encoding: "jwk",
              // The badge is the role, so the two halves of one `out` have to
              // differ here or the glance cannot tell them apart. Not a
              // licence to publish — that is the `openpgp-public` kind's
              // declaration, not this word.
              role: "public-key",
              tags: ["keypair", "public"],
              traits: value.meta?.alg ? { alg: value.meta.alg } : undefined,
            },
            value,
            { which: "public" }
          )
        );
      } catch (_) {
        /* ignore */
      }
    }
    if (!parts.length) {
      // A recipe that wrote `out` *did* ask for this one, and there is
      // genuinely nothing to hand over — so unlike the dangling tip below,
      // the body is a sentence rather than nothing at all. What goes is the
      // bracket syntax: `[keypair — no extractable material]` reads as a
      // token some other layer is meant to substitute, and it was the whole
      // of the tile. Stamped with a role too, so it lands on a key tile
      // instead of the fallback's untyped one.
      parts.push(
        attachPipeMeta(
          {
            label,
            filename: `${stem}.txt`,
            content:
              value.type === "key"
                ? "No extractable key material — this key was generated non-extractable."
                : "No extractable key material — this keypair was generated non-extractable.",
            sensitive: value.type !== "key" || value.meta?.which !== "public",
            mime: "text/plain",
            encoding: "text",
            role: "key",
            traits: value.meta?.alg ? { alg: value.meta.alg } : undefined,
          },
          value
        )
      );
    }
    return parts;
  }

  return valueToArtifacts(value, stem);
}

/**
 * The public JWK of a key handle, as text — or undefined when there is none.
 *
 * The one derivation a dangling key tip is allowed to make. §34b's rule is
 * about *where a value lands*, not how sensitive its neighbour is: the public
 * half of a keypair is publishable material, so exporting it to describe the
 * tile is the same permission `openpgp-key` already exercises when it stamps a
 * fingerprint onto a masked private key. The private half is never exported
 * here — `out`/`export` is the only thing that materializes it, which is
 * `ACTION_REASONS.neverAskedFor`'s whole position.
 *
 * @param {CryptoKey|null} pub
 * @returns {Promise<string|undefined>}
 */
async function publicJwkText(pub) {
  if (!pub) return undefined;
  try {
    return JSON.stringify(await crypto.subtle.exportKey("jwk", pub), null, 2);
  } catch (_) {
    // Non-extractable, or an algorithm WebCrypto will not export. The tile
    // simply has less to say; it is not an error to raise at anyone.
    return undefined;
  }
}

/**
 * @param {PipelineValue} value
 * @param {string} [name]
 * @returns {Promise<ToolkitArtifact[]>}
 */
async function valueToArtifacts(value, name = "artifact") {
  if (value.type === "int") {
    return [
      attachPipeMeta(
        {
          label: name,
          filename: `${name}.txt`,
          content: String(value.data),
          sensitive: !!value.meta?.sensitive,
          mime: "text/plain; charset=utf-8",
          encoding: "text",
          disposition: "file",
          role: "text",
          tags: ["int"],
        },
        value
      ),
    ];
  }
  if (value.type === "bool") {
    return [
      attachPipeMeta(
        {
          label: name,
          filename: `${name}.txt`,
          content: value.data ? "true" : "false",
          sensitive: !!value.meta?.sensitive,
          mime: "text/plain; charset=utf-8",
          encoding: "text",
          disposition: "file",
          role: "text",
          tags: ["bool"],
        },
        value
      ),
    ];
  }
  if (value.type === "text") {
    const isInspect = !!value.meta?.inspect;
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
          // `inspect` is an explicit "show me this", so its tile may reveal.
          // Bare pipeline text was never asked to be displayed and stays
          // masked if sensitive.
          revealable: isInspect || undefined,
          tags: isInspect
            ? ["inspect"]
            : value.meta?.sensitive
              ? ["sensitive"]
              : [],
          // Snapshot may be omitted for sensitive tips (no secret retention).
          inspectSnapshot: value.meta?.inspectSnapshot,
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
  if (value.type === "keypair" || value.type === "key") {
    const handles = pipelineKeyHandles(value);
    const pub = handles.publicKey;
    /**
     * Which half this artifact holds, read off the handle rather than off
     * `meta.which`. A symmetric key answers `"secret"` — the platform's own
     * word, and neither half of anything.
     */
    const which = handles.secretKey
      ? "secret"
      : pub && !handles.privateKey
        ? "public"
        : "private";
    /**
     * Both halves present is what makes this a *keypair* rather than a key,
     * and it is a runtime fact rather than a projection of the type: an
     * `import pkcs8` may or may not carry a public half, so only the handles
     * know. `role` is the emit site's to declare for exactly this class of
     * question (§32c) — the same licence `receipt` and `envelope` already use.
     *
     * The symmetric caveat that used to live here is gone: AES and HMAC keys
     * no longer arrive as half-empty `keypair` values, so there is nothing to
     * exclude. `key.type === "secret"` files them under `secretKey`, and
     * `secretKey && privateKey` cannot both be set for one handle.
     */
    const bothHalves = !!(handles.privateKey && pub);
    return [
      attachPipeMeta(
        {
          label: name,
          filename: `${name}.txt`,
          /**
           * **No body, on purpose.** This tip is the value the recipe never
           * asked to see, and materializing it would reverse
           * `ACTION_REASONS.neverAskedFor` — the position §34b is built on.
           * What went is the bracketed instruction that used to *be* the
           * tile: `[keypair — use out or export before emitting]` was a
           * placeholder standing where a value goes, so Copy handed out a
           * sentence about writing more recipe and Download wrote it to a
           * file. An empty body is the honest shape of "nothing was asked
           * for": Copy and Download refuse, in the sentences the action
           * table already owns, and the kind draws the public facts instead.
           */
          content: "",
          sensitive: value.type === "keypair" || which !== "public",
          mime: "text/plain",
          encoding: "text",
          disposition: "file",
          // Both halves → `keypair`; otherwise the half names the role, and
          // `key` is left for the one case that genuinely does not know.
          role: bothHalves
            ? "keypair"
            : which === "secret"
              ? "secret-key"
              : which === "public"
                ? "public-key"
                : "key",
          tags: value.type === "key" ? [which] : ["keypair"],
          /**
           * The public facts, carried where the tile can reach them.
           *
           * `traits` rather than a field of its own because `traits` is the
           * one bag both projections copy wholesale (`useNotebook` and both
           * of the shell's mappings) — the OTP tile learned that the hard
           * way, with three named fields that reached nothing.
           */
          traits: {
            ...(value.meta?.alg ? { alg: value.meta.alg } : null),
            ...(pub ? { publicJwk: await publicJwkText(pub) } : null),
          },
        },
        value,
        // `genkey` types its output `keypair/…/private`, which is a claim
        // about a value that has both halves. Nothing matches on `which`, so
        // nothing was visibly wrong — the same silence `ssh-public` sat in
        // before it bit. The *value's* type is left alone (the validator's
        // overloads never read `which` on a keypair); the artifact's copy
        // stops claiming a half it does not have.
        bothHalves ? { which: undefined } : undefined
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
          // The same traits `materializeOutArtifacts` stamps. Without them the
          // auto-emitted tip of a bare `gpg.genkey` and the tile from
          // `| out $priv` were the same key described two different ways, and
          // the difference was visible: Copy fingerprint sat disabled on the
          // tip, reading "This artifact carries no key to fingerprint" about a
          // key whose fingerprint the step had already computed and put on the
          // public tile beside it. A fingerprint is a public fact about a key,
          // which is exactly what §34b keeps available while the private half
          // stays masked — the rule is about where a value lands, not how
          // sensitive its neighbour is.
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
          role: "recipients",
          tags: ["openpgp", "recipients"],
        },
        value
      ),
    ];
  }
  /**
   * A network value that fell off the end of a pipeline (§25a).
   *
   * There was no branch at all, so `rtc.gather`, `rtc.offer`, `stun.check`,
   * `rtc.certificate`, `rtc.ice`, `rtc.state`, `rtc.check` and friends with no
   * `out` after them returned `[]` — **no tile whatsoever**, which reads as a
   * step that failed rather than one whose result was thrown away. Every one
   * of these is a value a user runs the op specifically to read.
   *
   * The **body is emitted in full**, which is where this parts company with
   * the keypair tip. That tip withholds its body because materializing a
   * private half is what `out` is for, and `ACTION_REASONS.neverAskedFor` is
   * the sentence Copy and Download refuse with. None of that applies here:
   * these values are `sensitive: false` at every emit site, nothing is being
   * held back, and a tile that rendered the whole candidate list from
   * `netData` while Copy said "this value was not asked for" would be an
   * incoherent pair. `recipients` above — the other structured, non-secret
   * dangling tip — already emits its body for exactly this reason.
   *
   * Built by `networkArtifact` rather than here, so this tile and the one
   * `out $label` produces cannot drift into two descriptions of one value.
   */
  if (NETWORK_VALUE_TYPES.has(value.type)) {
    return [
      networkArtifact(value, name, `${name}.${value.type === "sdp" ? "sdp" : "json"}`),
    ];
  }
  return [];
}

export { splitArmoredMessages } from "../pgp/armor.js";
export { bytesToText };
