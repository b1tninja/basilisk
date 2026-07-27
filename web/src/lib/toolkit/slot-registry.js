/**
 * Live @slot registry for toolkit recipes / notebook kernel.
 */

import { slotLabelKey } from "./recipe-parse.js";
import { formatType, typeOf } from "./types.js";

/**
 * @typedef {import("./engine.js").PipelineValue} PipelineValue
 */

/**
 * Deep-enough clone for pipeline values held in slots.
 * @param {PipelineValue} value
 * @returns {PipelineValue}
 */
export function clonePipelineValue(value) {
  if (!value) return value;
  if (value.type === "bytes" && value.data instanceof Uint8Array) {
    return {
      type: "bytes",
      data: new Uint8Array(value.data),
      meta: { ...value.meta },
    };
  }
  if (value.type === "text") {
    return { type: "text", data: String(value.data), meta: { ...value.meta } };
  }
  if (value.type === "item") {
    const inner = value.data?.value;
    return {
      type: "item",
      data: {
        key: value.data?.key,
        value: inner ? clonePipelineValue(inner) : inner,
      },
      meta: { ...value.meta },
    };
  }
  if (value.type === "shares") {
    const d = value.data || {};
    return {
      type: "shares",
      data: {
        ...d,
        mnemonics: d.mnemonics ? d.mnemonics.map((m) => String(m)) : d.mnemonics,
        raw: d.raw
          ? d.raw.map((s) => ({
              index: s.index,
              data: s.data instanceof Uint8Array ? new Uint8Array(s.data) : s.data,
            }))
          : d.raw,
      },
      meta: { ...value.meta },
    };
  }
  if (value.type === "keypair") {
    return {
      type: "keypair",
      data: value.data,
      meta: { ...value.meta },
    };
  }
  if (value.type === "recipients") {
    return {
      type: "recipients",
      data: Array.isArray(value.data)
        ? value.data.map((r) => (r && typeof r === "object" ? { ...r } : r))
        : [],
      meta: { ...value.meta },
    };
  }
  if (value.type === "openpgp-key") {
    return {
      type: "openpgp-key",
      data: String(value.data || ""),
      meta: { ...value.meta },
    };
  }
  return { type: value.type, data: value.data, meta: { ...value.meta } };
}

/**
 * @typedef {object} SlotMeta
 * @property {string} label
 * @property {string} type
 * @property {boolean} sensitive
 * @property {string} [fingerprint]
 * @property {number} [recipients]
 * @property {number} [length]
 */

/**
 * @returns {{
 *   register: (nameRef: string, value: PipelineValue, opts?: { allowReplace?: boolean, preexisting?: Set<string> }) => void,
 *   resolve: (ref: string) => PipelineValue,
 *   has: (ref: string) => boolean,
 *   clear: () => void,
 *   labels: () => string[],
 *   listMetas: () => SlotMeta[],
 *   snapshotKeys: () => Set<string>,
 *   size: () => number,
 * }}
 */
export function createSlotRegistry() {
  /** @type {Map<string, PipelineValue>} */
  const slotsByLabel = new Map();
  /** @type {PipelineValue[]} */
  const slotsByIndex = [];

  /**
   * @param {string} nameRef
   * @param {PipelineValue} value
   * @param {{ allowReplace?: boolean, preexisting?: Set<string> }} [opts]
   */
  const register = (nameRef, value, opts = {}) => {
    const cloned = clonePipelineValue(value);
    if (value.meta?.shareIndex) {
      slotsByIndex.push(cloned);
      return;
    }
    const key = slotLabelKey(nameRef);
    if (key) {
      if (slotsByLabel.has(key)) {
        const canReplace =
          opts.allowReplace &&
          opts.preexisting &&
          opts.preexisting.has(key);
        if (!canReplace) {
          throw new Error(`Duplicate out slot @${key}`);
        }
        slotsByLabel.set(key, cloned);
        return;
      }
      slotsByLabel.set(key, cloned);
    }
    slotsByIndex.push(cloned);
  };

  /**
   * @param {string} ref
   * @returns {PipelineValue}
   */
  const resolve = (ref) => {
    const r = String(ref || "");
    if (/^\d+$/.test(r)) {
      const n = Number(r);
      const v = slotsByIndex[n - 1];
      if (!v) throw new Error(`in ${r}: no slot at index ${r}`);
      return clonePipelineValue(v);
    }
    const key = slotLabelKey(r);
    const v = key ? slotsByLabel.get(key) : undefined;
    if (!v) {
      throw new Error(
        `in ${r}: unknown slot (register earlier with out ${r.startsWith("@") ? r : `@${key}`})`
      );
    }
    return clonePipelineValue(v);
  };

  /**
   * @param {string} ref
   */
  const has = (ref) => {
    const r = String(ref || "");
    if (/^\d+$/.test(r)) {
      return !!slotsByIndex[Number(r) - 1];
    }
    const key = slotLabelKey(r);
    return !!(key && slotsByLabel.has(key));
  };

  const clear = () => {
    slotsByLabel.clear();
    slotsByIndex.length = 0;
  };

  const labels = () => [...slotsByLabel.keys()];

  const snapshotKeys = () => new Set(slotsByLabel.keys());

  /**
   * Metas only — safe for Variables drawer (no armor / key material).
   * @returns {SlotMeta[]}
   */
  const listMetas = () => {
    /** @type {SlotMeta[]} */
    const out = [];
    for (const [label, value] of slotsByLabel) {
      const t =
        value?.meta?.type ||
        typeOf(/** @type {import("./registry.js").IoType} */ (value?.type || "none"));
      const meta = {
        label,
        type: typeof t === "string" ? t : formatType(t),
        sensitive: !!value?.meta?.sensitive || value?.type === "openpgp-key",
      };
      if (value?.meta?.fingerprint) {
        meta.fingerprint = String(value.meta.fingerprint);
      }
      if (value?.type === "recipients" && Array.isArray(value.data)) {
        meta.recipients = value.data.length;
      }
      if (value?.type === "bytes" && value.data instanceof Uint8Array) {
        meta.length = value.data.length;
      }
      if (value?.type === "text" || value?.type === "openpgp-key") {
        meta.length = String(value.data || "").length;
      }
      out.push(meta);
    }
    return out.sort((a, b) => a.label.localeCompare(b.label));
  };

  return {
    register,
    resolve,
    has,
    clear,
    labels,
    listMetas,
    snapshotKeys,
    size: () => slotsByLabel.size,
  };
}
