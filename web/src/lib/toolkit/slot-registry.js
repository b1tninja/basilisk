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
  if (value.type === "int") {
    const n = Number(value.data);
    return {
      type: "int",
      data: Number.isFinite(n) ? Math.trunc(n) : 0,
      meta: { ...value.meta },
    };
  }
  if (value.type === "bool") {
    return { type: "bool", data: !!value.data, meta: { ...value.meta } };
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
 * Best-effort wipe of owned secret buffers in a pipeline value.
 * Inlines fill(0) per memory-safety.js (no shared zeroBuffer helper).
 * @param {PipelineValue|null|undefined} value
 */
export function wipePipelineValue(value) {
  if (!value) return;
  try {
    if (value.data instanceof Uint8Array && value.data.byteLength > 0) {
      value.data.fill(0);
    }
  } catch (_) {
    /* never throw from cleanup */
  }
  if (value.type === "shares" && value.data) {
    const raw = value.data.raw;
    if (Array.isArray(raw)) {
      for (const s of raw) {
        try {
          if (s?.data instanceof Uint8Array && s.data.byteLength > 0) {
            s.data.fill(0);
          }
        } catch (_) {
          /* ignore */
        }
      }
    }
  }
  if (value.type === "item" && value.data?.value) {
    wipePipelineValue(value.data.value);
  }
  if (value.type === "keypair" && value.data) {
    const raw = value.data.raw || value.data.privateRaw;
    try {
      if (raw instanceof Uint8Array && raw.byteLength > 0) raw.fill(0);
    } catch (_) {
      /* ignore */
    }
  }
  // Drop string refs (cannot wipe JS strings — only drop reachability).
  if (value.type === "openpgp-key" || value.type === "text") {
    value.data = "";
  }
  if (value.meta) {
    const snap = value.meta.inspectSnapshot;
    if (snap) wipeInspectSnapshot(snap);
    value.meta.inspectSnapshot = undefined;
  }
}

/**
 * @param {import("./inspect.js").InspectSnapshot|null|undefined} snap
 */
function wipeInspectSnapshot(snap) {
  if (!snap) return;
  try {
    if (snap.bytes instanceof Uint8Array && snap.bytes.byteLength > 0) {
      snap.bytes.fill(0);
    }
  } catch (_) {
    /* ignore */
  }
  if (typeof snap.text === "string") snap.text = "";
  if (snap.shares?.mnemonics) {
    snap.shares.mnemonics = snap.shares.mnemonics.map(() => "");
  }
  const kp = snap.keypair;
  if (kp) {
    try {
      if (kp.raw instanceof Uint8Array && kp.raw.byteLength > 0) kp.raw.fill(0);
    } catch (_) {
      /* ignore */
    }
    if (kp.privateJwk && typeof kp.privateJwk === "object") {
      for (const k of ["d", "p", "q", "dp", "dq", "qi", "k"]) {
        if (k in kp.privateJwk) kp.privateJwk[k] = "";
      }
    }
    kp.privateJwk = undefined;
    kp.hasPrivate = false;
  }
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
 *   evictSensitive: () => void,
 *   deleteSlot: (label: string) => void,
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
    for (const value of slotsByLabel.values()) {
      wipePipelineValue(value);
    }
    for (const value of slotsByIndex) {
      wipePipelineValue(value);
    }
    slotsByLabel.clear();
    slotsByIndex.length = 0;
  };

  /**
   * Wipe + remove private / sensitive slots (agent Lock-all path).
   * Keeps public recipients / public keys.
   */
  const evictSensitive = () => {
    /** @type {string[]} */
    const drop = [];
    for (const [label, value] of slotsByLabel) {
      const privateKey =
        value?.type === "openpgp-key" &&
        String(value?.meta?.which || "") !== "public";
      const sensitive =
        !!value?.meta?.sensitive ||
        value?.type === "keypair" ||
        value?.type === "shares" ||
        privateKey;
      if (sensitive) drop.push(label);
    }
    for (const label of drop) {
      const v = slotsByLabel.get(label);
      wipePipelineValue(v);
      slotsByLabel.delete(label);
    }
    // Rebuild index without sensitive entries
    const kept = slotsByIndex.filter((v) => {
      const privateKey =
        v?.type === "openpgp-key" && String(v?.meta?.which || "") !== "public";
      const sensitive =
        !!v?.meta?.sensitive ||
        v?.type === "keypair" ||
        v?.type === "shares" ||
        privateKey;
      if (sensitive) {
        wipePipelineValue(v);
        return false;
      }
      return true;
    });
    slotsByIndex.length = 0;
    slotsByIndex.push(...kept);
  };

  /**
   * Wipe + remove a single labeled slot (Variables drawer per-row Clear).
   * @param {string} label
   */
  const deleteSlot = (label) => {
    const key = slotLabelKey(String(label || ""));
    if (!key) return;
    const value = slotsByLabel.get(key);
    if (!value) return;
    wipePipelineValue(value);
    slotsByLabel.delete(key);
  };

  const labels = () => [...slotsByLabel.keys()];

  /**
   * Cloned indexed slots (foreach `out` values carry `shareIndex` and land
   * here) — what the `shares` op falls back to when nothing was pasted.
   * @returns {PipelineValue[]}
   */
  const indexed = () => slotsByIndex.map((v) => clonePipelineValue(v));

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
      // Length of private armor / sensitive text is itself a minor leak — omit.
      if (
        (value?.type === "text" || value?.type === "openpgp-key") &&
        !meta.sensitive
      ) {
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
    evictSensitive,
    deleteSlot,
    labels,
    indexed,
    listMetas,
    snapshotKeys,
    size: () => slotsByLabel.size,
  };
}
