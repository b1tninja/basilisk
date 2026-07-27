/**
 * Named toolkit notebook library (localStorage) + file import/export helpers.
 *
 * Stores title + recipe source only — never Inputs, kernel slots, or private keys.
 * XSS can read localStorage; refuse recipes that look like secret material.
 */

import { recipeLooksSecret } from "./fragment.js";

export const WORKSPACE_STORE_KEY = "basilisk.toolkit.workspaces";
export const WORKSPACE_SCHEMA_VERSION = 1;
export const WORKSPACE_MAX_ENTRIES = 40;
/** Soft cap on serialized library JSON size. */
export const WORKSPACE_MAX_BYTES = 1_500_000;

/**
 * @typedef {{
 *   v: number,
 *   id: string,
 *   title: string,
 *   recipe: string,
 *   updatedAt: string,
 * }} ToolkitWorkspace
 */

/**
 * @param {string} title
 * @param {string} recipe
 * @returns {string}
 */
export function workspaceFingerprint(title, recipe) {
  return `${String(title || "").trim()}\0${String(recipe || "").trim()}`;
}

/**
 * @returns {string}
 */
export function newWorkspaceId() {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }
  return `ws-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
}

/**
 * @param {unknown} raw
 * @returns {ToolkitWorkspace|null}
 */
export function normalizeWorkspace(raw) {
  if (!raw || typeof raw !== "object") return null;
  const o = /** @type {Record<string, unknown>} */ (raw);
  const id = String(o.id || "").trim();
  const recipe = String(o.recipe ?? "").trim();
  if (!id || !recipe) return null;
  const title = String(o.title || "").trim() || "Untitled notebook";
  const updatedAt =
    typeof o.updatedAt === "string" && o.updatedAt
      ? o.updatedAt
      : new Date().toISOString();
  return {
    v: WORKSPACE_SCHEMA_VERSION,
    id,
    title: title.slice(0, 120),
    recipe,
    updatedAt,
  };
}

/**
 * @param {{ getItem?: (k: string) => string|null }} [storage]
 * @returns {ToolkitWorkspace[]}
 */
export function listWorkspaces(storage = typeof localStorage !== "undefined" ? localStorage : undefined) {
  if (!storage?.getItem) return [];
  try {
    const raw = storage.getItem(WORKSPACE_STORE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed
      .map((w) => normalizeWorkspace(w))
      .filter(/** @returns {w is ToolkitWorkspace} */ (w) => !!w)
      .sort((a, b) => String(b.updatedAt).localeCompare(String(a.updatedAt)));
  } catch {
    return [];
  }
}

/**
 * @param {ToolkitWorkspace[]} list
 * @param {{ setItem?: (k: string, v: string) => void }} [storage]
 * @returns {{ ok: true } | { ok: false, reason: string }}
 */
function writeList(list, storage) {
  if (!storage?.setItem) {
    return { ok: false, reason: "localStorage is not available." };
  }
  const json = JSON.stringify(list);
  if (json.length > WORKSPACE_MAX_BYTES) {
    return {
      ok: false,
      reason: "Workspace library is full — delete some entries or export to a file.",
    };
  }
  try {
    storage.setItem(WORKSPACE_STORE_KEY, json);
    return { ok: true };
  } catch {
    return {
      ok: false,
      reason: "Could not write workspace library (storage full or blocked).",
    };
  }
}

/**
 * @param {string} id
 * @param {{ getItem?: (k: string) => string|null }} [storage]
 * @returns {ToolkitWorkspace|null}
 */
export function getWorkspace(id, storage = typeof localStorage !== "undefined" ? localStorage : undefined) {
  const want = String(id || "").trim();
  if (!want) return null;
  return listWorkspaces(storage).find((w) => w.id === want) || null;
}

/**
 * @param {{ id?: string, title?: string, recipe: string }} input
 * @param {{ getItem?: (k: string) => string|null, setItem?: (k: string, v: string) => void }} [storage]
 * @returns {{ ok: true, workspace: ToolkitWorkspace } | { ok: false, reason: string }}
 */
export function saveWorkspace(
  input,
  storage = typeof localStorage !== "undefined" ? localStorage : undefined
) {
  const recipe = String(input?.recipe ?? "").trim();
  if (!recipe) {
    return { ok: false, reason: "Nothing to save — notebook is empty." };
  }
  if (recipeLooksSecret(recipe)) {
    return {
      ok: false,
      reason:
        "Recipe looks like it contains secret material — keep private keys in Inputs / the vault, not the library.",
    };
  }
  const title = String(input?.title || "").trim() || "Untitled notebook";
  let list = listWorkspaces(storage);
  const id = String(input?.id || "").trim() || newWorkspaceId();
  const existing = list.findIndex((w) => w.id === id);
  /** @type {ToolkitWorkspace} */
  const workspace = {
    v: WORKSPACE_SCHEMA_VERSION,
    id,
    title: title.slice(0, 120),
    recipe,
    updatedAt: new Date().toISOString(),
  };
  if (existing >= 0) {
    list[existing] = workspace;
  } else {
    if (list.length >= WORKSPACE_MAX_ENTRIES) {
      return {
        ok: false,
        reason: `Library limit (${WORKSPACE_MAX_ENTRIES}) reached — delete an entry first.`,
      };
    }
    list = [workspace, ...list];
  }
  // Keep newest-first
  list.sort((a, b) => String(b.updatedAt).localeCompare(String(a.updatedAt)));
  const written = writeList(list, storage);
  if (!written.ok) return written;
  return { ok: true, workspace };
}

/**
 * @param {string} id
 * @param {{ getItem?: (k: string) => string|null, setItem?: (k: string, v: string) => void }} [storage]
 * @returns {{ ok: true } | { ok: false, reason: string }}
 */
export function deleteWorkspace(
  id,
  storage = typeof localStorage !== "undefined" ? localStorage : undefined
) {
  const want = String(id || "").trim();
  if (!want) return { ok: false, reason: "Missing workspace id." };
  const next = listWorkspaces(storage).filter((w) => w.id !== want);
  return writeList(next, storage);
}

/**
 * Pretty JSON for download.
 * @param {ToolkitWorkspace} ws
 * @returns {string}
 */
export function exportWorkspaceBlob(ws) {
  const normalized = normalizeWorkspace(ws);
  if (!normalized) throw new Error("Invalid workspace");
  return `${JSON.stringify(normalized, null, 2)}\n`;
}

/**
 * Parse a downloaded workspace JSON or plain recipe text.
 * @param {string} text
 * @param {{ filename?: string }} [opts]
 * @returns {{ ok: true, workspace: Omit<ToolkitWorkspace, "id"|"updatedAt"> & { id?: string, updatedAt?: string } }
 *   | { ok: false, reason: string }}
 */
export function parseWorkspaceFile(text, opts = {}) {
  const raw = String(text ?? "").trim();
  if (!raw) {
    return { ok: false, reason: "File is empty." };
  }
  if (recipeLooksSecret(raw)) {
    return {
      ok: false,
      reason:
        "File looks like it contains secret material — keep private keys out of recipe files.",
    };
  }

  if (raw.startsWith("{")) {
    try {
      const parsed = JSON.parse(raw);
      const ws = normalizeWorkspace(parsed);
      if (!ws) {
        return { ok: false, reason: "JSON is not a valid Basilisk workspace." };
      }
      if (recipeLooksSecret(ws.recipe)) {
        return {
          ok: false,
          reason:
            "Workspace recipe looks like it contains secret material.",
        };
      }
      return { ok: true, workspace: ws };
    } catch {
      return { ok: false, reason: "Could not parse workspace JSON." };
    }
  }

  const base = String(opts.filename || "")
    .replace(/\.(basilisk\.)?json$/i, "")
    .replace(/\.(txt|recipe)$/i, "")
    .trim();
  return {
    ok: true,
    workspace: {
      v: WORKSPACE_SCHEMA_VERSION,
      title: base || "Imported recipe",
      recipe: raw,
    },
  };
}
