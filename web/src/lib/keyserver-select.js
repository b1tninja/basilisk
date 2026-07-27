/**
 * Shared upstream keyserver <select> markup + wiring (Encrypt / Toolkit / Preferences).
 */

import { getPreferredKeyserver, setPreferredKeyserver } from "./prefs.js";
import {
  canUseUpstream,
  getUpstreamConfig,
  isKeyserverAllowed,
  normalizeKeyserverHost,
  resolveUpstreamHost,
} from "./upstream-config.js";
import { escapeHtml } from "./utils.js";

/**
 * @param {object} [opts]
 * @param {string} [opts.id]
 * @param {string} [opts.className]
 * @param {boolean} [opts.includeEmpty]  empty option = "Server default"
 * @param {string} [opts.selected]  force selected host
 * @param {import("./upstream-config.js").UpstreamConfig} [opts.config]
 * @returns {Promise<string>} HTML for a <select>, or "" if upstream disabled / empty allowlist
 */
export async function keyserverSelectHtml(opts = {}) {
  const cfg = opts.config || (await getUpstreamConfig());
  if (!cfg.enabled || !(cfg.allowlist || []).length) return "";
  const id = opts.id || "keyserver-select";
  const cls = opts.className || "text-input keyserver-select";
  const includeEmpty = opts.includeEmpty !== false;
  const selected =
    normalizeKeyserverHost(opts.selected) ||
    normalizeKeyserverHost(getPreferredKeyserver()) ||
    "";
  const options = [];
  if (includeEmpty) {
    const defLabel = cfg.default ? `Server default (${cfg.default})` : "Server default";
    options.push(
      `<option value=""${selected ? "" : " selected"}>${escapeHtml(defLabel)}</option>`
    );
  }
  for (const host of cfg.allowlist) {
    const h = normalizeKeyserverHost(host);
    if (!h) continue;
    const sel = selected === h ? " selected" : "";
    options.push(`<option value="${escapeHtml(h)}"${sel}>${escapeHtml(h)}</option>`);
  }
  return `<select id="${escapeHtml(id)}" class="${escapeHtml(cls)}" aria-label="Upstream keyserver">${options.join("")}</select>`;
}

/**
 * Compact control row for recipient search UIs.
 * @param {object} [opts]
 * @param {string} [opts.id]
 * @returns {Promise<string>}
 */
export async function keyserverControlRowHtml(opts = {}) {
  const cfg = await getUpstreamConfig();
  if (!cfg.enabled) return "";
  const ok = await canUseUpstream();
  const select = await keyserverSelectHtml({
    id: opts.id || "recipient-keyserver",
    includeEmpty: true,
    config: cfg,
  });
  if (!select) return "";
  const hint = ok
    ? "Used when this directory has no match."
    : "Sign in to search upstream keyservers.";
  return `<div class="keyserver-control" data-upstream-ready="${ok ? "1" : "0"}">
    <label class="field-label" for="${escapeHtml(opts.id || "recipient-keyserver")}">Upstream keyserver</label>
    <div class="btn-row wrap items-center gap-sm">
      ${select}
      <a class="text-link fs-sm" href="/preferences">Preferences</a>
    </div>
    <p class="muted fs-sm mt-xs mb-0">${escapeHtml(hint)}</p>
  </div>`;
}

/**
 * Read current selection from a select element (or preferred/default).
 * @param {string|HTMLSelectElement|null} [elOrId]
 * @returns {Promise<string>}
 */
export async function readKeyserverSelection(elOrId) {
  let el = elOrId;
  if (typeof elOrId === "string") {
    el = document.getElementById(elOrId);
  }
  if (el instanceof HTMLSelectElement) {
    const v = normalizeKeyserverHost(el.value);
    if (v) return resolveUpstreamHost(v);
  }
  return resolveUpstreamHost();
}

/**
 * Wire a select to persist preferred keyserver on change (Preferences page).
 * @param {HTMLSelectElement|null} select
 * @param {(host: string) => void} [onChange]
 */
export function wirePreferredKeyserverSelect(select, onChange) {
  if (!(select instanceof HTMLSelectElement)) return;
  select.addEventListener("change", async () => {
    const cfg = await getUpstreamConfig();
    const host = normalizeKeyserverHost(select.value);
    if (host && !isKeyserverAllowed(host, cfg.allowlist)) {
      select.value = "";
      setPreferredKeyserver("");
      onChange?.("");
      return;
    }
    setPreferredKeyserver(host || "");
    onChange?.(host || "");
  });
}
