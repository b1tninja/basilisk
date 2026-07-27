/**
 * Shared keyserver <select> markup + wiring (Encrypt / Toolkit / Preferences).
 */

import { getPreferredKeyserver, setPreferredKeyserver } from "./prefs.js";
import {
  canUseUpstream,
  getUpstreamConfig,
  isKeyserverAllowed,
  normalizeKeyserverHost,
  resolveUpstreamHost,
} from "./upstream-config.js";
import { pageKeyserverOrigin } from "./upstream-hkp.js";
import { escapeHtml } from "./utils.js";

/**
 * Option list for Toolkit / binder: This site (page origin) + preferred + allowlist.
 * Empty value = This site HKP on `location.origin` (no silent upstream).
 *
 * @param {object} [opts]
 * @param {string[]} [opts.allowlist]
 * @param {string} [opts.preferred]
 * @param {string} [opts.current]  ensure current host appears even if not allowlisted
 * @param {string|null} [opts.pageOrigin]
 * @returns {{ value: string, label: string }[]}
 */
export function buildKeyserverOptions(opts = {}) {
  const pageOrigin =
    opts.pageOrigin !== undefined ? opts.pageOrigin : pageKeyserverOrigin();
  /** @type {{ value: string, label: string }[]} */
  const options = [
    {
      value: "",
      label: pageOrigin ? `This site (${pageOrigin})` : "This site",
    },
  ];
  const seen = new Set([""]);
  const pref = normalizeKeyserverHost(opts.preferred);
  if (pref && !seen.has(pref)) {
    options.push({ value: pref, label: `Preferred upstream (${pref})` });
    seen.add(pref);
  }
  for (const host of opts.allowlist || []) {
    const h = normalizeKeyserverHost(host);
    if (!h || seen.has(h)) continue;
    seen.add(h);
    options.push({ value: h, label: h });
  }
  const cur = normalizeKeyserverHost(opts.current);
  if (cur && !seen.has(cur)) {
    options.push({ value: cur, label: cur });
  }
  return options;
}

/**
 * HTML <select> for This site + allowlisted upstreams (Toolkit HKP steps).
 * Always returns a select (at least This site).
 *
 * @param {object} [opts]
 * @param {string} [opts.id]
 * @param {string} [opts.className]
 * @param {string} [opts.selected]
 * @param {string} [opts.dataAttrs]  extra attributes on <select>
 * @param {import("./upstream-config.js").UpstreamConfig} [opts.config]
 * @param {string|null} [opts.pageOrigin]
 * @returns {Promise<string>}
 */
export async function toolkitKeyserverSelectHtml(opts = {}) {
  const cfg = opts.config || (await getUpstreamConfig());
  const preferred = getPreferredKeyserver();
  const options = buildKeyserverOptions({
    allowlist: cfg.enabled ? cfg.allowlist || [] : [],
    preferred: cfg.enabled ? preferred : "",
    current: opts.selected,
    pageOrigin: opts.pageOrigin,
  });
  const id = opts.id || "keyserver-select";
  const cls = opts.className || "text-input keyserver-select";
  const selectedRaw = opts.selected == null ? "" : String(opts.selected);
  const selected =
    selectedRaw === "" ? "" : normalizeKeyserverHost(selectedRaw) || "";
  const dataAttrs = opts.dataAttrs ? ` ${opts.dataAttrs}` : "";
  const optsHtml = options
    .map((o) => {
      const sel = selected === o.value ? " selected" : "";
      return `<option value="${escapeHtml(o.value)}"${sel}>${escapeHtml(o.label)}</option>`;
    })
    .join("");
  return `<select id="${escapeHtml(id)}" class="${escapeHtml(cls)}" aria-label="Keyserver"${dataAttrs}>${optsHtml}</select>`;
}

/**
 * Sync HTML for builder cells (options prefetched).
 *
 * @param {object} opts
 * @param {{ value: string, label: string }[]} opts.options
 * @param {string} [opts.selected]
 * @param {string} [opts.dataAttrs]
 * @param {string} [opts.className]
 * @returns {string}
 */
export function keyserverSelectFromOptionsHtml(opts) {
  const options = opts.options || buildKeyserverOptions();
  const cls = opts.className || "text-input keyserver-select";
  const selectedRaw = opts.selected == null ? "" : String(opts.selected);
  const selected =
    selectedRaw === "" ? "" : normalizeKeyserverHost(selectedRaw) || "";
  const dataAttrs = opts.dataAttrs ? ` ${opts.dataAttrs}` : "";
  const optsHtml = options
    .map((o) => {
      const sel = selected === o.value ? " selected" : "";
      return `<option value="${escapeHtml(o.value)}"${sel}>${escapeHtml(o.label)}</option>`;
    })
    .join("");
  return `<select class="${escapeHtml(cls)}" aria-label="Keyserver"${dataAttrs}>${optsHtml}</select>`;
}

/**
 * Preferences / Encrypt: upstream-only select (empty = server default).
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
 * Compact control row for recipient search UIs (Encrypt).
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
 * Raw select value: "" = This site; host = explicit upstream. No preferred fallback.
 * @param {string|HTMLSelectElement|null} [elOrId]
 * @returns {string}
 */
export function readKeyserverSelectValue(elOrId) {
  let el = elOrId;
  if (typeof elOrId === "string") {
    el = document.getElementById(elOrId);
  }
  if (el instanceof HTMLSelectElement) {
    return normalizeKeyserverHost(el.value) || "";
  }
  return "";
}

/**
 * Read selection from Encrypt-style select (empty → preferred/server default).
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
