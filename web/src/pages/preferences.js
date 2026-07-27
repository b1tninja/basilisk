/**
 * Browser-local preferences (localStorage).
 */

import { Auth } from "../lib/auth.js";
import {
  keyserverSelectHtml,
  wirePreferredKeyserverSelect,
} from "../lib/keyserver-select.js";
import {
  getExpertMode,
  getPreferredKeyserver,
  setExpertMode,
} from "../lib/prefs.js";
import { cacheClear, cacheList } from "../lib/pubkey-cache.js";
import { getUpstreamConfig } from "../lib/upstream-config.js";
import { escapeHtml } from "../lib/utils.js";
import "../css/site.css";

Auth.initWidget(document.getElementById("auth-widget"), "/preferences");

async function render() {
  const root = document.getElementById("prefs-app");
  if (!root) return;

  const cfg = await getUpstreamConfig();
  const expert = getExpertMode();
  const pref = getPreferredKeyserver();
  const cached = await cacheList();
  const ksSelect = cfg.enabled
    ? await keyserverSelectHtml({
        id: "pref-keyserver",
        includeEmpty: true,
        selected: pref,
        config: cfg,
      })
    : "";

  root.innerHTML = `
    <section class="card prefs-card">
      <p class="card-title">Encrypt UI</p>
      <label class="radio-row">
        <input type="checkbox" id="pref-expert" ${expert ? "checked" : ""}>
        Expert mode (show advanced encryption options)
      </label>
      <p class="muted fs-sm mt-xs mb-0">Stored in this browser only.</p>
    </section>

    <section class="card prefs-card mt-lg">
      <p class="card-title">Upstream keyserver</p>
      ${
        cfg.enabled
          ? `<p class="muted fs-md m-0-b-md">
              When this directory has no match, signed-in lookups can query an allowlisted
              verifying keyserver from your browser (not proxied by Basilisk).
            </p>
            <label class="field-label" for="pref-keyserver">Default upstream</label>
            ${ksSelect}
            <p class="muted fs-sm mt-xs mb-0">
              Allowlist: ${escapeHtml(cfg.allowlist.join(", ") || "—")}.
              Server default: <code>${escapeHtml(cfg.default || "—")}</code>.
            </p>
            <p id="pref-ks-status" class="muted fs-sm mt-sm" role="status"></p>`
          : `<p class="muted fs-md m-0">
              Upstream search is disabled on this server
              (<code>BASILISK_UPSTREAM_ENABLED=0</code>).
            </p>`
      }
    </section>

    <section class="card prefs-card mt-lg">
      <p class="card-title">Local public-key cache</p>
      <p class="muted fs-md m-0-b-md">
        ${cached.length} public key${cached.length === 1 ? "" : "s"} cached in IndexedDB
        on this device (encrypt recipients you have looked up).
      </p>
      <button type="button" class="btn btn-ghost" id="pref-clear-cache">Clear pubkey cache</button>
      <p id="pref-cache-status" class="muted fs-sm mt-sm" role="status"></p>
    </section>
  `;

  document.getElementById("pref-expert")?.addEventListener("change", (e) => {
    const on = !!/** @type {HTMLInputElement} */ (e.target).checked;
    setExpertMode(on);
  });

  const ksEl = /** @type {HTMLSelectElement|null} */ (
    document.getElementById("pref-keyserver")
  );
  wirePreferredKeyserverSelect(ksEl, (host) => {
    const st = document.getElementById("pref-ks-status");
    if (st) {
      st.textContent = host
        ? `Saved preferred keyserver: ${host}`
        : "Using server default.";
    }
  });

  document.getElementById("pref-clear-cache")?.addEventListener("click", async () => {
    await cacheClear();
    const st = document.getElementById("pref-cache-status");
    if (st) st.textContent = "Pubkey cache cleared.";
    // Refresh count
    await render();
  });
}

render();
