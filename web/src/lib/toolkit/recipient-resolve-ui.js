/**
 * Recipient lookup modal for gpg.encrypt to=email (Check Names–style resolve).
 * UI copy: "Look up recipients" — never "Check Names".
 */

import { keyHitHtml } from "../key-hit.js";
import {
  loadRecipientKey,
  searchRecipientsPayload,
} from "../recipient-picker.js";
import { sortByTrust } from "../trust.js";
import { escapeHtml, formatFingerprint } from "../utils.js";
import {
  filterRecipients,
  recipientFromSearchHit,
  recipientResolutionKey,
} from "./recipients-ops.js";

/**
 * @typedef {object} ResolveResult
 * @property {string[]} fingerprints
 * @property {boolean} [pinAsFpr]
 */

/**
 * Magnifying-glass SVG for lookup buttons.
 * @param {string} [className]
 */
export function lookupGlyphHtml(className = "lookup-glyph") {
  return `<svg class="${className}" width="16" height="16" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><circle cx="8.5" cy="8.5" r="5"/><path d="M12.5 12.5L17 17"/></svg>`;
}

/**
 * Open modal to pick recipients for a query.
 * @param {{
 *   query: string,
 *   policy?: "ask"|"one"|"all",
 *   showAll?: boolean,
 * }} opts
 * @returns {Promise<ResolveResult|null>} null if cancelled
 */
export function openRecipientResolveModal(opts) {
  const query = String(opts.query || "").trim();
  const policy = String(opts.policy || "ask").toLowerCase();

  return new Promise((resolve) => {
    const overlay = document.createElement("div");
    overlay.className = "recipient-resolve-overlay";
    overlay.setAttribute("role", "dialog");
    overlay.setAttribute("aria-modal", "true");
    overlay.setAttribute("aria-label", `Matches for ${query}`);

    let showAll = !!opts.showAll;
    /** @type {Set<string>} */
    const selected = new Set();
    /** @type {import("./recipients-ops.js").ToolkitRecipient[]} */
    let hits = [];
    let preselectAll = policy === "all";

    const close = (result) => {
      overlay.remove();
      document.removeEventListener("keydown", onKey);
      resolve(result);
    };

    const onKey = (e) => {
      if (e.key === "Escape") close(null);
    };
    document.addEventListener("keydown", onKey);

    const render = () => {
      const list = showAll
        ? hits
        : filterRecipients(hits, { approved: true, encrypt: true });
      const title = query
        ? `Matches for ${escapeHtml(query)}`
        : "Look up recipients";
      overlay.innerHTML = `
        <div class="recipient-resolve-modal">
          <div class="recipient-resolve-head">
            <h2 class="recipient-resolve-title">${title}</h2>
            <button type="button" class="btn btn-ghost btn-compact" data-cancel aria-label="Cancel">✕</button>
          </div>
          <p class="muted fs-sm mb-sm" data-status>Searching…</p>
          <label class="field-label field-label-inline mb-sm">
            <input type="checkbox" data-show-all ${showAll ? "checked" : ""}>
            Show pending / all
          </label>
          <div class="recipient-resolve-hits" data-hits></div>
          <div class="btn-row wrap mt-md recipient-resolve-actions">
            <button type="button" class="btn btn-ghost" data-cancel>Cancel</button>
            <button type="button" class="btn" data-use ${policy === "one" ? "hidden" : ""}>${
              policy === "all" ? "Use all selected" : "Use selected"
            }</button>
          </div>
        </div>`;

      overlay.querySelectorAll("[data-cancel]").forEach((el) => {
        el.addEventListener("click", () => close(null));
      });
      overlay.querySelector("[data-show-all]")?.addEventListener("change", (e) => {
        showAll = !!(e.target instanceof HTMLInputElement && e.target.checked);
        paintHits();
      });
      overlay.querySelector("[data-use]")?.addEventListener("click", () => {
        if (!selected.size) return;
        close({ fingerprints: [...selected] });
      });
      void loadHits().then(paintHits);
    };

    const paintHits = () => {
      const status = overlay.querySelector("[data-status]");
      const hitsEl = overlay.querySelector("[data-hits]");
      if (!hitsEl) return;
      const list = showAll
        ? hits
        : filterRecipients(hits, { approved: true, encrypt: true });
      if (status) {
        status.textContent = list.length
          ? `${list.length} key${list.length === 1 ? "" : "s"}`
          : hits.length
            ? "No usable approved keys (try Show pending / all)"
            : "No keys found";
      }
      if (!list.length) {
        hitsEl.innerHTML = `<p class="muted">No matches.</p>`;
        return;
      }
      if (preselectAll) {
        for (const r of list) selected.add(r.fingerprint);
        preselectAll = false;
      }
      const multi = (policy === "ask" || policy === "all") && list.length > 1;
      hitsEl.innerHTML = list
        .map((r) => {
          const fpr = r.fingerprint;
          const checked = selected.has(fpr) ? "checked" : "";
          if (multi) {
            return `<label class="recipient-resolve-row">
              <input type="checkbox" data-fpr="${escapeHtml(fpr)}" ${checked}>
              <span class="recipient-resolve-hit-body">
                <span class="hit-label">${escapeHtml(r.label || r.email || fpr)}</span>
                <span class="muted mono fs-xs">${escapeHtml(formatFingerprint(fpr))}</span>
                <span class="muted fs-xs">${escapeHtml(r.approvalState || "")}</span>
              </span>
            </label>`;
          }
          return keyHitHtml(
            {
              fingerprint: fpr,
              label: r.label,
              email: r.email,
              approval_state: r.approvalState,
              approvalState: r.approvalState,
            },
            {
              dataAttrs: { "data-pick": fpr },
            }
          );
        })
        .join("");

      hitsEl.querySelectorAll("[data-fpr]").forEach((el) => {
        el.addEventListener("change", () => {
          const fpr = el.getAttribute("data-fpr") || "";
          if (el instanceof HTMLInputElement && el.checked) selected.add(fpr);
          else selected.delete(fpr);
        });
      });
      hitsEl.querySelectorAll("[data-pick]").forEach((el) => {
        el.addEventListener("click", () => {
          const fpr = el.getAttribute("data-pick") || "";
          if (fpr) close({ fingerprints: [fpr] });
        });
      });
    };

    const loadHits = async () => {
      if (!query) {
        hits = [];
        return;
      }
      const hex = query.replace(/[^0-9A-Fa-f]/g, "");
      if (hex.length >= 40) {
        try {
          const r = await loadRecipientKey(hex.slice(-40));
          const row = recipientFromSearchHit({
            fingerprint: r.fingerprint || hex.slice(-40),
            armoredKey: r.armoredKey,
            label: r.label,
            email: r.email,
            approval_state: r.approvalState || (r.valid ? "approved" : "pending"),
            valid: r.valid,
          });
          hits = row ? [row] : [];
        } catch {
          hits = [];
        }
        return;
      }
      const payload = await searchRecipientsPayload(query);
      hits = sortByTrust(payload.results || [])
        .map(recipientFromSearchHit)
        .filter(Boolean)
        // Same removal as `resolveRecipientQuery` below: promoting an unknown
        // capability to `true` here is what put a signing-only key in this
        // modal's default list looking exactly like a key that can receive.
        .map((r) => ({
          ...r,
          approvalState: r.approvalState || "approved",
        }));
    };

    document.body.appendChild(overlay);
    overlay.addEventListener("click", (e) => {
      if (e.target === overlay) close(null);
    });
    render();
  });
}

/**
 * Resolve a to= query without opening a modal when unambiguous / policy allows.
 * @param {{
 *   query: string,
 *   policy?: string,
 * }} opts
 * @returns {Promise<{
 *   status: "bound"|"ask"|"none"|"fail",
 *   fingerprints?: string[],
 *   message?: string,
 *   hits?: import("./recipients-ops.js").ToolkitRecipient[],
 * }>}
 */
export async function lookupRecipientsForPolicy(opts) {
  const query = String(opts.query || "").trim();
  const policy = String(opts.policy || "ask").toLowerCase();
  if (!query) {
    return { status: "none", message: "Enter an email or name to look up" };
  }

  const payload = await searchRecipientsPayload(query);
  const all = (payload.results || [])
    .map(recipientFromSearchHit)
    .filter(Boolean)
    // `encryptCapable: r.encryptCapable !== false` used to sit here and promote
    // the directory's "cannot tell" to "yes"; `valid` beside it was the identity
    // on a boolean. What the row mapping decided is what this resolves against.
    .map((r) => ({
      ...r,
      approvalState: r.approvalState || "approved",
    }));
  const approved = filterRecipients(all, { approved: true, encrypt: true });

  if (!approved.length) {
    return {
      status: "none",
      // Not "no encrypt-capable keys": nothing here read a certificate, so the
      // state that is true is that the directory has no approved key it can
      // offer — revoked and expired ones having been dropped on its own word.
      message: payload.reason || "No usable approved keys in the directory",
      hits: all,
    };
  }

  if (policy === "one") {
    if (approved.length !== 1) {
      return {
        status: "fail",
        message: `policy=one expects exactly one key, found ${approved.length}`,
        hits: approved,
      };
    }
    return { status: "bound", fingerprints: [approved[0].fingerprint], hits: approved };
  }

  if (policy === "all") {
    if (approved.length === 1) {
      return {
        status: "bound",
        fingerprints: [approved[0].fingerprint],
        hits: approved,
      };
    }
    return { status: "ask", hits: approved };
  }

  // ask
  if (approved.length === 1) {
    return {
      status: "bound",
      fingerprints: [approved[0].fingerprint],
      hits: approved,
    };
  }
  return { status: "ask", hits: approved };
}

/**
 * @param {string} query
 * @param {Record<string, string[]>} resolutions
 */
export function resolutionForQuery(query, resolutions) {
  const key = recipientResolutionKey(query);
  return resolutions[key] || resolutions[query] || null;
}

/**
 * Short pill label for resolved fingerprints.
 * @param {string[]} fingerprints
 */
export function resolutionPillText(fingerprints) {
  if (!fingerprints?.length) return "";
  if (fingerprints.length === 1) {
    return formatFingerprint(fingerprints[0]);
  }
  return `${fingerprints.length} keys · ${formatFingerprint(fingerprints[0])}…`;
}
