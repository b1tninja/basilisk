/**
 * Shared recipient loading + lightweight picker UI for Encrypt and Toolkit.
 * Identities are never serialized into toolkit recipes — only bound at run time.
 */

import { readKey } from "openpgp";
import { keyHitHtml, keyPillExtrasHtml } from "./key-hit.js";
import { supportsSeipdV2 } from "./pgp/capabilities.js";
import { normalizeSearchQuery } from "./pgp/verify-fpr.js";
import { sortByTrust } from "./trust.js";
import {
  escapeHtml,
  fetchJson,
  fetchText,
  formatFingerprint,
  uidEmail,
} from "./utils.js";

const ENCRYPT_FLAG = 0x04 | 0x08;

/**
 * @typedef {{
 *   fingerprint: string,
 *   keyId: string,
 *   label: string,
 *   email: string,
 *   userLabel: string,
 *   keyExpiration: string|null,
 *   approvalState: string,
 *   revoked: boolean,
 *   valid: boolean,
 *   error: string,
 *   pgpKey: import("openpgp").Key | null,
 *   modernCapable: boolean,
 *   armoredKey: string,
 * }} Recipient
 */

function uidLabel(uids) {
  const list = uids || [];
  if (!list.length) return "";
  const uid = list[0];
  if (uid && typeof uid === "object") {
    const email = uid.email || "";
    const name = (uid.name || "").trim();
    if (name && email) return `${name} <${email}>`;
    return email || uid.raw || "";
  }
  return typeof uid === "string" ? uid : "";
}

function hasEncryptCapability(pgpKey) {
  try {
    const keys = [pgpKey, ...(pgpKey.subkeys || []).map((s) => s)];
    for (const k of keys) {
      const pkt = k.keyPacket || k;
      if (pkt && pkt.flags != null && pkt.flags & ENCRYPT_FLAG) return true;
    }
  } catch (_) {
    /* fall through */
  }
  return false;
}

/**
 * Fetch and validate a recipient public key from the keyserver.
 * @param {string} fingerprint
 * @returns {Promise<Recipient>}
 */
export async function loadRecipientKey(fingerprint) {
  const clean = String(fingerprint)
    .toUpperCase()
    .replace(/[^0-9A-F]/g, "");
  const [meta, armored] = await Promise.all([
    fetchJson(`/api/v1/key/${encodeURIComponent(clean)}`),
    fetchText(`/pks/lookup?op=get&search=${encodeURIComponent(`0x${clean}`)}`),
  ]);
  if (!String(armored).includes("BEGIN PGP")) {
    throw new Error("Could not fetch public key");
  }
  const pgpKey = await readKey({ armoredKey: armored });
  const uids = meta.approved_uids || meta.pending_uids || [];
  const label = uidLabel(uids) || formatFingerprint(clean);
  const email = uidEmail(uids[0]) || "";
  let valid = true;
  let err = "";
  if (meta.revoked) {
    valid = false;
    err = "Key is revoked";
  } else if (meta.approval_state !== "approved") {
    valid = false;
    err = `Key is ${meta.approval_state || "not approved"}`;
  } else if (!hasEncryptCapability(pgpKey)) {
    try {
      await pgpKey.getEncryptionKey();
    } catch (_) {
      valid = false;
      err = "No encryption-capable subkey";
    }
  }
  if (valid) {
    try {
      await pgpKey.getEncryptionKey();
    } catch (_) {
      valid = false;
      err = "No encryption-capable subkey";
    }
  }
  const modernCapable = valid ? await supportsSeipdV2(pgpKey) : false;
  return {
    fingerprint: clean,
    keyId: meta.key_id || clean.slice(-16),
    label,
    email,
    userLabel: String(meta.label || "").trim(),
    keyExpiration: meta.key_expiration || null,
    approvalState: meta.approval_state || "",
    revoked: !!meta.revoked,
    valid,
    error: err,
    pgpKey: valid ? pgpKey : null,
    modernCapable,
    armoredKey: valid ? pgpKey.armor() : "",
  };
}

/**
 * Search keys by query (email / fpr / key id).
 * @param {string} q
 * @returns {Promise<{ results: object[], warning: string, reason: string }>}
 */
export async function searchRecipientsPayload(q) {
  const query = normalizeSearchQuery(q);
  if (query.length < 2) return { results: [], warning: "", reason: "empty" };
  const payload = await fetchJson(
    `/api/v1/search?q=${encodeURIComponent(query)}`
  );
  return {
    results: payload.results || payload.keys || [],
    warning: String(payload.warning || ""),
    reason: String(payload.reason || ""),
  };
}

/**
 * Search keys by query (email / fpr / key id).
 * @param {string} q
 * @returns {Promise<object[]>}
 */
export async function searchRecipients(q) {
  return (await searchRecipientsPayload(q)).results;
}

/**
 * Mount a multi-slot recipient binder for toolkit Run.
 *
 * @param {HTMLElement} host
 * @param {object} opts
 * @param {number} opts.slots
 * @param {boolean} [opts.foreach]
 * @param {(recipients: Recipient[]) => void} opts.onChange
 */
export function mountRecipientBinder(host, opts) {
  const slots = Math.max(1, Number(opts.slots) || 1);
  const foreach = !!opts.foreach;
  /** @type {(Recipient|null)[]} */
  const bound = Array.from({ length: slots }, () => null);
  let sameForAll = false;

  const render = () => {
    host.innerHTML = `
      <div class="recipient-binder">
        <p class="muted m-0-b-md fs-md">
          Choose GPG recipients and confirm fingerprints before running.
          Identities are not stored in the recipe.
        </p>
        ${
          foreach && slots > 1
            ? `<label class="radio-row mb-md">
                <input type="checkbox" id="binder-same-all" ${sameForAll ? "checked" : ""}>
                Same recipient for all shares
              </label>`
            : ""
        }
        <div class="binder-slots">
          ${bound
            .map((r, i) => {
              if (sameForAll && i > 0) return "";
              const title = foreach ? `Share ${i + 1} of ${slots}` : "Recipient";
              const extras = r
                ? keyPillExtrasHtml({
                    fingerprint: r.fingerprint,
                    userLabel: r.userLabel,
                    label: r.userLabel,
                    keyExpiration: r.keyExpiration,
                    key_id: r.keyId,
                  })
                : "";
              const pill = r
                ? `<span class="recipient-pill">
                     <span class="pill-body">
                       <span class="pill-label">${escapeHtml(r.label)}</span>
                       <a class="text-link fpr pill-fpr" href="/key?fpr=${escapeHtml(r.fingerprint)}" target="_blank" rel="noopener">
                         ${escapeHtml(formatFingerprint(r.fingerprint))}
                       </a>
                       ${extras ? `<span class="pill-extras">${extras}</span>` : ""}
                     </span>
                     <button type="button" class="pill-remove" data-clear="${i}" aria-label="Clear">×</button>
                   </span>`
                : `<span class="muted">Not selected</span>`;
              return `
                <div class="binder-slot" data-slot="${i}">
                  <p class="field-label">${escapeHtml(title)}</p>
                  <div class="btn-row wrap items-center">
                    <input type="search" class="text-input binder-search flex-1 minw-180" data-slot="${i}"
                           placeholder="Email, fingerprint, or key ID"
                           autocomplete="off">
                    <button type="button" class="btn btn-ghost btn-compact binder-go" data-slot="${i}">Look up</button>
                  </div>
                  <div class="binder-hits" data-slot="${i}"></div>
                  <div class="binder-current mt-xs">${pill}</div>
                </div>`;
            })
            .join("")}
        </div>
      </div>`;

    host.querySelector("#binder-same-all")?.addEventListener("change", (e) => {
      sameForAll = !!/** @type {HTMLInputElement} */ (e.target).checked;
      if (sameForAll && bound[0]) {
        for (let i = 1; i < slots; i++) bound[i] = bound[0];
      }
      render();
      emit();
    });

    host.querySelectorAll(".binder-go").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const i = Number(btn.getAttribute("data-slot"));
        const input = host.querySelector(`.binder-search[data-slot="${i}"]`);
        const q = input instanceof HTMLInputElement ? input.value.trim() : "";
        const hitsEl = host.querySelector(`.binder-hits[data-slot="${i}"]`);
        if (!hitsEl) return;
        hitsEl.innerHTML = `<p class="muted">Searching…</p>`;
        try {
          const hex = q.replace(/[^0-9A-Fa-f]/g, "");
          if (hex.length >= 16) {
            const r = await loadRecipientKey(hex.length >= 40 ? hex.slice(-40) : hex);
            await select(i, r);
            return;
          }
          const { results, warning } = await searchRecipientsPayload(q);
          const sorted = sortByTrust(results);
          if (!sorted.length) {
            hitsEl.innerHTML = `<p class="muted">No keys found.</p>`;
            return;
          }
          const caution = warning
            ? `<p class="name-search-caution" role="status"><strong>Short key ID.</strong> ${escapeHtml(warning)}</p>`
            : "";
          hitsEl.innerHTML =
            caution +
            sorted
              .slice(0, 12)
              .map((k) => {
                const fpr = String(k.fingerprint || "").toUpperCase();
                return keyHitHtml(k, {
                  dataAttrs: {
                    "data-pick": fpr,
                    "data-slot": String(i),
                  },
                });
              })
              .join("");
          hitsEl.querySelectorAll("[data-pick]").forEach((el) => {
            el.addEventListener("click", async () => {
              const fpr = el.getAttribute("data-pick") || "";
              const slot = Number(el.getAttribute("data-slot"));
              const r = await loadRecipientKey(fpr);
              await select(slot, r);
            });
          });
        } catch (err) {
          hitsEl.innerHTML = `<p class="status-row err">${escapeHtml(err?.message || "Lookup failed")}</p>`;
        }
      });
    });

    host.querySelectorAll("[data-clear]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const i = Number(btn.getAttribute("data-clear"));
        bound[i] = null;
        if (sameForAll) for (let j = 0; j < slots; j++) bound[j] = null;
        render();
        emit();
      });
    });
  };

  /**
   * @param {number} i
   * @param {Recipient} r
   */
  async function select(i, r) {
    if (!r.valid) throw new Error(r.error || "Invalid recipient key");
    bound[i] = r;
    if (sameForAll) for (let j = 0; j < slots; j++) bound[j] = r;
    render();
    emit();
  }

  function emit() {
    const list = sameForAll
      ? Array.from({ length: slots }, () => bound[0]).filter(Boolean)
      : bound.filter(Boolean);
    // For foreach, require all slots
    if (foreach && !sameForAll) {
      opts.onChange(bound.every(Boolean) ? /** @type {Recipient[]} */ (bound.slice()) : []);
    } else {
      opts.onChange(/** @type {Recipient[]} */ (list));
    }
  }

  render();
  return {
    getRecipients: () =>
      sameForAll
        ? Array.from({ length: slots }, () => bound[0]).filter(Boolean)
        : bound.filter(Boolean),
    destroy: () => {
      host.innerHTML = "";
    },
  };
}
