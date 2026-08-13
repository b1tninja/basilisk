/**
 * The account half of the old `/my-keys`: public keys this server holds for you.
 *
 * `my-keys-mount.js` rendered two stores under one possessive heading — the
 * browser vault (private keys, this machine, no account) and "Your keys"
 * (public keys, the server, behind a sign-in). They answer different questions
 * and a reader could not tell which one a sentence was about; the report that
 * started this was a session telling somebody with three of the second that
 * they had none of the first, and both statements were true.
 *
 * The vault moved to the toolkit's Keys tray, where the run that needs it is.
 * What is left is this: publishing a public key, seeing what is published, and
 * taking one down. **Nothing on this page can sign or decrypt**, because
 * nothing on it is a private key — which is why the sign-in gate belongs here
 * and must never be put in front of the vault. A person with a key in this
 * browser has an account with nobody.
 *
 * @module lib/published-mount
 */

import { Auth } from "./auth.js";
import {
  copyButtonHtml,
  escapeHtml,
  fetchJson,
  formatFingerprint,
  showError,
  wireCopyButtons,
} from "./utils.js";
import { renderKeysTable, renderUploadCard, wireUploadForm } from "./keys.js";
import { getDeviceLabel, setDeviceLabel } from "./prefs.js";
import { listKeys as vaultListKeys } from "./vault.js";
import { mdsStatusBadgeHtml } from "./webauthn/mds.js";

/**
 * The one link off this page, and what the place it leads to cannot do.
 *
 * Stated rather than implied, because the two stores are exactly as easy to
 * confuse from this side as they were when they shared a heading. The vault's
 * own link back says the converse.
 */
function renderVaultCrossLink() {
  return `
    <div class="card mt-lg" id="vault-cross-link">
      <p class="card-title">Looking for the keys that can sign?</p>
      <p class="muted mb-0">
        Private keys live in <a class="text-link" href="/toolkit#keys">this browser's vault</a>,
        on the Toolkit's Keys tray — that is where you generate one, import one,
        export one or delete one, and no account is involved.
        <strong>Nothing there is published:</strong> this server has never seen those
        keys, so nobody can search for one or encrypt to you with it until you
        publish its public half here.
      </p>
    </div>`;
}

/**
 * Mount the published-keys UI into `container`.
 * @param {HTMLElement} container
 * @returns {() => void} cleanup
 */
export function mountPublished(container) {
  const content = container.querySelector("#content");
  const error = container.querySelector("#error");

  /** Fingerprints with a delete request in flight, so a second press is a no-op. */
  const deleting = new Set();
  /** @type {Record<string, import("./vault.js").VaultKeyMeta>} */
  let vaultMetaByFpr = {};

  async function renderSignedOut() {
    const providers = await Auth.getProviders();
    const buttons = Auth.providerButtons("/published", providers);
    const hint =
      providers.includes("google") && providers.includes("microsoft")
        ? "Sign in with your Microsoft or Google account to see and claim the public keys published under your email address."
        : providers.includes("google")
          ? "Sign in with your Google account to see and claim the public keys published under your email address."
          : "Sign in with your Microsoft account to see and claim the public keys published under your email address.";
    content.innerHTML = `
      ${renderUploadCard({ signedIn: false })}
      <div class="card maxw-440">
        <p class="card-title">Sign in to see what is published under your address</p>
        <p class="muted mb-xl">${hint}</p>
        ${buttons || "<p class='muted'>Sign-in is not configured.</p>"}
      </div>
      ${renderVaultCrossLink()}`;
  }

  /** Render an inline label editor (key label or device label). */
  function renderLabelEditor({ id, currentValue, placeholder, note }) {
    const escaped = escapeHtml(currentValue || "");
    return `
      <div class="label-editor" id="${escapeHtml(id)}">
        <span class="label-current">${escaped ? `<span class="key-label">🏷 ${escaped}</span>` : `<span class="muted">None</span>`}</span>
        <button type="button" class="btn btn-ghost btn-compact label-edit-trigger"
                data-editor="${escapeHtml(id)}">${currentValue ? "Edit" : "Add"}</button>
        <form class="label-form hidden" data-editor="${escapeHtml(id)}" autocomplete="off">
          <input type="text" class="label-input" maxlength="200"
                 placeholder="${escapeHtml(placeholder)}"
                 value="${escaped}" />
          <button type="submit" class="btn btn-compact">Save</button>
          <button type="button" class="btn btn-ghost btn-compact label-cancel"
                  data-editor="${escapeHtml(id)}">Cancel</button>
          ${currentValue ? `<button type="button" class="btn btn-ghost btn-compact text-error label-clear" data-editor="${escapeHtml(id)}">Remove</button>` : ""}
        </form>
        ${note ? `<p class="muted label-note">${note}</p>` : ""}
      </div>`;
  }

  function renderKeyLabelsSection(keys) {
    if (!keys || !keys.length) return "";
    const cards = keys
      .map((item) => {
        const fpr = item.fingerprint || "";
        const fpDisplay = formatFingerprint(fpr);
        const deviceLabel = getDeviceLabel(fpr);
        const vaultMeta =
          vaultMetaByFpr[String(fpr).toUpperCase().replace(/[^0-9A-F]/g, "")] ||
          null;
        const mdsStatus = vaultMeta?.mdsStatus;
        const mdsDescription = vaultMeta?.mdsDescription || "";

        return `
          <details class="key-label-details">
            <summary class="key-label-summary">
              <code class="fpr">${escapeHtml(fpDisplay)}</code>
              ${copyButtonHtml("Copy", fpr, { title: "Copy fingerprint" })}
              ${item.label ? `<span class="key-label">🏷 ${escapeHtml(item.label)}</span>` : ""}
              ${mdsStatus ? mdsStatusBadgeHtml(mdsStatus, mdsDescription) : ""}
            </summary>
            <div class="key-label-body">
              <div class="key-label-row">
                <div>
                  <p class="label-section-title">Key label <span class="badge approved fs-2xs va-middle">public</span></p>
                  <p class="muted label-description">Shown to anyone who views this key. Use it to describe the key's purpose.</p>
                </div>
                ${renderLabelEditor({
                  id: `key-label-${fpr}`,
                  currentValue: item.label || "",
                  placeholder: "e.g. Work signing key",
                  note: "",
                })}
              </div>
              <hr class="label-divider" />
              <div class="key-label-row">
                <div>
                  <p class="label-section-title">Device label <span class="muted fs-2xs">(private, this browser only)</span></p>
                  <p class="muted label-description">Stored only in your browser. Use it to identify which physical card or device holds the private half without exposing hardware serial numbers.</p>
                </div>
                ${renderLabelEditor({
                  id: `device-label-${fpr}`,
                  currentValue: deviceLabel,
                  placeholder: "e.g. Blue YubiKey 5C",
                  note: mdsStatus
                    ? `${mdsStatusBadgeHtml(mdsStatus, mdsDescription)} Soft check at PRF enroll — does not block unlock.`
                    : "",
                })}
              </div>
            </div>
          </details>`;
      })
      .join("");

    return `
      <h2>Key labels</h2>
      <p class="muted mb-md">
        <strong>Key labels</strong> are public and stored on the server.
        <strong>Device labels</strong> are private and stored only in this browser — use them to distinguish physical smart cards without sharing hardware identifiers.
      </p>
      <div class="key-labels-list">${cards}</div>`;
  }

  async function renderSignedIn(user, keys) {
    const userInfo = `<p class="mb-xl">Signed in as
        <strong>${escapeHtml(user.email)}</strong></p>`;

    // Read for the soft MDS badge on the device-label row only. A vault record
    // is the only place that knows which authenticator protects a key, and the
    // badge is about that device — not about the published key, which is
    // public bytes and protects nothing.
    try {
      const vaultKeys = await vaultListKeys();
      vaultMetaByFpr = Object.fromEntries(vaultKeys.map((k) => [k.fingerprint, k]));
    } catch (_) {
      vaultMetaByFpr = {};
    }

    const keysSection =
      keys && keys.length
        ? `<h2>Published under your address</h2>
           <p class="muted mb-md">Unclaimed pending keys expire after 30 days. Claimed keys can be taken down below.</p>
           ${renderKeysTable(keys, { showClaim: true, showDelete: true })}
           ${renderKeyLabelsSection(keys)}`
        : `<p class="muted">Nothing is published under your address yet. Submit a public key above — you can export one from the browser vault on the Toolkit's Keys tray.</p>`;

    content.innerHTML =
      userInfo +
      renderUploadCard({ signedIn: true }) +
      keysSection +
      renderVaultCrossLink();
    wireKeyLabelEditors(keys || []);
  }

  /** Wire up all inline label editors in the rendered content. */
  function wireKeyLabelEditors(keys) {
    // Map fpr -> current server label for quick lookup
    const serverLabels = Object.fromEntries(
      (keys || []).map((k) => [k.fingerprint, k.label || ""])
    );

    content.addEventListener("click", handleLabelClick);
    content.addEventListener("submit", handleLabelSubmit);

    function handleLabelClick(e) {
      // Toggle edit form open
      const trigger = e.target.closest?.(".label-edit-trigger");
      if (trigger) {
        const editorId = trigger.dataset.editor;
        const editor = content.querySelector("#" + CSS.escape(editorId));
        if (!editor) return;
        const form = editor.querySelector(".label-form");
        if (!form) return;
        form.classList.toggle("hidden");
        if (!form.classList.contains("hidden")) {
          form.querySelector(".label-input")?.focus();
        }
        return;
      }

      // Cancel
      const cancelBtn = e.target.closest?.(".label-cancel");
      if (cancelBtn) {
        const editorId = cancelBtn.dataset.editor;
        content.querySelector("#" + CSS.escape(editorId))?.querySelector(".label-form")?.classList.add("hidden");
        return;
      }

      // Clear (remove)
      const clearBtn = e.target.closest?.(".label-clear");
      if (clearBtn) {
        const editorId = clearBtn.dataset.editor;
        applyLabel(editorId, "");
      }
    }

    function handleLabelSubmit(e) {
      const form = e.target.closest?.(".label-form");
      if (!form) return;
      e.preventDefault();
      const editorId = form.dataset.editor;
      const val = (form.querySelector(".label-input")?.value || "").trim();
      applyLabel(editorId, val);
    }

    async function applyLabel(editorId, value) {
      const editor = content.querySelector("#" + CSS.escape(editorId));
      if (!editor) return;

      const isDevice = editorId.startsWith("device-label-");
      const fpr = editorId.replace(/^(key|device)-label-/, "");

      if (isDevice) {
        setDeviceLabel(fpr, "", value);
        refreshEditorDisplay(editor, value);
        editor.querySelector(".label-form")?.classList.add("hidden");
        return;
      }

      // Server key label. `aria-busy` rather than `disabled`: a control that
      // goes dead mid-flight explains nothing, and a second press here would
      // PUT the same label twice, which the server answers identically.
      const submitBtn = editor.querySelector("button[type=submit]");
      if (submitBtn) {
        submitBtn.setAttribute("aria-busy", "true");
        submitBtn.textContent = "Saving…";
      }
      try {
        const result = await fetchJson(
          `/api/v1/me/keys/${encodeURIComponent(fpr)}/label`,
          {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ label: value }),
          }
        );
        const saved = result.label || "";
        serverLabels[fpr] = saved;
        refreshEditorDisplay(editor, saved);
        editor.querySelector(".label-form")?.classList.add("hidden");

        // Also update the summary badge
        const details = editor.closest("details");
        const summary = details?.querySelector(".key-label-summary");
        if (summary) {
          const existing = summary.querySelector(".key-label");
          if (existing) existing.remove();
          if (saved) {
            const badge = document.createElement("span");
            badge.className = "key-label";
            badge.textContent = `🏷 ${saved}`;
            summary.appendChild(badge);
          }
        }
      } catch (err) {
        showError(error, err.message || "Label save failed");
      } finally {
        if (submitBtn) {
          submitBtn.removeAttribute("aria-busy");
          submitBtn.textContent = "Save";
        }
      }
    }

    function refreshEditorDisplay(editor, newValue) {
      const current = editor.querySelector(".label-current");
      if (current) {
        current.innerHTML = newValue
          ? `<span class="key-label">🏷 ${escapeHtml(newValue)}</span>`
          : `<span class="muted">None</span>`;
      }
      const trigger = editor.querySelector(".label-edit-trigger");
      if (trigger) trigger.textContent = newValue ? "Edit" : "Add";

      // Re-render the form (so the clear button appears/disappears correctly)
      const form = editor.querySelector(".label-form");
      if (form) {
        const input = form.querySelector(".label-input");
        if (input) input.value = newValue;
        const clearBtn = form.querySelector(".label-clear");
        if (newValue && !clearBtn) {
          const cancelBtn = form.querySelector(".label-cancel");
          if (cancelBtn) {
            const newClear = document.createElement("button");
            newClear.type = "button";
            newClear.className = "btn btn-ghost btn-compact text-error label-clear";
            newClear.dataset.editor = editor.id;
            newClear.textContent = "Remove";
            cancelBtn.insertAdjacentElement("afterend", newClear);
          }
        } else if (!newValue && clearBtn) {
          clearBtn.remove();
        }
      }
    }
  }

  async function loadPublished() {
    try {
      const user = await Auth.getUser();
      if (!user || !user.authenticated) {
        await renderSignedOut();
        return;
      }
      const payload = await fetchJson("/api/v1/me/keys");
      await renderSignedIn(user, payload.keys);
    } catch (err) {
      if (err.status === 401) {
        await renderSignedOut();
      } else {
        showError(error, err.message);
      }
    }
  }

  wireUploadForm();
  const onKeySubmitted = () => setTimeout(loadPublished, 800);
  container.addEventListener("basilisk:key-submitted", onKeySubmitted);

  const onDeleteClick = async (e) => {
    const btn = e.target.closest?.("[data-delete-fpr]");
    if (!btn) return;
    const fpr = btn.getAttribute("data-delete-fpr");
    if (!fpr) return;
    if (deleting.has(fpr)) return;
    if (
      !confirm(
        `Unpublish key ${fpr}? The server stops handing it out; the private half, wherever it is, is untouched.`
      )
    ) {
      return;
    }
    deleting.add(fpr);
    btn.setAttribute("aria-busy", "true");
    try {
      await fetchJson(`/api/v1/me/keys/${encodeURIComponent(fpr)}`, { method: "DELETE" });
      await loadPublished();
    } catch (err) {
      showError(error, err.message || "Delete failed");
    } finally {
      deleting.delete(fpr);
      btn.removeAttribute("aria-busy");
    }
  };
  container.addEventListener("click", onDeleteClick);

  wireCopyButtons();
  loadPublished();

  return () => {
    container.removeEventListener("basilisk:key-submitted", onKeySubmitted);
    container.removeEventListener("click", onDeleteClick);
  };
}
