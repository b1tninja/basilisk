import { Auth } from "../lib/auth.js";
import { escapeHtml, fetchJson, formatFingerprint, showError } from "../lib/utils.js";
import { renderKeysTable, renderUploadCard, wireUploadForm } from "../lib/keys.js";
import { getDeviceLabel, setDeviceLabel } from "../lib/prefs.js";
import "../css/site.css";

const content = document.getElementById("content");
const error = document.getElementById("error");

async function renderSignedOut() {
  const providers = await Auth.getProviders();
  const buttons = Auth.providerButtons("/my-keys", providers);
  const hint =
    providers.includes("google") && providers.includes("microsoft")
      ? "Sign in with your Microsoft or Google account to view and claim keys associated with your email address."
      : providers.includes("google")
        ? "Sign in with your Google account to view and claim keys associated with your email address."
        : "Sign in with your Microsoft account to view and claim keys associated with your email address.";
  content.innerHTML = `
    ${renderUploadCard({ signedIn: false })}
    <div class="card" style="max-width:440px">
      <p class="card-title">Sign in to manage your keys</p>
      <p class="muted" style="margin-bottom:1.25rem">${hint}</p>
      ${buttons || "<p class='muted'>Sign-in is not configured.</p>"}
    </div>`;
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

      return `
        <details class="key-label-details">
          <summary class="key-label-summary">
            <code class="fpr">${escapeHtml(fpDisplay)}</code>
            ${item.label ? `<span class="key-label">🏷 ${escapeHtml(item.label)}</span>` : ""}
          </summary>
          <div class="key-label-body">
            <div class="key-label-row">
              <div>
                <p class="label-section-title">Key label <span class="badge approved" style="font-size:0.7rem;vertical-align:middle">public</span></p>
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
                <p class="label-section-title">Device label <span class="muted" style="font-size:0.75rem">(private, this browser only)</span></p>
                <p class="muted label-description">Stored only in your browser. Use it to identify which physical card or device holds this key without exposing hardware serial numbers.</p>
              </div>
              ${renderLabelEditor({
                id: `device-label-${fpr}`,
                currentValue: deviceLabel,
                placeholder: "e.g. Blue YubiKey 5C",
                note: "",
              })}
            </div>
          </div>
        </details>`;
    })
    .join("");

  return `
    <h2>Key labels</h2>
    <p class="muted" style="margin-bottom:0.75rem">
      <strong>Key labels</strong> are public and stored on the server.
      <strong>Device labels</strong> are private and stored only in this browser — use them to distinguish physical smart cards without sharing hardware identifiers.
    </p>
    <div class="key-labels-list">${cards}</div>`;
}

function renderSignedIn(user, keys) {
  const userInfo = `<p style="margin-bottom:1.25rem">Signed in as
      <strong>${escapeHtml(user.email)}</strong></p>`;

  const keysSection =
    keys && keys.length
      ? `<h2>Your keys</h2>
         <p class="muted" style="margin-bottom:0.75rem">Unclaimed pending keys expire after 30 days. Claimed keys can be deleted below.</p>
         ${renderKeysTable(keys, { showClaim: true, showDelete: true })}
         ${renderKeyLabelsSection(keys)}`
      : `<p class="muted">No keys on file yet for your account. Submit one above.</p>`;

  content.innerHTML = userInfo + renderUploadCard({ signedIn: true }) + keysSection;
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
      const editor = document.getElementById(editorId);
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
      document.getElementById(editorId)?.querySelector(".label-form")?.classList.add("hidden");
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
    const editor = document.getElementById(editorId);
    if (!editor) return;

    const isDevice = editorId.startsWith("device-label-");
    const fpr = editorId.replace(/^(key|device)-label-/, "");

    if (isDevice) {
      setDeviceLabel(fpr, "", value);
      refreshEditorDisplay(editor, value);
      editor.querySelector(".label-form")?.classList.add("hidden");
      return;
    }

    // Server key label
    const submitBtn = editor.querySelector("button[type=submit]");
    if (submitBtn) { submitBtn.disabled = true; submitBtn.textContent = "Saving…"; }
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
      if (submitBtn) { submitBtn.disabled = false; submitBtn.textContent = "Save"; }
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

async function loadMyKeys() {
  try {
    const user = await Auth.getUser();
    if (!user || !user.authenticated) {
      await renderSignedOut();
      return;
    }
    const payload = await fetchJson("/api/v1/me/keys");
    renderSignedIn(user, payload.keys);
  } catch (err) {
    if (err.status === 401) {
      await renderSignedOut();
    } else {
      showError(error, err.message);
    }
  }
}

wireUploadForm();
document.addEventListener("basilisk:key-submitted", () => {
  setTimeout(loadMyKeys, 800);
});

document.addEventListener("click", async (e) => {
  const btn = e.target.closest?.("[data-delete-fpr]");
  if (!btn) return;
  const fpr = btn.getAttribute("data-delete-fpr");
  if (!fpr) return;
  if (!confirm(`Delete / unpublish key ${fpr}? This cannot be undone.`)) return;
  btn.disabled = true;
  try {
    await fetchJson(`/api/v1/me/keys/${encodeURIComponent(fpr)}`, { method: "DELETE" });
    await loadMyKeys();
  } catch (err) {
    showError(error, err.message || "Delete failed");
    btn.disabled = false;
  }
});

Auth.initWidget(document.getElementById("auth-widget"), "/my-keys");
loadMyKeys();
