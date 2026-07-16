import { Auth } from "../lib/auth.js";
import { escapeHtml, fetchJson, showError } from "../lib/utils.js";
import { renderKeysTable, renderUploadCard, wireUploadForm } from "../lib/keys.js";
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

function renderSignedIn(user, keys) {
  const userInfo = `<p style="margin-bottom:1.25rem">Signed in as
      <strong>${escapeHtml(user.email)}</strong></p>`;

  const keysSection =
    keys && keys.length
      ? `<h2>Your keys</h2>
         <p class="muted" style="margin-bottom:0.75rem">Unclaimed pending keys expire after 30 days. Claimed keys can be deleted below.</p>
         ${renderKeysTable(keys, { showClaim: true, showDelete: true })}`
      : `<p class="muted">No keys on file yet for your account. Submit one above.</p>`;

  content.innerHTML = userInfo + renderUploadCard({ signedIn: true }) + keysSection;
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
