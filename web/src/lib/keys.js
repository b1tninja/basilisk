import { Auth } from "./auth.js";
import {
  escapeHtml,
  fetchJson,
  formatFingerprint,
  uidWithSearchLinks,
} from "./utils.js";
import { renderSubmitSnippets, wireSnippetCopy } from "./snippets.js";

export function badgeClass(state) {
  if (state === "approved") return "badge approved";
  if (state === "pending") return "badge pending";
  if (state === "expired") return "badge pending";
  return "badge";
}

function renderUidCell(item) {
  const list = item.approved_uids || item.pending_uids || item.uids || [];
  if (!list.length) return "—";
  return list
    .map((u) => `<div class="uid-cell-line">${uidWithSearchLinks(u)}</div>`)
    .join("");
}

export function renderKeysTable(items, options = {}) {
  if (!items || !items.length) {
    return "<p class='muted'>No keys found.</p>";
  }
  const rows = items.map((item) => {
    const fp = item.fingerprint || "";
    const fpHref = `/key?fpr=${encodeURIComponent(fp)}`;
    let actions = `<a class="text-link" href="${fpHref}">View</a>`;
    if (options.showClaim && item.can_claim && item.claim_url) {
      actions += ` · <a class="text-link" href="/key?fpr=${encodeURIComponent(fp)}&claim=1">Claim</a>`;
    }
    if (options.showDelete) {
      actions += ` · <button type="button" class="text-link link-btn" data-delete-fpr="${escapeHtml(fp)}">Delete</button>`;
    }
    return (
      `<tr>` +
      `<td><a class="text-link fpr" href="${fpHref}">${escapeHtml(formatFingerprint(fp))}</a></td>` +
      `<td><span class="${badgeClass(item.approval_state)}">${escapeHtml(item.approval_state || "")}</span></td>` +
      `<td class="uid-cell">${renderUidCell(item)}</td>` +
      `<td>${actions}</td>` +
      `</tr>`
    );
  });
  return (
    `<div class="table-scroll"><table class="key-table"><thead><tr>` +
    `<th>Fingerprint</th><th>Status</th><th>UIDs</th><th></th>` +
    `</tr></thead><tbody>${rows.join("")}</tbody></table></div>`
  );
}

function renderUploadForm() {
  return `
    <div class="form-group">
      <label for="key-paste">Paste your armored public key</label>
      <textarea id="key-paste" spellcheck="false"
        placeholder="-----BEGIN PGP PUBLIC KEY BLOCK-----&#10;&#10;..."></textarea>
    </div>
    <div class="or-divider">or upload a file</div>
    <div style="display:flex;align-items:center;gap:.75rem;flex-wrap:wrap">
      <label class="file-label" for="key-file">
        <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none"
             stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
          <polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/>
        </svg>
        Choose file
      </label>
      <input type="file" id="key-file" accept=".asc,.gpg,.pgp,text/plain">
      <span class="file-name" id="file-name-display"></span>
    </div>
    <div style="margin-top:1rem">
      <button class="btn" id="submit-key-btn" type="button">Submit key</button>
    </div>
    <div id="submit-status" class="hidden"></div>`;
}

export function renderUploadCard(options = {}) {
  const signedIn = options.signedIn === true;
  const intro = signedIn
    ? "Paste your armored public key or upload a <code>.asc</code> file. It will be associated with your account if a UID matches your email."
    : "Paste your armored public key or upload a <code>.asc</code> file. Sign in above to auto-claim keys that match your email; otherwise you can submit anonymously and claim later.";
  return `
    <div class="card" id="submit-key-card">
      <p class="card-title">Submit a public key</p>
      <p class="muted" style="margin-bottom:1rem">${intro}</p>
      ${renderUploadForm()}
    </div>
    ${renderSubmitSnippets()}`;
}

export async function submitKey() {
  const btn = document.getElementById("submit-key-btn");
  const status = document.getElementById("submit-status");
  const paste = document.getElementById("key-paste");
  const fileInput = document.getElementById("key-file");
  if (!btn || !status) return;

  status.className = "hidden";
  status.textContent = "";

  let keytext = (paste ? paste.value : "").trim();

  if (!keytext && fileInput && fileInput.files && fileInput.files.length) {
    try {
      keytext = (await fileInput.files[0].text()).trim();
    } catch (_) {
      status.textContent = "Could not read file.";
      status.className = "status-row err";
      return;
    }
  }

  if (!keytext) {
    status.textContent = "Please paste or upload a PGP public key.";
    status.className = "status-row err";
    return;
  }

  btn.disabled = true;
  btn.textContent = "Submitting…";

  try {
    const user = await Auth.getUser();
    const authenticated = !!(user && user.authenticated);
    if (authenticated) {
      const result = await fetchJson("/api/v1/me/keys", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ key: keytext }),
      });

      const fp = escapeHtml(result.fingerprint || "");
      const state = escapeHtml(result.approval_state || "pending");
      const dup = result.duplicate ? " (key already on file)" : "";

      status.innerHTML =
        `Key submitted — fingerprint <code>${fp}</code>, ` +
        `status <span class="${badgeClass(result.approval_state)}">${state}</span>${dup}.` +
        (result.claimed ? " Ownership claimed." : "");
      status.className = "status-row ok";
      document.dispatchEvent(new CustomEvent("basilisk:key-submitted", { detail: result }));
    } else {
      const r = await fetch("/pks/add", {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: `keytext=${encodeURIComponent(keytext)}`,
      });
      const body = await r.text();
      if (!r.ok) {
        throw Object.assign(new Error(body.trim() || `Request failed (${r.status})`), {
          status: r.status,
        });
      }

      const claimMatch = body.match(/^Claim:\s*(.+)$/m);
      const claimUrl = claimMatch ? claimMatch[1].trim() : "";
      status.innerHTML = claimUrl
        ? `Key submitted. <a class="text-link" href="${escapeHtml(claimUrl)}">Claim this key</a> to verify ownership.`
        : "Key submitted.";
      status.className = "status-row ok";
    }

    if (paste) paste.value = "";
    if (fileInput) fileInput.value = "";
    const fn = document.getElementById("file-name-display");
    if (fn) fn.textContent = "";
  } catch (err) {
    status.textContent = err.message || "Submission failed.";
    status.className = "status-row err";
  } finally {
    btn.disabled = false;
    btn.textContent = "Submit key";
  }
}

export function wireUploadForm() {
  document.addEventListener("change", (e) => {
    if (e.target && e.target.id === "key-file") {
      const f = e.target.files[0];
      const fn = document.getElementById("file-name-display");
      if (fn) fn.textContent = f ? f.name : "";
      if (f) {
        f.text()
          .then((txt) => {
            const ta = document.getElementById("key-paste");
            if (ta) ta.value = txt.trim();
          })
          .catch(() => {});
      }
    }
  });

  document.addEventListener("click", (e) => {
    if (e.target && e.target.id === "submit-key-btn") {
      e.preventDefault();
      submitKey();
    }
  });

  // Snippet copy buttons may be injected with the upload card.
  wireSnippetCopy(document);
}
