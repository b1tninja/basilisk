/* ===== Utilities ===== */

function escapeHtml(text) {
  const d = document.createElement("div");
  d.textContent = text;
  return d.innerHTML;
}

function queryParam(name) {
  return new URLSearchParams(window.location.search).get(name) || "";
}

function showError(el, msg) {
  el.textContent = msg;
  el.classList.remove("hidden");
}

async function fetchJson(url, opts) {
  const r = await fetch(url, { credentials: "include", ...opts });
  if (!r.ok) {
    const txt = await r.text().catch(() => "");
    let msg = txt;
    try { msg = JSON.parse(txt).error || txt; } catch (_) {}
    throw Object.assign(new Error(msg || `Request failed (${r.status})`), { status: r.status });
  }
  return r.json();
}

async function fetchText(url) {
  const r = await fetch(url, { credentials: "include" });
  if (!r.ok) throw new Error(`Request failed (${r.status})`);
  return r.text();
}

/* ===== Auth Module ===== */

const Auth = (() => {
  let _user = undefined; // undefined = not fetched yet, null = not signed in
  let _providers = undefined;

  async function getProviders() {
    if (_providers !== undefined) return _providers;
    try {
      const cfg = await fetchJson("/api/v1/auth/config");
      _providers = Array.isArray(cfg.providers) ? cfg.providers : ["microsoft"];
    } catch (_) {
      _providers = ["microsoft"];
    }
    return _providers;
  }

  async function getUser() {
    if (_user !== undefined) return _user;
    try {
      _user = await fetchJson("/api/v1/me");
    } catch (e) {
      _user = null;
    }
    return _user;
  }

  // Absolute URL on the public host (custom domain / Front Door). Relative paths make
  // Easy Auth resolve against *.azurewebsites.net when the origin Host is rewritten.
  function postLoginRedirect(redirectUrl) {
    if (redirectUrl && /^https?:\/\//i.test(redirectUrl)) return redirectUrl;
    const path = redirectUrl || (window.location.pathname + window.location.search) || "/";
    return new URL(path, window.location.origin).href;
  }

  function signInMenu(redirectUrl, providers) {
    const enc = encodeURIComponent(postLoginRedirect(redirectUrl));
    const links = [];
    if (providers.includes("microsoft")) {
      links.push(`<a href="/.auth/login/aad?post_login_redirect_uri=${enc}">
          ${ICON_MICROSOFT} Sign in with Microsoft
        </a>`);
    }
    if (providers.includes("google")) {
      links.push(`<a href="/.auth/login/google?post_login_redirect_uri=${enc}">
          ${ICON_GOOGLE} Sign in with Google
        </a>`);
    }
    if (!links.length) {
      return `<p class="muted" style="font-size:.85rem">Sign-in is not configured.</p>`;
    }
    return `
      <div class="sign-in-menu" id="sign-in-menu" hidden>
        ${links.join("")}
      </div>`;
  }

  function providerButtons(redirectUrl, providers) {
    const enc = encodeURIComponent(postLoginRedirect(redirectUrl));
    const buttons = [];
    if (providers.includes("microsoft")) {
      buttons.push(`<a class="provider-btn" href="/.auth/login/aad?post_login_redirect_uri=${enc}">
            ${ICON_MICROSOFT}
            Sign in with Microsoft
          </a>`);
    }
    if (providers.includes("google")) {
      buttons.push(`<a class="provider-btn" href="/.auth/login/google?post_login_redirect_uri=${enc}">
            ${ICON_GOOGLE}
            Sign in with Google
          </a>`);
    }
    return buttons.join("");
  }

  async function initWidget(container, redirectUrl) {
    if (!container) return;
    const [user, providers] = await Promise.all([getUser(), getProviders()]);
    if (!user || !user.authenticated) {
      const menu = signInMenu(redirectUrl || window.location.pathname, providers);
      if (menu.includes("sign-in-menu")) {
        container.innerHTML = `
        <div class="sign-in-trigger">
          <button class="btn-sign-in" onclick="Auth.toggleMenu(event)">Sign in ▾</button>
          ${menu}
        </div>`;
      } else {
        container.innerHTML = menu;
      }
    } else {
      const home = encodeURIComponent(window.location.origin + "/");
      container.innerHTML = `
        <span class="auth-email" title="${escapeHtml(user.email)}">${escapeHtml(user.email)}</span>
        <a class="auth-signout" href="/.auth/logout?post_logout_redirect_uri=${home}">Sign out</a>`;
    }
  }

  function toggleMenu(e) {
    e.stopPropagation();
    const menu = document.getElementById("sign-in-menu");
    if (!menu) return;
    const show = menu.hidden;
    menu.hidden = !show;
    if (show) {
      document.addEventListener("click", () => { menu.hidden = true; }, { once: true });
    }
  }

  return { getUser, getProviders, initWidget, toggleMenu, providerButtons };
})();

/* ===== SVG Icons ===== */

const ICON_MICROSOFT = `<svg class="provider-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 21 21">
  <rect width="10" height="10" fill="#f25022"/>
  <rect x="11" width="10" height="10" fill="#7fba00"/>
  <rect y="11" width="10" height="10" fill="#00a4ef"/>
  <rect x="11" y="11" width="10" height="10" fill="#ffb900"/>
</svg>`;

const ICON_GOOGLE = `<svg class="provider-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">
  <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
  <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
  <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
  <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
</svg>`;

/* ===== Key Table ===== */

function badgeClass(state) {
  if (state === "approved") return "badge approved";
  if (state === "pending") return "badge pending";
  return "badge";
}

function renderKeysTable(items, options = {}) {
  if (!items || !items.length) {
    return "<p class='muted'>No keys found.</p>";
  }
  const rows = items.map((item) => {
    const uids = (item.approved_uids || item.pending_uids || item.uids || []).join(", ") || "—";
    const fp = item.fingerprint || "";
    let actions = `<a class="text-link" href="/key?fpr=${encodeURIComponent(fp)}">View</a>`;
    if (options.showClaim && item.can_claim && item.claim_url) {
      actions += ` · <a class="text-link" href="${escapeHtml(item.claim_url)}">Claim</a>`;
    }
    return (
      `<tr>` +
      `<td><code>${escapeHtml(fp)}</code></td>` +
      `<td><span class="${badgeClass(item.approval_state)}">${escapeHtml(item.approval_state || "")}</span></td>` +
      `<td style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escapeHtml(uids)}</td>` +
      `<td>${actions}</td>` +
      `</tr>`
    );
  });
  return (
    `<table class="key-table"><thead><tr>` +
    `<th>Fingerprint</th><th>Status</th><th>UIDs</th><th></th>` +
    `</tr></thead><tbody>${rows.join("")}</tbody></table>`
  );
}

/* ===== Key Upload Form ===== */

function renderUploadCard(options = {}) {
  const signedIn = options.signedIn === true;
  const intro = signedIn
    ? "Paste your armored public key or upload a <code>.asc</code> file. It will be associated with your account if a UID matches your email."
    : "Paste your armored public key or upload a <code>.asc</code> file. Sign in above to auto-claim keys that match your email; otherwise you can submit anonymously and claim later.";
  return `
    <div class="card" id="submit-key-card">
      <p class="card-title">Submit a public key</p>
      <p class="muted" style="margin-bottom:1rem">${intro}</p>
      ${renderUploadForm()}
    </div>`;
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
      <button class="btn" id="submit-key-btn" type="button" onclick="submitKey()">Submit key</button>
    </div>
    <div id="submit-status" class="hidden"></div>`;
}

async function submitKey() {
  const btn = document.getElementById("submit-key-btn");
  const status = document.getElementById("submit-status");
  const paste = document.getElementById("key-paste");
  const fileInput = document.getElementById("key-file");

  status.className = "hidden";
  status.textContent = "";

  let keytext = (paste ? paste.value : "").trim();

  if (!keytext && fileInput && fileInput.files && fileInput.files.length) {
    try {
      keytext = await fileInput.files[0].text();
      keytext = keytext.trim();
    } catch (e) {
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
    } else {
      const r = await fetch("/pks/add", {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: `keytext=${encodeURIComponent(keytext)}`,
      });
      const body = await r.text();
      if (!r.ok) {
        throw Object.assign(new Error(body.trim() || `Request failed (${r.status})`), { status: r.status });
      }

      const claimMatch = body.match(/^Claim:\s*(.+)$/m);
      const claimUrl = claimMatch ? claimMatch[1].trim() : "";
      status.innerHTML = claimUrl
        ? `Key submitted. <a class="text-link" href="${escapeHtml(claimUrl)}">Claim this key</a> to verify ownership.`
        : "Key submitted.";
      status.className = "status-row ok";
    }

    if (paste) paste.value = "";
    if (fileInput) { fileInput.value = ""; }
    const fn = document.getElementById("file-name-display");
    if (fn) fn.textContent = "";

    if (typeof loadMyKeys === "function" && authenticated) setTimeout(loadMyKeys, 800);
  } catch (err) {
    status.textContent = err.message || "Submission failed.";
    status.className = "status-row err";
  } finally {
    btn.disabled = false;
    btn.textContent = "Submit key";
  }
}

/* Wire file input → textarea / name display */
document.addEventListener("DOMContentLoaded", () => {
  document.addEventListener("change", (e) => {
    if (e.target && e.target.id === "key-file") {
      const f = e.target.files[0];
      const fn = document.getElementById("file-name-display");
      if (fn) fn.textContent = f ? f.name : "";
      if (f) {
        f.text().then((txt) => {
          const ta = document.getElementById("key-paste");
          if (ta) ta.value = txt.trim();
        }).catch(() => {});
      }
    }
  });
});
