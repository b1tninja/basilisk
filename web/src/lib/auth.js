import { escapeHtml, fetchJson } from "./utils.js";

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

let _user = undefined;
let _providers = undefined;

function currentPathWithQuery() {
  return window.location.pathname + window.location.search || "/";
}

function postLoginRedirect(redirectUrl) {
  if (redirectUrl && /^https?:\/\//i.test(redirectUrl)) return redirectUrl;
  const path = redirectUrl || currentPathWithQuery();
  return new URL(path, window.location.origin).href;
}

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
  } catch (_) {
    _user = null;
  }
  return _user;
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

function toggleMenu(e) {
  e.stopPropagation();
  const menu = document.getElementById("sign-in-menu");
  if (!menu) return;
  const show = menu.hidden;
  menu.hidden = !show;
  if (show) {
    document.addEventListener(
      "click",
      () => {
        menu.hidden = true;
      },
      { once: true }
    );
  }
}

async function initWidget(container, redirectUrl) {
  if (!container) return;
  const [user, providers] = await Promise.all([getUser(), getProviders()]);
  if (!user || !user.authenticated) {
    const menu = signInMenu(redirectUrl || currentPathWithQuery(), providers);
    if (menu.includes("sign-in-menu")) {
      container.innerHTML = `
      <div class="sign-in-trigger">
        <button type="button" class="btn-sign-in" id="sign-in-btn">Sign in ▾</button>
        ${menu}
      </div>`;
      const btn = container.querySelector("#sign-in-btn");
      if (btn) btn.addEventListener("click", toggleMenu);
    } else {
      container.innerHTML = menu;
    }
  } else {
    const home = encodeURIComponent(`${window.location.origin}/`);
    container.innerHTML = `
      <span class="auth-email" title="${escapeHtml(user.email)}">${escapeHtml(user.email)}</span>
      <a class="auth-signout" href="/.auth/logout?post_logout_redirect_uri=${home}">Sign out</a>`;
  }
}

export const Auth = {
  getUser,
  getProviders,
  initWidget,
  toggleMenu,
  providerButtons,
};
