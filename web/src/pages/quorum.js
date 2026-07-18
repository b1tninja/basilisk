import { decryptKey, readPrivateKey } from "openpgp";
import { Auth } from "../lib/auth.js";
import { normalizeFingerprintInput, normalizeSearchQuery } from "../lib/pgp/verify-fpr.js";
import { DEFAULT_ICE_SERVERS, QuorumSession } from "../lib/quorum/rtc.js";
import { unlockPrivateKey } from "../lib/quorum/crypto.js";
import { deriveRoomId, isValidRoomId, quorumRelyingPartyId } from "../lib/quorum/room.js";
import {
  getTrust,
  listTrusted,
  sortByTrust,
  trustBadgeHtml,
} from "../lib/trust.js";
import {
  getPasskeyPrf,
  listKeys as vaultListKeys,
  unlockKey as vaultUnlockKey,
} from "../lib/vault.js";
import {
  copyText,
  escapeHtml,
  fetchJson,
  formatFingerprint,
  showError,
} from "../lib/utils.js";
import "../css/site.css";

Auth.initWidget(document.getElementById("auth-widget"), "/quorum");

const errorEl = document.getElementById("error");
const app = document.getElementById("quorum-app");

/** @type {Array<{ fingerprint: string, label: string }>} */
let audience = [];
/** @type {QuorumSession|null} */
let session = null;
/** @type {Array<{ from: string, text: string, ts: number, self?: boolean }>} */
let chatLog = [];
let searchTimer = null;

function render() {
  const trusted = listTrusted().filter(
    (t) => t.level === "trusted" || t.level === "marginal"
  );
  app.innerHTML = `
    <div class="quorum-layout">
      <div class="card">
        <p class="card-title">Your identity</p>
        <p class="muted fs-sm mb-md">Signaling is OpenPGP-signed with your key and encrypted to the audience. Unlock a vault key or paste a private key.</p>
        <div id="vault-row" class="mb-md">
          <label class="field-label" for="vault-key-select">Vault key</label>
          <select id="vault-key-select" class="text-input">
            <option value="">— paste key below —</option>
          </select>
        </div>
        <label class="field-label" for="private-key">Armored private key</label>
        <textarea id="private-key" class="text-input mono" rows="5"
          placeholder="-----BEGIN PGP PRIVATE KEY BLOCK-----"></textarea>
        <label class="field-label mt-md" for="passphrase">Key passphrase</label>
        <input type="password" id="passphrase" class="text-input" autocomplete="off">
      </div>

      <div class="card">
        <p class="card-title">Create room</p>
        <p class="muted fs-sm mb-md">Pick the audience (including yourself). Room ID is derived from this site’s hostname (<code>${escapeHtml(quorumRelyingPartyId())}</code>, same as the WebAuthn RP id) plus sorted audience fingerprints — no extra config.</p>
        ${
          trusted.length
            ? `<div class="mb-md">
                <p class="field-label">Trusted keys</p>
                <div class="btn-row wrap" id="trusted-chips">
                  ${trusted
                    .map(
                      (t) =>
                        `<button type="button" class="btn btn-ghost btn-compact trusted-add" data-fpr="${escapeHtml(t.fingerprint)}">${escapeHtml(formatFingerprint(t.fingerprint).slice(-14))} ${trustBadgeHtml(t.fingerprint)}</button>`
                    )
                    .join("")}
                </div>
              </div>`
            : ""
        }
        <label class="field-label" for="audience-search">Add by search / fingerprint</label>
        <div class="quorum-audience-search">
          <input type="text" id="audience-search" class="text-input" autocomplete="off" placeholder="email, name, or fingerprint">
          <div id="audience-dropdown" class="recipient-dropdown hidden"></div>
        </div>
        <div id="audience-pills" class="recipient-pills mt-md"></div>
        <p id="derived-room" class="mono mt-md muted">Room ID: —</p>
        <div class="btn-row mt-md">
          <button type="button" class="btn" id="create-join-btn">Create &amp; join</button>
          <button type="button" class="btn btn-ghost" id="copy-room-btn">Copy room ID</button>
        </div>
      </div>

      <div class="card">
        <p class="card-title">Join by room ID</p>
        <label class="field-label" for="join-room-id">Room ID</label>
        <input type="text" id="join-room-id" class="text-input mono" autocomplete="off" placeholder="16-character base32">
        <label class="field-label mt-md" for="join-audience">Audience fingerprints (one per line)</label>
        <textarea id="join-audience" class="text-input mono" rows="4"
          placeholder="Required so peers can verify PGP signatures against the pinned audience"></textarea>
        <div class="btn-row mt-md">
          <button type="button" class="btn" id="join-btn">Join room</button>
        </div>
      </div>

      <details class="card">
        <summary class="card-title">Advanced — ICE servers</summary>
        <label class="field-label mt-md" for="ice-servers">STUN / TURN (one URI per line)</label>
        <textarea id="ice-servers" class="text-input mono" rows="3">${escapeHtml(
          DEFAULT_ICE_SERVERS.map((s) => s.urls).join("\n")
        )}</textarea>
      </details>

      <div class="card quorum-session-card">
        <div class="quorum-session-head">
          <p class="card-title mb-0">Session</p>
          <span id="session-status" class="muted fs-sm">Not connected</span>
          <button type="button" class="btn btn-ghost btn-compact" id="leave-btn" disabled>Leave</button>
        </div>
        <div id="roster" class="quorum-roster mt-md"></div>
        <div id="chat-log" class="quorum-chat mt-md" aria-live="polite"></div>
        <div class="btn-row mt-md">
          <input type="text" id="chat-input" class="text-input flex-1" placeholder="Encrypted group chat…" disabled>
          <button type="button" class="btn" id="chat-send-btn" disabled>Send</button>
        </div>
      </div>
    </div>
  `;
  renderAudiencePills();
  void refreshVaultSelect();
  wireEvents();
}

async function refreshVaultSelect() {
  const sel = document.getElementById("vault-key-select");
  if (!(sel instanceof HTMLSelectElement)) return;
  try {
    const keys = await vaultListKeys();
    const cur = sel.value;
    sel.innerHTML =
      `<option value="">— paste key below —</option>` +
      keys
        .map((k) => {
          const label =
            k.uid || k.name || k.email || formatFingerprint(k.fingerprint);
          return `<option value="${escapeHtml(k.fingerprint)}">${escapeHtml(
            label
          )}</option>`;
        })
        .join("");
    if (cur) sel.value = cur;
  } catch (_) {
    /* vault unavailable */
  }
}

function renderAudiencePills() {
  const el = document.getElementById("audience-pills");
  if (!el) return;
  const sorted = sortByTrust(audience);
  el.innerHTML = sorted
    .map(
      (r) => `
      <span class="recipient-pill">
        <span class="pill-body">
          <span class="pill-label">${escapeHtml(r.label)} ${trustBadgeHtml(r.fingerprint)}</span>
          <span class="pill-fpr">${escapeHtml(formatFingerprint(r.fingerprint))}</span>
        </span>
        <button type="button" class="pill-remove" data-remove="${escapeHtml(r.fingerprint)}" aria-label="Remove">×</button>
      </span>`
    )
    .join("");
  void updateDerivedRoom();
}

async function updateDerivedRoom() {
  const el = document.getElementById("derived-room");
  if (!el) return;
  if (audience.length < 2) {
    el.textContent = "Room ID: — (need at least two fingerprints)";
    return;
  }
  try {
    const id = await deriveRoomId(audience.map((a) => a.fingerprint));
    el.textContent = `Room ID: ${id}`;
    el.dataset.roomId = id;
  } catch (err) {
    el.textContent = `Room ID: error — ${err.message || err}`;
  }
}

function renderDropdown(results) {
  const el = document.getElementById("audience-dropdown");
  if (!el) return;
  const rows = sortByTrust(results || []);
  if (!rows.length) {
    el.classList.add("hidden");
    el.innerHTML = "";
    return;
  }
  el.classList.remove("hidden");
  el.innerHTML = rows
    .slice(0, 12)
    .map((r) => {
      const fpr = String(r.fingerprint || "").toUpperCase();
      const uids = r.approved_uids || r.uids || [];
      const label =
        (Array.isArray(uids) && uids[0] && (uids[0].uid || uids[0])) ||
        formatFingerprint(fpr);
      return `<button type="button" class="recipient-hit audience-pick" data-fpr="${escapeHtml(fpr)}" data-label="${escapeHtml(String(label))}">
        <span class="hit-main">
          <span class="hit-label">${escapeHtml(String(label))} ${trustBadgeHtml(fpr)}</span>
          <span class="hit-meta mono">${escapeHtml(formatFingerprint(fpr))}</span>
        </span>
      </button>`;
    })
    .join("");
}

function renderRoster(peers) {
  const el = document.getElementById("roster");
  if (!el) return;
  if (!peers || peers.size === 0) {
    el.innerHTML = `<p class="muted fs-sm">No remote peers yet.</p>`;
    return;
  }
  el.innerHTML = `<ul class="quorum-roster-list">${[...peers.values()]
    .map((p) => {
      const verify = p.pgpVerified
        ? `<span class="trust-badge trust-trusted">PGP verified</span>`
        : `<span class="trust-badge">unverified</span>`;
      return `<li>
        <code class="mono">${escapeHtml(formatFingerprint(p.fingerprint))}</code>
        ${verify}
        <span class="muted fs-sm">${escapeHtml(p.status)}</span>
        ${trustBadgeHtml(p.fingerprint)}
      </li>`;
    })
    .join("")}</ul>`;
}

function renderChat() {
  const el = document.getElementById("chat-log");
  if (!el) return;
  el.innerHTML = chatLog
    .map((m) => {
      const who = m.self ? "you" : formatFingerprint(m.from).slice(-10);
      return `<div class="quorum-chat-line ${m.self ? "self" : ""}">
        <span class="muted fs-sm mono">${escapeHtml(who)}</span>
        <span>${escapeHtml(m.text)}</span>
      </div>`;
    })
    .join("");
  el.scrollTop = el.scrollHeight;
}

function parseIceServers() {
  const ta = document.getElementById("ice-servers");
  const lines = String(ta?.value || "")
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(Boolean);
  if (!lines.length) return DEFAULT_ICE_SERVERS;
  return lines.map((urls) => ({ urls }));
}

async function resolvePrivateKey() {
  const sel = document.getElementById("vault-key-select");
  const vaultFpr = sel instanceof HTMLSelectElement ? sel.value : "";
  const pass = document.getElementById("passphrase")?.value || "";
  if (vaultFpr) {
    const keys = await vaultListKeys();
    const meta = keys.find((k) => k.fingerprint === vaultFpr);
    /** @type {{ passphrase?: string, prfIkm?: Uint8Array }} */
    const opts = {};
    if (meta?.protection === "passkey") {
      opts.prfIkm = await getPasskeyPrf();
    } else if (meta?.protection === "passphrase") {
      opts.passphrase = pass;
    }
    const armored = await vaultUnlockKey(vaultFpr, opts);
    const key = await unlockPrivateKey(armored, pass);
    return { key, fingerprint: normalizeFingerprintInput(vaultFpr) };
  }
  const armored = document.getElementById("private-key")?.value || "";
  if (!armored.includes("BEGIN PGP")) {
    throw new Error("Unlock a vault key or paste a private key");
  }
  let key = await readPrivateKey({ armoredKey: armored });
  if (!key.isDecrypted()) {
    key = await decryptKey({ privateKey: key, passphrase: pass });
  }
  return {
    key,
    fingerprint: normalizeFingerprintInput(key.getFingerprint()),
  };
}

function setSessionUi(active) {
  const leave = document.getElementById("leave-btn");
  const chatIn = document.getElementById("chat-input");
  const chatBtn = document.getElementById("chat-send-btn");
  if (leave instanceof HTMLButtonElement) leave.disabled = !active;
  if (chatIn instanceof HTMLInputElement) chatIn.disabled = !active;
  if (chatBtn instanceof HTMLButtonElement) chatBtn.disabled = !active;
}

/**
 * @param {string} roomId
 * @param {string[]} audienceFprs
 */
async function startSession(roomId, audienceFprs) {
  showError(errorEl, "");
  if (session) {
    session.stop();
    session = null;
  }
  chatLog = [];
  renderChat();
  const { key, fingerprint } = await resolvePrivateKey();
  const fprs = [...new Set([...audienceFprs.map(normalizeFingerprintInput), fingerprint])];
  if (fprs.length < 2) {
    throw new Error("Audience must include at least two fingerprints (you + peers)");
  }
  session = new QuorumSession({
    roomId,
    audienceFprs: fprs,
    privateKey: key,
    myFingerprint: fingerprint,
    iceServers: parseIceServers(),
    onRoster: (peers) => renderRoster(peers),
    onChat: (msg) => {
      chatLog.push({ ...msg, self: msg.from === fingerprint });
      renderChat();
    },
    onStatus: (s) => {
      const el = document.getElementById("session-status");
      if (el) el.textContent = s;
    },
    onError: (err) => {
      console.warn("Quorum:", err);
      const el = document.getElementById("session-status");
      if (el) el.textContent = `Warning: ${err.message || err}`;
    },
  });
  setSessionUi(true);
  await session.start();
}

function addAudience(fpr, label) {
  const clean = normalizeFingerprintInput(fpr);
  if (!(clean.length === 40 || clean.length === 64)) return;
  if (getTrust(clean)?.level === "never") {
    if (
      !confirm(
        `Key ${formatFingerprint(clean)} is marked "never" trust. Add to audience anyway?`
      )
    ) {
      return;
    }
  }
  if (audience.some((a) => a.fingerprint === clean)) return;
  audience.push({
    fingerprint: clean,
    label: label || formatFingerprint(clean),
  });
  renderAudiencePills();
}

function wireEvents() {
  app.addEventListener("input", (e) => {
    const t = e.target;
    if (!(t instanceof HTMLElement)) return;
    if (t.id === "audience-search") {
      const raw = /** @type {HTMLInputElement} */ (t).value.trim();
      clearTimeout(searchTimer);
      if (!raw) {
        renderDropdown([]);
        return;
      }
      searchTimer = setTimeout(async () => {
        try {
          const q = normalizeSearchQuery(raw);
          const payload = await fetchJson(
            `/api/v1/search?q=${encodeURIComponent(q)}`
          );
          renderDropdown(payload.results || []);
        } catch (_) {
          renderDropdown([]);
        }
      }, 250);
    }
  });

  app.addEventListener("click", async (e) => {
    const t = e.target;
    if (!(t instanceof Element)) return;

    const trustedBtn = t.closest(".trusted-add");
    if (trustedBtn instanceof HTMLElement) {
      addAudience(trustedBtn.dataset.fpr || "", "Trusted key");
      return;
    }

    const pick = t.closest(".audience-pick");
    if (pick instanceof HTMLElement) {
      addAudience(pick.dataset.fpr || "", pick.dataset.label || "");
      renderDropdown([]);
      const search = document.getElementById("audience-search");
      if (search instanceof HTMLInputElement) search.value = "";
      return;
    }

    const rem = t.closest("[data-remove]");
    if (rem instanceof HTMLElement) {
      const fpr = rem.getAttribute("data-remove") || "";
      audience = audience.filter((a) => a.fingerprint !== fpr);
      renderAudiencePills();
      return;
    }

    if (t.id === "copy-room-btn") {
      const el = document.getElementById("derived-room");
      const id = el?.dataset?.roomId;
      if (id) {
        await copyText(id);
        const st = document.getElementById("session-status");
        if (st) st.textContent = "Room ID copied";
      }
      return;
    }

    if (t.id === "create-join-btn") {
      try {
        showError(errorEl, "");
        if (audience.length < 2) {
          throw new Error("Add at least two audience fingerprints");
        }
        const roomId = await deriveRoomId(audience.map((a) => a.fingerprint));
        await startSession(
          roomId,
          audience.map((a) => a.fingerprint)
        );
      } catch (err) {
        showError(errorEl, err.message || String(err));
      }
      return;
    }

    if (t.id === "join-btn") {
      try {
        showError(errorEl, "");
        const roomId = String(
          document.getElementById("join-room-id")?.value || ""
        )
          .trim()
          .toUpperCase();
        if (!isValidRoomId(roomId)) throw new Error("Invalid room ID");
        const lines = String(
          document.getElementById("join-audience")?.value || ""
        ).split(/\r?\n/);
        const fprs = lines
          .map((l) => normalizeFingerprintInput(l))
          .filter((f) => f.length === 40 || f.length === 64);
        if (fprs.length < 2) {
          throw new Error("Paste at least two audience fingerprints");
        }
        await startSession(roomId, fprs);
      } catch (err) {
        showError(errorEl, err.message || String(err));
      }
      return;
    }

    if (t.id === "leave-btn") {
      session?.stop();
      session = null;
      setSessionUi(false);
      renderRoster(new Map());
      const st = document.getElementById("session-status");
      if (st) st.textContent = "Left room";
      return;
    }

    if (t.id === "chat-send-btn") {
      const input = document.getElementById("chat-input");
      const text = input instanceof HTMLInputElement ? input.value.trim() : "";
      if (!text || !session) return;
      try {
        await session.sendChat(text);
        chatLog.push({
          from: session.myFpr,
          text,
          ts: Date.now(),
          self: true,
        });
        renderChat();
        if (input instanceof HTMLInputElement) input.value = "";
      } catch (err) {
        showError(errorEl, err.message || String(err));
      }
    }
  });

  app.addEventListener("keydown", async (e) => {
    if (e.key !== "Enter") return;
    const t = e.target;
    if (t instanceof HTMLInputElement && t.id === "chat-input") {
      e.preventDefault();
      document.getElementById("chat-send-btn")?.click();
    }
  });
}

render();
