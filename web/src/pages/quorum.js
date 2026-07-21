import { decryptKey, readPrivateKey } from "openpgp";
import { Auth } from "../lib/auth.js";
import {
  keyHitHtml,
  keyPillExtrasHtml,
  primaryUidLabel,
} from "../lib/key-hit.js";
import { normalizeFingerprintInput, normalizeSearchQuery } from "../lib/pgp/verify-fpr.js";
import { DEFAULT_ICE_SERVERS, QuorumSession } from "../lib/quorum/rtc.js";
import {
  requireSelfInAudience,
  unlockPrivateKey,
} from "../lib/quorum/crypto.js";
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
  copyButtonHtml,
  escapeHtml,
  fetchJson,
  formatFingerprint,
  showError,
  wireCopyButtons,
} from "../lib/utils.js";
import "../css/site.css";

Auth.initWidget(document.getElementById("auth-widget"), "/quorum");

const errorEl = document.getElementById("error");
const app = document.getElementById("quorum-app");

/**
 * @typedef {{ fingerprint: string, label: string, userLabel?: string, keyExpiration?: string|null, keyId?: string, self?: boolean }} AudienceEntry
 */
/** @type {AudienceEntry[]} */
let audience = [];
/** @type {string} */
let selfFpr = "";
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
        <p class="muted fs-sm mb-md">You are always a room participant. Signaling is OpenPGP-signed (proving key possession) and encrypted to the audience. Unlock a vault key or paste a private key.</p>
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
        <p class="muted fs-sm mb-md">Add peers; your unlocked key is included automatically and cannot be removed. Creating publishes a signed invite. Room ID = hostname (<code>${escapeHtml(quorumRelyingPartyId())}</code>) + sorted audience fingerprints.</p>
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
        <div id="derived-room-row" class="meta-with-action mt-md">
          <p id="derived-room" class="mono muted mb-0">Room ID: —</p>
          <button type="button" class="btn btn-ghost btn-compact hidden" id="copy-room-btn" title="Copy room ID">Copy ID</button>
          <button type="button" class="btn btn-ghost btn-compact hidden" id="copy-audience-btn" title="Copy audience fingerprints">Copy audience</button>
        </div>
        <div class="btn-row mt-md">
          <button type="button" class="btn" id="create-join-btn">Create &amp; join</button>
        </div>
      </div>

      <div class="card">
        <p class="card-title">Join by room ID</p>
        <label class="field-label" for="join-room-id">Room ID</label>
        <input type="text" id="join-room-id" class="text-input mono" autocomplete="off" placeholder="16-character base32">
        <label class="field-label mt-md" for="join-audience">Audience fingerprints (one per line, including yours)</label>
        <textarea id="join-audience" class="text-input mono" rows="4"
          placeholder="Must match the creator’s audience (including your fingerprint). Join waits for their signed invite."></textarea>
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
    .map((r) => {
      const extras = keyPillExtrasHtml({
        fingerprint: r.fingerprint,
        userLabel: r.userLabel,
        label: r.userLabel,
        keyExpiration: r.keyExpiration,
        key_id: r.keyId,
      });
      const isSelf = Boolean(r.self) || (selfFpr && r.fingerprint === selfFpr);
      const youBadge = isSelf
        ? `<span class="trust-badge trust-trusted">you</span>`
        : "";
      const removeBtn = isSelf
        ? ""
        : `<button type="button" class="pill-remove" data-remove="${escapeHtml(r.fingerprint)}" aria-label="Remove">×</button>`;
      return `
      <span class="recipient-pill${isSelf ? " pill-self" : ""}">
        <span class="pill-body">
          <span class="pill-label">${escapeHtml(r.label)} ${youBadge} ${trustBadgeHtml(r.fingerprint)}</span>
          <span class="pill-fpr">${escapeHtml(formatFingerprint(r.fingerprint))}</span>
          ${extras ? `<span class="pill-extras">${extras}</span>` : ""}
        </span>
        ${removeBtn}
      </span>`;
    })
    .join("");
  void updateDerivedRoom();
}

async function updateDerivedRoom() {
  const el = document.getElementById("derived-room");
  const copyRoom = document.getElementById("copy-room-btn");
  const copyAud = document.getElementById("copy-audience-btn");
  if (!el) return;
  if (audience.length < 2) {
    el.textContent = "Room ID: — (need at least two fingerprints)";
    delete el.dataset.roomId;
    copyRoom?.classList.add("hidden");
    copyAud?.classList.add("hidden");
    return;
  }
  try {
    const id = await deriveRoomId(audience.map((a) => a.fingerprint));
    el.textContent = `Room ID: ${id}`;
    el.dataset.roomId = id;
    if (copyRoom instanceof HTMLButtonElement) {
      copyRoom.classList.remove("hidden");
      copyRoom.setAttribute("data-copy", id);
    }
    if (copyAud instanceof HTMLButtonElement) {
      copyAud.classList.remove("hidden");
      copyAud.setAttribute(
        "data-copy",
        audience.map((a) => a.fingerprint).join("\n")
      );
    }
  } catch (err) {
    el.textContent = `Room ID: error — ${err.message || err}`;
    delete el.dataset.roomId;
    copyRoom?.classList.add("hidden");
    copyAud?.classList.add("hidden");
  }
}

function renderDropdown(results, warning = "") {
  const el = document.getElementById("audience-dropdown");
  if (!el) return;
  const rows = sortByTrust(results || []);
  if (!rows.length) {
    el.classList.add("hidden");
    el.innerHTML = "";
    return;
  }
  el.classList.remove("hidden");
  const caution = warning
    ? `<p class="name-search-caution m-0-b-sm" role="status"><strong>Short key ID.</strong> ${escapeHtml(warning)}</p>`
    : "";
  el.innerHTML =
    caution +
    rows
      .slice(0, 12)
      .map((r) => {
        const fpr = String(r.fingerprint || "").toUpperCase();
        const label = primaryUidLabel(r);
        return keyHitHtml(r, {
          className: "audience-pick",
          dataAttrs: {
            "data-fpr": fpr,
            "data-label": label,
            "data-user-label": String(r.label || ""),
            "data-key-id": String(r.key_id || ""),
            "data-key-exp": String(r.key_expiration || ""),
          },
        });
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
      const badges = [
        p.isInitiator
          ? `<span class="trust-badge trust-trusted">initiator</span>`
          : "",
        p.pgpVerified
          ? `<span class="trust-badge trust-trusted">PGP</span>`
          : `<span class="trust-badge">no PGP</span>`,
        p.kcVerified
          ? `<span class="trust-badge trust-trusted">key confirmed</span>`
          : `<span class="trust-badge">awaiting KC</span>`,
      ]
        .filter(Boolean)
        .join(" ");
      return `<li>
        <code class="mono">${escapeHtml(formatFingerprint(p.fingerprint))}</code>
        ${copyButtonHtml("Copy", p.fingerprint, { title: "Copy fingerprint" })}
        ${badges}
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
 * Ensure unlocked key appears as a locked audience member.
 * @param {string} fingerprint
 */
function ensureSelfInAudienceList(fingerprint) {
  const me = normalizeFingerprintInput(fingerprint);
  selfFpr = me;
  const existing = audience.find((a) => a.fingerprint === me);
  if (existing) {
    existing.self = true;
    existing.label = existing.label || "You";
  } else {
    audience.unshift({
      fingerprint: me,
      label: "You",
      self: true,
    });
  }
  // Drop accidental duplicates of self without the flag
  audience = audience.filter(
    (a, i, arr) => a.fingerprint !== me || arr.findIndex((x) => x.fingerprint === me) === i
  );
  const selfEntry = audience.find((a) => a.fingerprint === me);
  if (selfEntry) selfEntry.self = true;
  renderAudiencePills();
}

/**
 * @param {string} roomId
 * @param {string[]} audienceFprs
 * @param {"creator"|"joiner"} role
 * @param {{ key: import("openpgp").PrivateKey, fingerprint: string }} [identity]
 */
async function startSession(roomId, audienceFprs, role, identity) {
  showError(errorEl, "");
  if (session) {
    session.stop();
    session = null;
  }
  chatLog = [];
  renderChat();
  const { key, fingerprint } = identity || (await resolvePrivateKey());
  ensureSelfInAudienceList(fingerprint);
  const fprs = requireSelfInAudience(fingerprint, audienceFprs);
  const derived = await deriveRoomId(fprs);
  if (derived !== String(roomId || "").trim().toUpperCase()) {
    throw new Error(
      "Room ID does not match this audience (hostname + fingerprints). Check the audience list."
    );
  }
  session = new QuorumSession({
    roomId: derived,
    audienceFprs: fprs,
    privateKey: key,
    myFingerprint: fingerprint,
    role,
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

/**
 * @param {string} fpr
 * @param {string} [label]
 * @param {{ userLabel?: string, keyExpiration?: string|null, keyId?: string }} [meta]
 */
function addAudience(fpr, label, meta = {}) {
  const clean = normalizeFingerprintInput(fpr);
  if (!(clean.length === 40 || clean.length === 64)) return;
  if (selfFpr && clean === selfFpr) {
    ensureSelfInAudienceList(clean);
    return;
  }
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
    userLabel: meta.userLabel || "",
    keyExpiration: meta.keyExpiration || null,
    keyId: meta.keyId || "",
    self: false,
  });
  renderAudiencePills();
}

async function syncSelfFromIdentity() {
  try {
    const { fingerprint } = await resolvePrivateKey();
    ensureSelfInAudienceList(fingerprint);
  } catch (_) {
    /* identity not unlocked yet */
  }
}

function wireEvents() {
  app.addEventListener("change", (e) => {
    const t = e.target;
    if (!(t instanceof HTMLElement)) return;
    if (t.id === "vault-key-select" || t.id === "private-key") {
      void syncSelfFromIdentity();
    }
  });

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
          renderDropdown(payload.results || [], payload.warning || "");
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
      addAudience(pick.dataset.fpr || "", pick.dataset.label || "", {
        userLabel: pick.dataset.userLabel || "",
        keyExpiration: pick.dataset.keyExp || null,
        keyId: pick.dataset.keyId || "",
      });
      renderDropdown([]);
      const search = document.getElementById("audience-search");
      if (search instanceof HTMLInputElement) search.value = "";
      return;
    }

    const rem = t.closest("[data-remove]");
    if (rem instanceof HTMLElement) {
      const fpr = rem.getAttribute("data-remove") || "";
      const clean = normalizeFingerprintInput(fpr);
      if (selfFpr && clean === selfFpr) return;
      audience = audience.filter((a) => a.fingerprint !== clean);
      renderAudiencePills();
      return;
    }

    if (t.id === "copy-room-btn" || t.id === "copy-audience-btn") {
      // Handled by wireCopyButtons via data-copy; keep a status hint.
      const st = document.getElementById("session-status");
      if (st && t.getAttribute("data-copy")) {
        st.textContent =
          t.id === "copy-audience-btn" ? "Audience copied" : "Room ID copied";
      }
      return;
    }

    if (t.id === "create-join-btn") {
      try {
        showError(errorEl, "");
        const identity = await resolvePrivateKey();
        ensureSelfInAudienceList(identity.fingerprint);
        const fprs = requireSelfInAudience(
          identity.fingerprint,
          audience.map((a) => a.fingerprint)
        );
        if (fprs.length < 2) {
          throw new Error("Add at least one peer (you are included automatically)");
        }
        const roomId = await deriveRoomId(fprs);
        await startSession(roomId, fprs, "creator", identity);
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
        const identity = await resolvePrivateKey();
        const lines = String(
          document.getElementById("join-audience")?.value || ""
        ).split(/\r?\n/);
        const fprs = lines
          .map((l) => normalizeFingerprintInput(l))
          .filter((f) => f.length === 40 || f.length === 64);
        const audienceWithSelf = requireSelfInAudience(
          identity.fingerprint,
          fprs
        );
        const derived = await deriveRoomId(audienceWithSelf);
        if (derived !== roomId) {
          throw new Error(
            "Room ID does not match the pasted audience on this host"
          );
        }
        await startSession(roomId, audienceWithSelf, "joiner", identity);
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
wireCopyButtons();
