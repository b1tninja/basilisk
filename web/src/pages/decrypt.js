import {
  decrypt,
  decryptKey,
  decryptSessionKeys,
  enums,
  readKey,
  readMessage,
  readPrivateKey,
  verify,
} from "openpgp";
import { Auth } from "../lib/auth.js";
import {
  CryptoModuleError,
  SELF_TEST_LABELS,
  assertCryptoReady,
  formatCryptoVerifiedMessage,
  runCryptoSelfTests,
} from "../lib/crypto-self-test.js";
import {
  applySessionKeyDetails,
  dearmorToBytes,
  enrichSpansWithPackets,
  mapPacketSpans,
  tagColorClass,
} from "../lib/packet-map.js";
import { splitArmoredMessages } from "../lib/pgp/armor.js";
import { analyzeArmored } from "../lib/pgp/inspect.js";
import {
  fingerprintHex,
  isAnonymousKeyId,
  keyIdHex,
  keySearchLink,
} from "../lib/pgp/identity.js";
import {
  checkIntendedRecipient,
  intendedRecipientsFromDecryptSignatures,
} from "../lib/pgp/intended-recipient.js";
import { zeroKeyMaterial } from "../lib/pgp/memory.js";
import {
  escapeHtml,
  fetchText,
  formatDate,
  formatFingerprint,
  copyTextTransient,
  queryParam,
  showError,
} from "../lib/utils.js";
import { getExpertMode, setExpertMode } from "../lib/prefs.js";
import {
  getPasskeyPrf,
  listKeys as vaultListKeys,
  unlockKey as vaultUnlockKey,
  vaultKeyMatchesRecipients,
} from "../lib/vault.js";
import "../css/site.css";

Auth.initWidget(document.getElementById("auth-widget"), "/decrypt");

const errorEl = document.getElementById("error");
const app = document.getElementById("decrypt-app");

/** @type {ReturnType<typeof analyzeArmored> extends Promise<infer T> ? T | null : never} */
let currentAnalysis = null;
let analyzeTimer = null;
let verifyGen = 0;
let cryptoReady = false;
let hexExpanded = false;
/** @type {ReturnType<typeof enrichSpansWithPackets> | null} */
let currentPacketMap = null;
let expertMode = getExpertMode();
/** @type {string} */
let lastPlaintext = "";
/** @type {string[]} */
let lastPlaintexts = [];
/** @type {import("../lib/vault.js").VaultKeyMeta[]} */
let vaultKeys = [];

const IDLE_CLEAR_MS = 5 * 60 * 1000;
const HIDDEN_CLEAR_MS = 60 * 1000;
let idleTimer = null;
let hiddenTimer = null;
let lastActivity = Date.now();

app.innerHTML = `
  <div class="compose-toolbar">
    <label class="expert-toggle" title="Show packet hex inspector and technical details">
      <input type="checkbox" id="expert-mode-toggle" ${expertMode ? "checked" : ""}>
      <span>Expert mode</span>
    </label>
  </div>

  <div id="crypto-status" class="status-row" role="status" aria-live="polite">
    Verifying crypto module…
  </div>

  <div class="card">
    <p class="card-title">Message or signature</p>
    <label class="field-label" for="ciphertext">Armored PGP message(s), cleartext signature, or detached signature</label>
    <textarea id="ciphertext" class="compose-message" rows="10"
      placeholder="-----BEGIN PGP MESSAGE-----&#10;…&#10;-----END PGP MESSAGE-----&#10;&#10;(multiple MESSAGE blocks OK)"></textarea>
    <div class="mt-md">
      <label class="file-label" for="cipher-file">Or choose .asc / .pgp file(s)</label>
      <input type="file" id="cipher-file" accept=".asc,.pgp,.gpg,text/plain" multiple hidden>
      <span class="file-name" id="cipher-file-name"></span>
    </div>
  </div>

  <div id="inspect-card" class="card hidden"></div>
  <div id="packet-map-card" class="card hidden"></div>

  <div id="decrypt-section" class="hidden">
    <div class="card hidden" id="skesk-card">
      <p class="card-title">Message passphrase</p>
      <label class="field-label" for="msg-passphrase">Shared passphrase (SKESK)</label>
      <input type="password" id="msg-passphrase" class="text-input" autocomplete="off" placeholder="Passphrase used to encrypt this message">
      <p class="muted mt-sm">Detected password-protected session key. Private key not required if you have the passphrase.</p>
    </div>
    <div class="card" id="private-key-card">
      <div class="card-title-row">
        <p class="card-title m-0">Private key (local only)</p>
        <button type="button" class="btn btn-ghost btn-compact" id="clear-sensitive-btn"
          title="Zero and clear all sensitive fields">Clear sensitive data</button>
      </div>
      <div id="vault-key-row" class="hidden mb-md">
        <label class="field-label" for="vault-key-select">Use a stored key</label>
        <div class="btn-row gap-sm items-center">
          <select id="vault-key-select" class="text-input flex-1">
            <option value="">— paste key below —</option>
          </select>
        </div>
        <p id="vault-unlock-status" class="muted mt-xs fs-sm"></p>
        <p class="muted mt-xs fs-xs">
          Matching vault keys unlock and decrypt in one step — the private key is not left in the text field.
        </p>
      </div>
      <label class="field-label" for="private-key">Armored private key <span class="muted">(optional if using a vault key)</span></label>
      <textarea id="private-key" class="compose-message" rows="8"
        placeholder="-----BEGIN PGP PRIVATE KEY BLOCK-----&#10;…&#10;(leave empty to use the selected vault key)"></textarea>
      <label class="field-label mt-md" for="passphrase">Key passphrase</label>
      <input type="password" id="passphrase" class="text-input" autocomplete="off" placeholder="Key passphrase (if the OpenPGP key is locked)">
      <p class="muted mt-md">Decrypt runs in a Web Worker when available. Vault keys are scrubbed from memory after use. Sensitive fields auto-clear after 5 minutes idle.</p>
      <p id="idle-clear-note" class="muted mt-xs"></p>
    </div>
    <div class="btn-row">
      <button type="button" class="btn" id="decrypt-btn" disabled>Decrypt</button>
    </div>
    <div id="decrypt-status" class="hidden"></div>
    <div id="decrypt-output" class="card hidden"></div>
  </div>
`;

// ── Self-test: run at module startup, block decrypt until done ──────────────
initToolkitCiphertextTransfer();
runCryptoSelfTests().then((result) => {
  const banner = document.getElementById("crypto-status");
  const decryptBtn = document.getElementById("decrypt-btn");
  if (result.passed) {
    cryptoReady = true;
    if (banner) {
      banner.className = "status-row ok";
      banner.textContent = formatCryptoVerifiedMessage(result);
      const fullRoot = result.moduleIntegrity?.root || "";
      if (fullRoot) banner.title = `Module Merkle root (SHA-256): ${fullRoot}`;
      setTimeout(() => {
        banner.classList.add("hidden");
      }, 4000);
    }
    if (decryptBtn) decryptBtn.disabled = false;
    signalToolkitDecryptReady();
  } else {
    cryptoReady = false;
    if (banner) {
      const failedChecks = Object.entries(result.results)
        .filter(([, v]) => !v)
        .map(([k]) => SELF_TEST_LABELS[k] || k)
        .join(", ");
      banner.className = "status-row err";
      banner.innerHTML =
        `<strong>Crypto self-test FAILED</strong> — do not use this page to decrypt private data. ` +
        (failedChecks ? `Failed: ${escapeHtml(failedChecks)}. ` : "") +
        (result.error ? `Error: ${escapeHtml(result.error)}.` : "");
    }
    if (decryptBtn) decryptBtn.disabled = true;
  }
});

/**
 * Receive OpenPGP ciphertext from a same-origin Toolkit popout.
 * Ready is signaled only after the crypto self-test passes.
 */
function initToolkitCiphertextTransfer() {
  if (queryParam("source") !== "toolkit" || !window.opener) return;
  const opener = window.opener;

  /** @param {MessageEvent} event */
  function onCiphertext(event) {
    if (
      event.origin !== window.location.origin ||
      event.source !== opener ||
      event.data?.type !== "basilisk:decrypt-ciphertext"
    ) {
      return;
    }
    const artifact = event.data.artifact;
    if (!artifact || typeof artifact.content !== "string") return;
    if (!/-----BEGIN PGP MESSAGE-----/i.test(artifact.content)) {
      showError(errorEl, "Toolkit transfer did not include an OpenPGP MESSAGE block.");
      return;
    }

    window.removeEventListener("message", onCiphertext);
    const ct = document.getElementById("ciphertext");
    if (ct instanceof HTMLTextAreaElement) {
      ct.value = artifact.content;
      ct.focus();
    }
    touchActivity();
    void runAnalyze();
    const label =
      typeof artifact.label === "string" && artifact.label.trim()
        ? artifact.label.trim()
        : "Toolkit ciphertext";
    const status = document.getElementById("decrypt-status");
    if (status) {
      status.className = "status-row ok";
      status.textContent = `${label} loaded from Toolkit. Unlock a key (or passphrase) to decrypt.`;
      status.classList.remove("hidden");
    }
  }

  window.addEventListener("message", onCiphertext);
}

function signalToolkitDecryptReady() {
  if (queryParam("source") !== "toolkit" || !window.opener) return;
  window.opener.postMessage(
    { type: "basilisk:decrypt-ready" },
    window.location.origin
  );
}

// ── Memory protection helpers ────────────────────────────────────────────────

/** Clear all sensitive DOM fields and the decrypt output. */
function clearSensitiveFields() {
  const keyEl = document.getElementById("private-key");
  const passEl = document.getElementById("passphrase");
  const msgPass = document.getElementById("msg-passphrase");
  const out = document.getElementById("decrypt-output");
  const status = document.getElementById("decrypt-status");
  if (keyEl) keyEl.value = "";
  if (passEl) passEl.value = "";
  if (msgPass) msgPass.value = "";
  const vaultSelect = document.getElementById("vault-key-select");
  if (vaultSelect instanceof HTMLSelectElement) vaultSelect.value = "";
  const vaultStatus = document.getElementById("vault-unlock-status");
  if (vaultStatus) vaultStatus.textContent = "";
  updateDecryptButtonLabel();
  if (out) {
    out.classList.add("hidden");
    out.innerHTML = "";
  }
  lastPlaintext = "";
  lastPlaintexts = [];
  if (status) status.className = "hidden";
  touchActivity();
}

function typeLabel(type) {
  switch (type) {
    case "encrypted":
      return "Encrypted message";
    case "message":
      return "Signed / literal message";
    case "cleartext":
      return "Clearsigned message";
    case "detached":
      return "Detached signature";
    default:
      return type || "Unknown";
  }
}

/**
 * @param {Awaited<ReturnType<typeof analyzeArmored>>} analysis
 */
function renderInspect(analysis) {
  const card = document.getElementById("inspect-card");
  if (!card) return;
  if (!analysis || analysis.type === "empty") {
    card.classList.add("hidden");
    card.innerHTML = "";
    return;
  }

  const recipients = analysis.recipientKeyIDs || [];
  const recipientsHtml = recipients.length
    ? `<ul class="inspect-list">${recipients
        .map((id) => {
          if (isAnonymousKeyId(id)) {
            return `<li><span class="muted">anonymous / hidden recipient</span></li>`;
          }
          return `<li>${keySearchLink(id, formatFingerprint(id))}</li>`;
        })
        .join("")}</ul>`
    : analysis.type === "encrypted"
      ? `<p class="muted">No recipient key IDs found (password-encrypted or hidden).</p>`
      : "";

  const sigs = analysis.sigDetails || [];
  const signersHtml = sigs.length
    ? `<ul class="inspect-list">${sigs
        .map((s, i) => {
          const id = s.fingerprint || s.keyId;
          const label = s.fingerprint
            ? formatFingerprint(s.fingerprint)
            : formatFingerprint(s.keyId);
          const when = s.created ? formatDate(s.created) : "timestamp unknown";
          return (
            `<li class="inspect-signer" data-sig-index="${i}">` +
            `${keySearchLink(id, label)}` +
            ` <span class="muted">· ${escapeHtml(when)}</span> ` +
            `<span class="badge" data-sig-badge="${i}">checking…</span>` +
            `</li>`
          );
        })
        .join("")}</ul>`
    : analysis.type === "encrypted"
      ? `<p class="muted">Signer details are inside the encrypted payload — decrypt to verify.</p>`
      : `<p class="muted">No signature packets found.</p>`;

  const clearHtml =
    analysis.type === "cleartext" && analysis.cleartext
      ? `<p class="card-title mt-lg">Cleartext</p>
         <pre class="output-pre">${escapeHtml(analysis.cleartext)}</pre>`
      : "";

  const recipientBlock =
    analysis.type === "encrypted" || recipients.length
      ? `<p class="card-title mt-lg">Encrypted to</p>${recipientsHtml}`
      : "";

  const multiNote =
    analysis.multiMessage && analysis.messageCount > 1
      ? `<p class="muted mt-sm">${analysis.messageCount} PGP MESSAGE blocks detected. Inspect shows the first; Decrypt unlocks once and opens all.</p>`
      : "";

  card.innerHTML = `
    <p class="card-title">Inspect</p>
    <p><span class="badge">${escapeHtml(typeLabel(analysis.type))}</span>${
      analysis.messageCount > 1
        ? ` <span class="badge pending">${analysis.messageCount} messages</span>`
        : ""
    }</p>
    ${multiNote}
    ${recipientBlock}
    <p class="card-title mt-lg">Signed by</p>
    ${signersHtml}
    ${clearHtml}
  `;
  card.classList.remove("hidden");
}

/**
 * Attempt keyserver lookup + verify for each unique signer.
 * @param {Awaited<ReturnType<typeof analyzeArmored>>} analysis
 */
async function verifySigners(analysis) {
  const gen = ++verifyGen;
  const sigs = analysis?.sigDetails || [];
  if (!sigs.length) return;

  const uniqueIds = [
    ...new Set(
      sigs
        .map((s) => (s.fingerprint || s.keyId || "").toUpperCase())
        .filter((id) => id && !isAnonymousKeyId(id))
    ),
  ];

  /** @type {Map<string, import("openpgp").Key | null>} */
  const keysById = new Map();

  await Promise.all(
    uniqueIds.map(async (id) => {
      try {
        const armored = await fetchText(
          `/pks/lookup?op=get&search=${encodeURIComponent(`0x${id}`)}`
        );
        if (!String(armored).includes("BEGIN PGP")) {
          keysById.set(id, null);
          return;
        }
        const key = await readKey({ armoredKey: armored });
        keysById.set(id, key);
      } catch (_) {
        keysById.set(id, null);
      }
    })
  );

  if (gen !== verifyGen) return;

  // Clearsigned: cryptographic verify when keys are available
  if (analysis.type === "cleartext" && analysis.message) {
    const verificationKeys = [...keysById.values()].filter(Boolean);
    let results = [];
    if (verificationKeys.length) {
      try {
        const verified = await verify({
          message: analysis.message,
          verificationKeys,
        });
        results = verified.signatures || [];
      } catch (_) {
        results = [];
      }
    }
    if (gen !== verifyGen) return;
    for (let i = 0; i < sigs.length; i++) {
      const badge = document.querySelector(`[data-sig-badge="${i}"]`);
      if (!badge) continue;
      const id = (sigs[i].fingerprint || sigs[i].keyId || "").toUpperCase();
      const key =
        keysById.get(id) ||
        [...keysById.entries()].find(([k]) => id.endsWith(k) || k.endsWith(sigs[i].keyId || ""))?.[1];
      if (!key) {
        badge.className = "badge";
        badge.textContent = "key not on server";
        continue;
      }
      const sigResult = results[i] || results.find((r) => keyIdHex(r.keyID) === sigs[i].keyId);
      if (!sigResult) {
        badge.className = "badge";
        badge.textContent = "unverified";
        continue;
      }
      try {
        await sigResult.verified;
        if (gen !== verifyGen) return;
        badge.className = "badge approved";
        badge.textContent = "verified";
      } catch (_) {
        if (gen !== verifyGen) return;
        badge.className = "badge revoked";
        badge.textContent = "invalid";
      }
    }
    return;
  }

  // Encrypted / detached: show whether signing key is on this keyserver
  if (analysis.type === "encrypted" || analysis.type === "detached") {
    for (let i = 0; i < sigs.length; i++) {
      const badge = document.querySelector(`[data-sig-badge="${i}"]`);
      if (!badge) continue;
      const id = (sigs[i].fingerprint || sigs[i].keyId || "").toUpperCase();
      const key =
        keysById.get(id) ||
        [...keysById.entries()].find(([k]) => id.endsWith(k) || k.endsWith(id))?.[1];
      if (!key) {
        badge.className = "badge";
        badge.textContent = "key not on server";
      } else {
        badge.className = "badge pending";
        badge.textContent =
          analysis.type === "detached"
            ? "key found (needs signed data)"
            : "key found";
      }
    }
    return;
  }

  // Binary signed (unencrypted) message: try verify
  if (analysis.type === "message" && analysis.message) {
    const verificationKeys = [...keysById.values()].filter(Boolean);
    for (let i = 0; i < sigs.length; i++) {
      const badge = document.querySelector(`[data-sig-badge="${i}"]`);
      if (!badge) continue;
      const id = (sigs[i].fingerprint || sigs[i].keyId || "").toUpperCase();
      const key =
        keysById.get(id) ||
        [...keysById.entries()].find(([k]) => id.endsWith(k) || k.endsWith(id))?.[1];
      if (!key) {
        badge.className = "badge";
        badge.textContent = "key not on server";
      } else {
        badge.className = "badge pending";
        badge.textContent = "key found";
      }
    }
    if (!verificationKeys.length) return;
    let results = [];
    try {
      const verified = await verify({
        message: analysis.message,
        verificationKeys,
      });
      results = verified.signatures || [];
    } catch (_) {
      return;
    }
    if (gen !== verifyGen) return;
    for (let i = 0; i < sigs.length; i++) {
      const badge = document.querySelector(`[data-sig-badge="${i}"]`);
      if (!badge) continue;
      const sigResult = results[i];
      if (!sigResult) continue;
      try {
        await sigResult.verified;
        if (gen !== verifyGen) return;
        badge.className = "badge approved";
        badge.textContent = "verified";
      } catch (_) {
        if (gen !== verifyGen) return;
        badge.className = "badge revoked";
        badge.textContent = "invalid";
      }
    }
  }
}

function updateDecryptSection(analysis) {
  const section = document.getElementById("decrypt-section");
  if (!section) return;
  const show = analysis && analysis.type === "encrypted";
  section.classList.toggle("hidden", !show);
  const skesk = document.getElementById("skesk-card");
  const privCard = document.getElementById("private-key-card");
  if (skesk) skesk.classList.toggle("hidden", !(show && analysis.hasSkesk));
  if (privCard) {
    // Hide private-key card only when SKESK-only (no PKESK recipients).
    const skeskOnly = show && analysis.hasSkesk && !analysis.hasPkesk && !(analysis.recipientKeyIDs || []).length;
    privCard.classList.toggle("hidden", !!skeskOnly);
  }
  if (!show) {
    const out = document.getElementById("decrypt-output");
    const status = document.getElementById("decrypt-status");
    if (out) {
      out.classList.add("hidden");
      out.innerHTML = "";
    }
    if (status) status.className = "hidden";
  }
}

const HEX_INITIAL = 4096;

function renderPacketMap(analysis) {
  const card = document.getElementById("packet-map-card");
  if (!card) return;
  if (!expertMode) {
    card.classList.add("hidden");
    card.innerHTML = "";
    currentPacketMap = null;
    return;
  }
  if (!analysis || analysis.type === "empty" || !analysis.armored) {
    card.classList.add("hidden");
    card.innerHTML = "";
    currentPacketMap = null;
    return;
  }
  let binary;
  try {
    binary = dearmorToBytes(analysis.armored);
  } catch (_) {
    card.classList.add("hidden");
    return;
  }
  const spans = mapPacketSpans(binary);
  const packets =
    analysis.message && analysis.type !== "cleartext" && analysis.type !== "detached"
      ? analysis.message.packets
      : analysis.message?.packets || analysis.message?.signature?.packets || null;
  currentPacketMap = enrichSpansWithPackets(spans, packets);

  const legend = [...new Set(spans.map((s) => s.name))]
    .map((name, i) => {
      const span = spans.find((s) => s.name === name);
      return `<span class="pkt-legend-chip ${tagColorClass(span?.colorIndex ?? i)}">${escapeHtml(name)}</span>`;
    })
    .join("");

  const detailRows = currentPacketMap
    .map((s, i) => {
      const lines = (s.detail?.lines || []).map((l) => `<div>${escapeHtml(l)}</div>`).join("");
      const warns = (s.detail?.warnings || [])
        .map((w) => `<div class="text-error">${escapeHtml(w)}</div>`)
        .join("");
      return `<div class="pkt-detail-row ${tagColorClass(s.colorIndex)}" data-pkt-idx="${i}" tabindex="0">
        <div class="pkt-detail-title">${escapeHtml(s.name)} <span class="muted">@ ${s.headerStart}–${s.end}</span></div>
        <div class="pkt-detail-body">${lines}${warns}</div>
      </div>`;
    })
    .join("");

  const limit = hexExpanded ? binary.length : Math.min(binary.length, HEX_INITIAL);
  card.innerHTML = `
    <p class="card-title">Packet map</p>
    <div class="pkt-legend">${legend}</div>
    <div class="hex-view" id="hex-view" aria-label="Colorized packet bytes">${renderHexGrid(binary, currentPacketMap, limit)}</div>
    ${
      binary.length > HEX_INITIAL
        ? `<button type="button" class="text-link" id="hex-expand-btn">${
            hexExpanded ? "Show less" : `Show full (${binary.length} bytes)`
          }</button>`
        : ""
    }
    <p class="card-title mt-lg">Packet details</p>
    <div class="pkt-detail-list">${detailRows}</div>
  `;
  card.classList.remove("hidden");
}

function renderHexGrid(binary, spans, limit) {
  const rows = [];
  for (let off = 0; off < limit; off += 16) {
    const slice = binary.subarray(off, Math.min(off + 16, limit));
    const hexParts = [];
    const asciiParts = [];
    for (let i = 0; i < slice.length; i++) {
      const abs = off + i;
      const span = spans.find((s) => abs >= s.headerStart && abs < s.end);
      const isHdr = span && abs < span.bodyStart;
      const cls = span
        ? `${tagColorClass(span.colorIndex)}${isHdr ? " pkt-hdr" : ""}`
        : "";
      const b = slice[i];
      hexParts.push(
        `<span class="hex-byte ${cls}" data-off="${abs}" title="${
          span ? escapeHtml(span.name) : ""
        }">${b.toString(16).padStart(2, "0")}</span>`
      );
      const ch = b >= 32 && b < 127 ? String.fromCharCode(b) : ".";
      asciiParts.push(`<span class="hex-ascii ${cls}" data-off="${abs}">${escapeHtml(ch)}</span>`);
    }
    rows.push(
      `<div class="hex-row"><span class="hex-off">${off
        .toString(16)
        .padStart(4, "0")}</span><span class="hex-bytes">${hexParts.join(
        " "
      )}</span><span class="hex-gutter">${asciiParts.join("")}</span></div>`
    );
  }
  return rows.join("");
}

function highlightPacket(idx) {
  document.querySelectorAll(".pkt-detail-row").forEach((el) => {
    el.classList.toggle("pkt-active", Number(el.getAttribute("data-pkt-idx")) === idx);
  });
  const span = currentPacketMap?.[idx];
  document.querySelectorAll(".hex-byte, .hex-ascii").forEach((el) => {
    const off = Number(el.getAttribute("data-off"));
    const on = span && off >= span.headerStart && off < span.end;
    el.classList.toggle("hex-hl", !!on);
  });
}

async function runAnalyze() {
  errorEl.classList.add("hidden");
  const armored = document.getElementById("ciphertext").value.trim();
  if (!armored) {
    currentAnalysis = null;
    renderInspect(null);
    renderPacketMap(null);
    updateDecryptSection(null);
    return;
  }
  try {
    const blocks = splitArmoredMessages(armored);
    const primary = blocks[0] || armored;
    const analysis = await analyzeArmored(primary);
    if (blocks.length > 1) {
      analysis.messageCount = blocks.length;
      analysis.multiMessage = true;
    }
    currentAnalysis = analysis;
    renderInspect(analysis);
    renderPacketMap(blocks.length > 1 ? null : analysis);
    updateDecryptSection(analysis);
    await autoSelectVaultKey(analysis);
    await verifySigners(analysis);
  } catch (err) {
    currentAnalysis = null;
    renderInspect(null);
    renderPacketMap(null);
    updateDecryptSection(null);
    showError(errorEl, err.message || "Could not parse message");
  }
}

function scheduleAnalyze() {
  clearTimeout(analyzeTimer);
  analyzeTimer = setTimeout(() => {
    runAnalyze().catch(() => {});
  }, 300);
}

function touchActivity() {
  lastActivity = Date.now();
  scheduleIdleClear();
  const note = document.getElementById("idle-clear-note");
  if (note) {
    note.textContent = "Sensitive fields clear after 5 minutes of inactivity.";
  }
}

function scheduleIdleClear() {
  clearTimeout(idleTimer);
  idleTimer = setTimeout(() => {
    const keyEl = document.getElementById("private-key");
    const msgPass = document.getElementById("msg-passphrase");
    const passEl = document.getElementById("passphrase");
    if (
      (keyEl && keyEl.value.trim()) ||
      (msgPass && msgPass.value) ||
      (passEl && passEl.value)
    ) {
      clearSensitiveFields();
      const status = document.getElementById("decrypt-status");
      if (status) {
        status.className = "status-row";
        status.textContent = "Sensitive fields cleared after idle timeout.";
        status.classList.remove("hidden");
      }
    }
  }, IDLE_CLEAR_MS);
}

/**
 * Decrypt with private key via Web Worker when possible; falls back in-page.
 */
async function decryptWithPrivateKeyWorker(armored, privArmored, keyPassphrase, verificationKeysArmored) {
  if (typeof Worker === "undefined") {
    return decryptWithPrivateKeyInline(armored, privArmored, keyPassphrase, verificationKeysArmored);
  }
  return new Promise((resolve, reject) => {
    let worker;
    try {
      worker = new Worker(new URL("../lib/crypto-worker.js", import.meta.url), {
        type: "module",
      });
    } catch (_) {
      decryptWithPrivateKeyInline(armored, privArmored, keyPassphrase, verificationKeysArmored)
        .then(resolve)
        .catch(reject);
      return;
    }
    const id = `d-${Date.now()}-${Math.random().toString(36).slice(2)}`;
    const timer = setTimeout(() => {
      try {
        worker.terminate();
      } catch (_) {
        /* ignore */
      }
      reject(new Error("Decrypt worker timed out"));
    }, 120000);
    worker.onmessage = (ev) => {
      if (ev.data?.id !== id) return;
      clearTimeout(timer);
      try {
        worker.terminate();
      } catch (_) {
        /* ignore */
      }
      if (ev.data.ok) resolve(ev.data);
      else reject(new Error(ev.data.error || "Decrypt failed"));
    };
    worker.onerror = (err) => {
      clearTimeout(timer);
      try {
        worker.terminate();
      } catch (_) {
        /* ignore */
      }
      // Fallback to inline on worker failure (e.g. bundler / CSP).
      decryptWithPrivateKeyInline(armored, privArmored, keyPassphrase, verificationKeysArmored)
        .then(resolve)
        .catch(reject);
    };
    worker.postMessage({
      type: "decrypt",
      id,
      armoredMessage: armored,
      privateKeyArmored: privArmored,
      passphrase: keyPassphrase || "",
      verificationKeysArmored: verificationKeysArmored || [],
    });
  });
}

async function decryptWithPrivateKeyInline(armored, privArmored, keyPassphrase, verificationKeysArmored) {
  let privateKey = await readPrivateKey({ armoredKey: privArmored });
  try {
    if (!privateKey.isDecrypted()) {
      privateKey = await decryptKey({ privateKey, passphrase: keyPassphrase || "" });
    }
    // OpenPGP.js Message objects are stateful — do not reuse across
    // decryptSessionKeys + decrypt (causes null sessionKeyParams destructure).
    const verificationKeys = [];
    for (const a of verificationKeysArmored || []) {
      try {
        verificationKeys.push(await readKey({ armoredKey: a }));
      } catch (_) {
        /* skip */
      }
    }
    let sessionKeys = [];
    try {
      sessionKeys = await decryptSessionKeys({
        message: await readMessage({ armoredMessage: armored }),
        decryptionKeys: privateKey,
      });
    } catch (_) {
      sessionKeys = [];
    }
    const result = await decrypt({
      message: await readMessage({ armoredMessage: armored }),
      decryptionKeys: privateKey,
      ...(verificationKeys.length ? { verificationKeys } : {}),
      config: { allowInsecureDecryptionWithSigningKeys: true },
    });
    const plaintext =
      typeof result.data === "string"
        ? result.data
        : new TextDecoder().decode(result.data);
    const signatures = [];
    for (const s of result.signatures || []) {
      let verified = false;
      try {
        await s.verified;
        verified = true;
      } catch (_) {
        verified = false;
      }
      signatures.push({ keyID: keyIdHex(s.keyID), verified });
    }
    return {
      ok: true,
      plaintext,
      signatures,
      // Never retain raw session-key octets on the main thread (worker path
      // already sends length-only). UI only needs algorithm + bit length.
      sessionKeys: sanitizeSessionKeysForUi(sessionKeys),
    };
  } finally {
    zeroKeyMaterial(privateKey);
  }
}

/**
 * Strip session-key material to metadata and wipe any raw key bytes.
 * @param {Array<{ algorithm?: *, aeadAlgorithm?: *, data?: Uint8Array }>|null|undefined} sessionKeys
 */
function sanitizeSessionKeysForUi(sessionKeys) {
  return (sessionKeys || []).map((sk) => {
    const length = sk.data?.length || 0;
    if (sk.data instanceof Uint8Array) {
      try {
        sk.data.fill(0);
      } catch (_) {
        /* wipe */
      }
    }
    return {
      algorithm: sk.algorithm,
      aeadAlgorithm: sk.aeadAlgorithm,
      length,
    };
  });
}

async function fetchVerificationArmored(signerIds) {
  const out = [];
  await Promise.all(
    signerIds.map(async (id) => {
      try {
        const armoredKey = await fetchText(
          `/pks/lookup?op=get&search=${encodeURIComponent(`0x${id}`)}`
        );
        if (String(armoredKey).includes("BEGIN PGP")) out.push(armoredKey);
      } catch (_) {
        /* skip */
      }
    })
  );
  return out;
}

function applySessionKeysToMap(sessionKeys) {
  if (!currentPacketMap || !sessionKeys?.length) return;
  // Length-only metadata: synthesize a zeroed stand-in so applySessionKeyDetails
  // can show bit length without ever holding real session-key octets.
  const forApply = sessionKeys.map((sk) => ({
    algorithm: sk.algorithm,
    aeadAlgorithm: sk.aeadAlgorithm,
    data:
      sk.data instanceof Uint8Array
        ? sk.data
        : sk.length
          ? new Uint8Array(sk.length)
          : sk.data?.length
            ? new Uint8Array(sk.data.length)
            : undefined,
  }));
  currentPacketMap = applySessionKeyDetails(currentPacketMap, forApply);
  const list = document.querySelector("#packet-map-card .pkt-detail-list");
  if (!list) return;
  list.innerHTML = currentPacketMap
    .map((s, i) => {
      const lines = (s.detail?.lines || []).map((l) => `<div>${escapeHtml(l)}</div>`).join("");
      const warns = (s.detail?.warnings || [])
        .map((w) => `<div class="text-error">${escapeHtml(w)}</div>`)
        .join("");
      return `<div class="pkt-detail-row ${tagColorClass(s.colorIndex)}" data-pkt-idx="${i}" tabindex="0">
        <div class="pkt-detail-title">${escapeHtml(s.name)} <span class="muted">@ ${s.headerStart}–${s.end}</span></div>
        <div class="pkt-detail-body">${lines}${warns}</div>
      </div>`;
    })
    .join("");
}

document.getElementById("ciphertext").addEventListener("input", () => {
  touchActivity();
  scheduleAnalyze();
});

document.getElementById("cipher-file").addEventListener("change", async (e) => {
  touchActivity();
  const files = Array.from(e.target.files || []);
  document.getElementById("cipher-file-name").textContent = files.length
    ? files.map((f) => f.name).join(", ")
    : "";
  if (!files.length) return;
  const texts = await Promise.all(files.map((f) => f.text()));
  document.getElementById("ciphertext").value = texts.join("\n\n");
  await runAnalyze();
});

document.getElementById("decrypt-btn").addEventListener("click", async () => {
  // Primary gate: flag set by the POST completion handler below.
  if (!cryptoReady) {
    showError(errorEl, "Crypto self-test has not passed. Refusing to decrypt.");
    return;
  }
  // Defensive CAST gate: assertCryptoReady() catches any race where the button
  // became clickable before the module state was latched to READY/ERROR.
  try {
    await assertCryptoReady();
  } catch (err) {
    showError(errorEl, err instanceof CryptoModuleError
      ? `Decryption refused — crypto self-test failed: ${err.message}`
      : String(err));
    return;
  }
  touchActivity();

  errorEl.classList.add("hidden");
  const status = document.getElementById("decrypt-status");
  const out = document.getElementById("decrypt-output");
  out.classList.add("hidden");
  status.className = "status-row";
  status.textContent = "Working…";
  status.classList.remove("hidden");

  const armoredRaw = document.getElementById("ciphertext").value.trim();
  const pastedKey = document.getElementById("private-key")?.value.trim() || "";
  const keyPassphrase = document.getElementById("passphrase")?.value || "";
  const msgPassphrase = document.getElementById("msg-passphrase")?.value || "";
  const vaultSelect = document.getElementById("vault-key-select");
  const vaultFpr = vaultSelect instanceof HTMLSelectElement ? vaultSelect.value : "";

  if (!armoredRaw) {
    showError(errorEl, "Paste a PGP message or choose a file.");
    status.className = "hidden";
    return;
  }

  const blocks = splitArmoredMessages(armoredRaw);
  const messages = blocks.length ? blocks : [armoredRaw];
  const usePassword = !!msgPassphrase;
  /** Ephemeral vault-sourced armored key — never written to the textarea. */
  let vaultArmored = "";
  let usedVaultEphemeral = false;
  /** Decryption key fingerprint for Intended Recipient checks */
  let decryptKeyFpr = "";
  /** @type {{ ok: boolean, index: number, plaintext?: string, sigStatuses?: object[], sessionKeys?: object[], intendedCheck?: ReturnType<typeof checkIntendedRecipient> | null, error?: string }[]} */
  const results = [];

  try {
    let privArmored = "";
    /** @type {string[]} */
    let verificationKeysArmored = [];

    if (!usePassword) {
      privArmored = pastedKey;
      if (!privArmored) {
        const fpr =
          vaultFpr ||
          matchingVaultKeys(currentAnalysis?.recipientKeyIDs || [])[0]
            ?.fingerprint ||
          "";
        if (fpr) {
          status.textContent = "Unlocking vault key…";
          vaultArmored = await unlockVaultArmoredEphemeral(fpr, status);
          privArmored = vaultArmored;
          usedVaultEphemeral = true;
          decryptKeyFpr = fpr.toUpperCase().replace(/[^0-9A-F]/g, "");
          if (vaultSelect instanceof HTMLSelectElement) {
            vaultSelect.value = fpr;
          }
        }
      }
      if (!privArmored) {
        showError(
          errorEl,
          currentAnalysis?.hasSkesk
            ? "Enter the message passphrase, select a vault key, or paste a private key."
            : "Select a stored vault key or paste your private key to decrypt."
        );
        status.className = "hidden";
        return;
      }
      if (!decryptKeyFpr) {
        try {
          const pk = await readPrivateKey({ armoredKey: privArmored });
          decryptKeyFpr =
            fingerprintHex(pk.getFingerprintBytes?.()) ||
            String(pk.getFingerprint?.() || "")
              .toUpperCase()
              .replace(/[^0-9A-F]/g, "");
        } catch (_) {
          decryptKeyFpr = "";
        }
      }
      const knownSigners = (currentAnalysis?.sigDetails || [])
        .map((s) => s.fingerprint || s.keyId)
        .filter((id) => id && !isAnonymousKeyId(id));
      verificationKeysArmored = await fetchVerificationArmored(knownSigners);
    }

    status.textContent =
      messages.length > 1
        ? `Decrypting ${messages.length} messages…`
        : usedVaultEphemeral
          ? "Decrypting with vault key…"
          : "Working…";

    for (let i = 0; i < messages.length; i++) {
      const armored = messages[i];
      try {
        if (usePassword) {
          let sessionKeys = [];
          try {
            sessionKeys = await decryptSessionKeys({
              message: await readMessage({ armoredMessage: armored }),
              passwords: [msgPassphrase],
            });
          } catch (_) {
            sessionKeys = [];
          }
          const result = await decrypt({
            message: await readMessage({ armoredMessage: armored }),
            passwords: [msgPassphrase],
            config: { allowInsecureDecryptionWithSigningKeys: true },
          });
          const plaintext =
            typeof result.data === "string"
              ? result.data
              : new TextDecoder().decode(result.data);
          /** @type {{keyID:string,verified:boolean,intendedRecipients?:string[]}[]} */
          const sigStatuses = [];
          for (const s of result.signatures || []) {
            let verified = false;
            try {
              await s.verified;
              verified = true;
            } catch (_) {
              verified = false;
            }
            sigStatuses.push({ keyID: keyIdHex(s.keyID), verified });
          }
          const intended = await intendedRecipientsFromDecryptSignatures(
            result.signatures || []
          );
          const intendedCheck =
            sigStatuses.length && decryptKeyFpr
              ? checkIntendedRecipient(intended, decryptKeyFpr)
              : null;
          results.push({
            ok: true,
            index: i,
            plaintext,
            sigStatuses,
            sessionKeys: sanitizeSessionKeysForUi(sessionKeys),
            intendedCheck,
          });
        } else {
          const workerResult = await decryptWithPrivateKeyWorker(
            armored,
            privArmored,
            keyPassphrase,
            verificationKeysArmored
          );
          const intended = [
            ...new Set(
              (workerResult.signatures || []).flatMap(
                (s) => s.intendedRecipients || []
              )
            ),
          ];
          const intendedCheck =
            (workerResult.signatures || []).length && decryptKeyFpr
              ? checkIntendedRecipient(intended, decryptKeyFpr)
              : null;
          results.push({
            ok: true,
            index: i,
            plaintext: workerResult.plaintext,
            sigStatuses: workerResult.signatures || [],
            sessionKeys: (workerResult.sessionKeys || []).map((sk) => ({
              algorithm: sk.algorithm,
              aeadAlgorithm: sk.aeadAlgorithm,
              length: sk.length,
            })),
            intendedCheck,
          });
        }
      } catch (err) {
        results.push({
          ok: false,
          index: i,
          error: err?.message || "Decrypt failed",
        });
      }
    }

    if (usedVaultEphemeral) {
      privArmored = "";
      vaultArmored = "";
    }

    const firstOk = results.find((r) => r.ok);
    if (firstOk?.sessionKeys) applySessionKeysToMap(firstOk.sessionKeys);

    const cards = results
      .map((r) => {
        const title =
          messages.length > 1 ? `Message ${r.index + 1}` : "Plaintext";
        if (!r.ok) {
          return `
          <div class="card artifact-card mb-md">
            <p class="card-title m-0-b-xs">${escapeHtml(title)}
              <span class="badge">failed</span></p>
            <p class="text-error m-0">${escapeHtml(r.error || "Decrypt failed")}</p>
          </div>`;
        }
        let sigHtml = "";
        if (r.sigStatuses?.length) {
          const parts = r.sigStatuses.map((s) => {
            const kid = (s.keyID || "").toUpperCase();
            const link = kid ? keySearchLink(kid, formatFingerprint(kid)) : "";
            return s.verified
              ? `<span>${link} <span class="badge approved">verified</span></span>`
              : `<span>${link} <span class="badge">signature unverified</span></span>`;
          });
          sigHtml = `<p class="mb-md">${parts.join(" · ")}</p>`;
        }
        let irfHtml = "";
        if (r.intendedCheck) {
          const tone =
            r.intendedCheck.status === "mismatch"
              ? "err"
              : r.intendedCheck.status === "ok"
                ? "ok"
                : "";
          irfHtml = `<p class="status-row ${tone} mb-md" role="status">${escapeHtml(
            r.intendedCheck.message
          )}</p>`;
        }
        const sk = r.sessionKeys?.[0];
        const cipherNote = sk?.algorithm
          ? `<p class="muted">Session cipher: <code>${escapeHtml(
              String(sk.algorithm).toUpperCase()
            )}${
              sk.aeadAlgorithm
                ? "-" + String(sk.aeadAlgorithm).toUpperCase()
                : ""
            }</code>${sk.length ? ` (${sk.length} bytes)` : ""}</p>`
          : "";
        return `
        <div class="card artifact-card mb-md">
          <div class="card-title-row">
            <p class="card-title m-0">${escapeHtml(title)}</p>
            <button type="button" class="btn btn-ghost btn-compact" data-copy-plain="${r.index}"
              title="Clipboard clears after 60 seconds">Copy (clears in 60s)</button>
          </div>
          ${cipherNote}
          ${sigHtml}
          ${irfHtml}
          <pre class="output-pre">${escapeHtml(r.plaintext || "")}</pre>
        </div>`;
      })
      .join("");

    out.innerHTML = cards;
    out.classList.remove("hidden");
    lastPlaintexts = results.map((r) => (r.ok ? r.plaintext || "" : ""));
    lastPlaintext = lastPlaintexts.filter(Boolean).join("\n\n---\n\n");

    const okCount = results.filter((r) => r.ok).length;
    const failCount = results.length - okCount;
    status.textContent =
      failCount === 0
        ? usePassword
          ? `Decrypted ${okCount} message${okCount === 1 ? "" : "s"} with passphrase. Passphrase cleared.`
          : usedVaultEphemeral
            ? `Decrypted ${okCount} message${okCount === 1 ? "" : "s"} with vault key. Private key scrubbed.`
            : `Decrypted ${okCount} message${okCount === 1 ? "" : "s"}. Key material zeroed.`
        : `Decrypted ${okCount} of ${results.length}; ${failCount} failed.`;
    status.className = failCount && !okCount ? "status-row err" : "status-row ok";
    const vaultStatus = document.getElementById("vault-unlock-status");
    if (vaultStatus && usedVaultEphemeral) {
      vaultStatus.textContent =
        "Vault key used for decrypt and scrubbed — not retained in the private key field.";
    }
  } catch (err) {
    status.className = "status-row err";
    status.textContent = err.message || "Decrypt failed";
    showError(errorEl, err.message || "Decrypt failed");
  } finally {
    vaultArmored = "";
    const passEl = document.getElementById("passphrase");
    if (passEl) passEl.value = "";
    const msgPass = document.getElementById("msg-passphrase");
    if (msgPass) msgPass.value = "";
  }
});

// ── Clear / hex / packet interactions ─────────────────────────────────────────
document.addEventListener("click", (e) => {
  const t = e.target;
  if (!(t instanceof Element)) return;
  if (t.id === "clear-sensitive-btn") {
    clearSensitiveFields();
    return;
  }
  const copyIdx = t.getAttribute?.("data-copy-plain");
  if (t.id === "copy-plaintext-btn" || copyIdx != null) {
    const text =
      copyIdx != null
        ? lastPlaintexts[Number(copyIdx)] || ""
        : lastPlaintext;
    const original = t.textContent;
    copyTextTransient(text, 60000)
      .then(() => {
        t.textContent = "Copied — clears in 60s";
        setTimeout(() => {
          t.textContent = original;
        }, 2000);
      })
      .catch(() => {
        t.textContent = "Copy failed";
        setTimeout(() => {
          t.textContent = original;
        }, 1500);
      });
    return;
  }
  if (t.id === "hex-expand-btn") {
    hexExpanded = !hexExpanded;
    if (currentAnalysis) renderPacketMap(currentAnalysis);
    return;
  }
  const row = t.closest("[data-pkt-idx]");
  if (row) {
    highlightPacket(Number(row.getAttribute("data-pkt-idx")));
    return;
  }
  const byte = t.closest("[data-off]");
  if (byte && currentPacketMap) {
    const off = Number(byte.getAttribute("data-off"));
    const idx = currentPacketMap.findIndex((s) => off >= s.headerStart && off < s.end);
    if (idx >= 0) highlightPacket(idx);
  }
});

document.addEventListener("change", (e) => {
  if (e.target?.id === "expert-mode-toggle") {
    expertMode = !!e.target.checked;
    setExpertMode(expertMode);
    if (currentAnalysis) renderPacketMap(currentAnalysis);
  }
});

document.addEventListener("input", (e) => {
  const id = e.target?.id;
  if (
    id === "private-key" ||
    id === "passphrase" ||
    id === "msg-passphrase" ||
    id === "ciphertext"
  ) {
    touchActivity();
  }
});

document.addEventListener("visibilitychange", () => {
  if (document.hidden) {
    clearTimeout(hiddenTimer);
    hiddenTimer = setTimeout(() => {
      if (document.hidden) clearSensitiveFields();
    }, HIDDEN_CLEAR_MS);
  } else {
    clearTimeout(hiddenTimer);
    touchActivity();
  }
});

window.addEventListener("beforeunload", (e) => {
  const keyEl = document.getElementById("private-key");
  const msgPass = document.getElementById("msg-passphrase");
  if ((keyEl && keyEl.value.trim()) || (msgPass && msgPass.value)) {
    e.preventDefault();
  }
});

/**
 * Find vault keys that can decrypt the message (PKESK recipient match).
 * @param {string[]} recipientKeyIDs
 * @returns {import("../lib/vault.js").VaultKeyMeta[]}
 */
function matchingVaultKeys(recipientKeyIDs) {
  return vaultKeys.filter((k) => vaultKeyMatchesRecipients(k, recipientKeyIDs));
}

/**
 * After inspecting a message, select a matching vault key when unambiguous.
 * Does NOT load the private key into the textarea — Decrypt unlocks ephemerally.
 * @param {typeof currentAnalysis} analysis
 */
async function autoSelectVaultKey(analysis) {
  const select = document.getElementById("vault-key-select");
  const status = document.getElementById("vault-unlock-status");
  if (!select || !vaultKeys.length) return;

  const recipients = analysis?.recipientKeyIDs || [];
  if (!recipients.length || analysis?.type !== "encrypted") return;

  const matches = matchingVaultKeys(recipients);
  if (!matches.length) {
    if (status && !select.value) {
      status.textContent =
        "No stored vault key matches this message's recipient key ID(s). Paste a key or pick one below.";
    }
    return;
  }

  let chosen = matches[0];
  if (matches.length > 1) {
    const current = vaultKeys.find((k) => k.fingerprint === select.value);
    if (current && matches.some((m) => m.fingerprint === current.fingerprint)) {
      chosen = current;
    }
  }

  select.value = chosen.fingerprint;
  updateDecryptButtonLabel();

  if (status) {
    const fpr = formatFingerprint(chosen.fingerprint);
    if (matches.length > 1) {
      status.textContent = `Matched ${matches.length} vault keys — selected ${fpr}. Click Decrypt to unlock and decrypt (key will not stay loaded).`;
    } else if (chosen.protection === "passkey") {
      status.textContent = `Matched vault key ${fpr}. Click Decrypt — you will confirm your passkey, then the key is scrubbed.`;
    } else if (chosen.protection === "passphrase") {
      status.textContent = `Matched vault key ${fpr}. Enter the key passphrase if needed, then Decrypt (key will not stay loaded).`;
    } else {
      status.textContent = `Matched vault key ${fpr}. Click Decrypt to unlock and decrypt in one step (key will not stay loaded).`;
    }
  }
}

/**
 * Unlock a vault private key into a local string only (never the textarea).
 * @param {string} fpr
 * @param {HTMLElement|null} statusEl
 * @returns {Promise<string>} armored private key
 */
async function unlockVaultArmoredEphemeral(fpr, statusEl) {
  const meta = vaultKeys.find((k) => k.fingerprint === fpr);
  if (!meta) throw new Error("Key not found in vault");

  /** @type {{ passphrase?: string, prfIkm?: Uint8Array }} */
  const opts = {};
  try {
    if (meta.protection === "passkey") {
      if (statusEl) statusEl.textContent = "Confirm passkey…";
      opts.prfIkm = await getPasskeyPrf();
    }
    return await vaultUnlockKey(fpr, opts);
  } finally {
    try {
      opts.prfIkm?.fill?.(0);
    } catch (_) {
      /* wipe */
    }
  }
}

function updateDecryptButtonLabel() {
  const btn = document.getElementById("decrypt-btn");
  const select = document.getElementById("vault-key-select");
  const pasted = document.getElementById("private-key")?.value.trim();
  if (!(btn instanceof HTMLButtonElement)) return;
  const vaultFpr = select instanceof HTMLSelectElement ? select.value : "";
  if (vaultFpr && !pasted) {
    const meta = vaultKeys.find((k) => k.fingerprint === vaultFpr);
    if (meta?.protection === "passkey") {
      btn.textContent = "Unlock passkey & decrypt";
    } else {
      btn.textContent = "Unlock & decrypt";
    }
  } else {
    btn.textContent = "Decrypt";
  }
}

async function refreshVaultKeySelect() {
  const row = document.getElementById("vault-key-row");
  const select = document.getElementById("vault-key-select");
  if (!row || !select) return;
  try {
    vaultKeys = await vaultListKeys();
  } catch (_) {
    vaultKeys = [];
  }
  if (!vaultKeys.length) {
    row.classList.add("hidden");
    updateDecryptButtonLabel();
    return;
  }
  row.classList.remove("hidden");
  const prev = select.value;
  select.innerHTML =
    `<option value="">— paste key below —</option>` +
    vaultKeys
      .map((k) => {
        const label = `${formatFingerprint(k.fingerprint)} · ${k.protection}${
          k.email ? ` · ${k.email}` : ""
        }`;
        return `<option value="${escapeHtml(k.fingerprint)}">${escapeHtml(label)}</option>`;
      })
      .join("");
  if (prev && vaultKeys.some((k) => k.fingerprint === prev)) {
    select.value = prev;
  }
  if (currentAnalysis?.type === "encrypted") {
    await autoSelectVaultKey(currentAnalysis);
  }
  updateDecryptButtonLabel();
}

document.getElementById("vault-key-select")?.addEventListener("change", () => {
  updateDecryptButtonLabel();
  const status = document.getElementById("vault-unlock-status");
  const select = document.getElementById("vault-key-select");
  const fpr = select instanceof HTMLSelectElement ? select.value : "";
  const meta = vaultKeys.find((k) => k.fingerprint === fpr);
  if (!status) return;
  if (!meta) {
    status.textContent = "";
    return;
  }
  status.textContent =
    meta.protection === "passkey"
      ? "Click Unlock & decrypt — confirm your passkey; the private key will not stay loaded."
      : meta.protection === "passphrase"
        ? "Enter the key passphrase if needed, then Unlock & decrypt (key will not stay loaded)."
        : "Click Unlock & decrypt — vault key unlocks only for this decrypt, then is scrubbed.";
});

document.getElementById("private-key")?.addEventListener("input", () => {
  updateDecryptButtonLabel();
});

refreshVaultKeySelect();
touchActivity();
