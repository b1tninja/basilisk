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
import { SELF_TEST_LABELS, runCryptoSelfTests } from "../lib/crypto-self-test.js";
import {
  applySessionKeyDetails,
  dearmorToBytes,
  enrichSpansWithPackets,
  mapPacketSpans,
  tagColorClass,
} from "../lib/packet-map.js";
import { analyzeArmored } from "../lib/pgp/inspect.js";
import {
  isAnonymousKeyId,
  keyIdHex,
  keySearchLink,
} from "../lib/pgp/identity.js";
import { zeroKeyMaterial } from "../lib/pgp/memory.js";
import {
  escapeHtml,
  fetchText,
  formatDate,
  formatFingerprint,
  copyTextTransient,
  showError,
} from "../lib/utils.js";
import { getExpertMode, setExpertMode } from "../lib/prefs.js";
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
    <label class="field-label" for="ciphertext">Armored PGP message, cleartext signature, or detached signature</label>
    <textarea id="ciphertext" class="compose-message" rows="10"
      placeholder="-----BEGIN PGP MESSAGE-----&#10;…&#10;-----END PGP MESSAGE-----"></textarea>
    <div style="margin-top:0.75rem">
      <label class="file-label" for="cipher-file">Or choose a .asc / .pgp file</label>
      <input type="file" id="cipher-file" accept=".asc,.pgp,.gpg,text/plain" hidden>
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
      <p class="muted" style="margin-top:0.5rem">Detected password-protected session key. Private key not required if you have the passphrase.</p>
    </div>
    <div class="card" id="private-key-card">
      <div class="card-title-row" style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1rem">
        <p class="card-title" style="margin:0">Private key (local only)</p>
        <button type="button" class="btn btn-ghost btn-compact" id="clear-sensitive-btn"
          title="Zero and clear all sensitive fields">Clear sensitive data</button>
      </div>
      <label class="field-label" for="private-key">Armored private key</label>
      <textarea id="private-key" class="compose-message" rows="8"
        placeholder="-----BEGIN PGP PRIVATE KEY BLOCK-----&#10;…"></textarea>
      <label class="field-label" for="passphrase" style="margin-top:0.75rem">Key passphrase</label>
      <input type="password" id="passphrase" class="text-input" autocomplete="off" placeholder="Key passphrase (if any)">
      <p class="muted" style="margin-top:0.65rem">Decrypt runs in a Web Worker when available. Sensitive fields auto-clear after 5 minutes idle.</p>
      <p id="idle-clear-note" class="muted" style="margin-top:0.35rem"></p>
    </div>
    <div class="btn-row">
      <button type="button" class="btn" id="decrypt-btn" disabled>Decrypt</button>
    </div>
    <div id="decrypt-status" class="hidden"></div>
    <div id="decrypt-output" class="card hidden"></div>
  </div>
`;

// ── Self-test: run at module startup, block decrypt until done ──────────────
runCryptoSelfTests().then((result) => {
  const banner = document.getElementById("crypto-status");
  const decryptBtn = document.getElementById("decrypt-btn");
  if (result.passed) {
    cryptoReady = true;
    if (banner) {
      banner.className = "status-row ok";
      banner.textContent = `Crypto module verified (${result.elapsed} ms) — ${Object.keys(result.results).length} checks passed.`;
      setTimeout(() => {
        banner.classList.add("hidden");
      }, 4000);
    }
    if (decryptBtn) decryptBtn.disabled = false;
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
  if (out) {
    out.classList.add("hidden");
    out.innerHTML = "";
  }
  lastPlaintext = "";
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
      ? `<p class="card-title" style="margin-top:1rem">Cleartext</p>
         <pre class="output-pre">${escapeHtml(analysis.cleartext)}</pre>`
      : "";

  const recipientBlock =
    analysis.type === "encrypted" || recipients.length
      ? `<p class="card-title" style="margin-top:1rem">Encrypted to</p>${recipientsHtml}`
      : "";

  card.innerHTML = `
    <p class="card-title">Inspect</p>
    <p><span class="badge">${escapeHtml(typeLabel(analysis.type))}</span></p>
    ${recipientBlock}
    <p class="card-title" style="margin-top:1rem">Signed by</p>
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
    <p class="card-title" style="margin-top:1rem">Packet details</p>
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
    const analysis = await analyzeArmored(armored);
    currentAnalysis = analysis;
    renderInspect(analysis);
    renderPacketMap(analysis);
    updateDecryptSection(analysis);
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
    const message = await readMessage({ armoredMessage: armored });
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
        message,
        decryptionKeys: privateKey,
      });
    } catch (_) {
      sessionKeys = [];
    }
    const result = await decrypt({
      message,
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
      sessionKeys: (sessionKeys || []).map((sk) => ({
        algorithm: sk.algorithm,
        aeadAlgorithm: sk.aeadAlgorithm,
        length: sk.data?.length || 0,
        data: sk.data,
      })),
    };
  } finally {
    zeroKeyMaterial(privateKey);
  }
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
  const normalized = sessionKeys.map((sk) => ({
    algorithm: sk.algorithm,
    aeadAlgorithm: sk.aeadAlgorithm,
    data:
      sk.data ||
      (sk.length ? { length: sk.length } : undefined),
  }));
  // Length-only from worker: synthesize a stand-in so applySessionKeyDetails can show bit length.
  const forApply = normalized.map((sk) => ({
    algorithm: sk.algorithm,
    aeadAlgorithm: sk.aeadAlgorithm,
    data:
      sk.data instanceof Uint8Array
        ? sk.data
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
  const f = e.target.files?.[0];
  document.getElementById("cipher-file-name").textContent = f ? f.name : "";
  if (f) {
    document.getElementById("ciphertext").value = await f.text();
    await runAnalyze();
  }
});

document.getElementById("decrypt-btn").addEventListener("click", async () => {
  if (!cryptoReady) {
    showError(errorEl, "Crypto self-test has not passed. Refusing to decrypt.");
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

  const armored = document.getElementById("ciphertext").value.trim();
  const privArmored = document.getElementById("private-key")?.value.trim() || "";
  const keyPassphrase = document.getElementById("passphrase")?.value || "";
  const msgPassphrase = document.getElementById("msg-passphrase")?.value || "";

  if (!armored) {
    showError(errorEl, "Paste a PGP message or choose a file.");
    status.className = "hidden";
    return;
  }

  const usePassword = !!msgPassphrase;
  if (!usePassword && !privArmored) {
    showError(
      errorEl,
      currentAnalysis?.hasSkesk
        ? "Enter the message passphrase, or paste a private key."
        : "Paste your private key to decrypt (stays in the browser)."
    );
    status.className = "hidden";
    return;
  }

  try {
    let plaintext = "";
    let sigStatuses = [];
    let sessionKeys = [];

    if (usePassword) {
      // OpenPGP.js: passwords XOR decryptionKeys — not both.
      const message = await readMessage({ armoredMessage: armored });
      try {
        sessionKeys = await decryptSessionKeys({
          message,
          passwords: [msgPassphrase],
        });
      } catch (_) {
        sessionKeys = [];
      }
      const result = await decrypt({
        message,
        passwords: [msgPassphrase],
        config: { allowInsecureDecryptionWithSigningKeys: true },
      });
      plaintext =
        typeof result.data === "string"
          ? result.data
          : new TextDecoder().decode(result.data);
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
    } else {
      // Prefetch signer keys if we already know IDs from inspect.
      const knownSigners = (currentAnalysis?.sigDetails || [])
        .map((s) => s.fingerprint || s.keyId)
        .filter((id) => id && !isAnonymousKeyId(id));
      const verificationKeysArmored = await fetchVerificationArmored(knownSigners);
      const workerResult = await decryptWithPrivateKeyWorker(
        armored,
        privArmored,
        keyPassphrase,
        verificationKeysArmored
      );
      plaintext = workerResult.plaintext;
      sigStatuses = workerResult.signatures || [];
      sessionKeys = (workerResult.sessionKeys || []).map((sk) => ({
        algorithm: sk.algorithm,
        aeadAlgorithm: sk.aeadAlgorithm,
        data: sk.length ? new Uint8Array(sk.length) : undefined,
        length: sk.length,
      }));
    }

    applySessionKeysToMap(sessionKeys);

    let sigHtml = "";
    if (sigStatuses.length) {
      const parts = [];
      for (const s of sigStatuses) {
        const kid = (s.keyID || "").toUpperCase();
        const link = kid ? keySearchLink(kid, formatFingerprint(kid)) : "";
        parts.push(
          s.verified
            ? `<span>${link} <span class="badge approved">verified</span></span>`
            : `<span>${link} <span class="badge">signature unverified</span></span>`
        );
      }
      sigHtml = `<p style="margin-bottom:0.75rem">${parts.join(" · ")}</p>`;
    }

    const cipherNote =
      sessionKeys[0]?.algorithm
        ? `<p class="muted">Session cipher: <code>${escapeHtml(
            String(sessionKeys[0].algorithm).toUpperCase()
          )}${
            sessionKeys[0].aeadAlgorithm
              ? "-" + String(sessionKeys[0].aeadAlgorithm).toUpperCase()
              : ""
          }</code>${
            sessionKeys[0].length ? ` (${sessionKeys[0].length} bytes)` : ""
          }</p>`
        : "";

    out.innerHTML = `
      <div class="card-title-row">
        <p class="card-title" style="margin:0">Plaintext</p>
        <button type="button" class="btn btn-ghost btn-compact" id="copy-plaintext-btn" title="Clipboard clears after 60 seconds">Copy (clears in 60s)</button>
      </div>
      ${cipherNote}
      ${sigHtml}
      <pre class="output-pre" id="decrypt-plaintext">${escapeHtml(plaintext)}</pre>
    `;
    out.classList.remove("hidden");
    lastPlaintext = plaintext;
    status.textContent = usePassword
      ? "Decrypted with passphrase. Passphrase cleared."
      : "Decrypted (worker when available). Key material zeroed.";
    status.className = "status-row ok";
  } catch (err) {
    status.className = "status-row err";
    status.textContent = err.message || "Decrypt failed";
    showError(errorEl, err.message || "Decrypt failed");
  } finally {
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
  if (t.id === "copy-plaintext-btn") {
    const text = lastPlaintext;
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

touchActivity();
