import { Auth } from "../lib/auth.js";
import {
  compareFingerprints,
  normalizeFingerprintInput,
} from "../lib/pgp/verify-fpr.js";
import { getFirstVerifiedAt, recordVerification } from "../lib/verify-tofu.js";
import {
  copyText,
  describeExpiry,
  escapeHtml,
  fetchJson,
  formatDate,
  formatFingerprint,
  queryParam,
  showError,
  uidWithSearchLinks,
} from "../lib/utils.js";
import "../css/site.css";

Auth.initWidget(document.getElementById("auth-widget"), "/verify");

const errorEl = document.getElementById("error");
const app = document.getElementById("verify-app");

/** @type {MediaStream | null} */
let cameraStream = null;
/** @type {number | null} */
let scanTimer = null;

function stopCamera() {
  if (scanTimer != null) {
    clearInterval(scanTimer);
    scanTimer = null;
  }
  if (cameraStream) {
    for (const t of cameraStream.getTracks()) t.stop();
    cameraStream = null;
  }
  const video = document.getElementById("verify-video");
  if (video instanceof HTMLVideoElement) {
    video.srcObject = null;
  }
}

/**
 * Fingerprint as 4-hex groups with last 8 (key ID) highlighted.
 * @param {string} fpr
 */
function fingerprintBreakdownHtml(fpr) {
  const clean = normalizeFingerprintInput(fpr);
  if (clean.length < 8) {
    return `<code class="fpr">${escapeHtml(formatFingerprint(clean))}</code>`;
  }
  const body = clean.slice(0, -8);
  const keyId = clean.slice(-8);
  const groups = body.match(/.{1,4}/g) || [];
  const bodyHtml = groups
    .map((g) => `<span class="fpr-group">${escapeHtml(g)}</span>`)
    .join("");
  return `<span class="fpr-breakdown" aria-label="Fingerprint">${bodyHtml}<span class="fpr-group fpr-keyid" title="Key ID (last 8 hex)">${escapeHtml(
    keyId
  )}</span></span>`;
}

function renderApp() {
  const initial = queryParam("fpr") || "";
  app.innerHTML = `
    <div class="card">
      <p class="card-title">Expected fingerprint</p>
      <label class="field-label" for="expected-fpr">Fingerprint (or paste openpgp4fpr:…)</label>
      <input type="text" id="expected-fpr" class="text-input" autocomplete="off"
        placeholder="40 or 64 hex characters" value="${escapeHtml(initial)}">
      <p class="muted mt-sm">Optional: leave blank and only look up what you scan.</p>
      <div class="btn-row mt-md">
        <button type="button" class="btn btn-ghost btn-compact" id="share-verify-btn">Share verification link</button>
        <span id="share-verify-status" class="muted fs-sm"></span>
      </div>
    </div>

    <div class="card">
      <p class="card-title">Scan or enter</p>
      <div class="btn-row mb-md">
        <button type="button" class="btn" id="start-camera-btn">Start camera</button>
        <button type="button" class="btn btn-ghost" id="stop-camera-btn">Stop</button>
      </div>
      <video id="verify-video" class="verify-camera hidden" playsinline muted></video>
      <p id="camera-status" class="muted mt-sm"></p>
      <label class="field-label mt-lg" for="scanned-fpr">Fingerprint from QR / manual entry</label>
      <input type="text" id="scanned-fpr" class="text-input" autocomplete="off" placeholder="Scan QR or type fingerprint">
      <div class="btn-row mt-md">
        <button type="button" class="btn" id="check-btn">Check against keyserver</button>
      </div>
    </div>

    <div id="verify-out" class="hidden"></div>
  `;
}

/**
 * @param {string} fpr
 * @param {{ ok: boolean, reason: string } | null} cmp
 */
async function showResult(fpr, cmp) {
  const out = document.getElementById("verify-out");
  if (!out) return;
  const clean = normalizeFingerprintInput(fpr);
  if (clean.length !== 40 && clean.length !== 64) {
    out.className = "verify-result fail";
    out.classList.remove("hidden");
    out.innerHTML = `<p class="card-title m-0-b-xs">FAIL</p><p class="m-0">Invalid fingerprint (need 40 or 64 hex characters).</p>`;
    return;
  }

  let record = null;
  try {
    record = await fetchJson(`/api/v1/key/${encodeURIComponent(clean)}`);
  } catch (err) {
    out.className = "verify-result fail";
    out.classList.remove("hidden");
    out.innerHTML = `
      <p class="card-title m-0-b-xs">FAIL</p>
      <p class="m-0">${escapeHtml(err.message || "Key not found on this server.")}</p>
      <p class="muted fpr mt-md">${escapeHtml(formatFingerprint(clean))}</p>`;
    return;
  }

  const matchOk = !cmp || cmp.ok;
  const revoked = !!record.revoked;
  const approved = record.approval_state === "approved" && !revoked;
  const pass = matchOk && approved;
  const uids = (record.approved_uids || [])
    .map((u) => `<li>${uidWithSearchLinks(u)}</li>`)
    .join("");
  const certCount = Array.isArray(record.certifications)
    ? record.certifications.length
    : 0;
  const expiry = record.key_expiration
    ? describeExpiry(record.key_expiration)
    : null;
  const expiryHtml = expiry
    ? expiry.relative
      ? `${escapeHtml(expiry.absolute)} <span class="expiry-badge ${expiry.tone}">${escapeHtml(expiry.relative)}</span>`
      : escapeHtml(expiry.absolute)
    : "Does not expire / unknown";

  let tofuNote = "";
  if (pass) {
    const tofu = recordVerification(clean);
    tofuNote = tofu.isNew
      ? `<p class="status-row mt-md mb-0" role="status">New key — never verified in this browser before. First verified just now.</p>`
      : `<p class="muted mt-md mb-0">You first verified this key on ${escapeHtml(
          formatDate(tofu.firstSeen)
        )}.</p>`;
  } else {
    const prior = getFirstVerifiedAt(clean);
    if (prior) {
      tofuNote = `<p class="muted mt-md mb-0">You previously verified this fingerprint on ${escapeHtml(
        formatDate(prior)
      )}.</p>`;
    }
  }

  out.className = `verify-result ${pass ? "pass" : "fail"}`;
  out.classList.remove("hidden");
  out.innerHTML = `
    <p class="card-title m-0-b-xs">${pass ? "PASS" : "FAIL"}</p>
    <p class="m-0-b-sm">${escapeHtml(
      cmp && !cmp.ok
        ? cmp.reason
        : revoked
          ? "Key is revoked."
          : approved
            ? "Fingerprint found and approved on this keyserver."
            : `Key state: ${record.approval_state || "unknown"}`
    )}</p>
    <p class="m-0-b-sm">${fingerprintBreakdownHtml(clean)}</p>
    <dl class="key-meta-grid mt-md">
      <div class="key-meta-row"><dt>Approval</dt><dd>${escapeHtml(
        revoked ? "revoked" : record.approval_state || "—"
      )}</dd></div>
      <div class="key-meta-row"><dt>Expires</dt><dd>${expiryHtml}</dd></div>
      <div class="key-meta-row"><dt>Certifications</dt><dd>${escapeHtml(
        String(certCount)
      )}</dd></div>
      <div class="key-meta-row"><dt>Key ID</dt><dd><code>${escapeHtml(
        clean.slice(-8)
      )}</code></dd></div>
    </dl>
    <p class="muted m-0-b-sm">Still confirm this fingerprint and verified email out of band before trusting the key.</p>
    ${uids ? `<ul class="uid-list">${uids}</ul>` : ""}
    ${tofuNote}
    <div class="btn-row mt-md">
      <a class="text-link" href="/key?fpr=${encodeURIComponent(clean)}">Open key page</a>
      <button type="button" class="btn btn-ghost btn-compact" id="share-result-btn"
        data-fpr="${escapeHtml(clean)}">Share verification link</button>
    </div>
  `;

  document.getElementById("share-result-btn")?.addEventListener("click", () => {
    const url = `${window.location.origin}/verify?fpr=${encodeURIComponent(clean)}`;
    copyText(url).then(
      () => {
        const st = document.getElementById("share-verify-status");
        if (st) st.textContent = "Link copied.";
      },
      () => showError(errorEl, "Could not copy link")
    );
  });
}

async function startCamera() {
  const status = document.getElementById("camera-status");
  const video = document.getElementById("verify-video");
  if (!(video instanceof HTMLVideoElement)) return;

  stopCamera();
  if (typeof BarcodeDetector === "undefined") {
    if (status) {
      status.textContent =
        "BarcodeDetector is not available in this browser. Paste an openpgp4fpr: URI or fingerprint manually.";
    }
    return;
  }

  try {
    cameraStream = await navigator.mediaDevices.getUserMedia({
      video: { facingMode: { ideal: "environment" } },
      audio: false,
    });
    video.srcObject = cameraStream;
    video.classList.remove("hidden");
    await video.play();
    if (status) status.textContent = "Point the camera at an openpgp4fpr QR code…";

    const detector = new BarcodeDetector({ formats: ["qr_code"] });
    scanTimer = window.setInterval(async () => {
      if (video.readyState < 2) return;
      try {
        const codes = await detector.detect(video);
        for (const c of codes) {
          const raw = String(c.rawValue || "");
          if (!/openpgp4fpr:|[0-9a-fA-F]{40,}/i.test(raw)) continue;
          const scanned = document.getElementById("scanned-fpr");
          if (scanned instanceof HTMLInputElement) {
            // Prefer openpgp4fpr line from rich QR payloads
            const line =
              raw
                .split(/\r?\n/)
                .find((l) => /openpgp4fpr:/i.test(l)) || raw;
            scanned.value = line.trim();
          }
          if (status) status.textContent = "QR detected — checking…";
          stopCamera();
          await runCheck();
          return;
        }
      } catch (_) {
        /* ignore frame errors */
      }
    }, 400);
  } catch (err) {
    if (status) {
      status.textContent = err?.message || "Could not start camera.";
    }
  }
}

async function runCheck() {
  showError(errorEl, "");
  const expectedEl = document.getElementById("expected-fpr");
  const scannedEl = document.getElementById("scanned-fpr");
  const expected = expectedEl instanceof HTMLInputElement ? expectedEl.value : "";
  const scanned = scannedEl instanceof HTMLInputElement ? scannedEl.value : "";

  const expectedClean = normalizeFingerprintInput(expected);
  const scannedClean = normalizeFingerprintInput(scanned);
  const lookup = scannedClean || expectedClean;

  if (!lookup) {
    showError(errorEl, "Enter or scan a fingerprint.");
    return;
  }

  let cmp = null;
  if (expectedClean && scannedClean) {
    cmp = compareFingerprints(expectedClean, scannedClean);
  }

  await showResult(lookup, cmp);
}

function wireEvents() {
  app.addEventListener("click", (e) => {
    const t = /** @type {HTMLElement} */ (e.target);
    if (t.id === "start-camera-btn" || t.closest("#start-camera-btn")) {
      startCamera();
    }
    if (t.id === "stop-camera-btn" || t.closest("#stop-camera-btn")) {
      stopCamera();
      const status = document.getElementById("camera-status");
      if (status) status.textContent = "";
    }
    if (t.id === "check-btn" || t.closest("#check-btn")) {
      runCheck();
    }
    if (t.id === "share-verify-btn" || t.closest("#share-verify-btn")) {
      const expectedEl = document.getElementById("expected-fpr");
      const fpr = normalizeFingerprintInput(
        expectedEl instanceof HTMLInputElement ? expectedEl.value : ""
      );
      if (fpr.length !== 40 && fpr.length !== 64) {
        showError(errorEl, "Enter a valid fingerprint to share.");
        return;
      }
      const url = `${window.location.origin}/verify?fpr=${encodeURIComponent(fpr)}`;
      copyText(url).then(
        () => {
          const st = document.getElementById("share-verify-status");
          if (st) st.textContent = "Link copied.";
        },
        () => showError(errorEl, "Could not copy link")
      );
    }
  });
}

renderApp();
wireEvents();

const initialFpr = normalizeFingerprintInput(queryParam("fpr") || "");
if (initialFpr.length === 40 || initialFpr.length === 64) {
  runCheck();
}

window.addEventListener("pagehide", stopCamera);
