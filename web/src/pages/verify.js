import { Auth } from "../lib/auth.js";
import {
  compareFingerprints,
  normalizeFingerprintInput,
} from "../lib/pgp/verify-fpr.js";
import {
  escapeHtml,
  fetchJson,
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

function renderApp() {
  const initial = queryParam("fpr") || "";
  app.innerHTML = `
    <div class="card">
      <p class="card-title">Expected fingerprint</p>
      <label class="field-label" for="expected-fpr">Fingerprint (or paste openpgp4fpr:…)</label>
      <input type="text" id="expected-fpr" class="text-input" autocomplete="off"
        placeholder="40 hex characters" value="${escapeHtml(initial)}">
      <p class="muted mt-sm">Optional: leave blank and only look up what you scan.</p>
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
  if (clean.length !== 40) {
    out.className = "verify-result fail";
    out.classList.remove("hidden");
    out.innerHTML = `<p class="card-title m-0-b-xs">FAIL</p><p class="m-0">Invalid fingerprint.</p>`;
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
    <p class="fpr m-0-b-sm"><code>${escapeHtml(formatFingerprint(clean))}</code></p>
    <p class="muted m-0-b-sm">Still confirm this fingerprint and verified email out of band before trusting the key.</p>
    ${uids ? `<ul class="uid-list">${uids}</ul>` : ""}
    <p class="mt-md"><a class="text-link" href="/key?fpr=${encodeURIComponent(clean)}">Open key page</a></p>
  `;
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
          if (!/openpgp4fpr:|^[0-9a-fA-F\s]{40,}$/i.test(raw)) continue;
          const scanned = document.getElementById("scanned-fpr");
          if (scanned instanceof HTMLInputElement) {
            scanned.value = normalizeFingerprintInput(raw) || raw;
          }
          if (status) status.textContent = "QR detected — checking…";
          stopCamera();
          await runCheck();
          return;
        }
      } catch (_) {
        /* keep scanning */
      }
    }, 500);
  } catch (err) {
    if (status) {
      status.textContent = err?.message || "Could not access camera.";
    }
  }
}

async function runCheck() {
  errorEl.classList.add("hidden");
  const expected = document.getElementById("expected-fpr")?.value || "";
  const scanned = document.getElementById("scanned-fpr")?.value || "";
  const target = normalizeFingerprintInput(scanned) || normalizeFingerprintInput(expected);
  if (!target) {
    showError(errorEl, "Enter or scan a fingerprint.");
    return;
  }
  let cmp = null;
  if (expected.trim() && scanned.trim()) {
    cmp = compareFingerprints(expected, scanned);
    if (!cmp.ok) {
      await showResult(scanned || expected, cmp);
      return;
    }
  }
  await showResult(target, cmp);
}

function wireEvents() {
  app.addEventListener("click", async (e) => {
    const t = e.target;
    if (!(t instanceof Element)) return;
    if (t.id === "start-camera-btn") {
      await startCamera();
      return;
    }
    if (t.id === "stop-camera-btn") {
      stopCamera();
      const status = document.getElementById("camera-status");
      if (status) status.textContent = "Camera stopped.";
      return;
    }
    if (t.id === "check-btn") {
      await runCheck();
    }
  });
  window.addEventListener("beforeunload", stopCamera);
  document.addEventListener("visibilitychange", () => {
    if (document.hidden) stopCamera();
  });
}

renderApp();
wireEvents();
if (queryParam("fpr")) {
  // Prefill expected; user still scans or pastes to confirm.
}
