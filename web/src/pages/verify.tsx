// First import on the page, deliberately: it installs listeners for failures
// that happen *while the rest of this module graph loads*. Anything imported
// above it could fail unobserved.
import { installBootDiagnostics } from "../lib/boot-diagnostics.js";
import { createRoot } from "react-dom/client";
import { useEffect, useRef, useState } from "react";
import { Layout } from "../components/Layout";
import { compareFingerprints, normalizeFingerprintInput } from "../lib/pgp/verify-fpr.js";
import { setTrust, trustBadgeHtml } from "../lib/trust.js";
import { getFirstVerifiedAt, recordVerification } from "../lib/verify-tofu.js";
import {
  copyText,
  describeExpiry,
  escapeHtml,
  fetchJson,
  formatDate,
  formatFingerprint,
  queryParam,
  uidWithSearchLinks,
} from "../lib/utils.js";

declare const BarcodeDetector: {
  new (opts: { formats: string[] }): {
    detect(video: HTMLVideoElement): Promise<{ rawValue?: string }[]>;
  };
};

type KeyRecord = {
  revoked?: boolean;
  approval_state?: string;
  approved_uids?: string[];
  certifications?: unknown[];
  key_expiration?: string;
};

/** Fingerprint as 4-hex groups with last 8 (key ID) highlighted. */
function fingerprintBreakdownHtml(fpr: string): string {
  const clean = normalizeFingerprintInput(fpr);
  if (clean.length < 8) {
    return `<code class="fpr">${escapeHtml(formatFingerprint(clean))}</code>`;
  }
  const body = clean.slice(0, -8);
  const keyId = clean.slice(-8);
  const groups = body.match(/.{1,4}/g) || [];
  const bodyHtml = groups.map((g) => `<span class="fpr-group">${escapeHtml(g)}</span>`).join("");
  return `<span class="fpr-breakdown" aria-label="Fingerprint">${bodyHtml}<span class="fpr-group fpr-keyid" title="Key ID (last 8 hex)">${escapeHtml(keyId)}</span></span>`;
}

function VerifyPage() {
  const initialFpr = queryParam("fpr") || "";
  const [expectedFpr, setExpectedFpr] = useState(initialFpr);
  const [scannedFpr, setScannedFpr] = useState("");
  const [error, setError] = useState("");
  const [cameraStatus, setCameraStatus] = useState("");
  const [shareStatus, setShareStatus] = useState("");
  const [cameraOn, setCameraOn] = useState(false);
  const [resultClass, setResultClass] = useState("");
  const [resultHtml, setResultHtml] = useState("");

  const videoRef = useRef<HTMLVideoElement | null>(null);
  const scannedFprRef = useRef(scannedFpr);
  scannedFprRef.current = scannedFpr;
  const streamRef = useRef<MediaStream | null>(null);
  const timerRef = useRef<number | null>(null);

  const stopCamera = () => {
    if (timerRef.current != null) {
      clearInterval(timerRef.current);
      timerRef.current = null;
    }
    if (streamRef.current) {
      for (const t of streamRef.current.getTracks()) t.stop();
      streamRef.current = null;
    }
    if (videoRef.current) videoRef.current.srcObject = null;
    setCameraOn(false);
  };

  useEffect(() => {
    window.addEventListener("pagehide", stopCamera);
    return () => {
      window.removeEventListener("pagehide", stopCamera);
      stopCamera();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const showResult = async (fpr: string, cmp: { ok: boolean; reason: string } | null) => {
    const clean = normalizeFingerprintInput(fpr);
    if (clean.length !== 40 && clean.length !== 64) {
      setResultClass("verify-result fail");
      setResultHtml(
        `<p class="card-title m-0-b-xs">FAIL</p><p class="m-0">Invalid fingerprint (need 40 or 64 hex characters).</p>`
      );
      return;
    }

    let record: KeyRecord;
    try {
      record = await fetchJson(`/api/v1/key/${encodeURIComponent(clean)}`);
    } catch (err) {
      setResultClass("verify-result fail");
      setResultHtml(`
        <p class="card-title m-0-b-xs">FAIL</p>
        <p class="m-0">${escapeHtml(err instanceof Error ? err.message : "Key not found on this server.")}</p>
        <p class="muted fpr mt-md">${escapeHtml(formatFingerprint(clean))}</p>`);
      return;
    }

    const matchOk = !cmp || cmp.ok;
    const revoked = !!record.revoked;
    const approved = record.approval_state === "approved" && !revoked;
    const pass = matchOk && approved;
    const uids = (record.approved_uids || []).map((u) => `<li>${uidWithSearchLinks(u)}</li>`).join("");
    const certCount = Array.isArray(record.certifications) ? record.certifications.length : 0;
    const expiry = record.key_expiration ? describeExpiry(record.key_expiration) : null;
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
        : `<p class="muted mt-md mb-0">You first verified this key on ${escapeHtml(formatDate(tofu.firstSeen))}.</p>`;
    } else {
      const prior = getFirstVerifiedAt(clean);
      if (prior) {
        tofuNote = `<p class="muted mt-md mb-0">You previously verified this fingerprint on ${escapeHtml(formatDate(prior))}.</p>`;
      }
    }

    setResultClass(`verify-result ${pass ? "pass" : "fail"}`);
    setResultHtml(`
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
        <div class="key-meta-row"><dt>Approval</dt><dd>${escapeHtml(revoked ? "revoked" : record.approval_state || "—")}</dd></div>
        <div class="key-meta-row"><dt>Expires</dt><dd>${expiryHtml}</dd></div>
        <div class="key-meta-row"><dt>Certifications</dt><dd>${escapeHtml(String(certCount))}</dd></div>
        <div class="key-meta-row"><dt>Key ID</dt><dd><code>${escapeHtml(clean.slice(-8))}</code></dd></div>
      </dl>
      <p class="muted m-0-b-sm">Still confirm this fingerprint and verified email out of band before trusting the key.</p>
      ${uids ? `<ul class="uid-list">${uids}</ul>` : ""}
      ${tofuNote}
      ${
        pass
          ? `<div class="btn-row mt-md">
        <button type="button" class="btn" id="mark-trusted-btn">Mark this key as trusted</button>
        <span id="mark-trusted-status" class="muted fs-sm">${trustBadgeHtml(clean)}</span>
      </div>`
          : ""
      }
      <div class="btn-row mt-md">
        <a class="text-link" href="/key?fpr=${encodeURIComponent(clean)}">Open key page</a>
        <button type="button" class="btn btn-ghost btn-compact" id="share-result-btn" data-fpr="${escapeHtml(clean)}">Share verification link</button>
      </div>
    `);
  };

  const runCheck = async () => {
    setError("");
    const expectedClean = normalizeFingerprintInput(expectedFpr);
    const scannedClean = normalizeFingerprintInput(scannedFprRef.current);
    const lookup = scannedClean || expectedClean;
    if (!lookup) {
      setError("Enter or scan a fingerprint.");
      return;
    }
    let cmp: { ok: boolean; reason: string } | null = null;
    if (expectedClean && scannedClean) {
      cmp = compareFingerprints(expectedClean, scannedClean);
    }
    await showResult(lookup, cmp);
  };
  const runCheckRef = useRef(runCheck);
  runCheckRef.current = runCheck;

  const startCamera = async () => {
    const video = videoRef.current;
    if (!video) return;
    stopCamera();
    if (typeof BarcodeDetector === "undefined") {
      setCameraStatus(
        "BarcodeDetector is not available in this browser. Paste an openpgp4fpr: URI or fingerprint manually."
      );
      return;
    }
    try {
      const stream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: { ideal: "environment" } },
        audio: false,
      });
      streamRef.current = stream;
      video.srcObject = stream;
      setCameraOn(true);
      await video.play();
      setCameraStatus("Point the camera at an openpgp4fpr QR code…");

      const detector = new BarcodeDetector({ formats: ["qr_code"] });
      timerRef.current = window.setInterval(async () => {
        if (video.readyState < 2) return;
        try {
          const codes = await detector.detect(video);
          for (const c of codes) {
            const raw = String(c.rawValue || "");
            if (!/openpgp4fpr:|[0-9a-fA-F]{40,}/i.test(raw)) continue;
            const line = raw.split(/\r?\n/).find((l) => /openpgp4fpr:/i.test(l)) || raw;
            setScannedFpr(line.trim());
            setCameraStatus("QR detected — checking…");
            stopCamera();
            await runCheckRef.current();
            return;
          }
        } catch {
          /* ignore frame errors */
        }
      }, 400);
    } catch (err) {
      setCameraStatus(err instanceof Error ? err.message : "Could not start camera.");
    }
  };

  const shareLink = async (fpr: string) => {
    const clean = normalizeFingerprintInput(fpr);
    if (clean.length !== 40 && clean.length !== 64) {
      setError("Enter a valid fingerprint to share.");
      return;
    }
    const url = `${window.location.origin}/verify?fpr=${encodeURIComponent(clean)}`;
    try {
      await copyText(url);
      setShareStatus("Link copied.");
    } catch {
      setError("Could not copy link");
    }
  };

  useEffect(() => {
    if (initialFpr) {
      const clean = normalizeFingerprintInput(initialFpr);
      if (clean.length === 40 || clean.length === 64) void runCheckRef.current();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <Layout active="verify">
      <div className="page-header">
        <h1>Verify fingerprint</h1>
        <p className="muted">
          Scan an <code>openpgp4fpr:</code> QR or enter a fingerprint, then confirm against this
          keyserver. Always verify email and fingerprint — names are unverified.
        </p>
      </div>

      {error ? <p className="text-error">{error}</p> : null}

      <div className="card">
        <p className="card-title">Expected fingerprint</p>
        <label className="field-label" htmlFor="expected-fpr">
          Fingerprint (or paste openpgp4fpr:…)
        </label>
        <input
          type="text"
          id="expected-fpr"
          className="text-input"
          autoComplete="off"
          placeholder="40 or 64 hex characters"
          value={expectedFpr}
          onChange={(e) => setExpectedFpr(e.target.value)}
        />
        <p className="muted mt-sm">Optional: leave blank and only look up what you scan.</p>
        <div className="btn-row mt-md">
          <button
            type="button"
            className="btn btn-ghost btn-compact"
            onClick={() => void shareLink(expectedFpr)}
          >
            Share verification link
          </button>
          <span className="muted fs-sm">{shareStatus}</span>
        </div>
      </div>

      <div className="card">
        <p className="card-title">Scan or enter</p>
        <div className="btn-row mb-md">
          <button type="button" className="btn" onClick={() => void startCamera()}>
            Start camera
          </button>
          <button
            type="button"
            className="btn btn-ghost"
            onClick={() => {
              stopCamera();
              setCameraStatus("");
            }}
          >
            Stop
          </button>
        </div>
        <video
          id="verify-video"
          ref={videoRef}
          className={cameraOn ? "verify-camera" : "verify-camera hidden"}
          playsInline
          muted
        />
        <p className="muted mt-sm">{cameraStatus}</p>
        <label className="field-label mt-lg" htmlFor="scanned-fpr">
          Fingerprint from QR / manual entry
        </label>
        <input
          type="text"
          id="scanned-fpr"
          className="text-input"
          autoComplete="off"
          placeholder="Scan QR or type fingerprint"
          value={scannedFpr}
          onChange={(e) => setScannedFpr(e.target.value)}
        />
        <div className="btn-row mt-md">
          <button type="button" className="btn" onClick={() => void runCheck()}>
            Check against keyserver
          </button>
        </div>
      </div>

      {resultHtml ? (
        <div
          className={resultClass}
          onClick={(e) => {
            const t = e.target as HTMLElement;
            if (t.id === "share-result-btn" || t.closest("#share-result-btn")) {
              void shareLink(t.dataset.fpr || (t.closest("#share-result-btn") as HTMLElement)?.dataset.fpr || "");
            }
            if (t.id === "mark-trusted-btn" || t.closest("#mark-trusted-btn")) {
              const clean = normalizeFingerprintInput(expectedFpr || scannedFpr);
              const fprMatch = resultHtml.match(/data-fpr="([^"]+)"/);
              const fpr = fprMatch ? fprMatch[1] : clean;
              setTrust(fpr, "trusted");
              const st = document.getElementById("mark-trusted-status");
              if (st) st.innerHTML = trustBadgeHtml(fpr);
              const btn = document.getElementById("mark-trusted-btn") as HTMLButtonElement | null;
              if (btn) {
                btn.textContent = "Marked trusted";
                btn.disabled = true;
              }
            }
          }}
          dangerouslySetInnerHTML={{ __html: resultHtml }}
        />
      ) : null}
    </Layout>
  );
}

installBootDiagnostics();
createRoot(document.getElementById("app")!).render(<VerifyPage />);
