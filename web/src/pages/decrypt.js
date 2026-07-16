import {
  decrypt,
  decryptKey,
  enums,
  readCleartextMessage,
  readKey,
  readMessage,
  readPrivateKey,
  readSignature,
  verify,
} from "openpgp";
import { Auth } from "../lib/auth.js";
import {
  escapeHtml,
  fetchText,
  formatDate,
  formatFingerprint,
  searchUrl,
  showError,
} from "../lib/utils.js";
import "../css/site.css";

Auth.initWidget(document.getElementById("auth-widget"), "/decrypt");

const errorEl = document.getElementById("error");
const app = document.getElementById("decrypt-app");

/** @type {ReturnType<typeof analyzeArmored> extends Promise<infer T> ? T | null : never} */
let currentAnalysis = null;
let analyzeTimer = null;
let verifyGen = 0;

app.innerHTML = `
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

  <div id="decrypt-section" class="hidden">
    <div class="card">
      <p class="card-title">Private key (local only)</p>
      <label class="field-label" for="private-key">Armored private key</label>
      <textarea id="private-key" class="compose-message" rows="8"
        placeholder="-----BEGIN PGP PRIVATE KEY BLOCK-----&#10;…"></textarea>
      <label class="field-label" for="passphrase" style="margin-top:0.75rem">Passphrase</label>
      <input type="password" id="passphrase" class="text-input" autocomplete="off" placeholder="Key passphrase (if any)">
      <p class="muted" style="margin-top:0.65rem">Nothing is uploaded. Clear this page when finished.</p>
    </div>
    <div class="btn-row">
      <button type="button" class="btn" id="decrypt-btn">Decrypt</button>
    </div>
    <div id="decrypt-status" class="hidden"></div>
    <div id="decrypt-output" class="card hidden"></div>
  </div>
`;

/**
 * @param {import("openpgp").KeyID | { toHex?: () => string, bytes?: Uint8Array } | null | undefined} keyID
 * @returns {string}
 */
function keyIdHex(keyID) {
  if (!keyID) return "";
  try {
    if (typeof keyID.toHex === "function") return String(keyID.toHex()).toUpperCase();
  } catch (_) {
    /* fall through */
  }
  if (keyID.bytes instanceof Uint8Array) {
    return Array.from(keyID.bytes)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("")
      .toUpperCase();
  }
  return String(keyID).toUpperCase().replace(/[^0-9A-F]/g, "");
}

/**
 * @param {Uint8Array | null | undefined} fp
 * @returns {string}
 */
function fingerprintHex(fp) {
  if (!(fp instanceof Uint8Array) || !fp.length) return "";
  return Array.from(fp)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")
    .toUpperCase();
}

function isAnonymousKeyId(hex) {
  return !hex || /^0+$/.test(hex);
}

/**
 * @param {Iterable} packets
 * @returns {Array<{ keyId: string, fingerprint: string, created: Date | null }>}
 */
function sigDetailsFromPackets(packets) {
  const list = Array.isArray(packets) ? packets : [...(packets || [])];
  return list.map((pkt) => {
    const keyId = keyIdHex(pkt.issuerKeyID);
    const fingerprint = fingerprintHex(pkt.issuerFingerprint);
    const created =
      pkt.created instanceof Date && !Number.isNaN(pkt.created.getTime())
        ? pkt.created
        : null;
    return { keyId, fingerprint, created };
  });
}

/**
 * @param {string} armored
 */
async function analyzeArmored(armored) {
  const text = String(armored || "").trim();
  if (!text) {
    return { type: "empty", recipientKeyIDs: [], sigDetails: [], cleartext: "", message: null };
  }

  // Encrypted or binary signed message
  try {
    const message = await readMessage({ armoredMessage: text });
    const recipientKeyIDs = (message.getEncryptionKeyIDs?.() || []).map(keyIdHex);
    let sigDetails = [];
    try {
      const sigPkts = message.packets?.filterByTag?.(enums.packet.signature) || [];
      sigDetails = sigDetailsFromPackets(sigPkts);
    } catch (_) {
      /* ignore */
    }
    if (!sigDetails.length && typeof message.getSigningKeyIDs === "function") {
      sigDetails = (message.getSigningKeyIDs() || []).map((id) => ({
        keyId: keyIdHex(id),
        fingerprint: "",
        created: null,
      }));
    }
    const encrypted = recipientKeyIDs.length > 0;
    return {
      type: encrypted ? "encrypted" : "message",
      recipientKeyIDs,
      sigDetails,
      cleartext: "",
      message,
    };
  } catch (_) {
    /* try cleartext / signature */
  }

  // Clearsigned message
  try {
    const clearMsg = await readCleartextMessage({ cleartextMessage: text });
    let sigDetails = [];
    try {
      const sigPkts = clearMsg.signature?.packets || [];
      sigDetails = sigDetailsFromPackets(sigPkts);
    } catch (_) {
      /* ignore */
    }
    if (!sigDetails.length && typeof clearMsg.getSigningKeyIDs === "function") {
      sigDetails = (clearMsg.getSigningKeyIDs() || []).map((id) => ({
        keyId: keyIdHex(id),
        fingerprint: "",
        created: null,
      }));
    }
    return {
      type: "cleartext",
      recipientKeyIDs: [],
      sigDetails,
      cleartext: clearMsg.getText?.() ?? String(clearMsg.text || ""),
      message: clearMsg,
    };
  } catch (_) {
    /* try detached signature */
  }

  // Detached signature
  try {
    const signature = await readSignature({ armoredSignature: text });
    const sigDetails = sigDetailsFromPackets(signature.packets || []);
    return {
      type: "detached",
      recipientKeyIDs: [],
      sigDetails,
      cleartext: "",
      message: signature,
    };
  } catch (err) {
    throw new Error(err?.message || "Could not parse as a PGP message or signature.");
  }
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

function keySearchLink(hex, label) {
  if (isAnonymousKeyId(hex)) {
    return `<span class="muted">${escapeHtml(label || "anonymous")}</span>`;
  }
  const q = `0x${hex}`;
  const display = label || formatFingerprint(hex);
  return `<a class="text-link fpr" href="${escapeHtml(searchUrl(q))}" title="Search keyserver">${escapeHtml(display)}</a>`;
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

async function runAnalyze() {
  errorEl.classList.add("hidden");
  const armored = document.getElementById("ciphertext").value.trim();
  if (!armored) {
    currentAnalysis = null;
    renderInspect(null);
    updateDecryptSection(null);
    return;
  }
  try {
    const analysis = await analyzeArmored(armored);
    currentAnalysis = analysis;
    renderInspect(analysis);
    updateDecryptSection(analysis);
    await verifySigners(analysis);
  } catch (err) {
    currentAnalysis = null;
    renderInspect(null);
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

document.getElementById("ciphertext").addEventListener("input", scheduleAnalyze);

document.getElementById("cipher-file").addEventListener("change", async (e) => {
  const f = e.target.files?.[0];
  document.getElementById("cipher-file-name").textContent = f ? f.name : "";
  if (f) {
    document.getElementById("ciphertext").value = await f.text();
    await runAnalyze();
  }
});

document.getElementById("decrypt-btn").addEventListener("click", async () => {
  errorEl.classList.add("hidden");
  const status = document.getElementById("decrypt-status");
  const out = document.getElementById("decrypt-output");
  out.classList.add("hidden");
  status.className = "status-row";
  status.textContent = "Working…";
  status.classList.remove("hidden");

  const armored = document.getElementById("ciphertext").value.trim();
  const privArmored = document.getElementById("private-key").value.trim();
  const passphrase = document.getElementById("passphrase").value;

  if (!armored) {
    showError(errorEl, "Paste a PGP message or choose a file.");
    status.className = "hidden";
    return;
  }
  if (!privArmored) {
    showError(errorEl, "Paste your private key to decrypt (stays in the browser).");
    status.className = "hidden";
    return;
  }

  try {
    let privateKey = await readPrivateKey({ armoredKey: privArmored });
    if (!privateKey.isDecrypted()) {
      privateKey = await decryptKey({ privateKey, passphrase });
    }
    const message =
      currentAnalysis?.type === "encrypted" && currentAnalysis.message
        ? currentAnalysis.message
        : await readMessage({ armoredMessage: armored });

    let result = await decrypt({
      message,
      decryptionKeys: privateKey,
      config: { allowInsecureDecryptionWithSigningKeys: true },
    });

    // Look up signing keys on this keyserver and re-decrypt with verificationKeys.
    const signerIds = [
      ...new Set(
        (result.signatures || [])
          .map((s) => keyIdHex(s.keyID))
          .filter((id) => id && !isAnonymousKeyId(id))
      ),
    ];
    if (signerIds.length) {
      const verificationKeys = [];
      await Promise.all(
        signerIds.map(async (id) => {
          try {
            const armoredKey = await fetchText(
              `/pks/lookup?op=get&search=${encodeURIComponent(`0x${id}`)}`
            );
            if (String(armoredKey).includes("BEGIN PGP")) {
              verificationKeys.push(await readKey({ armoredKey }));
            }
          } catch (_) {
            /* skip */
          }
        })
      );
      if (verificationKeys.length) {
        result = await decrypt({
          message,
          decryptionKeys: privateKey,
          verificationKeys,
          config: { allowInsecureDecryptionWithSigningKeys: true },
        });
      }
    }

    const plaintext =
      typeof result.data === "string"
        ? result.data
        : new TextDecoder().decode(result.data);
    const sigs = result.signatures || [];
    let sigHtml = "";
    if (sigs.length) {
      const parts = [];
      for (const s of sigs) {
        const kid = keyIdHex(s.keyID);
        const link = kid
          ? keySearchLink(kid, formatFingerprint(kid))
          : "";
        try {
          await s.verified;
          parts.push(
            `<span>${link} <span class="badge approved">verified</span></span>`
          );
        } catch (_) {
          parts.push(
            `<span>${link} <span class="badge">signature unverified</span></span>`
          );
        }
      }
      sigHtml = `<p style="margin-bottom:0.75rem">${parts.join(" · ")}</p>`;
    }
    out.innerHTML = `
      <p class="card-title">Plaintext</p>
      ${sigHtml}
      <pre class="output-pre">${escapeHtml(plaintext)}</pre>
    `;
    out.classList.remove("hidden");
    status.textContent = "Decrypted locally.";
    status.className = "status-row ok";
  } catch (err) {
    status.className = "status-row err";
    status.textContent = err.message || "Decrypt failed";
    showError(errorEl, err.message || "Decrypt failed");
  }
});
