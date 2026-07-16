import { createMessage, encrypt, readKey } from "openpgp";
import { Auth } from "../lib/auth.js";
import { badgeClass } from "../lib/keys.js";
import {
  copyText,
  escapeHtml,
  extractEmail,
  fetchJson,
  fetchText,
  formatFingerprint,
  queryParam,
  showError,
} from "../lib/utils.js";
import "../css/site.css";

Auth.initWidget(document.getElementById("auth-widget"), "/compose");

const MAX_TOTAL_BYTES = 50 * 1024 * 1024;
const ENCRYPT_FLAG = 0x04 | 0x08;

const errorEl = document.getElementById("error");
const app = document.getElementById("compose-app");

/** @type {Map<string, Recipient>} */
const recipients = new Map();
/** @type {File[]} */
let files = [];
let activeTab = "message";
/** @type {Array<{ label: string, filename: string, armored: string }>} */
let outputs = [];
let searchTimer = null;
let encrypting = false;

/**
 * @typedef {{
 *   fingerprint: string,
 *   keyId: string,
 *   label: string,
 *   email: string,
 *   approvalState: string,
 *   revoked: boolean,
 *   valid: boolean,
 *   error: string,
 *   pgpKey: import("openpgp").Key | null,
 * }} Recipient
 */

function shortFpr(fpr) {
  const c = String(fpr || "")
    .toUpperCase()
    .replace(/[^0-9A-F]/g, "");
  return c.length > 8 ? c.slice(-8) : c;
}

function uidLabel(uids) {
  const list = uids || [];
  if (!list.length) return "";
  const uid = list[0];
  const email = extractEmail(uid);
  const m = String(uid).match(/^(.*)<[^>]+>\s*$/);
  const name = m ? m[1].trim() : "";
  if (name && email) return `${name} <${email}>`;
  return email || uid;
}

function formatBytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

function totalFileBytes() {
  return files.reduce((sum, f) => sum + f.size, 0);
}

function hasEncryptCapability(pgpKey) {
  try {
    const keys = [pgpKey, ...(pgpKey.subkeys || []).map((s) => s)];
    for (const k of keys) {
      const pkt = k.keyPacket || k;
      if (pkt && pkt.flags != null && pkt.flags & ENCRYPT_FLAG) return true;
    }
  } catch (_) {
    /* fall through */
  }
  return false;
}

async function loadRecipientKey(fingerprint) {
  const clean = String(fingerprint)
    .toUpperCase()
    .replace(/[^0-9A-F]/g, "");
  const [meta, armored] = await Promise.all([
    fetchJson(`/api/v1/key/${encodeURIComponent(clean)}`),
    fetchText(`/pks/lookup?op=get&search=${encodeURIComponent(`0x${clean}`)}`),
  ]);
  if (!String(armored).includes("BEGIN PGP")) {
    throw new Error("Could not fetch public key");
  }
  const pgpKey = await readKey({ armoredKey: armored });
  const uids = meta.approved_uids || meta.pending_uids || [];
  const label = uidLabel(uids) || formatFingerprint(clean);
  const email = extractEmail(uids[0] || "") || "";
  let valid = true;
  let err = "";
  if (meta.revoked) {
    valid = false;
    err = "Key is revoked";
  } else if (meta.approval_state !== "approved") {
    valid = false;
    err = `Key is ${meta.approval_state || "not approved"}`;
  } else if (!hasEncryptCapability(pgpKey)) {
    // Still try getEncryptionKey — OpenPGP.js is authoritative
    try {
      await pgpKey.getEncryptionKey();
    } catch (_) {
      valid = false;
      err = "No encryption-capable subkey";
    }
  }
  if (valid) {
    try {
      await pgpKey.getEncryptionKey();
    } catch (_) {
      valid = false;
      err = "No encryption-capable subkey";
    }
  }
  /** @type {Recipient} */
  const recipient = {
    fingerprint: clean,
    keyId: meta.key_id || clean.slice(-16),
    label,
    email,
    approvalState: meta.approval_state || "",
    revoked: !!meta.revoked,
    valid,
    error: err,
    pgpKey: valid ? pgpKey : null,
  };
  return recipient;
}

function validRecipients() {
  return [...recipients.values()].filter((r) => r.valid && r.pgpKey);
}

function canEncrypt() {
  if (encrypting) return false;
  if (!validRecipients().length) return false;
  const hasMsg = !!(document.getElementById("compose-message")?.value || "").trim();
  const hasFiles = files.length > 0;
  if (!hasMsg && !hasFiles) return false;
  if (totalFileBytes() > MAX_TOTAL_BYTES) return false;
  return true;
}

function updateEncryptButton() {
  const btn = document.getElementById("encrypt-btn");
  if (btn) btn.disabled = !canEncrypt();
  const tally = document.getElementById("size-tally");
  if (tally) {
    const total = totalFileBytes();
    const over = total > MAX_TOTAL_BYTES;
    tally.textContent = `${formatBytes(total)} / ${formatBytes(MAX_TOTAL_BYTES)}`;
    tally.classList.toggle("over", over);
  }
}

function renderPills() {
  const el = document.getElementById("recipient-pills");
  if (!el) return;
  if (!recipients.size) {
    el.innerHTML = `<p class="muted" style="margin:0">No recipients yet. Search by email, fingerprint, or key ID.</p>`;
    return;
  }
  el.innerHTML = [...recipients.values()]
    .map((r) => {
      const initial = (r.email || r.label || "?").charAt(0).toUpperCase();
      const title = r.error || formatFingerprint(r.fingerprint);
      return `<span class="recipient-pill${r.valid ? "" : " invalid"}" title="${escapeHtml(title)}" data-fpr="${escapeHtml(r.fingerprint)}">
        <span class="pill-avatar">${escapeHtml(initial)}</span>
        <span class="pill-body">
          <span class="pill-label">${escapeHtml(r.label)}</span>
          <span class="pill-fpr muted">${escapeHtml(shortFpr(r.fingerprint))}</span>
        </span>
        ${r.valid ? "" : `<span class="pill-warn" title="${escapeHtml(r.error)}">!</span>`}
        <button type="button" class="pill-remove" data-remove-fpr="${escapeHtml(r.fingerprint)}" aria-label="Remove recipient">×</button>
      </span>`;
    })
    .join("");
}

function renderFiles() {
  const el = document.getElementById("file-list");
  if (!el) return;
  if (!files.length) {
    el.innerHTML = "";
    updateEncryptButton();
    return;
  }
  el.innerHTML = `<ul class="file-list">${files
    .map(
      (f, i) => `<li>
      <span class="file-name">${escapeHtml(f.name)}</span>
      <span class="muted">${escapeHtml(formatBytes(f.size))}</span>
      <button type="button" class="btn btn-ghost btn-compact" data-remove-file="${i}">Remove</button>
    </li>`
    )
    .join("")}</ul>`;
  updateEncryptButton();
}

function renderDropdown(results) {
  const el = document.getElementById("recipient-dropdown");
  if (!el) return;
  if (!results || !results.length) {
    el.hidden = true;
    el.innerHTML = "";
    return;
  }
  el.hidden = false;
  el.innerHTML = results
    .map((item) => {
      const fp = item.fingerprint || "";
      const uids = item.approved_uids || item.uids || [];
      const label = uidLabel(uids) || formatFingerprint(fp);
      const state = item.approval_state || "";
      const already = recipients.has(fp.toUpperCase());
      return `<button type="button" class="recipient-hit" data-add-fpr="${escapeHtml(fp)}" ${already ? "disabled" : ""}>
        <span class="hit-main">
          <span class="hit-label">${escapeHtml(label)}</span>
          <code class="hit-fpr muted">${escapeHtml(formatFingerprint(fp))}</code>
        </span>
        <span class="${badgeClass(state)}">${escapeHtml(state)}</span>
        ${already ? `<span class="muted">Added</span>` : ""}
      </button>`;
    })
    .join("");
}

function truncateArmored(text, maxLines = 40) {
  const lines = String(text).split("\n");
  if (lines.length <= maxLines) {
    return { html: escapeHtml(text), truncated: false };
  }
  const head = lines.slice(0, maxLines).join("\n");
  return {
    html: escapeHtml(head) + "\n…",
    truncated: true,
    full: text,
  };
}

function renderOutput() {
  const el = document.getElementById("compose-output");
  if (!el) return;
  if (!outputs.length) {
    el.classList.add("hidden");
    el.innerHTML = "";
    return;
  }
  el.classList.remove("hidden");
  el.innerHTML = `
    <div class="card-title-row">
      <p class="card-title" style="margin:0">Encrypted output</p>
      <div class="btn-row">
        <button type="button" class="btn btn-ghost" id="reencrypt-btn">Re-encrypt</button>
        <button type="button" class="btn btn-ghost" id="clear-output-btn">Encrypt another</button>
      </div>
    </div>
    ${outputs
      .map((o, i) => {
        const trunc = truncateArmored(o.armored);
        return `<div class="output-artifact" data-output-idx="${i}">
          <div class="card-title-row" style="margin-bottom:0.5rem">
            <p style="margin:0;font-weight:600">${escapeHtml(o.label)}</p>
            <div class="btn-row">
              <button type="button" class="btn btn-ghost btn-compact" data-copy-output="${i}">Copy</button>
              <button type="button" class="btn btn-ghost btn-compact" data-download-output="${i}">Download</button>
            </div>
          </div>
          <pre class="output-pre${trunc.truncated ? " output-truncated" : ""}" data-output-pre="${i}">${trunc.html}</pre>
          ${
            trunc.truncated
              ? `<button type="button" class="text-link output-expand" data-expand-output="${i}">Show full ciphertext</button>`
              : ""
          }
        </div>`;
      })
      .join("")}`;
}

function setTab(name) {
  activeTab = name;
  document.querySelectorAll(".compose-tab").forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.tab === name);
  });
  const msg = document.getElementById("tab-message");
  const filesTab = document.getElementById("tab-files");
  if (msg) msg.classList.toggle("hidden", name !== "message");
  if (filesTab) filesTab.classList.toggle("hidden", name !== "files");
}

async function addRecipient(fingerprint) {
  const clean = String(fingerprint)
    .toUpperCase()
    .replace(/[^0-9A-F]/g, "");
  if (!clean || recipients.has(clean)) return;
  // Optimistic placeholder
  recipients.set(clean, {
    fingerprint: clean,
    keyId: clean.slice(-16),
    label: "Loading…",
    email: "",
    approvalState: "",
    revoked: false,
    valid: false,
    error: "Loading",
    pgpKey: null,
  });
  renderPills();
  updateEncryptButton();
  try {
    const recipient = await loadRecipientKey(clean);
    recipients.set(clean, recipient);
  } catch (err) {
    recipients.set(clean, {
      fingerprint: clean,
      keyId: clean.slice(-16),
      label: formatFingerprint(clean),
      email: "",
      approvalState: "",
      revoked: false,
      valid: false,
      error: err.message || "Failed to load key",
      pgpKey: null,
    });
  }
  renderPills();
  updateEncryptButton();
  renderDropdown([]);
  const input = document.getElementById("recipient-search");
  if (input) input.value = "";
}

function removeRecipient(fingerprint) {
  recipients.delete(
    String(fingerprint)
      .toUpperCase()
      .replace(/[^0-9A-F]/g, "")
  );
  renderPills();
  updateEncryptButton();
}

function addFiles(fileList) {
  const incoming = [...fileList];
  for (const f of incoming) {
    if (files.some((x) => x.name === f.name && x.size === f.size && x.lastModified === f.lastModified)) {
      continue;
    }
    files.push(f);
  }
  renderFiles();
}

function downloadBlob(filename, text) {
  const blob = new Blob([text], { type: "application/pgp-encrypted" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

async function runEncrypt() {
  errorEl.classList.add("hidden");
  if (!canEncrypt()) return;
  const keys = validRecipients().map((r) => r.pgpKey);
  const messageText = (document.getElementById("compose-message")?.value || "").trim();
  encrypting = true;
  updateEncryptButton();
  const status = document.getElementById("encrypt-status");
  if (status) {
    status.classList.remove("hidden");
    status.textContent = "Encrypting…";
  }
  try {
    /** @type {Array<{ label: string, filename: string, armored: string }>} */
    const next = [];
    if (messageText) {
      const msg = await createMessage({ text: messageText });
      const armored = await encrypt({
        message: msg,
        encryptionKeys: keys,
        format: "armored",
      });
      next.push({
        label: "Message",
        filename: "encrypted-message.asc",
        armored: String(armored),
      });
    }
    for (const file of files) {
      const buf = new Uint8Array(await file.arrayBuffer());
      const msg = await createMessage({ binary: buf, filename: file.name });
      const armored = await encrypt({
        message: msg,
        encryptionKeys: keys,
        format: "armored",
      });
      next.push({
        label: file.name,
        filename: `${file.name}.asc`,
        armored: String(armored),
      });
    }
    outputs = next;
    renderOutput();
    if (status) {
      status.textContent = `Encrypted ${next.length} artifact${next.length === 1 ? "" : "s"} for ${keys.length} recipient${keys.length === 1 ? "" : "s"}.`;
      status.className = "status-row ok";
    }
  } catch (err) {
    showError(errorEl, err.message || "Encryption failed");
    if (status) {
      status.textContent = err.message || "Encryption failed";
      status.className = "status-row err";
    }
  } finally {
    encrypting = false;
    updateEncryptButton();
  }
}

function renderApp() {
  app.innerHTML = `
    <div class="card">
      <p class="card-title">Recipients</p>
      <div id="recipient-pills" class="recipient-pills"></div>
      <div class="recipient-input-row">
        <input type="search" id="recipient-search" placeholder="Add recipient by email, fingerprint, or key ID…" autocomplete="off">
        <div id="recipient-dropdown" class="recipient-dropdown" hidden></div>
      </div>
    </div>

    <div class="card">
      <div class="compose-tabs" role="tablist">
        <button type="button" class="compose-tab active" data-tab="message" role="tab">Message</button>
        <button type="button" class="compose-tab" data-tab="files" role="tab">Files</button>
      </div>
      <div id="tab-message" role="tabpanel">
        <label class="sr-only" for="compose-message">Message</label>
        <textarea id="compose-message" class="compose-message" rows="10"
          placeholder="Type your message… (optional if you attach files)"></textarea>
      </div>
      <div id="tab-files" class="hidden" role="tabpanel">
        <div id="drop-zone" class="drop-zone" tabindex="0">
          <p><strong>Drop files here</strong> or</p>
          <label class="file-label" for="compose-files">Choose files</label>
          <input type="file" id="compose-files" multiple hidden>
          <p class="muted" style="margin-top:0.75rem">Max total ${formatBytes(MAX_TOTAL_BYTES)}. Each file becomes its own encrypted .asc.</p>
        </div>
        <div id="file-list"></div>
        <p class="size-tally muted" id="size-tally">0 B / ${formatBytes(MAX_TOTAL_BYTES)}</p>
      </div>
    </div>

    <div class="btn-row" style="margin:1rem 0">
      <button type="button" class="btn" id="encrypt-btn" disabled>Encrypt</button>
      <span id="encrypt-status" class="hidden"></span>
    </div>

    <div id="compose-output" class="card compose-output hidden"></div>

    <p class="muted" style="margin-top:1.5rem">
      Encrypt-only — no signing. Recipients decrypt with their private keys
      (<code>gpg --decrypt file.asc</code>).
    </p>
  `;

  renderPills();
  renderFiles();
  updateEncryptButton();
}

function wireEvents() {
  app.addEventListener("input", (e) => {
    if (e.target && e.target.id === "compose-message") updateEncryptButton();
    if (e.target && e.target.id === "recipient-search") {
      const q = e.target.value.trim();
      clearTimeout(searchTimer);
      if (!q) {
        renderDropdown([]);
        return;
      }
      searchTimer = setTimeout(async () => {
        try {
          const payload = await fetchJson(`/api/v1/search?q=${encodeURIComponent(q)}`);
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

    const tab = t.closest(".compose-tab");
    if (tab) {
      setTab(tab.dataset.tab);
      return;
    }

    const hit = t.closest("[data-add-fpr]");
    if (hit) {
      await addRecipient(hit.getAttribute("data-add-fpr"));
      return;
    }

    const rem = t.closest("[data-remove-fpr]");
    if (rem) {
      removeRecipient(rem.getAttribute("data-remove-fpr"));
      return;
    }

    const remFile = t.closest("[data-remove-file]");
    if (remFile) {
      const idx = Number(remFile.getAttribute("data-remove-file"));
      files.splice(idx, 1);
      renderFiles();
      return;
    }

    if (t.id === "encrypt-btn" || t.closest("#encrypt-btn")) {
      await runEncrypt();
      return;
    }

    if (t.id === "reencrypt-btn") {
      await runEncrypt();
      return;
    }

    if (t.id === "clear-output-btn") {
      outputs = [];
      renderOutput();
      const status = document.getElementById("encrypt-status");
      if (status) {
        status.className = "hidden";
        status.textContent = "";
      }
      return;
    }

    const copyBtn = t.closest("[data-copy-output]");
    if (copyBtn) {
      const i = Number(copyBtn.getAttribute("data-copy-output"));
      const o = outputs[i];
      if (!o) return;
      const original = copyBtn.textContent;
      try {
        await copyText(o.armored);
        copyBtn.textContent = "Copied";
        setTimeout(() => {
          copyBtn.textContent = original;
        }, 1500);
      } catch (_) {
        copyBtn.textContent = "Failed";
        setTimeout(() => {
          copyBtn.textContent = original;
        }, 1500);
      }
      return;
    }

    const dlBtn = t.closest("[data-download-output]");
    if (dlBtn) {
      const i = Number(dlBtn.getAttribute("data-download-output"));
      const o = outputs[i];
      if (o) downloadBlob(o.filename, o.armored);
      return;
    }

    const expand = t.closest("[data-expand-output]");
    if (expand) {
      const i = Number(expand.getAttribute("data-expand-output"));
      const o = outputs[i];
      const pre = document.querySelector(`[data-output-pre="${i}"]`);
      if (o && pre) {
        pre.textContent = o.armored;
        pre.classList.remove("output-truncated");
        expand.remove();
      }
    }
  });

  app.addEventListener("change", (e) => {
    if (e.target && e.target.id === "compose-files") {
      addFiles(e.target.files || []);
      e.target.value = "";
    }
  });

  // Drag and drop
  app.addEventListener("dragover", (e) => {
    const zone = e.target.closest?.("#drop-zone");
    if (!zone) return;
    e.preventDefault();
    zone.classList.add("dragover");
  });
  app.addEventListener("dragleave", (e) => {
    const zone = e.target.closest?.("#drop-zone");
    if (!zone) return;
    zone.classList.remove("dragover");
  });
  app.addEventListener("drop", (e) => {
    const zone = e.target.closest?.("#drop-zone");
    if (!zone) return;
    e.preventDefault();
    zone.classList.remove("dragover");
    if (e.dataTransfer?.files?.length) addFiles(e.dataTransfer.files);
  });

  // Close dropdown on outside click
  document.addEventListener("click", (e) => {
    const row = document.querySelector(".recipient-input-row");
    if (row && !row.contains(e.target)) renderDropdown([]);
  });

  // Keyboard navigation for recipient dropdown
  app.addEventListener("keydown", async (e) => {
    const dropdown = document.getElementById("recipient-dropdown");
    if (!dropdown || dropdown.hidden) return;
    const hits = [...dropdown.querySelectorAll(".recipient-hit:not(:disabled)")];
    if (!hits.length) return;
    const active = dropdown.querySelector(".recipient-hit.active");
    let idx = hits.indexOf(active);
    if (e.key === "ArrowDown") {
      e.preventDefault();
      idx = Math.min(hits.length - 1, idx + 1);
      hits.forEach((h) => h.classList.remove("active"));
      hits[idx].classList.add("active");
      hits[idx].focus();
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      idx = Math.max(0, idx < 0 ? 0 : idx - 1);
      hits.forEach((h) => h.classList.remove("active"));
      hits[idx].classList.add("active");
      hits[idx].focus();
    } else if (e.key === "Enter" && active) {
      e.preventDefault();
      await addRecipient(active.getAttribute("data-add-fpr"));
    } else if (e.key === "Escape") {
      renderDropdown([]);
    }
  });
}

async function init() {
  renderApp();
  wireEvents();
  const fpr = queryParam("fpr");
  if (fpr) {
    await addRecipient(fpr);
  }
  setTab(activeTab);
}

init().catch((err) => showError(errorEl, err.message || "Failed to load composer"));
