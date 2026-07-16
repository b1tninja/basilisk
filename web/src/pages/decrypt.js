import { decrypt, decryptKey, readMessage, readPrivateKey } from "openpgp";
import { Auth } from "../lib/auth.js";
import { escapeHtml, showError } from "../lib/utils.js";
import "../css/site.css";

Auth.initWidget(document.getElementById("auth-widget"), "/decrypt");

const errorEl = document.getElementById("error");
const app = document.getElementById("decrypt-app");

app.innerHTML = `
  <div class="card">
    <p class="card-title">Ciphertext</p>
    <label class="field-label" for="ciphertext">Armored message or signature</label>
    <textarea id="ciphertext" class="compose-message" rows="10"
      placeholder="-----BEGIN PGP MESSAGE-----&#10;…&#10;-----END PGP MESSAGE-----"></textarea>
    <div style="margin-top:0.75rem">
      <label class="file-label" for="cipher-file">Or choose a .asc / .pgp file</label>
      <input type="file" id="cipher-file" accept=".asc,.pgp,.gpg,text/plain" hidden>
      <span class="file-name" id="cipher-file-name"></span>
    </div>
  </div>

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
    <button type="button" class="btn" id="decrypt-btn">Decrypt / verify</button>
  </div>
  <div id="decrypt-status" class="hidden"></div>
  <div id="decrypt-output" class="card hidden"></div>
`;

document.getElementById("cipher-file").addEventListener("change", async (e) => {
  const f = e.target.files?.[0];
  document.getElementById("cipher-file-name").textContent = f ? f.name : "";
  if (f) {
    document.getElementById("ciphertext").value = await f.text();
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
    const message = await readMessage({ armoredMessage: armored });
    const result = await decrypt({
      message,
      decryptionKeys: privateKey,
      config: { allowInsecureDecryptionWithSigningKeys: true },
    });
    const plaintext =
      typeof result.data === "string"
        ? result.data
        : new TextDecoder().decode(result.data);
    const sigs = result.signatures || [];
    let sigHtml = "";
    if (sigs.length) {
      const parts = [];
      for (const s of sigs) {
        try {
          await s.verified;
          parts.push(`<span class="badge approved">signature valid</span>`);
        } catch (_) {
          parts.push(`<span class="badge">signature unverified</span>`);
        }
      }
      sigHtml = `<p style="margin-bottom:0.75rem">${parts.join(" ")}</p>`;
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
