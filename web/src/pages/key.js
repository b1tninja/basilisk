import { readKey } from "openpgp";
import { Auth } from "../lib/auth.js";
import {
  copyText,
  describeExpiry,
  escapeHtml,
  extractEmail,
  fetchJson,
  fetchText,
  formatDate,
  formatFingerprint,
  queryParam,
  searchUrl,
  showError,
  uidWithSearchLinks,
} from "../lib/utils.js";
import { badgeClass } from "../lib/keys.js";
import {
  renderKeyClientSnippets,
  wireSnippetCopy,
} from "../lib/snippets.js";
import "../css/site.css";

Auth.initWidget(document.getElementById("auth-widget"));

const fpr = queryParam("fpr");
const error = document.getElementById("error");
const content = document.getElementById("content");
const loading = document.getElementById("loading");

function metaRow(label, valueHtml) {
  return `<div class="key-meta-row"><dt>${escapeHtml(label)}</dt><dd>${valueHtml}</dd></div>`;
}

function copyButton(label, value, id) {
  return `<button type="button" class="btn btn-ghost btn-compact" data-copy="${escapeHtml(value)}" id="${escapeHtml(id)}">${escapeHtml(label)}</button>`;
}

function formatAlgo(info) {
  if (!info) return "—";
  const parts = [info.algorithm || info.algo || ""];
  if (info.curve) parts.push(info.curve);
  if (info.bits) parts.push(`${info.bits}-bit`);
  return parts.filter(Boolean).join(" / ") || "—";
}

function usageTags(keyPacket) {
  const tags = [];
  try {
    if (keyPacket?.flags != null) {
      // OpenPGP key flags: 0x01 certify, 0x02 sign, 0x04 encrypt comm, 0x08 encrypt storage, 0x20 auth
      const flags = keyPacket.flags;
      if (flags & 0x02) tags.push("Sign");
      if (flags & 0x04 || flags & 0x08) tags.push("Encrypt");
      if (flags & 0x20) tags.push("Auth");
      if (flags & 0x01) tags.push("Certify");
    }
  } catch (_) {
    /* ignore */
  }
  if (!tags.length) return '<span class="muted">—</span>';
  return tags.map((t) => `<span class="usage-tag">${escapeHtml(t)}</span>`).join(" ");
}

function renderUids(record) {
  const approved = record.approved_uids || [];
  const pending = record.pending_uids || [];
  const items = [
    ...approved.map((u) => ({ uid: u, state: "approved" })),
    ...pending
      .filter((u) => !approved.includes(u))
      .map((u) => ({ uid: u, state: "pending" })),
  ];
  if (!items.length) return `<p class="muted">No user IDs available.</p>`;
  return `<ul class="uid-list">${items
    .map(({ uid, state }) => {
      return `<li>
        <div class="uid-main">
          <span class="${badgeClass(state)}">${escapeHtml(state)}</span>
          <span class="uid-text">${uidWithSearchLinks(uid)}</span>
        </div>
      </li>`;
    })
    .join("")}</ul>`;
}

async function renderSubkeys(pgpKey) {
  if (!pgpKey || !pgpKey.subkeys || !pgpKey.subkeys.length) {
    return `<p class="muted">No subkeys.</p>`;
  }
  const rows = [];
  for (const sub of pgpKey.subkeys) {
    let algo = "—";
    let created = "—";
    let expires = "—";
    let fprSub = "";
    try {
      const info = await sub.getAlgorithmInfo();
      algo = formatAlgo(info);
    } catch (_) {
      /* ignore */
    }
    try {
      created = formatDate(sub.getCreationTime());
    } catch (_) {
      /* ignore */
    }
    try {
      const exp = await sub.getExpirationTime();
      if (exp === Infinity || exp == null) {
        expires = "Does not expire";
      } else {
        const info = describeExpiry(exp);
        expires = info.relative
          ? `${escapeHtml(info.absolute)} <span class="expiry-badge ${info.tone}">${escapeHtml(info.relative)}</span>`
          : escapeHtml(info.absolute);
      }
    } catch (_) {
      /* ignore */
    }
    try {
      fprSub = sub.getFingerprint().toUpperCase();
    } catch (_) {
      /* ignore */
    }
    const keyPacket = sub.keyPacket || sub;
    rows.push(`<tr>
      <td><code class="fpr">${escapeHtml(formatFingerprint(fprSub))}</code></td>
      <td>${escapeHtml(algo)}</td>
      <td>${usageTags(keyPacket)}</td>
      <td>${escapeHtml(created)}</td>
      <td>${expires}</td>
    </tr>`);
  }
  return `<table class="key-table"><thead><tr>
    <th>Fingerprint</th><th>Algorithm</th><th>Usage</th><th>Created</th><th>Expires</th>
  </tr></thead><tbody>${rows.join("")}</tbody></table>`;
}

function renderArmored(armored, fingerprint) {
  if (!armored) return "";
  return `
    <div class="card">
      <div class="card-title-row">
        <p class="card-title" style="margin:0">Public key</p>
        <div class="btn-row">
          <button type="button" class="btn btn-ghost" id="copy-armored">Copy</button>
          <a class="btn btn-ghost" id="download-armored"
             download="${escapeHtml(fingerprint)}.asc"
             href="#">Download .asc</a>
        </div>
      </div>
      <pre id="armored">${escapeHtml(armored)}</pre>
    </div>`;
}

async function maybeClaimNotice(record) {
  if (record.approval_state !== "pending") return "";
  const user = await Auth.getUser();
  if (!user || !user.authenticated) {
    const providers = await Auth.getProviders();
    const buttons = Auth.providerButtons(
      window.location.pathname + window.location.search,
      providers
    );
    return `<div class="card claim-notice">
      <p class="card-title">Claim this key</p>
      <p class="muted" style="margin-bottom:1rem">Sign in with an email that matches a UID on this key to claim ownership.</p>
      ${buttons || ""}
    </div>`;
  }
  const email = (user.email || "").toLowerCase();
  const pending = record.pending_uids || [];
  const match = pending.some((u) => extractEmail(u) === email);
  if (!match) {
    return `<div class="card claim-notice">
      <p class="muted">This key is pending. Your signed-in email does not match any pending UID.</p>
    </div>`;
  }
  return `<div class="card claim-notice">
    <p class="card-title">Claim this key</p>
    <p class="muted" style="margin-bottom:1rem">Your email matches a UID on this key. Submit a claim to verify ownership.</p>
    <form id="claim-form" method="post" action="/claim/${escapeHtml(record.fingerprint)}">
      <button class="btn" type="submit">Claim key</button>
    </form>
    <p id="claim-status" class="hidden"></p>
  </div>`;
}

async function loadKey() {
  if (!fpr) {
    loading.classList.add("hidden");
    showError(error, "Missing fingerprint — use ?fpr=…");
    return;
  }

  const clean = fpr.replace(/^0x/i, "").toUpperCase();
  document.title = `Key ${clean} — Basilisk`;

  try {
    const [metaResult, armoredResult] = await Promise.allSettled([
      fetchJson(`/api/v1/key/${encodeURIComponent(clean)}`),
      fetchText(`/pks/lookup?op=get&search=${encodeURIComponent(`0x${clean}`)}`),
    ]);

    if (metaResult.status !== "fulfilled") {
      throw metaResult.reason || new Error("Key not found");
    }
    const record = metaResult.value;
    const armored =
      armoredResult.status === "fulfilled" &&
      String(armoredResult.value).includes("BEGIN PGP")
        ? armoredResult.value
        : null;

    let pgpKey = null;
    if (armored) {
      try {
        pgpKey = await readKey({ armoredKey: armored });
      } catch (_) {
        pgpKey = null;
      }
    }

    let algo = "—";
    let created = "—";
    let pgpExpiry = null;
    if (pgpKey) {
      try {
        algo = formatAlgo(await pgpKey.getAlgorithmInfo());
      } catch (_) {
        /* ignore */
      }
      try {
        created = formatDate(pgpKey.getCreationTime());
      } catch (_) {
        /* ignore */
      }
      try {
        const exp = await pgpKey.getExpirationTime();
        if (exp && exp !== Infinity) pgpExpiry = exp;
      } catch (_) {
        /* ignore */
      }
    }

    // Prefer DB value (set at ingest); fall back to OpenPGP.js for legacy rows.
    const expirySource = record.key_expiration || pgpExpiry;
    const expiryInfo = describeExpiry(expirySource);
    const expiryHtml = expiryInfo.relative
      ? `${escapeHtml(expiryInfo.absolute)} <span class="expiry-badge ${expiryInfo.tone}">${escapeHtml(expiryInfo.relative)}</span>`
      : escapeHtml(expiryInfo.absolute);

    const statusBadge = record.revoked
      ? `<span class="badge revoked">revoked</span>`
      : `<span class="${badgeClass(record.approval_state)}">${escapeHtml(record.approval_state)}</span>`;

    const revokedBanner = record.revoked
      ? `<div class="card revoked-notice">
          <p class="card-title">This key is revoked</p>
          <p class="muted" style="margin:0">Do not use it for encryption or trust decisions. Fetch the revocation with GnuPG if you need the certificate update.</p>
        </div>`
      : "";

    const claimHtml = await maybeClaimNotice(record);
    const subkeysHtml = await renderSubkeys(pgpKey);
    const clientSnippets = renderKeyClientSnippets({
      fingerprint: record.fingerprint,
      keyId: record.key_id,
      approved: record.approval_state === "approved" && !record.revoked,
    });

    const fpDisplay = formatFingerprint(record.fingerprint);
    const fpRaw = String(record.fingerprint || "").toUpperCase();
    const keyId = String(record.key_id || "");
    const pageUrl = `${window.location.origin}/key?fpr=${encodeURIComponent(fpRaw)}`;
    const claimerHtml = record.claimer_email
      ? `<a class="text-link" href="${escapeHtml(searchUrl(record.claimer_email))}" title="Search for this email">${escapeHtml(record.claimer_email)}</a>`
      : "";

    content.innerHTML = `
      <div class="page-header">
        <div class="page-header-row">
          <div>
            <h1>OpenPGP key</h1>
            <p class="muted fpr">${escapeHtml(fpDisplay)}</p>
            <p style="margin-top:0.5rem">${statusBadge}</p>
          </div>
          <div class="btn-row">
            ${copyButton("Copy link", pageUrl, "copy-page-link")}
            ${copyButton("Copy fingerprint", fpRaw, "copy-fingerprint")}
          </div>
        </div>
      </div>

      ${revokedBanner}

      <div class="card">
        <p class="card-title">Key information</p>
        <dl class="key-meta-grid">
          ${metaRow(
            "Fingerprint",
            `<span class="meta-with-action"><code class="fpr">${escapeHtml(fpDisplay)}</code>${copyButton("Copy", fpRaw, "copy-fpr-meta")}</span>`
          )}
          ${metaRow(
            "Key ID",
            `<span class="meta-with-action"><a class="text-link" href="${escapeHtml(searchUrl(`0x${keyId}`))}" title="Search by key ID"><code>${escapeHtml(keyId)}</code></a>${copyButton("Copy", keyId, "copy-keyid")}</span>`
          )}
          ${metaRow("Algorithm", escapeHtml(algo))}
          ${metaRow("Created", escapeHtml(created))}
          ${metaRow("Primary expires", expiryHtml)}
          ${metaRow("Revoked", escapeHtml(record.revoked ? "Yes" : "No"))}
          ${claimerHtml ? metaRow("Claimed by", claimerHtml) : ""}
        </dl>
      </div>

      <div class="card">
        <div class="card-title-row">
          <p class="card-title" style="margin:0">User IDs</p>
          <p class="muted" style="margin:0;font-size:0.8rem">Click a name or email to search</p>
        </div>
        ${renderUids(record)}
      </div>

      <div class="card">
        <p class="card-title">Subkeys</p>
        ${subkeysHtml}
      </div>

      ${claimHtml}
      ${clientSnippets}
      ${renderArmored(armored, record.fingerprint)}
      <p><a class="text-link" href="/">← Back to search</a></p>
    `;

    loading.classList.add("hidden");
    content.classList.remove("hidden");

    wireSnippetCopy(content);

    const copyArmored = document.getElementById("copy-armored");
    if (copyArmored && armored) {
      copyArmored.addEventListener("click", async () => {
        try {
          await copyText(armored);
          copyArmored.textContent = "Copied";
          setTimeout(() => {
            copyArmored.textContent = "Copy";
          }, 1500);
        } catch (_) {
          copyArmored.textContent = "Failed";
          setTimeout(() => {
            copyArmored.textContent = "Copy";
          }, 1500);
        }
      });
    }

    const dl = document.getElementById("download-armored");
    if (dl && armored) {
      const blob = new Blob([armored], { type: "application/pgp-keys" });
      dl.href = URL.createObjectURL(blob);
    }
  } catch (err) {
    loading.classList.add("hidden");
    showError(error, err.message || "Key not found");
  }
}

loadKey();
