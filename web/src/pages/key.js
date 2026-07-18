import { readKey } from "openpgp";
import { Auth } from "../lib/auth.js";
import { formatAlgo } from "../lib/pgp/algos.js";
import { collectDeprecationWarnings } from "../lib/pgp/deprecation.js";
import { readKeyPreferences } from "../lib/pgp/preferences.js";
import { openpgp4fprUri, qrSvg, richOpenpgpQrPayload } from "../lib/qr.js";
import {
  copyButtonHtml,
  copyText,
  describeExpiry,
  escapeHtml,
  fetchJson,
  fetchText,
  formatDate,
  formatFingerprint,
  queryParam,
  searchUrl,
  showError,
  uidEmail,
  uidRaw,
  uidWithSearchLinks,
} from "../lib/utils.js";
import { badgeClass } from "../lib/keys.js";
import {
  renderKeyClientSnippets,
  wireSnippetCopy,
} from "../lib/snippets.js";
import {
  trustBadgeHtml,
  trustControlsHtml,
  wireTrustControls,
} from "../lib/trust.js";
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
  return copyButtonHtml(label, value, { id });
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

/**
 * @param {string[]} warnings
 */
function renderDeprecationNotice(warnings) {
  if (!warnings.length) return "";
  return `<div class="card deprecation-notice" role="status">
    <p class="card-title">Deprecated algorithms (RFC 9580 §9.1)</p>
    <ul class="deprecation-list m-0">
      ${warnings.map((w) => `<li>${escapeHtml(w)}</li>`).join("")}
    </ul>
    <p class="muted mt-sm mb-0 fs-sm">Shown for awareness — this key remains usable for interoperability.</p>
  </div>`;
}

/**
 * @param {Awaited<ReturnType<typeof readKeyPreferences>>} prefs
 */
function renderPreferencesCard(prefs) {
  const rows = [
    ["Preferred symmetric", prefs.symmetric],
    ["Preferred AEAD", prefs.aead],
    ["Preferred hash", prefs.hash],
    ["Preferred compression", prefs.compression],
  ];
  const hasAny = rows.some(([, list]) => list.length);
  if (!hasAny && !prefs.noModify) {
    return `<div class="card">
      <p class="card-title">Algorithm preferences</p>
      <p class="muted m-0">No preference subpackets on the primary self-signature (RFC 9580 §5.2.3.14–17).</p>
    </div>`;
  }
  const prefRows = rows
    .map(([label, list]) => {
      const value = list.length
        ? list.map((a) => `<code class="pref-algo">${escapeHtml(a)}</code>`).join(" ")
        : `<span class="muted">—</span>`;
      return metaRow(label, value);
    })
    .join("");
  const noModify = prefs.noModify
    ? `<p class="status-row mt-md mb-0" role="status">Key server preference: <strong>no-modify</strong> — third-party certifications should not be merged onto this key (RFC 9580 §5.2.3.25).</p>`
    : "";
  return `<div class="card">
    <p class="card-title">Algorithm preferences</p>
    <p class="muted fs-sm mt-0">From the primary self-signature (RFC 9580 §5.2.3.14–17).</p>
    <dl class="key-meta-grid">${prefRows}</dl>
    ${noModify}
  </div>`;
}

/**
 * @param {import("../lib/pgp/notations.js").NotationEntry[]} notations
 */
function renderNotationsCard(notations) {
  if (!notations?.length) return "";
  return `<div class="card">
    <p class="card-title">Notations</p>
    <p class="muted fs-sm mt-0">Notation Data on the primary self-signature (RFC 9580 §5.2.3.24).</p>
    <ul class="notation-list m-0">${notations
      .map(
        (n) => `<li>
        <code class="notation-name">${escapeHtml(n.name)}</code>
        <span class="notation-value">${escapeHtml(n.value)}</span>
      </li>`
      )
      .join("")}</ul>
  </div>`;
}

function renderUids(record) {
  const approved = record.approved_uids || [];
  const pending = record.pending_uids || [];
  const approvedRaws = new Set(approved.map(uidRaw));
  const items = [
    ...approved.map((u) => ({ uid: u, state: "approved" })),
    ...pending
      .filter((u) => !approvedRaws.has(uidRaw(u)))
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
        <p class="card-title m-0">Public key</p>
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
      <p class="muted mb-lg">Sign in with an email that matches a UID on this key to claim ownership.</p>
      ${buttons || ""}
    </div>`;
  }
  const email = (user.email || "").toLowerCase();
  const pending = record.pending_uids || [];
  const match = pending.some((u) => uidEmail(u) === email);
  if (!match) {
    return `<div class="card claim-notice">
      <p class="muted">This key is pending. Your signed-in email does not match any pending UID.</p>
    </div>`;
  }
  return `<div class="card claim-notice">
    <p class="card-title">Claim this key</p>
    <p class="muted mb-lg">Your email matches a UID on this key. Submit a claim to verify ownership.</p>
    <button type="button" class="btn" id="claim-btn" data-fpr="${escapeHtml(record.fingerprint)}">Claim key</button>
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
    /** @type {{ algorithm?: string, algo?: string, curve?: string } | null} */
    let primaryAlgoInfo = null;
    /** @type {Array<{ algorithm?: string, algo?: string, curve?: string }>} */
    const subAlgoInfos = [];
    let prefs = {
      symmetric: [],
      aead: [],
      hash: [],
      compression: [],
      noModify: false,
      hashAlgorithm: null,
      notations: [],
    };
    let keyVersion = null;
    /** @type {string[]} */
    let bindingWarnings = [];
    if (pgpKey) {
      try {
        primaryAlgoInfo = await pgpKey.getAlgorithmInfo();
        algo = formatAlgo(primaryAlgoInfo);
      } catch (_) {
        /* ignore */
      }
      try {
        keyVersion = pgpKey.keyPacket?.version ?? null;
      } catch (_) {
        keyVersion = null;
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
      if (pgpKey.subkeys?.length) {
        for (const sub of pgpKey.subkeys) {
          try {
            subAlgoInfos.push(await sub.getAlgorithmInfo());
          } catch (_) {
            /* ignore */
          }
          if (keyVersion === 6) {
            try {
              await sub.verify();
            } catch (err) {
              bindingWarnings.push(
                `Subkey ${formatFingerprint(sub.getFingerprint?.() || "")}: ${err?.message || "binding check failed"}`
              );
            }
          }
        }
      }
      prefs = await readKeyPreferences(pgpKey);
    }
    if (!keyVersion) {
      const hexLen = String(record.fingerprint || "")
        .replace(/[^0-9A-Fa-f]/g, "").length;
      if (hexLen === 64) keyVersion = 6;
      else if (hexLen === 40) keyVersion = 4;
    }

    const deprecationWarnings = collectDeprecationWarnings({
      primary: primaryAlgoInfo,
      subkeys: subAlgoInfos,
      hashAlgorithm: prefs.hashAlgorithm,
    });
    const deprecationHtml = renderDeprecationNotice(deprecationWarnings);
    const preferencesHtml = pgpKey ? renderPreferencesCard(prefs) : "";
    const notationsHtml = renderNotationsCard(prefs.notations || []);
    const bindingWarnHtml = bindingWarnings.length
      ? `<div class="card deprecation-notice" role="status">
          <p class="card-title">v6 subkey binding</p>
          <ul class="deprecation-list m-0">${bindingWarnings
            .map((w) => `<li>${escapeHtml(w)}</li>`)
            .join("")}</ul>
        </div>`
      : "";
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
          <p class="muted m-0">Do not use it for encryption or trust decisions. Fetch the revocation with GnuPG if you need the certificate update.</p>
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
    const fpRaw = String(record.fingerprint || "")
      .toUpperCase()
      .replace(/[^0-9A-F]/g, "");
    const keyId = String(record.key_id || "");
    const pageUrl = `${window.location.origin}/key?fpr=${encodeURIComponent(fpRaw)}`;
    const firstSeen = record.created_at ? formatDate(record.created_at) : "—";
    const lastModified = record.updated_at ? formatDate(record.updated_at) : "—";
    const tofuHtml = `<div class="card">
        <div class="card-title-row">
          <p class="card-title m-0">Key continuity (server TOFU)</p>
          <a class="text-link fs-sm" href="/api/v1/key/${encodeURIComponent(fpRaw)}/history" target="_blank" rel="noopener">History JSON</a>
        </div>
        <dl class="key-meta-grid">
          ${metaRow("First seen", escapeHtml(firstSeen))}
          ${metaRow("Last modified", escapeHtml(lastModified))}
          ${metaRow("SHA-256", `<code class="fpr">${escapeHtml(record.sha256 || "—")}</code>`)}
        </dl>
        <p class="muted fs-sm mb-0">Compare these timestamps and digests on later visits to detect silent key substitution.</p>
      </div>`;
    const claimerHtml = record.claimer_email
      ? `<a class="text-link" href="${escapeHtml(searchUrl(record.claimer_email))}" title="Search for this email">${escapeHtml(record.claimer_email)}</a>`
      : "";

    const user = await Auth.getUser().catch(() => null);
    const isClaimer = Boolean(
      user?.authenticated &&
        record.claimer_email &&
        user.email?.toLowerCase() === record.claimer_email?.toLowerCase()
    );
    const currentLabel = record.label || "";
    const labelDisplayHtml = currentLabel
      ? `<p class="key-label" id="key-label-display" title="Owner-supplied label">🏷 ${escapeHtml(currentLabel)}</p>`
      : isClaimer
        ? `<p class="key-label muted" id="key-label-display">No label set</p>`
        : "";
    const labelEditHtml = isClaimer
      ? `<button type="button" class="btn btn-ghost btn-compact" id="label-edit-btn">${currentLabel ? "Edit label" : "Add label"}</button>
         <form id="label-form" class="label-form hidden" autocomplete="off">
           <input type="text" id="label-input" class="label-input" maxlength="200"
                  placeholder="e.g. Work signing key"
                  value="${escapeHtml(currentLabel)}" />
           <button type="submit" class="btn btn-compact">Save</button>
           <button type="button" class="btn btn-ghost btn-compact" id="label-cancel-btn">Cancel</button>
           ${currentLabel ? `<button type="button" class="btn btn-ghost btn-compact text-error" id="label-clear-btn">Remove</button>` : ""}
         </form>
         <span id="label-status" class="label-status hidden"></span>`
      : "";

    const primaryUid =
      (record.approved_uids && record.approved_uids[0]) ||
      (record.pending_uids && record.pending_uids[0]) ||
      null;
    const richUid = {
      name:
        primaryUid && typeof primaryUid === "object"
          ? String(primaryUid.name || "").trim()
          : "",
      email: uidEmail(primaryUid),
    };
    const fprUri = openpgp4fprUri(fpRaw);
    const richPayload = richOpenpgpQrPayload(fpRaw, richUid);
    let verifyQrHtml = "";
    try {
      const svgFpr = qrSvg(fprUri, { moduleSize: 3, margin: 2 });
      verifyQrHtml = `
      <div class="card verify-card">
        <div class="card-title-row">
          <p class="card-title m-0">Out-of-band verify</p>
          <a class="text-link" href="/verify?fpr=${encodeURIComponent(fpRaw)}">Open verifier</a>
        </div>
        <label class="field-label field-label-inline mb-md">
          <input type="checkbox" id="rich-qr-toggle"
            data-fpr-uri="${escapeHtml(fprUri)}"
            data-rich-payload="${escapeHtml(richPayload)}">
          Rich QR (include name/email for offline check)
        </label>
        <div class="verify-qr-row">
          <div class="verify-qr" id="verify-qr-svg" aria-hidden="true">${svgFpr}</div>
          <div>
            <p class="m-0-b-sm">Compare this fingerprint in person or over a trusted channel.</p>
            <p class="muted fpr m-0-b-md">${escapeHtml(fpDisplay)}</p>
            <p class="muted m-0 fs-sm" id="verify-qr-caption">QR encodes <code>${escapeHtml(fprUri)}</code> (OpenKeychain-compatible). Always confirm the email and full fingerprint — never trust a name alone.</p>
          </div>
        </div>
      </div>`;
    } catch (_) {
      verifyQrHtml = "";
    }

    const certifications = Array.isArray(record.certifications) ? record.certifications : [];
    const signedByHtml = certifications.length
      ? `<div class="card">
          <p class="card-title">Signed by</p>
          <ul class="uid-list">${certifications
            .map((c) => {
              const sf = String(c.signer_fingerprint || "").toUpperCase();
              const label = formatFingerprint(sf);
              return `<li>
                <div class="uid-main">
                  <a class="text-link fpr" href="/key?fpr=${encodeURIComponent(sf)}">${escapeHtml(label)}</a>
                  ${c.uid ? `<span class="muted">${escapeHtml(c.uid)}</span>` : ""}
                </div>
              </li>`;
            })
            .join("")}</ul>
          <p class="muted mt-md fs-sm">Attested certifications from keys approved on this server. Still verify fingerprints out of band.</p>
        </div>`
      : "";

    content.innerHTML = `
      <div class="page-header">
        <div class="page-header-row">
          <div>
            <h1>OpenPGP key</h1>
            <p class="muted fpr">${escapeHtml(fpDisplay)}</p>
            ${labelDisplayHtml}
            ${labelEditHtml}
            <p class="mt-sm">${statusBadge} ${trustBadgeHtml(fpRaw)}</p>
          </div>
          <div class="btn-row">
            ${
              record.revoked
                ? ""
                : `<a class="btn btn-compose" href="/encrypt?fpr=${encodeURIComponent(fpRaw)}" title="Encrypt a message or file to this key">Encrypt</a>`
            }
            ${copyButton("Copy link", pageUrl, "copy-page-link")}
            ${copyButton("Copy fingerprint", fpRaw, "copy-fingerprint")}
          </div>
        </div>
        <div class="card mt-md trust-card">
          ${trustControlsHtml(fpRaw, "key-trust")}
        </div>
      </div>

      ${revokedBanner}
      ${deprecationHtml}
      ${bindingWarnHtml}

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
          ${
            keyVersion
              ? metaRow(
                  "Version",
                  `<span class="key-version-badge">v${escapeHtml(String(keyVersion))}</span>${
                    keyVersion === 6
                      ? ` <span class="muted fs-sm">(${fpRaw.length}-hex fingerprint)</span>`
                      : ""
                  }`
                )
              : ""
          }
          ${metaRow("Algorithm", escapeHtml(algo))}
          ${metaRow("Created", escapeHtml(created))}
          ${metaRow("Primary expires", expiryHtml)}
          ${metaRow("Revoked", escapeHtml(record.revoked ? "Yes" : "No"))}
          ${claimerHtml ? metaRow("Claimed by", claimerHtml) : ""}
        </dl>
      </div>

      ${tofuHtml}
      ${preferencesHtml}
      ${notationsHtml}

      ${verifyQrHtml}

      <div class="card">
        <div class="card-title-row">
          <p class="card-title m-0">User IDs</p>
          <p class="muted m-0 fs-xs">Verified emails are solid links; names are dashed (unverified) — always confirm email and fingerprint</p>
        </div>
        ${renderUids(record)}
      </div>

      ${signedByHtml}

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
    wireTrustControls(content);

    const richToggle = document.getElementById("rich-qr-toggle");
    const qrSvgEl = document.getElementById("verify-qr-svg");
    const qrCaption = document.getElementById("verify-qr-caption");
    richToggle?.addEventListener("change", () => {
      if (!(richToggle instanceof HTMLInputElement) || !qrSvgEl) return;
      const fprUri = richToggle.dataset.fprUri || "";
      const rich = richToggle.dataset.richPayload || "";
      const payload = richToggle.checked ? rich : fprUri;
      try {
        qrSvgEl.innerHTML = qrSvg(payload, { moduleSize: 3, margin: 2 });
        if (qrCaption) {
          qrCaption.innerHTML = richToggle.checked
            ? `Rich QR includes UID text plus <code>${escapeHtml(fprUri)}</code> for offline identity check.`
            : `QR encodes <code>${escapeHtml(fprUri)}</code> (OpenKeychain-compatible). Always confirm the email and full fingerprint — never trust a name alone.`;
        }
      } catch (_) {
        /* ignore */
      }
    });

    // Label edit (claimer only)
    const labelEditBtn = document.getElementById("label-edit-btn");
    const labelForm = document.getElementById("label-form");
    const labelCancelBtn = document.getElementById("label-cancel-btn");
    const labelClearBtn = document.getElementById("label-clear-btn");
    const labelStatus = document.getElementById("label-status");
    const labelDisplay = document.getElementById("key-label-display");

    if (labelEditBtn && labelForm) {
      labelEditBtn.addEventListener("click", () => {
        labelForm.classList.toggle("hidden");
        if (!labelForm.classList.contains("hidden")) {
          document.getElementById("label-input")?.focus();
        }
      });
      labelCancelBtn?.addEventListener("click", () => labelForm.classList.add("hidden"));

      const saveLabel = async (newLabel) => {
        if (labelStatus) {
          labelStatus.textContent = "Saving…";
          labelStatus.className = "label-status";
        }
        try {
          const result = await fetchJson(
            `/api/v1/me/keys/${encodeURIComponent(fpRaw)}/label`,
            { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ label: newLabel }) }
          );
          const saved = result.label || "";
          if (labelDisplay) {
            labelDisplay.textContent = saved ? `🏷 ${saved}` : (isClaimer ? "No label set" : "");
            labelDisplay.className = saved ? "key-label" : "key-label muted";
            labelDisplay.title = saved ? "Owner-supplied label" : "";
          }
          if (labelEditBtn) labelEditBtn.textContent = saved ? "Edit label" : "Add label";
          labelForm.classList.add("hidden");
          if (labelStatus) {
            labelStatus.textContent = "Saved";
            labelStatus.className = "label-status ok";
            setTimeout(() => { if (labelStatus) labelStatus.className = "label-status hidden"; }, 2000);
          }
        } catch (err) {
          if (labelStatus) {
            labelStatus.textContent = err.message || "Save failed";
            labelStatus.className = "label-status err";
          }
        }
      };

      labelForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        const val = (document.getElementById("label-input")?.value || "").trim();
        await saveLabel(val);
      });
      labelClearBtn?.addEventListener("click", () => saveLabel(""));
    }

    const claimBtn = document.getElementById("claim-btn");
    if (claimBtn) {
      claimBtn.addEventListener("click", async () => {
        const status = document.getElementById("claim-status");
        claimBtn.disabled = true;
        claimBtn.textContent = "Claiming…";
        try {
          const r = await fetch(`/claim/${encodeURIComponent(claimBtn.dataset.fpr)}`, {
            method: "POST",
            credentials: "include",
            headers: { Accept: "application/json" },
          });
          const data = await r.json().catch(() => ({}));
          if (status) {
            status.textContent = data.message || (r.ok ? "Claim submitted." : "Claim failed.");
            status.className = r.ok ? "status-row ok" : "status-row err";
            status.classList.remove("hidden");
          }
          if (r.ok) setTimeout(() => loadKey(), 800);
        } catch (err) {
          if (status) {
            status.textContent = err.message || "Claim failed.";
            status.className = "status-row err";
            status.classList.remove("hidden");
          }
        } finally {
          claimBtn.disabled = false;
          claimBtn.textContent = "Claim key";
        }
      });
    }

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
