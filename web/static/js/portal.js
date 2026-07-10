function escapeHtml(text) {
  const div = document.createElement("div");
  div.textContent = text;
  return div.innerHTML;
}

function renderKeysTable(items, options = {}) {
  if (!items.length) {
    return "<p class='muted'>No keys found.</p>";
  }
  const rows = items.map((item) => {
    const uids = (item.pending_uids || item.approved_uids || item.uids || []).join(", ") || "—";
    let actions = `<a href="/key?fpr=${encodeURIComponent(item.fingerprint)}">View</a>`;
    if (options.showClaim && item.can_claim && item.claim_url) {
      actions += ` · <a href="${escapeHtml(item.claim_url)}">Claim</a>`;
    }
    return (
      `<tr><td><code>${escapeHtml(item.fingerprint)}</code></td>` +
      `<td><span class="badge">${escapeHtml(item.approval_state)}</span></td>` +
      `<td>${escapeHtml(uids)}</td><td>${actions}</td></tr>`
    );
  });
  return (
    "<table><thead><tr><th>Fingerprint</th><th>Status</th><th>UIDs</th><th></th></tr></thead>" +
    `<tbody>${rows.join("")}</tbody></table>`
  );
}

async function fetchJson(url) {
  const response = await fetch(url, { credentials: "include" });
  if (!response.ok) {
    const text = await response.text();
    throw new Error(text || `Request failed (${response.status})`);
  }
  return response.json();
}

async function fetchText(url) {
  const response = await fetch(url, { credentials: "include" });
  if (!response.ok) {
    throw new Error(`Request failed (${response.status})`);
  }
  return response.text();
}

function queryParam(name) {
  return new URLSearchParams(window.location.search).get(name) || "";
}

function showError(el, message) {
  el.textContent = message;
  el.classList.remove("hidden");
}
