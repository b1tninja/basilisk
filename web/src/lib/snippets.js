import { copyText, escapeHtml } from "./utils.js";

export function keyserverOrigin() {
  return window.location.origin.replace(/\/$/, "");
}

function snippetRow(cmd, id) {
  return `
    <div class="snippet-row">
      <pre class="snippet-code"><code>${escapeHtml(cmd)}</code></pre>
      <button type="button" class="btn btn-ghost btn-compact" data-copy="${escapeHtml(cmd)}" id="${escapeHtml(id)}">Copy</button>
    </div>`;
}

/**
 * @param {{ title: string, hint?: string, items: Array<{ id: string, cmd: string, note?: string }> }} opts
 */
export function renderSnippetCard(opts) {
  const rows = opts.items
    .map((item) => {
      const note = item.note
        ? `<p class="snippet-note muted">${escapeHtml(item.note)}</p>`
        : "";
      return `${note}${snippetRow(item.cmd, item.id)}`;
    })
    .join("");
  const hint = opts.hint
    ? `<p class="muted" style="margin:-0.35rem 0 0.85rem">${escapeHtml(opts.hint)}</p>`
    : "";
  return `
    <div class="card snippet-card">
      <p class="card-title">${escapeHtml(opts.title)}</p>
      ${hint}
      ${rows}
    </div>`;
}

/** Fetch/install snippets for a specific key. */
export function renderKeyClientSnippets({ fingerprint, keyId, approved }) {
  const origin = keyserverOrigin();
  const fpr = String(fingerprint || "").toUpperCase().replace(/[^0-9A-F]/g, "");
  const kid = String(keyId || "").replace(/^0x/i, "");
  const items = [
    {
      id: "snip-recv-fpr",
      cmd: `gpg --keyserver ${origin} --recv-keys ${fpr}`,
      note: "Fetch with GnuPG (fingerprint)",
    },
    {
      id: "snip-recv-kid",
      cmd: `gpg --keyserver ${origin} --recv-keys 0x${kid}`,
      note: "Or by 16-character key ID",
    },
    {
      id: "snip-curl-get",
      cmd: `curl -fsSL "${origin}/pks/lookup?op=get&options=mr&search=0x${fpr}"`,
      note: "Raw HKP GET (machine-readable)",
    },
  ];
  const hint = approved
    ? "Use these after the key is approved. Email search only returns approved keys."
    : "Fingerprint lookup works while pending (UIDs stripped until claimed). Email index requires approval.";
  return renderSnippetCard({
    title: "Install with GnuPG / HKP",
    hint,
    items,
  });
}

/** Submit snippets for My Keys / search help. */
export function renderSubmitSnippets() {
  const origin = keyserverOrigin();
  return renderSnippetCard({
    title: "Submit with GnuPG",
    hint: "gpg --send-keys uploads via HKP (/pks/add). Claim the key afterward if a UID matches your email.",
    items: [
      {
        id: "snip-send-keys",
        cmd: `gpg --keyserver ${origin} --send-keys YOURKEYID`,
        note: "Replace YOURKEYID with your 16-character key ID (or full fingerprint)",
      },
      {
        id: "snip-send-export",
        cmd: `gpg --armor --export YOURKEYID | curl -fsS --data-urlencode keytext@- ${origin}/pks/add`,
        note: "Or export and POST armored text",
      },
    ],
  });
}

/** General CLI help for the search landing page. */
export function renderSearchHelpSnippets() {
  const origin = keyserverOrigin();
  return renderSnippetCard({
    title: "Command-line usage",
    hint: "Basilisk speaks classic HKP. Point GnuPG at this host — no WKD endpoint yet.",
    items: [
      {
        id: "snip-help-recv",
        cmd: `gpg --keyserver ${origin} --recv-keys FINGERPRINT_OR_KEYID`,
        note: "Download an approved key",
      },
      {
        id: "snip-help-send",
        cmd: `gpg --keyserver ${origin} --send-keys YOURKEYID`,
        note: "Upload a public key (then claim on the site)",
      },
      {
        id: "snip-help-search",
        cmd: `gpg --keyserver ${origin} --search-keys user@example.com`,
        note: "Search by email (approved keys only)",
      },
    ],
  });
}

export function wireSnippetCopy(_root) {
  if (wireSnippetCopy._bound) return;
  wireSnippetCopy._bound = true;
  document.addEventListener("click", async (e) => {
    const btn = e.target.closest("[data-copy]");
    if (!btn) return;
    e.preventDefault();
    const value = btn.getAttribute("data-copy") || "";
    const original = btn.textContent;
    try {
      await copyText(value);
      btn.textContent = "Copied";
      setTimeout(() => {
        btn.textContent = original;
      }, 1500);
    } catch (_) {
      btn.textContent = "Failed";
      setTimeout(() => {
        btn.textContent = original;
      }, 1500);
    }
  });
}
