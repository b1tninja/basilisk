/**
 * Local visual fixture for ops icon tiles + standard tool cards.
 * Served at /tool-card-preview.html during vite dev/preview.
 */
import { glyphHtml } from "../../lib/toolkit/glyphs.js";
import {
  getShelfMeta,
  getStep,
  TOOLBOX_META,
} from "../../lib/toolkit/registry.js";

const SAMPLE = ["sss.split", "genkey", "gpg.encrypt", "base64", "recover"];

const KIND_META = {
  source: { label: "Sources" },
  transform: { label: "Transforms" },
  sink: { label: "Outputs" },
  flow: { label: "Flow control" },
};

function escapeHtml(s) {
  return String(s ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function toolboxBadgeHtml(toolbox) {
  const tb = toolbox || "io";
  const meta = TOOLBOX_META[tb] || { badge: tb, label: tb };
  return `<span class="toolbox-badge toolbox-${escapeHtml(tb)}" title="${escapeHtml(meta.label)}">${escapeHtml(meta.badge)}</span>`;
}

function opsGlyphForStep(s) {
  if (s.shelf) {
    const g = getShelfMeta(s.shelf)?.glyph;
    if (g) return g;
  }
  return TOOLBOX_META[s.toolbox]?.glyph || "gear";
}

function toolCardHtml(s, opts = {}) {
  const decode = !!opts.decode;
  const io = s.effectiveIo
    ? s.effectiveIo(decode ? { decode: true } : {})
    : { input: s.input, output: s.output };
  const display = s.label || s.name;
  const nameLabel = decode ? `${display} -d` : display;
  const glyph = opsGlyphForStep(s);
  const kindLabel = KIND_META[s.kind]?.label || s.kind;
  const shelf = s.shelf ? getShelfMeta(s.shelf).label : "";
  const recipeTok = `${s.name}${decode ? " -d" : ""}`;
  const aliases = (s.aliases || []).length
    ? `<p class="tool-card-aliases muted fs-xs">Aliases: ${(s.aliases || [])
        .map((a) => `<code>${escapeHtml(a)}</code>`)
        .join(", ")}</p>`
    : "";
  const paramList = s.params || [];
  const shown = paramList.slice(0, 8);
  const paramsHtml = shown.length
    ? `<div class="tool-card-params">
        <p class="tool-card-section">Parameters</p>
        <ul class="tool-card-param-list">
          ${shown
            .map((p) => {
              const typeBits = [p.type];
              if (p.enum?.length) typeBits.push(p.enum.join("|"));
              else if (p.default !== undefined && p.default !== null)
                typeBits.push(`default ${String(p.default)}`);
              return `<li>
                <code>${escapeHtml(p.name)}</code>
                <span class="tool-card-param-type muted">${escapeHtml(typeBits.join(" · "))}</span>
                ${p.doc ? `<span class="tool-card-param-doc">${escapeHtml(p.doc)}</span>` : ""}
              </li>`;
            })
            .join("")}
        </ul>
      </div>`
    : `<p class="tool-card-noparams muted fs-xs">No parameters.</p>`;
  const flags = [];
  if (opts.fit) flags.push(`<span class="tool-card-flag tool-card-flag-fit">Fits tip</span>`);

  return `
    <div class="tool-card">
      <header class="tool-card-head">
        ${glyphHtml(glyph, "ops-glyph ops-glyph-tile tool-card-glyph")}
        <div class="tool-card-titles">
          <p class="tool-card-name">${escapeHtml(nameLabel)}</p>
          <p class="tool-card-recipe muted fs-xs">Recipe <code>${escapeHtml(recipeTok)}</code></p>
        </div>
      </header>
      <div class="tool-card-meta">
        ${toolboxBadgeHtml(s.toolbox)}
        ${shelf ? `<span class="tool-card-chip">${escapeHtml(shelf)}</span>` : ""}
        <span class="tool-card-chip">${escapeHtml(kindLabel)}</span>
        ${flags.join("")}
      </div>
      <div class="tool-card-io" aria-label="Input and output types">
        <div class="tool-card-io-side">
          <span class="tool-card-io-label muted">In</span>
          <span class="tool-card-type" data-io="in">${escapeHtml(io.input)}</span>
        </div>
        <span class="tool-card-io-arrow" aria-hidden="true">→</span>
        <div class="tool-card-io-side">
          <span class="tool-card-io-label muted">Out</span>
          <span class="tool-card-type" data-io="out">${escapeHtml(io.output)}</span>
        </div>
      </div>
      <p class="tool-card-doc">${escapeHtml(s.doc)}</p>
      ${aliases}
      ${paramsHtml}
      ${
        opts.hideHint
          ? ""
          : `<p class="tool-card-hint muted fs-xs">Drag onto a cell, or click to append.</p>`
      }
    </div>`;
}

function tileHtml(s) {
  const short = s.name.length > 10 ? `${s.name.slice(0, 9)}…` : s.name;
  return `
    <button type="button" class="ops-item ops-item-icon ops-item-fit"
      data-op="${escapeHtml(s.name)}" aria-label="${escapeHtml(s.name)}">
      ${glyphHtml(opsGlyphForStep(s), "ops-glyph ops-glyph-tile")}
      <span class="ops-item-name">${escapeHtml(short)}</span>
    </button>`;
}

const steps = SAMPLE.map((n) => getStep(n)).filter(Boolean);

const opsMock = document.getElementById("ops-mock");
if (opsMock) {
  opsMock.innerHTML = `<h2>Toolkit</h2><div class="ops-icon-grid">${steps
    .map(tileHtml)
    .join("")}</div>`;
}

const cards = document.getElementById("cards");
if (cards) {
  cards.innerHTML = steps
    .slice(0, 3)
    .map((s, i) => toolCardHtml(s, { fit: i === 0, hideHint: false }))
    .join("");
}

const live = document.getElementById("ops-live");
const cardHost = document.getElementById("ops-tool-card");
if (live && cardHost) {
  live.innerHTML = steps.map(tileHtml).join("");
  let hideTimer = null;

  function hide() {
    cardHost.classList.add("hidden");
    cardHost.hidden = true;
    cardHost.innerHTML = "";
  }

  function show(anchor, name) {
    const s = getStep(name);
    if (!s) return;
    if (hideTimer) clearTimeout(hideTimer);
    cardHost.innerHTML = toolCardHtml(s, { fit: true });
    const r = anchor.getBoundingClientRect();
    const cardW = 300;
    cardHost.style.width = `${cardW}px`;
    let left = r.right + 12;
    if (left + cardW > window.innerWidth - 12) left = Math.max(12, r.left - cardW - 12);
    cardHost.classList.remove("hidden");
    cardHost.hidden = false;
    const h = cardHost.offsetHeight || 240;
    let top = r.top + r.height / 2 - h / 2;
    top = Math.max(12, Math.min(top, window.innerHeight - h - 12));
    cardHost.style.left = `${left}px`;
    cardHost.style.top = `${top}px`;
  }

  live.querySelectorAll("[data-op]").forEach((el) => {
    const name = el.getAttribute("data-op") || "";
    el.addEventListener("pointerenter", () => show(el, name));
    el.addEventListener("pointerleave", () => {
      hideTimer = setTimeout(hide, 160);
    });
  });
  cardHost.addEventListener("pointerenter", () => {
    if (hideTimer) clearTimeout(hideTimer);
  });
  cardHost.addEventListener("pointerleave", () => {
    hideTimer = setTimeout(hide, 160);
  });

  // Auto-open first tile for screenshot harness
  const first = live.querySelector("[data-op]");
  if (first) show(first, first.getAttribute("data-op") || "");
}
