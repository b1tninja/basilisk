/**
 * Colorized OpenPGP packet-map hex view (SEIPD-aware).
 * Shared by Decrypt expert mode and Toolkit output format switching.
 * @module lib/packet-hex-view
 */

import {
  dearmorToBytes,
  enrichSpansWithPackets,
  mapPacketSpans,
  tagColorClass,
} from "./packet-map.js";
import { analyzeArmored } from "./pgp/inspect.js";
import { escapeHtml } from "./utils.js";

/** Bytes shown before “Show full”. */
export const PACKET_HEX_INITIAL = 4096;

/**
 * @param {Uint8Array} binary
 * @param {{ headerStart: number, bodyStart: number, end: number, name: string, colorIndex: number }[]} spans
 * @param {number} limit
 * @returns {string}
 */
export function renderHexGridHtml(binary, spans, limit) {
  const rows = [];
  for (let off = 0; off < limit; off += 16) {
    const slice = binary.subarray(off, Math.min(off + 16, limit));
    const hexParts = [];
    const asciiParts = [];
    for (let i = 0; i < slice.length; i++) {
      const abs = off + i;
      const span = spans.find((s) => abs >= s.headerStart && abs < s.end);
      const isHdr = span && abs < span.bodyStart;
      const cls = span
        ? `${tagColorClass(span.colorIndex)}${isHdr ? " pkt-hdr" : ""}`
        : "";
      const b = slice[i];
      hexParts.push(
        `<span class="hex-byte ${cls}" data-off="${abs}" title="${
          span ? escapeHtml(span.name) : ""
        }">${b.toString(16).padStart(2, "0")}</span>`
      );
      const ch = b >= 32 && b < 127 ? String.fromCharCode(b) : ".";
      asciiParts.push(
        `<span class="hex-ascii ${cls}" data-off="${abs}">${escapeHtml(ch)}</span>`
      );
    }
    rows.push(
      `<div class="hex-row"><span class="hex-off">${off
        .toString(16)
        .padStart(4, "0")}</span><span class="hex-bytes">${hexParts.join(
        " "
      )}</span><span class="hex-gutter">${asciiParts.join("")}</span></div>`
    );
  }
  return rows.join("");
}

/**
 * @param {{
 *   binary: Uint8Array,
 *   spans: ReturnType<typeof enrichSpansWithPackets>,
 *   expanded?: boolean,
 *   title?: string,
 *   expandBtnId?: string,
 * }} opts
 * @returns {string}
 */
export function packetMapViewHtml(opts) {
  const {
    binary,
    spans,
    expanded = false,
    title = "Packet map",
    expandBtnId = "hex-expand-btn",
  } = opts;
  const legend = [...new Set(spans.map((s) => s.name))]
    .map((name, i) => {
      const span = spans.find((s) => s.name === name);
      return `<span class="pkt-legend-chip ${tagColorClass(span?.colorIndex ?? i)}">${escapeHtml(name)}</span>`;
    })
    .join("");

  const detailRows = spans
    .map((s, i) => {
      const lines = (s.detail?.lines || [])
        .map((l) => `<div>${escapeHtml(l)}</div>`)
        .join("");
      const warns = (s.detail?.warnings || [])
        .map((w) => `<div class="text-error">${escapeHtml(w)}</div>`)
        .join("");
      return `<div class="pkt-detail-row ${tagColorClass(s.colorIndex)}" data-pkt-idx="${i}" tabindex="0">
        <div class="pkt-detail-title">${escapeHtml(s.name)} <span class="muted">@ ${s.headerStart}–${s.end}</span></div>
        <div class="pkt-detail-body">${lines}${warns}</div>
      </div>`;
    })
    .join("");

  const limit = expanded
    ? binary.length
    : Math.min(binary.length, PACKET_HEX_INITIAL);

  return `
    <div class="packet-map-view">
      <p class="card-title">${escapeHtml(title)}</p>
      <div class="pkt-legend">${legend}</div>
      <div class="hex-view" aria-label="Colorized packet bytes">${renderHexGridHtml(
        binary,
        spans,
        limit
      )}</div>
      ${
        binary.length > PACKET_HEX_INITIAL
          ? `<button type="button" class="text-link" data-hex-expand="${escapeHtml(
              expandBtnId
            )}">${
              expanded ? "Show less" : `Show full (${binary.length} bytes)`
            }</button>`
          : ""
      }
      <p class="card-title mt-lg">Packet details</p>
      <div class="pkt-detail-list">${detailRows}</div>
    </div>`;
}

/**
 * Plain-text packet listing (copy/download friendly).
 * @param {ReturnType<typeof enrichSpansWithPackets>} spans
 * @returns {string}
 */
export function packetMapTextSummary(spans) {
  const lines = ["packets:"];
  for (const s of spans) {
    lines.push(`- ${s.name} @ ${s.headerStart}–${s.end}`);
    for (const line of s.detail?.lines || []) lines.push(`    ${line}`);
    for (const w of s.detail?.warnings || []) lines.push(`    ! ${w}`);
  }
  return `${lines.join("\n")}\n`;
}

/**
 * Build enriched spans + binary from armored OpenPGP (async for OpenPGP.js details).
 * @param {string} armored
 * @returns {Promise<{ binary: Uint8Array, spans: ReturnType<typeof enrichSpansWithPackets>, summary: string }>}
 */
export async function buildPacketMapFromArmored(armored) {
  const analysis = await analyzeArmored(armored);
  const src = analysis.armored || armored;
  const binary = dearmorToBytes(src);
  const spans = mapPacketSpans(binary);
  const packets =
    analysis.message &&
    analysis.type !== "cleartext" &&
    analysis.type !== "detached"
      ? analysis.message.packets
      : analysis.message?.packets ||
        analysis.message?.signature?.packets ||
        null;
  const enriched = enrichSpansWithPackets(spans, packets);
  return {
    binary,
    spans: enriched,
    summary: packetMapTextSummary(enriched),
  };
}

/**
 * Sync build (tag colors only — no OpenPGP.js packet enrichment).
 * @param {string} armored
 */
export function buildPacketMapFromArmoredSync(armored) {
  const binary = dearmorToBytes(armored);
  const spans = enrichSpansWithPackets(mapPacketSpans(binary), null);
  return {
    binary,
    spans,
    summary: packetMapTextSummary(spans),
  };
}

/**
 * Highlight a packet in a rooted packet-map view.
 * @param {ParentNode} root
 * @param {ReturnType<typeof enrichSpansWithPackets>|null|undefined} spans
 * @param {number} idx
 */
export function highlightPacketIn(root, spans, idx) {
  root.querySelectorAll(".pkt-detail-row").forEach((el) => {
    el.classList.toggle(
      "pkt-active",
      Number(el.getAttribute("data-pkt-idx")) === idx
    );
  });
  const span = spans?.[idx];
  root.querySelectorAll(".hex-byte, .hex-ascii").forEach((el) => {
    const off = Number(el.getAttribute("data-off"));
    const on = !!(span && off >= span.headerStart && off < span.end);
    el.classList.toggle("hex-hl", on);
  });
}

/**
 * Wire click / keyboard highlight inside a packet-map root.
 * @param {ParentNode} root
 * @param {ReturnType<typeof enrichSpansWithPackets>} spans
 * @param {{ onExpand?: () => void }} [opts]
 */
export function wirePacketMapView(root, spans, opts = {}) {
  root.querySelectorAll("[data-hex-expand]").forEach((btn) => {
    btn.addEventListener("click", () => opts.onExpand?.());
  });
  root.querySelectorAll("[data-pkt-idx]").forEach((row) => {
    const activate = () =>
      highlightPacketIn(root, spans, Number(row.getAttribute("data-pkt-idx")));
    row.addEventListener("click", activate);
    row.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        activate();
      }
    });
  });
  root.querySelectorAll("[data-off]").forEach((el) => {
    el.addEventListener("click", () => {
      const off = Number(el.getAttribute("data-off"));
      const idx = spans.findIndex((s) => off >= s.headerStart && off < s.end);
      if (idx >= 0) highlightPacketIn(root, spans, idx);
    });
  });
}
