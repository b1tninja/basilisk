/**
 * Inline stroke SVG fragments for toolkit toolbox / shelf glyphs.
 * viewBox 0 0 20 20 — matches landing-page feature-icon language.
 */

/** @type {Record<string, string>} */
export const GLYPH_PATHS = {
  // Toolboxes
  webcrypto:
    '<circle cx="10" cy="10" r="3"/><path d="M12.1 8.9l3.2-3.2M14.5 4.3l1.2 1.2-1.8 1.8"/>',
  openpgp:
    '<rect x="3" y="8" width="14" height="10" rx="1.5"/><path d="M3 9.5l7 4.5 7-4.5"/><path d="M7 8V6.5a3 3 0 016 0V8"/>',
  sss: '<path d="M10 2l8 4.5v7L10 18l-8-4.5v-7L10 2z"/><path d="M10 2v16M2.5 6.5L17.5 14.5M17.5 6.5L2.5 14.5"/>',
  webauthn:
    '<path d="M10 2a4 4 0 014 4c0 3-4 6-4 6s-4-3-4-6a4 4 0 014-4z"/><circle cx="10" cy="6" r="1.2"/><path d="M7 17c1.5-2 4.5-2 6 0"/>',
  // Agent = vault key + TTL arc (distinct from bare Keys)
  agent:
    '<path d="M7.5 10.5a2.5 2.5 0 112.7-2.4L14 12v1.5h-1.5V15H11v-1.5H9.8z"/><circle cx="7.2" cy="8" r="0.9"/><path d="M14.5 4.5a5.5 5.5 0 11-9 0"/><path d="M14.5 4.5V7H12"/>',
  hkp: '<circle cx="10" cy="10" r="3"/><path d="M10 3v2M10 15v2M3 10h2M15 10h2M5.2 5.2l1.4 1.4M13.4 13.4l1.4 1.4M5.2 14.8l1.4-1.4M13.4 6.6l1.4-1.4"/>',
  encoding: '<path d="M4 7h5l2 2h5M4 13h5l2-2h5"/><path d="M14 5l3 3-3 3M6 15l-3-3 3-3"/>',
  io: '<rect x="3" y="4" width="14" height="12" rx="1.5"/><path d="M3 8h14M7 12h6"/>',
  flow: '<path d="M4 4v5h5"/><path d="M4 9l5-5"/><path d="M11 11v5h5"/><path d="M11 16l5-5"/>',
  // Recipients list (HKP directory / merge)
  recipients:
    '<circle cx="7" cy="7" r="2.2"/><circle cx="13.5" cy="7.5" r="1.8"/><path d="M3.5 15c.6-2.4 2.2-3.5 3.5-3.5s2.9 1.1 3.5 3.5"/><path d="M11.2 14.5c.4-1.6 1.5-2.4 2.3-2.4s1.9.8 2.3 2.4"/>',
  // Kernel @slots
  variables:
    '<rect x="3.5" y="4" width="5" height="5" rx="1"/><rect x="11.5" y="4" width="5" height="5" rx="1"/><rect x="3.5" y="11" width="5" height="5" rx="1"/><path d="M12.5 13.5h4M14.5 11.5v4"/>',
  gear: '<circle cx="10" cy="10" r="2.2"/><path d="M10 3.2v1.8M10 15v1.8M3.2 10h1.8M15 10h1.8M5.1 5.1l1.3 1.3M13.6 13.6l1.3 1.3M5.1 14.9l1.3-1.3M13.6 6.4l1.3-1.3"/>',
  more: '<circle cx="5" cy="10" r="1.3"/><circle cx="10" cy="10" r="1.3"/><circle cx="15" cy="10" r="1.3"/>',
  shortcuts:
    '<rect x="3" y="5" width="14" height="11" rx="1.5"/><path d="M6 9h2M9.5 9h2M13 9h1M6 12h8"/>',

  // Shelves
  keys: '<path d="M8 11a3 3 0 113.2-2.8L16 13v2h-2v2h-2v-2h-1.5z"/><circle cx="7.5" cy="8" r="1"/>',
  directory: '<circle cx="7" cy="7" r="2.2"/><circle cx="13.5" cy="7.5" r="1.8"/><path d="M3.5 15c.6-2.4 2.2-3.5 3.5-3.5s2.9 1.1 3.5 3.5"/><path d="M11.2 14.5c.4-1.6 1.5-2.4 2.3-2.4s1.9.8 2.3 2.4"/>',
  digest: '<path d="M4 5h12M4 10h8M4 15h10"/><path d="M14 8v8"/>',
  sign: '<path d="M4 16c2-4 5-7 8-8l3-3 2 2-3 3c-1 3-4 6-8 8z"/>',
  aead: '<path d="M10 3l7 3v5c0 4-3 6.5-7 8-4-1.5-7-4-7-8V6l7-3z"/>',
  cipher: '<path d="M3 10c2-4 5-6 7-6s5 2 7 6c-2 4-5 6-7 6s-5-2-7-6z"/><circle cx="10" cy="10" r="2"/>',
  rsa: '<rect x="4" y="3" width="12" height="14" rx="1"/><path d="M7 7h6M7 10h6M7 13h4"/>',
  kdf: '<path d="M4 4h5v5H4zM11 11h5v5h-5z"/><path d="M9 6.5h2.5V9M10.5 11V9"/>',
  agreement: '<path d="M5 14l5-9 5 9"/><path d="M7 11h6"/>',
  wrap: '<path d="M3 8l7-4 7 4v8l-7 4-7-4V8z"/><path d="M3 8l7 4 7-4M10 12v8"/>',
  pubkey: '<path d="M3 9.5l7 4.5 7-4.5"/><rect x="3" y="8" width="14" height="9" rx="1"/><circle cx="10" cy="5" r="2"/>',
  password: '<circle cx="7" cy="10" r="2.5"/><path d="M9.2 10H17v2.5h-2V15h-2v-2.5H11"/>',
  split: '<path d="M8 4l-4 6h4l-3 6M12 4l4 6h-4l3 6"/>',
  recover: '<path d="M4 10h5l2-3 2 6 2-3h5"/><path d="M16 6v4h4"/>',
  binary: '<path d="M5 5h3v3H5zM12 5h3v3h-3zM5 12h3v3H5zM12 12h3v3h-3z"/>',
  text: '<path d="M5 5h10M7 5v10M5 15h4M11 9h4M11 12h3"/>',
  ports: '<path d="M4 7h5v6H4zM11 7h5v6h-5z"/><path d="M9 10h2"/>',
  control: '<circle cx="5" cy="5" r="2"/><circle cx="15" cy="5" r="2"/><circle cx="10" cy="15" r="2"/><path d="M5 7v3c0 2 2 3 5 3s5-1 5-3V7"/>',
  essentials: '<path d="M10 2l2 6h6l-5 3.5 2 6L10 14l-5 3.5 2-6L2 8h6z"/>',
  attestation: '<path d="M10 2l7 3v5c0 3.5-2.5 6-7 7.5C5.5 16 3 13.5 3 10V5l7-3z"/><path d="M7.5 10l2 2 3.5-4"/>',
};

/**
 * @param {string|undefined|null} id
 * @param {string} [className]
 * @returns {string}
 */
export function glyphHtml(id, className = "ops-glyph") {
  const key = String(id || "");
  const inner = GLYPH_PATHS[key];
  if (!inner) return "";
  return `<svg class="${className}" width="16" height="16" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">${inner}</svg>`;
}
