import { Glyph } from "basilisk-portal";

const grid = {
  display: "grid",
  gridTemplateColumns: "repeat(auto-fill, minmax(84px, 1fr))",
  gap: 10,
  maxWidth: 460,
  color: "var(--foreground)",
};

const tile = {
  display: "flex",
  flexDirection: "column" as const,
  alignItems: "center",
  gap: 4,
  padding: "8px 4px",
  border: "1px solid var(--border)",
  borderRadius: 6,
};

const tileLabel = {
  fontFamily: "var(--font-mono, ui-monospace, monospace)",
  fontSize: 10,
  color: "var(--muted-foreground)",
  textAlign: "center" as const,
};

const Tile = ({ id }: { id: string }) => (
  <div style={tile}>
    <Glyph id={id} size={22} />
    <span style={tileLabel}>{id}</span>
  </div>
);

/**
 * One op icon, at the size a chip uses it. Every glyph in the set is a
 * single 20×20 stroke path drawn in `currentColor` — they inherit the text
 * colour of whatever row they sit in rather than carrying colour of their
 * own, because colour on a chip already means "which toolbox".
 */
export const Default = () => (
  <div style={{ color: "var(--foreground)" }}>
    <Glyph id="genkey" size={22} />
  </div>
);

/**
 * The three sanctioned sizes. 16 is the chip and list scale, 18 the drawer
 * header, 22 the toolbox tile — the set is closed because a stroke width of
 * 1.6 stops reading as a deliberate weight outside that band.
 */
export const Sizes = () => (
  <div style={{ display: "flex", gap: 14, alignItems: "flex-end", color: "var(--foreground)" }}>
    {([16, 18, 22] as const).map((s) => (
      <div key={s} style={{ display: "grid", justifyItems: "center", gap: 4 }}>
        <Glyph id="gpg-sign" size={s} />
        <span style={tileLabel}>{s}px</span>
      </div>
    ))}
  </div>
);

/**
 * The toolbox glyphs — one per toolbox in `TOOLBOX_META`, and the icon a
 * chip falls back to when its op declares none of its own. These are the
 * highest-traffic twelve in the set: every drawer header and every ops
 * strip is built from them.
 */
export const Toolboxes = () => (
  <div style={grid}>
    {[
      "webcrypto",
      "encoding",
      "io",
      "flow",
      "openpgp",
      "age",
      "ssh",
      "agent",
      "hkp",
      "sss",
      "webauthn",
      "jose",
    ].map((id) => (
      <Tile key={id} id={id} />
    ))}
  </div>
);

/**
 * A spread across the op set — 99 icons in `lib/toolkit/glyphs.js`, sampled
 * here across key material, signing, encoding, secret-sharing and flow so
 * the visual family is checkable. They have to stay distinguishable at
 * 16px in a row of six, which is the real constraint on adding one.
 */
export const OpGlyphs = () => (
  <div style={grid}>
    {[
      "genkey",
      "sign",
      "digest",
      "hkdf",
      "fingerprint",
      "gpg-encrypt",
      "ssh-key",
      "sshsig-sign",
      "agent-sign",
      "agent-boundary",
      "blip39",
      "shares",
      "split",
      "recover",
      "base64",
      "pem",
      "qr",
      "random",
      "tee",
      "foreach",
    ].map((id) => (
      <Tile key={id} id={id} />
    ))}
  </div>
);

/**
 * An id with no path renders a bold `#` at the same footprint, not an empty
 * box and not a guessed icon. A missing glyph is a registry bug, and the
 * placeholder is meant to be recognisable as one on sight while still
 * keeping the row's alignment.
 */
export const UnknownId = () => (
  <div style={{ display: "flex", gap: 14, alignItems: "center", color: "var(--foreground)" }}>
    <div style={{ display: "grid", justifyItems: "center", gap: 4 }}>
      <Glyph id="genkey" size={22} />
      <span style={tileLabel}>genkey</span>
    </div>
    <div style={{ display: "grid", justifyItems: "center", gap: 4 }}>
      <Glyph id="rtc.teleport" size={22} />
      <span style={tileLabel}>rtc.teleport</span>
    </div>
    <span style={{ fontSize: 11, color: "var(--muted-foreground)" }}>
      unknown id → `#`, never a guessed icon
    </span>
  </div>
);
