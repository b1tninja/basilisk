import { KindGlyph } from "basilisk-portal";

const chip = {
  display: "inline-flex",
  alignItems: "center",
  gap: 5,
  padding: "3px 8px",
  border: "1px solid var(--border)",
  borderRadius: 999,
  fontSize: 11,
  color: "var(--foreground)",
  fontFamily: "var(--font-mono, ui-monospace, monospace)",
};

const wrap = {
  display: "flex",
  flexWrap: "wrap" as const,
  gap: 6,
  maxWidth: 440,
};

const groupTitle = {
  fontSize: 10.5,
  fontWeight: 700,
  textTransform: "uppercase" as const,
  letterSpacing: "0.06em",
  color: "var(--muted-foreground)",
  margin: "0 0 6px",
};

const Kind = ({ kind }: { kind: string }) => (
  <span style={chip}>
    <KindGlyph kind={kind} />
    {kind}
  </span>
);

/**
 * The canonical use: a kind badge on an output row. The glyph goes before
 * the word, never instead of it — this is chrome labelling a surface, so it
 * is allowed to be a lucide pictogram, but a pictogram alone would be
 * asserting a reading the word states exactly.
 */
export const Default = () => <Kind kind="keypair" />;

/**
 * The closed map, in full. It is shared precisely so a kind can never show
 * one pictogram in an output row and a different one on a type card — and
 * the collisions are deliberate: `key` and `keypair` take the same key glyph
 * because at badge size they are the same claim, and `share`/`shares`/
 * `recipients` all take the people glyph.
 *
 * `openpgp-key` is **not** here, though this list once claimed it "takes the
 * key glyph". It resolves through neither `KIND_GLYPHS` nor `GLYPH_PATHS`, so
 * it renders nothing — and in this cell there is no dashed slot to say so, so
 * it drew as a bare chip between two mapped neighbours and read as breakage.
 * It belongs in `UnmappedRendersNothing`, where absence is captioned as
 * intent, and that is where it now is.
 */
export const AllKinds = () => (
  <div style={{ display: "grid", gap: 12 }}>
    <div>
      <p style={groupTitle}>Data</p>
      <div style={wrap}>
        {["text", "bytes", "inspect", "artifact", "bundle"].map((k) => (
          <Kind key={k} kind={k} />
        ))}
      </div>
    </div>
    <div>
      <p style={groupTitle}>Key material</p>
      <div style={wrap}>
        {["key", "keypair", "secret", "signature"].map((k) => (
          <Kind key={k} kind={k} />
        ))}
      </div>
    </div>
    <div>
      <p style={groupTitle}>People &amp; shares</p>
      <div style={wrap}>
        {["share", "shares", "recipients"].map((k) => (
          <Kind key={k} kind={k} />
        ))}
      </div>
    </div>
    <div>
      <p style={groupTitle}>Network &amp; telemetry</p>
      <div style={wrap}>
        {["endpoint", "candidate", "session", "channel", "connstate", "stats", "diag"].map((k) => (
          <Kind key={k} kind={k} />
        ))}
      </div>
    </div>
  </div>
);

/**
 * On the output rows it was drawn for. The glyph is the fastest read in the
 * row — before the label, before the size — which is why an unmapped kind
 * must render nothing rather than a near-miss: a wrong icon here reads as a
 * wrong claim about what the artifact is.
 */
export const InAnOutputRow = () => (
  <div style={{ display: "grid", gap: 8, maxWidth: 400 }}>
    {[
      ["keypair", "ed25519-2026-07.key"],
      ["text", "ed25519-2026-07.pub"],
      ["signature", "release-notes.md.sig"],
      ["shares", "board-root · 3 of 5"],
    ].map(([kind, label]) => (
      <div
        style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 12 }}
        key={String(label)}
      >
        <span
          style={{
            display: "inline-flex",
            alignItems: "center",
            gap: 4,
            minWidth: 92,
            fontSize: 11,
            color: "var(--muted-foreground)",
          }}
        >
          <KindGlyph kind={kind} />
          {kind}
        </span>
        <code
          style={{
            fontFamily: "var(--font-mono, ui-monospace, monospace)",
            color: "var(--foreground)",
          }}
        >
          {label}
        </code>
      </div>
    ))}
  </div>
);

/**
 * Sizing. `size` is a **closed set** — `GlyphSize` is `12 | 14 | 16 | 18 | 22`
 * and nothing between them exists, because the glyph family is drawn on a grid
 * and an off-ladder box lands the strokes off-pixel. Asking for 20 is a type
 * error, not a rounding.
 *
 * The product asks for two of the five: 12px is the badge default and pairs
 * with 11px type, 14px is the output row. The rest of the ladder is here so the
 * family can be seen holding together — `strokeWidth` is fixed at 2 as the box
 * grows, which is what keeps 22 from reading as a different set of icons.
 */
export const Sizes = () => (
  <div style={{ display: "flex", gap: 16, alignItems: "flex-end", color: "var(--foreground)" }}>
    {([12, 14, 16, 18, 22] as const).map((size) => (
      <div key={size} style={{ display: "grid", justifyItems: "center", gap: 4 }}>
        <KindGlyph kind="signature" size={size} />
        <span style={{ fontSize: 10, color: "var(--muted-foreground)" }}>{size}px</span>
      </div>
    ))}
  </div>
);

/**
 * Unmapped kinds render nothing at all. The §25a value shapes
 * (candidate/session/channel/connstate dots) stay abstract for the same
 * reason a wrong icon is refused here — a plug for "session" implies
 * *connected* even mid-negotiation. The dashed boxes are this preview's
 * scaffolding; the component emits nothing inside them.
 */
export const UnmappedRendersNothing = () => (
  <div style={{ display: "grid", gap: 8, maxWidth: 400 }}>
    {/* These four are checked against the maps, not assumed. `kindGlyph` is
     * `KIND_GLYPHS[k] || (GLYPH_PATHS[k] ? k : null)` — it resolves through
     * *either* namespace, which is the trap `glyphExists`'s own comment warns
     * about. This cell previously used `peer` and `quorum` as its unmapped
     * examples; both are in `GLYPH_PATHS`, so both drew a glyph directly
     * beneath a caption reading "unmapped — no glyph, never a guess". Three of
     * the four rows stated the opposite of what they showed.
     *
     * `sdp`, `openpgp-key` and `certificate` are in neither map. */}
    {["keypair", "sdp", "openpgp-key", "certificate"].map((k) => (
      <div key={k} style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 12 }}>
        <span
          style={{
            display: "inline-flex",
            alignItems: "center",
            justifyContent: "center",
            width: 16,
            height: 16,
            border: "1px dashed color-mix(in srgb, var(--border) 90%, transparent)",
            borderRadius: 3,
            color: "var(--foreground)",
          }}
        >
          <KindGlyph kind={k} />
        </span>
        <code
          style={{
            fontFamily: "var(--font-mono, ui-monospace, monospace)",
            minWidth: 80,
            color: "var(--foreground)",
          }}
        >
          {k}
        </code>
        <span style={{ fontSize: 11, color: "var(--muted-foreground)" }}>
          {k === "keypair" ? "mapped" : "unmapped — no glyph, never a guess"}
        </span>
      </div>
    ))}
  </div>
);
