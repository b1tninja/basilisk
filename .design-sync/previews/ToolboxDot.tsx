import { ToolboxDot } from "basilisk-portal";

const rowStyle = {
  display: "flex",
  alignItems: "center",
  gap: 8,
  fontSize: 12,
  color: "var(--foreground)",
};

const slot = {
  display: "inline-flex",
  alignItems: "center",
  justifyContent: "center",
  width: 10,
  height: 10,
  flexShrink: 0,
};

const opName = {
  fontFamily: "var(--font-mono, ui-monospace, monospace)",
  fontSize: 11.5,
  minWidth: 92,
};

const meaning = {
  fontSize: 11,
  color: "var(--muted-foreground)",
};

/**
 * The shape axis (design v2 §25a). Shape is derived from the op's declared
 * `output` type, never from a parallel presentational field, so it cannot
 * drift from what the type system enforces. Addressing values are diamonds,
 * session and identity values are squares, a live channel is a triangle,
 * and observe-only values are hollow — "display me, don't consume me".
 */
export const Shapes = () => (
  <div style={{ display: "grid", gap: 9 }}>
    <div style={rowStyle}>
      <span style={slot}>
        <ToolboxDot op={{ toolbox: "webrtc", output: "candidate" }} />
      </span>
      <span style={opName}>candidate</span>
      <span style={meaning}>diamond — an address</span>
    </div>
    <div style={rowStyle}>
      <span style={slot}>
        <ToolboxDot op={{ toolbox: "webrtc", output: "sdp" }} />
      </span>
      <span style={opName}>sdp</span>
      <span style={meaning}>square — a session or identity</span>
    </div>
    <div style={rowStyle}>
      <span style={slot}>
        <ToolboxDot op={{ toolbox: "webrtc", output: "channel" }} />
      </span>
      <span style={opName}>channel</span>
      <span style={meaning}>triangle — live, valid only inside this run</span>
    </div>
    <div style={rowStyle}>
      <span style={slot}>
        <ToolboxDot op={{ toolbox: "webrtc", output: "connstate" }} />
      </span>
      <span style={opName}>connstate</span>
      <span style={meaning}>hollow — observe-only, cannot be consumed</span>
    </div>
  </div>
);

/**
 * A real WebRTC pipeline, which is where the shapes earn their keep: four
 * consecutive steps whose outputs are all "some network thing", and only
 * the shape says which of them can be piped onward. `rtc.stats` and
 * `rtc.state` read hollow at a glance, so nobody wires them into a step
 * that expects a value.
 */
export const InAPipeline = () => (
  <div style={{ display: "grid", gap: 9 }}>
    {[
      ["rtc.gather", "candidate", "→ candidate"],
      ["rtc.certificate", "certificate", "→ certificate"],
      ["rtc.offer", "sdp", "→ sdp"],
      ["rtc.state", "connstate", "→ connstate"],
      ["rtc.stats", "stats", "→ stats"],
    ].map(([name, output, note]) => (
      <div key={name} style={rowStyle}>
        <span style={slot}>
          <ToolboxDot op={{ toolbox: "webrtc", output }} />
        </span>
        <span style={opName}>{name}</span>
        <span style={meaning}>{note}</span>
      </div>
    ))}
  </div>
);

/**
 * The colour axis: origin toolbox, from a closed palette a stylesheet can
 * enumerate. Colour lives entirely in CSS (`.toolbox-shape[data-toolbox]`
 * sets `color`, the shape paints with `currentColor`) because this one
 * component renders once per op — its single style prop was responsible for
 * roughly 76 of the ~79 inline styles on /toolkit, every one of them a
 * write `style-src 'self'` refuses in production.
 */
export const ToolboxColour = () => (
  <div
    style={{
      display: "grid",
      gridTemplateColumns: "repeat(2, minmax(0, 1fr))",
      gap: "8px 16px",
      maxWidth: 360,
    }}
  >
    {[
      ["webcrypto", "WebCrypto"],
      ["encoding", "Encoding"],
      ["openpgp", "OpenPGP"],
      ["age", "age"],
      ["ssh", "SSH"],
      ["agent", "Agent"],
      ["hkp", "HKP"],
      ["sss", "SSS"],
      ["webauthn", "WebAuthn"],
      ["jose", "JOSE"],
      ["io", "I/O"],
      ["flow", "Flow"],
    ].map(([tb, label]) => (
      <div key={tb} style={rowStyle}>
        <span style={slot}>
          <ToolboxDot op={{ toolbox: tb }} />
        </span>
        <span style={{ fontSize: 11.5 }}>{label}</span>
      </div>
    ))}
  </div>
);

/**
 * Ordinary data gets a plain circle and no accessible name — the colour
 * only repeats the toolbox the label beside it already states. Callers that
 * want only the meaningful marks skip the dot entirely rather than render
 * this; SuggestChip does exactly that, for the same reason the CAST light
 * is withheld from toolboxes that make no claim.
 */
export const OrdinaryData = () => (
  <div style={{ display: "grid", gap: 9 }}>
    {[
      ["ssh.encode", "ssh", "text"],
      ["digest", "webcrypto", "bytes"],
      ["gpg.sign", "openpgp", "signature"],
    ].map(([name, tb, output]) => (
      <div key={name} style={rowStyle}>
        <span style={slot}>
          <ToolboxDot op={{ toolbox: tb, output }} />
        </span>
        <span style={opName}>{name}</span>
        <span style={meaning}>→ {output} — no shape, decorative only</span>
      </div>
    ))}
  </div>
);
