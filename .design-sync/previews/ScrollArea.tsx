import { ScrollArea } from "basilisk-portal";

const frame = {
  border: "1px solid var(--border)",
  borderRadius: 8,
  maxWidth: 300,
  overflow: "hidden",
};

const footnote = {
  fontSize: 10.5,
  color: "var(--muted-foreground)",
  margin: "5px 0 0",
  maxWidth: 300,
};

const rowStyle = {
  display: "flex",
  alignItems: "center",
  justifyContent: "space-between",
  gap: 8,
  padding: "5px 10px",
  fontSize: 12,
  color: "var(--foreground)",
};

const monoStyle = {
  fontFamily: "var(--font-mono, ui-monospace, monospace)",
  fontSize: 11,
  color: "var(--muted-foreground)",
};

const OPS: [string, string][] = [
  ["genkey", "WebCrypto"],
  ["sign", "WebCrypto"],
  ["verify", "WebCrypto"],
  ["digest", "WebCrypto"],
  ["hkdf", "WebCrypto"],
  ["pbkdf2", "WebCrypto"],
  ["gpg.encrypt", "OpenPGP"],
  ["gpg.sign", "OpenPGP"],
  ["gpg.inspect", "OpenPGP"],
  ["ssh.encode", "SSH"],
  ["ssh.fingerprint", "SSH"],
  ["agent.sign", "Agent"],
  ["agent.unlock", "Agent"],
  ["blip39", "SSS"],
  ["split", "SSS"],
];

/**
 * The ops drawer, which is what this component was reduced to serve: a list
 * longer than any panel, bounded by its container and scrolled natively.
 * The thumb is the platform's own, painted with `--border` in `toolkit.css`
 * — this deliberately replaced a Radix ScrollArea whose synthetic thumb
 * needed a runtime `<style>` injection that `style-src 'self'` refuses.
 */
export const OpsDrawer = () => (
  <div>
    <div style={frame}>
      <ScrollArea style={{ height: 168 }}>
        <div style={{ padding: "4px 0" }}>
          {OPS.map(([name, toolbox]) => (
            <div key={name} style={rowStyle}>
              <code style={{ fontFamily: "var(--font-mono, ui-monospace, monospace)" }}>{name}</code>
              <span style={monoStyle}>{toolbox}</span>
            </div>
          ))}
        </div>
      </ScrollArea>
    </div>
    <p style={footnote}>
      15 ops in a 168px region — 6 visible, the rest below. The cut row is the affordance.
    </p>
  </div>
);

/**
 * Wrapping a long value rather than a list. `overflow-x` is hidden by
 * design: a horizontal scrollbar in a 300px drawer hides the end of every
 * line behind a gesture, so long armor wraps instead and only the vertical
 * axis scrolls.
 */
export const LongOutput = () => (
  <div>
    <div style={frame}>
    <ScrollArea style={{ height: 140 }}>
      <pre
        style={{
          margin: 0,
          padding: 10,
          fontFamily: "var(--font-mono, ui-monospace, monospace)",
          fontSize: 11,
          lineHeight: 1.5,
          whiteSpace: "pre-wrap",
          wordBreak: "break-all",
          color: "var(--foreground)",
        }}
      >
        {`-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgc2FtcGxlX3BsYWNlaG9s
ZGVyX25vdF9hX3JlYWxfc2lnbmF0dXJlAAAABGZpbGUAAAAAAAAABnNoYTUxMgAA
AFMAAAALc3NoLWVkMjU1MTkAAABAcGxhY2Vob2xkZXJfYnl0ZXNfZm9yX2xheW91
dF9vbmx5X25vdF92YWxpZF9mb3JfdmVyaWZpY2F0aW9uPT09
-----END SSH SIGNATURE-----`}
      </pre>
    </ScrollArea>
    </div>
    <p style={footnote}>
      One armored signature, wrapped and clipped — nothing scrolls sideways.
    </p>
  </div>
);

/**
 * Content that fits. No scrollbar appears and no space is reserved for one,
 * which is the reason the region can be used unconditionally around any
 * panel body without the short cases paying a gutter.
 */
export const FitsWithoutScrolling = () => (
  <div>
    <div style={frame}>
      <ScrollArea style={{ height: 96 }}>
        <div style={{ padding: "4px 0" }}>
          <div style={rowStyle}>
            <code style={{ fontFamily: "var(--font-mono, ui-monospace, monospace)" }}>
              agent.list
            </code>
            <span style={monoStyle}>Agent</span>
          </div>
          <div style={rowStyle}>
            <code style={{ fontFamily: "var(--font-mono, ui-monospace, monospace)" }}>
              agent.pub
            </code>
            <span style={monoStyle}>Agent</span>
          </div>
        </div>
      </ScrollArea>
    </div>
    <p style={footnote}>
      Two ops in the same 96px region — no cut row, no gutter reserved.
    </p>
  </div>
);
