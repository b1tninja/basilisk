import { Separator } from "basilisk-portal";

const sectionTitle = {
  fontSize: 11,
  fontWeight: 700,
  textTransform: "uppercase" as const,
  letterSpacing: "0.06em",
  color: "var(--muted-foreground)",
  margin: 0,
};

const body = {
  fontSize: 12,
  color: "var(--foreground)",
  margin: 0,
};

/**
 * A 1px rule is only ever as good as what it divides, so the story is the
 * division: two named sections of the Preferences panel, with the separator
 * carrying the whole burden of saying "these are different subjects".
 * `decorative` defaults to true — the heading below already announces the
 * boundary to a screen reader, and a second announcement is noise.
 */
export const BetweenSections = () => (
  <div style={{ display: "grid", gap: 10, maxWidth: 360 }}>
    <div style={{ display: "grid", gap: 4 }}>
      <p style={sectionTitle}>Default crypto profile</p>
      <p style={body}>Applies to new OpenPGP steps.</p>
    </div>
    <Separator />
    <div style={{ display: "grid", gap: 4 }}>
      <p style={sectionTitle}>Crypto self-test (POST)</p>
      <p style={body}>Runs once per session, per suite.</p>
    </div>
  </div>
);

/**
 * Vertical, grouping a control row. In the run bar the separator is what
 * keeps "what will run" and "what happens to the result" from reading as
 * one six-button toolbar — the alternative, extra gap, gets eaten the first
 * time the panel narrows.
 */
export const Vertical = () => (
  <div
    style={{
      display: "flex",
      alignItems: "center",
      gap: 10,
      height: 22,
      fontSize: 12,
      color: "var(--foreground)",
    }}
  >
    <span>Run</span>
    <span>Step</span>
    <Separator orientation="vertical" />
    <span>Copy</span>
    <span>Download</span>
    <Separator orientation="vertical" />
    <span style={{ color: "var(--muted-foreground)" }}>Clear</span>
  </div>
);

/**
 * A full drawer section, which is where most separators in the app actually
 * live: title, rule, list, rule, footer. Stacked at real spacing it is
 * visible that the rule is `--border` — the same token the panel edges use —
 * so an internal division never out-weighs the panel's own boundary.
 */
export const InAPanel = () => (
  <div
    style={{
      display: "grid",
      gap: 8,
      maxWidth: 300,
      border: "1px solid var(--border)",
      borderRadius: 8,
      padding: 12,
    }}
  >
    <p style={sectionTitle}>Keyring</p>
    <Separator />
    <div style={{ display: "grid", gap: 6, fontSize: 12 }}>
      <span>ed25519-2026-07</span>
      <span>gpg.board-root</span>
      <span>ssh.deploy-ci</span>
    </div>
    <Separator />
    <p style={{ fontSize: 11, color: "var(--muted-foreground)", margin: 0 }}>
      3 keys — stored on this device only
    </p>
  </div>
);
