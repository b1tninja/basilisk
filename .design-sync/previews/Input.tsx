import { Input } from "basilisk-portal";

const field = {
  display: "grid",
  gap: 4,
};

const label = {
  fontSize: 11,
  fontWeight: 600,
  color: "var(--foreground)",
};

const help = {
  fontSize: 10.5,
  color: "var(--muted-foreground)",
};

/**
 * The canonical use: a single op parameter. Almost every Input in Basilisk
 * is one field of one step, so the placeholder carries the example rather
 * than a generic "enter value".
 */
export const Default = () => (
  <Input placeholder="Board key, Q3 root key, room name…" defaultValue="" />
);

/**
 * A labelled parameter with its help line — the shape the ceremony sheet and
 * the step editor both use. The help text sits *below* the control because
 * it explains a consequence of the value, and a consequence should be read
 * after the thing that causes it.
 */
export const LabelledParam = () => (
  <div style={{ ...field, maxWidth: 320 }}>
    <span style={label}>Ceremony label</span>
    <Input defaultValue="Q3 root key" />
    <small style={help}>Printed on every card and recorded in the receipt.</small>
  </div>
);

/**
 * The quorum pair from the split ceremony. Numeric params get `type=number`
 * with real bounds, because a threshold above the share count is not a
 * validation message you want to discover after the shares are printed.
 */
export const NumericParams = () => (
  <div style={{ display: "flex", gap: 12, maxWidth: 320 }}>
    <div style={field}>
      <span style={label}>Shares to make</span>
      <Input type="number" min={2} max={16} defaultValue={5} />
    </div>
    <div style={field}>
      <span style={label}>Needed to recover</span>
      <Input type="number" min={1} max={16} defaultValue={3} />
    </div>
  </div>
);

/**
 * The ops-drawer filter. Same primitive, no label — the surrounding drawer
 * already says what is being filtered, and a label here would cost a row of
 * the densest panel in the product.
 */
export const Filter = () => (
  <div style={{ maxWidth: 260 }}>
    <Input placeholder="Filter ops — gpg.sign, hkdf, ssh.encode…" defaultValue="ssh." />
  </div>
);

/**
 * `readOnly` is the only non-editable state this control has. A value the app
 * resolved rather than the user typed stays full-strength and selectable,
 * because the whole point of showing it is that it can be copied.
 *
 * **There is no `disabled`** — `InputProps` omits it and types it `never`, the
 * same rule `Button` enforces with `disabledReason`. A boolean cannot say why a
 * field went dead, and a grey box with nothing to read is the defect that rule
 * exists to remove. Nothing in the product disables an input today, so there is
 * no paired refusal to reach for either: a field whose op is not yet reachable
 * stays live, and the panel around it says what is missing. Do not dim a field
 * to mean "not ready".
 */
export const ReadOnly = () => (
  <div style={{ display: "grid", gap: 10, maxWidth: 360 }}>
    <div style={field}>
      <span style={label}>Fingerprint (resolved by agent.pub)</span>
      <Input readOnly defaultValue="SHA256:9Nb7q2Lx4kA1vRt0wZcE6mYpH8sJd3FuQnKgX5oT2Bc" />
    </div>
    <div style={field}>
      <span style={label}>Recipient</span>
      <Input placeholder="Fingerprint, uid, or a key from the keyring" />
      <small style={help}>No keyring is connected yet — nothing will resolve.</small>
    </div>
  </div>
);
