import { Textarea } from "basilisk-portal";

const label = {
  fontSize: 11,
  fontWeight: 600,
  color: "var(--foreground)",
  display: "block",
  marginBottom: 4,
};

const help = {
  fontSize: 10.5,
  color: "var(--muted-foreground)",
  display: "block",
  marginTop: 4,
};

const ARMORED = `-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEZqT1WhYJKwYBBAHaRw8BAQdAcW5rZXlfc2Ft
cGxlX25vdF9hX3JlYWxfa2V5IQIbAwUJA8JnAAUL
eV9wbGFjZWhvbGRlcl9ub3RfdmFsaWRfZm9yPT09
=Ab3D
-----END PGP PUBLIC KEY BLOCK-----`;

/**
 * The canonical use: somewhere to paste a block of crypto text. The control
 * is monospaced by default — every value that reaches it is armored text,
 * base64, a recipe, or a fingerprint, and all four are unreadable in a
 * proportional face.
 */
export const Default = () => (
  <Textarea placeholder="Paste an OpenPGP public key block, an SSH key, or base64…" />
);

/**
 * Holding a value. This is the shape of the input step's editor: the field
 * grows past its 60px floor to fit what was pasted, and armor lines stay
 * unwrapped-looking because the mono face makes the column width real.
 */
export const ArmoredKeyBlock = () => (
  <div style={{ maxWidth: 420 }}>
    <label style={label}>Public key</label>
    <Textarea rows={7} defaultValue={ARMORED} />
    <small style={help}>Parsed on blur — a malformed block reports at the step, not here.</small>
  </div>
);

/**
 * Recipe source. The notebook's text view is this same primitive, which is
 * why the mono default is not a per-call-site className: a pipeline whose
 * pipes do not line up column-wise is materially harder to read.
 */
export const RecipeSource = () => (
  <div style={{ maxWidth: 420 }}>
    <label style={label}>Recipe</label>
    <Textarea
      rows={5}
      defaultValue={`in $secret
| genkey ed25519
| ssh.encode as=openssh
| agent.sign key=$me
| out $signature`}
    />
  </div>
);

/**
 * The share-check pair. Two identical fields side by side, one for input and
 * one for what came back, so a mismatch is a visual diff rather than a claim
 * the app makes on the user's behalf.
 */
export const SharePair = () => (
  <div style={{ display: "grid", gap: 10, maxWidth: 420 }}>
    <div>
      <label style={label}>Paste a share to check</label>
      <Textarea rows={3} defaultValue="blip39:3-of-5:acorn ridge cobalt violin ember tundra…" />
    </div>
    <div>
      <label style={label}>Recovered secret</label>
      <Textarea rows={3} readOnly defaultValue="— needs 3 shares; 1 pasted —" />
    </div>
  </div>
);

/**
 * Not yet filled. **There is no `disabled` prop** — `TextareaProps` omits it
 * and types it `never`, for the reason spelled out on `Input` and enforced on
 * `Button` by `disabledReason`: a boolean cannot say why a field went dead, and
 * a dimmed box with nothing to read is the defect that rule removes.
 *
 * So a field whose op has not run yet stays live and legible, and the sentence
 * that would have been a tooltip on a grey box is ordinary text under the
 * control. Keeping it visible is what tells the user the parameter exists at
 * all; keeping it readable is what tells them what to do about it.
 */
export const NotYetFilled = () => (
  <div style={{ maxWidth: 420 }}>
    <label style={label}>Detached signature</label>
    <Textarea rows={3} placeholder="Appears here once agent.sign has run" />
    <small style={help}>agent.sign has not run in this recipe yet.</small>
  </div>
);
