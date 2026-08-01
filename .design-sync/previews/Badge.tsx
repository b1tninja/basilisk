import { Badge } from "basilisk-portal";

const row = {
  display: "flex",
  gap: 6,
  alignItems: "center",
  flexWrap: "wrap" as const,
};

const caption = {
  fontSize: 11,
  color: "var(--muted-foreground)",
  margin: "0 0 6px",
};

/**
 * The canonical use: a short status word beside the thing it qualifies.
 * `default` is brand-tinted, so it reads as "this is what the system is
 * doing" rather than as a warning.
 */
export const Default = () => <Badge>Modern</Badge>;

/**
 * The variant axis. It is a severity ramp, not a palette: `secondary` is
 * inert metadata, `ok` is a claim that something was checked and passed,
 * `warn` is "you can proceed but know this", `destructive` is "a guarantee
 * this app makes is currently not holding". Reaching for `warn` because it
 * looks nice is how the real warnings stop being read.
 */
export const Variants = () => (
  <div style={row}>
    <Badge>Modern</Badge>
    <Badge variant="secondary">OpenPGP</Badge>
    <Badge variant="ok">Self-tested</Badge>
    <Badge variant="warn">Sensitive</Badge>
    <Badge variant="destructive">CAST failed</Badge>
  </div>
);

/**
 * Preferences → Cryptographic parameters renders one badge per CAST suite,
 * pill-shaped and sentence-cased via className — the only place the default
 * uppercase micro-caps treatment is overridden, because these carry a glyph
 * and a proper noun rather than a one-word status. A suite that failed its
 * power-on self-test drops to `destructive`; a suite not yet run is `warn`,
 * never `ok`, because "untested" and "passed" must never look alike.
 */
export const SuiteSelfTest = () => (
  <div>
    <p style={caption}>Crypto self-test (POST)</p>
    <div style={row}>
      <Badge
        variant="ok"
        className="rounded-full px-[9px] py-[3px] text-[10.5px] normal-case tracking-normal"
      >
        ✓ WebCrypto
      </Badge>
      <Badge
        variant="ok"
        className="rounded-full px-[9px] py-[3px] text-[10.5px] normal-case tracking-normal"
      >
        ✓ OpenPGP
      </Badge>
      <Badge
        variant="warn"
        className="rounded-full px-[9px] py-[3px] text-[10.5px] normal-case tracking-normal"
      >
        ⚠ SSS / BLIP39
      </Badge>
    </div>
  </div>
);

/**
 * On an output row. The `sensitive` flag is the one badge a user must not
 * miss — it is what stands between "Copy" and a private key on the
 * clipboard — so it is `warn` and it sits directly against the artifact
 * label rather than at the end of the row.
 */
export const OnAnArtifactRow = () => (
  <div style={{ display: "grid", gap: 8 }}>
    <div style={row}>
      <span style={{ fontSize: 11, color: "var(--muted-foreground)", width: 58 }}>keypair</span>
      <code style={{ fontFamily: "var(--font-mono, ui-monospace, monospace)", fontSize: 12 }}>
        ed25519-2026-07.key
      </code>
      <Badge variant="warn" className="normal-case tracking-normal">
        sensitive
      </Badge>
    </div>
    <div style={row}>
      <span style={{ fontSize: 11, color: "var(--muted-foreground)", width: 58 }}>text</span>
      <code style={{ fontFamily: "var(--font-mono, ui-monospace, monospace)", fontSize: 12 }}>
        ed25519-2026-07.pub
      </code>
      <Badge variant="secondary">ssh.encode</Badge>
    </div>
  </div>
);

/**
 * `secondary` doing the quiet job it exists for: naming the toolbox an op
 * came from, next to a dozen others. It has to be legible at 10px and it
 * has to stay out of the way, which is why it is the only variant with a
 * visible border and no colour of its own.
 */
export const ToolboxTags = () => (
  <div style={row}>
    <Badge variant="secondary">WebCrypto</Badge>
    <Badge variant="secondary">Encode</Badge>
    <Badge variant="secondary">OpenPGP</Badge>
    <Badge variant="secondary">SSH</Badge>
    <Badge variant="secondary">Agent</Badge>
    <Badge variant="secondary">HKP</Badge>
    <Badge variant="secondary">SSS</Badge>
    <Badge variant="secondary">JOSE</Badge>
  </div>
);
