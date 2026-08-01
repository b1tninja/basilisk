import { CastDot } from "basilisk-portal";

const ALL_PASSED = { openpgp: "verified", webcrypto: "verified", sss: "verified" };

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
  width: 12,
  height: 12,
  flexShrink: 0,
};

const emptySlot = {
  ...slot,
  border: "1px dashed color-mix(in srgb, var(--border) 90%, transparent)",
  borderRadius: 3,
};

const toolboxName = {
  fontWeight: 700,
  fontSize: 11.5,
  minWidth: 88,
};

const meaning = {
  fontSize: 11,
  color: "var(--muted-foreground)",
};

/**
 * The three states, on the toolbox headers that carry them. This is a
 * safety light, not decoration: green says the suite passed its power-on
 * self-test this session, amber says it has not run yet, red says it ran
 * and FAILED. Amber and green must never be confusable, because "untested"
 * and "passed" are the two things a FIPS-mode user is deciding between.
 */
export const States = () => (
  <div style={{ display: "grid", gap: 8 }}>
    <div style={rowStyle}>
      <span style={slot}>
        <CastDot op={{ toolbox: "openpgp" }} status={{ openpgp: "verified" }} />
      </span>
      <span style={toolboxName}>OpenPGP</span>
      <span style={meaning}>verified — self-test passed</span>
    </div>
    <div style={rowStyle}>
      <span style={slot}>
        <CastDot op={{ toolbox: "sss" }} status={{ sss: "unverified" }} />
      </span>
      <span style={toolboxName}>SSS / BLIP39</span>
      <span style={meaning}>unverified — not self-tested yet</span>
    </div>
    <div style={rowStyle}>
      <span style={slot}>
        <CastDot op={{ toolbox: "webcrypto" }} status={{ webcrypto: "error" }} />
      </span>
      <span style={toolboxName}>WebCrypto</span>
      <span style={meaning}>error — self-test FAILED</span>
    </div>
  </div>
);

/**
 * The state that matters. `error` is the only one that also gets a ring, so
 * it survives red-green colour deficiency and survives being 6px in a busy
 * header — this is the single indicator in the product where being missed
 * has a cryptographic consequence, and it is deliberately louder than its
 * size. Note that SSH reports the *WebCrypto* suite: its maths is
 * SubtleCrypto, so a WebCrypto CAST failure lights every SSH op too.
 */
export const SelfTestFailed = () => (
  <div style={{ display: "grid", gap: 8 }}>
    <div style={rowStyle}>
      <span style={slot}>
        <CastDot op={{ toolbox: "webcrypto" }} status={{ webcrypto: "error", sss: "verified" }} />
      </span>
      <span style={toolboxName}>WebCrypto</span>
      <span style={meaning}>do not rely on these ops</span>
    </div>
    <div style={rowStyle}>
      <span style={slot}>
        <CastDot op={{ toolbox: "ssh" }} status={{ webcrypto: "error", sss: "verified" }} />
      </span>
      <span style={toolboxName}>SSH</span>
      <span style={meaning}>same suite — SSH&apos;s maths is SubtleCrypto</span>
    </div>
    <div style={rowStyle}>
      <span style={slot}>
        <CastDot op={{ toolbox: "sss" }} status={{ webcrypto: "error", sss: "verified" }} />
      </span>
      <span style={toolboxName}>SSS / BLIP39</span>
      <span style={meaning}>unaffected — a different suite</span>
    </div>
  </div>
);

/**
 * The renders-nothing case, which is half the design. Only `openpgp`,
 * `webcrypto`/`ssh` and `sss` make a CAST claim; every other toolbox gets
 * no dot at all rather than a neutral one, because an indicator that is
 * always present and never means anything is exactly how the original
 * signal got lost. The dashed boxes below are this preview's scaffolding —
 * the component emits nothing there.
 */
export const NoClaimNoDot = () => (
  <div style={{ display: "grid", gap: 8 }}>
    {[
      ["encoding", "Encoding"],
      ["io", "Input / output"],
      ["flow", "Flow"],
      ["hkp", "HKP"],
    ].map(([tb, label]) => (
      <div key={tb} style={rowStyle}>
        <span style={emptySlot}>
          <CastDot op={{ toolbox: tb }} status={ALL_PASSED} />
        </span>
        <span style={toolboxName}>{label}</span>
        <span style={meaning}>no CAST claim — nothing rendered</span>
      </div>
    ))}
  </div>
);

/**
 * Before the self-test has reported at all, `status` is null and every dot
 * is withheld — including for the suites that will eventually claim one.
 * Showing amber here would be a lie in the other direction: the suite is
 * not "unverified", the app simply does not know yet.
 */
export const BeforeFirstSelfTest = () => (
  <div style={{ display: "grid", gap: 8 }}>
    {[
      ["openpgp", "OpenPGP"],
      ["webcrypto", "WebCrypto"],
      ["sss", "SSS / BLIP39"],
    ].map(([tb, label]) => (
      <div key={tb} style={rowStyle}>
        <span style={emptySlot}>
          <CastDot op={{ toolbox: tb }} status={null} />
        </span>
        <span style={toolboxName}>{label}</span>
        <span style={meaning}>status not reported yet — nothing rendered</span>
      </div>
    ))}
  </div>
);
