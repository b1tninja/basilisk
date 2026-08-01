import { OtpCodeCard } from "basilisk-portal";

/*
 * Every code and trait bag below is `otp.code`'s real output, taken by running
 * the op against a fixed `at=` so the step number is stable:
 *
 *   otp.code at=1785110400   (2026-07-27T00:00:00Z)
 *
 * from `otpauth://totp/Basilisk:ada.lovelace@example.org?secret=…&period=30`
 * and its HOTP and 8-digit siblings. The digits are therefore the real RFC 6238
 * codes for that instant — not decorative numerals — and `otpStep` is the real
 * step they belong to, which is what makes the countdown below honest.
 *
 * `nowMs` is injectable for exactly this: a step ends at `(step + 1) × period`
 * from the Unix epoch, so moving the clock forward against a fixed artifact
 * drains the bar without touching the value. Nothing here recomputes a code —
 * a Refresh button is the one feature this widget exists to refuse.
 */

const TOTP = "016748";
const TOTP_TRAITS = {
  kind: "otp-code",
  sensitive: false,
  otpMode: "totp",
  otpDigits: 6,
  otpPeriod: 30,
  otpExpiresIn: 30,
  otpStep: "59503680",
  otpLabel: "Basilisk: ada.lovelace@example.org",
};

/** The step above ends at (59503680 + 1) × 30 = 1785110430 Unix seconds. */
const ENDS_AT_MS = 1785110430_000;

const HOTP = "436867";
const HOTP_TRAITS = {
  kind: "otp-code",
  sensitive: false,
  otpMode: "hotp",
  otpDigits: 6,
  otpCounter: 42,
  otpLabel: "Basilisk: ops-bot@example.org",
};

const TOTP8 = "79352534";
const TOTP8_TRAITS = {
  kind: "otp-code",
  sensitive: false,
  otpMode: "totp",
  otpDigits: 8,
  otpPeriod: 60,
  otpExpiresIn: 60,
  otpStep: "29751840",
  otpLabel: "Basilisk: release-signing@example.org",
};

/**
 * A live code, at the top of its step. The digits lead at a size you can read
 * across a desk while typing them into another window; underneath are the two
 * facts the string cannot carry — whose account it is, and how much of the
 * step is left.
 */
export const Live = () => (
  <OtpCodeCard content={TOTP} traits={TOTP_TRAITS} nowMs={ENDS_AT_MS - 30_000} />
);

/**
 * The countdown, driven entirely by `nowMs` against one unchanging artifact.
 * Same code, same step, three moments: full, urgent (≤5s, where the tone
 * escalates to warn), and past the end.
 *
 * The expired card is the design decision worth staring at. It keeps showing
 * the value it always showed, says which step that value belonged to, and
 * tells you to run the cell again — because this is the code the run receipt
 * digested, and a tile that quietly swapped in a fresh one would be lying
 * about which value the receipt covers.
 */
export const Draining = () => (
  <div style={{ display: "grid", gridTemplateColumns: "minmax(0, 1fr)", gap: 16 }}>
    <OtpCodeCard content={TOTP} traits={TOTP_TRAITS} nowMs={ENDS_AT_MS - 30_000} />
    <OtpCodeCard content={TOTP} traits={TOTP_TRAITS} nowMs={ENDS_AT_MS - 3_000} />
    <OtpCodeCard content={TOTP} traits={TOTP_TRAITS} nowMs={ENDS_AT_MS + 15_000} />
  </div>
);

/**
 * HOTP has no countdown — not a disabled one, not a zeroed one: none. A code
 * that answers to an event counter has no clock, so the timer is simply not
 * drawn and the counter takes its place. "It does not expire, it gets spent."
 */
export const CounterNotClock = () => <OtpCodeCard content={HOTP} traits={HOTP_TRAITS} />;

/**
 * The grouping axis. Six digits split 3+3, eight split 4+4 — a gap between
 * spans, never a character in the string, so Copy still copies the code the
 * recipe produced. The 60-second step drains at half the rate, which the bar
 * shows and the sentence names.
 */
export const DigitsAndStep = () => (
  <div style={{ display: "grid", gridTemplateColumns: "minmax(0, 1fr)", gap: 16 }}>
    <OtpCodeCard content={TOTP} traits={TOTP_TRAITS} nowMs={ENDS_AT_MS - 22_000} />
    <OtpCodeCard content={TOTP8} traits={TOTP8_TRAITS} nowMs={1785110460_000 - 45_000} />
  </div>
);
