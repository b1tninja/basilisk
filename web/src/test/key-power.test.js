/**
 * The five states a key can be in, and the sentences that name them.
 *
 * The vocabulary exists because the old split was on storage — "Your keys" and
 * "Your browser vault", both called keys — and a person holding three account
 * keys was told by the session that they had none. Both statements were true
 * about different things, which is the property a shared vocabulary removes.
 */
import { describe, expect, it } from "vitest";
import {
  KEY_POWERS,
  keyIsExpired,
  keyPower,
  keyPowerReadout,
  loadedCount,
  strongestPower,
} from "../lib/toolkit/key-power.js";

const ADA = "A".repeat(40);
const NOW = Date.parse("2026-08-12T12:00:00Z");
const day = (n) => new Date(NOW + n * 86_400_000).toISOString();

describe("the vocabulary is closed", () => {
  it("names exactly the five states, in order of capability", () => {
    // A sixth value with no rule beside it in toolkit.css is the drift a
    // closed set exists to prevent, so the list is exported rather than
    // spelled out at each call site.
    expect([...KEY_POWERS]).toEqual(["absent", "unusable", "held", "loaded", "ready"]);
  });

  it("answers absent for a key this browser does not hold", () => {
    // Not an error state and not a loading state: it is the ordinary state of
    // every key you have ever been sent, and the state the session's empty
    // picker was in.
    expect(keyPower(null)).toBe("absent");
    expect(keyPower(undefined)).toBe("absent");
  });
});

describe("held here is not the same as able to sign", () => {
  it("calls a stored, unopened key held", () => {
    expect(keyPower({ fingerprint: ADA, protection: "passphrase" }, NOW)).toBe("held");
  });

  it("separates an open envelope from a usable key", () => {
    // `vault.unlockKey` removes the vault's device-bound wrapper and returns
    // armor that may still carry OpenPGP's own S2K lock. "unlocked · 4:58 left"
    // beside such a key was a true statement about the envelope and a false one
    // about the key, and the run found out inside `resolveGpgPrivateKey`.
    const opened = { fingerprint: ADA, protection: "passphrase", loaded: true, locked: true };
    expect(keyPower(opened, NOW)).toBe("loaded");
    expect(keyPower({ ...opened, locked: false }, NOW)).toBe("ready");
  });

  it("treats an unestablished lock as ready rather than refusing", () => {
    // `keyOwesPassphrase` answers undefined where nothing observed the armor,
    // and a "needs a passphrase" on a device key would be the same defect
    // pointing the other way. `ready`'s sentence is written to claim only what
    // is known.
    const unobserved = { fingerprint: ADA, protection: "session", loaded: true };
    expect(keyPower(unobserved, NOW)).toBe("ready");
    expect(keyPowerReadout(unobserved, NOW).why).toMatch(/nothing this browser can see/);
  });
});

describe("unusable is two states and says which", () => {
  it("refuses the kinds that cannot sign an OpenPGP invite", () => {
    for (const kind of ["ssh", "raw"]) {
      const key = { fingerprint: ADA, kind, loaded: true };
      expect(keyPower(key, NOW)).toBe("unusable");
      expect(keyPowerReadout(key, NOW).why).toMatch(/only an OpenPGP key can open one/);
    }
  });

  it("refuses an expired OpenPGP key, and names the day", () => {
    // Unlocking an expired key succeeds — the vault knows nothing about
    // validity — and the signature then fails in OpenPGP's own words, several
    // steps after the choice. The refusal belongs at the choice.
    const key = { fingerprint: ADA, expires: day(-3), loaded: true, locked: false };
    expect(keyPower(key, NOW)).toBe("unusable");
    const readout = keyPowerReadout(key, NOW);
    expect(readout.label).toBe("expired");
    expect(readout.why).toMatch(/expired on 2026-08-09/);
    expect(readout.why).not.toMatch(/SSH|OpenSSH/);
  });

  it("answers at the instant, not the day", () => {
    // `expiryNote` rounds to days on purpose — it is advice on a card. This
    // decides whether a key is offered to sign with, and at day resolution a
    // key that expired this morning is still on offer.
    expect(keyIsExpired({ expires: day(0.4) }, NOW)).toBe(false);
    expect(keyIsExpired({ expires: day(-0.4) }, NOW)).toBe(true);
  });

  it("never reads a session row's TTL as the key's validity", () => {
    // A session-only row carries the agent session's five-minute clock in the
    // same `expires` field. Read as validity it would print "this key expired"
    // about a key that expired at nothing — a refusal naming a state the
    // reader is not in, about the key they most recently made by hand.
    const stale = { fingerprint: ADA, protection: "session", expires: NOW - 1000, loaded: true };
    expect(keyIsExpired(stale, NOW)).toBe(false);
    expect(keyPower(stale, NOW)).toBe("ready");
  });

  it("says nothing about expiry for a key that never expires", () => {
    expect(keyIsExpired({ expires: null }, NOW)).toBe(false);
    expect(keyIsExpired({ expires: "" }, NOW)).toBe(false);
  });
});

describe("every state is a sentence somebody can act on", () => {
  it("gives each power a label and a reason", () => {
    const rows = [
      null,
      { fingerprint: ADA, kind: "ssh" },
      { fingerprint: ADA, protection: "passphrase" },
      { fingerprint: ADA, protection: "passphrase", loaded: true, locked: true },
      { fingerprint: ADA, protection: "device", loaded: true, locked: false },
    ];
    const seen = new Set();
    for (const row of rows) {
      const readout = keyPowerReadout(row, NOW);
      seen.add(readout.power);
      expect(readout.label.length).toBeGreaterThan(2);
      // The same bar `disabled-needs-reason.test.js` sets for a refusal: a
      // sentence, not a label that ends the question.
      expect(readout.why.length).toBeGreaterThan(30);
      expect(readout.why).toMatch(/[.!?]$/);
    }
    expect([...seen].sort()).toEqual(["absent", "held", "loaded", "ready", "unusable"]);
  });

  it("points the still-locked key at the field that answers it", () => {
    const readout = keyPowerReadout(
      { fingerprint: ADA, protection: "passphrase", loaded: true, locked: true },
      NOW
    );
    expect(readout.why).toMatch(/Inputs → Key passphrase/);
  });
});

describe("the count behind the Keys tab", () => {
  it("counts what is in the agent session, loaded or ready", () => {
    // Both count: the tab says how many keys have armor in memory with a clock
    // running, which is the fact the tray's Lock all acts on. Whether one of
    // them still owes a passphrase is the row's business, not the badge's.
    const keys = [
      { fingerprint: ADA, protection: "passphrase" },
      { fingerprint: "B".repeat(40), protection: "passphrase", loaded: true, locked: true },
      { fingerprint: "C".repeat(40), protection: "device", loaded: true, locked: false },
      { fingerprint: "D".repeat(40), kind: "ssh", loaded: true },
    ];
    expect(loadedCount(keys.map((k) => keyPower(k, NOW)))).toBe(2);
    expect(loadedCount([])).toBe(0);
    expect(loadedCount(undefined)).toBe(0);
  });

  it("summarises a whole browser by its strongest key, not its worst", () => {
    // The chip answers "can I do the thing". Somebody holding one ready key
    // and one expired one can sign, and a chip reading `unusable` would be a
    // refusal naming a state they are not in.
    expect(strongestPower(["unusable", "ready", "held"])).toBe("ready");
    expect(strongestPower(["unusable", "held"])).toBe("held");
    expect(strongestPower(["unusable"])).toBe("unusable");
    expect(strongestPower([])).toBe("absent");
    expect(strongestPower(undefined)).toBe("absent");
  });
});
